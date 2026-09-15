//! T5.10 — the whole matrix again, with `ALWAYS_USE_RELAY=Y`.
//!
//! The question is one sentence: **does the relay ever become an authorization
//! bypass?** It has two chokepoints' worth of answer, because the relay is a
//! separate gate (T3.3b) with a separate call site, and every earlier suite in
//! this milestone ran against a world where the relay was the *fallback* rather
//! than the only path.
//!
//! **Start with what the flag does not do, because it is the first thing to get
//! wrong.** `ALWAYS_USE_RELAY=Y` is silently ignored whenever hbbs sees the same
//! IP for both peers: the override rewrites `nat_type` only, and `same_intranet`
//! is computed independently and selects the `FetchLocalAddr` branch, which
//! carries no `nat_type` at all (`rendezvous_server.rs:760-763`, found in T0.5).
//! Every peer in this harness is on 127.0.0.1, so switching the flag on and
//! running the old tests would have produced a suite that looked like it forced
//! the relay and did not. Two tests here pin both halves — the flag ignored on
//! one IP, and the flag biting when the device is reached on the host's LAN
//! address — and the rest drive the relay gate explicitly, which is the only way
//! to be sure which gate answered.
//!
//! What is re-run here, under the flag: the access matrix, revocation, the
//! fail-closed path, and the bypass rows. Not because they are expected to
//! differ — but "expected not to differ" is exactly the assumption that made
//! `handle_request_relay` unauthorized until T3.3b.

mod harness;

use std::time::Duration;

use harness::{
    peer::{Controller, Device},
    relay::{assert_relays, relay_host, relay_join},
    world::World,
};
use hbb_common::{
    bytes::Bytes,
    rendezvous_proto::*,
    tokio::{self, time::sleep},
};

const WAIT: u64 = 8_000;
const REFUSAL: u64 = 2_500;
const QUIET: u64 = 1_200;
const DEADLINE: Duration = Duration::from_secs(10);

/// A world with the flag on, and the cache off so each row below is its own
/// decision rather than the previous row's.
fn relayed() -> harness::world::WorldBuilder {
    World::builder().always_use_relay(true).auth_cache_ttl_ms(1)
}

/// The relay gate's verdict on one connection, in the words A would see.
async fn relay_refusal(who: &Controller, device: &mut Device, w: &World, what: &str) -> String {
    match who
        .connect_relayed(device, &w.relay_addr(), &w.hbbs.key, REFUSAL)
        .await
    {
        Err(reason) => reason,
        Ok(_) => panic!("{what}: the relayed connection was ALLOWED"),
    }
}

// ---------------------------------------------------------------- what the flag does

/// **The flag is ignored on one IP, and this is the reason the rest of this file
/// is written the way it is.** With `ALWAYS_USE_RELAY=Y` and both peers on
/// loopback, hbbs still brokers a direct `FetchLocalAddr` and `hbbr` is never
/// contacted.
///
/// T0.5 found this against the real binaries; nothing had pinned it since. It is
/// not a fault of ours to fix — the branch is upstream's — but it **is** our
/// production shape: one public `hbbs`, every device behind one office NAT is
/// exactly "the same IP for both peers", so the knob cannot be relied on in the
/// field either.
#[tokio::test(flavor = "multi_thread")]
async fn the_flag_is_ignored_when_both_peers_share_an_ip() {
    let w = relayed().up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let (brokerage, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the owner was refused");

    assert!(
        brokerage.local,
        "hbbs took the relay-forcing branch for two peers on one IP — the T0.5 finding has \
         changed, and the tests below that work around it should be revisited"
    );
    assert!(
        !w.hbbr.log().contains("New relay request"),
        "hbbr was contacted for a connection that never left loopback:\n{}",
        w.hbbr.log()
    );
}

/// And the flag biting, in the shape production would see: the device is reached
/// on the host's own LAN address, so the two peers no longer share an IP.
/// `same_intranet` is false, the override applies, and hbbs sends a `PunchHole`
/// naming a relay instead of a `FetchLocalAddr`.
///
/// Only what hbbs forwards is checked. Completing the handshake would need B to
/// answer from the same address it registered from, which the brokerage ledger
/// (T3.8) is right to insist on and which is not what this test is about.
#[tokio::test(flavor = "multi_thread")]
async fn the_flag_forces_a_relay_when_the_peers_are_on_different_ips() {
    let w = relayed().up().await;
    let alice = w.controller("alice").await;
    // Enrolled through the console as usual, then registered from the LAN
    // address so hbbs records it there.
    let owned = w.device(&alice).await;
    let mut elsewhere =
        Device::register_from(&relay_host(), w.hbbs.port, &owned.id, &owned.uuid, &owned.pk).await;

    let _waiting = alice.punch_alone(&elsewhere.id).await;
    let brokerage = elsewhere
        .brokered(WAIT)
        .await
        .expect("hbbs brokered nothing to a device on the LAN address");

    assert!(
        !brokerage.local,
        "hbbs sent FetchLocalAddr to peers on different IPs with ALWAYS_USE_RELAY=Y"
    );
    assert!(
        !brokerage.relay_server.is_empty(),
        "the brokerage named no relay server, so the client has nowhere to fall back to"
    );
}

// ---------------------------------------------------------------- the matrix, over the relay

/// The T5.2 rows again, every one of them through `hbbr`, in one world so that
/// the allows and the denials are answered by the same server in the same state.
///
/// The allow is carried all the way to bytes coming out the other side. A gate
/// that returned a `RelayResponse` and nothing else would pass a test that
/// stopped at the refusal string, and "the relay never becomes a bypass" is a
/// claim about traffic, not about messages.
#[tokio::test(flavor = "multi_thread")]
async fn the_access_matrix_holds_on_the_relay_gate() {
    let w = relayed().up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let admin = w.controller_with_role("root", "admin").await;
    let mut laptop = w.device(&alice).await;

    // A → own device.
    let (mut a_end, mut b_end, _) = alice
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, WAIT)
        .await
        .expect("the owner was refused their own device over the relay");
    assert_relays(&mut a_end, &mut b_end, b"the owner's own machine", WAIT).await;
    drop((a_end, b_end));

    // B → A's device, ungranted.
    let refusal = relay_refusal(&bob, &mut laptop, &w, "a stranger over the relay").await;
    assert!(
        refusal.to_lowercase().contains("do not have access"),
        "the relay gate refused a stranger for the wrong reason: {refusal}"
    );

    // An admin is refused too — the role is never consulted (T5.2's corrected
    // row), and the relay gate must not be the one place it is.
    let refusal = relay_refusal(&admin, &mut laptop, &w, "an ungranted admin over the relay").await;
    assert!(
        refusal.to_lowercase().contains("do not have access"),
        "an admin was treated as privileged on the relay gate: {refusal}"
    );

    // B → A's device, granted.
    w.console.grant(&bob.user_id, &laptop.id).await;
    let (mut a_end, mut b_end, _) = bob
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, WAIT)
        .await
        .expect("a granted user was refused over the relay");
    assert_relays(&mut a_end, &mut b_end, b"granted, and relayed", WAIT).await;
    drop((a_end, b_end));

    // And revoked again.
    w.console.revoke(&bob.user_id, &laptop.id).await;
    let refusal = relay_refusal(&bob, &mut laptop, &w, "a revoked user over the relay").await;
    // A revoked grant says something different from never having had one, and
    // the distinction is deliberate — the user is told their access was
    // withdrawn rather than that it never existed.
    assert!(
        refusal.to_lowercase().contains("withdrawn"),
        "a revoked grant did not close the relay gate: {refusal}"
    );
}

/// Decision D2 over the relay, with the flag on: revoking a grant ends a session
/// that is already carrying bytes through `hbbr`, with nobody doing anything.
///
/// T5.3 covers this; it is re-run here because the termination channel is the
/// device's heartbeat and **not** the relay, and a world where every session is
/// relayed is exactly where somebody would be tempted to reach for `hbbr`
/// instead. If that ever happens, this test is where it shows up.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_ends_a_relayed_session_under_the_flag() {
    let w = relayed().up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;
    w.console.grant(&bob.user_id, &laptop.id).await;

    let (mut a_end, mut b_end, forwarded) = bob
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, WAIT)
        .await
        .expect("the granted user was refused");
    assert_relays(&mut a_end, &mut b_end, b"before the revoke", WAIT).await;

    let brokerage = harness::peer::Brokerage {
        local: false,
        conn_audit_ref: forwarded
            .controlled_context
            .into_option()
            .map(|c| c.conn_audit_ref),
        permissions: None,
        addr_a: Vec::new(),
        relay_server: String::new(),
    };
    let mut session = w.session(&laptop, &brokerage).await;
    assert!(session.attributed, "the relayed session was never joined to its decision");

    w.console.revoke(&bob.user_id, &laptop.id).await;
    let took = session
        .wait_for_disconnect(&w.client, DEADLINE)
        .await
        .expect("a relayed session was never told to close after the grant was revoked");
    assert!(took < DEADLINE, "the disconnect took {took:?}");
}

// ---------------------------------------------------------------- fail-closed, and bypasses

/// D1 on the relay gate with the flag on: the api is gone, so every connection
/// is refused — including, and especially, on the path that is now the only one
/// there is.
#[tokio::test(flavor = "multi_thread")]
async fn the_relay_gate_still_fails_closed_under_the_flag() {
    let mut w = relayed().up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    alice
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, WAIT)
        .await
        .expect("the owner could not relay before the outage");

    w.api.kill_now();
    assert!(w.api.is_down(), "the api is still listening");

    let refusal = relay_refusal(&alice, &mut laptop, &w, "with the api killed").await;
    assert!(
        refusal.to_lowercase().contains("unavailable"),
        "the relay gate refused for the wrong reason during the outage: {refusal}"
    );
}

/// The bypass rows again on the relay gate, and the one that matters most: a
/// refused request **never reaches `hbbr`**.
///
/// That is the whole of why an unauthenticated relay is survivable. `hbbr` pairs
/// whoever presents a uuid (T5.7), so the only thing keeping a stranger out is
/// that hbbs never forwards their `RequestRelay` — the device never joins, and
/// the stranger's own join sits parked until it times out with nobody to pair
/// with.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_relay_leaves_the_stranger_parked_with_nobody() {
    let w = relayed().up().await;
    let alice = w.controller("alice").await;
    let laptop = w.device(&alice).await;
    let bob = w.controller("bob").await;

    // Bob asks for a relay he is not entitled to, and joins hbbr himself under
    // the uuid he chose — which is everything a client does, minus the device
    // that hbbs declined to tell.
    let answer = bob
        .request_relay_alone(&laptop.id, REFUSAL)
        .await
        .expect("hbbs said nothing to an ungranted relay request");
    assert!(
        answer.refuse_reason.to_lowercase().contains("do not have access"),
        "the relay gate refused for the wrong reason: {}",
        answer.refuse_reason
    );

    let mut parked = relay_join(&w.relay_addr(), "bobs-own-uuid", &w.hbbs.key).await;
    parked.send_bytes(Bytes::from_static(b"anybody?")).await.unwrap();
    assert!(
        parked.next_timeout(QUIET).await.is_none(),
        "a refused user was paired with something on hbbr"
    );
    assert!(
        !w.hbbr.log().contains(&laptop.id),
        "the refused device's id reached hbbr:\n{}",
        w.hbbr.log()
    );
}

/// No token, and a forged one, on the relay gate under the flag. Cheap to run
/// and the case a regression would reach first: this gate's empty-token branch
/// is a separate call site from the punch gate's.
#[tokio::test(flavor = "multi_thread")]
async fn an_untokened_and_a_forged_client_are_both_refused_on_the_relay_gate() {
    let w = relayed().up().await;
    let alice = w.controller("alice").await;
    let laptop = w.device(&alice).await;

    for (what, token, expected) in [
        ("no token", String::new(), "sign in"),
        (
            "a forged token",
            base64::encode_config([7u8; 32], base64::URL_SAFE_NO_PAD),
            "session has expired",
        ),
    ] {
        let nobody = Controller {
            user_id: String::new(),
            email: "nobody@test.invalid".to_owned(),
            token,
            id: "stranger".to_owned(),
            hbbs_port: w.hbbs.port,
            key: w.hbbs.key.clone(),
        };
        let answer = nobody
            .request_relay_alone(&laptop.id, REFUSAL)
            .await
            .unwrap_or_else(|| panic!("{what}: hbbs said nothing at all"));
        assert!(
            answer.refuse_reason.to_lowercase().contains(expected),
            "{what}: refused for the wrong reason: {}",
            answer.refuse_reason
        );
    }

    // Nothing any of that did reached the relay.
    sleep(Duration::from_millis(300)).await;
    assert!(
        !w.hbbr.log().contains("New relay request"),
        "a refused request still put something on hbbr:\n{}",
        w.hbbr.log()
    );
}
