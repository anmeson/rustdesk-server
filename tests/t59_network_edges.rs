//! T5.9 — the connect path when the network, or the token, does not hold still.
//!
//! Three situations the task board names, and each one has a "must" and a "must
//! not" that are easy to get backwards:
//!
//!   - **a dropped handshake, retried.** The client sends the same
//!     `PunchHoleRequest` up to three times. That must be *one* decision and one
//!     audit row, not three — and the decision cache is the only thing making it
//!     so (`auth.rs:812`). Past the cache it must be a *fresh* decision with a
//!     fresh `conn_audit_ref`, or two sessions would share one handle and
//!     revoking either would find the wrong one.
//!   - **a token expiring mid-session.** The session must survive it. This is
//!     deliberate and stated in `services/authorize.ts`: `userMayReach`
//!     excludes the token check, because re-testing a credential against a
//!     connection that is already open would mean an expiry — or a sign-out —
//!     killing a remote-control session somebody is in the middle of using. But
//!     the *next* connection must be refused.
//!   - **a token refreshed during a connection.** Signing in again issues a
//!     second token without revoking the first, so both work; the new one must
//!     get its own decision and its own ref, and the session opened with the old
//!     one must not notice.
//!
//! The "must not" halves are the ones worth the runtime here. Each is a
//! `assert_undisturbed` over several real 3 s heartbeats, because
//! `enforceLiveSessionAccess` runs unattended against every live session in the
//! fleet — a mistake there does not disconnect one person, it disconnects
//! everybody.

mod harness;

use std::time::Duration;

use harness::{
    peer::{Brokerage, Controller},
    world::World,
};
use hbb_common::{
    rendezvous_proto::*,
    tokio::{self, time::sleep},
};

const WAIT: u64 = 8_000;
const REFUSAL: u64 = 2_500;
const AUTHORIZE_PATH: &str = "/api/internal/authorize";

/// Three beats' worth. Long enough that the unattended sweep has run against
/// this session several times and declined to kill it.
const PATIENCE: Duration = Duration::from_secs(9);

fn reference(brokerage: &Brokerage) -> String {
    brokerage
        .conn_audit_ref
        .clone()
        .filter(|r| !r.is_empty())
        .expect("the brokerage carried no conn_audit_ref, so the session is unrevocable")
}

// ---------------------------------------------------------------- a dropped handshake

/// A retried handshake is one connection, and must be one decision.
///
/// The client's own retry is indistinguishable, on the wire, from a second
/// connection attempt — same token, same id, same conn type. The cache is what
/// makes it one: same `conn_audit_ref` back, and the api asked once.
#[tokio::test(flavor = "multi_thread")]
async fn a_retried_handshake_is_one_decision_and_one_audit_ref() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    let before = w.api.requests_to(AUTHORIZE_PATH);

    let (first, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the first attempt was refused");
    // Two more, as a client retrying a handshake that did not complete. Each
    // opens its own TCP connection to hbbs, exactly as the real retry does.
    let (second, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the retry was refused");
    let (third, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the second retry was refused");

    assert_eq!(reference(&first), reference(&second), "the retry got a different audit ref");
    assert_eq!(reference(&first), reference(&third), "the second retry got a different audit ref");
    assert_eq!(
        w.api.requests_to(AUTHORIZE_PATH) - before,
        1,
        "three attempts at one connection cost more than one decision"
    );
}

/// Past the cache, a reconnect is a **different** connection and must get its
/// own handle. Sharing one would mean the console shows one session where there
/// are two, and revoking would end whichever the join happened to find.
#[tokio::test(flavor = "multi_thread")]
async fn a_reconnect_past_the_cache_gets_a_fresh_decision_and_a_fresh_ref() {
    let w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    let before = w.api.requests_to(AUTHORIZE_PATH);

    let (first, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the first connection was refused");
    let (second, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the reconnection was refused");

    assert_ne!(
        reference(&first),
        reference(&second),
        "two separate connections were given the same audit ref — one of them is unrevocable"
    );
    assert_eq!(
        w.api.requests_to(AUTHORIZE_PATH) - before,
        2,
        "a reconnection past the cache did not cost a decision"
    );

    // Both are real sessions the console can see and revoke independently.
    let one = w.session(&laptop, &first).await;
    let two = w.session(&laptop, &second).await;
    assert!(one.attributed && two.attributed, "a reconnection produced an unattributed session");
    assert_ne!(one.conn_id, two.conn_id);
}

/// The device's own network dropping and coming back. It comes back on a new UDP
/// source port — which is what a NAT rebind or a wifi hop looks like to hbbs —
/// and the next brokerage must reach it **there**, not at the address it used to
/// have.
///
/// **The recovery is a `RegisterPeer`, and that is not a detail of this test.**
/// A second `RegisterPk` from a device whose uuid, key and IP are unchanged
/// leaves the peer table alone: `update_pk` is skipped when nothing changed
/// (`rendezvous_server.rs:603`), so the stored `socket_addr` stays stale and the
/// brokerage goes to an address nobody is listening on. The only path that moves
/// an existing peer is `update_addr` (`:939`), on the heartbeat — which is what
/// a real client sends, and what it sends *first* after the network comes back.
/// Written the other way round this test failed, and the symptom was a
/// connection that hung rather than anything that pointed here.
///
/// The old socket getting nothing is the half that matters: a peer table that
/// kept the stale address would broker connections into a black hole.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_drops_and_comes_back_is_brokered_at_its_new_address() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let mut old_socket = std::mem::replace(&mut laptop.sock, harness::udp_socket().await);

    // The keepalive, from where the device is now. `request_pk` comes back false
    // — same IP, known key — which is the branch that moves the address.
    let request_pk = harness::register_peer_on(&mut laptop.sock, w.hbbs.port, &laptop.id, 3_000)
        .await
        .expect("hbbs did not answer the heartbeat from the new address");
    assert!(
        !request_pk,
        "hbbs asked for the public key again, which is the branch that does *not* move the address"
    );

    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the device could not be reached after it came back");

    // And nothing was sent to where it used to be.
    assert!(
        old_socket.next_timeout(800).await.is_none(),
        "hbbs brokered a connection to the device's old address"
    );
}

/// The other half of the same fact, pinned so that a future change to
/// `update_pk`'s `changed` test is deliberate: a device that comes back and
/// sends only `RegisterPk` is **not** moved, and connections to it go to the old
/// address.
///
/// This is upstream's behaviour and it is harmless in the field, because a real
/// client sends `RegisterPeer` every 15 s and `RegisterPk` almost never. It is
/// recorded because it is the second time it has cost this milestone an
/// afternoon — the first was T5.6, where the same skipped write let a device age
/// out of `REG_TIMEOUT` while it was apparently registering.
#[tokio::test(flavor = "multi_thread")]
async fn re_registering_the_public_key_alone_does_not_move_a_device() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let mut old_socket = std::mem::replace(&mut laptop.sock, harness::udp_socket().await);
    let result = harness::register_pk_on(
        &mut laptop.sock,
        w.hbbs.port,
        &laptop.id,
        &laptop.uuid,
        &laptop.pk,
        3_000,
    )
    .await;
    assert_eq!(
        result,
        Some(register_pk_response::Result::OK),
        "hbbs refused the re-registration outright, which is a different thing entirely"
    );

    // Answered OK, and the peer table is untouched: the brokerage still goes to
    // the socket the device has stopped using.
    let _watcher = alice.punch_alone(&laptop.id).await;
    assert!(
        old_socket.next_timeout(2_000).await.is_some(),
        "the brokerage did not go to the old address — `update_pk`'s `changed` test has moved,          and both this test and the one above it need rereading"
    );
    assert!(
        laptop.sock.next_timeout(800).await.is_none(),
        "the brokerage reached the new address, which a bare RegisterPk is not supposed to do"
    );
}

// ---------------------------------------------------------------- the token moves under a session

/// **A token expiring must not end a session that is already running**, and this
/// is a design decision rather than an accident: `userMayReach` deliberately
/// excludes the token check (`services/authorize.ts`), because a remote-control
/// session dying at a 30-day boundary — or the moment somebody signs out on
/// their laptop — is indistinguishable from a network fault to whoever is on the
/// call.
///
/// The other half is asserted in the same test, because one without the other is
/// either a hole or a hazard: the **next** connection is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_expiring_mid_session_does_not_end_the_session() {
    let w = World::builder()
        .auth_cache_ttl_ms(1)
        .api_env("CLIENT_TOKEN_TTL_SECONDS", "3")
        .up()
        .await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let (brokerage, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the connection was refused while the token was still valid");
    let mut session = w.session(&laptop, &brokerage).await;
    assert!(session.attributed, "the session was never joined to its decision");

    // Past the expiry, with the session beating throughout.
    sleep(Duration::from_millis(3_500)).await;

    session.assert_undisturbed(&w.client, PATIENCE).await;

    // And the next connection is refused, which is what makes the above safe
    // rather than a hole: the credential is dead for anything new.
    let refusal = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, REFUSAL)
        .await
        .err()
        .expect("an expired token opened a new connection");
    assert!(
        refusal.to_lowercase().contains("session has expired"),
        "refused for the wrong reason: {refusal}"
    );
}

/// The same shape, produced by a person rather than by a clock: the user signs
/// out on their laptop while a session is running. `POST /api/logout` revokes
/// the token outright — a stronger thing than letting it expire — and the live
/// session must still survive it.
#[tokio::test(flavor = "multi_thread")]
async fn signing_out_mid_session_does_not_end_the_session_either() {
    let w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let (brokerage, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the connection was refused before the sign-out");
    let mut session = w.session(&laptop, &brokerage).await;

    w.client.logout(&alice.token).await;

    session.assert_undisturbed(&w.client, PATIENCE).await;

    let refusal = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, REFUSAL)
        .await
        .err()
        .expect("a revoked token opened a new connection");
    assert!(
        refusal.to_lowercase().contains("session has expired"),
        "refused for the wrong reason: {refusal}"
    );
}

/// A refresh: the client signs in again and holds a new token while the old
/// session runs. Signing in does not revoke anything (`account.ts:54`), so both
/// tokens are live — and the two must be separate decisions with separate
/// handles, or the second connection would complete the first one's audit row.
#[tokio::test(flavor = "multi_thread")]
async fn a_refreshed_token_opens_its_own_connection_and_leaves_the_old_one_alone() {
    let w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let (first, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the first connection was refused");
    let mut original = w.session(&laptop, &first).await;

    // The refresh, through the real endpoint: same account, same machine.
    let refreshed = Controller {
        token: w
            .client
            .login(&alice.email, &alice.id, &format!("uuid-{}", alice.id))
            .await,
        user_id: alice.user_id.clone(),
        email: alice.email.clone(),
        id: alice.id.clone(),
        hbbs_port: w.hbbs.port,
        key: w.hbbs.key.clone(),
    };
    assert_ne!(refreshed.token, alice.token, "signing in again returned the same token");

    let (second, _) = refreshed
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the refreshed token was refused");
    assert_ne!(
        reference(&first),
        reference(&second),
        "the refreshed token was given the first connection's audit ref"
    );

    let mut newer = w.session(&laptop, &second).await;
    assert!(newer.attributed, "the refreshed connection produced an unattributed session");

    // The device now holds both, and reports both — which is what a real client
    // does and what stops the api reading one as ended.
    original.also_live = vec![newer.conn_id];
    newer.also_live = vec![original.conn_id];
    original.assert_undisturbed(&w.client, PATIENCE).await;

    // And the old token still works, because signing in again revokes nothing.
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("signing in again invalidated the token the client was still using");
}

/// A session that ends properly and a controller that comes back. The point is
/// the pair: the closed session is gone from the console's live list, and the
/// new connection is a new session rather than a resurrection of the old one.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_that_ends_and_reconnects_is_a_new_session() {
    let w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let (first, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the first connection was refused");
    let original = w.session(&laptop, &first).await;
    original.close(&w.client).await;

    let (second, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the reconnection was refused");
    let mut reopened = w.session(&laptop, &second).await;
    assert_ne!(original.conn_id, reopened.conn_id);
    assert!(reopened.attributed, "the reconnection produced an unattributed session");

    // The reopened session is not collaterally affected by the closed one — a
    // sweep that keyed on the device rather than the connection would kill it.
    reopened.assert_undisturbed(&w.client, PATIENCE).await;

    let closed = w
        .session_row(&laptop.id, original.conn_id)
        .await
        .expect("the closed session left no row at all");
    assert_eq!(
        closed["state"].as_str(),
        Some("closed"),
        "the closed session is still open as far as the console is concerned: {closed}"
    );
    assert!(
        closed["closedAt"].is_string(),
        "the closed session has no closing time: {closed}"
    );
}
