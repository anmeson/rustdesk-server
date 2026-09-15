//! T5.1 — the standing harness, proved against itself.
//!
//! Everything in Milestone 5 is written against `harness::world`, so these are
//! the tests that say the foundation holds: a real `apps/api` decides, a real
//! `hbbs` obeys it, a real `hbbr` carries the bytes, and two clients with two
//! tokens see two different answers. They are not the matrix — that is T5.2 —
//! they are the proof that a failing row in T5.2 would mean something.
//!
//! Each test brings up its own world. Read `harness/world.rs` before adding one:
//! the boot order is forced and the comment there says why.

mod harness;

use harness::{
    peer::next_device_id,
    relay::assert_relays,
    world::World,
};
use hbb_common::{rendezvous_proto::*, tokio};

/// How long to wait for something that has to cross four processes.
const WAIT: u64 = 8_000;

#[tokio::test(flavor = "multi_thread")]
async fn the_whole_stack_comes_up_and_talks_to_itself() {
    let w = World::up().await;

    // The api is the one nobody else can vouch for: hbbs is proved by the tests
    // below, hbbr by the relay one, but a world whose api is wedged would fail
    // every test with a fail-closed denial and explain none of them.
    let health = w.console.get("/api/admin/me").await;
    assert_eq!(health["user"]["role"], "admin", "the seeded admin is not an admin: {health}");

    assert!(
        w.hbbs.wait_for_log("Listening on tcp/udp", WAIT).await,
        "hbbs never announced its listener:\n{}",
        w.hbbs.log()
    );
    assert!(
        w.hbbr.wait_for_log("Listening on tcp", WAIT).await,
        "hbbr never announced its listener:\n{}",
        w.hbbr.log()
    );
    // hbbs and hbbr must share a key or every relay is refused, and an hbbr with
    // *no* key relays for anybody (docs/CONTEXT.md §7).
    assert!(!w.hbbs.key.is_empty());
    assert!(
        w.hbbr.log().contains(&w.hbbs.key),
        "hbbr is not holding hbbs's key:\n{}",
        w.hbbr.log()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_reaches_their_own_device_and_the_real_api_said_so() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let (brokerage, response) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("alice was refused her own device");

    // The brokerage carries the two fields Milestone 3 added, and this is the
    // first time they have come from the real api rather than from a stub: the
    // ref is a uuid minted by `authorize()`, not the string a stub was told to
    // return.
    let conn_audit_ref = brokerage.conn_audit_ref.expect("no conn_audit_ref reached the device");
    assert_eq!(conn_audit_ref.len(), 36, "not a uuid: {conn_audit_ref}");
    // Ownership is unlimited access, so the api sends no permission mask at all
    // — which must arrive as an absent field, not as a zero one. Zero is "no
    // permissions", and forwarding it would silently strip a session of
    // everything it is allowed to do.
    assert!(
        brokerage.permissions.is_none(),
        "an owner got a permission mask: {:?}",
        brokerage.permissions
    );
    assert!(response.other_failure.is_empty(), "{}", response.other_failure);

    // And the decision is in the session log, joinable to the session that is
    // about to exist. Without this row a revocation has nothing to find.
    let sessions = w.console.sessions(&format!("deviceId={}", laptop.id)).await;
    assert_eq!(sessions["sessions"][0]["outcome"], "allowed", "{sessions}");
    assert_eq!(sessions["sessions"][0]["fromUserId"], alice.user_id, "{sessions}");
    assert_eq!(sessions["sessions"][0]["connAuditRef"], conn_audit_ref, "{sessions}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_user_is_refused_the_same_device_in_words() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;

    let refusal = bob
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect_err("bob reached a device that is not his");

    // The exact sentence, because it is shown to the user verbatim — it becomes
    // `PunchHoleResponse.other_failure` and the client prints it.
    assert_eq!(refusal, "You do not have access to this device.");

    // Two tokens, two answers, one device: the thing a single-client harness
    // cannot show at all.
    assert!(
        alice
            .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
            .await
            .is_ok(),
        "alice lost access to her own device"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_written_in_the_console_changes_what_hbbs_decides() {
    // Effectively no decision cache: this test is about the console and hbbs
    // agreeing, and a five-second reuse window would make it about the cache
    // instead. One millisecond, not zero — hbbs refuses to boot on zero.
    let w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;

    assert!(
        bob.connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT).await.is_err(),
        "bob reached the device before he was granted anything"
    );

    w.console.grant(&bob.user_id, &laptop.id).await;

    let (brokerage, _) = bob
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the grant did not take effect");
    assert!(brokerage.conn_audit_ref.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_session_is_relayed_and_the_bytes_come_out_the_other_side() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let (mut a_end, mut b_end, forwarded) = alice
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, WAIT)
        .await
        .expect("alice was refused a relay to her own device");

    // T3.3b: the relay gate authorizes in its own right, and hbbs **overwrites**
    // the two context fields with what the api decided rather than forwarding
    // what A sent. A stub could not tell the two apart; a real ref can.
    let relayed_ref = forwarded
        .controlled_context
        .into_option()
        .map(|c| c.conn_audit_ref)
        .expect("no conn_audit_ref survived into the relay");
    assert_eq!(relayed_ref.len(), 36, "not a uuid: {relayed_ref}");

    // The product, not the log line: hbbr pairs two sockets and pumps bytes.
    assert_relays(&mut a_end, &mut b_end, b"hello from the controller", WAIT).await;
    assert_relays(&mut b_end, &mut a_end, b"and back from the device", WAIT).await;

    assert!(
        w.hbbr.log().contains("got paired"),
        "hbbr never reported pairing:\n{}",
        w.hbbr.log()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_relay_never_reaches_the_device_or_the_relay() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;

    // `expect_err` is unavailable here: the Ok side is a pair of live sockets
    // and `FramedStream` is not `Debug`.
    let refusal = match bob
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, 3_000)
        .await
    {
        Ok(_) => panic!("bob was relayed to a device that is not his"),
        Err(reason) => reason,
    };
    assert_eq!(refusal, "You do not have access to this device.");

    // The device was never told, and hbbr was never asked. A refusal that still
    // introduces the peers is not a refusal.
    assert!(
        laptop.sock.next_timeout(700).await.is_none(),
        "the device was contacted anyway"
    );
    assert!(
        !w.hbbr.log().contains("New relay request"),
        "hbbr saw a request for a refused connection:\n{}",
        w.hbbr.log()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn enrolment_runs_against_the_real_api_too() {
    let w = World::builder().enrol_required(true).up().await;
    let alice = w.controller("alice").await;

    // Deployed through `POST /api/devices/deploy`, so the api knows it.
    let laptop = w.device(&alice).await;
    assert_eq!(w.console.device(&laptop.id).await["status"], "enrolled");

    // An id nobody deployed.
    //
    // **The first answer is `OK`, and that is not a bug.** hbbs has never heard
    // of this id, so it has no verdict to act on; it answers OK, writes nothing
    // to the peer table, and asks the api off the loop — the deferred branch at
    // `rendezvous_server.rs:564`. The refusal lands on the next registration.
    // A test that stopped at the first answer would read this as the gate being
    // open, which is exactly backwards.
    let stranger = next_device_id();
    let mut sock = harness::udp_socket().await;
    let first = harness::register_pk_on(
        &mut sock,
        w.hbbs.port,
        &stranger,
        b"uuid-stranger",
        b"pk-stranger",
        WAIT,
    )
    .await;
    assert_eq!(first, Some(register_pk_response::Result::OK), "the first contact should defer");

    let mut refused = None;
    for _ in 0..8 {
        refused = harness::register_pk_on(
            &mut sock,
            w.hbbs.port,
            &stranger,
            b"uuid-stranger",
            b"pk-stranger",
            2_000,
        )
        .await;
        if refused == Some(register_pk_response::Result::NOT_DEPLOYED) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
    assert_eq!(
        refused,
        Some(register_pk_response::Result::NOT_DEPLOYED),
        "an undeployed device was allowed to claim an id"
    );

    // And it never took the id: nothing is in the peer table for it, so a
    // connection to it fails as an unknown peer rather than reaching a stranger.
    assert!(
        !w.hbbs.log().contains(&format!("update_pk {stranger}")),
        "an undeployed device was written into the peer table"
    );
}
