//! T5.3 — revocation, including of sessions already running.
//!
//! Decision D2: revoking access ends the session it was authorizing, without
//! anyone having to go and kill it. Two things make that hard to get right, and
//! both are asserted here rather than reasoned about.
//!
//! **It cannot be done at the relay.** `hbbr` sees only the relay *fallback*, so
//! a relay-side kill misses every direct P2P session — and a direct session is
//! the normal case, not the exception. It also has no per-session handle to kill
//! with: `PEERS` is keyed by an ephemeral uuid nobody else ever learns. So the
//! channel is the controlled device's own heartbeat, which works the same for
//! both. The task board asks for the **direct** case explicitly, because that is
//! the one a plausible wrong design would miss, and it is tested first.
//!
//! **A revocation can only reach a session it can name.** The whole chain has to
//! hold: `authorize()` mints a `conn_audit_ref`, hbbs copies it into
//! `ControlledContext` (T3.3), the device echoes it on its `action: "new"` audit
//! post, and `/api/audit/conn` merges the two rows. Break any link and the
//! session is *unattributed* — still reachable by an explicit revoke, by design,
//! but invisible to the unattended sweep. These tests assert the join happened,
//! so a silent break shows up here rather than as a revocation that quietly
//! finds nothing.
//!
//! Latency is measured, not assumed: the floor is the 3 s live-session heartbeat
//! (`TIME_CONN`), and a number well under it would mean this harness is beating
//! faster than a real client.

mod harness;

use std::time::Duration;

use harness::{peer::Controller, session::BEAT, world::World};
use hbb_common::{rendezvous_proto::*, tokio};

const WAIT: u64 = 8_000;

/// Room for two beats plus the round trips around them. A revocation that needs
/// more than this is not "slightly slow", it has missed a beat — which is the
/// symptom of the instruction being queued after the drain rather than before.
const DEADLINE: Duration = Duration::from_secs(10);

/// A granted user with a live session on someone else's device, which is the
/// setup every test below starts from.
async fn granted_with_a_live_session(
    w: &World,
    owner: &Controller,
    guest: &Controller,
) -> (harness::peer::Device, harness::session::Session) {
    let mut laptop = w.device(owner).await;
    w.console.grant(&guest.user_id, &laptop.id).await;

    let (brokerage, _) = guest
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the granted user was refused");
    let session = w.session(&laptop, &brokerage).await;
    assert!(
        session.attributed,
        "the session was never joined to its decision — revocation would have nothing to find"
    );
    (laptop, session)
}

// ---------------------------------------------------------------- next connection

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_user_is_refused_the_next_connection_in_the_right_words() {
    // Effectively no decision cache, so this measures the revoke and not the
    // five seconds a positive decision may be reused.
    let w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;
    w.console.grant(&bob.user_id, &laptop.id).await;

    assert!(
        bob.connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT).await.is_ok(),
        "the grant never worked in the first place"
    );

    w.console.revoke(&bob.user_id, &laptop.id).await;

    // "Withdrawn", not "you do not have access": a revoked grant is kept as a
    // record (T1.5a), so the api can tell the user which of the two happened,
    // and the client prints this sentence verbatim.
    let refusal = bob
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect_err("a revoked user still connected");
    assert_eq!(refusal, "Your access to this device has been withdrawn.");

    // The relay gate too — it is a separate check on a separate path.
    let relayed = match bob
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, 4_000)
        .await
    {
        Ok(_) => panic!("a revoked user was still relayed"),
        Err(reason) => reason,
    };
    assert_eq!(relayed, "Your access to this device has been withdrawn.");
}

/// The window the cache buys a revoked user, stated as a test so nobody
/// rediscovers it as a bug.
///
/// `AUTH_CACHE_TTL_MS` (5 s by default) is how long a positive decision may be
/// reused, so a revoke does not stop the *next* connection instantly. It does
/// not extend to sessions already running — those are the heartbeat's job, below
/// — and that distinction is the one worth being explicit about.
#[tokio::test(flavor = "multi_thread")]
async fn the_decision_cache_delays_a_revocation_and_then_stops_it() {
    // Long enough that the revoke-then-connect below is inside the window even
    // on a loaded machine — the subject is the cache, so the test must not be
    // racing it — and short enough that waiting it out does not pad the run.
    let ttl = 10_000;
    let w = World::builder().auth_cache_ttl_ms(ttl).up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;
    w.console.grant(&bob.user_id, &laptop.id).await;

    bob.connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the grant never worked");
    w.console.revoke(&bob.user_id, &laptop.id).await;

    // Inside the window: still allowed, from memory, without asking the api.
    assert!(
        bob.connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT).await.is_ok(),
        "the cached decision was not reused — this test is no longer measuring the cache"
    );

    w.let_auth_cache_lapse(ttl).await;
    let refusal = bob
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect_err("the cache never expired");
    assert_eq!(refusal, "Your access to this device has been withdrawn.");
}

// ---------------------------------------------------------------- live sessions

/// **The headline of T5.3, and deliberately the direct P2P case.**
#[tokio::test(flavor = "multi_thread")]
async fn revoking_ends_a_live_direct_session_without_operator_action() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let (laptop, mut session) = granted_with_a_live_session(&w, &alice, &bob).await;

    // Nothing here touches hbbr. The session was brokered peer to peer, so a
    // relay-side kill would have had nothing to kill.
    assert!(
        !w.hbbr.log().contains("New relay request"),
        "this was supposed to be a direct session"
    );

    let result = w.console.revoke(&bob.user_id, &laptop.id).await;
    assert_eq!(
        result["results"][0]["disconnectsQueued"], 1,
        "the revoke queued no disconnect: {result}"
    );

    let took = session
        .wait_for_disconnect(&w.client, DEADLINE)
        .await
        .expect("a revoked session was never told to close");
    // The floor is one beat; the ceiling is two. Printed because T5.3 asks for
    // the number, not just the outcome.
    println!("direct session revoked and closed in {took:?} (beat is {BEAT:?})");
    assert!(
        took < BEAT * 3,
        "revocation took {took:?}, which is more than two heartbeats"
    );

    // And it is over: the device reports the session gone and the log closes it.
    session.close(&w.client).await;
    let row = w
        .session_row(&laptop.id, session.conn_id)
        .await
        .expect("the session vanished from the log");
    assert!(row["closedAt"].is_string(), "the session was never closed out: {row}");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_ends_a_live_relayed_session_too() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;
    w.console.grant(&bob.user_id, &laptop.id).await;

    let (mut a_end, mut b_end, forwarded) = bob
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, WAIT)
        .await
        .expect("the granted user was refused a relay");
    harness::relay::assert_relays(&mut a_end, &mut b_end, b"live", WAIT).await;

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
    assert!(session.attributed, "a relayed session was not attributable");

    w.console.revoke(&bob.user_id, &laptop.id).await;
    let took = session
        .wait_for_disconnect(&w.client, DEADLINE)
        .await
        .expect("a revoked relayed session was never told to close");
    println!("relayed session revoked and closed in {took:?}");

    // The instruction reached the controlled device, which is the point: it did
    // not go through hbbr, and hbbr was never asked to do anything about it.
    assert!(
        !w.hbbr.log().contains("disconnect"),
        "something tried to terminate a session through the relay"
    );
}

/// The case with **no operator at all**: a grant that runs out while somebody is
/// using it.
///
/// This is `enforceLiveSessionAccess` (T1.5a), which rides the same heartbeat.
/// `authorize()` starts denying the moment the clock passes, but until T1.5a
/// nothing told the session already running, so a two-hour grant lasted as long
/// as nobody hung up.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_that_expires_mid_session_ends_it() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;

    let expires =
        chrono::Utc::now() + chrono::Duration::seconds(6);
    w.console
        .grant_with(
            &bob.user_id,
            &laptop.id,
            serde_json::json!({ "expiresAt": expires.to_rfc3339() }),
        )
        .await;

    let (brokerage, _) = bob
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the timed grant did not authorize");
    let mut session = w.session(&laptop, &brokerage).await;
    assert!(session.attributed);

    let took = session
        .wait_for_disconnect(&w.client, Duration::from_secs(25))
        .await
        .expect("an expired grant left its session running");
    println!("session ended {took:?} after it opened, by expiry alone");

    let row = w
        .session_row(&laptop.id, session.conn_id)
        .await
        .expect("the session vanished from the log");
    assert_eq!(row["fromUserId"], bob.user_id, "{row}");
}

// ---------------------------------------------------------------- what must NOT die

/// Revoking one user must not disconnect another, on the same device, at the
/// same moment.
///
/// The failure mode is not hypothetical: `liveSessionsFor` deliberately
/// terminates sessions it *cannot attribute* along with the revoked user's, so
/// the line between "cannot attribute" and "belongs to someone else" is the only
/// thing protecting the second user. That line is the `conn_audit_ref` join.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_one_user_leaves_another_users_session_running() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;
    w.console.grant(&bob.user_id, &laptop.id).await;

    // Alice owns it; bob was granted it. Both are connected at once.
    let (alice_broker, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the owner was refused");
    let mut alice_session = w.session(&laptop, &alice_broker).await;

    let (bob_broker, _) = bob
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the granted user was refused");
    let mut bob_session = w.session(&laptop, &bob_broker).await;
    assert!(alice_session.attributed && bob_session.attributed);

    // The device reports both, as a real one does in a single heartbeat.
    alice_session.also_live = vec![bob_session.conn_id];
    bob_session.also_live = vec![alice_session.conn_id];

    let result = w.console.revoke(&bob.user_id, &laptop.id).await;
    assert_eq!(
        result["results"][0]["collateral"], 0,
        "the revoke dropped sessions it could not attribute: {result}"
    );

    let took = bob_session
        .wait_for_disconnect(&w.client, DEADLINE)
        .await
        .expect("the revoked user's session survived");
    println!("the revoked user's session closed in {took:?}");

    alice_session
        .assert_undisturbed(&w.client, BEAT * 3)
        .await;
}

/// Removing a grant from someone who owns the device anyway must not disconnect
/// them.
///
/// `revokeGrantAndDisconnect` checks ownership before queueing anything, because
/// a disconnect with no security purpose is still somebody's session ending
/// mid-sentence — and the redundant-grant case is ordinary console tidying.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_redundant_grant_from_an_owner_disconnects_nothing() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    // A grant on top of ownership: redundant, and entirely normal to have.
    w.console.grant(&alice.user_id, &laptop.id).await;

    let (brokerage, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the owner was refused");
    let mut session = w.session(&laptop, &brokerage).await;

    let result = w.console.revoke(&alice.user_id, &laptop.id).await;
    assert_eq!(
        result["results"][0]["stillHasAccess"], true,
        "the owner was treated as having lost access: {result}"
    );
    assert_eq!(result["results"][0]["disconnectsQueued"], 0, "{result}");

    session.assert_undisturbed(&w.client, BEAT * 3).await;

    // And she can still connect, because she still owns it.
    assert!(
        alice.connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT).await.is_ok(),
        "the owner lost access to her own device"
    );
}
