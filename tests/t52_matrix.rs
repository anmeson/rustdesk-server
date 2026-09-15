//! T5.2 — the multi-user matrix, on both gates.
//!
//! Four rows: a user reaching their own device, a user reaching someone else's,
//! a user reaching one they were granted, and an admin reaching any of them.
//!
//! **Every row runs twice, direct and relayed, and that is the point of the
//! task.** The two are separate gates in separate functions —
//! `handle_punch_hole_request` (T3.3) and `handle_request_relay` (T3.3b) — and
//! the fork's own history is the argument for testing both: before T3.3b the
//! punch gate was complete and the relay path authorized nothing at all, so
//! every row here would have passed while a `RequestRelay` with no token and a
//! deliberately wrong key reached any registered peer. A matrix that tested one
//! gate would have called that system correct.
//!
//! They are also not symmetrical, which is why a shared helper runs both rather
//! than one being assumed from the other:
//!
//!   - the punch gate sends `from_id`; the relay gate sends `from_id: ""`,
//!     because `RequestRelay` names the peer and never the caller;
//!   - a punch refusal comes back as `PunchHoleResponse.other_failure`, a relay
//!     refusal as `RelayResponse.refuse_reason`, and the client prints each
//!     verbatim — so the *words* are part of the assertion;
//!   - on the relay gate the context fields arrive from A and are **overwritten**
//!     with what the api decided; on the punch gate hbbs builds them itself.

mod harness;

use harness::{
    peer::{Brokerage, Controller, Device, Refusal},
    relay::assert_relays,
    world::World,
};
use hbb_common::{rendezvous_proto::*, tokio};
use serde_json::Value;

const WAIT: u64 = 8_000;

/// Which of the two gates a row is being run through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// `PunchHoleRequest` — `handle_punch_hole_request`, T3.3.
    Punch,
    /// `RequestRelay` — `handle_request_relay`, T3.3b. Carries the session
    /// through the real `hbbr` and sends bytes over it, because a gate that
    /// allows and then fails to relay is not an allow.
    Relay,
}

const BOTH: [Gate; 2] = [Gate::Punch, Gate::Relay];

/// What an allowed connection handed the controlled device.
///
/// Both gates deliver the same two fields — `conn_audit_ref` and
/// `control_permissions` — by different routes, so the matrix can assert on one
/// shape either way. That equivalence is itself worth having: it is what makes
/// a relayed session as attributable, and therefore as revocable, as a direct
/// one (T3.3b).
async fn attempt(
    w: &World,
    a: &Controller,
    b: &mut Device,
    gate: Gate,
) -> Result<Brokerage, Refusal> {
    match gate {
        Gate::Punch => a
            .connect(b, ConnType::DEFAULT_CONN, WAIT)
            .await
            .map(|(brokerage, _)| brokerage),
        Gate::Relay => {
            let (mut a_end, mut b_end, forwarded) = a
                .connect_relayed(b, &w.relay_addr(), &w.hbbs.key, WAIT)
                .await?;
            // An allowed relay has to actually relay. `hbbr` authorizes nothing,
            // so if this ever stops working it is hbbs handing out an address
            // nobody can reach — which looks exactly like an authorization
            // failure from the user's side.
            assert_relays(&mut a_end, &mut b_end, b"matrix", WAIT).await;
            Ok(Brokerage {
                local: false,
                conn_audit_ref: forwarded
                    .controlled_context
                    .into_option()
                    .map(|c| c.conn_audit_ref),
                permissions: forwarded.control_permissions.into_option().map(|p| p.permissions),
                addr_a: forwarded.socket_addr.to_vec(),
                relay_server: forwarded.relay_server,
            })
        }
    }
}

/// Every allow must be attributable, whichever gate it came through: without a
/// `conn_audit_ref` on the wire there is nothing to join the session to the
/// decision, and a session nobody can name is a session nobody can revoke.
fn assert_attributable(brokerage: &Brokerage, gate: Gate) {
    let reference = brokerage
        .conn_audit_ref
        .as_deref()
        .unwrap_or_else(|| panic!("{gate:?}: an allowed connection carried no conn_audit_ref"));
    assert_eq!(reference.len(), 36, "{gate:?}: conn_audit_ref is not a uuid: {reference}");
}

// ---------------------------------------------------------------- the rows

#[tokio::test(flavor = "multi_thread")]
async fn a_user_reaches_their_own_device_on_both_gates() {
    for gate in BOTH {
        let w = World::up().await;
        let alice = w.controller("alice").await;
        let mut laptop = w.device(&alice).await;

        let brokerage = attempt(&w, &alice, &mut laptop, gate)
            .await
            .unwrap_or_else(|why| panic!("{gate:?}: alice was refused her own device: {why}"));
        assert_attributable(&brokerage, gate);

        // Ownership is access without limits, so no mask is sent at all. It has
        // to arrive **absent**, not zero: zero is "no permissions", and a client
        // reading one would offer a session that can do nothing.
        assert!(
            brokerage.permissions.is_none(),
            "{gate:?}: an owner was given a permission mask: {:?}",
            brokerage.permissions
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_cannot_reach_someone_elses_device_on_either_gate() {
    for gate in BOTH {
        let w = World::up().await;
        let alice = w.controller("alice").await;
        let bob = w.controller("bob").await;
        let mut laptop = w.device(&alice).await;

        let refusal = attempt(&w, &bob, &mut laptop, gate)
            .await
            .err()
            .unwrap_or_else(|| panic!("{gate:?}: bob reached a device that is not his"));
        // The sentence, not just the refusal: it is shown to the user verbatim
        // and it is the only explanation they get.
        assert_eq!(refusal, "You do not have access to this device.", "{gate:?}");

        // And the device was never told. A refusal that still introduces the
        // peers has leaked the existence of a machine to a stranger, and on the
        // punch gate it would also have started a NAT hole nobody asked for.
        assert!(
            laptop.sock.next_timeout(700).await.is_none(),
            "{gate:?}: the device was contacted for a refused connection"
        );

        // The refusal is in the log, attributed. This is the row an operator
        // sees when someone reports "I cannot connect", and the only record that
        // an attempt happened at all.
        let logged = w.console.sessions(&format!("deviceId={}&outcome=denied", laptop.id)).await;
        assert_eq!(logged["total"], 1, "{gate:?}: {logged}");
        assert_eq!(logged["sessions"][0]["fromUserId"], bob.user_id, "{gate:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_opens_both_gates_and_carries_its_permission_mask() {
    for gate in BOTH {
        // Effectively no decision cache: a grant written mid-test must be read,
        // not remembered from the refusal before it.
        let w = World::builder().auth_cache_ttl_ms(1).up().await;
        let alice = w.controller("alice").await;
        let bob = w.controller("bob").await;
        let mut laptop = w.device(&alice).await;

        assert!(
            attempt(&w, &bob, &mut laptop, gate).await.is_err(),
            "{gate:?}: bob got in before he was granted anything"
        );

        // A restricted grant, because the mask is the field both gates deliver
        // and neither invents: hbbs copies what the api decided and nothing else.
        w.console
            .grant_with(&bob.user_id, &laptop.id, serde_json::json!({ "permissions": 6 }))
            .await;

        let brokerage = attempt(&w, &bob, &mut laptop, gate)
            .await
            .unwrap_or_else(|why| panic!("{gate:?}: the grant did not take effect: {why}"));
        assert_attributable(&brokerage, gate);
        assert_eq!(
            brokerage.permissions,
            Some(6),
            "{gate:?}: the grant's permission mask did not reach the device"
        );
    }
}

/// **The fourth row does not say what the task board said it said.**
///
/// TASK.md and PLAN.md both listed "admin → any device (allow)". `apps/api`
/// refuses it, and refuses it on purpose: `userMayReach` consults ownership and
/// grants and never the role, and T1.6's matrix has asserted exactly that since
/// it was written — "administering the fleet is not the same as being able to
/// control every machine in it. If that ever becomes desirable it has to be an
/// explicit branch in `authorize()`, with an audit story — not a side effect of
/// a role check added elsewhere" (`authorize.test.ts:245`).
///
/// Settled in T5.2 in favour of the code, and both documents corrected. The
/// reasons are worth keeping next to the test, because the cheap change is the
/// wrong one:
///
///   - an implicit allow is a **standing fleet-wide backdoor**, where a grant is
///     a record of who decided and when;
///   - it overlaps break-glass, which exists precisely so that emergency access
///     is signed, time-boxed and audited rather than ambient (decision D1);
///   - `userMayReach` is also what decides whether a session **already running**
///     may stay open (T1.5a), so an admin session allowed by role alone would
///     have no grant to revoke and nothing to terminate it.
///
/// An admin is not locked out: the console grants in one click, which is the
/// point — the access exists, and it leaves a trail.
#[tokio::test(flavor = "multi_thread")]
async fn an_admin_is_refused_until_they_grant_themselves_access() {
    for gate in BOTH {
        let w = World::builder().auth_cache_ttl_ms(1).up().await;
        let alice = w.controller("alice").await;
        let root = w.controller_with_role("root", "admin").await;
        let mut laptop = w.device(&alice).await;

        let refusal = attempt(&w, &root, &mut laptop, gate)
            .await
            .err()
            .unwrap_or_else(|| {
                panic!("{gate:?}: an admin reached a device by role alone — see this test's note")
            });
        assert_eq!(refusal, "You do not have access to this device.", "{gate:?}");

        // The console is the way in, and it is one call — the same one any
        // other user's access goes through.
        w.console.grant(&root.user_id, &laptop.id).await;

        let brokerage = attempt(&w, &root, &mut laptop, gate)
            .await
            .unwrap_or_else(|why| panic!("{gate:?}: an admin's own grant did not work: {why}"));
        assert_attributable(&brokerage, gate);

        // And the grant is visible as a grant, which is the whole difference
        // between this and an implicit allow.
        let grants = w
            .console
            .get(&format!("/api/admin/grants?deviceId={}", laptop.id))
            .await;
        assert_eq!(grants["total"], 1, "{gate:?}: {grants}");
        assert_eq!(grants["grants"][0]["userId"], root.user_id, "{gate:?}");
    }
}

// ---------------------------------------------------------------- the pair

/// The clause T3.3b deferred to this task: a connect that falls back to a relay
/// is **one** decision and **one** row, not two.
///
/// It matters for the session log, which is the audit trail: two rows for one
/// connection would double every relayed session and leave the second one
/// unjoinable, because only one `conn_audit_ref` ever reaches the device. The
/// mechanism is the decision cache — the same (token, peer) inside its TTL is
/// answered from memory — so this is also the test that says the cache is doing
/// the job it was added for rather than merely existing.
#[tokio::test(flavor = "multi_thread")]
async fn a_punch_that_falls_back_to_a_relay_is_one_decision_and_one_row() {
    // **The window is configured, not assumed.** The property is "a fallback
    // *inside* the decision cache's window is one decision", and a real client's
    // fallback follows its punch by seconds — well inside the 5 s default. On a
    // loaded machine this test's two connects can drift past it, at which point
    // the relay is legitimately a second decision with a second ref and a second
    // row, and the test fails for a reason that has nothing to do with the code.
    // Setting the TTL puts the window under the test's control instead of the
    // scheduler's.
    let w = World::builder().auth_cache_ttl_ms(30_000).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let (punched, _) = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the punch was refused");

    // The fallback a real client sends when the hole never opens: a fresh TCP
    // connection, same peer, same token, seconds later (`client.rs:1720`).
    let (mut a_end, mut b_end, forwarded) = alice
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, WAIT)
        .await
        .expect("the relay fallback was refused after the punch was allowed");
    assert_relays(&mut a_end, &mut b_end, b"fallback", WAIT).await;

    let relayed_ref = forwarded
        .controlled_context
        .into_option()
        .map(|c| c.conn_audit_ref)
        .expect("the fallback carried no conn_audit_ref");
    assert_eq!(
        Some(&relayed_ref),
        punched.conn_audit_ref.as_ref(),
        "the fallback was given a different audit ref than the punch it continued"
    );

    let logged = w.console.sessions(&format!("deviceId={}", laptop.id)).await;
    assert_eq!(
        logged["total"], 1,
        "one connection produced {} rows in the session log: {logged}",
        logged["total"]
    );
}

/// Two users on one device, at the same time, on the two gates at once — the
/// case a single-client harness cannot produce at all.
///
/// The failure this guards against is a decision cache keyed too loosely: cache
/// on the peer id alone and the second user inherits the first one's allow. That
/// would be invisible to every row above, because each of them uses one token.
#[tokio::test(flavor = "multi_thread")]
async fn one_device_answers_two_users_differently_at_the_same_time() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let bob = w.controller("bob").await;
    let mut laptop = w.device(&alice).await;

    // Alice first, so her allow is the freshest thing in the cache.
    let allowed = alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("alice was refused her own device");
    assert!(allowed.0.conn_audit_ref.is_some());

    let refusal = bob
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect_err("bob inherited alice's decision");
    assert_eq!(refusal, "You do not have access to this device.");

    // And the other way round on the relay gate, within the same TTL.
    let denied = match bob
        .connect_relayed(&mut laptop, &w.relay_addr(), &w.hbbs.key, 4_000)
        .await
    {
        Ok(_) => panic!("bob was relayed to a device that is not his"),
        Err(reason) => reason,
    };
    assert_eq!(denied, "You do not have access to this device.");

    let log: Value = w.console.sessions(&format!("deviceId={}", laptop.id)).await;
    let outcomes: Vec<&str> = log["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["outcome"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(outcomes.len(), 3, "{log}");
    assert_eq!(outcomes.iter().filter(|o| **o == "denied").count(), 2, "{log}");
    assert_eq!(outcomes.iter().filter(|o| **o == "allowed").count(), 1, "{log}");
}
