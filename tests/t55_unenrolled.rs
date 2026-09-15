//! T5.5 — the unenrolled device, against the real `apps/api`.
//!
//! Registration is not the connect path and fails differently. A connection is
//! one request with a human waiting on it; registration is a **UDP keepalive
//! loop**, so a mistake here does not produce an error somebody reads, it
//! produces a retry storm — every device in the fleet, every few seconds,
//! against the api that is already having a bad day. That is why T3.5.3 makes
//! this path fail *open* while the connect path fails closed, and why the
//! interesting assertions below are about **how many requests arrived**.
//!
//! Three mechanisms stand between a registering fleet and the api, and all three
//! are checked here rather than trusted:
//!
//!   - the **verdict cache** in the peer table (`ENROL_CACHE_TTL_MS`), so a
//!     settled answer is reused rather than re-asked;
//!   - the **in-flight claim**, so one device cannot have two questions
//!     outstanding;
//!   - the **global token bucket** (`ENROL_RATE_PER_MINUTE`), which bounds the
//!     whole fleet and not just one device.
//!
//! `t352_enrolment.rs` covers the same gate against a stub, which is where the
//! outage and malformed-answer cases belong. What only the real api can settle
//! is whether a device deployed through `POST /api/devices/deploy` is the same
//! device hbbs then asks about — the two describe it differently, and T5.1 found
//! that the hard way.

mod harness;

use std::time::Duration;

use harness::{
    peer::{next_device_id, Device},
    world::World,
};
use hbb_common::{
    rendezvous_proto::*,
    tokio::{self, time::sleep},
};

const WAIT: u64 = 8_000;
const ENROLLED_PATH: &str = "/api/internal/enrolled";

/// `REG_TIMEOUT` lets a peer register roughly once every few seconds; past that
/// hbbs answers `TOO_FREQUENT` and nothing reaches the api at all, which would
/// make a "does it storm the api" test pass for the wrong reason.
const REG_WINDOW: Duration = Duration::from_millis(7_200);

/// Registers an id nobody deployed, returning every verdict hbbs gave.
async fn register_repeatedly(
    w: &World,
    sock: &mut hbb_common::udp::FramedSocket,
    id: &str,
    times: usize,
) -> Vec<register_pk_response::Result> {
    let mut seen = Vec::new();
    for _ in 0..times {
        if let Some(result) =
            harness::register_pk_on(sock, w.hbbs.port, id, b"uuid-stranger", b"pk-stranger", 2_000)
                .await
        {
            if result == register_pk_response::Result::TOO_FREQUENT {
                sleep(REG_WINDOW).await;
                continue;
            }
            seen.push(result);
        }
        sleep(Duration::from_millis(120)).await;
    }
    seen
}

// ---------------------------------------------------------------- the refusal

/// `NOT_DEPLOYED` reaches the client, and the id stays unclaimed.
#[tokio::test(flavor = "multi_thread")]
async fn an_undeployed_device_is_refused_and_does_not_take_the_id() {
    let w = World::builder().enrol_required(true).up().await;
    let stranger = next_device_id();
    let mut sock = harness::udp_socket().await;

    // The first contact is answered `OK` and deliberately not written down —
    // hbbs has no verdict yet, so it defers by one round trip rather than
    // letting a stranger claim the id (`rendezvous_server.rs:564`). The refusal
    // is the *second* answer, which is what a real client sees 15 s later.
    let verdicts = register_repeatedly(&w, &mut sock, &stranger, 4).await;
    assert_eq!(
        verdicts.first(),
        Some(&register_pk_response::Result::OK),
        "the first contact should defer, not refuse: {verdicts:?}"
    );
    assert!(
        verdicts.contains(&register_pk_response::Result::NOT_DEPLOYED),
        "an undeployed device was never told to deploy: {verdicts:?}"
    );

    // It never entered the peer table, so nobody can reach it either — the whole
    // point of the gate is that claiming an id is what it stops.
    assert!(
        !w.hbbs.log().contains(&format!("update_pk {stranger}")),
        "an undeployed device was written into the peer table"
    );
    let alice = w.controller("alice").await;
    let mut ghost = Device {
        id: stranger.clone(),
        uuid: b"uuid-stranger".to_vec(),
        pk: b"pk-stranger".to_vec(),
        sock,
        hbbs_port: w.hbbs.port,
    };
    assert!(
        alice.connect(&mut ghost, ConnType::DEFAULT_CONN, 4_000).await.is_err(),
        "an unenrolled device was reachable"
    );

    // And the api agrees it is not a device: `/api/login` upserts a `pending`
    // row on first sign-in from a machine, and `pending` is deliberately **not**
    // enrolled — claiming an id is exactly what creates one of those.
    let seen = w.console.get(&format!("/api/admin/devices?q={stranger}")).await;
    assert_eq!(seen["total"], 0, "an undeployed device appeared in the console: {seen}");
}

// ---------------------------------------------------------------- the storm

/// **The headline: a refused device retries forever and the api barely notices.**
///
/// A client told `NOT_DEPLOYED` clears `key_confirmed` and throttles itself to
/// `DEPLOY_RETRY_INTERVAL` — but that is the client's promise, and a patched or
/// broken one makes no such promise. The protection that has to hold is hbbs's,
/// so this hammers registration far faster than any real client would and counts
/// what actually reached the api.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_device_retrying_does_not_storm_the_api() {
    let w = World::builder()
        .enrol_required(true)
        // The production default, left alone on purpose: the cache **is** the
        // protection being measured, and turning it down would measure a
        // deployment nobody runs.
        .up()
        .await;
    let stranger = next_device_id();
    let mut sock = harness::udp_socket().await;

    let before = w.api.requests_to(ENROLLED_PATH);
    let verdicts = register_repeatedly(&w, &mut sock, &stranger, 12).await;
    // Let anything in flight land before counting.
    sleep(Duration::from_millis(800)).await;
    let asked = w.api.requests_to(ENROLLED_PATH) - before;

    assert!(
        verdicts.len() >= 6,
        "the test did not actually retry: {verdicts:?}"
    );
    // One question, one answer, cached for ten minutes. A couple more would be
    // the in-flight claim losing a race; twelve would be no cache at all.
    assert!(
        asked <= 2,
        "{} registrations produced {asked} api calls — the enrolment cache is not holding",
        verdicts.len()
    );
    // Every retry after the first still gets a real refusal, from memory.
    assert!(
        verdicts
            .iter()
            .filter(|v| **v == register_pk_response::Result::NOT_DEPLOYED)
            .count()
            >= 4,
        "the cached verdict stopped being applied: {verdicts:?}"
    );
}

/// The same property from the other side: a device that *is* enrolled is asked
/// about once, not on every beat.
#[tokio::test(flavor = "multi_thread")]
async fn an_enrolled_device_is_asked_about_once_and_then_remembered() {
    let w = World::builder().enrol_required(true).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let after_enrolment = w.api.requests_to(ENROLLED_PATH);

    // Heartbeats, which is what a settled client actually sends — and the path
    // T3.5.4 added a second gate to. Every one of these reads the verdict from
    // memory; none of them may become a request.
    for _ in 0..8 {
        laptop.heartbeat(1_500).await;
        sleep(Duration::from_millis(100)).await;
    }
    sleep(Duration::from_millis(500)).await;

    assert_eq!(
        w.api.requests_to(ENROLLED_PATH),
        after_enrolment,
        "the heartbeat path asked the api again — it must be an in-memory read (T3.5.4)"
    );

    // And the device is still reachable throughout, which is the thing all this
    // caching exists to protect.
    assert!(
        alice.connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT).await.is_ok(),
        "an enrolled device stopped being reachable"
    );
}

// ---------------------------------------------------------------- un-enrolling

/// T3.5.4's *Done when*, against the real console: a device disabled in the
/// console goes offline on its own, with nobody restarting anything.
///
/// The mechanism is deliberately upstream's: the heartbeat answers
/// `request_pk: true` for a refused peer, which walks the client back into the
/// `RegisterPk` arm where `NOT_DEPLOYED` already lives. No client patch, and the
/// device ages out through upstream's own `REG_TIMEOUT`.
#[tokio::test(flavor = "multi_thread")]
async fn disabling_a_device_in_the_console_takes_it_offline_by_itself() {
    let w = World::builder()
        .enrol_required(true)
        // Ten minutes is right in production and useless in a test that has to
        // watch a verdict change.
        .enrol_cache_ttl_ms(1_000)
        .up()
        .await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    // Settled: heartbeating, not re-registering, exactly like a real client.
    assert_eq!(
        laptop.heartbeat(2_000).await,
        Some(false),
        "hbbs asked a healthy device for its key"
    );

    w.console
        .patch(
            &format!("/api/admin/devices/{}", laptop.id),
            serde_json::json!({ "disabled": true }),
        )
        .await;

    // Nobody restarts anything. The next heartbeats past the cache TTL carry the
    // new verdict.
    let mut asked_for_pk = false;
    for _ in 0..20 {
        sleep(Duration::from_millis(500)).await;
        if laptop.heartbeat(2_000).await == Some(true) {
            asked_for_pk = true;
            break;
        }
    }
    assert!(
        asked_for_pk,
        "a device disabled in the console kept its registration:\n{}",
        w.hbbs.log()
    );

    // And when it does what it is told, it is refused.
    let mut refused = None;
    for _ in 0..6 {
        refused = laptop
            .register_again(&laptop.id.clone(), &laptop.uuid.clone(), &laptop.pk.clone())
            .await;
        if refused == Some(register_pk_response::Result::NOT_DEPLOYED) {
            break;
        }
        sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(
        refused,
        Some(register_pk_response::Result::NOT_DEPLOYED),
        "a disabled device was allowed to re-register"
    );
}

// ---------------------------------------------------------------- the open question

/// **A changed public key is recorded and not refused, and T5.5 could not settle
/// whether it should be.**
///
/// `services/enrolment.ts` defers the strict reading of T3.5.2 to this task, on
/// the grounds that T5.5 would be "the first time this runs against an installed
/// client". It is not: this harness speaks the protocol, and the question is
/// specifically what key pair `rustdesk --deploy` reads on an installed host —
/// which needs `/Applications/RustDesk.app` and root (`core_main.rs:651`), the
/// same blocker that stopped T3.5.1.
///
/// So this test pins the behaviour that ships rather than guessing at the one
/// that should. Refusing here would turn "the operator re-deployed the device"
/// into a fleet that cannot register, and `RegisterPk` already answers
/// `UUID_MISMATCH` when the pk changes from a new ip
/// (`rendezvous_server.rs:446-459`), so the hole is narrower than it looks. The
/// gap stays open, with what it needs written down.
#[tokio::test(flavor = "multi_thread")]
async fn a_changed_public_key_is_recorded_rather_than_refused() {
    let w = World::builder().enrol_required(true).enrol_cache_ttl_ms(1_000).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    let before = w.console.device(&laptop.id).await;
    assert_eq!(before["status"], "enrolled");

    // The same machine, same uuid, a new key pair — a re-install, or a re-deploy.
    let new_pk = b"pk-rotated".to_vec();
    sleep(Duration::from_millis(1_200)).await;
    let mut verdict = None;
    for _ in 0..6 {
        verdict = laptop
            .register_again(&laptop.id.clone(), &laptop.uuid.clone(), &new_pk)
            .await;
        if verdict == Some(register_pk_response::Result::OK) {
            break;
        }
        sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(
        verdict,
        Some(register_pk_response::Result::OK),
        "a re-keyed device was refused — the api's behaviour changed without this test being updated"
    );

    // The api recorded the change instead, which is what makes it visible to an
    // operator without taking the device offline.
    let after = w.console.device(&laptop.id).await;
    assert_eq!(after["status"], "enrolled", "{after}");
    assert!(
        after["pkChangedAt"].as_str().is_some(),
        "a changed public key left no trace for an operator to see: {after}"
    );
}
