//! T3.5.2 / T3.5.3: registration ownership against the real `hbbs` binary.
//!
//! The unit tests in `src/enrolment.rs` prove the config and the rate limit.
//! This proves the behaviour a device actually sees, and the four properties
//! that make it safe to turn on:
//!
//!   1. an unenrolled device is answered `NOT_DEPLOYED` and does **not** land in
//!      the peer table — otherwise the id is taken anyway and the check is
//!      decorative;
//!   2. the answer is **cached**, so a 15 s keepalive loop across a fleet is not
//!      a request storm against `apps/api`;
//!   3. the call never happens on the datagram path — `handle_udp` is awaited
//!      inline in `io_loop`, so a blocking call there would stall the whole
//!      server. The first registration is answered immediately, from memory;
//!   4. **an api outage does not deregister anybody.** This is the one that
//!      separates registration from connection authorization (decision D1) and
//!      the one whose failure mode is a fleet going dark.
//!
//! `AUTH_API_URL` alone must not turn any of this on, which is why every test
//! that wants it passes `enrol_args()` explicitly.

mod harness;

use harness::*;
use hbb_common::{
    rendezvous_proto::*,
    tokio::{self, time::sleep},
    udp::FramedSocket,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

const UUID: &[u8] = b"t352-uuid-0001";
const PK: &[u8] = b"t352-public-key-0001";

/// A stub that answers the enrolment endpoint from a closure and the authorize
/// endpoint with a plain allow, counting the enrolment calls separately.
async fn enrol_stub(
    verdict: impl Fn(&str) -> String + Send + Sync + 'static,
) -> (Stub, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let stub = stub_by(move |request| {
        if is_enrolment(request) {
            counter.fetch_add(1, Ordering::SeqCst);
            (200, verdict(request))
        } else {
            (200, ALLOW.to_owned())
        }
    })
    .await;
    (stub, calls)
}

fn args(stub: &Stub) -> Vec<String> {
    let mut a = auth_args(stub);
    a.extend(enrol_args());
    a
}

/// **Upstream lets a peer register three times per six seconds** and answers
/// `TOO_FREQUENT` after that (`rendezvous_server.rs:476-483`), counted from the
/// last registration rather than from a fixed window. The real client registers
/// every 15 s (`REG_INTERVAL`) and never meets it; a test that polls does, and
/// it looks exactly like this feature refusing a device.
///
/// So every test here either stays inside three registrations per id, or waits
/// the window out — which is what this does. Registration is a keepalive loop
/// and the verdict is written by a task the arm does not wait for, so "ask
/// again" is how a test observes an answer at all.
const REG_BURST: usize = 3;
/// **7.2 s, not 6.** The comparison is `elapsed().as_secs() > 6`, and `as_secs`
/// truncates — 6.5 s reads as 6, which is not greater than 6. A window that
/// looks generous and is off by one truncation is how this reads as the feature
/// misbehaving.
const REG_WINDOW: Duration = Duration::from_millis(7_200);

/// Registers a device **properly** — not just "got an `OK`".
///
/// The first contact is answered `OK` and deliberately not written to the peer
/// table (the `deferred` branch), so a test that stops at the first `OK` is
/// testing an unregistered device. `update_pk` in the log is the only honest
/// signal that hbbs actually holds this peer, which is what the heartbeat path
/// below depends on.
async fn register_fully(hbbs: &Hbbs, sock: &mut FramedSocket, id: &str) {
    let needle = format!("update_pk {id}");
    for _ in 0..6 {
        match register_pk_on(sock, hbbs.port, id, UUID, PK, 1_000).await {
            Some(register_pk_response::Result::TOO_FREQUENT) => sleep(REG_WINDOW).await,
            _ => {}
        }
        if hbbs.wait_for_log(&needle, 600).await {
            return;
        }
    }
    panic!("{id} never made it into the peer table\n{}", hbbs.log());
}

async fn register_until(
    sock: &mut FramedSocket,
    port: u16,
    id: &str,
    want: register_pk_response::Result,
) -> register_pk_response::Result {
    let mut last = register_pk_response::Result::OK;
    for _ in 0..8 {
        match register_pk_on(sock, port, id, UUID, PK, 1_000).await {
            Some(register_pk_response::Result::TOO_FREQUENT) => sleep(REG_WINDOW).await,
            Some(result) => {
                last = result;
                if result == want {
                    return result;
                }
                sleep(Duration::from_millis(250)).await;
            }
            None => sleep(Duration::from_millis(250)).await,
        }
    }
    last
}

#[tokio::test]
async fn an_unenrolled_device_is_told_to_deploy() {
    let (stub, _) = enrol_stub(|_| enrolled(false)).await;
    let hbbs = hbbs(&args(&stub)).await;
    let mut sock = udp_socket().await;

    // The first answer is upstream's: nothing is known yet, and registration
    // does not fail closed (T3.5.3). The refusal arrives once the api has been
    // asked, off the datagram path.
    let first = register_pk_on(&mut sock, hbbs.port, "352000001", UUID, PK, 2_000).await;
    assert_eq!(first, Some(register_pk_response::Result::OK));

    let settled = register_until(
        &mut sock,
        hbbs.port,
        "352000001",
        register_pk_response::Result::NOT_DEPLOYED,
    )
    .await;
    assert_eq!(
        settled,
        register_pk_response::Result::NOT_DEPLOYED,
        "hbbs never refused an unenrolled device\n{}",
        hbbs.log()
    );
}

#[tokio::test]
async fn an_enrolled_device_registers_exactly_as_upstream() {
    let (stub, _) = enrol_stub(|_| enrolled(true)).await;
    let hbbs = hbbs(&args(&stub)).await;
    let mut sock = udp_socket().await;

    for _ in 0..REG_BURST {
        let result = register_pk_on(&mut sock, hbbs.port, "352000002", UUID, PK, 2_000).await;
        assert_eq!(result, Some(register_pk_response::Result::OK));
        sleep(Duration::from_millis(150)).await;
    }
    // Every answer being OK is not enough: the first contact is answered OK
    // *without* writing the peer row (see the `deferred` branch), so this is
    // what proves the device ends up actually registered.
    assert!(
        hbbs.wait_for_log("update_pk 352000002", 3_000).await,
        "an enrolled device never made it into the peer table\n{}",
        hbbs.log()
    );
}

/// The point of caching in the `peer` row rather than only in memory: this is
/// what a 15 s keepalive loop across a fleet costs `apps/api`.
#[tokio::test]
async fn the_answer_is_cached_rather_than_asked_every_beat() {
    let (stub, calls) = enrol_stub(|_| enrolled(true)).await;
    let hbbs = hbbs(&args(&stub)).await;
    let mut sock = udp_socket().await;

    // Two bursts either side of the throttle window, so this is six
    // registrations spread over the kind of interval a real client uses — not
    // three in a row that a single in-flight guard would collapse anyway.
    for _ in 0..REG_BURST {
        register_pk_on(&mut sock, hbbs.port, "352000003", UUID, PK, 1_000).await;
        sleep(Duration::from_millis(120)).await;
    }
    sleep(REG_WINDOW).await;
    for _ in 0..REG_BURST {
        let result = register_pk_on(&mut sock, hbbs.port, "352000003", UUID, PK, 1_000).await;
        assert_eq!(result, Some(register_pk_response::Result::OK));
        sleep(Duration::from_millis(120)).await;
    }

    let asked = calls.load(Ordering::SeqCst);
    assert_eq!(
        asked, 1,
        "six registrations cost {asked} enrolment calls\n{}",
        hbbs.log()
    );
}

/// **The T3.5.3 rule.** An api that stops answering must not deregister a device
/// it already confirmed — that is the difference between this and connection
/// authorization, and the reason it is not a contradiction of decision D1.
#[tokio::test]
async fn an_api_outage_does_not_deregister_a_confirmed_device() {
    let healthy = Arc::new(AtomicBool::new(true));
    let flag = healthy.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let stub = stub_by(move |request| {
        if is_enrolment(request) {
            counter.fetch_add(1, Ordering::SeqCst);
            if flag.load(Ordering::SeqCst) {
                return (200, enrolled(true));
            }
            return (503, r#"{"error":"down"}"#.to_owned());
        }
        (200, ALLOW.to_owned())
    })
    .await;

    // A short TTL so the outage is guaranteed to fall on a refresh rather than
    // on a cache hit — otherwise this test would pass without testing anything.
    let mut a = args(&stub);
    a.extend(["--enrol-cache-ttl-ms".to_owned(), "200".to_owned()]);
    let hbbs = hbbs(&a).await;
    let mut sock = udp_socket().await;

    register_pk_on(&mut sock, hbbs.port, "352000004", UUID, PK, 2_000).await;
    sleep(Duration::from_millis(400)).await;
    let confirmed = calls.load(Ordering::SeqCst);
    assert!(confirmed >= 1, "the api was never asked\n{}", hbbs.log());

    healthy.store(false, Ordering::SeqCst);
    // Two registrations here, not six: one is enough to prove the point and the
    // budget is three per six seconds. The TTL is 200 ms, so both of these are
    // past it and both try — and fail — to refresh.
    for _ in 0..2 {
        let result = register_pk_on(&mut sock, hbbs.port, "352000004", UUID, PK, 1_000).await;
        assert_eq!(
            result,
            Some(register_pk_response::Result::OK),
            "an api outage deregistered a confirmed device\n{}",
            hbbs.log()
        );
        sleep(Duration::from_millis(250)).await;
    }
    assert!(
        hbbs.wait_for_log("outcome=unavailable", 2_000).await,
        "the outage was not logged\n{}",
        hbbs.log()
    );
}

/// The same rule in the other direction: a device already refused must recover
/// once it is deployed, without an hbbs restart.
#[tokio::test]
async fn a_device_that_gets_deployed_recovers_on_its_own() {
    let deployed = Arc::new(AtomicBool::new(false));
    let flag = deployed.clone();
    let (stub, _) = enrol_stub(move |_| enrolled(flag.load(Ordering::SeqCst))).await;

    let mut a = args(&stub);
    a.extend(["--enrol-cache-ttl-ms".to_owned(), "200".to_owned()]);
    let hbbs = hbbs(&a).await;
    let mut sock = udp_socket().await;

    let refused = register_until(
        &mut sock,
        hbbs.port,
        "352000005",
        register_pk_response::Result::NOT_DEPLOYED,
    )
    .await;
    assert_eq!(refused, register_pk_response::Result::NOT_DEPLOYED);

    deployed.store(true, Ordering::SeqCst);
    let recovered = register_until(
        &mut sock,
        hbbs.port,
        "352000005",
        register_pk_response::Result::OK,
    )
    .await;
    assert_eq!(
        recovered,
        register_pk_response::Result::OK,
        "a deployed device never recovered\n{}",
        hbbs.log()
    );
}

/// A refusal that still wrote the peer row would be decorative: the id is
/// claimed either way, and the next machine to try it gets `UUID_MISMATCH`
/// forever.
///
/// Asked from the wire rather than by reading `db_v2.sqlite3`, because what
/// "claimed" means is exactly what a second machine experiences.
///
/// **It is `OFFLINE`, not `ID_NOT_EXIST`, that a controller sees for a refused
/// device** — upstream's `get_or` has already put an empty peer in the in-memory
/// map by the time the check runs, and `handle_punch_hole_request` reads that
/// map. Both refuse and neither brokers anything; only the wording differs.
#[tokio::test]
async fn a_refused_device_does_not_claim_the_id() {
    let (stub, _) = enrol_stub(|_| enrolled(false)).await;
    let hbbs = hbbs(&args(&stub)).await;
    let mut sock = udp_socket().await;

    register_until(
        &mut sock,
        hbbs.port,
        "352000006",
        register_pk_response::Result::NOT_DEPLOYED,
    )
    .await;

    // A controller is refused, without hbbs brokering anything.
    let response = punch(
        hbbs.port,
        &hbbs.key,
        "352000006",
        "any-token",
        ConnType::DEFAULT_CONN,
        REFUSAL_WAIT,
    )
    .await
    .expect("hbbs answered the controller nothing");
    assert!(
        matches!(
            response.failure.enum_value(),
            Ok(punch_hole_response::Failure::OFFLINE)
                | Ok(punch_hole_response::Failure::ID_NOT_EXIST)
        ),
        "a refused device was brokered: {:?}\n{}",
        response.failure,
        hbbs.log()
    );

    // And a different machine can still take the id, which it could not if the
    // refused one had been written.
    let mut other = udp_socket().await;
    sleep(REG_WINDOW).await;
    let result = register_pk_on(
        &mut other,
        hbbs.port,
        "352000006",
        b"a-different-machine",
        b"a-different-key",
        2_000,
    )
    .await;
    assert_ne!(
        result,
        Some(register_pk_response::Result::UUID_MISMATCH),
        "the refused device had claimed the id\n{}",
        hbbs.log()
    );
}

/// The whole point of `ENROL_REQUIRED` shipping off: an operator who configured
/// the auth API for T3.3 and upgraded hbbs must not find their fleet
/// deregistered by the upgrade.
#[tokio::test]
async fn the_api_url_alone_does_not_turn_it_on() {
    let (stub, calls) = enrol_stub(|_| enrolled(false)).await;
    // auth_args only — no enrol_args.
    let hbbs = hbbs(&auth_args(&stub)).await;
    let mut sock = udp_socket().await;

    for _ in 0..REG_BURST {
        let result = register_pk_on(&mut sock, hbbs.port, "352000007", UUID, PK, 2_000).await;
        assert_eq!(
            result,
            Some(register_pk_response::Result::OK),
            "enrolment was enforced without being switched on\n{}",
            hbbs.log()
        );
        sleep(Duration::from_millis(120)).await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the enrolment endpoint was called with the feature off"
    );
}

#[tokio::test]
async fn it_refuses_to_start_without_somewhere_to_ask() {
    let log = hbbs_expect_exit(&enrol_args()).await;
    assert!(
        log.contains("AUTH_API_URL"),
        "hbbs did not say what was missing:\n{log}"
    );
}

/// A body hbbs cannot read is an outage, not a refusal. The failure this guards
/// against is a proxy or a login page answering 200 with HTML, which would
/// otherwise decode as "not enrolled" and take the fleet offline.
#[tokio::test]
async fn an_unreadable_answer_is_an_outage_not_a_refusal() {
    let stub = stub_by(|request| {
        if is_enrolment(request) {
            (200, "<html>please log in</html>".to_owned())
        } else {
            (200, ALLOW.to_owned())
        }
    })
    .await;
    let hbbs = hbbs(&args(&stub)).await;
    let mut sock = udp_socket().await;

    for _ in 0..REG_BURST {
        let result = register_pk_on(&mut sock, hbbs.port, "352000008", UUID, PK, 2_000).await;
        assert_eq!(
            result,
            Some(register_pk_response::Result::OK),
            "an unparseable answer was read as a refusal\n{}",
            hbbs.log()
        );
        sleep(Duration::from_millis(120)).await;
    }
    assert!(
        hbbs.wait_for_log("unparseable json", 2_000).await,
        "the contract break was not logged\n{}",
        hbbs.log()
    );
}

// ---------------------------------------------------------------------------
// T3.5.4 — the heartbeat path
// ---------------------------------------------------------------------------

/// **The gap T3.5.2 left.** A client that has registered successfully sets
/// `key_confirmed` and sends only `RegisterPeer` from then on, so the
/// `RegisterPk` gate never sees it again. Un-enrolling a device in the console
/// has to reach it anyway.
#[tokio::test]
async fn un_enrolling_a_registered_device_takes_it_offline() {
    let enrolled_flag = Arc::new(AtomicBool::new(true));
    let flag = enrolled_flag.clone();
    let (stub, _) = enrol_stub(move |_| enrolled(flag.load(Ordering::SeqCst))).await;

    let mut a = args(&stub);
    a.extend(["--enrol-cache-ttl-ms".to_owned(), "200".to_owned()]);
    let hbbs = hbbs(&a).await;
    let mut sock = udp_socket().await;

    // Properly registered first — the first contact is deferred, so this takes
    // more than one round trip.
    register_fully(&hbbs, &mut sock, "352000009").await;

    // Settled: heartbeats are answered without asking for the key back.
    let asked = register_peer_on(&mut sock, hbbs.port, "352000009", 2_000).await;
    assert_eq!(
        asked,
        Some(false),
        "hbbs asked a healthy device for its key\n{}",
        hbbs.log()
    );

    // Now the console un-enrols it. No restart, no RegisterPk.
    enrolled_flag.store(false, Ordering::SeqCst);
    let mut refused = false;
    for _ in 0..25 {
        if register_peer_on(&mut sock, hbbs.port, "352000009", 1_000).await == Some(true) {
            refused = true;
            break;
        }
        sleep(Duration::from_millis(150)).await;
    }
    assert!(
        refused,
        "an un-enrolled device kept being told it was fine\n{}",
        hbbs.log()
    );
    assert!(
        hbbs.wait_for_log("gate=heartbeat outcome=not-deployed", 2_000).await,
        "the heartbeat refusal was not logged\n{}",
        hbbs.log()
    );
}

/// `request_pk` is only useful if it lands the client somewhere that explains
/// itself. It has to be the same `NOT_DEPLOYED` the client already handles.
#[tokio::test]
async fn the_heartbeat_walks_the_client_into_not_deployed() {
    let (stub, _) = enrol_stub(|_| enrolled(false)).await;
    let hbbs = hbbs(&args(&stub)).await;
    let mut sock = udp_socket().await;

    let settled = register_until(
        &mut sock,
        hbbs.port,
        "352000010",
        register_pk_response::Result::NOT_DEPLOYED,
    )
    .await;
    assert_eq!(settled, register_pk_response::Result::NOT_DEPLOYED);

    // And the heartbeat keeps pointing there rather than answering "you're fine".
    let asked = register_peer_on(&mut sock, hbbs.port, "352000010", 2_000).await;
    assert_eq!(
        asked,
        Some(true),
        "the heartbeat let a refused device settle\n{}",
        hbbs.log()
    );
}

/// The heartbeat is every device every few seconds. With the feature off it must
/// cost nothing at all, and with it on it must not cost an api call per beat.
#[tokio::test]
async fn the_heartbeat_does_not_ask_the_api_every_beat() {
    let (stub, calls) = enrol_stub(|_| enrolled(true)).await;
    let hbbs = hbbs(&args(&stub)).await;
    let mut sock = udp_socket().await;

    register_fully(&hbbs, &mut sock, "352000011").await;
    let after_registration = calls.load(Ordering::SeqCst);

    for _ in 0..12 {
        let asked = register_peer_on(&mut sock, hbbs.port, "352000011", 1_000).await;
        assert_eq!(
            asked,
            Some(false),
            "a healthy device was asked for its key\n{}",
            hbbs.log()
        );
        sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        after_registration,
        "twelve heartbeats cost api calls inside one cache TTL\n{}",
        hbbs.log()
    );
}
