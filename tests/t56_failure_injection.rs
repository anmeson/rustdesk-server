//! T5.6 — what `hbbs` does when the api is down, slow, or talking nonsense.
//!
//! This is decision **D1** under test. Everything else in Milestone 5 asks
//! whether the right answer is produced from a working api; this asks what
//! happens when there is no answer to be had, and there are only two acceptable
//! outcomes: the connection is refused, or the connection is refused. A single
//! allow anywhere below is the whole login layer defeated by unplugging one
//! cable.
//!
//! The second half of the task — "and `hbbs` does not wedge" — is the one that
//! is easy to state and easy to skip, so it is spelled out as three separate
//! claims, each with its own test:
//!
//!   - a refusal costs **the timeout and no more** (`a_denial_costs_the_timeout…`);
//!   - connections waiting on a dead api do **not queue behind each other**
//!     (`…does_not_serialise_the_connections_waiting_on_it`) — they are handled
//!     in a task each, and if that ever stopped being true the fleet would go
//!     down one connection at a time;
//!   - the parts of hbbs that never needed the api keep working throughout, and
//!     it recovers **without a restart** when the api comes back.
//!
//! Three faults are real outages and are produced by killing the api outright.
//! The other three — slow, garbage, hangup — cannot be produced by `apps/api`
//! without shipping a fault mode in the product, so they are injected into the
//! wire between hbbs and the api instead; `harness/fault.rs` says how, and why
//! only hbbs sits behind it.
//!
//! **The decision cache is turned off in nearly every test here** (`ttl = 1`).
//! With it on, the first healthy connection would answer the next five seconds
//! of faulty ones from memory, and a test that passed would be proving the
//! cache works rather than that the fault was survived.

mod harness;

use std::time::{Duration, Instant};

use harness::{
    fault::Fault,
    peer::{next_device_id, Controller, Device},
    world::World,
};
use hbb_common::{
    rendezvous_proto::*,
    tokio::{self, time::sleep},
};

const WAIT: u64 = 8_000;

/// How long hbbs may wait on the api. Short enough that a blackholed request is
/// a second rather than four, long enough that a healthy round trip through the
/// proxy on a loaded laptop is nowhere near it.
const TIMEOUT_MS: u64 = 1_500;

/// Waiting for a refusal costs this in full — `connect` cannot know the device
/// will never be brokered to, so it waits the whole window before reading what
/// A was told. Anything that *measures* a denial uses `request_relay_alone`,
/// which returns the moment hbbs answers.
const REFUSAL: u64 = 3_000;

/// The sentence a user sees when no decision could be obtained at all
/// (`auth.rs:262`). Matched on a fragment, because the assertion is about which
/// branch answered and not about the punctuation.
const UNAVAILABLE: &str = "unavailable";

/// A world whose api path can be broken on demand, with a user who genuinely
/// has access — so that every refusal below is the fault refusing them and not
/// a missing grant.
async fn faulty_world() -> (World, Controller, Device) {
    let w = World::builder()
        .fault_injection(true)
        .auth_timeout_ms(TIMEOUT_MS)
        .auth_cache_ttl_ms(1)
        .up()
        .await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the owner could not connect through a healthy proxy — the fault is not the fault");
    (w, alice, laptop)
}

/// The refusal text, or a panic naming the allow that should not have happened.
async fn refusal_for(alice: &Controller, laptop: &mut Device, what: &str) -> String {
    match alice.connect(laptop, ConnType::DEFAULT_CONN, REFUSAL).await {
        Err(reason) => reason,
        Ok(_) => panic!("{what}: the connection was ALLOWED — fail-closed is not holding"),
    }
}

/// One counter out of the runtime console's `ad` summary.
fn counter(report: &str, key: &str) -> u64 {
    report
        .split_whitespace()
        .find_map(|field| field.strip_prefix(&format!("{key}="))?.parse().ok())
        .unwrap_or(0)
}

async fn decisions(w: &World) -> String {
    harness::console(w.hbbs.port, "ad").await
}

/// One keepalive, as a settled client sends every `REG_INTERVAL` (15 s).
///
/// Needed by any test that spends more than `REG_TIMEOUT` (30 s,
/// `rendezvous_server.rs:56`) refusing connections: that check runs *before*
/// authorization, so a device left un-registered while the api path is broken
/// stops being refused and starts being `OFFLINE` — a true answer to a different
/// question, and one that would let this suite pass without ever reaching the
/// gate it is about.
///
/// **`RegisterPeer`, not `RegisterPk`.** Only `update_pk` refreshes
/// `last_reg_time`, and it is skipped when nothing about the registration
/// changed (`rendezvous_server.rs:603`) — so a repeated `RegisterPk` from a
/// settled device is answered `OK` and does **not** keep it online. That is
/// upstream's design and it is exactly what a real client does: `RegisterPk`
/// once, `RegisterPeer` forever after.
async fn keep_registered(w: &World, device: &mut Device) {
    let _ = harness::register_peer_on(&mut device.sock, w.hbbs.port, &device.id, 2_000).await;
}

// ---------------------------------------------------------------- the api is gone

/// The plain case, on the punch gate: the api is not there, and the user who
/// owns the machine is told to try again rather than let in.
#[tokio::test(flavor = "multi_thread")]
async fn an_api_that_is_gone_denies_the_punch_gate() {
    let mut w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the owner could not connect before the outage");

    w.api.kill_now();
    assert!(w.api.is_down(), "the api is still listening");

    let refusal = refusal_for(&alice, &mut laptop, "with the api killed").await;
    assert!(
        refusal.to_lowercase().contains(UNAVAILABLE),
        "refused, but for the wrong reason: {refusal}"
    );

    // A fail-closed refusal is the one denial with no row anywhere else: the api
    // that would have recorded it is the thing that is down. T3.7's counter is
    // the only trace, so it had better be there.
    let report = decisions(&w).await;
    assert!(
        counter(&report, "fail-closed") >= 1,
        "the outage left no fail-closed decision on record:\n{report}"
    );
}

/// The same outage on the **relay** gate, which is a separate chokepoint with
/// its own call site (T3.3b). A fail-open here would be the whole enforcement
/// bypassed by a client that simply asks for a relay first.
#[tokio::test(flavor = "multi_thread")]
async fn an_api_that_is_gone_denies_the_relay_gate_too() {
    let mut w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    let relay = w.relay_addr();
    let key = w.hbbs.key.clone();
    alice
        .connect_relayed(&mut laptop, &relay, &key, WAIT)
        .await
        .expect("the owner could not relay before the outage");

    w.api.kill_now();

    let refusal = alice
        .connect_relayed(&mut laptop, &relay, &key, REFUSAL)
        .await
        .err()
        .expect("the relay gate let the connection through while the api was down");
    assert!(
        refusal.to_lowercase().contains(UNAVAILABLE),
        "the relay gate refused for the wrong reason: {refusal}"
    );

    let report = decisions(&w).await;
    assert!(
        report.contains("relay"),
        "the denial was not recorded against the relay gate:\n{report}"
    );
}

/// The outage stops connections. It must not stop the **fleet**: a device that
/// cannot register is a device that drops out of the peer table and is offline
/// to everybody afterwards, including once the api is back. That is T3.5.3's
/// asymmetry — the connect path fails closed, registration does not — and this
/// is the test that would notice if the two were ever made consistent.
#[tokio::test(flavor = "multi_thread")]
async fn the_outage_denies_connections_and_still_lets_the_fleet_register() {
    let mut w = World::builder()
        .enrol_required(true)
        .auth_cache_ttl_ms(1)
        .up()
        .await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    w.api.kill_now();

    let refusal = refusal_for(&alice, &mut laptop, "with the api killed").await;
    assert!(refusal.to_lowercase().contains(UNAVAILABLE), "wrong refusal: {refusal}");

    // The same device, still registering, with nobody to ask whether it is
    // enrolled. Its verdict is already cached and the answer has to be OK.
    let mut result = None;
    for _ in 0..3 {
        result = harness::register_pk_on(
            &mut laptop.sock,
            w.hbbs.port,
            &laptop.id,
            &laptop.uuid,
            &laptop.pk,
            2_000,
        )
        .await;
        if result != Some(register_pk_response::Result::TOO_FREQUENT) {
            break;
        }
        sleep(Duration::from_millis(7_200)).await;
    }
    assert_eq!(
        result,
        Some(register_pk_response::Result::OK),
        "the outage deregistered a device that was already enrolled"
    );

    // And the operator can still see what is happening, on a console that never
    // needed the api.
    let report = decisions(&w).await;
    assert!(report.contains("allow="), "the runtime console stopped answering:\n{report}");
}

/// Recovery, with nobody restarting anything. The client that was refused during
/// the outage gets in afterwards on the same token, which is the difference
/// between an outage and an incident.
#[tokio::test(flavor = "multi_thread")]
async fn hbbs_recovers_when_the_api_comes_back_without_a_restart() {
    let mut w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    w.api.kill_now();
    let refusal = refusal_for(&alice, &mut laptop, "during the outage").await;
    assert!(refusal.to_lowercase().contains(UNAVAILABLE), "wrong refusal: {refusal}");

    w.api.restart().await;

    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("hbbs never recovered — the outage outlived the api that caused it");
}

// ---------------------------------------------------------------- the api is slow

/// The sharpest case in the task, and the reason the injector forwards rather
/// than sleeping in front of the api: **the api said allow**. It answered, it
/// wrote its audit row, and the answer arrived after `AUTH_TIMEOUT_MS` — so
/// hbbs denies. Fail-closed is hbbs's decision, taken without the api's
/// permission and against the api's own conclusion.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_that_arrives_after_the_timeout_is_a_denial() {
    let (w, alice, mut laptop) = faulty_world().await;
    let before = w.api.requests_to("/api/internal/authorize");

    w.fault().set(Fault::Slow(TIMEOUT_MS + 1_500));
    let refusal = refusal_for(&alice, &mut laptop, "with the answer arriving late").await;
    assert!(
        refusal.to_lowercase().contains(UNAVAILABLE),
        "refused, but not as an unavailable api: {refusal}"
    );

    // The proof that this is a *timeout* and not a fault the api produced.
    assert!(
        w.api.requests_to("/api/internal/authorize") > before,
        "the api never saw the request, so nothing here was about it being slow"
    );

    // And the late answer is not banked for later: healing the path is enough,
    // no waiting out a cache entry that was never created.
    w.fault().heal();
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("a connection after the slow period was still refused");
}

/// A refusal costs the timeout, not the connection. A user waiting on a dead api
/// gets an answer and a client that can retry; a user waiting on a *wedged* hbbs
/// gets silence and a client that gives up somewhere else.
///
/// Measured through `request_relay_alone` because it returns the instant hbbs
/// answers — `connect` waits out its whole window on a refusal, so it can say
/// that a denial happened but never when.
#[tokio::test(flavor = "multi_thread")]
async fn a_denial_costs_the_timeout_and_not_the_connection() {
    let (w, alice, laptop) = faulty_world().await;

    w.fault().set(Fault::Blackhole);
    let started = Instant::now();
    let answer = alice
        .request_relay_alone(&laptop.id, TIMEOUT_MS * 6)
        .await
        .expect("hbbs never answered at all — that is the wedge this test exists for");
    let took = started.elapsed();

    assert!(
        !answer.refuse_reason.is_empty(),
        "hbbs answered a blackholed api with an empty RelayResponse, which a client reads as an allow"
    );
    assert!(
        answer.refuse_reason.to_lowercase().contains(UNAVAILABLE),
        "refused for the wrong reason: {}",
        answer.refuse_reason
    );
    // The floor matters as much as the ceiling: an answer that came back
    // *instantly* would mean the timeout is not being waited for at all, and the
    // 300 ms production default would be refusing connections that are merely
    // slow.
    assert!(
        took >= Duration::from_millis(TIMEOUT_MS / 2),
        "the denial came back in {took:?}, well inside the {TIMEOUT_MS} ms budget — was the api asked?"
    );
    assert!(
        took < Duration::from_millis(TIMEOUT_MS * 3),
        "the denial took {took:?}, which is past the timeout it was given by more than any round trip"
    );
}

/// Four connections, one dead api, and they must not queue. Serialised, this
/// costs four timeouts; it is the shape of failure where one unreachable api
/// takes the whole rendezvous server down rather than one connection at a time.
///
/// The bound is deliberately loose. The claim is not "concurrent to the
/// microsecond", it is "not serialised" — and those differ by a factor of four.
#[tokio::test(flavor = "multi_thread")]
async fn a_blackholed_api_does_not_serialise_the_connections_waiting_on_it() {
    let (w, alice, laptop) = faulty_world().await;
    let bob = w.controller("bob").await;
    let carol = w.controller("carol").await;
    let dave = w.controller("dave").await;

    w.fault().set(Fault::Blackhole);
    let started = Instant::now();
    let (a, b, c, d) = tokio::join!(
        alice.request_relay_alone(&laptop.id, TIMEOUT_MS * 8),
        bob.request_relay_alone(&laptop.id, TIMEOUT_MS * 8),
        carol.request_relay_alone(&laptop.id, TIMEOUT_MS * 8),
        dave.request_relay_alone(&laptop.id, TIMEOUT_MS * 8),
    );
    let took = started.elapsed();

    for (who, answer) in [("alice", a), ("bob", b), ("carol", c), ("dave", d)] {
        let answer = answer.unwrap_or_else(|| panic!("{who} never heard back from hbbs"));
        assert!(
            !answer.refuse_reason.is_empty(),
            "{who} was not refused while the api was blackholed"
        );
    }
    assert!(
        took < Duration::from_millis(TIMEOUT_MS * 3),
        "four refusals took {took:?}; serialised they would cost {} ms, and they appear to have been",
        TIMEOUT_MS * 4
    );
}

// ---------------------------------------------------------------- the api talks nonsense

/// The failure mode that looks like a bug in hbbs: something in front of the api
/// — a proxy, a login page, a captive portal — answers `200` with HTML. The
/// status says success and the body decides nothing, so the only safe reading is
/// that no decision was obtained.
#[tokio::test(flavor = "multi_thread")]
async fn a_200_full_of_html_is_not_an_allow() {
    let (w, alice, mut laptop) = faulty_world().await;

    w.fault().set(Fault::Reply(
        200,
        "<!doctype html><html><body><h1>Sign in to continue</h1></body></html>".to_owned(),
    ));
    let refusal = refusal_for(&alice, &mut laptop, "with a 200 full of html").await;
    assert!(
        refusal.to_lowercase().contains(UNAVAILABLE),
        "refused for the wrong reason: {refusal}"
    );

    // The body is in the log on purpose (`auth.rs:951`) — the whole point of
    // that branch is that a status code alone sends the operator hunting in the
    // wrong place.
    assert!(
        w.hbbs.wait_for_log("unparseable json", 4_000).await,
        "hbbs did not say what it could not parse:\n{}",
        w.hbbs.log()
    );
    assert!(
        w.hbbs.log().contains("Sign in to continue"),
        "the log names no body, so the operator cannot see what answered:\n{}",
        w.hbbs.log()
    );
}

/// An error status carrying a perfectly good denial body. The body must not be
/// believed: `{"allow":false,"reason":…}` under a `500` is a server that fell
/// over mid-thought, and showing its reason to the user would put a database
/// error on an end user's screen as if it were an access decision.
#[tokio::test(flavor = "multi_thread")]
async fn an_error_status_never_reaches_the_user_as_its_own_reason() {
    let (w, alice, mut laptop) = faulty_world().await;

    w.fault().set(Fault::Reply(
        500,
        r#"{"allow":false,"reason":"ECONNREFUSED writing to the audit collection"}"#.to_owned(),
    ));
    let refusal = refusal_for(&alice, &mut laptop, "with a 500 carrying a denial body").await;

    assert!(
        !refusal.contains("ECONNREFUSED"),
        "the api's internal error was shown to the user verbatim: {refusal}"
    );
    assert!(
        refusal.to_lowercase().contains(UNAVAILABLE),
        "a 500 was treated as a considered refusal rather than as no answer: {refusal}"
    );
    assert!(
        w.hbbs.wait_for_log("answered 500", 4_000).await,
        "the status hbbs actually got is not in the log:\n{}",
        w.hbbs.log()
    );
}

/// The mistyped-secret case. `apps/api` answers `401` with a body that reads
/// like a refusal, and if hbbs passed it through, every user in the fleet would
/// be told they are unauthorized while the real fault is one line of
/// configuration.
#[tokio::test(flavor = "multi_thread")]
async fn a_401_reads_as_unavailable_and_not_as_unauthorized() {
    let (w, alice, mut laptop) = faulty_world().await;

    w.fault().set(Fault::Reply(
        401,
        r#"{"allow":false,"reason":"Unauthorized"}"#.to_owned(),
    ));
    let refusal = refusal_for(&alice, &mut laptop, "with a 401").await;

    assert!(
        !refusal.to_lowercase().contains("unauthorized"),
        "a misconfigured secret was reported to the user as their own problem: {refusal}"
    );
    assert!(
        refusal.to_lowercase().contains(UNAVAILABLE),
        "refused for the wrong reason: {refusal}"
    );
    assert!(
        w.hbbs.wait_for_log("answered 401", 4_000).await,
        "the 401 is not in the log, so nobody would find the mistyped secret:\n{}",
        w.hbbs.log()
    );
}

// ---------------------------------------------------------------- the whole sweep

/// Every fault this harness can produce, against one world, asserting the one
/// property the milestone rests on: **none of them is an allow.**
///
/// The individual tests above each check *why* a particular fault was refused.
/// This one exists because the dangerous failure is not a wrong reason, it is a
/// mode nobody thought about — so it is written as a list that a future fault
/// gets added to.
#[tokio::test(flavor = "multi_thread")]
async fn no_fault_mode_produces_an_allow() {
    let (w, alice, mut laptop) = faulty_world().await;
    let baseline = counter(&decisions(&w).await, "allow");

    let modes: Vec<(&str, Fault)> = vec![
        ("a connection accepted and closed", Fault::Hangup),
        ("a connection accepted and never answered", Fault::Blackhole),
        ("an answer past the timeout", Fault::Slow(TIMEOUT_MS + 1_500)),
        ("an empty 200", Fault::Reply(200, String::new())),
        ("a 200 that is not json at all", Fault::Reply(200, "not json".to_owned())),
        // Valid json, wrong shape: `allow` is deliberately not defaulted
        // (`auth.rs:398`), so a body missing it is a contract break and not a
        // quiet refusal.
        ("a 200 whose json has no `allow`", Fault::Reply(200, r#"{"ok":true}"#.to_owned())),
        ("a 200 whose `allow` is a string", Fault::Reply(200, r#"{"allow":"true"}"#.to_owned())),
        ("a truncated body", Fault::Reply(200, r#"{"allow":tr"#.to_owned())),
        ("a 502 from a proxy", Fault::Reply(502, "<html>Bad Gateway</html>".to_owned())),
        ("a 503", Fault::Reply(503, r#"{"error":"starting up"}"#.to_owned())),
    ];

    for (what, fault) in modes {
        keep_registered(&w, &mut laptop).await;
        w.fault().set(fault);
        let refusal = refusal_for(&alice, &mut laptop, what).await;
        assert!(
            refusal.to_lowercase().contains(UNAVAILABLE),
            "{what}: refused, but not as an unavailable api — {refusal}"
        );
    }

    assert_eq!(
        counter(&decisions(&w).await, "allow"),
        baseline,
        "one of the fault modes produced an allow:\n{}",
        decisions(&w).await
    );

    // Healed, and the same user gets in again — so every refusal above was the
    // fault and not something the sweep broke on its way through.
    w.fault().heal();
    keep_registered(&w, &mut laptop).await;
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the world never recovered after the sweep");

    // A device nobody has heard of, for luck: the sweep must not have left a
    // cached decision that admits anyone to anything.
    let stranger = next_device_id();
    let answer = alice.request_relay_alone(&stranger, 1_500).await;
    assert!(
        answer.is_none(),
        "hbbs answered for an id it has never seen: {answer:?}"
    );
}
