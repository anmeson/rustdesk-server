//! T3.7 verification: the audit trail for connections that never became one.
//!
//! Everything that *becomes* a session is in `connection_logs` on the api side.
//! A refusal leaves nothing there at all whenever the api was never asked —
//! which is every no-token refusal, every fail-closed denial, and every
//! break-glass refusal. Those are precisely the attempts an operator wants to
//! see, so hbbs has to be the one that records them.
//!
//! Two surfaces, both checked here against the real binary: one structured log
//! line per decision, and `auth-decisions` in the runtime console.

mod harness;

use harness::*;
use hbb_common::{rendezvous_proto::*, tokio};

/// Every decision, not only the refusals — `AUTH_TIMEOUT_MS` cannot be tuned
/// (T5.8) from denials alone.
#[tokio::test(flavor = "multi_thread")]
async fn allows_and_denials_are_both_logged_with_their_latency() {
    let api = stub_by(|body: &str| {
        if body.contains("t37-dev-1") {
            (200, ALLOW.to_owned())
        } else {
            (200, DENY.to_owned())
        }
    })
    .await;
    let s = hbbs(&auth_args(&api)).await;
    let mut allowed = register(s.port, "t37-dev-1").await;
    let _refused = register(s.port, "t37-dev-2").await;

    assert!(punch(s.port, &s.key, "t37-dev-1", "tok", ConnType::DEFAULT_CONN, ALLOW_WAIT)
        .await
        .is_none());
    let _ = next_from_hbbs(&mut allowed).await;
    assert!(punch(s.port, &s.key, "t37-dev-2", "tok", ConnType::DEFAULT_CONN, REFUSAL_WAIT)
        .await
        .is_some());

    assert!(s.wait_for_log("authz gate=punch outcome=allow", 4_000).await);
    assert!(s.wait_for_log("authz gate=punch outcome=deny", 4_000).await);

    let log = s.log();
    let line = log
        .lines()
        .find(|l| l.contains("authz gate=punch outcome=allow"))
        .expect("no allow line");
    // key=value, so this is greppable by a person and parseable by whatever
    // ships the logs.
    for field in ["source=api", "to_id=\"t37-dev-1\"", "conn_type=\"DEFAULT_CONN\"", "ms=", "ref="] {
        assert!(line.contains(field), "{field:?} missing from: {line}");
    }
    let deny = log
        .lines()
        .find(|l| l.contains("authz gate=punch outcome=deny"))
        .expect("no deny line");
    assert!(deny.contains("You do not have access to this device."));
}

/// The gate is in the line, because "which of the two chokepoints stopped this"
/// is the first thing anyone asks and the one thing the api cannot answer.
#[tokio::test(flavor = "multi_thread")]
async fn the_relay_gate_is_named_separately_from_the_punch_gate() {
    let api = stub(200, DENY).await;
    let s = hbbs(&auth_args(&api)).await;
    let _b = register(s.port, "t37-dev-3").await;

    assert!(request_relay(s.port, "t37-dev-3", "tok", None, REFUSAL_WAIT).await.is_some());

    assert!(
        s.wait_for_log("authz gate=relay outcome=deny", 4_000).await,
        "log was:\n{}",
        s.log()
    );
}

/// A refusal the api never heard about still leaves a record. This is the case
/// the whole task exists for.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_the_api_never_saw_is_still_recorded() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let _b = register(s.port, "t37-dev-4").await;

    // No token: answered locally, so `connection_logs` will never have a row.
    assert!(punch(s.port, &s.key, "t37-dev-4", "", ConnType::DEFAULT_CONN, REFUSAL_WAIT)
        .await
        .is_some());
    assert_eq!(api.calls(), 0);

    assert!(s.wait_for_log("source=no-token", 4_000).await, "log was:\n{}", s.log());

    let out = console(s.port, "auth-decisions").await;
    assert!(out.contains("deny=1"), "console said: {out}");
    assert!(out.contains("no-token=1"), "console said: {out}");
    assert!(out.contains("t37-dev-4"), "the denial tail is missing the attempt: {out}");
}

/// The console command itself: summary, the denial tail, paging, and clearing.
#[tokio::test(flavor = "multi_thread")]
async fn the_console_counts_decisions_and_lists_refusals() {
    let api = stub(200, DENY).await;
    let s = hbbs(&auth_args(&api)).await;
    let _b = register(s.port, "t37-dev-5").await;

    for _ in 0..3 {
        // A fresh token each time, or the decision cache would answer — and a
        // cached *denial* is exactly what `authorize` refuses to do, so this
        // would pass either way and prove nothing.
        assert!(punch(
            s.port,
            &s.key,
            "t37-dev-5",
            &format!("tok-{}", hbb_common::rand::random::<u32>()),
            ConnType::DEFAULT_CONN,
            REFUSAL_WAIT
        )
        .await
        .is_some());
    }

    let out = console(s.port, "auth-decisions").await;
    assert!(out.contains("allow=0 deny=3"), "console said: {out}");
    assert!(out.contains("api=3"), "console said: {out}");
    assert!(out.contains("latency_mean="), "console said: {out}");
    assert!(out.contains("break-glass: armed=false"), "console said: {out}");
    assert_eq!(
        out.lines().filter(|l| l.contains("t37-dev-5")).count(),
        3,
        "console said: {out}"
    );

    // It answers to its short name, and pages.
    let paged = console(s.port, "ad 0 1").await;
    assert_eq!(paged.lines().filter(|l| l.contains("t37-dev-5")).count(), 1);

    assert!(console(s.port, "auth-decisions -").await.contains("cleared"));
    assert!(console(s.port, "ad").await.contains("allow=0 deny=0"));

    // And it is listed in the help, next to `punch-requests`.
    let help = console(s.port, "h").await;
    assert!(help.contains("auth-decisions(ad)"), "help was: {help}");
}

/// The console is loopback-only and unauthenticated, which is upstream's
/// design. Worth an assertion now that it exposes who was refused and from
/// where — a deployment that binds it publicly would be handing that out.
#[tokio::test(flavor = "multi_thread")]
async fn the_console_is_reachable_only_from_loopback() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    // Not a network test — there is one interface here. What is asserted is the
    // branch: `handle_listener2` answers a command only for a loopback peer and
    // otherwise falls through to the protobuf path, where a bare string is not
    // a parseable message and gets no reply.
    let out = console(s.port, "auth-decisions").await;
    assert!(out.contains("allow=0"), "the loopback console did not answer: {out}");
}
