//! T3.5 verification: break-glass against the real `hbbs` binary.
//!
//! The unit tests in `src/breakglass.rs` prove the verifier. This proves the
//! *deployment*: that a capability pasted into `access_token` travels in
//! `PunchHoleRequest.token` with a stock client, that hbbs verifies it without
//! asking the auth API, and — the case the whole feature exists for — that it
//! still works when the auth API is not answering at all.
//!
//! The minting here is a **deliberate re-implementation** of
//! `apps/api/src/scripts/mint-breakglass.ts`, not a call into
//! `breakglass::mint_for_test`. A shared helper would let hbbs and this test
//! agree with each other while both disagreeing with the thing that actually
//! mints capabilities in production — and the detail most likely to drift is
//! exactly the one a shared helper would hide: the signature covers the
//! **base64url payload text**, not the decoded JSON.

mod harness;

use harness::*;
use hbb_common::{
    rendezvous_proto::*,
    sodiumoxide::crypto::sign,
    tokio::{self, time::sleep},
};
use std::time::Duration;

/// `mint-breakglass.ts`, line for line.
fn mint(sk: &sign::SecretKey, admin: &str, device: &str, exp: i64, nonce: &str) -> String {
    let payload =
        format!(r#"{{"admin_id":"{admin}","to_id":"{device}","exp":{exp},"nonce":"{nonce}"}}"#);
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    // `sign(null, Buffer.from(payloadB64), privateKey)` — over the text.
    let sig = sign::sign_detached(payload_b64.as_bytes(), sk);
    format!(
        "bg.{payload_b64}.{}",
        base64::encode_config(sig.as_ref(), base64::URL_SAFE_NO_PAD)
    )
}

/// The base64 form `keygen-breakglass.ts` prints for `BREAKGLASS_PUBKEY`: the
/// raw 32 bytes, DER prefix already stripped.
fn keypair() -> (String, sign::SecretKey) {
    hbb_common::sodiumoxide::init().ok();
    let (pk, sk) = sign::gen_keypair();
    (base64::encode(pk.as_ref()), sk)
}

fn in_minutes(mins: i64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    now + mins * 60
}

fn armed(api: &Stub, pubkey: &str) -> Vec<String> {
    let mut args = auth_args(api);
    args.push("--breakglass-pubkey".into());
    args.push(pubkey.to_owned());
    args
}

/// A dead port for the api, so every ordinary decision fails closed. This is
/// the outage break-glass exists for.
fn armed_with_no_api(pubkey: &str) -> Vec<String> {
    vec![
        "--auth-api-url".into(),
        format!("http://127.0.0.1:{}", dead_port()),
        "--auth-api-secret".into(),
        "t35-shared-secret".into(),
        "--auth-timeout-ms".into(),
        "400".into(),
        "--breakglass-pubkey".into(),
        pubkey.to_owned(),
    ]
}

// ---------------------------------------------------------------- tests

/// The one that matters: the api is unreachable, every ordinary user is denied,
/// and the capability still gets through.
#[tokio::test(flavor = "multi_thread")]
async fn a_capability_authorizes_while_the_api_is_down() {
    let (pubkey, sk) = keypair();
    let s = hbbs(&armed_with_no_api(&pubkey)).await;
    let mut b = register(s.port, "t35-dev-1").await;

    // An ordinary user is refused — fail-closed is working, so this really is
    // the outage case and not a server that is quietly allowing everything.
    let denied = punch(
        s.port,
        &s.key,
        "t35-dev-1",
        "an-ordinary-token",
        ConnType::DEFAULT_CONN,
        REFUSAL_WAIT,
    )
    .await
    .expect("fail-closed did not refuse an ordinary user");
    assert!(!denied.other_failure.is_empty());

    // The operator pastes their capability into `access_token` and connects.
    let token = mint(&sk, "alice", "t35-dev-1", in_minutes(30), "t35-nonce-1");
    let refused = punch(
        s.port,
        &s.key,
        "t35-dev-1",
        &token,
        ConnType::DEFAULT_CONN,
        ALLOW_WAIT,
    )
    .await;
    assert!(refused.is_none(), "break-glass was refused: {refused:?}");

    // …and the device is actually contacted, carrying the nonce as the audit
    // ref, which is what makes even an emergency session revocable.
    // `FetchLocalAddr` rather than `PunchHole`, because both ends are on
    // 127.0.0.1 and hbbs takes the same-intranet branch. Either carries the
    // metadata; which one arrives is not what this test is about.
    let carried = match next_from_hbbs(&mut b).await.union {
        Some(rendezvous_message::Union::FetchLocalAddr(fla)) => fla.controlled_context,
        Some(rendezvous_message::Union::PunchHole(ph)) => ph.controlled_context,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(
        carried.conn_audit_ref, "t35-nonce-1",
        "a break-glass session with no audit ref is a session nobody can revoke"
    );

    assert!(
        s.wait_for_log("BREAK-GLASS USED", 4_000).await,
        "T3.5 requires a warn on every use; log was:\n{}",
        s.log()
    );
}

/// Armed or not, a capability is never forwarded to the api as if it were a
/// login token.
#[tokio::test(flavor = "multi_thread")]
async fn a_capability_is_decided_locally_even_when_the_api_is_healthy() {
    let (pubkey, sk) = keypair();
    // The api would deny anything it is asked about, so an allow proves nobody
    // asked it.
    let api = stub(200, DENY).await;
    let s = hbbs(&armed(&api, &pubkey)).await;
    let mut b = register(s.port, "t35-dev-2").await;

    let token = mint(&sk, "alice", "t35-dev-2", in_minutes(30), "t35-nonce-2");
    let refused = punch(s.port, &s.key, "t35-dev-2", &token, ConnType::DEFAULT_CONN, ALLOW_WAIT).await;

    assert!(refused.is_none(), "the api's denial reached a capability: {refused:?}");
    assert_eq!(api.calls(), 0, "the emergency path asked the api");
    let _ = next_from_hbbs(&mut b).await;
}

/// Expired, wrong-device, and forged capabilities are all refused — and the
/// device is never contacted.
#[tokio::test(flavor = "multi_thread")]
async fn expired_wrong_device_and_forged_capabilities_are_refused() {
    let (pubkey, sk) = keypair();
    let (_, other_sk) = keypair();
    let api = stub(200, DENY).await;
    let s = hbbs(&armed(&api, &pubkey)).await;
    let _b = register(s.port, "t35-dev-3").await;
    let _other = register(s.port, "t35-dev-4").await;

    for (name, token) in [
        ("expired", mint(&sk, "alice", "t35-dev-3", in_minutes(-1), "t35-n-exp")),
        // Minted for a different device, presented at this one.
        (
            "wrong device",
            mint(&sk, "alice", "t35-dev-4", in_minutes(30), "t35-n-dev"),
        ),
        // Signed with a key hbbs does not hold.
        (
            "forged",
            mint(&other_sk, "alice", "t35-dev-3", in_minutes(30), "t35-n-forge"),
        ),
        // A year long: what a leaked private key would mint, and past the
        // ceiling the real minter itself refuses to exceed.
        (
            "too long lived",
            mint(&sk, "alice", "t35-dev-3", in_minutes(60 * 24 * 365), "t35-n-long"),
        ),
    ] {
        let refused = punch(
            s.port,
            &s.key,
            "t35-dev-3",
            &token,
            ConnType::DEFAULT_CONN,
            REFUSAL_WAIT,
        )
        .await
        .unwrap_or_else(|| panic!("a {name} capability was allowed"));
        assert!(
            !refused.other_failure.is_empty(),
            "a {name} capability was refused without telling the operator why"
        );
        assert!(refused.socket_addr.is_empty(), "a {name} capability brokered something");
    }
    assert_eq!(api.calls(), 0);
}

/// A replay inside the validity window is refused. The first use has to be a
/// *different* connection than the retry the decision cache covers, so this
/// asks for a file transfer the second time — a different cache key, the same
/// capability.
#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_capability_is_refused() {
    let (pubkey, sk) = keypair();
    let api = stub(200, DENY).await;
    let s = hbbs(&armed(&api, &pubkey)).await;
    let mut b = register(s.port, "t35-dev-5").await;

    let token = mint(&sk, "alice", "t35-dev-5", in_minutes(30), "t35-nonce-5");
    let first = punch(s.port, &s.key, "t35-dev-5", &token, ConnType::DEFAULT_CONN, ALLOW_WAIT).await;
    assert!(first.is_none(), "the first use was refused: {first:?}");
    let _ = next_from_hbbs(&mut b).await;

    let replay = punch(
        s.port,
        &s.key,
        "t35-dev-5",
        &token,
        ConnType::FILE_TRANSFER,
        REFUSAL_WAIT,
    )
    .await
    .expect("a replayed capability was allowed");
    assert!(
        replay.other_failure.contains("already been used"),
        "unexpected refusal: {:?}",
        replay.other_failure
    );
}

/// A client's punch retries must not burn the capability. Same token, same conn
/// type, twice — which is what `client.rs:913` does when the peer is slow.
#[tokio::test(flavor = "multi_thread")]
async fn a_punch_retry_is_not_a_replay() {
    let (pubkey, sk) = keypair();
    let api = stub(200, DENY).await;
    let s = hbbs(&armed(&api, &pubkey)).await;
    let mut b = register(s.port, "t35-dev-6").await;

    let token = mint(&sk, "alice", "t35-dev-6", in_minutes(30), "t35-nonce-6");
    for attempt in 1..=2 {
        let refused =
            punch(s.port, &s.key, "t35-dev-6", &token, ConnType::DEFAULT_CONN, ALLOW_WAIT).await;
        assert!(refused.is_none(), "attempt {attempt} was refused: {refused:?}");
        let _ = next_from_hbbs(&mut b).await;
    }
}

/// With no `BREAKGLASS_PUBKEY` the path is off, and a capability is refused as
/// a capability rather than forwarded to the api as a login token — an operator
/// whose real problem is a disarmed server must not be told their session
/// expired.
#[tokio::test(flavor = "multi_thread")]
async fn with_no_public_key_the_path_is_off() {
    let (_, sk) = keypair();
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let _b = register(s.port, "t35-dev-7").await;

    let token = mint(&sk, "alice", "t35-dev-7", in_minutes(30), "t35-nonce-7");
    let refused = punch(
        s.port,
        &s.key,
        "t35-dev-7",
        &token,
        ConnType::DEFAULT_CONN,
        REFUSAL_WAIT,
    )
    .await
    .expect("a disarmed server allowed a capability");

    assert_eq!(refused.other_failure, "Break-glass is not enabled");
    assert_eq!(api.calls(), 0, "a capability was forwarded to the api");
}

/// A mistyped public key is a refusal to start, not a server that looks armed
/// and is not. Discovering that during the outage is the failure this avoids.
#[tokio::test(flavor = "multi_thread")]
async fn a_bad_public_key_refuses_to_start() {
    let api = stub(200, ALLOW).await;
    let mut args = auth_args(&api);
    args.push("--breakglass-pubkey".into());
    args.push("this-is-not-a-key".into());

    let err = hbbs_expect_exit(&args).await;
    assert!(
        err.contains("BREAKGLASS_PUBKEY"),
        "hbbs died without naming the setting: {err}"
    );
}

// ------------------------------------------------ T3.6: local-first audit

/// Every use is on disk on the **hbbs host**, fsynced, before the connection is
/// allowed — and it is there whether or not the api ever hears about it.
#[tokio::test(flavor = "multi_thread")]
async fn a_use_is_recorded_locally_during_the_outage() {
    let (pubkey, sk) = keypair();
    let s = hbbs(&armed_with_no_api(&pubkey)).await;
    let mut b = register(s.port, "t36-dev-1").await;

    let token = mint(&sk, "alice", "t36-dev-1", in_minutes(30), "t36-nonce-1");
    assert!(
        punch(s.port, &s.key, "t36-dev-1", &token, ConnType::DEFAULT_CONN, ALLOW_WAIT)
            .await
            .is_none(),
        "break-glass was refused during the outage it exists for"
    );
    let _ = next_from_hbbs(&mut b).await;

    // Relative path, so it lands in hbbs's working directory.
    let audit = s.dir().join("breakglass-audit.log");
    let text = std::fs::read_to_string(&audit).unwrap_or_default();
    assert!(
        text.contains("t36-nonce-1") && text.contains("\"outcome\":\"used\""),
        "no local record of an emergency access; file was:\n{text}"
    );
    // Nothing acknowledged yet — the api has never answered.
    assert!(
        !s.dir().join("breakglass-audit.log.cursor").exists(),
        "the cursor advanced without the api accepting anything"
    );
}

/// The reconciliation itself: hbbs records during the outage, the api comes
/// back, and the record is replayed without anybody asking.
#[tokio::test(flavor = "multi_thread")]
async fn records_are_replayed_once_the_api_comes_back() {
    let (pubkey, sk) = keypair();
    let (on, reply) = switchable();
    let api = stub_by(reply).await;

    let mut args = auth_args(&api);
    args.push("--breakglass-pubkey".into());
    args.push(pubkey.clone());
    // Fast enough to watch, slow enough not to spin.
    args.push("--breakglass-reconcile-sec".into());
    args.push("1".into());
    let s = hbbs(&args).await;
    let mut b = register(s.port, "t36-dev-2").await;

    let token = mint(&sk, "alice", "t36-dev-2", in_minutes(30), "t36-nonce-2");
    assert!(
        punch(s.port, &s.key, "t36-dev-2", &token, ConnType::DEFAULT_CONN, ALLOW_WAIT)
            .await
            .is_none()
    );
    let _ = next_from_hbbs(&mut b).await;

    // While the api is answering 503, the cursor must not move — otherwise the
    // record is marked delivered to a server that never got it.
    let cursor = s.dir().join("breakglass-audit.log.cursor");
    sleep(Duration::from_millis(2_500)).await;
    assert!(!cursor.exists(), "the cursor advanced while the api was failing");

    on.store(true, std::sync::atomic::Ordering::SeqCst);

    let mut delivered = false;
    for _ in 0..80 {
        if cursor.exists() {
            delivered = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(delivered, "the record was never replayed; hbbs log:\n{}", s.log());

    // The api got the record, in the documented shape.
    let posted = api
        .requests
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.contains("/api/internal/breakglass/reconcile") && r.contains("t36-nonce-2"))
        .cloned()
        .expect("the reconcile POST never carried the record");
    assert!(posted.contains("x-hbbs-secret"), "reconciliation went unauthenticated");
    assert!(posted.contains("\"admin_id\":\"alice\""));
    assert!(posted.contains("\"outcome\":\"used\""));

    // And it stops being sent. Counted from the moment of delivery, not from
    // the start: every tick during the outage POSTed this record too and was
    // answered 503, which is the retry working rather than a duplicate.
    let sent = |api: &Stub| {
        api.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.contains("t36-nonce-2"))
            .count()
    };
    let at_delivery = sent(&api);
    sleep(Duration::from_millis(3_000)).await;
    assert_eq!(
        sent(&api),
        at_delivery,
        "the cursor did not stop an acknowledged record being replayed"
    );
}
