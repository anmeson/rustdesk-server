//! T5.4 — break-glass, end to end, through the outage it exists for.
//!
//! `t35_breakglass.rs` proves hbbs's verifier against a stub. This proves the
//! *feature*: that the two scripts an operator runs at three in the morning
//! produce something these servers accept, that it works while `apps/api` is
//! genuinely not there, that the record of it survives the outage on hbbs's own
//! disk, and that the record reaches the console once the api is back.
//!
//! **The thing that must be true throughout is the boring one: ordinary users
//! stay denied.** Break-glass is a hole in a fail-closed wall (decision D1), and
//! a hole that widens while the api is down would be worse than no wall — so
//! every test here that allows a capability also checks that an ordinary token
//! is refused at the same moment, on the same server.
//!
//! The outage is produced with **SIGKILL**, not a graceful stop. That is the
//! honest shape of it — a host that went away, not a service asked politely —
//! and it is the case where hbbs's local-first audit has to carry the record on
//! its own.

mod harness;

use std::time::Duration;

use harness::{
    breakglass::{audit_records, keygen, mint, mint_expired, mint_refused, Keys},
    peer::{Controller, Device},
    world::World,
};
use hbb_common::{
    rendezvous_proto::*,
    tokio::{self, time::sleep},
};

const WAIT: u64 = 8_000;
/// Long enough for a refusal to have come back; short enough not to pad the run.
const REFUSAL: u64 = 5_000;

/// A world with the emergency path armed on both servers, and the keys that arm
/// it. The private key is written into hbbs's temp directory purely because it
/// is a scratch space that gets cleaned up — nothing ever reads it from there
/// but the minting tool, which in production runs on someone's laptop.
async fn armed_world() -> (World, Keys) {
    let scratch = std::env::temp_dir();
    let keys = keygen(&scratch);
    let world = World::builder().breakglass(&keys.pubkey).up().await;
    assert!(
        world.hbbs.wait_for_log("break-glass is ARMED", WAIT).await,
        "hbbs did not arm break-glass:\n{}",
        world.hbbs.log()
    );
    (world, keys)
}

/// Uses a capability as the operator does: pasted into `access_token`, so it
/// travels in `PunchHoleRequest.token` exactly like an ordinary one.
fn operator(w: &World, capability: &str) -> Controller {
    Controller {
        user_id: String::new(),
        email: "operator@test.invalid".to_owned(),
        token: capability.to_owned(),
        id: "operator".to_owned(),
        hbbs_port: w.hbbs.port,
        key: w.hbbs.key.clone(),
    }
}

/// An ordinary user who genuinely has access — so that when they are refused, it
/// is the outage refusing them and not a missing grant.
async fn ordinary_user_is_refused(w: &World, user: &Controller, device: &mut Device) {
    let refusal = user
        .connect(device, ConnType::DEFAULT_CONN, REFUSAL)
        .await
        .expect_err("an ordinary user got through during the outage — fail-closed is not holding");
    assert!(
        refusal.to_lowercase().contains("unavailable"),
        "refused for the wrong reason: {refusal}"
    );
}

// ---------------------------------------------------------------- the outage

/// The one the feature exists for, with every part real: the api is gone, the
/// capability came out of `mint-breakglass.ts`, and the user who *does* have
/// access cannot get in.
#[tokio::test(flavor = "multi_thread")]
async fn a_minted_capability_authorizes_while_the_api_is_down() {
    let (mut w, keys) = armed_world().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    // Everything normal works first, so the outage below is the only variable.
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the owner could not connect before the outage");

    w.api.kill_now();
    assert!(w.api.is_down(), "the api is still listening");
    // Past the decision cache, so nothing below is answered from memory.
    w.let_auth_cache_lapse(5_000).await;

    ordinary_user_is_refused(&w, &alice, &mut laptop).await;

    let capability = mint(&keys, "alice-the-admin", &laptop.id, 30);
    let operator = operator(&w, &capability);
    let (brokerage, _) = operator
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the capability did not get through during the outage");

    // The nonce doubles as the `conn_audit_ref`, so an emergency session is
    // attributable — and therefore revocable — the same way every other one is.
    let reference = brokerage
        .conn_audit_ref
        .expect("an emergency session carried no conn_audit_ref");
    assert!(!reference.is_empty());

    // hbbs never asked anybody. It could not have: there was nobody to ask.
    assert!(
        w.hbbs.wait_for_log("break-glass", WAIT).await,
        "no break-glass line in hbbs's log:\n{}",
        w.hbbs.log()
    );

    // And the ordinary user is *still* refused afterwards — the capability
    // opened one door, not the building.
    ordinary_user_is_refused(&w, &alice, &mut laptop).await;
}

/// The record exists during the outage, on hbbs's own disk, before anyone has
/// been told — which is the whole of T3.6's local-first design.
#[tokio::test(flavor = "multi_thread")]
async fn the_local_audit_record_is_written_during_the_outage() {
    let (mut w, keys) = armed_world().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    w.api.kill_now();
    w.let_auth_cache_lapse(5_000).await;

    let capability = mint(&keys, "alice-the-admin", &laptop.id, 30);
    operator(&w, &capability)
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the capability did not get through");

    // Written and fsynced *before* the connection was allowed, so it is already
    // there — no waiting, and that ordering is the point: a record written
    // afterwards is a record the same power cut takes with it.
    let records = audit_records(w.hbbs.dir());
    assert_eq!(records.len(), 1, "expected one audit record, got {records:?}");
    assert_eq!(records[0]["admin_id"], "alice-the-admin");
    assert_eq!(records[0]["to_id"], laptop.id);
    assert_eq!(records[0]["outcome"], "used");
    assert!(records[0]["nonce"].as_str().is_some_and(|n| !n.is_empty()));

    // Nothing has acknowledged it, so the cursor has not moved past it.
    let cursor = w.hbbs.dir().join("breakglass-audit.log.cursor");
    let acknowledged = std::fs::read_to_string(&cursor).unwrap_or_default();
    assert!(
        acknowledged.trim().is_empty() || acknowledged.contains('0'),
        "the cursor advanced past a record nobody received: {acknowledged:?}"
    );
}

/// And it reaches the console once the api is back — without anyone doing
/// anything.
#[tokio::test(flavor = "multi_thread")]
async fn the_record_is_reconciled_when_the_api_comes_back() {
    let (mut w, keys) = armed_world().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    w.api.kill_now();
    w.let_auth_cache_lapse(5_000).await;

    let capability = mint(&keys, "alice-the-admin", &laptop.id, 30);
    operator(&w, &capability)
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the capability did not get through");
    assert_eq!(audit_records(w.hbbs.dir()).len(), 1);

    // Back on the same port with the same database — to hbbs, an api that
    // returns anywhere else is an outage that never ended.
    w.api.restart().await;
    // The console has to be signed in again: the process that held the session
    // is gone, even though its rows are not.
    let console = harness::api::Console::login(&w.api).await;

    // No operator action. hbbs replays on its own timer.
    let mut seen = serde_json::Value::Null;
    for _ in 0..40 {
        sleep(Duration::from_millis(500)).await;
        let page = console.get("/api/admin/breakglass").await;
        if page["total"].as_i64().unwrap_or(0) > 0 {
            seen = page;
            break;
        }
    }
    assert_eq!(seen["total"], 1, "the record never reached the console: {seen}");
    let use_row = &seen["uses"][0];
    assert_eq!(use_row["adminId"], "alice-the-admin", "{seen}");
    assert_eq!(use_row["targetDeviceId"], laptop.id, "{seen}");
    // The console resolved it to a real device, so the operator sees a machine
    // and not just an id.
    assert_eq!(use_row["device"]["rustdeskId"], laptop.id, "{seen}");
    // hbbs's clock, not ours: these records arrive late by construction.
    assert!(use_row["usedAt"].as_str().is_some(), "{seen}");
    // The capability's own expiry travelled with the record (T2.7) — without it
    // the console could say an emergency access happened but not whether it is
    // still happening.
    assert!(use_row["expiresAt"].as_str().is_some(), "no expiry reached the console: {seen}");

    // It is an *open window*, which is what the console's fleet-wide banner
    // reads — a 30-minute capability used a moment ago is still live.
    let active = console.get("/api/admin/breakglass/active").await;
    assert!(
        active["active"].as_i64().unwrap_or(0) >= 1,
        "an emergency access in its window did not show as active: {active}"
    );

    // Replayed exactly once: hbbs advances its cursor only on a 2xx, and the
    // api's unique index on `nonce` absorbs a re-send. Give the reconciler a few
    // more ticks and the count must not climb.
    sleep(Duration::from_secs(3)).await;
    let again = console.get("/api/admin/breakglass").await;
    assert_eq!(again["total"], 1, "the record was stored more than once: {again}");
}

// ---------------------------------------------------------------- refusals

/// Every way a capability can be wrong, against the real servers with the real
/// tool's output as the control.
#[tokio::test(flavor = "multi_thread")]
async fn expired_wrong_device_forged_and_replayed_capabilities_are_all_refused() {
    let (mut w, keys) = armed_world().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    let mut other = w.device(&alice).await;

    w.api.kill_now();
    w.let_auth_cache_lapse(5_000).await;

    // Expired — the one case `mint-breakglass.ts` will not produce, signed with
    // the operator's own key so that only the clock is wrong.
    let expired = mint_expired(&keys, "alice-the-admin", &laptop.id);
    assert!(
        operator(&w, &expired)
            .connect(&mut laptop, ConnType::DEFAULT_CONN, REFUSAL)
            .await
            .is_err(),
        "an expired capability was accepted"
    );

    // Scoped to another device. A capability names exactly one machine.
    let elsewhere = mint(&keys, "alice-the-admin", &other.id, 30);
    assert!(
        operator(&w, &elsewhere)
            .connect(&mut laptop, ConnType::DEFAULT_CONN, REFUSAL)
            .await
            .is_err(),
        "a capability for another device opened this one"
    );

    // Signed by a key these servers do not hold — the case that matters most,
    // because it is the one an attacker can attempt without stealing anything.
    let attacker = keygen(&std::env::temp_dir());
    let forged = mint(&attacker, "alice-the-admin", &laptop.id, 30);
    assert!(
        operator(&w, &forged)
            .connect(&mut laptop, ConnType::DEFAULT_CONN, REFUSAL)
            .await
            .is_err(),
        "a capability signed by an unknown key was accepted"
    );

    // Nothing above was allowed, so nothing above was recorded as used.
    let records = audit_records(w.hbbs.dir());
    assert!(
        records.iter().all(|r| r["outcome"] != "used"),
        "a refused capability was recorded as used: {records:?}"
    );

    // And a real one, used twice.
    //
    // **Single use does not mean single connection, and the difference is the
    // decision cache.** The cache sits deliberately *in front of* the break-glass
    // verifier (`auth.rs:805-825`): a client sends the same `PunchHoleRequest` up
    // to three times, so without it a peer slow to answer would burn the
    // capability on attempt one and be refused as a replay on attempt two — the
    // emergency path failing in exactly the conditions that produced the
    // emergency. Within `AUTH_CACHE_TTL_MS` the same capability to the same
    // device is therefore answered from memory, allow included, and the nonce is
    // never consulted.
    //
    // So both halves are asserted: reusable inside the window, refused outside
    // it. Anything else would be testing a system that fails an operator at the
    // worst moment, or one whose capabilities never expire.
    let once = mint(&keys, "alice-the-admin", &laptop.id, 30);
    operator(&w, &once)
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("a valid capability was refused");
    operator(&w, &once)
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("a retry inside the cache window was refused — a slow peer would burn the capability");

    w.let_auth_cache_lapse(5_000).await;
    let replayed = operator(&w, &once)
        .connect(&mut laptop, ConnType::DEFAULT_CONN, REFUSAL)
        .await
        .expect_err("a capability was accepted again after the cache lapsed");
    assert!(
        replayed.to_lowercase().contains("already been used")
            || replayed.to_lowercase().contains("replay"),
        "a replay was refused for the wrong reason: {replayed}"
    );

    // The replay is recorded too — an attempt to reuse one is exactly the thing
    // an operator reviewing the log wants to see.
    let records = audit_records(w.hbbs.dir());
    assert!(
        records.iter().any(|r| r["outcome"] == "replay"),
        "the replay left no record: {records:?}"
    );
}

/// The minting tool refuses a window nobody could remember issuing, and hbbs
/// refuses one too. Two bounds, in two places, that must not disagree.
#[tokio::test(flavor = "multi_thread")]
async fn a_capability_valid_for_too_long_is_refused_before_it_is_even_minted() {
    let keys = keygen(&std::env::temp_dir());
    let complaint = mint_refused(&keys, "alice-the-admin", "123456789", 241);
    assert!(
        complaint.to_lowercase().contains("4 hours") || complaint.to_lowercase().contains("refus"),
        "the tool refused for an unexpected reason: {complaint}"
    );
}

/// Disarmed is the default, and a default that fails open would be the worst
/// possible one.
#[tokio::test(flavor = "multi_thread")]
async fn a_world_with_no_public_key_refuses_every_capability() {
    let keys = keygen(&std::env::temp_dir());
    // Deliberately *not* `.breakglass(...)`: this is how the servers ship.
    let mut w = World::up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    assert!(
        w.hbbs.log().contains("break-glass is off"),
        "break-glass was armed in a world that did not ask for it"
    );

    w.api.kill_now();
    w.let_auth_cache_lapse(5_000).await;

    let capability = mint(&keys, "alice-the-admin", &laptop.id, 30);
    assert!(
        operator(&w, &capability)
            .connect(&mut laptop, ConnType::DEFAULT_CONN, REFUSAL)
            .await
            .is_err(),
        "a disarmed server accepted a capability"
    );
    assert!(
        audit_records(w.hbbs.dir()).is_empty(),
        "a disarmed server wrote an audit record"
    );
}
