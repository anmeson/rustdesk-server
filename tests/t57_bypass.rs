//! T5.7 — trying to get in without permission, on every door there is.
//!
//! The rest of Milestone 5 asks whether the system does the right thing for
//! people using it correctly. This one asks what happens to somebody who is not:
//! a stranger with no token, a forged one, an expired one, a token in the wrong
//! field, a client that never logged in at all, and a client that skips `hbbs`
//! entirely and goes straight at `hbbr`.
//!
//! Two deliberate choices about what is written down here.
//!
//! **`hbbr` authorizes nothing, and this file proves it rather than asserting
//! it.** The task board asks for that in those words. `hbbr` reads one
//! `RequestRelay`, compares the licence key if it has one, and splices the
//! stream to whoever else presents the same uuid (`relay_server.rs:461-498`).
//! There is no user, no device and no session in that code path, so the whole of
//! its safety is: the uuid is unguessable, and it is only ever learned by two
//! peers `hbbs` has already introduced. Both halves are tested —
//! `hbbr_relays_for_any_two_peers_that_present_the_same_uuid` is the unpleasant
//! one, and it is unpleasant on purpose.
//!
//! **Two enumeration oracles are pinned, not fixed.** An unauthenticated
//! stranger can tell a real device id from a fake one, and can ask `hbbs`
//! outright which ids are online. Neither is an authorization bypass — nothing
//! below gets a stranger a connection — but both make guessing a nine-digit id
//! cheaper, and neither was written down anywhere. They are upstream's design;
//! the tests exist so that a change to either is deliberate. See the notes in
//! TASK.md and docs/CONTEXT.md §"What a stranger can still learn".

mod harness;

use std::time::Duration;

use harness::{
    peer::{next_device_id, Controller, Device},
    relay::{assert_relays, hbbr, relay_join},
    world::World,
};
use hbb_common::{
    bytes::Bytes,
    rendezvous_proto::*,
    tokio::{self, time::sleep},
};

const WAIT: u64 = 8_000;

/// A refusal is read after the device fails to be brokered to, so this is paid
/// in full on every denial. Short, because there are a lot of them here.
const REFUSAL: u64 = 2_500;

/// Long enough that a relay which was going to pair would have paired. `hbbr`
/// parks an unmatched stream for 30 s, so a test that waits for *silence* is
/// asserting on a window, and this is the window.
const QUIET: u64 = 1_500;

const AUTHORIZE_PATH: &str = "/api/internal/authorize";

/// A token of exactly the shape `tokens.issue` produces — 32 random bytes,
/// base64url — that was never issued. The point of matching the shape is that a
/// refusal must not depend on the token looking wrong.
fn forged_token() -> String {
    let raw: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(13));
    base64::encode_config(raw, base64::URL_SAFE_NO_PAD)
}

/// A stranger: no account, no token, but a client that speaks the protocol.
fn stranger(w: &World, token: &str) -> Controller {
    Controller {
        user_id: String::new(),
        email: "nobody@test.invalid".to_owned(),
        token: token.to_owned(),
        id: "stranger".to_owned(),
        hbbs_port: w.hbbs.port,
        key: w.hbbs.key.clone(),
    }
}

/// The refusal text, or a panic naming the allow that should not have happened.
async fn refusal_for(who: &Controller, device: &mut Device, what: &str) -> String {
    match who.connect(device, ConnType::DEFAULT_CONN, REFUSAL).await {
        Err(reason) => reason,
        Ok(_) => panic!("{what}: the connection was ALLOWED"),
    }
}

/// A world with one real user and one real, online, owned device to aim at.
async fn world_with_a_target() -> (World, Controller, Device) {
    let w = World::builder().auth_cache_ttl_ms(1).up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the owner could not connect, so nothing below would mean anything");
    (w, alice, laptop)
}

// ---------------------------------------------------------------- tokens

/// No token at all — a client that skipped login and aimed straight at a device
/// id it knows is real.
///
/// Two things are asserted and the second is the interesting one: **the api is
/// never asked.** hbbs answers this itself (`auth.rs:800`), because it is the
/// internet-facing half of the pair and forwarding would let any stranger who
/// can reach the rendezvous port spend an api request.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_skips_login_is_refused_without_costing_an_api_call() {
    let (w, _alice, mut laptop) = world_with_a_target().await;
    let before = w.api.requests_to(AUTHORIZE_PATH);
    let nobody = stranger(&w, "");

    let refusal = refusal_for(&nobody, &mut laptop, "with no token").await;
    assert!(
        refusal.to_lowercase().contains("sign in"),
        "refused, but not as an unauthenticated client: {refusal}"
    );
    assert_eq!(
        w.api.requests_to(AUTHORIZE_PATH),
        before,
        "an empty token reached the api — a stranger can spend api requests from the open internet"
    );
}

/// The same, on the relay gate. `RequestRelay` is a separate chokepoint with its
/// own call site (T3.3b) and its own empty-token path, and a client that asks
/// for a relay first never touches the punch gate at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_skips_login_is_refused_on_the_relay_gate_too() {
    let (w, _alice, laptop) = world_with_a_target().await;
    let nobody = stranger(&w, "");

    let answer = nobody
        .request_relay_alone(&laptop.id, REFUSAL)
        .await
        .expect("hbbs said nothing at all to an untokened relay request");
    assert!(
        !answer.refuse_reason.is_empty(),
        "the relay gate answered an untokened request with an empty RelayResponse"
    );
    assert!(
        answer.refuse_reason.to_lowercase().contains("sign in"),
        "the relay gate refused for the wrong reason: {}",
        answer.refuse_reason
    );
    // Nothing was put on the relay: no uuid, no parked stream, nothing for a
    // guesser to pair with. The refusal happens before hbbs forwards anything.
    assert!(
        !w.hbbr.log().contains("New relay request"),
        "a refused request still reached hbbr:\n{}",
        w.hbbr.log()
    );
}

/// A token of exactly the right shape that was never issued. It is a lookup, not
/// a signature check (`tokens.ts` is deliberately not a JWT), so there is
/// nothing to forge — but that is a claim worth testing rather than believing.
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_token_is_refused_and_told_apart_from_no_token_at_all() {
    let (w, _alice, mut laptop) = world_with_a_target().await;
    let before = w.api.requests_to(AUTHORIZE_PATH);
    let faker = stranger(&w, &forged_token());

    let refusal = refusal_for(&faker, &mut laptop, "with a forged token").await;
    assert!(
        refusal.to_lowercase().contains("session has expired"),
        "refused, but not as an unknown token: {refusal}"
    );
    // The contrast with the empty-token test above: a token that *might* be real
    // has to be looked up, and is.
    assert!(
        w.api.requests_to(AUTHORIZE_PATH) > before,
        "a forged token was refused without asking the api, which means hbbs is guessing"
    );
}

/// An expired token, aged by the api's own clock rather than by a fixture:
/// `CLIENT_TOKEN_TTL_SECONDS=1`, sign in, wait.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_token_is_refused() {
    let w = World::builder()
        .auth_cache_ttl_ms(1)
        .api_env("CLIENT_TOKEN_TTL_SECONDS", "1")
        .up()
        .await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;

    // Still fresh — so what follows is the expiry and not a broken fixture.
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the token was refused while it was still valid");

    sleep(Duration::from_millis(1_400)).await;

    let refusal = refusal_for(&alice, &mut laptop, "with an expired token").await;
    assert!(
        refusal.to_lowercase().contains("session has expired"),
        "an expired token was refused for the wrong reason: {refusal}"
    );
}

/// A token belonging to a disabled account.
///
/// **The refusal is "your session has expired", not "this account has been
/// disabled", and that is not the branch anyone would predict from reading
/// `services/authorize.ts`.** Disabling revokes every client token the user
/// holds (`admin-users.ts:147`), so `tokens.verify` fails before the account
/// check below it is ever reached. The `isActive` branch in `authorize()` is
/// effectively unreachable from the connect path.
///
/// Pinned as it is, because the security outcome is the stronger one — the
/// token is dead, not merely refused, so nothing downstream has to remember to
/// check the account — and because the user is told the truth one step later:
/// signing in again answers "This account has been disabled". Both halves are
/// asserted here, since it is the pair that makes the first message acceptable.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_for_a_disabled_account_is_refused_even_on_the_users_own_device() {
    let (w, alice, mut laptop) = world_with_a_target().await;

    w.console.set_user_disabled(&alice.user_id, true).await;

    let refusal = refusal_for(&alice, &mut laptop, "with a disabled account").await;
    assert!(
        refusal.to_lowercase().contains("session has expired"),
        "a disabled account was refused for an unexpected reason: {refusal}"
    );

    // The step that stops the message above being a lie: the client is told to
    // sign in again, and when it does it learns what actually happened.
    let denied = w
        .client
        .try_login(&alice.email, &alice.id, &format!("uuid-{}", alice.id))
        .await
        .expect_err("a disabled account was allowed to sign in again");
    assert!(
        denied.to_lowercase().contains("disabled"),
        "signing in again did not say why it failed: {denied}"
    );

    // Re-enabling restores access, but only through a fresh sign-in — the old
    // token was revoked, not suspended, so disabling is reversible for the
    // account and final for the credential.
    w.console.set_user_disabled(&alice.user_id, false).await;
    let renewed = w
        .client
        .try_login(&alice.email, &alice.id, &format!("uuid-{}", alice.id))
        .await
        .expect("a re-enabled account could not sign in");
    assert_ne!(renewed, alice.token, "the revoked token was handed back");

    let back = Controller { token: renewed, ..clone_of(&alice, &w) };
    back.connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("re-enabling the account did not restore access");
}

/// `Controller` holds no `Clone`, and giving it one would let a test share a
/// token by accident — which is the one thing an authorization suite must make
/// awkward. This is the explicit copy, at the one call site that needs it.
fn clone_of(who: &Controller, w: &World) -> Controller {
    Controller {
        user_id: who.user_id.clone(),
        email: who.email.clone(),
        token: who.token.clone(),
        id: who.id.clone(),
        hbbs_port: w.hbbs.port,
        key: w.hbbs.key.clone(),
    }
}

/// The two fields are not interchangeable, in either direction. A client that
/// puts its access token in `licence_key` is unauthenticated; one that puts the
/// licence key in `token` is presenting a value every client already has.
///
/// Worth its own test because the licence key is **public** — it ships in every
/// client configuration — so a system that accepted it as a credential would be
/// open to everyone who has ever installed the app.
#[tokio::test(flavor = "multi_thread")]
async fn a_licence_key_is_not_a_credential_and_a_token_is_not_a_licence_key() {
    let (w, alice, mut laptop) = world_with_a_target().await;

    // The licence key presented where the token goes.
    let confused = stranger(&w, &w.hbbs.key);
    let refusal = refusal_for(&confused, &mut laptop, "with the licence key as a token").await;
    assert!(
        refusal.to_lowercase().contains("session has expired")
            || refusal.to_lowercase().contains("sign in"),
        "the licence key was treated as something other than an unknown token: {refusal}"
    );

    // The token presented where the licence key goes, and nothing in `token`.
    let misplaced = Controller {
        token: String::new(),
        key: alice.token.clone(),
        user_id: alice.user_id.clone(),
        email: alice.email.clone(),
        id: alice.id.clone(),
        hbbs_port: w.hbbs.port,
    };
    let refusal = refusal_for(&misplaced, &mut laptop, "with the token as a licence key").await;
    // `LICENSE_MISMATCH` is upstream's check and it runs first, so either
    // refusal is correct — what must not happen is a connection.
    assert!(
        !refusal.is_empty(),
        "hbbs said nothing to a request with the token in the licence field"
    );
}

// ---------------------------------------------------------------- what a stranger can learn

/// **Pins an oracle rather than fixing it.** With no token at all, a stranger is
/// told `ID_NOT_EXIST` for an id nobody registered and "please sign in" for one
/// that is real — so the two are distinguishable, and a nine-digit id space is
/// walkable.
///
/// Not fixed, because the fix is worse: authorization runs *after* the
/// peer-exists check precisely so that a scan costs hbbs nothing and the api
/// nothing (T3.3's own comment). Moving it in front would turn every scan into
/// one api request per guess, which is a denial-of-service amplifier handed to
/// the same stranger. The mitigation that does work is elsewhere — a real id
/// gets a stranger no further than this message.
#[tokio::test(flavor = "multi_thread")]
async fn an_unauthenticated_stranger_can_still_tell_a_real_id_from_a_fake_one() {
    let (w, _alice, mut laptop) = world_with_a_target().await;
    let nobody = stranger(&w, "");

    let real = refusal_for(&nobody, &mut laptop, "against a real id").await;

    let mut ghost = Device {
        id: next_device_id(),
        uuid: b"never-registered".to_vec(),
        pk: b"never-registered".to_vec(),
        sock: harness::udp_socket().await,
        hbbs_port: w.hbbs.port,
    };
    let fake = refusal_for(&nobody, &mut ghost, "against an id nobody registered").await;

    assert!(
        fake.contains("ID_NOT_EXIST"),
        "an unregistered id was answered with something else: {fake}"
    );
    assert_ne!(
        real, fake,
        "these are expected to differ — if they no longer do, the oracle was closed and this test \
         should be rewritten as the assertion that it stays closed"
    );
    assert!(
        real.to_lowercase().contains("sign in"),
        "a real id answered a stranger with something other than the sign-in message: {real}"
    );
}

/// The larger oracle, and the one nothing in this repo had written down:
/// `OnlineRequest` on the NAT-test port answers **anybody** — no licence key, no
/// token — with a bitmap saying which of up to a batch of ids are online
/// (`rendezvous_server.rs:1740`). It is upstream's, it is how the client's peer
/// list greys out offline machines, and it makes the id scan above cheap and
/// parallel.
///
/// Pinned, not fixed: the client depends on it, and closing it is a protocol
/// change on both sides. It belongs in the deployment notes instead — this port
/// has no reason to be reachable from the internet.
#[tokio::test(flavor = "multi_thread")]
async fn hbbs_tells_any_caller_which_device_ids_are_online() {
    let (w, _alice, laptop) = world_with_a_target().await;
    let absent = next_device_id();

    // From the host's LAN address, because a loopback caller reaches the runtime
    // console on this port instead.
    let host = harness::relay::relay_host();
    let ids = vec![laptop.id.clone(), absent.clone()];
    let states = harness::online_request(&host, w.hbbs.port, &ids, 4_000)
        .await
        .expect("the online check answered nothing at all");

    assert!(
        harness::online_bit(&states, 0),
        "a registered, online device was reported offline — the oracle is real but this is not it"
    );
    assert!(
        !harness::online_bit(&states, 1),
        "an id nobody registered was reported online"
    );
}

// ---------------------------------------------------------------- hbbr

/// **The uncomfortable one, and the whole point of the task's `hbbr` clause.**
///
/// Two peers that have never signed in, never been introduced by `hbbs`, and do
/// not exist as far as `apps/api` is concerned agree on a uuid between
/// themselves and relay bytes through `hbbr`. It works, because `hbbr`
/// authorizes nothing: there is no user, no device and no session anywhere in
/// `make_pair_`.
///
/// So the security of the relay is one property and one only — **the uuid is
/// unguessable and is only ever learned by two peers `hbbs` already
/// introduced.** Everything else in this file is about keeping it that way.
#[tokio::test(flavor = "multi_thread")]
async fn hbbr_relays_for_any_two_peers_that_present_the_same_uuid() {
    let w = World::up().await;
    let relay = w.relay_addr();
    let uuid = format!("agreed-between-strangers-{}", next_device_id());

    let mut one = relay_join(&relay, &uuid, &w.hbbs.key).await;
    let mut two = relay_join(&relay, &uuid, &w.hbbs.key).await;

    assert_relays(&mut one, &mut two, b"neither of us has an account", 4_000).await;
    assert_relays(&mut two, &mut one, b"nor did hbbs introduce us", 4_000).await;
}

/// The other half: a guess that is wrong is answered with **silence**, and so is
/// a guess that is right but early. There is no oracle here — a stranger
/// spraying uuids cannot tell "nobody has this" from "somebody has this and has
/// not arrived yet", because `hbbr` parks both for 30 s and says nothing either
/// way.
#[tokio::test(flavor = "multi_thread")]
async fn a_guessed_uuid_is_answered_with_silence_and_not_with_a_hint() {
    let w = World::up().await;
    let relay = w.relay_addr();

    let mut guess = relay_join(&relay, "a-uuid-nobody-chose", &w.hbbs.key).await;
    guess.send_bytes(Bytes::from_static(b"anybody there?")).await.unwrap();
    assert!(
        guess.next_timeout(QUIET).await.is_none(),
        "hbbr answered a stranger's uuid with something"
    );

    // And the same silence for a uuid that *is* in use, from the outside, while
    // its owner has not yet arrived. Indistinguishable, which is the property.
    let real = format!("real-{}", next_device_id());
    let _waiting = relay_join(&relay, &real, &w.hbbs.key).await;
    // Deliberately not joining as the second peer here — this is a third party
    // guessing the uuid of a *pending* session, which is the one moment the
    // guess would pay off. It is covered by the next test; what is asserted
    // here is only that guessing tells you nothing.
    let mut early = relay_join(&relay, "another-uuid-nobody-chose", &w.hbbs.key).await;
    early.send_bytes(Bytes::from_static(b"and here?")).await.unwrap();
    assert!(
        early.next_timeout(QUIET).await.is_none(),
        "hbbr distinguished a wrong guess from a pending session"
    );
}

/// A session that is already paired cannot be joined. `make_pair_` **removes**
/// the parked entry when it splices (`relay_server.rs:462`), so a third arrival
/// with the same uuid parks as a fresh request and waits for a fourth — it does
/// not attach to the two peers already talking.
///
/// This is the difference between "the uuid is a secret worth keeping" and "the
/// uuid is a password to a live session". It is the former.
#[tokio::test(flavor = "multi_thread")]
async fn an_established_session_cannot_be_joined_by_a_third_party() {
    let w = World::up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    let relay = w.relay_addr();

    let (mut a_end, mut b_end, forwarded) = alice
        .connect_relayed(&mut laptop, &relay, &w.hbbs.key, WAIT)
        .await
        .expect("the owner could not open a relayed session");
    assert_relays(&mut a_end, &mut b_end, b"before the intruder", 4_000).await;

    // The uuid, exactly as it travelled — no guessing required, so this is the
    // strongest form of the attack: a stranger who somehow *knows* it.
    let mut intruder = relay_join(&relay, &forwarded.uuid, &w.hbbs.key).await;
    intruder.send_bytes(Bytes::from_static(b"let me in")).await.unwrap();
    assert!(
        intruder.next_timeout(QUIET).await.is_none(),
        "a third party with the uuid received traffic from a live session"
    );

    // And the session is undisturbed — the intruder did not steal an end of it.
    assert_relays(&mut a_end, &mut b_end, b"after the intruder", 4_000).await;
    assert_relays(&mut b_end, &mut a_end, b"and back again", 4_000).await;
}

/// The licence key is the only thing `hbbr` checks, and it does check it: a
/// wrong one is closed without a word (`relay_server.rs:466`) and cannot pair
/// with a peer that has the right one.
///
/// It is not a credential — every client has it — but it is the difference
/// between a relay that is usable by the internet and one that is usable by
/// this deployment's clients.
#[tokio::test(flavor = "multi_thread")]
async fn hbbr_refuses_a_wrong_licence_key() {
    let w = World::up().await;
    let relay = w.relay_addr();
    let uuid = format!("wrong-key-{}", next_device_id());

    let mut wrong = relay_join(&relay, &uuid, "not-the-licence-key").await;
    assert!(
        w.hbbr.wait_for_log("Relay authentication failed", 4_000).await,
        "hbbr did not log the refusal:\n{}",
        w.hbbr.log()
    );

    // The refused stream is gone, so a correct-key peer arriving on the same
    // uuid finds nobody parked and waits — it must not be spliced to the
    // stranger.
    let mut right = relay_join(&relay, &uuid, &w.hbbs.key).await;
    right.send_bytes(Bytes::from_static(b"hello?")).await.unwrap();
    assert!(
        wrong.next_timeout(QUIET).await.is_none(),
        "a peer with a wrong licence key was spliced to one with the right key"
    );
}

/// **The deployment trap, measured.** `hbbr`'s key comparison is
/// `if !key.is_empty() && …` (`relay_server.rs:466`), so an `hbbr` started with
/// `-k ""` relays for anybody who asks, from anywhere, with no key at all.
/// docs/CONTEXT.md §7 warns about it; this is the warning as a fact.
///
/// Its own `hbbr`, not the world's — the world's is correctly keyed and must
/// stay that way for every other test here to mean anything.
#[tokio::test(flavor = "multi_thread")]
async fn an_hbbr_with_no_key_relays_for_anybody() {
    let open = hbbr("").await;
    let addr = open.addr();
    let uuid = format!("keyless-{}", next_device_id());

    let mut one = relay_join(&addr, &uuid, "").await;
    let mut two = relay_join(&addr, &uuid, "any old nonsense").await;

    assert_relays(&mut one, &mut two, b"no key, no questions", 4_000).await;
}
