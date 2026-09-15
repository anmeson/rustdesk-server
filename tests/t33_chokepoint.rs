//! T3.3 verification: drives the real `hbbs` binary over the real wire.
//!
//! Checks both what controller A gets back and what device B is handed, for the
//! punch-hole gate (T3.3) and the relay gate (T3.3b). The machinery lives in
//! `harness`.

mod harness;

use harness::*;
use hbb_common::{
    rendezvous_proto::*, tcp::FramedStream, tokio, AddrMangle,
};

// ---------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread")]
async fn a_granted_user_is_brokered_and_b_is_told_who_it_is() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-1").await;

    let refusal = punch(s.port, &s.key, "t33-dev-1", "good-token", ConnType::DEFAULT_CONN, ALLOW_WAIT).await;
    assert!(refusal.is_none(), "denied: {:?}", refusal);

    let msg = next_from_hbbs(&mut b).await;
    let (ctx, perms) = match msg.union {
        Some(rendezvous_message::Union::PunchHole(p)) => {
            (p.controlled_context.into_option(), p.control_permissions.into_option())
        }
        Some(rendezvous_message::Union::FetchLocalAddr(f)) => {
            (f.controlled_context.into_option(), f.control_permissions.into_option())
        }
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(ctx.expect("no controlled_context").conn_audit_ref, "ref-t33");
    assert_eq!(perms.expect("no control_permissions").permissions, 6);
    assert_eq!(api.calls(), 1);
    assert!(api.requests.lock().unwrap()[0].contains("\"to_id\":\"t33-dev-1\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ungranted_user_is_refused_in_words() {
    let api = stub(200, DENY).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-2").await;

    let ph = punch(s.port, &s.key, "t33-dev-2", "bad-token", ConnType::DEFAULT_CONN, REFUSAL_WAIT)
        .await
        .expect("no refusal came back");
    assert!(
        !ph.other_failure.is_empty(),
        "not an authorization refusal at all: failure={:?} (port {})",
        ph.failure.enum_value(),
        s.port
    );
    assert_eq!(ph.other_failure, "You do not have access to this device.");
    assert!(ph.socket_addr.is_empty());
    assert!(b.next_timeout(700).await.is_none(), "B was contacted anyway");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_api_fails_closed() {
    let api = stub(200, ALLOW).await;
    let mut args = auth_args(&api);
    // Point at a port nothing listens on.
    args[1] = format!("http://127.0.0.1:{}", dead_port());
    let s = hbbs(&args).await;
    let mut b = register(s.port, "t33-dev-3").await;

    let ph = punch(s.port, &s.key, "t33-dev-3", "good-token", ConnType::DEFAULT_CONN, REFUSAL_WAIT)
        .await
        .expect("no refusal came back");
    assert!(!ph.other_failure.is_empty());
    assert!(ph.other_failure.to_lowercase().contains("unavailable"), "{}", ph.other_failure);
    assert!(b.next_timeout(700).await.is_none(), "B was contacted anyway");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_token_is_refused_without_asking_the_api() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let _b = register(s.port, "t33-dev-4").await;

    let ph = punch(s.port, &s.key, "t33-dev-4", "", ConnType::DEFAULT_CONN, REFUSAL_WAIT)
        .await
        .expect("no refusal came back");
    assert!(!ph.other_failure.is_empty(), "empty token was allowed");
    assert_eq!(api.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_offline_peer_is_refused_before_the_api_is_asked() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;

    let ph = punch(s.port, &s.key, "t33-nobody", "good-token", ConnType::DEFAULT_CONN, REFUSAL_WAIT)
        .await
        .expect("no refusal came back");
    assert_eq!(
        ph.failure.enum_value(),
        Ok(punch_hole_response::Failure::ID_NOT_EXIST)
    );
    assert_eq!(api.calls(), 0, "spent an api call on a peer that does not exist");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_key_is_refused_before_the_api_is_asked() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let _b = register(s.port, "t33-dev-5").await;

    let ph = punch(s.port, "not-the-key", "t33-dev-5", "good-token", ConnType::DEFAULT_CONN, REFUSAL_WAIT)
        .await
        .expect("no refusal came back");
    assert_eq!(
        ph.failure.enum_value(),
        Ok(punch_hole_response::Failure::LICENSE_MISMATCH)
    );
    assert_eq!(api.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_authorization_off_the_wire_is_unchanged() {
    let s = hbbs(&[]).await;
    let mut b = register(s.port, "t33-dev-6").await;

    let refusal = punch(s.port, &s.key, "t33-dev-6", "", ConnType::DEFAULT_CONN, ALLOW_WAIT).await;
    assert!(refusal.is_none(), "an empty token was refused with authorization off: {refusal:?}");
    let msg = next_from_hbbs(&mut b).await;
    match msg.union {
        Some(rendezvous_message::Union::PunchHole(p)) => {
            assert!(p.controlled_context.is_none());
            assert!(p.control_permissions.is_none());
        }
        Some(rendezvous_message::Union::FetchLocalAddr(f)) => {
            assert!(f.controlled_context.is_none());
            assert!(f.control_permissions.is_none());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retry_of_one_connect_spends_one_decision_but_a_file_transfer_does_not() {
    let api = stub_by(|request| {
        let body = if request.contains("\"conn_type\":\"FILE_TRANSFER\"") {
            r#"{"allow":true,"conn_audit_ref":"ref-t33-files"}"#
        } else {
            ALLOW
        };
        (200, body.to_owned())
    })
    .await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-7").await;

    punch(s.port, &s.key, "t33-dev-7", "good-token", ConnType::DEFAULT_CONN, ALLOW_WAIT).await;
    next_from_hbbs(&mut b).await;
    // The client's second punch attempt for the same connection.
    punch(s.port, &s.key, "t33-dev-7", "good-token", ConnType::DEFAULT_CONN, ALLOW_WAIT).await;
    next_from_hbbs(&mut b).await;
    assert_eq!(api.calls(), 1, "a retry minted a second audit ref");

    punch(s.port, &s.key, "t33-dev-7", "good-token", ConnType::FILE_TRANSFER, ALLOW_WAIT).await;
    let msg = next_from_hbbs(&mut b).await;
    let ctx = match msg.union {
        Some(rendezvous_message::Union::PunchHole(p)) => p.controlled_context.into_option(),
        Some(rendezvous_message::Union::FetchLocalAddr(f)) => f.controlled_context.into_option(),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(api.calls(), 2, "a file transfer reused the remote-control decision");
    assert_eq!(ctx.unwrap().conn_audit_ref, "ref-t33-files");
}

// ------------------------------------------------- the relay path (T3.3b)
//
// `RequestRelay` is the second way into a controlled device. Until T3.3b it was
// forwarded to the peer with nothing checked at all, which made the punch-hole
// gate above decorative: a stranger could simply not send a `PunchHoleRequest`.

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_request_without_a_token_is_refused_in_words() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-8").await;

    let rs = request_relay(s.port, "t33-dev-8", "", None, REFUSAL_WAIT)
        .await
        .expect("no refusal came back");
    assert!(!rs.refuse_reason.is_empty(), "the relay path let an empty token through");
    assert!(b.next_timeout(700).await.is_none(), "B was contacted anyway");
    assert_eq!(api.calls(), 0, "spent an api call on an empty token");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_request_from_an_ungranted_user_is_refused_in_words() {
    let api = stub(200, DENY).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-9").await;

    let rs = request_relay(s.port, "t33-dev-9", "bad-token", None, REFUSAL_WAIT)
        .await
        .expect("no refusal came back");
    assert_eq!(rs.refuse_reason, "You do not have access to this device.");
    assert!(b.next_timeout(700).await.is_none(), "B was contacted anyway");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_api_fails_closed_on_the_relay_path_too() {
    let api = stub(200, ALLOW).await;
    let mut args = auth_args(&api);
    args[1] = format!("http://127.0.0.1:{}", dead_port());
    let s = hbbs(&args).await;
    let mut b = register(s.port, "t33-dev-10").await;

    let rs = request_relay(s.port, "t33-dev-10", "good-token", None, REFUSAL_WAIT)
        .await
        .expect("no refusal came back");
    assert!(rs.refuse_reason.to_lowercase().contains("unavailable"), "{}", rs.refuse_reason);
    assert!(b.next_timeout(700).await.is_none(), "B was contacted anyway");
}

/// A relayed session is attributable only if the ref reaches B *on this
/// message*: each hbbs message carries its own metadata, so the ref sent with
/// the earlier `PunchHole` does not survive into the relay fallback. Before
/// T3.3b every relayed session was therefore unattributed — and an unattributed
/// session is one D2 revocation cannot find.
#[tokio::test(flavor = "multi_thread")]
async fn a_granted_relay_request_carries_the_audit_ref_to_the_device() {
    let api = stub(200, r#"{"allow":true,"conn_audit_ref":"ref-relay","permissions":6}"#).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-11").await;

    let refusal = request_relay(s.port, "t33-dev-11", "good-token", None, ALLOW_WAIT).await;
    assert!(refusal.is_none(), "denied: {refusal:?}");

    let rr = relay_at_b(&mut b).await;
    assert_eq!(rr.uuid, "t33-relay-uuid");
    assert_eq!(
        rr.controlled_context.into_option().expect("no controlled_context").conn_audit_ref,
        "ref-relay"
    );
    assert_eq!(
        rr.control_permissions.into_option().expect("no control_permissions").permissions,
        6
    );
}

/// The two metadata fields arrive from A on this path, and upstream forwards
/// them untouched. A ref A chose would let A's session complete somebody else's
/// decision row — logged as that user, and leaving the real session with nothing
/// to join and so unrevocable.
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_audit_ref_on_a_relay_request_is_overwritten() {
    let api = stub(200, r#"{"allow":true,"conn_audit_ref":"ref-real"}"#).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-12").await;

    let refusal = request_relay(
        s.port,
        "t33-dev-12",
        "good-token",
        Some("ref-somebody-elses"),
        ALLOW_WAIT,
    )
    .await;
    assert!(refusal.is_none(), "denied: {refusal:?}");

    let rr = relay_at_b(&mut b).await;
    assert_eq!(
        rr.controlled_context.into_option().expect("no controlled_context").conn_audit_ref,
        "ref-real"
    );
    // The api set no permission limit, so the field A supplied must be gone
    // rather than left to grant A whatever it asked for.
    assert!(
        rr.control_permissions.is_none(),
        "A's own control_permissions survived: {:?}",
        rr.control_permissions
    );
}

/// The real sequence: a punch we approved, then the relay fallback for the same
/// connection. It must cost one decision and carry one ref — a second ref means
/// a second `connection_logs` row for one connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_fallback_reuses_the_punch_decision() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-13").await;

    punch(s.port, &s.key, "t33-dev-13", "good-token", ConnType::DEFAULT_CONN, ALLOW_WAIT).await;
    next_from_hbbs(&mut b).await;

    let refusal = request_relay(s.port, "t33-dev-13", "good-token", None, ALLOW_WAIT).await;
    assert!(refusal.is_none(), "denied: {refusal:?}");
    let rr = relay_at_b(&mut b).await;

    assert_eq!(api.calls(), 1, "the relay fallback minted a second decision");
    assert_eq!(
        rr.controlled_context.into_option().expect("no controlled_context").conn_audit_ref,
        "ref-t33",
        "the relay fallback carried a different ref from the punch it followed"
    );
}

/// With authorization off, upstream's path runs unchanged — including the two
/// metadata fields, which are otherwise replaced.
#[tokio::test(flavor = "multi_thread")]
async fn with_authorization_off_a_relay_request_is_forwarded_unchanged() {
    let s = hbbs(&[]).await;
    let mut b = register(s.port, "t33-dev-14").await;

    let refusal = request_relay(s.port, "t33-dev-14", "", Some("whatever-a-said"), ALLOW_WAIT).await;
    assert!(refusal.is_none(), "refused with authorization off: {refusal:?}");

    let rr = relay_at_b(&mut b).await;
    assert_eq!(
        rr.controlled_context.into_option().expect("no controlled_context").conn_audit_ref,
        "whatever-a-said"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_request_for_an_unknown_peer_is_silent_and_free() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;

    let rs = request_relay(s.port, "t33-nobody", "good-token", None, 1_200).await;
    assert!(rs.is_none(), "answered for a peer that does not exist: {rs:?}");
    assert_eq!(api.calls(), 0, "spent an api call on a peer that does not exist");
}

// ------------------------------------------- injecting into a waiting peer
//
// `PunchHoleSent`, `LocalAddr` and `RelayResponse` are all routed on an address
// the *sender* supplies, and upstream checks nothing about who sent them. So a
// stranger who knows a waiting controller's address as hbbs sees it could answer
// on the real peer's behalf. Written against the running binaries, not from
// reading the source.
//
// **T3.8 closes this**, with a ledger of who hbbs actually brokered to whom
// (`src/broker.rs`). What these tests can reach is the *id* layer, which is the
// one that ships on. The *ip* layer — `BROKER_STRICT_IP`, off by default — is
// invisible from here for a structural reason: every party in this harness is
// on 127.0.0.1, so a stranger and the real peer have the same address and no ip
// check can tell them apart. It is unit-tested in `broker.rs` instead, and the
// reason it does not ship on is written up there.

/// A stranger's *words* must not reach a waiting user. This one is fixed
/// (T3.3b): `refuse_reason` is the only attacker-reachable field that becomes
/// text on screen, nothing legitimate ever sets it, so hbbs drops it.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_cannot_put_text_on_a_waiting_users_screen() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-15").await;

    // A asks for a relay and waits for a RelayResponse.
    let mut a = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let a_addr = a.local_addr();
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: "t33-dev-15".to_owned(),
        uuid: "t33-relay-uuid".to_owned(),
        token: "good-token".to_owned(),
        relay_server: "127.0.0.1:21117".to_owned(),
        ..Default::default()
    });
    a.send(&msg).await.unwrap();
    let _ = relay_at_b(&mut b).await;

    // Someone entirely unrelated answers on A's behalf.
    let mut evil = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_relay_response(RelayResponse {
        socket_addr: AddrMangle::encode(a_addr).into(),
        refuse_reason: "Your licence has expired. Call +1-555-0100 to renew.".to_owned(),
        ..Default::default()
    });
    evil.send(&msg).await.unwrap();

    if let Some(msg) = next_plaintext(&mut a, 2_500).await {
        match msg.union {
            Some(rendezvous_message::Union::RelayResponse(rs)) => assert!(
                rs.refuse_reason.is_empty(),
                "a stranger's text reached the user: {:?}",
                rs.refuse_reason
            ),
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// The T3.8 fix, and the exact attack it was found by.
///
/// A stranger answers a waiting controller naming an id hbbs has never heard
/// of. That was the cheap and worst version of the attack: `get_pk` returns
/// nothing for an unknown id, and the client treats an absent peer key as "no
/// identity to verify" and connects anyway
/// (`apps/rustdesk/src/client.rs:1624-1634`) — so the signature check that
/// normally makes impersonation impossible was simply skipped, and the
/// controller could be steered to an attacker while sending its connection
/// password.
///
/// This test asserted the hole until T3.8. It now asserts that A hears nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_cannot_answer_a_waiting_controller() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-16").await;

    let mut a = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let a_addr = a.local_addr();
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: "t33-dev-16".to_owned(),
        licence_key: s.key.clone(),
        token: "good-token".to_owned(),
        ..Default::default()
    });
    a.send(&msg).await.unwrap();
    // B is contacted and A hears nothing yet: that is the window.
    let _ = next_from_hbbs(&mut b).await;

    let mut evil = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_sent(PunchHoleSent {
        socket_addr: AddrMangle::encode(a_addr).into(),
        id: "t33-not-a-device".to_owned(),
        relay_server: "evil.example.com:21117".to_owned(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    evil.send(&msg).await.unwrap();

    let heard = next_plaintext(&mut a, 2_500).await;
    assert!(
        heard.is_none(),
        "a stranger answered for a peer hbbs never brokered: {heard:?}"
    );
}

/// The other half, and the one that matters more than the fix: the real peer
/// must still get through. A drop here is "nobody can connect".
#[tokio::test(flavor = "multi_thread")]
async fn the_brokered_peer_still_answers_its_waiting_controller() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-17").await;

    let mut a = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let a_addr = a.local_addr();
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: "t33-dev-17".to_owned(),
        licence_key: s.key.clone(),
        token: "good-token".to_owned(),
        ..Default::default()
    });
    a.send(&msg).await.unwrap();
    let _ = next_from_hbbs(&mut b).await;

    // The real device answers over a **new TCP connection**, which is the whole
    // reason only an ip can ever be matched here and never a port
    // (`rendezvous_mediator.rs:995`).
    let mut peer = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_sent(PunchHoleSent {
        socket_addr: AddrMangle::encode(a_addr).into(),
        id: "t33-dev-17".to_owned(),
        relay_server: format!("127.0.0.1:{}", s.port + 1),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    peer.send(&msg).await.unwrap();

    match next_plaintext(&mut a, 3_000)
        .await
        .expect("the brokered peer's answer was dropped")
        .union
    {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
            assert_eq!(ph.relay_server, format!("127.0.0.1:{}", s.port + 1));
            assert!(
                !ph.pk.is_empty(),
                "no peer key: the client would skip identity verification"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// `LocalAddr` is the same hole with a sharper edge — `la.local_addr` is copied
/// straight into the response, so the sender picks the address A dials.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_cannot_answer_with_a_local_addr() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-18").await;

    let mut a = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let a_addr = a.local_addr();
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: "t33-dev-18".to_owned(),
        licence_key: s.key.clone(),
        token: "good-token".to_owned(),
        ..Default::default()
    });
    a.send(&msg).await.unwrap();
    let _ = next_from_hbbs(&mut b).await;

    let mut evil = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_local_addr(LocalAddr {
        socket_addr: AddrMangle::encode(a_addr).into(),
        local_addr: AddrMangle::encode("10.66.66.66:21118".parse::<std::net::SocketAddr>().unwrap())
            .into(),
        id: "t33-not-a-device".to_owned(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    evil.send(&msg).await.unwrap();

    let heard = next_plaintext(&mut a, 2_500).await;
    assert!(heard.is_none(), "a stranger chose the address A dials: {heard:?}");
}

/// A `RelayResponse` that names an id is B choosing the relay server
/// (`create_relay(initiate = true)`), and A takes that server from the message.
/// A stranger naming another id must not reach it.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_response_naming_another_peer_is_dropped() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-19").await;

    let mut a = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let a_addr = a.local_addr();
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: "t33-dev-19".to_owned(),
        uuid: "t33-relay-uuid".to_owned(),
        token: "good-token".to_owned(),
        relay_server: "127.0.0.1:21117".to_owned(),
        ..Default::default()
    });
    a.send(&msg).await.unwrap();
    let _ = relay_at_b(&mut b).await;

    let mut evil = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let mut rr = RelayResponse {
        socket_addr: AddrMangle::encode(a_addr).into(),
        uuid: "evil-uuid".to_owned(),
        relay_server: "evil.example.com:21117".to_owned(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    };
    rr.set_id("t33-not-a-device".to_owned());
    let mut msg = RendezvousMessage::new();
    msg.set_relay_response(rr);
    evil.send(&msg).await.unwrap();

    let heard = next_plaintext(&mut a, 2_500).await;
    assert!(heard.is_none(), "a stranger chose A's relay server: {heard:?}");
}

/// The relay **fallback** ack carries no id at all — `create_relay` sends it
/// with `initiate = false`, so no id, no uuid and no relay server
/// (`rendezvous_mediator.rs:579-604`). Requiring an id would have broken every
/// relayed session, so an absent one is accepted on the brokerage alone.
///
/// This is also the residual: on the fallback path the id layer has nothing to
/// check, and only `BROKER_STRICT_IP` separates a stranger's ack from B's. It
/// buys a stranger nothing beyond a race — A keeps its own uuid and relay
/// server and learns only that somebody answered
/// (`apps/rustdesk/src/client.rs:1750-1760`) — but it is a residual, not a fix.
#[tokio::test(flavor = "multi_thread")]
async fn the_relay_fallback_ack_carries_no_id_and_still_reaches_the_controller() {
    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t33-dev-20").await;

    let mut a = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let a_addr = a.local_addr();
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: "t33-dev-20".to_owned(),
        uuid: "t33-relay-uuid".to_owned(),
        token: "good-token".to_owned(),
        relay_server: "127.0.0.1:21117".to_owned(),
        ..Default::default()
    });
    a.send(&msg).await.unwrap();
    let _ = relay_at_b(&mut b).await;

    let mut peer = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_relay_response(RelayResponse {
        socket_addr: AddrMangle::encode(a_addr).into(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    peer.send(&msg).await.unwrap();

    match next_plaintext(&mut a, 3_000)
        .await
        .expect("the relay fallback ack was dropped — every relayed session would hang")
        .union
    {
        Some(rendezvous_message::Union::RelayResponse(rs)) => {
            assert!(rs.refuse_reason.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// With `BROKER_VERIFY=N` the ledger is bypassed entirely and upstream's
/// routing is back, hole included. Pinned so the escape hatch is known to work
/// — it is the lever an operator pulls if T3.8 ever breaks their fleet.
#[tokio::test(flavor = "multi_thread")]
async fn with_verification_off_a_stranger_can_answer_again() {
    let api = stub(200, ALLOW).await;
    let mut args = auth_args(&api);
    args.push("--broker-verify".into());
    args.push("N".into());
    let s = hbbs(&args).await;
    let mut b = register(s.port, "t33-dev-21").await;

    let mut a = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let a_addr = a.local_addr();
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: "t33-dev-21".to_owned(),
        licence_key: s.key.clone(),
        token: "good-token".to_owned(),
        ..Default::default()
    });
    a.send(&msg).await.unwrap();
    let _ = next_from_hbbs(&mut b).await;

    let mut evil = FramedStream::new(format!("127.0.0.1:{}", s.port), None, 3_000)
        .await
        .unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_sent(PunchHoleSent {
        socket_addr: AddrMangle::encode(a_addr).into(),
        id: "t33-not-a-device".to_owned(),
        relay_server: "evil.example.com:21117".to_owned(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    evil.send(&msg).await.unwrap();

    let msg = next_plaintext(&mut a, 2_500)
        .await
        .expect("BROKER_VERIFY=N did not restore upstream's routing");
    match msg.union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
            assert_eq!(ph.relay_server, "evil.example.com:21117");
        }
        other => panic!("unexpected {other:?}"),
    }
}
