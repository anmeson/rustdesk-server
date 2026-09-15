//! T3.4 verification: the `KeyExchange` responder in `hbbs`.
//!
//! The bug this closes is T0.6's: `secure_tcp`
//! (`apps/rustdesk/src/common.rs:2069-2113`) blocks on `conn.next()` waiting for
//! the rendezvous server to speak first, and OSS `hbbs` never did — so a client
//! with both a licence key and a login token stalled for `READ_TIMEOUT` (18 s,
//! measured at 18.004 s in T0.6) and then failed *every* outbound connection.
//! Making login mandatory would have made that everyone's first experience.
//!
//! These tests are deliberately hand-rolled down to the frame: the point is what
//! is on the wire, so nothing here may go through a helper that would hide it.
//! The sealing is done by hand with the same primitives the client uses, and the
//! token is looked for in the actual bytes written to the socket.

mod harness;

use harness::*;
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::Encrypt,
    timeout,
    tokio::{self, net::TcpStream},
    AddrMangle,
    tokio_util::codec::Framed,
};
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::time::{Duration, Instant};

/// `READ_TIMEOUT` from `libs/hbb_common/src/config.rs:46` — what the client
/// waits before giving up on an offer, and therefore the length of the stall
/// this task exists to remove.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_millis(18_000);

/// Generous enough not to be flaky on a loaded laptop, and still two orders of
/// magnitude below the stall. Anything that passes this is "gone", not "faster".
const PROMPT: Duration = Duration::from_millis(2_000);

// ------------------------------------------------------------- a raw client

/// A TCP connection to `hbbs` with no help from `FramedStream`.
///
/// `FramedStream::set_key` would do the crypto transparently, which is exactly
/// what these tests must not allow: a test that cannot see the bytes cannot
/// tell "encrypted" from "the library encrypted it for both of us".
struct Raw {
    inner: Framed<TcpStream, BytesCodec>,
    /// Set once the handshake completes. Separate instances per direction, as in
    /// `hbbs` — `Encrypt` counts sends in `.1` and receives in `.2`.
    enc: Option<Encrypt>,
    dec: Option<Encrypt>,
    /// Every frame as it actually went out, after sealing. What the wire saw.
    sent_on_the_wire: Vec<Vec<u8>>,
}

impl Raw {
    async fn connect(port: u16) -> Self {
        let sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.set_nodelay(true).ok();
        Self {
            inner: Framed::new(sock, BytesCodec::new()),
            enc: None,
            dec: None,
            sent_on_the_wire: Vec::new(),
        }
    }

    /// The next frame, decrypted if the handshake has keyed this connection.
    /// `None` is a closed connection or a timeout — the tests distinguish by
    /// what they asked for.
    async fn recv(&mut self, ms: u64) -> Option<RendezvousMessage> {
        let mut bytes = timeout(ms, self.inner.next()).await.ok()??.ok()?;
        if let Some(dec) = self.dec.as_mut() {
            dec.dec(&mut bytes).expect("hbbs sent a frame we cannot decrypt");
        }
        Some(RendezvousMessage::parse_from_bytes(&bytes).unwrap())
    }

    async fn send(&mut self, msg: &RendezvousMessage) {
        let plain = msg.write_to_bytes().unwrap();
        let wire = match self.enc.as_mut() {
            Some(enc) => enc.enc(&plain),
            None => plain,
        };
        self.sent_on_the_wire.push(wire.clone());
        self.inner.send(Bytes::from(wire)).await.unwrap();
    }

    /// Reads the offer and verifies it against `key`, the way the client does:
    /// `sign::verify` against the licence public key it was configured with.
    /// Returns the server's ephemeral box public key.
    async fn read_offer(&mut self, key: &str, ms: u64) -> Result<[u8; 32], String> {
        let msg = self.recv(ms).await.ok_or("hbbs said nothing")?;
        let ex = match msg.union {
            Some(rendezvous_message::Union::KeyExchange(ex)) => ex,
            other => return Err(format!("not an offer: {other:?}")),
        };
        if ex.keys.len() != 1 {
            return Err(format!("{} keys, want 1", ex.keys.len()));
        }
        let pk = rs_pk(key);
        let opened = sign::verify(&ex.keys[0], &pk).map_err(|_| "Signature mismatch".to_owned())?;
        let opened: [u8; 32] = opened.try_into().map_err(|_| "not 32 bytes".to_owned())?;
        Ok(opened)
    }

    /// The client's half of the exchange: seal a fresh symmetric key to the
    /// server's ephemeral public key and send both parts in the clear. Mirrors
    /// `create_symmetric_key_msg` (`apps/rustdesk/src/common.rs:2164-2171`).
    async fn accept_offer(&mut self, their_pk_b: [u8; 32]) {
        let their_pk_b = box_::PublicKey(their_pk_b);
        let (our_pk_b, our_sk_b) = box_::gen_keypair();
        let sym = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let sealed = box_::seal(&sym.0, &nonce, &their_pk_b, &our_sk_b);

        let mut msg = RendezvousMessage::new();
        msg.set_key_exchange(KeyExchange {
            keys: vec![our_pk_b.0.to_vec().into(), sealed.into()],
            ..Default::default()
        });
        // Sent in the clear, then keyed — the same order as the client
        // (`common.rs:2098-2100`), which is why neither side's counter moves for
        // the handshake itself.
        self.send(&msg).await;
        self.enc = Some(Encrypt::new(sym.clone()));
        self.dec = Some(Encrypt::new(sym));
    }

    async fn handshake(&mut self, key: &str) {
        let pk = self.read_offer(key, PROMPT.as_millis() as u64).await.expect("offer");
        self.accept_offer(pk).await;
    }
}

fn rs_pk(key: &str) -> sign::PublicKey {
    let raw = base64::decode(key).expect("licence key is not base64");
    sign::PublicKey::from_slice(&raw).expect("licence key is not an ed25519 public key")
}

fn punch_hole(id: &str, key: &str, token: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        licence_key: key.to_owned(),
        token: token.to_owned(),
        conn_type: ConnType::DEFAULT_CONN.into(),
        nat_type: NatType::ASYMMETRIC.into(),
        ..Default::default()
    });
    msg
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------------------- tests

/// The whole of T0.6 in one assertion: something arrives, and it arrives now.
#[tokio::test(flavor = "multi_thread")]
async fn hbbs_speaks_first_and_the_18_second_stall_is_gone() {
    let s = hbbs(&[]).await;
    let mut c = Raw::connect(s.port).await;

    // Not a byte is sent first. `secure_tcp` does not send one either — it goes
    // straight to `conn.next()` — so if hbbs waits to be spoken to, nobody
    // speaks, which was the bug.
    let start = Instant::now();
    let pk = c
        .read_offer(&s.key, CLIENT_READ_TIMEOUT.as_millis() as u64)
        .await
        .expect("hbbs never made an offer");
    let waited = start.elapsed();

    assert!(
        waited < PROMPT,
        "hbbs took {waited:?} to make an offer; the T0.6 stall was {CLIENT_READ_TIMEOUT:?}"
    );
    assert_ne!(pk, [0u8; 32], "offered an all-zero public key");
}

/// The offer proves the server holds the licence *secret* key. A client that
/// reached the wrong rendezvous server now learns so in a millisecond, where
/// before it learned nothing for 18 seconds and then blamed the peer.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_signed_by_the_wrong_key_fails_immediately() {
    let s = hbbs(&[]).await;
    let mut c = Raw::connect(s.port).await;

    let (other_pk, _) = sign::gen_keypair();
    let start = Instant::now();
    let err = c
        .read_offer(&base64::encode(other_pk), CLIENT_READ_TIMEOUT.as_millis() as u64)
        .await
        .expect_err("a key we never configured verified");
    let waited = start.elapsed();

    assert!(err.contains("Signature mismatch"), "wrong failure: {err}");
    assert!(waited < PROMPT, "took {waited:?} to reject a forged offer");
}

/// **The reason the task is 🔴.** After the handshake the login token must not
/// be readable by anything between the client and `hbbs`.
#[tokio::test(flavor = "multi_thread")]
async fn a_secured_connection_keeps_the_token_off_the_wire() {
    const TOKEN: &str = "t34-secret-token-do-not-leak";

    let api = stub(200, ALLOW).await;
    let s = hbbs(&auth_args(&api)).await;
    let mut b = register(s.port, "t34-dev-1").await;

    let mut c = Raw::connect(s.port).await;
    c.handshake(&s.key).await;

    let msg = punch_hole("t34-dev-1", &s.key, TOKEN);
    // The token is in the message, beyond doubt, before we look for it on the wire.
    assert!(
        contains(&msg.write_to_bytes().unwrap(), TOKEN.as_bytes()),
        "the test is not testing what it thinks it is"
    );
    c.send(&msg).await;

    let wire = c.sent_on_the_wire.last().unwrap();
    assert!(
        !contains(wire, TOKEN.as_bytes()),
        "the token crossed the wire in cleartext"
    );

    // And it is not merely scrambled — hbbs read it, which is the other half of
    // "encrypted" and the half a broken cipher would still fail. An allow is
    // answered to B, never to A (t33: `punch()` returning `None` *is* the allow),
    // so the proof that the frame was understood is that B was contacted at all.
    match next_from_hbbs(&mut b).await.union {
        Some(rendezvous_message::Union::PunchHole(_))
        | Some(rendezvous_message::Union::FetchLocalAddr(_)) => {}
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(api.calls(), 1, "hbbs never asked the api");
    assert!(
        api.requests.lock().unwrap()[0].contains(TOKEN),
        "hbbs did not recover the token it decrypted"
    );
}

/// The reply direction too, not just the request. A server that encrypted only
/// what it read would still hang the client.
#[tokio::test(flavor = "multi_thread")]
async fn the_reply_is_encrypted_too() {
    let api = stub(200, DENY).await;
    let s = hbbs(&auth_args(&api)).await;
    let _b = register(s.port, "t34-dev-2").await;

    let mut c = Raw::connect(s.port).await;
    c.handshake(&s.key).await;
    c.send(&punch_hole("t34-dev-2", &s.key, "any-token")).await;

    // Read the frame twice: once raw, to prove it is not a protobuf anyone can
    // parse, and once through `dec`, to prove it is ours.
    let mut raw = timeout(4_000, c.inner.next()).await.unwrap().expect("no reply").unwrap();
    let readable = RendezvousMessage::parse_from_bytes(&raw)
        .map(|m| m.union.is_some())
        .unwrap_or(false);
    assert!(!readable, "hbbs replied in cleartext");
    c.dec.as_mut().unwrap().dec(&mut raw).expect("cannot decrypt hbbs's reply");
    match RendezvousMessage::parse_from_bytes(&raw).unwrap().union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => assert_eq!(
            ph.other_failure, "You do not have access to this device.",
            "the refusal did not survive the round trip"
        ),
        other => panic!("unexpected {other:?}"),
    }
}

/// The compatibility half, and the one that would take the fleet down if it were
/// wrong. The controlled device opens short, write-only TCP connections to
/// answer a punch — `RelayResponse`, `LocalAddr`, `PunchHoleSent`
/// (`apps/rustdesk/src/rendezvous_mediator.rs:627`, `:717`, `:995`). None of
/// them calls `secure_tcp`, none of them ever reads the offer, and all of them
/// must keep working exactly as before.
///
/// Uses a denial because that is the branch that answers *A*: an allow is
/// answered to B.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_ignores_the_offer_is_served_in_plaintext() {
    let api = stub(200, DENY).await;
    let s = hbbs(&auth_args(&api)).await;
    let _b = register(s.port, "t34-dev-3").await;

    let mut c = Raw::connect(s.port).await;
    // Deliberately no read: the offer sits unread in the socket buffer, which is
    // what a write-only mediator connection does to it.
    c.send(&punch_hole("t34-dev-3", &s.key, "any-token")).await;

    // The offer is still first in line, and still plaintext.
    match c.recv(PROMPT.as_millis() as u64).await.expect("nothing at all").union {
        Some(rendezvous_message::Union::KeyExchange(_)) => {}
        other => panic!("expected the unread offer, got {other:?}"),
    }
    // `c.dec` is None, so this parsed without being decrypted: plaintext.
    match c.recv(4_000).await.expect("no response").union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
            assert_eq!(ph.other_failure, "You do not have access to this device.");
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// **The mixed case, and the one the design turns on.** Controller A is
/// encrypted; the controlled device answers a punch over a short, *plaintext*,
/// write-only connection (`PunchHoleSent`). hbbs routes that answer by pulling
/// A's sink out of `tcp_punch` — a sink belonging to a different connection, in
/// a different task, that must seal it with *A's* key.
///
/// If the encryptor lived beside the read loop instead of inside `Sink`, this is
/// the test that would fail: A would be sent plaintext and would try to decrypt
/// it.
///
/// The impersonation here is T3.8's open hole, not something this task
/// introduces — it is simply the cheapest way to make a plaintext peer answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_peer_can_answer_an_encrypted_controller() {
    let s = hbbs(&[]).await;
    let mut b = register(s.port, "t34-dev-5").await;

    // A: handshakes, then asks, encrypted throughout.
    let mut a = Raw::connect(s.port).await;
    a.handshake(&s.key).await;
    a.send(&punch_hole("t34-dev-5", &s.key, "")).await;
    let a_addr = a.inner.get_ref().local_addr().unwrap();

    // B hears about it, and A has heard nothing back yet: that is the window.
    match next_from_hbbs(&mut b).await.union {
        Some(rendezvous_message::Union::PunchHole(_))
        | Some(rendezvous_message::Union::FetchLocalAddr(_)) => {}
        other => panic!("unexpected {other:?}"),
    }

    // The answer comes in over a separate plaintext connection that never reads
    // the offer — the shape of `rendezvous_mediator.rs:995`.
    let mut peer = Raw::connect(s.port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_sent(PunchHoleSent {
        socket_addr: AddrMangle::encode(a_addr).into(),
        id: "t34-dev-5".to_owned(),
        relay_server: "127.0.0.1:21117".to_owned(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    peer.send(&msg).await;

    // A's `dec` is set, so this only parses if hbbs sealed it with A's key.
    match a.recv(4_000).await.expect("nothing reached A").union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
            assert_eq!(ph.relay_server, "127.0.0.1:21117");
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// A second exchange would re-key a connection already carrying traffic and
/// desynchronise both counters. `hbbs` drops the connection instead.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_key_exchange_drops_the_connection() {
    let s = hbbs(&[]).await;
    let mut c = Raw::connect(s.port).await;
    c.handshake(&s.key).await;

    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(KeyExchange {
        keys: vec![vec![7u8; box_::PUBLICKEYBYTES].into(), vec![9u8; 48].into()],
        ..Default::default()
    });
    c.send(&msg).await;

    assert!(
        c.recv(PROMPT.as_millis() as u64).await.is_none(),
        "hbbs kept talking after a second key exchange"
    );
}

/// Junk where the sealed key should be. The connection goes, rather than the
/// server carrying on with a key only one side has.
#[tokio::test(flavor = "multi_thread")]
async fn an_unopenable_key_exchange_drops_the_connection() {
    let s = hbbs(&[]).await;
    let mut c = Raw::connect(s.port).await;
    let _ = c.read_offer(&s.key, PROMPT.as_millis() as u64).await.expect("offer");

    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(KeyExchange {
        keys: vec![vec![1u8; box_::PUBLICKEYBYTES].into(), vec![2u8; 48].into()],
        ..Default::default()
    });
    c.send(&msg).await;

    assert!(
        c.recv(PROMPT.as_millis() as u64).await.is_none(),
        "hbbs kept talking after a key exchange it could not open"
    );
}

/// **`-k ''` does not turn the offer off**, which is not what you would guess.
///
/// `get_server_sk("")` falls into the same branch as `-`/`_` and calls
/// `gen_sk`, so a keyless `hbbs` still generates and keeps a secret key — it
/// just never advertises the public half as a licence key
/// (`src/rendezvous_server.rs`, `src/common.rs:196-230`). So `inner.sk` is
/// `Some` and we can sign, and we do.
///
/// That is the right way round: a client *with* a key pointed at a keyless
/// server now fails in a millisecond on a signature it cannot verify, where
/// before it stalled for 18 s and blamed the peer. A client without one skips
/// the offer and is served exactly as upstream serves it, which is what this
/// asserts.
#[tokio::test(flavor = "multi_thread")]
async fn a_keyless_server_still_offers_and_a_keyless_client_ignores_it() {
    let s = hbbs_with_key("", &[]).await;
    let mut b = register(s.port, "t34-dev-4").await;

    let mut c = Raw::connect(s.port).await;
    c.send(&punch_hole("t34-dev-4", "", "")).await;

    match c.recv(PROMPT.as_millis() as u64).await.expect("nothing at all").union {
        Some(rendezvous_message::Union::KeyExchange(ex)) => {
            assert_eq!(ex.keys.len(), 1, "a keyless server made a malformed offer");
        }
        other => panic!("expected an offer even with -k '', got {other:?}"),
    }
    // Skipped, exactly as `get_next_nonkeyexchange_msg` skips it. Authorization
    // is off here, so the punch is allowed and B is the one who hears about it.
    match next_from_hbbs(&mut b).await.union {
        Some(rendezvous_message::Union::PunchHole(_))
        | Some(rendezvous_message::Union::FetchLocalAddr(_)) => {}
        other => panic!("unexpected {other:?}"),
    }
}
