//! The two clients — TASK.md T5.1.
//!
//! "At least two real clients" is the part of T5.1 that needs stating honestly,
//! because the Flutter client cannot be driven from a test: on this host it is a
//! macOS `.app` with no headless mode, `--server` is a no-op in a
//! `--features flutter` build (T4.3), and `--connect` opens a window. What *is*
//! real, and what every one of these tests turns on, is the wire: these peers
//! speak the protocol the client speaks, byte for byte, to the same binaries,
//! and they are two separate identities with two separate tokens rather than one
//! socket pretending to be both.
//!
//! So the shape is deliberate. [`Device`] is the **controlled** side — it
//! registers over UDP and answers what hbbs forwards it, which is what
//! `rendezvous_mediator.rs` does. [`Controller`] is the **controlling** side —
//! it holds an `access_token` obtained from the real api and opens sessions,
//! which is what `client.rs` does. What neither does is anything a real client
//! would not: no message is sent here that the client does not send, which is
//! what makes T5.7's forged ones mean something.
//!
//! Where a GUI client is genuinely required — the login gate, the privilege
//! boundary, the tip string on screen — the task board says so and a person
//! drives it. This harness covers the server side of every one of those.

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use hbb_common::{
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::FramedStream,
    udp::FramedSocket,
    AddrMangle,
};

use super::{next_plaintext, relay::relay_join};

/// RustDesk ids are nine digits in the field, and the api's device fixtures are
/// too. Worth imitating: `rendezvous_server.rs` treats the id as opaque, but the
/// console renders it and `/api/internal/enrolled` matches on it exactly.
pub fn next_device_id() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!(
        "{:09}",
        700_000_000 + (std::process::id() as usize % 1_000) * 10_000 + NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

// ---------------------------------------------------------------- device (B)

/// The controlled device: an id, a uuid, a public key, and the UDP socket it is
/// registered from. hbbs forwards every brokerage to that socket, so keeping it
/// is what makes the device reachable at all.
pub struct Device {
    pub id: String,
    /// **Raw bytes, not text.** `RegisterPk.uuid` is a `bytes` field carrying a
    /// machine UID, and hbbs keeps it as bytes; the api stores the *base64* of
    /// those same bytes, because that is what hbbs sends it
    /// (`enrolment.rs:357`) and what `POST /api/devices/deploy` was given.
    /// Holding the raw form here and encoding at the api boundary keeps the two
    /// representations from being confused — which they were, once, and the
    /// symptom was `uuid belongs to another machine` for a device that had just
    /// been deployed.
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub sock: FramedSocket,
    pub hbbs_port: u16,
}

impl Device {
    /// The uuid as `apps/api` stores it: base64 of the raw bytes.
    pub fn uuid_b64(&self) -> String {
        base64::encode(&self.uuid)
    }

    pub fn pk_b64(&self) -> String {
        base64::encode(&self.pk)
    }
}

/// What hbbs handed the device when it brokered a connection to it.
///
/// `conn_audit_ref` and `permissions` are the two fields Milestone 3 added
/// (T3.3), and they are the whole reason a session can be attributed and
/// revoked later — so every session helper here returns them rather than
/// discarding them.
#[derive(Debug, Clone)]
pub struct Brokerage {
    /// `true` when hbbs sent `FetchLocalAddr` rather than `PunchHole` — it does
    /// that when A and B look like they share a LAN, which on loopback is
    /// always. Both are brokerages; they differ only in which ack B owes.
    pub local: bool,
    pub conn_audit_ref: Option<String>,
    pub permissions: Option<u64>,
    /// A's address as hbbs mangled it. Echoed back verbatim in the ack — it is
    /// how hbbs routes the response, and how T3.8's ledger checks the answer.
    pub addr_a: Vec<u8>,
    pub relay_server: String,
}

impl Device {
    /// Registers with hbbs and keeps the socket, retrying until hbbs actually
    /// holds the peer.
    ///
    /// **An `OK` is not a registration when enrolment is on.** The first
    /// `RegisterPk` from an id hbbs has never seen is answered `OK` and
    /// deliberately *not* written to the peer table — the deferred branch at
    /// `rendezvous_server.rs:564`, which exists so that an api outage cannot
    /// deregister the fleet while still refusing to let a stranger claim an id.
    /// So the honest signal is `update_pk <id>` in hbbs's log, and a device that
    /// stopped at the first `OK` would fail its first connection with
    /// `ID_NOT_EXIST` — a symptom that points at authorization rather than at
    /// registration, which is the wrong place to spend an afternoon.
    ///
    /// Retrying also covers the plain case: UDP to a process that has only just
    /// bound its socket is dropped silently.
    pub async fn register_fully(hbbs: &super::Hbbs, id: &str, uuid: &[u8], pk: &[u8]) -> Device {
        let mut device = Device::register(hbbs.port, id, uuid, pk).await;
        let needle = format!("update_pk {id}");
        for _ in 0..8 {
            if hbbs.wait_for_log(&needle, 600).await {
                return device;
            }
            // `REG_TIMEOUT` rate-limits a peer to one registration every few
            // seconds; a `TOO_FREQUENT` here means waiting, not trying harder.
            if device.register_again(id, uuid, pk).await
                == Some(register_pk_response::Result::TOO_FREQUENT)
            {
                hbb_common::tokio::time::sleep(Duration::from_millis(7_200)).await;
            }
        }
        panic!("{id} never made it into hbbs's peer table\n{}", hbbs.log());
    }

    /// Registers with hbbs and keeps the socket.
    ///
    /// Retries, for the reason the original `register` does: UDP to a process
    /// that has only just bound its socket is dropped silently, and an
    /// unregistered peer fails `ID_NOT_EXIST` *before* any authorization check —
    /// so a lost datagram does not look like a lost datagram, it looks like the
    /// gate under test not working.
    pub async fn register(hbbs_port: u16, id: &str, uuid: &[u8], pk: &[u8]) -> Device {
        let mut sock = FramedSocket::new("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let server: SocketAddr = format!("127.0.0.1:{hbbs_port}").parse().unwrap();
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: uuid.to_vec().into(),
            pk: pk.to_vec().into(),
            ..Default::default()
        });
        for _ in 0..40 {
            sock.send(&msg, server).await.unwrap();
            let Some(Ok((bytes, _))) = sock.next_timeout(500).await else {
                continue;
            };
            match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
                Some(rendezvous_message::Union::RegisterPkResponse(r)) => {
                    assert_eq!(
                        r.result.enum_value(),
                        Ok(register_pk_response::Result::OK),
                        "device {id} was refused registration: {:?}",
                        r.result
                    );
                    return Device {
                        id: id.to_owned(),
                        uuid: uuid.to_vec(),
                        pk: pk.to_vec(),
                        sock,
                        hbbs_port,
                    };
                }
                other => panic!("unexpected answer to RegisterPk: {other:?}"),
            }
        }
        panic!("hbbs never answered RegisterPk for {id}");
    }

    /// Sends one more `RegisterPk` on the socket this device already holds, and
    /// returns hbbs's verdict without asserting on it.
    pub async fn register_again(
        &mut self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
    ) -> Option<register_pk_response::Result> {
        let server: SocketAddr = format!("127.0.0.1:{}", self.hbbs_port).parse().unwrap();
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: uuid.to_vec().into(),
            pk: pk.to_vec().into(),
            ..Default::default()
        });
        self.sock.send(&msg, server).await.unwrap();
        let (bytes, _) = self.sock.next_timeout(1_500).await?.ok()?;
        match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
            Some(rendezvous_message::Union::RegisterPkResponse(r)) => r.result.enum_value().ok(),
            other => panic!("unexpected answer to RegisterPk: {other:?}"),
        }
    }

    /// The keepalive a settled client sends every few seconds. `request_pk` is
    /// hbbs asking the device to re-register, which is how T3.5.4 walks an
    /// un-enrolled device back to `NOT_DEPLOYED`.
    pub async fn heartbeat(&mut self, ms: u64) -> Option<bool> {
        let server: SocketAddr = format!("127.0.0.1:{}", self.hbbs_port).parse().unwrap();
        let mut msg = RendezvousMessage::new();
        msg.set_register_peer(RegisterPeer {
            id: self.id.clone(),
            ..Default::default()
        });
        self.sock.send(&msg, server).await.unwrap();
        let (bytes, _) = self.sock.next_timeout(ms).await?.ok()?;
        match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
            Some(rendezvous_message::Union::RegisterPeerResponse(r)) => Some(r.request_pk),
            other => panic!("unexpected answer to RegisterPeer: {other:?}"),
        }
    }

    /// Waits for hbbs to broker a connection to this device.
    ///
    /// `None` means nothing arrived, which on a denied connection is the correct
    /// outcome and the one worth asserting: a refusal that still contacts B has
    /// leaked B's existence to a stranger.
    pub async fn brokered(&mut self, ms: u64) -> Option<Brokerage> {
        let (bytes, _) = self.sock.next_timeout(ms).await?.ok()?;
        match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
            Some(rendezvous_message::Union::PunchHole(p)) => Some(Brokerage {
                local: false,
                conn_audit_ref: p
                    .controlled_context
                    .into_option()
                    .map(|c| c.conn_audit_ref),
                permissions: p.control_permissions.into_option().map(|p| p.permissions),
                addr_a: p.socket_addr.to_vec(),
                relay_server: p.relay_server,
            }),
            Some(rendezvous_message::Union::FetchLocalAddr(f)) => Some(Brokerage {
                local: true,
                conn_audit_ref: f
                    .controlled_context
                    .into_option()
                    .map(|c| c.conn_audit_ref),
                permissions: f.control_permissions.into_option().map(|p| p.permissions),
                addr_a: f.socket_addr.to_vec(),
                relay_server: f.relay_server,
            }),
            other => panic!("unexpected forward to the device: {other:?}"),
        }
    }

    /// Answers a brokerage, which is what makes A hear back.
    ///
    /// A real client opens a **fresh, write-only TCP connection** for this and
    /// never reads our `KeyExchange` offer
    /// (`apps/rustdesk/src/rendezvous_mediator.rs:627`, `:717`); that is why
    /// T3.4 had to make the offer optional, and imitating it here keeps that
    /// path exercised rather than assumed.
    pub async fn answer(&self, brokerage: &Brokerage) {
        let mut stream = FramedStream::new(format!("127.0.0.1:{}", self.hbbs_port), None, 3_000)
            .await
            .expect("device could not reach hbbs to answer");
        let mut msg = RendezvousMessage::new();
        if brokerage.local {
            msg.set_local_addr(LocalAddr {
                socket_addr: brokerage.addr_a.clone().into(),
                // Where A is told to connect. On loopback the only address that
                // could work is one of ours, and T3.8's whole subject is that a
                // stranger must not get to choose it.
                local_addr: brokerage.addr_a.clone().into(),
                id: self.id.clone(),
                ..Default::default()
            });
        } else {
            msg.set_punch_hole_sent(PunchHoleSent {
                socket_addr: brokerage.addr_a.clone().into(),
                id: self.id.clone(),
                relay_server: brokerage.relay_server.clone(),
                ..Default::default()
            });
        }
        stream.send(&msg).await.unwrap();
    }

    /// Completes a relay the way a client does when hbbs forwards it a
    /// `RequestRelay`: join `hbbr` under the uuid A chose, then tell hbbs so it
    /// can steer A to the same place.
    ///
    /// Returns the device's end of the relayed session.
    pub async fn accept_relay(&mut self, key: &str, ms: u64) -> Option<(FramedStream, RequestRelay)> {
        let (bytes, _) = self.sock.next_timeout(ms).await?.ok()?;
        let rf = match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
            Some(rendezvous_message::Union::RequestRelay(rf)) => rf,
            other => panic!("unexpected forward to the device: {other:?}"),
        };
        // Join first, ack second. Either order pairs — `hbbr` parks the first
        // arrival for 30 s — but this is the client's order, and doing it the
        // other way would hide a relay that is unreachable behind an A that is
        // already waiting.
        //
        // The address is used exactly as hbbs forwarded it, because that is what
        // the client does; a harness that rebuilt it from a port would paper
        // over hbbs handing out one nobody can reach.
        let stream = relay_join(&rf.relay_server, &rf.uuid, key).await;

        let mut ack = FramedStream::new(format!("127.0.0.1:{}", self.hbbs_port), None, 3_000)
            .await
            .expect("device could not reach hbbs to ack the relay");
        let mut msg = RendezvousMessage::new();
        // **No id.** This is `create_relay(initiate = false)`, the fallback ack,
        // and it carries no id, no uuid and no relay server
        // (`rendezvous_mediator.rs:579-604`). docs/CONTEXT.md §6 records that an
        // id-less ack is accepted on the brokerage alone — sending one with an
        // id here would test the *other* branch of T3.8 by accident.
        msg.set_relay_response(RelayResponse {
            socket_addr: rf.socket_addr.clone(),
            ..Default::default()
        });
        ack.send(&msg).await.unwrap();
        Some((stream, rf))
    }
}

// ---------------------------------------------------------------- controller (A)

/// The controlling side: a signed-in user with a token, opening sessions.
pub struct Controller {
    pub user_id: String,
    pub email: String,
    /// What `POST /api/login` issued. Travels in `PunchHoleRequest.token`.
    pub token: String,
    /// This client's *own* device id — a controller is a machine too.
    pub id: String,
    pub hbbs_port: u16,
    pub key: String,
}

/// Why a connection did not happen, in the words the user would see.
pub type Refusal = String;

impl Controller {
    /// Opens a direct session end to end: A asks, hbbs authorizes and brokers,
    /// B answers, A hears back.
    ///
    /// Both halves run concurrently because they have to: on an allow, A's
    /// `PunchHoleResponse` is *produced by B's answer*, so waiting for A first
    /// would deadlock against a device that has not been read from yet.
    pub async fn connect(
        &self,
        b: &mut Device,
        conn_type: ConnType,
        ms: u64,
    ) -> Result<(Brokerage, PunchHoleResponse), Refusal> {
        let mut stream = FramedStream::new(format!("127.0.0.1:{}", self.hbbs_port), None, 3_000)
            .await
            .expect("controller could not reach hbbs");
        let mut msg = RendezvousMessage::new();
        msg.set_punch_hole_request(PunchHoleRequest {
            id: b.id.clone(),
            licence_key: self.key.clone(),
            token: self.token.clone(),
            conn_type: conn_type.into(),
            nat_type: NatType::ASYMMETRIC.into(),
            ..Default::default()
        });
        stream.send(&msg).await.unwrap();

        let brokerage = b.brokered(ms).await;
        let Some(brokerage) = brokerage else {
            // Nothing reached B, so either this was refused or hbbs said nothing
            // at all. Both are failures of the connection; only one has words.
            let response = next_plaintext(&mut stream, ms).await;
            return Err(refusal_of(response));
        };
        b.answer(&brokerage).await;

        let Some(msg) = next_plaintext(&mut stream, ms).await else {
            return Err("hbbs brokered the connection but never answered A".to_owned());
        };
        match msg.union {
            Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
                if !ph.other_failure.is_empty() {
                    return Err(ph.other_failure);
                }
                Ok((brokerage, ph))
            }
            other => Err(format!("unexpected answer to A: {other:?}")),
        }
    }

    /// Opens a **relayed** session end to end, through the real `hbbr`, and
    /// returns both ends of it.
    ///
    /// This is the path T3.3b gates and the only one `hbbr` ever sees. Run every
    /// row of T5.2 through it as well as through [`connect`](Self::connect):
    /// they are two separate gates, and only this one carries A's own metadata.
    pub async fn connect_relayed(
        &self,
        b: &mut Device,
        relay_addr: &str,
        relay_key: &str,
        ms: u64,
    ) -> Result<(FramedStream, FramedStream, RequestRelay), Refusal> {
        let uuid = format!("e2e-relay-{}-{}", std::process::id(), next_device_id());
        let mut stream = FramedStream::new(format!("127.0.0.1:{}", self.hbbs_port), None, 3_000)
            .await
            .expect("controller could not reach hbbs");
        let mut msg = RendezvousMessage::new();
        msg.set_request_relay(RequestRelay {
            id: b.id.clone(),
            uuid: uuid.clone(),
            token: self.token.clone(),
            // Upstream never checks the licence key on this path and neither do
            // we — the token is the stronger claim. Sent as the client sends it.
            licence_key: self.key.clone(),
            relay_server: relay_addr.to_owned(),
            ..Default::default()
        });
        stream.send(&msg).await.unwrap();

        let Some((b_end, forwarded)) = b.accept_relay(relay_key, ms).await else {
            let response = next_plaintext(&mut stream, ms).await;
            return Err(refusal_of(response));
        };

        // B has acked; hbbs should now steer A to the same relay.
        let Some(msg) = next_plaintext(&mut stream, ms).await else {
            return Err("hbbs forwarded the relay request but never answered A".to_owned());
        };
        match msg.union {
            Some(rendezvous_message::Union::RelayResponse(rr)) if !rr.refuse_reason.is_empty() => {
                return Err(rr.refuse_reason)
            }
            Some(rendezvous_message::Union::RelayResponse(_)) => {}
            other => return Err(format!("unexpected answer to A: {other:?}")),
        }

        let a_end = relay_join(relay_addr, &uuid, relay_key).await;
        Ok((a_end, b_end, forwarded))
    }

    /// Asks hbbs for a relay and returns only what A was told, without a device
    /// on the other end. T5.7's forged-token cases want exactly this.
    pub async fn request_relay_alone(&self, to_id: &str, ms: u64) -> Option<RelayResponse> {
        let mut stream = FramedStream::new(format!("127.0.0.1:{}", self.hbbs_port), None, 3_000)
            .await
            .ok()?;
        let mut msg = RendezvousMessage::new();
        msg.set_request_relay(RequestRelay {
            id: to_id.to_owned(),
            uuid: format!("e2e-alone-{}", next_device_id()),
            token: self.token.clone(),
            licence_key: self.key.clone(),
            relay_server: "127.0.0.1:0".to_owned(),
            ..Default::default()
        });
        stream.send(&msg).await.ok()?;
        match next_plaintext(&mut stream, ms).await?.union {
            Some(rendezvous_message::Union::RelayResponse(rr)) => Some(rr),
            other => panic!("unexpected answer to A: {other:?}"),
        }
    }
}

/// Turns whatever hbbs said (or did not say) into the sentence a test asserts on.
fn refusal_of(response: Option<RendezvousMessage>) -> Refusal {
    match response.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(ph))) => {
            if !ph.other_failure.is_empty() {
                ph.other_failure
            } else {
                format!("{:?}", ph.failure.enum_value())
            }
        }
        Some(Some(rendezvous_message::Union::RelayResponse(rr))) => {
            if rr.refuse_reason.is_empty() {
                "hbbs answered A with an empty RelayResponse".to_owned()
            } else {
                rr.refuse_reason
            }
        }
        Some(other) => format!("unexpected answer to A: {other:?}"),
        // Silence. Upstream answers an unknown peer with nothing at all on the
        // relay path, so this is a real outcome and not a harness timeout.
        None => String::new(),
    }
}

/// Mangles an address the way hbbs does, for tests that forge one.
#[allow(dead_code)]
pub fn mangle(addr: SocketAddr) -> Vec<u8> {
    AddrMangle::encode(addr).into()
}

/// A short wait used where the assertion is that *nothing* happens.
#[allow(dead_code)]
pub const QUIET: Duration = Duration::from_millis(700);
