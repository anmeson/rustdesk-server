//! T3.3 verification: drives the real `hbbs` binary over the real wire.
//!
//! Throwaway harness — T5.1 owns the standing one. Speaks UDP `RegisterPk` +
//! `RegisterPeer` as device B, then TCP `PunchHoleRequest` as controller A, and
//! checks both what A gets back and what B is handed.

use hbb_common::{
    protobuf::{Message as _, MessageField},
    rendezvous_proto::*,
    tcp::FramedStream,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::sleep,
    },
    udp::FramedSocket,
    AddrMangle,
};
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

// ---------------------------------------------------------------- auth stub

struct Stub {
    addr: SocketAddr,
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

/// Answers on the content of the request, not on its ordinal.
///
/// Ordinal replies looked obvious and were wrong: the counter has to advance on
/// a *delivered request*, and a connection the client opens and does not use
/// would otherwise shift every reply after it by one — which reads as the
/// authorization logic misbehaving rather than as a test stub misbehaving.
async fn stub_by(reply: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> Stub {
    let reply = Arc::new(reply);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (c, r) = (calls.clone(), requests.clone());
    tokio::spawn(async move {
        let reply = reply.clone();
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let Ok(read) = sock.read(&mut buf).await else { break };
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..read]);
                let text = String::from_utf8_lossy(&raw).to_lowercase();
                if let (Some(head), Some(len)) = (
                    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4),
                    text.find("content-length:").and_then(|i| {
                        text[i + 15..].split("\r\n").next()?.trim().parse::<usize>().ok()
                    }),
                ) {
                    if raw.len() >= head + len {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&raw).into_owned();
            r.lock().unwrap().push(text.clone());
            c.fetch_add(1, Ordering::SeqCst);
            let (status, body) = reply(&text);
            let head = format!(
                "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    Stub { addr, calls, requests }
}

impl Stub {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// One answer to every request.
async fn stub(status: u16, body: &'static str) -> Stub {
    stub_by(move |_| (status, body.to_owned())).await
}

// ---------------------------------------------------------------- hbbs

struct Hbbs {
    _permit: tokio::sync::OwnedSemaphorePermit,
    child: Child,
    port: u16,
    key: String,
    _dir: TempDir,
}

/// Enough of `tempdir` not to add a dev-dependency to a throwaway harness.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        // A counter, not a timestamp. `SystemTime` on macOS is coarse enough that
        // two tests starting together got the same name — and then two `hbbs`
        // shared one directory, so the second regenerated `id_ed25519` under the
        // first, which had already read it. That surfaced as `LICENSE_MISMATCH`
        // in whichever test lost, and as `database is locked` in the other.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "t33-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Hbbs {
    fn log(&self) -> String {
        std::fs::read_to_string(self._dir.path().join("hbbs.log")).unwrap_or_default()
    }
}

impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One `hbbs` occupies four ports: TCP `p-1` (NAT test + console), TCP and UDP
/// `p`, and TCP `p+2`. An ephemeral port is therefore not enough — its
/// neighbours may be in use — so hand each test its own block and check all four
/// before spawning anything.
fn free_port_block() -> u16 {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    // Offset by pid so two `cargo test` runs at once do not fight.
    // Kept well below the ephemeral range (49152+ on macOS): the auth stubs bind
    // ephemeral ports, and a "dead" port drawn from there is one a later stub can
    // pick up — which is cross-talk between tests, not a dead port at all.
    let base = 39_000u16 + ((std::process::id() as u16) % 60) * 100;
    for _ in 0..400 {
        let port = base + (NEXT.fetch_add(4, Ordering::SeqCst) as u16 % 100);
        if port < 2 {
            continue;
        }
        let tcp = |p: u16| std::net::TcpListener::bind(("127.0.0.1", p));
        let udp = |p: u16| std::net::UdpSocket::bind(("127.0.0.1", p));
        if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (tcp(port - 1), tcp(port), tcp(port + 2), udp(port)) {
            drop((a, b, c, d));
            // A successful bind is not proof the port is free: `hbbs` sets
            // SO_REUSEPORT (`hbb_common::tcp::new_socket`), so a stray one from a
            // previous run shares the port instead of losing it. Ask whether
            // anything answers.
            let busy = [port - 1, port, port + 2].iter().any(|p| {
                std::net::TcpStream::connect_timeout(
                    &SocketAddr::from(([127, 0, 0, 1], *p)),
                    Duration::from_millis(80),
                )
                .is_ok()
            });
            if !busy {
                return port;
            }
        }
    }
    panic!("no free port block");
}

/// A port nothing will listen on, for the fail-closed test. Taken from our own
/// block range rather than from an ephemeral one, for the reason above; `p + 1`
/// is the one port in a block that `hbbs` itself does not bind.
fn dead_port() -> u16 {
    free_port_block() + 1
}

async fn hbbs(extra: &[String]) -> Hbbs {
    // Every test wants its own `hbbs`, and nine of them starting at once — each a
    // multi-threaded runtime opening its own sqlite — is enough load on a laptop
    // to push startup past any sane timeout. Cap how many exist at a time; the
    // permit is held by the guard, so it is released when the process is killed.
    static SLOTS: once_cell::sync::Lazy<Arc<tokio::sync::Semaphore>> =
        once_cell::sync::Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(3)));
    let permit = SLOTS.clone().acquire_owned().await.unwrap();
    let dir = TempDir::new();
    let port = free_port_block();
    let bin = std::env::current_dir().unwrap().join("target/debug/hbbs");
    let mut cmd = Command::new(bin);
    cmd.current_dir(dir.path())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.path())
        .env("TEST_HBBS", "no")
        .arg("-p")
        .arg(port.to_string())
        .arg("-k")
        .arg("_")
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(dir.path().join("hbbs.log")).unwrap(),
        ));
    for a in extra {
        cmd.arg(a);
    }
    // The guard is built *before* anything below can panic. `hbbs` binds with
    // SO_REUSEPORT, so a leaked one does not fail the next test's bind — it
    // quietly shares the port and swallows half its datagrams, which reads as
    // nine unrelated flaky assertions.
    let mut s = Hbbs {
        _permit: permit,
        child: cmd.spawn().unwrap(),
        port,
        key: String::new(),
        _dir: dir,
    };

    // `hbbs` creates its key file and then writes it, so "the file exists" is not
    // "the key is there". Wait for content, and if it never comes say whether the
    // process died rather than panicking on a read of a file nobody explains.
    let pub_key = s._dir.path().join("id_ed25519.pub");
    for _ in 0..600 {
        if let Ok(text) = std::fs::read_to_string(&pub_key) {
            if !text.trim().is_empty() {
                s.key = text.trim().to_owned();
                break;
            }
        }
        if let Ok(Some(status)) = s.child.try_wait() {
            panic!("hbbs exited before writing its key: {status} (port {port})\n{}", s.log());
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(!s.key.is_empty(), "hbbs never wrote id_ed25519.pub (port {port})");

    // The key is written well before any port is bound, so it is a bad readiness
    // signal — wait for the rendezvous listener itself. Without this, a test that
    // does not go through `register` (which retries) races the listener and fails
    // with a bare "failed to connect".
    let mut ready = false;
    for _ in 0..600 {
        if std::net::TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            ready = true;
            break;
        }
        if let Ok(Some(status)) = s.child.try_wait() {
            panic!("hbbs exited during startup: {status} (port {port})\n{}", s.log());
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "hbbs never accepted TCP on {port}");
    s
}

/// Registers device B and keeps its UDP socket, which is where hbbs forwards.
///
/// Retries until `hbbs` answers. UDP to a process that has only just bound its
/// socket is silently dropped, and an unregistered peer fails the `ID_NOT_EXIST`
/// branch *before* the authorization check — so a lost datagram here does not
/// look like a lost datagram, it looks like this whole task not working.
/// `RegisterPk` is enough on its own: `PeerMap::update_pk` sets `last_reg_time`
/// (`src/peer.rs:108`), which is what the `OFFLINE` check reads.
async fn register(port: u16, id: &str) -> FramedSocket {
    let mut sock = FramedSocket::new("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: b"t33-uuid-0001".to_vec().into(),
        pk: b"t33-public-key-0001".to_vec().into(),
        ..Default::default()
    });
    for _ in 0..40 {
        sock.send(&msg, server).await.unwrap();
        let Some(Ok((bytes, _))) = sock.next_timeout(500).await else {
            continue;
        };
        let reply = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        match reply.union {
            Some(rendezvous_message::Union::RegisterPkResponse(r)) => {
                assert_eq!(r.result.enum_value(), Ok(register_pk_response::Result::OK));
                return sock;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    panic!("hbbs never answered RegisterPk for {id}");
}

/// Sends one `PunchHoleRequest` and waits `ms` for a `PunchHoleResponse`.
///
/// `None` is the *allow* outcome: on an allow hbbs answers nobody and forwards
/// `PunchHole` / `FetchLocalAddr` to B instead, so A hears back only once B
/// replies. Every refusal, ours and upstream's, comes straight back on this
/// stream — which is what makes a denial visible to the user at all.
async fn punch(
    port: u16,
    key: &str,
    id: &str,
    token: &str,
    conn_type: ConnType,
    ms: u64,
) -> Option<PunchHoleResponse> {
    let mut stream = FramedStream::new(format!("127.0.0.1:{port}"), None, 3_000)
        .await
        .unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        licence_key: key.to_owned(),
        token: token.to_owned(),
        conn_type: conn_type.into(),
        nat_type: NatType::ASYMMETRIC.into(),
        ..Default::default()
    });
    stream.send(&msg).await.unwrap();
    let bytes = stream.next_timeout(ms).await?.unwrap();
    match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => Some(ph),
        other => panic!("unexpected {other:?}"),
    }
}

const REFUSAL_WAIT: u64 = 4_000;
/// How long to insist nothing came back on an allow. Short on purpose: this is
/// waited out on the happy path of several tests.
const ALLOW_WAIT: u64 = 800;

/// Sends one `RequestRelay` as A and waits `ms` for a `RelayResponse`.
///
/// `None` means hbbs forwarded it and said nothing to A, which is the allow
/// outcome. A refusal comes back here as `refuse_reason`, which the client
/// `bail!`s with verbatim.
async fn request_relay(
    port: u16,
    id: &str,
    token: &str,
    forged_ref: Option<&str>,
    ms: u64,
) -> Option<RelayResponse> {
    let mut stream = FramedStream::new(format!("127.0.0.1:{port}"), None, 3_000)
        .await
        .unwrap();
    let mut rr = RequestRelay {
        id: id.to_owned(),
        uuid: "t33-relay-uuid".to_owned(),
        token: token.to_owned(),
        // Deliberately not the server's key: upstream never checks it here, and
        // neither do we — the token is the stronger claim and the only one we
        // are prepared to defend.
        licence_key: "not-the-key".to_owned(),
        relay_server: "127.0.0.1:21117".to_owned(),
        ..Default::default()
    };
    if let Some(forged) = forged_ref {
        rr.controlled_context = MessageField::some(ControlledContext {
            conn_audit_ref: forged.to_owned(),
            ..Default::default()
        });
        rr.control_permissions = MessageField::some(ControlPermissions {
            permissions: 0b10_10_10,
            ..Default::default()
        });
    }
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(rr);
    stream.send(&msg).await.unwrap();
    let bytes = stream.next_timeout(ms).await?.unwrap();
    match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
        Some(rendezvous_message::Union::RelayResponse(rs)) => Some(rs),
        other => panic!("unexpected {other:?}"),
    }
}

/// The `RequestRelay` hbbs forwarded to B, with the two fields that matter.
async fn relay_at_b(sock: &mut FramedSocket) -> RequestRelay {
    let (bytes, _) = sock
        .next_timeout(4_000)
        .await
        .expect("hbbs forwarded B nothing")
        .unwrap();
    match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
        Some(rendezvous_message::Union::RequestRelay(rr)) => rr,
        other => panic!("unexpected {other:?}"),
    }
}

async fn next_from_hbbs(sock: &mut FramedSocket) -> RendezvousMessage {
    let (bytes, _) = sock.next_timeout(4_000).await.expect("hbbs sent B nothing").unwrap();
    RendezvousMessage::parse_from_bytes(&bytes).unwrap()
}

fn auth_args(stub: &Stub) -> Vec<String> {
    vec![
        "--auth-api-url".into(),
        format!("http://{}", stub.addr),
        "--auth-api-secret".into(),
        "t33-shared-secret".into(),
        // The 300 ms production default is right for production and wrong here:
        // nine hbbs processes and nine stubs on one loaded machine would turn
        // scheduler jitter into a fail-closed denial and a red test.
        "--auth-timeout-ms".into(),
        "4000".into(),
    ]
}

const ALLOW: &str = r#"{"allow":true,"conn_audit_ref":"ref-t33","permissions":6}"#;
const DENY: &str = r#"{"allow":false,"reason":"You do not have access to this device."}"#;

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
// stranger who knows a waiting controller's address as hbbs sees it can answer
// on the real peer's behalf. Both tests below were written against the running
// binaries, not from reading the source.

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

    if let Some(Ok(bytes)) = a.next_timeout(2_500).await {
        match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
            Some(rendezvous_message::Union::RelayResponse(rs)) => assert!(
                rs.refuse_reason.is_empty(),
                "a stranger's text reached the user: {:?}",
                rs.refuse_reason
            ),
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// **This test asserts a hole, not a fix — see T3.8.**
///
/// The message still arrives; only its text was taken away above. A stranger
/// can still answer a waiting controller with an address and relay server of
/// their choosing, because nothing ties a response to the peer it claims to come
/// from. Closing that needs hbbs to remember which pairs it brokered, which is a
/// change to upstream's core routing and wants testing against real devices on a
/// real network — so it is filed rather than guessed at here.
///
/// Pinned so that closing it shows up as this test failing.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_can_still_answer_a_waiting_controller() {
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
        // An id hbbs has never heard of, which is what makes this worse than a
        // nuisance: `get_pk` returns nothing, and the client treats an absent
        // peer key as "no identity to verify" and connects anyway
        // (`apps/rustdesk/src/client.rs:1624-1634`).
        id: "t33-not-a-device".to_owned(),
        relay_server: "evil.example.com:21117".to_owned(),
        version: "1.5.0".to_owned(),
        ..Default::default()
    });
    evil.send(&msg).await.unwrap();

    let (bytes, _) = (
        a.next_timeout(2_500)
            .await
            .expect("T3.8 may have landed: update this test")
            .unwrap(),
        (),
    );
    match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
            assert_eq!(ph.relay_server, "evil.example.com:21117");
            assert!(ph.pk.is_empty(), "hbbs supplied a key for an unknown id");
        }
        other => panic!("unexpected {other:?}"),
    }
}
