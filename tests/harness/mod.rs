//! Shared harness for the `hbbs` integration tests.
//!
//! Extracted from `t33_chokepoint.rs` when T3.4 needed the same spawn-a-real-
//! server machinery, and **grown into the standing harness by T5.1** rather than
//! replaced — the port allocator, the temp directory and the startup race below
//! are the four things that made the first suite flaky, and rediscovering them
//! in a second harness was never going to be cheaper than sharing this one.
//!
//! This file is the hbbs half: spawn the real binary, speak the real wire
//! protocol at it — UDP `RegisterPk` / `RegisterPeer` as device B, TCP
//! `PunchHoleRequest` / `RequestRelay` as controller A — and answer it with a
//! stub api that can be made to misbehave.
//!
//! Milestone 5 needs three things a stub cannot provide, and each is a module:
//!
//!   - [`api`] — the real `apps/api` on its own database, with the console and
//!     client endpoints driven over HTTP. A stub cannot *decide* anything.
//!   - [`relay`] — the real `hbbr`, and the bytes that go through it.
//!   - [`peer`] — two clients rather than one socket, each with its own token.
//!
//! and [`world`] brings all four up together, which is the unit a Milestone 5
//! test is written against.

// Each test binary uses a different subset of this.
#![allow(dead_code)]

pub mod api;
pub mod breakglass;
pub mod peer;
pub mod relay;
pub mod session;
pub mod world;


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

pub struct Stub {
    pub addr: SocketAddr,
    calls: Arc<AtomicUsize>,
    pub requests: Arc<Mutex<Vec<String>>>,
}

/// Answers on the content of the request, not on its ordinal.
///
/// Ordinal replies looked obvious and were wrong: the counter has to advance on
/// a *delivered request*, and a connection the client opens and does not use
/// would otherwise shift every reply after it by one — which reads as the
/// authorization logic misbehaving rather than as a test stub misbehaving.
pub async fn stub_by(reply: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> Stub {
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
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// One answer to every request.
pub async fn stub(status: u16, body: &'static str) -> Stub {
    stub_by(move |_| (status, body.to_owned())).await
}

/// A stub that refuses everything until it is switched on.
///
/// Not "a stub that is started later": the port has to be bound from the
/// beginning, because hbbs is given the address at boot and a port that is
/// closed and then opened is a different thing to test than a server that is
/// failing and then recovers. While it is off, every request gets a 503, which
/// is what hbbs sees from a service that is up but unwell — the outage this
/// path exists for.
pub fn switchable() -> (Arc<std::sync::atomic::AtomicBool>, impl Fn(&str) -> (u16, String) + Send + Sync + 'static) {
    let on = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = on.clone();
    (on, move |_: &str| {
        if flag.load(Ordering::SeqCst) {
            (200, r#"{"ok":true,"stored":1,"already_known":0}"#.to_owned())
        } else {
            (503, r#"{"error":"down"}"#.to_owned())
        }
    })
}

// ---------------------------------------------------------------- hbbs

pub struct Hbbs {
    _permit: tokio::sync::OwnedSemaphorePermit,
    child: Child,
    pub port: u16,
    pub key: String,
    _dir: TempDir,
}

/// Enough of `tempdir` not to add a dev-dependency to a throwaway harness.
pub struct TempDir(std::path::PathBuf);

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
    /// The working directory hbbs was started in, which is where it writes
    /// anything it is given a relative path for — the break-glass audit log
    /// (T3.6) among them.
    pub fn dir(&self) -> &std::path::Path {
        self._dir.path()
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self._dir.path().join("hbbs.log")).unwrap_or_default()
    }

    /// Waits for `needle` to appear in the log, up to `ms`.
    ///
    /// Polling rather than a single read, because `main` starts flexi_logger
    /// with `WriteMode::Async` (`src/main.rs:20`): the line exists in the
    /// process before it exists in the file, and how long that gap is depends
    /// on the flush interval and the load on the machine. A bare read here was
    /// a test that passed alone and failed in a full run.
    pub async fn wait_for_log(&self, needle: &str, ms: u64) -> bool {
        for _ in 0..(ms / 50).max(1) {
            if self.log().contains(needle) {
                return true;
            }
            sleep(Duration::from_millis(50)).await;
        }
        false
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
pub fn free_port_block() -> u16 {
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
pub fn dead_port() -> u16 {
    free_port_block() + 1
}

pub async fn hbbs(extra: &[String]) -> Hbbs {
    hbbs_with_key("_", extra).await
}

/// `hbbs` with extra environment variables as well as flags.
///
/// Not every switch has a flag. `ALWAYS_USE_RELAY` — the one T5.10 turns the
/// whole matrix on — is read through `get_arg` (`rendezvous_server.rs:253`),
/// which covers the environment and a `.env` file but has no CLI form. Since
/// the spawn uses `env_clear`, setting it in the test process would not reach
/// the child either.
pub async fn hbbs_full(key: &str, extra: &[String], env: &[(&str, String)]) -> Hbbs {
    hbbs_spawn(key, extra, env).await
}

/// `hbbs` with an explicit `-k`. `"_"` is the usual one — it makes `hbbs`
/// generate a key pair and write the public half to `id_ed25519.pub`, which is
/// where `Hbbs::key` comes from. `""` is the keyless deployment CONTEXT.md §7
/// warns about, and is its own case for T3.4.
pub async fn hbbs_with_key(key: &str, extra: &[String]) -> Hbbs {
    hbbs_spawn(key, extra, &[]).await
}

async fn hbbs_spawn(key: &str, extra: &[String], extra_env: &[(&str, String)]) -> Hbbs {
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
        .arg(key)
        // Both streams into one file. `main` logs to **stdout**
        // (`Logger::log_to_stdout`), so nulling it — as this harness did until
        // T3.5 needed to assert on a log line — threw away every log hbbs
        // writes and left `log()` holding only the panic channel.
        .stdout(Stdio::from(
            std::fs::File::create(dir.path().join("hbbs.log")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::options()
                .append(true)
                .open(dir.path().join("hbbs.log"))
                .unwrap(),
        ));
    for a in extra {
        cmd.arg(a);
    }
    for (name, value) in extra_env {
        cmd.env(name, value);
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

/// Runs one runtime-console command and returns what hbbs printed.
///
/// The console rides on the **NAT-test port** (`port - 1`, `handle_listener2`)
/// and answers only a **loopback** peer — it is a plaintext command channel with
/// no authentication at all, and that is upstream's design, not ours. Write the
/// command, read the reply, done: no framing, no protobuf.
pub async fn console(port: u16, cmd: &str) -> String {
    use hbb_common::tokio::net::TcpStream;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port - 1))
        .await
        .expect("the console port was not listening");
    stream.write_all(cmd.as_bytes()).await.unwrap();
    let mut buffer = vec![0u8; 16 * 1024];
    let n = stream.read(&mut buffer).await.unwrap_or(0);
    String::from_utf8_lossy(&buffer[..n]).into_owned()
}

/// Spawns `hbbs` expecting it **not** to start, and returns what it printed.
///
/// Every config value that bounds a security check is validated before any port
/// binds, so "hbbs refused to start" is a designed outcome and needs asserting
/// like any other. Panics if it starts anyway — a server that boots on a
/// misconfigured security setting is the failure, not the timeout.
pub async fn hbbs_expect_exit(extra: &[String]) -> String {
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
        .stdout(Stdio::from(
            std::fs::File::create(dir.path().join("hbbs.log")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::options()
                .append(true)
                .open(dir.path().join("hbbs.log"))
                .unwrap(),
        ));
    for a in extra {
        cmd.arg(a);
    }
    let mut child = cmd.spawn().unwrap();
    for _ in 0..200 {
        if let Ok(Some(status)) = child.try_wait() {
            let log = std::fs::read_to_string(dir.path().join("hbbs.log")).unwrap_or_default();
            assert!(!status.success(), "hbbs exited cleanly instead of refusing:\n{log}");
            return log;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!(
        "hbbs started with a configuration it should have refused:\n{}",
        std::fs::read_to_string(dir.path().join("hbbs.log")).unwrap_or_default()
    );
}

/// Registers device B and keeps its UDP socket, which is where hbbs forwards.
///
/// Retries until `hbbs` answers. UDP to a process that has only just bound its
/// socket is silently dropped, and an unregistered peer fails the `ID_NOT_EXIST`
/// branch *before* the authorization check — so a lost datagram here does not
/// look like a lost datagram, it looks like this whole task not working.
/// `RegisterPk` is enough on its own: `PeerMap::update_pk` sets `last_reg_time`
/// (`src/peer.rs:108`), which is what the `OFFLINE` check reads.
pub async fn register(port: u16, id: &str) -> FramedSocket {
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

/// Sends one `RegisterPk` and returns what hbbs answered, or `None` if it said
/// nothing within `ms`.
///
/// Unlike `register`, this neither retries nor asserts on the result — T3.5.2's
/// whole subject is the answer itself, and `NOT_DEPLOYED` is a legitimate one.
/// The socket is handed back so a test can send a second registration on the
/// same one and watch a verdict change.
pub async fn register_pk_on(
    sock: &mut FramedSocket,
    port: u16,
    id: &str,
    uuid: &[u8],
    pk: &[u8],
    ms: u64,
) -> Option<register_pk_response::Result> {
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: uuid.to_vec().into(),
        pk: pk.to_vec().into(),
        ..Default::default()
    });
    sock.send(&msg, server).await.unwrap();
    let (bytes, _) = sock.next_timeout(ms).await?.ok()?;
    match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
        Some(rendezvous_message::Union::RegisterPkResponse(r)) => Some(r.result.enum_value().unwrap()),
        other => panic!("unexpected {other:?}"),
    }
}

/// Sends one `RegisterPeer` — the keepalive a settled client sends instead of
/// `RegisterPk` — and returns whether hbbs asked for the public key back.
///
/// `request_pk` is the only lever hbbs has on this path, and T3.5.4 uses it: it
/// is how a device that has stopped sending `RegisterPk` is walked back into the
/// arm where `NOT_DEPLOYED` lives.
pub async fn register_peer_on(
    sock: &mut FramedSocket,
    port: u16,
    id: &str,
    ms: u64,
) -> Option<bool> {
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_peer(RegisterPeer {
        id: id.to_owned(),
        ..Default::default()
    });
    sock.send(&msg, server).await.unwrap();
    let (bytes, _) = sock.next_timeout(ms).await?.ok()?;
    match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
        Some(rendezvous_message::Union::RegisterPeerResponse(r)) => Some(r.request_pk),
        other => panic!("unexpected {other:?}"),
    }
}

/// A fresh UDP socket to speak `RegisterPk` from.
pub async fn udp_socket() -> FramedSocket {
    FramedSocket::new("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap()
}

/// Sends one `PunchHoleRequest` and waits `ms` for a `PunchHoleResponse`.
///
/// `None` is the *allow* outcome: on an allow hbbs answers nobody and forwards
/// `PunchHole` / `FetchLocalAddr` to B instead, so A hears back only once B
/// replies. Every refusal, ours and upstream's, comes straight back on this
/// stream — which is what makes a denial visible to the user at all.
pub async fn punch(
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
    match next_plaintext(&mut stream, ms).await?.union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => Some(ph),
        other => panic!("unexpected {other:?}"),
    }
}

/// Reads one rendezvous message from a TCP connection, skipping the opening
/// `KeyExchange` (T3.4).
///
/// Every one of these tests is a hand-rolled client that never wanted a secure
/// channel, and since T3.4 `hbbs` offers one to every TCP connection before it
/// has read a byte. The real client tolerates exactly this, and by skipping
/// exactly one: `get_next_nonkeyexchange_msg`
/// (`apps/rustdesk/src/common.rs:1972-1993`) loops twice and `continue`s past a
/// `KeyExchange`. Mirrored here rather than worked around, so that these tests
/// keep testing what a real plaintext client sees.
pub async fn next_plaintext(stream: &mut FramedStream, ms: u64) -> Option<RendezvousMessage> {
    for _ in 0..2 {
        let bytes = stream.next_timeout(ms).await?.unwrap();
        let msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        match &msg.union {
            Some(rendezvous_message::Union::KeyExchange(_)) => continue,
            _ => return Some(msg),
        }
    }
    None
}

pub const REFUSAL_WAIT: u64 = 4_000;
/// How long to insist nothing came back on an allow. Short on purpose: this is
/// waited out on the happy path of several tests.
pub const ALLOW_WAIT: u64 = 800;

/// Sends one `RequestRelay` as A and waits `ms` for a `RelayResponse`.
///
/// `None` means hbbs forwarded it and said nothing to A, which is the allow
/// outcome. A refusal comes back here as `refuse_reason`, which the client
/// `bail!`s with verbatim.
pub async fn request_relay(
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
    match next_plaintext(&mut stream, ms).await?.union {
        Some(rendezvous_message::Union::RelayResponse(rs)) => Some(rs),
        other => panic!("unexpected {other:?}"),
    }
}

/// The `RequestRelay` hbbs forwarded to B, with the two fields that matter.
pub async fn relay_at_b(sock: &mut FramedSocket) -> RequestRelay {
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

pub async fn next_from_hbbs(sock: &mut FramedSocket) -> RendezvousMessage {
    let (bytes, _) = sock.next_timeout(4_000).await.expect("hbbs sent B nothing").unwrap();
    RendezvousMessage::parse_from_bytes(&bytes).unwrap()
}

pub fn auth_args(stub: &Stub) -> Vec<String> {
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

/// Turns registration ownership on (T3.5.2). Separate from `auth_args` because
/// the feature is: `AUTH_API_URL` alone must *not* enable it.
pub fn enrol_args() -> Vec<String> {
    vec!["--enrol-required".into(), "Y".into()]
}

/// An answer to `POST /api/internal/enrolled`. The stub answers on content, so a
/// test can hand back different verdicts for different device ids.
pub fn enrolled(yes: bool) -> String {
    if yes {
        r#"{"enrolled":true,"user_id":"user-t352"}"#.to_owned()
    } else {
        r#"{"enrolled":false,"reason":"no such device"}"#.to_owned()
    }
}

/// True when this captured request is the enrolment call rather than the
/// authorize one.
pub fn is_enrolment(request: &str) -> bool {
    request.contains("/api/internal/enrolled")
}

pub const ALLOW: &str = r#"{"allow":true,"conn_audit_ref":"ref-t33","permissions":6}"#;
pub const DENY: &str = r#"{"allow":false,"reason":"You do not have access to this device."}"#;

