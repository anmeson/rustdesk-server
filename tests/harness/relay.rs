//! The real `hbbr`, and a peer's side of it — TASK.md T5.1.
//!
//! Milestone 3 never needed this: its tests stop at the point hbbs has decided,
//! because that is where hbbs's job ends. Milestone 5 cannot, for two reasons
//! the task board is explicit about. T5.7 has to *prove* that `hbbr` authorizes
//! nothing — that the relay UUID is the only thing standing between a stranger
//! and somebody's session — and a claim like that is worth nothing against a
//! simulated relay. And T5.10 re-runs the whole matrix with `ALWAYS_USE_RELAY`,
//! where the relay is the only path there is.
//!
//! `hbbr` is unmodified and stays that way (CLAUDE.md non-negotiables), so
//! everything here is upstream behaviour: it reads one `RequestRelay`, compares
//! the licence key if it has one, and then either parks the stream under
//! `rf.uuid` for 30 s or splices it to whoever is already parked there
//! (`src/relay_server.rs:461-498`). No user, no device, no session.
//!
//! **A peer cannot relay over loopback, and this is the thing to know before
//! writing a test here.** `handle_connection` (`src/relay_server.rs:386-393`)
//! reads *every* non-websocket connection whose peer address is loopback as a
//! runtime-console command: one read, one answer, close. There is no relay path
//! for 127.0.0.1 at all, so a harness that connects to `127.0.0.1:<relay port>`
//! is silently talking to the console — no error, no log line, and a session
//! that pairs with nobody. So these peers reach `hbbr` on the host's own LAN
//! address, which is also what `scripts/local-server.sh` hands clients and why
//! it defaults `RELAY_HOST` to the LAN IP rather than to localhost.

use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::Duration,
};

use hbb_common::{
    bytes::Bytes,
    rendezvous_proto::*,
    tcp::FramedStream,
    tokio::time::sleep,
};

use super::{free_port_block, TempDir};

pub struct Hbbr {
    child: Child,
    pub port: u16,
    /// The address peers reach it on — never loopback; see the module note.
    pub host: String,
    _dir: TempDir,
}

impl Hbbr {
    pub fn log(&self) -> String {
        std::fs::read_to_string(self._dir.path().join("hbbr.log")).unwrap_or_default()
    }

    pub async fn wait_for_log(&self, needle: &str, ms: u64) -> bool {
        for _ in 0..(ms / 50).max(1) {
            if self.log().contains(needle) {
                return true;
            }
            sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// What hbbs should hand clients as the relay server.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Drop for Hbbr {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawns `hbbr` with an explicit key.
///
/// **The key is not optional and the harness will not let it be.** `hbbr`
/// generates one for `-`/`_` but not for an empty string, and its comparison is
/// `if !key.is_empty() && …` (`relay_server.rs:466`, `:613`) — so an `hbbr`
/// started without `-k` relays for anybody who asks. That is a real deployment
/// trap (docs/CONTEXT.md §7), and a test that reproduced it by accident would be
/// testing a server nobody should run. T5.7 asks for it deliberately, through
/// `hbbr_with_key("")`.
pub async fn hbbr(key: &str) -> Hbbr {
    // hbbr binds `p` and `p + 2` (websocket). The four-port block hbbs uses
    // covers both, so the same allocator serves — and, more to the point, keeps
    // hbbs and hbbr from ever drawing overlapping blocks.
    hbbr_on(free_port_block(), key).await
}

/// `hbbr` on a port chosen by the caller.
///
/// A world needs this: hbbs takes the relay address as a boot argument, and
/// hbbs has to be running before hbbr can be given its key — so the port is
/// allocated before either of them starts.
pub async fn hbbr_on(port: u16, key: &str) -> Hbbr {
    let dir = TempDir::new();
    let bin = std::env::current_dir().unwrap().join("target/debug/hbbr");
    assert!(
        bin.exists(),
        "target/debug/hbbr is missing — run `cargo build --bins` first"
    );
    let log = dir.path().join("hbbr.log");
    let mut cmd = Command::new(bin);
    cmd.current_dir(dir.path())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("-k")
        .arg(key)
        // Both streams into one file, for the same reason hbbs gets it: `main`
        // logs to stdout, so nulling it throws away every line hbbr writes.
        .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
        .stderr(Stdio::from(
            std::fs::File::options().append(true).open(&log).unwrap(),
        ));

    let mut relay = Hbbr {
        child: cmd.spawn().unwrap(),
        port,
        host: relay_host(),
        _dir: dir,
    };

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
        if let Ok(Some(status)) = relay.child.try_wait() {
            panic!("hbbr exited during startup: {status} (port {port})\n{}", relay.log());
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "hbbr never accepted TCP on {port}\n{}", relay.log());
    relay
}

/// This host's own non-loopback IPv4 address.
///
/// Required, not preferred: a loopback peer reaches `hbbr`'s console instead of
/// its relay (see the module note). Cached, because it is asked for once per
/// world and the lookup walks every interface.
pub fn relay_host() -> String {
    static HOST: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
        match local_ip_address::local_ip() {
            Ok(std::net::IpAddr::V4(ip)) if !ip.is_loopback() => ip.to_string(),
            other => panic!(
                "these tests need a non-loopback IPv4 address on this host, and found {other:?}. \
                 hbbr answers every loopback connection with its runtime console instead of \
                 relaying (src/relay_server.rs:386), so a relay cannot be tested over 127.0.0.1."
            ),
        }
    });
    HOST.clone()
}

/// One end of a relay session: a stream `hbbr` will splice to whoever else
/// presents the same uuid.
///
/// `addr` is a full `host:port` and must not be loopback — see the module note.
/// Taking the whole address rather than a port is deliberate: it is the string
/// hbbs forwarded to the device, so the device joins exactly where A was told
/// to, and a mistake shows up as a refusal rather than as a silent console
/// conversation.
///
/// Both ends must reach `set_raw`. `hbbr` switches both sockets to raw the
/// moment it pairs them (`make_pair_`, `:483-486`), so a side still framing its
/// payloads would be writing a length prefix the other side reads as data —
/// which looks like corruption rather than like a protocol mistake.
pub async fn relay_join(addr: &str, uuid: &str, key: &str) -> FramedStream {
    let mut stream = FramedStream::new(addr.to_owned(), None, 3_000)
        .await
        .unwrap_or_else(|err| panic!("could not reach hbbr at {addr}: {err}"));
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        uuid: uuid.to_owned(),
        licence_key: key.to_owned(),
        ..Default::default()
    });
    stream.send(&msg).await.unwrap();
    stream.set_raw();
    stream
}

/// Sends `payload` and asserts it arrives at `other`, byte for byte.
///
/// The point of asserting on the bytes rather than on "hbbr said paired" is that
/// pairing is a log line and relaying is the product. A relay that pairs and
/// then drops everything is exactly what a half-applied patch would produce.
pub async fn assert_relays(
    from: &mut FramedStream,
    to: &mut FramedStream,
    payload: &[u8],
    ms: u64,
) {
    from.send_bytes(Bytes::copy_from_slice(payload)).await.unwrap();
    let got = to
        .next_timeout(ms)
        .await
        .unwrap_or_else(|| panic!("nothing came through the relay within {ms} ms"))
        .expect("relay stream errored");
    assert_eq!(&got[..], payload, "the relay changed the bytes");
}
