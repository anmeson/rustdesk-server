//! A live session, from the controlled device's side — TASK.md T5.3.
//!
//! Everything so far stops when hbbs has brokered a connection. Revocation does
//! not live there: **`hbbs` cannot end a session and neither can `hbbr`**
//! (decision D2). `hbbr` only ever carries the relay fallback, so a relay-side
//! kill would miss every direct P2P session, and it pairs streams by an
//! ephemeral uuid it never tells anybody. The channel that works is the
//! controlled device's own heartbeat, which upstream already sends and already
//! obeys — `{"disconnect":[conn_id,…]}` closes the session
//! (`apps/rustdesk/src/server/connection.rs:949-955`).
//!
//! So a session is two things that must both happen or revocation silently
//! cannot find it:
//!
//!   1. **The join.** `POST /api/audit/conn` with `action: "new"` carrying the
//!      `conn_audit_ref` hbbs forwarded. That is what merges the decision row —
//!      which knows the *user* — with the audit row, which knows the *conn_id*.
//!      Without it there are two rows nothing joins, and the session is
//!      `unattributed`: still killable by an explicit revoke, deliberately, but
//!      invisible to the unattended sweep.
//!   2. **The beat.** `POST /api/heartbeat` with `conns: [conn_id]`, every 3 s
//!      while a session is live (`TIME_CONN`, `sync.rs:18-20`). It is both how
//!      the instruction arrives and, because `enforceLiveSessionAccess` runs on
//!      it, the timer that notices an expiry nobody acted on.
//!
//! This models that side faithfully, at the real cadence, because the cadence is
//! the number T5.3 is asked to measure.

use std::time::{Duration, Instant};

use hbb_common::tokio::time::sleep;
use serde_json::{json, Value};

use super::{api::ClientApi, peer::Brokerage};

/// The real cadence while a session is live. Not a tunable: it is what bounds
/// how long a revoked user keeps looking at the screen, so a test that used a
/// faster one would be measuring a system nobody runs.
pub const BEAT: Duration = Duration::from_millis(3_000);

pub struct Session {
    pub device_id: String,
    pub device_uuid: String,
    pub conn_id: i64,
    /// Whether the decision row was actually joined to this session. `false`
    /// means the session is unattributed — worth asserting on rather than
    /// discovering later as a revocation that found nothing.
    pub attributed: bool,
    /// Other connections this device is holding at the same time.
    ///
    /// A real device reports **all** of its live connections in one heartbeat,
    /// and the api reads that list as the truth about what is running
    /// (`activeConnIds`, which `liveSessionsFor` consults for connections with
    /// no row of their own). Two `Session`s each beating only their own id would
    /// therefore take turns telling the api the other one had ended — and a test
    /// about collateral damage would be built on a device that never reports
    /// both at once.
    pub also_live: Vec<i64>,
    beats: u32,
}

/// One heartbeat's answer.
#[derive(Debug, Default, Clone)]
pub struct Beat {
    pub disconnect: Vec<i64>,
}

impl Session {
    /// Opens a session on the device, announcing it the way the client does.
    ///
    /// `conn_id` is the device's own counter for the connection; upstream assigns
    /// it and the console never sees another handle for a live session.
    pub async fn open(
        client: &ClientApi,
        device_id: &str,
        device_uuid: &str,
        conn_id: i64,
        brokerage: &Brokerage,
    ) -> Session {
        let reference = brokerage
            .conn_audit_ref
            .clone()
            .expect("a session cannot be opened from a brokerage with no conn_audit_ref");
        client
            .audit_conn(json!({
                "id": device_id,
                "uuid": device_uuid,
                "conn_id": conn_id,
                // 0 on the pre-auth record, as the client sends it: authentication
                // has not happened yet at this point in `connection.rs`.
                "session_id": 0,
                "nonce": format!("nonce-{device_id}-{conn_id}"),
                "action": "new",
                "ip": "127.0.0.1",
                "conn_audit_ref": reference,
            }))
            .await;

        let mut session = Session {
            device_id: device_id.to_owned(),
            device_uuid: device_uuid.to_owned(),
            conn_id,
            attributed: false,
            also_live: Vec::new(),
            beats: 0,
        };
        // One beat, so the device is on record as holding this connection before
        // anyone asks whether it should. `activeConnIds` is what
        // `liveSessionsFor` reads for connections with no row of their own.
        session.beat(client).await;
        session
    }

    /// One heartbeat, and whatever came back.
    pub async fn beat(&mut self, client: &ClientApi) -> Beat {
        self.beats += 1;
        let mut conns = vec![self.conn_id];
        conns.extend(self.also_live.iter().copied());
        let answer: Value = client
            .heartbeat(json!({
                "id": self.device_id,
                "uuid": self.device_uuid,
                "ver": 1,
                "conns": conns,
            }))
            .await;
        Beat {
            disconnect: answer["disconnect"]
                .as_array()
                .map(|ids| ids.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default(),
        }
    }

    /// Beats at the real cadence until this session is told to close, and
    /// returns how long that took.
    ///
    /// The measurement T5.3 asks for is wall-clock from the revoke to the
    /// instruction arriving, and its floor is one beat — so a result near 3 s is
    /// the system working, and one near zero would mean the harness is beating
    /// faster than a client does.
    pub async fn wait_for_disconnect(
        &mut self,
        client: &ClientApi,
        within: Duration,
    ) -> Option<Duration> {
        let started = Instant::now();
        while started.elapsed() < within {
            sleep(BEAT).await;
            if self.beat(client).await.disconnect.contains(&self.conn_id) {
                return Some(started.elapsed());
            }
        }
        None
    }

    /// Insists the session is *not* told to close, for as long as `patience`.
    ///
    /// The other half of every revocation test, and the one that catches a
    /// fail-closed sweep: `enforceLiveSessionAccess` runs unattended every three
    /// seconds against every live session in the fleet, so a mistake there does
    /// not disconnect one person, it disconnects everybody.
    pub async fn assert_undisturbed(&mut self, client: &ClientApi, patience: Duration) {
        let started = Instant::now();
        while started.elapsed() < patience {
            sleep(BEAT).await;
            let beat = self.beat(client).await;
            assert!(
                beat.disconnect.is_empty(),
                "session {} on {} was told to close after {:?}: {:?}",
                self.conn_id,
                self.device_id,
                started.elapsed(),
                beat.disconnect
            );
        }
    }

    /// What the device posts when the session ends.
    pub async fn close(&self, client: &ClientApi) {
        client
            .audit_conn(json!({
                "id": self.device_id,
                "conn_id": self.conn_id,
                "nonce": format!("nonce-close-{}-{}", self.device_id, self.conn_id),
                "action": "close",
            }))
            .await;
    }
}

/// Distinct `conn_id`s within a test run. Upstream's are per-device counters;
/// what matters here is only that two sessions on one device differ.
pub fn next_conn_id() -> i64 {
    use std::sync::atomic::{AtomicI64, Ordering};
    static NEXT: AtomicI64 = AtomicI64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst)
}
