//! The brokerage ledger — TASK.md T3.8.
//!
//! Three messages travel from a *controlled* device back to a waiting
//! *controller*: `PunchHoleSent`, `LocalAddr`, and `RelayResponse`. Upstream
//! routes all three purely on a `socket_addr` the **sender** supplies and checks
//! nothing about who sent it, so a stranger who knows a waiting controller's
//! address as hbbs sees it can answer in the real peer's place — choosing the
//! address, the relay server, and (via the id) which peer key hbbs looks up.
//! Demonstrated against the running binaries in T3.3b, not read from the source.
//!
//! **This is upstream's flaw, not one our patches introduced**, and it is
//! present in every RustDesk deployment. It is also not an authorization
//! bypass: none of these three messages ever reaches a controlled device, so
//! T3.3 and T3.3b's boundary is intact. What it defeats is the client's
//! *identity* check, which is worse than it sounds — see `id` below.
//!
//! The fix is a ledger. When hbbs brokers A → B it writes down
//! `A_addr → (B's id, B's registered ip)` with a short TTL, and a response
//! addressed to A must agree with that record before it is forwarded.
//!
//! # Two layers, and only one of them is safe to switch on by default
//!
//! **The id.** Always enforced. A response must name the exact peer hbbs
//! brokered to that controller. This is the layer that matters most, and not
//! because an attacker minds naming the right id: naming an id hbbs has *never
//! heard of* makes `get_pk` return nothing, and the client treats an absent peer
//! key as "no identity to verify" and connects anyway
//! (`apps/rustdesk/src/client.rs:1624-1634`). So the cheapest attack skips the
//! signature check entirely. Forcing the real id forces the real public key into
//! the response, which puts the client back on its own verification path. The
//! check compares two strings and is blind to address family, so it cannot
//! break anybody.
//!
//! **The ip.** `BROKER_STRICT_IP`, and it ships **off**. This is the stronger
//! check — with it, a stranger must also be on the peer's address — and it is
//! the one that can take a fleet offline, because the address B registers from
//! and the address B answers from are only *usually* the same:
//!
//!   - B registers over **UDP** and answers over a **new TCP connection**
//!     (`apps/rustdesk/src/rendezvous_mediator.rs:627`, `:717`, `:995`), so the
//!     port always differs and only the ip can be matched at all;
//!   - a dual-stack peer can register over IPv4 and answer over IPv6, and then
//!     the two addresses have nothing in common to compare;
//!   - carrier-grade NAT hands different flows different public addresses from a
//!     pool.
//!
//! The symptom of getting that wrong is "nobody can connect", which is the
//! failure TASK.md warns about in bold — so the layer is implemented, off by
//! default, and **every mismatch is logged even when it is not enforced**. That
//! last part is the point: an operator can read their own logs and find out
//! whether their fleet would survive `BROKER_STRICT_IP=Y` before switching it
//! on, instead of finding out from their users.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hbb_common::{log, ResultType};

use crate::common::get_arg_opt;

const KEY_VERIFY: &str = "BROKER_VERIFY";
const KEY_STRICT_IP: &str = "BROKER_STRICT_IP";

/// How long a brokerage stays answerable.
///
/// Has to outlive the whole legitimate exchange: the controller punches up to
/// three times with widening deadlines — `'punch_attempts: for i in 1..=3` at
/// `apps/rustdesk/src/client.rs:913`, roughly 3 s + 6 s + 9 s — and may then
/// fall back to the relay. Sixty seconds covers that with room to spare while
/// keeping the window a stranger could aim at short. The relay fallback arrives
/// on its own TCP connection and so writes its own record; it does not lean on
/// this one lasting.
const TTL: Duration = Duration::from_secs(60);

/// Ceiling on live brokerages, so that a flood of punch requests costs bounded
/// memory. At the 60 s TTL this is ~800 brokered connections per second before
/// it binds, far past what a rendezvous server does.
const CAPACITY: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerConfig {
    /// Master switch. On by default — this closes an upstream hole rather than
    /// enabling one of our features, so it is not tied to `AUTH_REQUIRED`.
    pub verify: bool,
    /// Also require the responder's ip to match the peer's registered ip.
    /// **Ships off.** See the module docs.
    pub strict_ip: bool,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            verify: true,
            strict_ip: false,
        }
    }
}

impl BrokerConfig {
    pub fn from_args() -> ResultType<Self> {
        Ok(Self::from_lookup(|name| get_arg_opt(name)))
    }

    /// Lookup passed in so the parsing can be tested without mutating the
    /// process environment, which is global and would race the parallel runner.
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let defaults = Self::default();
        Self {
            verify: flag(&get, KEY_VERIFY).unwrap_or(defaults.verify),
            strict_ip: flag(&get, KEY_STRICT_IP).unwrap_or(defaults.strict_ip),
        }
    }

    pub fn log(&self) {
        if !self.verify {
            log::warn!(
                "{KEY_VERIFY}=N — a stranger who knows a waiting controller's address can answer \
                 in a peer's place, choosing the address and relay server it connects to. \
                 See TASK.md T3.8."
            );
            return;
        }
        log::info!("{KEY_VERIFY}=Y {KEY_STRICT_IP}={}", yn(self.strict_ip));
    }
}

/// `Y`/`N`, matching `ALWAYS_USE_RELAY` and the `AUTH_*` keys. `None` when
/// unset, so "not configured" is distinguishable from "configured off".
fn flag(get: &impl Fn(&str) -> Option<String>, name: &str) -> Option<bool> {
    let value = get(name)?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.eq_ignore_ascii_case("y") || value.eq_ignore_ascii_case("yes") || value == "1")
}

fn yn(value: bool) -> &'static str {
    if value {
        "Y"
    } else {
        "N"
    }
}

/// What hbbs wrote down when it introduced a controller to a peer.
#[derive(Debug, Clone)]
struct Brokerage {
    peer_id: String,
    peer_ip: IpAddr,
    expires_at: Instant,
}

/// What to do with a response addressed to a waiting controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Forward,
    /// Dropped in silence: forwarding is the whole of what the sender wanted,
    /// and the controller's own timeout already covers "nobody answered". The
    /// reason is for the log.
    Drop(&'static str),
}

impl Verdict {
    pub fn is_forward(self) -> bool {
        matches!(self, Self::Forward)
    }
}

/// The ledger itself. One per process, shared — like the decision cache, it is
/// worthless per-clone.
pub struct BrokerLedger {
    config: BrokerConfig,
    entries: Mutex<HashMap<SocketAddr, Brokerage>>,
}

impl BrokerLedger {
    pub fn new(config: BrokerConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.verify
    }

    pub fn strict_ip(&self) -> bool {
        self.config.strict_ip
    }

    /// Live brokerages, for T3.7's runtime console counter.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        match self.entries.lock() {
            Ok(entries) => entries.values().filter(|e| e.expires_at > now).count(),
            Err(_) => 0,
        }
    }

    /// hbbs is about to introduce the controller at `waiting` to `peer_id`.
    ///
    /// `waiting` **must** be normalised with `try_into_v4` by the caller, the
    /// same way `tcp_punch` keys its sinks: the response comes back through
    /// `AddrMangle`, and an IPv4-mapped IPv6 address that round-trips as V6
    /// would otherwise miss a record stored as V4 and be dropped.
    pub fn record(&self, waiting: SocketAddr, peer_id: &str, peer_ip: IpAddr) {
        if !self.config.verify {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let now = Instant::now();
        if entries.len() >= CAPACITY {
            entries.retain(|_, e| e.expires_at > now);
        }
        // Declining to record would silently start dropping legitimate
        // responses, so a full ledger sheds the *check*, not the connection:
        // `verify` still holds for everyone whose record did fit.
        if entries.len() >= CAPACITY {
            log::warn!("brokerage ledger is full ({CAPACITY}); {peer_id} will not be verifiable");
            return;
        }
        entries.insert(
            waiting,
            Brokerage {
                peer_id: peer_id.to_owned(),
                peer_ip,
                expires_at: now + TTL,
            },
        );
    }

    /// May this response be forwarded to the controller waiting at `waiting`?
    ///
    /// `claimed_id` is the id the responder put on the message. It is empty on
    /// exactly one legitimate message — the relay-fallback `RelayResponse`,
    /// which `create_relay` sends with `initiate = false` and therefore without
    /// an id, uuid or relay server (`rendezvous_mediator.rs:579-604`). That one
    /// is a bare ack that steers the controller nowhere: A keeps its own uuid
    /// and relay server and only learns that somebody answered
    /// (`apps/rustdesk/src/client.rs:1750-1760`). So an absent id is accepted,
    /// and the brokerage still has to exist.
    ///
    /// `responder_ip` should also be `try_into_v4`-normalised, so that a peer
    /// registering as `127.0.0.1` and answering as `::ffff:127.0.0.1` compares
    /// equal rather than merely looking equal in a log line.
    pub fn check(
        &self,
        waiting: SocketAddr,
        claimed_id: &str,
        responder_ip: IpAddr,
    ) -> Verdict {
        if !self.config.verify {
            return Verdict::Forward;
        }
        let Ok(mut entries) = self.entries.lock() else {
            // A poisoned lock is a bug in this process, not a hostile peer.
            // Forwarding keeps connections working; the alternative is a server
            // that brokers nothing until it restarts.
            return Verdict::Forward;
        };
        let now = Instant::now();
        let Some(entry) = entries.get(&waiting) else {
            return Verdict::Drop("no brokerage for that controller");
        };
        if entry.expires_at <= now {
            entries.remove(&waiting);
            return Verdict::Drop("the brokerage expired");
        }
        if !claimed_id.is_empty() && claimed_id != entry.peer_id {
            log::warn!(
                "dropped a response to {waiting} claiming to be {claimed_id:?}: \
                 hbbs brokered {:?}",
                entry.peer_id
            );
            return Verdict::Drop("the responder named a peer hbbs did not broker");
        }
        if responder_ip != entry.peer_ip {
            // Logged whether or not it is enforced — this is the line an
            // operator reads to find out if `BROKER_STRICT_IP=Y` is safe for
            // their fleet before they switch it on.
            log::warn!(
                "{} answered for {} from {responder_ip}, but registered from {} \
                 ({KEY_STRICT_IP}={})",
                entry.peer_id,
                waiting,
                entry.peer_ip,
                yn(self.config.strict_ip),
            );
            if self.config.strict_ip {
                return Verdict::Drop("the responder is not at the peer's registered address");
            }
        }
        Verdict::Forward
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: Map<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ledger(strict_ip: bool) -> BrokerLedger {
        BrokerLedger::new(BrokerConfig {
            verify: true,
            strict_ip,
        })
    }

    #[test]
    fn verification_is_on_and_the_ip_layer_is_off_by_default() {
        let config = BrokerConfig::from_lookup(lookup(&[]));
        assert!(config.verify);
        assert!(!config.strict_ip, "the ip layer must not ship on — see the module docs");
    }

    #[test]
    fn both_layers_are_switchable() {
        let config = BrokerConfig::from_lookup(lookup(&[(KEY_STRICT_IP, "Y")]));
        assert!(config.verify);
        assert!(config.strict_ip);

        let config = BrokerConfig::from_lookup(lookup(&[(KEY_VERIFY, "N")]));
        assert!(!config.verify);
    }

    #[test]
    fn the_peer_we_brokered_is_forwarded() {
        let l = ledger(false);
        l.record(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9"));
        assert_eq!(
            l.check(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9")),
            Verdict::Forward
        );
    }

    #[test]
    fn a_stranger_naming_another_id_is_dropped() {
        let l = ledger(false);
        l.record(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9"));
        // The cheap attack: an id hbbs never heard of, so `get_pk` returns
        // nothing and the client skips verification altogether.
        assert!(!l
            .check(addr("10.0.0.1:5000"), "not-a-device", ip("10.0.0.9"))
            .is_forward());
    }

    #[test]
    fn a_response_to_a_controller_we_never_brokered_is_dropped() {
        let l = ledger(false);
        assert!(!l.check(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9")).is_forward());
    }

    #[test]
    fn the_relay_fallback_ack_carries_no_id_and_is_still_forwarded() {
        // `create_relay(initiate = false)` sends a `RelayResponse` with no id,
        // no uuid and no relay server. Requiring an id here would break every
        // relayed session.
        let l = ledger(false);
        l.record(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9"));
        assert_eq!(
            l.check(addr("10.0.0.1:5000"), "", ip("10.0.0.9")),
            Verdict::Forward
        );
    }

    #[test]
    fn a_different_ip_is_forwarded_unless_the_ip_layer_is_on() {
        let l = ledger(false);
        l.record(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9"));
        // The dual-stack / CGNAT case. Logged, not dropped.
        assert_eq!(
            l.check(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.77")),
            Verdict::Forward
        );

        let l = ledger(true);
        l.record(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9"));
        assert!(!l
            .check(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.77"))
            .is_forward());
        // …and the real peer still gets through with it on.
        assert_eq!(
            l.check(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9")),
            Verdict::Forward
        );
    }

    #[test]
    fn with_verification_off_nothing_is_recorded_and_everything_is_forwarded() {
        let l = BrokerLedger::new(BrokerConfig {
            verify: false,
            strict_ip: false,
        });
        l.record(addr("10.0.0.1:5000"), "dev-a", ip("10.0.0.9"));
        assert_eq!(l.len(), 0);
        assert_eq!(
            l.check(addr("10.0.0.1:5000"), "anything", ip("1.2.3.4")),
            Verdict::Forward
        );
    }

    #[test]
    fn an_expired_brokerage_stops_answering() {
        let l = ledger(false);
        let waiting = addr("10.0.0.1:5000");
        l.record(waiting, "dev-a", ip("10.0.0.9"));
        // Reach in rather than sleep for a minute.
        l.entries
            .lock()
            .unwrap()
            .get_mut(&waiting)
            .unwrap()
            .expires_at = Instant::now() - Duration::from_secs(1);
        assert!(!l.check(waiting, "dev-a", ip("10.0.0.9")).is_forward());
        assert_eq!(l.len(), 0, "the expired entry should have been swept");
    }
}
