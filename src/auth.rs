//! Connection authorization. TASK.md T3.1 (configuration) and T3.2 (the call).
//!
//! This module is the whole of our footprint outside `rendezvous_server.rs`,
//! and it stays that way on purpose: `rendezvous_server.rs` changes in most
//! upstream releases and carries all of our merge risk, so everything that can
//! live beside it rather than inside it does. The HTTP client and the decision
//! cache are here (T3.2); T3.3 adds the ~15 lines that call them.
//!
//! Every value is read through the existing `get_arg` mechanism
//! (`common.rs:150-185`), which already resolves, in order: a CLI flag, an
//! entry in `.env`, an entry in `--config <file>`, and a real environment
//! variable — in `AUTH_API_URL`, `AUTH-API-URL` or lowercase form. So no new
//! plumbing is added, and an operator can use whichever of those four they
//! already use for `--key` and `ALWAYS_USE_RELAY`.
//!
//! **Decision D1: hbbs fails closed.** Two consequences show up here rather
//! than at the connect path, because a boot-time refusal is a message someone
//! reads and a connect-time failure is a fleet that quietly cannot connect:
//!
//!   - asking for authorization without saying where to get it is a hard error,
//!     not a silent allow-all;
//!   - `AUTH_FAIL_OPEN` exists, ships `N`, and is unsupported. It is honoured so
//!     that an operator in an outage has a documented lever rather than a patched
//!     binary, but it warns on every boot, because a bypass nobody remembers
//!     enabling is exactly the failure D1 exists to prevent.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hbb_common::{bail, log, protobuf::EnumOrUnknown, rendezvous_proto::ConnType, ResultType};
use sodiumoxide::crypto::hash::sha256;

use crate::breakglass::{self, Breakglass, BreakglassConfig, Outcome};
use crate::common::get_arg_opt;

/// A human is waiting on this for every connection — T3.2's latency budget.
pub const DEFAULT_TIMEOUT_MS: u64 = 300;

/// How long a positive decision may be reused.
///
/// This is the one knob that trades latency against how quickly a revocation
/// stops *new* connections: within this window a user whose grant was just
/// revoked can still open one. Sessions already running are not affected — those
/// are decision D2's heartbeat channel, which is immediate and independent of
/// this. Five seconds keeps the common case (a client retrying a handshake) off
/// the api server without making revocation feel broken.
pub const DEFAULT_CACHE_TTL_MS: u64 = 5_000;

const KEY_API_URL: &str = "AUTH_API_URL";
const KEY_API_SECRET: &str = "AUTH_API_SECRET";
const KEY_REQUIRED: &str = "AUTH_REQUIRED";
const KEY_FAIL_OPEN: &str = "AUTH_FAIL_OPEN";
const KEY_TIMEOUT_MS: &str = "AUTH_TIMEOUT_MS";
const KEY_CACHE_TTL_MS: &str = "AUTH_CACHE_TTL_MS";

/// The licence key, so the shared secret can be checked against it. Not ours.
const KEY_RUSTDESK_KEY: &str = "key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// Base URL of `apps/api`, with no trailing slash. Empty when disabled.
    pub api_url: String,
    /// Sent as `x-hbbs-secret`. Must differ from the RustDesk licence key.
    pub api_secret: String,
    /// Whether a connection must be authorized before it is brokered.
    pub required: bool,
    /// Allow the connection when the api server cannot be reached. Unsupported.
    pub fail_open: bool,
    pub timeout: Duration,
    pub cache_ttl: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            api_url: String::new(),
            api_secret: String::new(),
            required: false,
            fail_open: false,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            cache_ttl: Duration::from_millis(DEFAULT_CACHE_TTL_MS),
        }
    }
}

impl AuthConfig {
    /// Reads the configuration from flags, `.env`, and the environment.
    pub fn from_args() -> ResultType<Self> {
        Self::from_lookup(|name| get_arg_opt(name))
    }

    /// The parsing and validation, with the lookup passed in so it can be tested
    /// without mutating the process environment — which is global, and would
    /// make these tests race each other under the default parallel runner.
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> ResultType<Self> {
        let api_url = trimmed(&get, KEY_API_URL);
        // A trailing slash would produce `…//api/internal/authorize`, which some
        // reverse proxies answer with a redirect that a POST does not follow.
        let api_url = api_url.trim_end_matches('/').to_owned();
        let api_secret = trimmed(&get, KEY_API_SECRET);

        // Configuring the endpoint is what turns authorization on. There is
        // deliberately no second switch to forget: an operator who sets
        // AUTH_API_URL and nothing else gets enforcement, not a server that
        // quietly brokers every connection while looking configured.
        let required = match flag(&get, KEY_REQUIRED) {
            Some(value) => value,
            None => !api_url.is_empty(),
        };
        let fail_open = flag(&get, KEY_FAIL_OPEN).unwrap_or(false);

        let timeout = Duration::from_millis(millis(&get, KEY_TIMEOUT_MS, DEFAULT_TIMEOUT_MS)?);
        let cache_ttl =
            Duration::from_millis(millis(&get, KEY_CACHE_TTL_MS, DEFAULT_CACHE_TTL_MS)?);

        let config = Self {
            api_url,
            api_secret,
            required,
            fail_open,
            timeout,
            cache_ttl,
        };
        config.validate(&get)?;
        Ok(config)
    }

    fn validate(&self, get: &impl Fn(&str) -> Option<String>) -> ResultType<()> {
        if !self.required {
            return Ok(());
        }
        if self.api_url.is_empty() {
            bail!(
                "{KEY_REQUIRED} is on but {KEY_API_URL} is not set. \
                 hbbs would have to deny every connection. \
                 Set {KEY_API_URL} to the api server, or set {KEY_REQUIRED}=N to broker without authorization."
            );
        }
        if !(self.api_url.starts_with("http://") || self.api_url.starts_with("https://")) {
            bail!("{KEY_API_URL} must start with http:// or https://, got {:?}", self.api_url);
        }
        if self.api_secret.is_empty() {
            bail!(
                "{KEY_REQUIRED} is on but {KEY_API_SECRET} is not set. \
                 The api server rejects an unauthenticated call, so every connection would be denied."
            );
        }

        // The api server's own contract: the shared secret must differ from the
        // licence key, because the licence key is distributed to every client.
        // Reusing it would let any client call the endpoint that decides
        // authorization for everyone.
        let licence_key = get(KEY_RUSTDESK_KEY).unwrap_or_default();
        let licence_key = licence_key.trim();
        if !licence_key.is_empty() && licence_key != "-" && licence_key == self.api_secret {
            bail!(
                "{KEY_API_SECRET} must not be the same as the RustDesk key (-k/--key). \
                 Every client is given that key, so sharing it would let any client authorize itself."
            );
        }
        Ok(())
    }

    /// Writes the resolved settings to the log, secret redacted, in the same
    /// shape `ALWAYS_USE_RELAY` and the other options use. Worth doing on every
    /// boot: "which of the four config sources won" is the question an operator
    /// actually has, and the answer is only visible here.
    pub fn log(&self) {
        if !self.required {
            log::info!("{KEY_REQUIRED}=N, connections are brokered without authorization");
            return;
        }
        log::info!(
            "{KEY_REQUIRED}=Y {KEY_API_URL}={} {KEY_API_SECRET}={} {KEY_TIMEOUT_MS}={} {KEY_CACHE_TTL_MS}={}",
            self.api_url,
            redact(&self.api_secret),
            self.timeout.as_millis(),
            self.cache_ttl.as_millis(),
        );
        if self.fail_open {
            log::warn!(
                "{KEY_FAIL_OPEN}=Y — UNSUPPORTED. Any connection will be brokered whenever the \
                 api server is unreachable, which defeats access control at exactly the moment \
                 it is most likely to matter. See docs/PLAN.md decision D1."
            );
        }
        if self.api_url.starts_with("http://") && !is_loopback(&self.api_url) {
            log::warn!(
                "{KEY_API_URL} is plain http to a non-loopback host — {KEY_API_SECRET} and every \
                 user token cross the network in cleartext. Use https, or keep the api server on \
                 this host."
            );
        }
    }
}

fn trimmed(get: &impl Fn(&str) -> Option<String>, name: &str) -> String {
    get(name).unwrap_or_default().trim().to_owned()
}

/// `Y`/`N`, matching `ALWAYS_USE_RELAY` (`rendezvous_server.rs:169`). `None`
/// when unset, so a caller can tell "not configured" from "configured off".
fn flag(get: &impl Fn(&str) -> Option<String>, name: &str) -> Option<bool> {
    let value = get(name)?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.eq_ignore_ascii_case("y") || value.eq_ignore_ascii_case("yes") || value == "1")
}

/// Unlike `rmem` and `serial`, a bad value here is refused rather than silently
/// replaced with the default: these bound a security check, and a typo that
/// quietly restores stock behaviour is the kind of thing nobody finds until it
/// matters.
fn millis(get: &impl Fn(&str) -> Option<String>, name: &str, default: u64) -> ResultType<u64> {
    let raw = trimmed(get, name);
    if raw.is_empty() {
        return Ok(default);
    }
    match raw.parse::<u64>() {
        Ok(0) => bail!("{name} must be greater than 0"),
        Ok(value) => Ok(value),
        Err(_) => bail!("{name} must be a whole number of milliseconds, got {raw:?}"),
    }
}

fn redact(secret: &str) -> String {
    if secret.is_empty() {
        "<unset>".to_owned()
    } else {
        format!("<{} chars>", secret.len())
    }
}

fn is_loopback(url: &str) -> bool {
    let host = url.trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// ---------------------------------------------------------------------------
// The call, and the cache — TASK.md T3.2
// ---------------------------------------------------------------------------

/// `POST` target on the api server. `apps/api/src/routes/internal/authorize.ts`.
const AUTHORIZE_PATH: &str = "/api/internal/authorize";

/// The api server authenticates hbbs with this header, not with a bearer token.
const SECRET_HEADER: &str = "x-hbbs-secret";

/// Shown to the user when no decision could be obtained at all. Every one of
/// these is an operator problem, so it says "try again" rather than naming a
/// cause the user cannot act on — the detail goes to the log, where somebody
/// can do something about it.
const UNAVAILABLE_REASON: &str = "The access server is unavailable. Please try again in a moment.";

/// Mirrors the empty-token branch of `services/authorize.ts`. See `authorize`
/// below for why hbbs answers this one itself.
const NO_TOKEN_REASON: &str = "Please sign in to connect to this device.";

/// Only reached when the api server denies without saying why, which its own
/// contract says it never does. Deliberately states no cause.
const REFUSED_REASON: &str = "This connection was not permitted.";

/// Ceiling on cached decisions. At the 5 s default TTL this is 2,000
/// connections per second before it binds, which is far past what a rendezvous
/// server brokers; it exists so that a token flood costs bounded memory.
const CACHE_CAPACITY: usize = 10_000;

/// What hbbs knows about a connection attempt at the chokepoint.
///
/// `from_id` is here because the api server accepts it, not because hbbs can
/// fill it: `PunchHoleRequest` carries no id for the *caller*
/// (`rendezvous.proto:20-32`), so at T3.3's call site it is empty. The
/// controlling device names itself only later, on its own unauthenticated audit
/// post — which is exactly why `apps/api` treats that name as a label rather
/// than as identity.
pub struct AuthRequest<'a> {
    /// `PunchHoleRequest.token` — a user access token or a break-glass capability.
    pub token: &'a str,
    pub from_id: &'a str,
    pub to_id: &'a str,
    /// Protobuf `ConnType` name, from `conn_type_name`.
    pub conn_type: &'a str,
    pub from_ip: &'a str,
}

/// Where an answer came from. Carried on the decision so that T3.7 can log it
/// and so that a test can tell "the api said yes" from "the cache said yes",
/// which are the same answer and very different facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// Authorization is switched off. Nothing was asked.
    Disabled,
    /// No token on the request; refused without spending an api call.
    NoToken,
    /// A fresh answer from the api server.
    Api,
    /// A positive answer from the api server, replayed inside its TTL.
    Cache,
    /// No answer could be obtained. Denied — decision D1.
    FailedClosed,
    /// No answer could be obtained and `AUTH_FAIL_OPEN` is on. Unsupported.
    FailedOpen,
    /// A break-glass capability, verified locally without asking the api at all
    /// — which is the point of it (T3.5).
    Breakglass,
}

impl DecisionSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::NoToken => "no-token",
            Self::Api => "api",
            Self::Cache => "cache",
            Self::FailedClosed => "fail-closed",
            Self::FailedOpen => "fail-open",
            Self::Breakglass => "break-glass",
        }
    }
}

/// The answer T3.3 acts on.
///
/// Deliberately has no `Default`: the only sane default is a denial, and a
/// struct whose `..Default::default()` silently means "allow" is the shape of
/// mistake this whole milestone exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDecision {
    pub allow: bool,
    /// Shown to the end user verbatim — it becomes
    /// `PunchHoleResponse.other_failure` (`apps/rustdesk/src/client.rs:940-941`).
    /// Empty on an allow.
    pub reason: String,
    /// `ControlPermissions` bitmask, when the grant limits permissions.
    pub permissions: Option<u32>,
    /// **Must be copied into `ControlledContext.conn_audit_ref`** (T3.3). It is
    /// the only handle tying a live session back to the user who opened it, and
    /// `enforceLiveSessionAccess` leaves anything it cannot attribute alone — so
    /// dropping this field does not degrade the audit trail, it silently makes
    /// the session immune to revocation. Empty when the api minted none.
    pub conn_audit_ref: String,
    /// The emergency path authorized this. `log::warn!` it — T3.5.
    pub breakglass: bool,
    pub source: DecisionSource,
    /// Wall time spent reaching the decision, for T3.7's latency log.
    pub latency: Duration,
}

impl AuthDecision {
    fn deny(reason: &str, source: DecisionSource, latency: Duration) -> Self {
        Self {
            allow: false,
            reason: reason.to_owned(),
            permissions: None,
            conn_audit_ref: String::new(),
            breakglass: false,
            source,
            latency,
        }
    }

    /// An allow carrying nothing — no permissions limit and, more importantly,
    /// no `conn_audit_ref`. Only the two paths that never consulted the api use
    /// it, and both of them therefore produce sessions nobody can attribute.
    fn blind_allow(source: DecisionSource, latency: Duration) -> Self {
        Self {
            allow: true,
            reason: String::new(),
            permissions: None,
            conn_audit_ref: String::new(),
            breakglass: false,
            source,
            latency,
        }
    }
}

/// The body of a 200 from the api server. `AuthorizeResponse` in
/// `apps/api/src/types.ts`.
#[derive(Debug, Clone, serde_derive::Deserialize)]
struct ApiDecision {
    /// Deliberately **not** `#[serde(default)]`. A body without `allow` denies
    /// either way, but a missing required field is a parse error, and a parse
    /// error is logged as the contract break it is instead of passing for an
    /// ordinary refusal.
    allow: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    permissions: Option<u32>,
    #[serde(default)]
    conn_audit_ref: Option<String>,
    #[serde(default)]
    breakglass: bool,
}

/// One cached *positive* decision.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheEntry {
    permissions: Option<u32>,
    conn_audit_ref: String,
    breakglass: bool,
    /// Absolute, and never extended on a hit. A sliding window would make the
    /// revocation delay unbounded for a peer that keeps retrying; this way the
    /// worst case is exactly `AUTH_CACHE_TTL_MS` after the decision.
    expires_at: Instant,
}

impl CacheEntry {
    fn decision(&self, source: DecisionSource, latency: Duration) -> AuthDecision {
        AuthDecision {
            allow: true,
            reason: String::new(),
            permissions: self.permissions,
            conn_audit_ref: self.conn_audit_ref.clone(),
            breakglass: self.breakglass,
            source,
            latency,
        }
    }
}

/// What a cached decision is keyed on.
///
/// **The token is stored as a sha256 digest, never in the clear.** These are
/// live credentials for the whole api, thousands of them, sitting in the
/// long-lived process most exposed to the internet; a hash makes a core dump or
/// a stray `Debug` print worthless. Hashing is also what makes the key safe:
/// a `DefaultHasher` over attacker-supplied strings turns a collision into one
/// user being admitted on another user's decision.
///
/// **`conn_type` is part of the key, and the task specified `(token, to_id)`.**
/// The extra field is not tidiness, it is the difference between a cache hit
/// that is correct and one that breaks revocation. See `authorize`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    token: [u8; 32],
    to_id: String,
    conn_type: String,
}

impl CacheKey {
    fn new(token: &str, to_id: &str, conn_type: &str) -> Self {
        Self {
            token: sha256::hash(token.as_bytes()).0,
            to_id: to_id.to_owned(),
            conn_type: conn_type.to_owned(),
        }
    }
}

/// Holds the connection pool and the decision cache for the lifetime of the
/// process. Build it **once**: a fresh `reqwest::Client` per connection would
/// pay a TCP and TLS handshake inside a 300 ms budget that a human is waiting
/// on, and would defeat keep-alive to the api server entirely.
pub struct Authorizer {
    config: AuthConfig,
    /// `None` when authorization is off, so the disabled path cannot make a
    /// call by accident.
    client: Option<reqwest::Client>,
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
    /// The emergency path (T3.5). Lives here rather than beside the api client
    /// because it is the *same decision*, reached without one — every caller
    /// that asks `authorize` gets break-glass handled for free, and none of them
    /// has to know the token format.
    breakglass: Breakglass,
}

impl Authorizer {
    /// Call from inside the tokio runtime — the client it builds belongs to one.
    pub fn new(config: AuthConfig) -> ResultType<Self> {
        // Read here rather than threaded in from `main`, but still before any
        // port binds — `Authorizer::new` is called first in `start_with_bind` —
        // so a mistyped `BREAKGLASS_PUBKEY` is a refusal to start. Discovering
        // it during the outage it exists for is the one unacceptable outcome.
        let breakglass_config = BreakglassConfig::from_args()?;
        breakglass_config.log();
        Self::new_with(config, breakglass_config)
    }

    /// The break-glass settings passed in rather than read from the process
    /// environment. Tests only: the environment is global, and a test that
    /// mutated it would race every other test in the binary.
    pub fn new_with(config: AuthConfig, breakglass: BreakglassConfig) -> ResultType<Self> {
        let client = if config.required {
            Some(build_client(&config)?)
        } else {
            None
        };
        Ok(Self {
            config,
            client,
            cache: Mutex::new(HashMap::new()),
            breakglass: Breakglass::new(breakglass),
        })
    }

    pub fn breakglass_armed(&self) -> bool {
        self.breakglass.enabled()
    }

    /// Spent capabilities still being remembered, for T3.7's console counter.
    pub fn breakglass_spent(&self) -> usize {
        self.breakglass.spent_nonces()
    }

    pub fn enabled(&self) -> bool {
        self.config.required
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Live cached decisions, for T3.7's runtime console counter.
    pub fn cached_decisions(&self) -> usize {
        let now = Instant::now();
        match self.cache.lock() {
            Ok(cache) => cache.values().filter(|e| e.expires_at > now).count(),
            Err(_) => 0,
        }
    }

    /// May this connection be brokered?
    ///
    /// **Why there is a cache at all, and it is not only latency.** The client
    /// sends the *same* `PunchHoleRequest` up to three times for one connection
    /// — `'punch_attempts: for i in 1..=3` in `apps/rustdesk/src/client.rs:913`,
    /// at roughly t=0 s, t=3 s and t=9 s — whenever the peer is slow to answer.
    /// Without a cache that single connection becomes three authorize calls,
    /// three rows in `connection_logs`, and three `conn_audit_ref`s of which two
    /// describe sessions that never existed. The 5 s default TTL covers the
    /// first retry, which is the case that actually occurs; by the third attempt
    /// the connection is failing anyway and one extra call is beside the point.
    ///
    /// **Only positive decisions are cached.** A cached denial would keep
    /// refusing a user for the whole TTL after an admin granted them access, and
    /// it would swallow the `connection_logs` row that is the only record a
    /// refused connection ever leaves.
    ///
    /// **`conn_type` is in the cache key even though T3.2 says `(token, to_id)`.**
    /// `conn_audit_ref` is minted per decision and consumed once: the device's
    /// audit post matches the one decision row that has no `conn_id` yet, and a
    /// second session arriving with the same ref finds nothing to join and is
    /// inserted **unattributed**. `enforceLiveSessionAccess` skips rows with no
    /// `fromUserId` by design, so that session is permanently immune to
    /// revocation. Three retries of one connection are safe to share a ref
    /// because at most one of them becomes a session; remote control followed by
    /// a file transfer to the same device — an ordinary thing to do, well inside
    /// 5 s — is *not*, and `conn_type` is what separates the two.
    ///
    /// Never panics and never propagates: every failure is a decision.
    pub async fn authorize(&self, req: &AuthRequest<'_>) -> AuthDecision {
        let started = Instant::now();

        if !self.config.required {
            return AuthDecision::blind_allow(DecisionSource::Disabled, started.elapsed());
        }

        // Answered here rather than forwarded. hbbs is the internet-facing half
        // of this pair and the api server may not be reachable from outside at
        // all, so forwarding would let any stranger who can reach the rendezvous
        // port spend an api request. Nothing is lost by answering locally:
        // `services/authorize.ts` refuses an empty token before it writes an
        // audit row, so there is no record to miss. The wording is copied from
        // that branch and is the one place the two can drift apart.
        let token = req.token.trim();
        if token.is_empty() {
            return AuthDecision::deny(NO_TOKEN_REASON, DecisionSource::NoToken, started.elapsed());
        }

        let key = CacheKey::new(token, req.to_id, req.conn_type);
        if let Some(entry) = self.cached(&key) {
            let source = if entry.breakglass {
                DecisionSource::Breakglass
            } else {
                DecisionSource::Cache
            };
            return entry.decision(source, started.elapsed());
        }

        // The emergency path — T3.5, decision D1. Checked *before* the api call
        // and answered without one, because the situation it exists for is the
        // api being unreachable; routing it through the thing that is down would
        // make the lifeboat depend on the ship. `apps/api` learns about the use
        // afterwards, from T3.6's local audit.
        //
        // It sits **after** the cache lookup on purpose: a capability is single
        // use, and the client sends the same `PunchHoleRequest` up to three
        // times. Without the cache in front, a peer slow to answer would burn
        // the capability on attempt one and be refused as a replay on attempt
        // two — the emergency path failing in exactly the conditions that
        // produced the emergency.
        if breakglass::looks_like(token) {
            return match self.breakglass.decide(token, req.to_id, req.from_ip) {
                Outcome::Allow(cap) => {
                    let entry = CacheEntry {
                        // A capability carries no permission limits; it is an
                        // operator reaching a machine, and the api answers the
                        // same way.
                        permissions: None,
                        // The nonce **is** the `conn_audit_ref`, exactly as
                        // `authorize.ts` does it: unique, single-use, and
                        // already travelling to the device. It is what makes a
                        // break-glass session attributable — and therefore
                        // revocable — like any other.
                        conn_audit_ref: cap.nonce,
                        breakglass: true,
                        expires_at: Instant::now() + self.config.cache_ttl,
                    };
                    let decision = entry.decision(DecisionSource::Breakglass, started.elapsed());
                    self.remember(key, entry);
                    decision
                }
                Outcome::Refuse(reason) => {
                    AuthDecision::deny(&reason, DecisionSource::Breakglass, started.elapsed())
                }
            };
        }

        match self.ask(req, token).await {
            Ok(answer) if answer.allow => {
                let entry = CacheEntry {
                    permissions: answer.permissions,
                    conn_audit_ref: answer.conn_audit_ref.unwrap_or_default(),
                    breakglass: answer.breakglass,
                    expires_at: Instant::now() + self.config.cache_ttl,
                };
                let decision = entry.decision(DecisionSource::Api, started.elapsed());
                self.remember(key, entry);
                decision
            }
            Ok(answer) => {
                let reason = answer.reason.unwrap_or_default();
                let reason = if reason.trim().is_empty() {
                    REFUSED_REASON
                } else {
                    reason.trim()
                };
                AuthDecision::deny(reason, DecisionSource::Api, started.elapsed())
            }
            Err(err) => {
                // Loud on purpose: every path that lands here is an operator
                // problem, and the user-facing message deliberately says none of
                // it. `log::error!` because the alternative — a fleet that
                // cannot connect, with the cause visible only per connection —
                // is what decision D1 costs when it is working as intended.
                log::error!(
                    "authorize {} failed after {:?}: {err:#}",
                    req.to_id,
                    started.elapsed()
                );
                if self.config.fail_open {
                    // Also loses the `conn_audit_ref`, so every session brokered
                    // this way is unattributable and cannot later be revoked —
                    // one more reason this switch is documented as unsupported.
                    log::warn!(
                        "AUTH_FAIL_OPEN: brokering {} without a decision",
                        req.to_id
                    );
                    AuthDecision::blind_allow(DecisionSource::FailedOpen, started.elapsed())
                } else {
                    AuthDecision::deny(
                        UNAVAILABLE_REASON,
                        DecisionSource::FailedClosed,
                        started.elapsed(),
                    )
                }
            }
        }
    }

    /// One round trip. Anything other than a 2xx carrying a parseable body is an
    /// error rather than a denial — including the api server's own `401` and
    /// `400`, whose `{allow:false}` bodies would otherwise pass for considered
    /// refusals and put "Unauthorized" on an end user's screen when the real
    /// fault is a mistyped `AUTH_API_SECRET`.
    async fn ask(&self, req: &AuthRequest<'_>, token: &str) -> ResultType<ApiDecision> {
        let Some(client) = self.client.as_ref() else {
            bail!("authorization is enabled but no http client was built");
        };

        let mut body = serde_json::Map::new();
        body.insert("token".to_owned(), serde_json::Value::from(token));
        body.insert("to_id".to_owned(), serde_json::Value::from(req.to_id));
        // Omitted rather than sent empty: the api server's schema marks these
        // optional, and an empty string would be stored as a real value on the
        // audit row.
        for (name, value) in [
            ("from_id", req.from_id),
            ("conn_type", req.conn_type),
            ("from_ip", req.from_ip),
        ] {
            if !value.is_empty() {
                body.insert(name.to_owned(), serde_json::Value::from(value));
            }
        }

        let response = client
            .post(format!("{}{AUTHORIZE_PATH}", self.config.api_url))
            .header(SECRET_HEADER, &self.config.api_secret)
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            bail!("{AUTHORIZE_PATH} answered {status}: {}", clip(&detail, 200));
        }

        let raw = response.text().await?;
        match serde_json::from_str::<ApiDecision>(&raw) {
            Ok(decision) => Ok(decision),
            // The body is in the message because the failure mode this catches
            // is a proxy or a login page answering 200 with HTML, and the status
            // code alone makes that look like a bug in hbbs.
            Err(err) => bail!("{AUTHORIZE_PATH} answered unparseable json ({err}): {}", clip(&raw, 200)),
        }
    }

    fn cached(&self, key: &CacheKey) -> Option<CacheEntry> {
        let now = Instant::now();
        let mut cache = self.cache.lock().ok()?;
        match cache.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.clone()),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    fn remember(&self, key: CacheKey, entry: CacheEntry) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= CACHE_CAPACITY {
            let now = Instant::now();
            cache.retain(|_, e| e.expires_at > now);
        }
        // Declining to store costs one round trip and can never produce a wrong
        // answer, so a full cache simply stops caching rather than evicting.
        if cache.len() < CACHE_CAPACITY {
            cache.insert(key, entry);
        }
    }
}

fn build_client(config: &AuthConfig) -> ResultType<reqwest::Client> {
    Ok(reqwest::Client::builder()
        // Whole-request budget, and the connect half of it separately, so an
        // api host that blackholes SYNs fails inside the same 300 ms rather
        // than at the OS connect timeout.
        .timeout(config.timeout)
        .connect_timeout(config.timeout)
        // Ambient `HTTP_PROXY` / `ALL_PROXY` would route the shared secret and
        // every user token through whatever that variable names. hbbs already
        // has form here — a stray `PORT` silently moves the listener (T0.4) —
        // so this call is explicit about not inheriting the environment.
        .no_proxy()
        .user_agent(format!("hbbs/{}", crate::version::VERSION))
        .build()?)
}

/// Protobuf `ConnType` name, as `apps/api`'s `connTypeFromProto` spells it.
///
/// Written out rather than derived from `Debug`, so that an upstream rename
/// breaks this build instead of quietly changing a vocabulary the api server
/// matches on. Unknown values map to the empty string, which is omitted from the
/// request — an unrecognised conn type must not become a fake audit label.
pub fn conn_type_name(conn_type: EnumOrUnknown<ConnType>) -> &'static str {
    match conn_type.enum_value() {
        Ok(ConnType::DEFAULT_CONN) => "DEFAULT_CONN",
        Ok(ConnType::FILE_TRANSFER) => "FILE_TRANSFER",
        Ok(ConnType::PORT_FORWARD) => "PORT_FORWARD",
        Ok(ConnType::RDP) => "RDP",
        Ok(ConnType::VIEW_CAMERA) => "VIEW_CAMERA",
        Ok(ConnType::TERMINAL) => "TERMINAL",
        Err(_) => "",
    }
}

fn clip(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max {
        return text.to_owned();
    }
    text.chars().take(max).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn defaults_to_disabled_when_nothing_is_configured() {
        let config = AuthConfig::from_lookup(lookup(&[])).unwrap();
        assert!(!config.required);
        assert!(!config.fail_open);
        assert_eq!(config.timeout.as_millis(), DEFAULT_TIMEOUT_MS as u128);
    }

    #[test]
    fn setting_the_url_is_what_turns_it_on() {
        // There is deliberately no second switch to forget.
        let config = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "https://api.example.com"),
            (KEY_API_SECRET, "s"),
        ]))
        .unwrap();
        assert!(config.required);
    }

    #[test]
    fn an_explicit_no_still_wins() {
        let config = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "https://api.example.com"),
            (KEY_REQUIRED, "N"),
        ]))
        .unwrap();
        assert!(!config.required);
    }

    #[test]
    fn refuses_to_start_when_asked_to_authorize_against_nothing() {
        // The alternative is a server that denies every connection in the
        // fleet, which is a far more expensive way to learn the same thing.
        let err = AuthConfig::from_lookup(lookup(&[(KEY_REQUIRED, "Y")])).unwrap_err();
        assert!(err.to_string().contains(KEY_API_URL));
    }

    #[test]
    fn refuses_to_start_without_a_secret() {
        let err =
            AuthConfig::from_lookup(lookup(&[(KEY_API_URL, "https://api.example.com")])).unwrap_err();
        assert!(err.to_string().contains(KEY_API_SECRET));
    }

    #[test]
    fn refuses_a_secret_that_is_the_licence_key() {
        // Every client is given the licence key, so sharing it with the
        // authorize endpoint would let any client authorize itself.
        let err = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "https://api.example.com"),
            (KEY_API_SECRET, "shared"),
            (KEY_RUSTDESK_KEY, "shared"),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("RustDesk key"));
    }

    #[test]
    fn allows_the_placeholder_licence_key_to_coincide() {
        // "-" is hbbs's own "no key" placeholder (main.rs), not a real key.
        let config = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "https://api.example.com"),
            (KEY_API_SECRET, "-"),
            (KEY_RUSTDESK_KEY, "-"),
        ]))
        .unwrap();
        assert!(config.required);
    }

    #[test]
    fn refuses_a_url_without_a_scheme() {
        let err = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "api.example.com"),
            (KEY_API_SECRET, "s"),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains(KEY_API_URL));
    }

    #[test]
    fn strips_a_trailing_slash() {
        // `…//api/internal/authorize` is answered by some proxies with a
        // redirect, which a POST does not follow.
        let config = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "https://api.example.com/"),
            (KEY_API_SECRET, "s"),
        ]))
        .unwrap();
        assert_eq!(config.api_url, "https://api.example.com");
    }

    #[test]
    fn refuses_a_timeout_that_is_not_a_number() {
        // Unlike rmem, this is not silently replaced with the default.
        let err = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "https://api.example.com"),
            (KEY_API_SECRET, "s"),
            (KEY_TIMEOUT_MS, "300ms"),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains(KEY_TIMEOUT_MS));
    }

    #[test]
    fn refuses_a_zero_timeout() {
        let err = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "https://api.example.com"),
            (KEY_API_SECRET, "s"),
            (KEY_CACHE_TTL_MS, "0"),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains(KEY_CACHE_TTL_MS));
    }

    #[test]
    fn fail_open_is_off_unless_asked_for() {
        let config = AuthConfig::from_lookup(lookup(&[
            (KEY_API_URL, "https://api.example.com"),
            (KEY_API_SECRET, "s"),
        ]))
        .unwrap();
        assert!(!config.fail_open, "decision D1: hbbs fails closed");
    }

    #[test]
    fn never_logs_the_secret() {
        assert_eq!(redact("super-secret-value"), "<18 chars>");
        assert_eq!(redact(""), "<unset>");
    }

    #[test]
    fn loopback_urls_do_not_warn_about_cleartext() {
        assert!(is_loopback("http://localhost:21114"));
        assert!(is_loopback("http://127.0.0.1:21114"));
        assert!(!is_loopback("http://api.example.com"));
    }
}

/// The decision path, against a real socket.
///
/// A hand-written HTTP/1.1 stub rather than a mock of our own client: the
/// interesting failures here — a timeout, a 401, a 200 full of HTML — are things
/// `reqwest` does, and a mock would only ever prove that the mock works. Every
/// reply closes the connection, so the accept count *is* the request count.
#[cfg(test)]
mod api_tests {
    use super::*;
    use sodiumoxide::crypto::sign;
    use hbb_common::tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    enum Reply {
        Http(u16, &'static str),
        /// Accept and never answer, to drive the timeout.
        Hang,
    }

    struct Stub {
        addr: SocketAddr,
        calls: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl Stub {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
        fn request(&self, n: usize) -> String {
            self.requests.lock().unwrap()[n].clone()
        }
    }

    /// Replies are served in order; the last one repeats.
    async fn stub(replies: Vec<Reply>) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (task_calls, task_requests) = (calls.clone(), requests.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let n = task_calls.fetch_add(1, Ordering::SeqCst);
                let raw = read_request(&mut socket).await;
                task_requests.lock().unwrap().push(raw);
                match replies.get(n).or_else(|| replies.last()) {
                    Some(Reply::Http(status, body)) => {
                        let head = format!(
                            "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\n\
                             content-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = socket.write_all(head.as_bytes()).await;
                        let _ = socket.write_all(body.as_bytes()).await;
                        let _ = socket.flush().await;
                    }
                    Some(Reply::Hang) | None => {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
        });
        Stub {
            addr,
            calls,
            requests,
        }
    }

    async fn read_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut raw = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            let Ok(read) = socket.read(&mut buf).await else {
                break;
            };
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..read]);
            if let (Some(head), Some(len)) = (head_end(&raw), content_length(&raw)) {
                if raw.len() >= head + len {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    }

    fn head_end(raw: &[u8]) -> Option<usize> {
        raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    fn content_length(raw: &[u8]) -> Option<usize> {
        let text = String::from_utf8_lossy(raw).to_lowercase();
        let rest = &text[text.find("content-length:")? + "content-length:".len()..];
        rest.split("\r\n").next()?.trim().parse().ok()
    }

    fn config_for(addr: SocketAddr) -> AuthConfig {
        AuthConfig {
            api_url: format!("http://{addr}"),
            api_secret: "hbbs-shared-secret".to_owned(),
            required: true,
            fail_open: false,
            // Generous, because these tests must not turn CI load into a
            // failure. The one test that cares about the timeout sets its own.
            timeout: Duration::from_millis(4_000),
            cache_ttl: Duration::from_millis(5_000),
        }
    }

    fn req<'a>(token: &'a str, to_id: &'a str, conn_type: &'a str) -> AuthRequest<'a> {
        AuthRequest {
            token,
            from_id: "",
            to_id,
            conn_type,
            from_ip: "203.0.113.7",
        }
    }

    const ALLOW: &str = r#"{"allow":true,"conn_audit_ref":"ref-one"}"#;
    const ALLOW_TWO: &str = r#"{"allow":true,"conn_audit_ref":"ref-two"}"#;
    const DENY: &str = r#"{"allow":false,"reason":"You do not have access to this device."}"#;

    #[tokio::test]
    async fn an_allow_is_carried_through_whole() {
        let stub = stub(vec![Reply::Http(
            200,
            r#"{"allow":true,"permissions":6,"conn_audit_ref":"ref-one"}"#,
        )])
        .await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(decision.allow);
        assert_eq!(decision.source, DecisionSource::Api);
        assert_eq!(decision.permissions, Some(6));
        assert_eq!(decision.conn_audit_ref, "ref-one");
        assert!(decision.reason.is_empty());
    }

    #[tokio::test]
    async fn the_request_is_shaped_the_way_the_api_documents_it() {
        let stub = stub(vec![Reply::Http(200, ALLOW)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        auth.authorize(&req("tok-abc", "123456789", "FILE_TRANSFER"))
            .await;

        let raw = stub.request(0);
        assert!(raw.starts_with("POST /api/internal/authorize "), "{raw}");
        assert!(raw.to_lowercase().contains("x-hbbs-secret: hbbs-shared-secret"), "{raw}");
        assert!(raw.contains(r#""token":"tok-abc""#), "{raw}");
        assert!(raw.contains(r#""to_id":"123456789""#), "{raw}");
        assert!(raw.contains(r#""conn_type":"FILE_TRANSFER""#), "{raw}");
        assert!(raw.contains(r#""from_ip":"203.0.113.7""#), "{raw}");
        // Empty optionals are omitted, not sent as "" — an empty string would be
        // stored as a real value on the audit row.
        assert!(!raw.contains("from_id"), "{raw}");
    }

    #[tokio::test]
    async fn a_retry_is_answered_from_cache_with_the_same_audit_ref() {
        // This is the punch-attempt retry (client.rs:913). One connection, so
        // one decision row and one ref — the second attempt must not mint a
        // second one.
        let stub = stub(vec![Reply::Http(200, ALLOW), Reply::Http(200, ALLOW_TWO)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let first = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;
        let second = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert_eq!(stub.calls(), 1, "the retry should not reach the api");
        assert_eq!(second.source, DecisionSource::Cache);
        assert_eq!(first.conn_audit_ref, second.conn_audit_ref);
    }

    #[tokio::test]
    async fn a_second_conn_type_is_a_second_connection_and_gets_its_own_ref() {
        // Remote control, then a file transfer to the same device, inside the
        // TTL. Sharing a ref would make the file-transfer session unattributable
        // and therefore immune to revocation.
        let stub = stub(vec![Reply::Http(200, ALLOW), Reply::Http(200, ALLOW_TWO)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let remote = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;
        let files = auth.authorize(&req("tok", "123456789", "FILE_TRANSFER")).await;

        assert_eq!(stub.calls(), 2);
        assert_eq!(remote.conn_audit_ref, "ref-one");
        assert_eq!(files.conn_audit_ref, "ref-two");
    }

    #[tokio::test]
    async fn a_different_device_is_a_different_key() {
        let stub = stub(vec![Reply::Http(200, ALLOW), Reply::Http(200, ALLOW_TWO)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        auth.authorize(&req("tok", "111111111", "DEFAULT_CONN")).await;
        let other = auth.authorize(&req("tok", "222222222", "DEFAULT_CONN")).await;

        assert_eq!(stub.calls(), 2);
        assert_eq!(other.conn_audit_ref, "ref-two");
    }

    #[tokio::test]
    async fn a_different_token_is_a_different_key() {
        let stub = stub(vec![Reply::Http(200, ALLOW), Reply::Http(200, ALLOW_TWO)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        auth.authorize(&req("tok-a", "123456789", "DEFAULT_CONN")).await;
        auth.authorize(&req("tok-b", "123456789", "DEFAULT_CONN")).await;

        assert_eq!(stub.calls(), 2);
    }

    #[tokio::test]
    async fn denials_are_never_cached() {
        // An admin granting access must take effect on the user's next attempt,
        // and every refusal is the only record that connection attempt leaves.
        let stub = stub(vec![Reply::Http(200, DENY), Reply::Http(200, ALLOW)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let refused = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;
        let granted = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(!refused.allow);
        assert_eq!(refused.reason, "You do not have access to this device.");
        assert_eq!(stub.calls(), 2, "the second attempt must ask again");
        assert!(granted.allow);
    }

    #[tokio::test]
    async fn an_expired_entry_is_asked_again() {
        let stub = stub(vec![Reply::Http(200, ALLOW), Reply::Http(200, ALLOW_TWO)]).await;
        let mut config = config_for(stub.addr);
        config.cache_ttl = Duration::from_millis(30);
        let auth = Authorizer::new(config).unwrap();

        auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        let after = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert_eq!(stub.calls(), 2);
        assert_eq!(after.source, DecisionSource::Api);
        assert_eq!(after.conn_audit_ref, "ref-two");
    }

    /// Since T3.5 the emergency path is decided **here**, with no api call.
    ///
    /// This test asserted the opposite before that — it stubbed the api
    /// answering `{"breakglass":true}` — which only worked because hbbs was
    /// forwarding capabilities to the very server the emergency is usually
    /// about.
    fn armed() -> (BreakglassConfig, sign::SecretKey) {
        sodiumoxide::init().ok();
        let (pk, sk) = sign::gen_keypair();
        (
            BreakglassConfig {
                pubkey: Some(pk),
                ..Default::default()
            },
            sk,
        )
    }

    fn capability(sk: &sign::SecretKey, device: &str, nonce: &str) -> String {
        crate::breakglass::mint_for_test(
            sk,
            "alice",
            device,
            crate::common::now() as i64 + 600,
            nonce,
        )
    }

    #[tokio::test]
    async fn a_break_glass_capability_never_reaches_the_api() {
        // The whole point of D1's escape hatch: it must work while the api is
        // down, so it must not consult it even when it is up.
        let stub = stub(vec![Reply::Http(200, r#"{"allow":false,"reason":"no"}"#)]).await;
        let (bg, sk) = armed();
        let auth = Authorizer::new_with(config_for(stub.addr), bg).unwrap();

        let decision = auth
            .authorize(&req(&capability(&sk, "123456789", "nonce-1"), "123456789", "DEFAULT_CONN"))
            .await;

        assert!(decision.allow);
        assert!(decision.breakglass);
        assert_eq!(decision.source, DecisionSource::Breakglass);
        // The nonce doubles as the audit ref, which is what makes the session
        // attributable and therefore revocable (`authorize.ts` agrees).
        assert_eq!(decision.conn_audit_ref, "nonce-1");
        assert_eq!(stub.calls(), 0, "the emergency path asked the api");
    }

    #[tokio::test]
    async fn a_break_glass_allow_is_cached_so_the_retry_is_not_a_replay() {
        // A capability is single use. The client sends the same
        // `PunchHoleRequest` up to three times, so without the cache in front
        // the second attempt would be refused as a replay and `bail!` the whole
        // connect — the emergency path failing whenever the peer is slow.
        let stub = stub(vec![]).await;
        let (bg, sk) = armed();
        let auth = Authorizer::new_with(config_for(stub.addr), bg).unwrap();
        let token = capability(&sk, "123456789", "nonce-2");

        let first = auth.authorize(&req(&token, "123456789", "DEFAULT_CONN")).await;
        let retry = auth.authorize(&req(&token, "123456789", "DEFAULT_CONN")).await;

        assert!(first.allow && first.breakglass);
        assert!(retry.allow, "the retry must not be refused as a replay");
        assert!(retry.breakglass);
        assert_eq!(retry.conn_audit_ref, "nonce-2", "the retry must reuse the one ref");
        assert_eq!(stub.calls(), 0);
    }

    #[tokio::test]
    async fn a_capability_refused_here_is_not_forwarded_to_the_api_as_a_login_token() {
        // Otherwise an operator who mistyped what they pasted is told their
        // session expired, which sends them to fix the wrong thing.
        let stub = stub(vec![Reply::Http(200, r#"{"allow":true}"#)]).await;
        let (bg, _) = armed();
        let auth = Authorizer::new_with(config_for(stub.addr), bg).unwrap();

        let decision = auth.authorize(&req("bg.garbage", "123456789", "DEFAULT_CONN")).await;

        assert!(!decision.allow);
        assert_eq!(decision.source, DecisionSource::Breakglass);
        assert_eq!(stub.calls(), 0);
    }

    #[tokio::test]
    async fn a_capability_authorizes_while_the_api_is_unreachable() {
        // D1's whole reason for existing, as one assertion.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let (bg, sk) = armed();
        let auth = Authorizer::new_with(config_for(addr), bg).unwrap();

        let decision = auth
            .authorize(&req(&capability(&sk, "123456789", "nonce-3"), "123456789", "DEFAULT_CONN"))
            .await;
        assert!(decision.allow && decision.breakglass);

        // …and an ordinary user stays denied throughout.
        let ordinary = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;
        assert!(!ordinary.allow);
        assert_eq!(ordinary.source, DecisionSource::FailedClosed);
    }

    #[tokio::test]
    async fn with_break_glass_disarmed_a_capability_is_refused_not_forwarded() {
        let stub = stub(vec![Reply::Http(200, r#"{"allow":true}"#)]).await;
        let (_, sk) = armed();
        let auth = Authorizer::new_with(config_for(stub.addr), BreakglassConfig::default()).unwrap();

        let decision = auth
            .authorize(&req(&capability(&sk, "123456789", "nonce-4"), "123456789", "DEFAULT_CONN"))
            .await;

        assert!(!decision.allow);
        assert_eq!(stub.calls(), 0);
        assert!(!auth.breakglass_armed());
    }

    #[tokio::test]
    async fn an_unreachable_api_denies() {
        // Bind and drop, so the port is certain to be closed.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let auth = Authorizer::new(config_for(addr)).unwrap();

        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(!decision.allow, "decision D1: hbbs fails closed");
        assert_eq!(decision.source, DecisionSource::FailedClosed);
        assert_eq!(decision.reason, UNAVAILABLE_REASON);
    }

    #[tokio::test]
    async fn a_timeout_denies_inside_the_budget() {
        let stub = stub(vec![Reply::Hang]).await;
        let mut config = config_for(stub.addr);
        config.timeout = Duration::from_millis(150);
        let auth = Authorizer::new(config).unwrap();

        let started = Instant::now();
        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(!decision.allow);
        assert_eq!(decision.source, DecisionSource::FailedClosed);
        assert!(
            started.elapsed() < Duration::from_millis(1_500),
            "a human is waiting on this: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_failure_is_never_cached() {
        let stub = stub(vec![Reply::Http(500, r#"{"allow":false}"#), Reply::Http(200, ALLOW)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let failed = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;
        let recovered = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(!failed.allow);
        assert!(recovered.allow, "hbbs must recover as soon as the api does");
        assert_eq!(stub.calls(), 2);
    }

    #[tokio::test]
    async fn an_html_body_with_a_200_denies() {
        // A proxy or a login page in front of the api server. Without this the
        // parse failure would have to be a panic or a silent allow.
        let stub = stub(vec![Reply::Http(200, "<html>Sign in</html>")]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(!decision.allow);
        assert_eq!(decision.source, DecisionSource::FailedClosed);
    }

    #[tokio::test]
    async fn a_401_is_an_operator_fault_and_never_reaches_the_user() {
        // The api server answers `{allow:false,reason:"Unauthorized"}` here, and
        // a wrong AUTH_API_SECRET is the only way to get it. Showing that word
        // to an end user would send them looking at their own account.
        let stub = stub(vec![Reply::Http(401, r#"{"allow":false,"reason":"Unauthorized"}"#)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(!decision.allow);
        assert_eq!(decision.source, DecisionSource::FailedClosed);
        assert!(!decision.reason.contains("Unauthorized"), "{}", decision.reason);
    }

    #[tokio::test]
    async fn a_body_without_allow_is_a_contract_break_not_a_refusal() {
        let stub = stub(vec![Reply::Http(200, r#"{"reason":"nope"}"#)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(!decision.allow);
        assert_eq!(decision.source, DecisionSource::FailedClosed);
    }

    #[tokio::test]
    async fn a_deny_without_a_reason_still_says_something_to_the_user() {
        let stub = stub(vec![Reply::Http(200, r#"{"allow":false}"#)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(!decision.allow);
        assert_eq!(decision.reason, REFUSED_REASON);
    }

    #[tokio::test]
    async fn fail_open_brokers_when_nothing_answers() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let mut config = config_for(addr);
        config.fail_open = true;
        let auth = Authorizer::new(config).unwrap();

        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(decision.allow);
        assert_eq!(decision.source, DecisionSource::FailedOpen);
        // And the session it brokers can never be revoked, because nothing
        // minted a ref for it.
        assert!(decision.conn_audit_ref.is_empty());
    }

    #[tokio::test]
    async fn an_empty_token_never_reaches_the_api() {
        let stub = stub(vec![Reply::Http(200, ALLOW)]).await;
        let auth = Authorizer::new(config_for(stub.addr)).unwrap();

        let decision = auth.authorize(&req("   ", "123456789", "DEFAULT_CONN")).await;

        assert!(!decision.allow);
        assert_eq!(decision.source, DecisionSource::NoToken);
        assert_eq!(decision.reason, NO_TOKEN_REASON);
        assert_eq!(stub.calls(), 0, "hbbs is internet-facing; this is amplification");
    }

    #[tokio::test]
    async fn disabled_allows_without_asking_anything() {
        let stub = stub(vec![Reply::Http(200, DENY)]).await;
        let mut config = config_for(stub.addr);
        config.required = false;
        let auth = Authorizer::new(config).unwrap();

        let decision = auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;

        assert!(decision.allow);
        assert_eq!(decision.source, DecisionSource::Disabled);
        assert_eq!(stub.calls(), 0);
        assert!(!auth.enabled());
    }

    #[tokio::test]
    async fn the_cache_counts_only_live_entries() {
        let stub = stub(vec![Reply::Http(200, ALLOW)]).await;
        let mut config = config_for(stub.addr);
        config.cache_ttl = Duration::from_millis(30);
        let auth = Authorizer::new(config).unwrap();

        auth.authorize(&req("tok", "123456789", "DEFAULT_CONN")).await;
        assert_eq!(auth.cached_decisions(), 1);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(auth.cached_decisions(), 0);
    }

    #[test]
    fn the_cache_key_never_holds_the_token() {
        // A `Debug` of the map, or a core dump, must not hand over live api
        // credentials.
        let key = CacheKey::new("super-secret-token", "123456789", "DEFAULT_CONN");
        assert!(!format!("{key:?}").contains("super-secret-token"));
        assert_eq!(key, CacheKey::new("super-secret-token", "123456789", "DEFAULT_CONN"));
        assert_ne!(key, CacheKey::new("another-token", "123456789", "DEFAULT_CONN"));
    }

    #[test]
    fn conn_type_names_match_the_api_vocabulary() {
        // `connTypeFromProto` in apps/api/src/types.ts switches on these exact
        // strings; anything else is silently dropped there.
        assert_eq!(conn_type_name(ConnType::DEFAULT_CONN.into()), "DEFAULT_CONN");
        assert_eq!(conn_type_name(ConnType::FILE_TRANSFER.into()), "FILE_TRANSFER");
        assert_eq!(conn_type_name(ConnType::PORT_FORWARD.into()), "PORT_FORWARD");
        assert_eq!(conn_type_name(ConnType::RDP.into()), "RDP");
        assert_eq!(conn_type_name(ConnType::VIEW_CAMERA.into()), "VIEW_CAMERA");
        assert_eq!(conn_type_name(ConnType::TERMINAL.into()), "TERMINAL");
        assert_eq!(conn_type_name(EnumOrUnknown::from_i32(99)), "");
    }
}
