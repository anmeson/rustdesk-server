//! Break-glass capability verification — TASK.md T3.5, docs/PLAN.md decision D1.
//!
//! D1 says hbbs fails closed: no decision from `apps/api` means no connection.
//! Taken alone that is a trap, because the machine you would fix `apps/api`
//! from is reached *through* hbbs — an outage locks you out of its own cure.
//! Break-glass is the way back in.
//!
//! It is deliberately **not** a static shared secret. A skeleton key cannot be
//! scoped to one device, cannot expire, and cannot be rotated without touching
//! every hbbs. Instead an operator mints a short-lived, device-scoped capability
//! offline with a private key that never touches a server; hbbs holds only the
//! **public** half, so leaking a server's whole configuration grants nothing.
//!
//! # The wire format, which is not ours to choose
//!
//! It is already minted by `apps/api/src/scripts/mint-breakglass.ts` and already
//! verified by `apps/api/src/services/breakglass.ts`. This module is the third
//! implementation of the same three lines and has to agree with both, byte for
//! byte:
//!
//! ```text
//! bg.<base64url(JSON payload)>.<base64url(ed25519 signature)>
//! payload = { admin_id, to_id, exp (unix seconds), nonce }
//! ```
//!
//! **The signature covers the base64url payload *text*, not the JSON bytes** —
//! `sign(null, Buffer.from(payloadB64), key)` in the minter. Verifying the
//! decoded JSON instead would fail every real capability, and it is the single
//! easiest thing to get wrong here, because both readings are plausible and only
//! one of them has a test.
//!
//! It rides in `PunchHoleRequest.token`, which is why there is **no client
//! patch**: the admin pastes the capability into `access_token` in their own
//! `RustDesk_local.toml` and connects with a stock client.
//!
//! # Why hbbs verifies locally rather than asking `apps/api`
//!
//! Because the premise of the whole feature is that `apps/api` is not
//! answering. Asking it first would make the emergency path's behaviour depend
//! on the health of the thing the emergency is about — and worse, it would make
//! the path *most* fragile in the case it exists for. So the decision is made
//! here, with no network call, and `apps/api` learns about it afterwards
//! (T3.6's local audit and reconciliation). `services/breakglass.ts` says the
//! same thing from the other side: "hbbs is the real enforcement point and
//! performs this same check itself".
//!
//! The cost of that is a **per-process** nonce store rather than the api's
//! unique index. Two consequences, both documented rather than fixed:
//!
//!   - a capability spent against one hbbs can be spent again against another,
//!     if a deployment runs more than one;
//!   - and against the same hbbs after a restart.
//!
//! Both are bounded by `exp`, which is minutes. Closing them properly means
//! shared state between rendezvous servers, which is a much larger thing than
//! the hole it would close.
//!
//! # Local-first auditing — T3.6
//!
//! Every use is appended and **fsynced** to a file on the hbbs host *before* the
//! decision is returned, and only then replayed to `apps/api`. The ordering is
//! the whole point: the reason an operator is on this path is that `apps/api` is
//! not answering, so an audit that goes to `apps/api` first would fail in
//! exactly the situation the feature exists for — and "every use is logged"
//! would be quietly untrue precisely when it mattered.
//!
//! A use that cannot be written to that file is **refused**. That is a real
//! tradeoff and it is made deliberately: an unauditable emergency access is the
//! thing this design exists to prevent, and the failure it protects against —
//! a full disk on the rendezvous host — has its own fix path that does not go
//! through break-glass. `BREAKGLASS_AUDIT_REQUIRED=N` is the documented lever
//! for an operator who disagrees at 3am, for the same reason `AUTH_FAIL_OPEN`
//! exists: a lever beats a patched binary.

use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hbb_common::{bail, log, ResultType};
use sodiumoxide::crypto::sign;

use crate::common::{get_arg_opt, now};

/// Every capability starts with this. Matches `BREAKGLASS_PREFIX` in
/// `services/breakglass.ts`.
pub const PREFIX: &str = "bg.";

const KEY_PUBKEY: &str = "BREAKGLASS_PUBKEY";
const KEY_MAX_TTL_SEC: &str = "BREAKGLASS_MAX_TTL_SEC";
const KEY_RATE_PER_MINUTE: &str = "BREAKGLASS_RATE_PER_MINUTE";
const KEY_AUDIT_LOG: &str = "BREAKGLASS_AUDIT_LOG";
const KEY_AUDIT_REQUIRED: &str = "BREAKGLASS_AUDIT_REQUIRED";
const KEY_RECONCILE_SEC: &str = "BREAKGLASS_RECONCILE_SEC";

/// Same name the api gives its own copy (`env.ts:46`), so the two files are
/// recognisable as the same kind of thing on two different hosts. Relative to
/// the working directory, like everything else hbbs writes.
const DEFAULT_AUDIT_LOG: &str = "./breakglass-audit.log";

/// How often the reconciler retries. Slow on purpose: the records are already
/// durable on disk, so this is a catch-up, not a delivery path — and `apps/api`
/// coming back up should not be met with a stampede.
const DEFAULT_RECONCILE_SEC: u64 = 60;

/// Records sent in one reconciliation POST.
const RECONCILE_BATCH: usize = 200;

/// A raw ed25519 public key is exactly this long. `keygen-breakglass.ts` strips
/// the 12-byte DER SubjectPublicKeyInfo prefix before printing it, so what an
/// operator pastes is the bare key.
const PUBKEY_LEN: usize = 32;

/// Longest future `exp` hbbs will accept, matching the ceiling the minter
/// already refuses to exceed ("Refusing to mint a capability valid for more
/// than 4 hours", `mint-breakglass.ts`). The two have to agree: raise this and
/// nothing changes, lower it and legitimate 4-hour capabilities start being
/// refused with a message about expiry that does not fit what happened.
///
/// It exists because `exp` is the *only* bound on a capability's life — there
/// is no `iat` — so without a ceiling, anyone holding the private key could
/// mint a skeleton key valid for a decade, which is the exact thing this design
/// was chosen to prevent.
const DEFAULT_MAX_TTL_SEC: u64 = 4 * 60 * 60;

/// Verification attempts allowed per source ip per minute.
///
/// Generous for a real operator — the decision cache absorbs a client's punch
/// retries, so a genuine emergency connect reaches this code roughly once — and
/// tight enough that this unauthenticated, internet-facing path cannot be used
/// to make hbbs spend its CPU on signature checks.
const DEFAULT_RATE_PER_MINUTE: u32 = 10;

/// The same, across all source addresses. An attacker with a botnet defeats the
/// per-ip limit trivially; this one bounds what that is worth.
const GLOBAL_RATE_PER_MINUTE: u32 = 60;

const RATE_WINDOW: Duration = Duration::from_secs(60);

// The user-facing strings below are copied **verbatim** from the matching
// branches of `services/breakglass.ts`. They are shown to a person, and hbbs
// and the api answering the same capability differently would be a confusing
// thing to debug at 3am. The three that have no counterpart there are marked.

const NOT_ENABLED: &str = "Break-glass is not enabled";
const MALFORMED: &str = "Malformed capability";
const MALFORMED_PAYLOAD: &str = "Malformed capability payload";
const UNCHECKABLE: &str = "Capability signature could not be checked";
const BAD_SIGNATURE: &str = "Invalid capability signature";
const EXPIRED: &str = "Capability has expired";
const WRONG_DEVICE: &str = "Capability is scoped to a different device";
const MISSING_FIELDS: &str = "Capability is missing required fields";
/// `authorize.ts` says exactly this when `recordUse` reports a duplicate nonce.
const REPLAYED: &str = "This emergency access code has already been used.";
/// hbbs-only: the api has no rate limiter, because it is not internet-facing.
const RATE_LIMITED: &str = "Too many emergency access attempts. Please wait a minute.";
/// hbbs-only: the api trusts its own minter, which enforces the same ceiling.
const TOO_LONG_LIVED: &str = "Capability is valid for too long to be accepted.";
/// hbbs-only (T3.6). Deliberately says the access could not be *recorded*
/// rather than that it was refused: it points the operator at the host, which
/// is where the fix is.
const AUDIT_UNAVAILABLE: &str =
    "Emergency access could not be recorded on the server, so it was refused.";

#[derive(Clone)]
pub struct BreakglassConfig {
    /// `None` switches the whole path off — T3.5's "off unless
    /// `BREAKGLASS_PUBKEY` is set". Nothing else needs a second switch.
    pub pubkey: Option<sign::PublicKey>,
    pub max_ttl: Duration,
    pub rate_per_minute: u32,
    /// Where the local-first audit goes (T3.6).
    pub audit_log: PathBuf,
    /// Refuse a use that cannot be audited. See the module docs.
    pub audit_required: bool,
    pub reconcile_every: Duration,
}

impl Default for BreakglassConfig {
    fn default() -> Self {
        Self {
            pubkey: None,
            max_ttl: Duration::from_secs(DEFAULT_MAX_TTL_SEC),
            rate_per_minute: DEFAULT_RATE_PER_MINUTE,
            audit_log: PathBuf::from(DEFAULT_AUDIT_LOG),
            audit_required: true,
            reconcile_every: Duration::from_secs(DEFAULT_RECONCILE_SEC),
        }
    }
}

impl std::fmt::Debug for BreakglassConfig {
    /// Hand-written so that a stray `{:?}` cannot print key material. The key
    /// here is public and harmless, but this struct is one field away from not
    /// being, and the habit is cheaper than the audit.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakglassConfig")
            .field("enabled", &self.pubkey.is_some())
            .field("max_ttl", &self.max_ttl)
            .field("rate_per_minute", &self.rate_per_minute)
            .field("audit_log", &self.audit_log)
            .field("audit_required", &self.audit_required)
            .finish()
    }
}

impl BreakglassConfig {
    pub fn from_args() -> ResultType<Self> {
        Self::from_lookup(|name| get_arg_opt(name))
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> ResultType<Self> {
        let defaults = Self::default();
        let raw = get(KEY_PUBKEY).unwrap_or_default();
        let raw = raw.trim();
        let pubkey = if raw.is_empty() {
            None
        } else {
            Some(parse_pubkey(raw)?)
        };

        let max_ttl = match number(&get, KEY_MAX_TTL_SEC)? {
            Some(secs) => Duration::from_secs(secs),
            None => defaults.max_ttl,
        };
        let rate_per_minute = match number(&get, KEY_RATE_PER_MINUTE)? {
            Some(rate) => rate as u32,
            None => defaults.rate_per_minute,
        };

        let audit_log = get(KEY_AUDIT_LOG).unwrap_or_default();
        let audit_log = audit_log.trim();
        let audit_log = if audit_log.is_empty() {
            defaults.audit_log
        } else {
            PathBuf::from(audit_log)
        };
        let audit_required = flag(&get, KEY_AUDIT_REQUIRED).unwrap_or(defaults.audit_required);
        let reconcile_every = match number(&get, KEY_RECONCILE_SEC)? {
            Some(secs) => Duration::from_secs(secs),
            None => defaults.reconcile_every,
        };

        Ok(Self {
            pubkey,
            max_ttl,
            rate_per_minute,
            audit_log,
            audit_required,
            reconcile_every,
        })
    }

    pub fn log(&self) {
        if self.pubkey.is_none() {
            log::info!(
                "{KEY_PUBKEY} is not set — break-glass is off. \
                 An outage of the auth API will lock this server's peers out with no way back in \
                 (docs/PLAN.md D1)."
            );
            return;
        }
        log::info!(
            "break-glass is ARMED: {KEY_MAX_TTL_SEC}={} {KEY_RATE_PER_MINUTE}={} \
             {KEY_AUDIT_LOG}={} {KEY_AUDIT_REQUIRED}={} {KEY_RECONCILE_SEC}={}. \
             Every use is logged at warn level.",
            self.max_ttl.as_secs(),
            self.rate_per_minute,
            self.audit_log.display(),
            yn(self.audit_required),
            self.reconcile_every.as_secs(),
        );
        if !self.audit_required {
            log::warn!(
                "{KEY_AUDIT_REQUIRED}=N — an emergency access that cannot be written to \
                 {} will be allowed anyway, and there will be no record of it on this host. \
                 See TASK.md T3.6.",
                self.audit_log.display()
            );
        }
    }
}

/// A capability's payload, after the signature checked out.
#[derive(Debug, Clone, PartialEq, Eq, serde_derive::Deserialize)]
pub struct Capability {
    pub admin_id: String,
    pub to_id: String,
    /// Unix seconds. Signed, so not attacker-controlled beyond what the private
    /// key holder chose.
    pub exp: i64,
    /// Unique per mint, single use — and it doubles as the `conn_audit_ref`, so
    /// that a break-glass session is attributable and therefore revocable the
    /// same way every other session is (`authorize.ts` does the same).
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Verified, unspent, in date, and for this device. The caller must
    /// `log::warn!` it — T3.5.
    Allow(Capability),
    /// Refused. The string is shown to the operator verbatim.
    Refuse(String),
}

impl Outcome {
    fn refuse(reason: &str) -> Self {
        Self::Refuse(reason.to_owned())
    }
}

/// Is this token a break-glass capability rather than a user access token?
///
/// Only a prefix test, and that is all it should be: a malformed capability has
/// to be *refused as a capability*, not fall through to the api as if it were a
/// login token — which would put "Your session has expired" on the screen of an
/// operator whose real problem is a typo in the thing they pasted.
pub fn looks_like(token: &str) -> bool {
    token.starts_with(PREFIX)
}

struct Window {
    count: u32,
    started: Instant,
}

/// Verifier plus the two pieces of state that make it safe to expose: which
/// nonces have been spent, and how often each address has tried.
pub struct Breakglass {
    config: BreakglassConfig,
    /// Shared with the reconciler task, which reads what this writes.
    audit: std::sync::Arc<AuditLog>,
    /// nonce → the `exp` it was minted with. Kept until then, which is exactly
    /// "inside the validity window": past `exp` the capability is refused by the
    /// expiry check anyway, so remembering it longer buys nothing and costs
    /// unbounded memory.
    spent: Mutex<HashMap<String, i64>>,
    per_ip: Mutex<HashMap<String, Window>>,
    global: Mutex<Window>,
}

impl Breakglass {
    pub fn new(config: BreakglassConfig) -> Self {
        let audit = std::sync::Arc::new(AuditLog::new(&config.audit_log));
        Self {
            config,
            audit,
            spent: Mutex::new(HashMap::new()),
            per_ip: Mutex::new(HashMap::new()),
            global: Mutex::new(Window {
                count: 0,
                started: Instant::now(),
            }),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.pubkey.is_some()
    }

    /// Unspent capabilities currently remembered, for T3.7's console counter.
    pub fn spent_nonces(&self) -> usize {
        self.spent.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn audit(&self) -> std::sync::Arc<AuditLog> {
        self.audit.clone()
    }

    pub fn reconcile_every(&self) -> Duration {
        self.config.reconcile_every
    }

    /// The whole decision, with no network call and no lock held across one.
    ///
    /// Order matters and is not the order the fields appear in. Cheap, local
    /// refusals come first; the signature check — the only part that costs real
    /// CPU — comes after the rate limiter; and the nonce is spent **last**, so
    /// that a capability refused for being expired or for the wrong device is
    /// not also burned.
    pub fn decide(&self, token: &str, to_id: &str, from_ip: &str) -> Outcome {
        let Some(pubkey) = self.config.pubkey.as_ref() else {
            return Outcome::refuse(NOT_ENABLED);
        };

        // Before the crypto, deliberately: this is reachable by anyone who can
        // open a TCP connection to the rendezvous port.
        if !self.allow_attempt(from_ip) {
            log::warn!("break-glass rate limit hit from {from_ip} for {to_id}");
            return Outcome::refuse(RATE_LIMITED);
        }

        let body = &token[PREFIX.len()..];
        let mut parts = body.split('.');
        let (Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Outcome::refuse(MALFORMED);
        };

        // `from_bytes`, not `from_slice`: sodiumoxide 0.2 re-exports the
        // `ed25519` crate's `Signature`, which takes a fixed-size array and
        // rejects anything else by length.
        let Some(signature) = b64(sig_b64).and_then(|raw| sign::Signature::from_bytes(&raw).ok())
        else {
            return Outcome::refuse(UNCHECKABLE);
        };
        // Over the base64url text, not the decoded JSON. See the module docs.
        if !sign::verify_detached(&signature, payload_b64.as_bytes(), pubkey) {
            log::warn!("break-glass capability with a bad signature from {from_ip} for {to_id}");
            return Outcome::refuse(BAD_SIGNATURE);
        }

        // Only now is the payload worth parsing: everything below this line was
        // signed by the holder of the private key.
        let Some(raw) = b64(payload_b64) else {
            return Outcome::refuse(MALFORMED_PAYLOAD);
        };
        let Ok(cap) = serde_json::from_slice::<Capability>(&raw) else {
            return Outcome::refuse(MALFORMED_PAYLOAD);
        };

        if cap.admin_id.is_empty() || cap.nonce.is_empty() {
            return Outcome::refuse(MISSING_FIELDS);
        }
        if cap.to_id != to_id {
            log::warn!(
                "break-glass capability for {:?} presented at {to_id} by admin {:?} from {from_ip}",
                cap.to_id,
                cap.admin_id
            );
            return Outcome::refuse(WRONG_DEVICE);
        }

        let now = now() as i64;
        if cap.exp <= now {
            return Outcome::refuse(EXPIRED);
        }
        if cap.exp - now > self.config.max_ttl.as_secs() as i64 {
            log::warn!(
                "break-glass capability from admin {:?} is valid for {}s, over the {}s ceiling",
                cap.admin_id,
                cap.exp - now,
                self.config.max_ttl.as_secs()
            );
            return Outcome::refuse(TOO_LONG_LIVED);
        }

        let first_use = self.spend(&cap.nonce, cap.exp, now);
        let outcome = if first_use { OUTCOME_USED } else { OUTCOME_REPLAY };

        // T3.6, and the order is the feature: the record is on disk and fsynced
        // *before* this function returns, so it survives the power cut the
        // operator may be breaking glass to investigate. Replays are recorded
        // too — a replayed capability is exactly the kind of event somebody
        // wants to see afterwards, and `services/breakglass.ts` files them the
        // same way.
        if let Err(err) = self.audit.append(&AuditRecord {
            at: timestamp(),
            admin_id: cap.admin_id.clone(),
            to_id: to_id.to_owned(),
            nonce: cap.nonce.clone(),
            from_ip: from_ip.to_owned(),
            outcome: outcome.to_owned(),
        }) {
            log::error!(
                "could not write the break-glass audit to {}: {err}",
                self.config.audit_log.display()
            );
            if self.config.audit_required {
                // The nonce stays spent. Handing back a capability that is
                // already burned would be worse than refusing: the operator
                // would retry it and be told it was replayed, which points at
                // the wrong problem entirely.
                return Outcome::refuse(AUDIT_UNAVAILABLE);
            }
            log::warn!(
                "{KEY_AUDIT_REQUIRED}=N: allowing an emergency access with no local record"
            );
        }

        if !first_use {
            log::warn!(
                "break-glass capability REPLAYED: admin {:?} device {to_id} from {from_ip}",
                cap.admin_id
            );
            return Outcome::refuse(REPLAYED);
        }

        // T3.5: every use, at warn level. This is the line an operator greps for
        // when asking "did anyone use the emergency path last night".
        log::warn!(
            "BREAK-GLASS USED: admin {:?} -> device {to_id} from {from_ip}, \
             expires in {}s, nonce {}",
            cap.admin_id,
            cap.exp - now,
            cap.nonce
        );
        Outcome::Allow(cap)
    }

    /// `false` once the window is full. Counts every attempt that gets this far,
    /// successes included — a flood of *valid* capabilities is no less a flood.
    fn allow_attempt(&self, from_ip: &str) -> bool {
        let now = Instant::now();
        if let Ok(mut global) = self.global.lock() {
            if now.duration_since(global.started) >= RATE_WINDOW {
                global.count = 0;
                global.started = now;
            }
            if global.count >= GLOBAL_RATE_PER_MINUTE {
                return false;
            }
            global.count += 1;
        }

        // An empty `from_ip` would otherwise make every caller share one bucket.
        // It cannot happen from either chokepoint — both fill it in — but the
        // failure mode if it ever did is "the emergency path is rate limited
        // globally", which is the worst possible time to discover a typo.
        if from_ip.is_empty() {
            return true;
        }
        let Ok(mut per_ip) = self.per_ip.lock() else {
            return true;
        };
        if per_ip.len() > 10_000 {
            per_ip.retain(|_, w| now.duration_since(w.started) < RATE_WINDOW);
        }
        let window = per_ip.entry(from_ip.to_owned()).or_insert(Window {
            count: 0,
            started: now,
        });
        if now.duration_since(window.started) >= RATE_WINDOW {
            window.count = 0;
            window.started = now;
        }
        if window.count >= self.config.rate_per_minute {
            return false;
        }
        window.count += 1;
        true
    }

    /// Records the nonce as spent. `false` if it already was — a replay.
    fn spend(&self, nonce: &str, exp: i64, now: i64) -> bool {
        let Ok(mut spent) = self.spent.lock() else {
            // A poisoned lock here would mean allowing an unlimited replay, so
            // this one fails closed. Unlike the brokerage ledger, refusing costs
            // one capability and not a fleet's connectivity.
            return false;
        };
        // Cheap and bounded: everything past its own `exp` is refused by the
        // expiry check regardless, so it has no reason to stay remembered.
        spent.retain(|_, e| *e > now);
        if spent.contains_key(nonce) {
            return false;
        }
        spent.insert(nonce.to_owned(), exp);
        true
    }
}

/// Node's `base64url` is URL-safe and unpadded, but `Buffer.from(x, "base64url")`
/// accepts far more than it produces, and a capability is pasted by hand into a
/// TOML file. Being lenient about the alphabet and the padding costs four tries
/// and avoids refusing a capability that the api would have accepted — which
/// would be the two implementations disagreeing, the one outcome the operator
/// cannot debug.
fn b64(text: &str) -> Option<Vec<u8>> {
    for config in [
        base64::URL_SAFE_NO_PAD,
        base64::URL_SAFE,
        base64::STANDARD_NO_PAD,
        base64::STANDARD,
    ] {
        if let Ok(raw) = base64::decode_config(text, config) {
            return Some(raw);
        }
    }
    None
}

/// Boot-time, so a mistyped key is a refusal to start rather than an emergency
/// path that silently does not work — which would be discovered during the
/// emergency.
fn parse_pubkey(raw: &str) -> ResultType<sign::PublicKey> {
    let Some(bytes) = b64(raw) else {
        bail!("{KEY_PUBKEY} is not valid base64. Use the value printed by `pnpm --filter api breakglass:keygen`.");
    };
    if bytes.len() != PUBKEY_LEN {
        bail!(
            "{KEY_PUBKEY} decoded to {} bytes, expected {PUBKEY_LEN}. \
             `keygen-breakglass.ts` prints the raw key with the DER prefix already stripped — \
             a {}-byte value is usually the full SubjectPublicKeyInfo.",
            bytes.len(),
            PUBKEY_LEN + 12,
        );
    }
    sign::PublicKey::from_slice(&bytes)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("{KEY_PUBKEY} is not a valid ed25519 key"))
}

/// `Y`/`N`, the same shape as the `AUTH_*` keys and `ALWAYS_USE_RELAY`.
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

fn number(get: &impl Fn(&str) -> Option<String>, name: &str) -> ResultType<Option<u64>> {
    let raw = get(name).unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    match raw.parse::<u64>() {
        Ok(0) => bail!("{name} must be greater than 0"),
        Ok(value) => Ok(Some(value)),
        // Refused rather than defaulted, like the `AUTH_*` numbers: these bound
        // a security check and a typo must not quietly restore the default.
        Err(_) => bail!("{name} must be a whole number, got {raw:?}"),
    }
}

// ---------------------------------------------------------------------------
// Local-first audit and reconciliation — TASK.md T3.6
// ---------------------------------------------------------------------------

/// One line of the audit log, and one element of a reconciliation POST.
///
/// Refusals that never got past the signature check are **not** recorded here.
/// They are noise an unauthenticated internet-facing port can generate at will,
/// and a file an attacker can grow is a file that stops being written when it
/// matters. They are logged instead, where a rotation policy already applies.
#[derive(Debug, Clone, PartialEq, Eq, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct AuditRecord {
    /// RFC3339 UTC. Written by hbbs, which may be the only clock that saw this.
    pub at: String,
    pub admin_id: String,
    pub to_id: String,
    pub nonce: String,
    pub from_ip: String,
    /// `used` or `replay`. The api's own file has no such field because its
    /// unique index makes the distinction for it; hbbs has to say so itself, or
    /// a reconciled replay is indistinguishable from a reconciled first use.
    ///
    /// `String` rather than `&'static str` so that `Deserialize` owns its data:
    /// a borrowing field would tie every parsed record to the line buffer it
    /// came from, which is reused for the next line.
    pub outcome: String,
}

pub const OUTCOME_USED: &str = "used";
pub const OUTCOME_REPLAY: &str = "replay";

/// The append-only file, and the cursor saying how much of it `apps/api` has.
///
/// Two files rather than a rewritten one: the audit itself must never be
/// rewritten, moved, or truncated by this process — an operator reading it
/// during an outage is one of its two jobs — so progress is tracked beside it.
/// A crash between a successful POST and the cursor write replays a record, and
/// the api's unique index on `nonce` absorbs that; the other order would lose
/// one, which is the failure that matters.
pub struct AuditLog {
    path: PathBuf,
    cursor_path: PathBuf,
    /// Serialises appends against each other and against the reconciler's read.
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(path: &Path) -> Self {
        let mut cursor_path = path.as_os_str().to_owned();
        cursor_path.push(".cursor");
        Self {
            path: path.to_owned(),
            cursor_path: PathBuf::from(cursor_path),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one record and **fsyncs** before returning.
    ///
    /// The fsync is the difference between this feature working and appearing
    /// to: a buffered write is lost by the same power cut or kernel panic that
    /// an operator was breaking glass to investigate. It costs a disk round trip
    /// on a path that has already skipped an HTTP request, so the budget is
    /// there.
    pub fn append(&self, record: &AuditRecord) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        let _guard = self.lock.lock();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&line)?;
        file.sync_all()
    }

    /// Records `apps/api` has not acknowledged, oldest first, with the byte
    /// offset that follows the last of them.
    fn pending(&self, limit: usize) -> std::io::Result<(u64, Vec<AuditRecord>)> {
        let _guard = self.lock.lock();
        let (start, marked) = self.cursor();
        let mut file = std::fs::File::open(&self.path)?;
        let len = file.metadata()?.len();
        let prefix = Self::prefix_hash(&mut file)?;
        // A truncated or replaced file — log rotation, or a hand-edit — must not
        // leave the cursor pointing into a different file. Length alone cannot
        // detect that: rotate, write one record of the same size, and the offset
        // still lands exactly at the end, so the reconciler goes *silently*
        // idle. The file is append-only, so its opening bytes never change while
        // it is the same file; a changed prefix means a new one, and the cursor
        // goes back to zero. Duplicates are free — the api's unique index
        // absorbs them — and silence is not.
        let replaced = marked.is_some_and(|m| m != prefix);
        let start = if start > len || replaced { 0 } else { start };
        file.seek(SeekFrom::Start(start))?;

        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(file);
        let mut offset = start;
        let mut records = Vec::new();
        let mut line = String::new();
        while records.len() < limit {
            line.clear();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                break;
            }
            // A partial final line means a crash mid-append. Stop before it and
            // pick it up next tick, when it is either complete or overwritten.
            if !line.ends_with('\n') {
                break;
            }
            offset += read as u64;
            match serde_json::from_str::<AuditRecord>(line.trim_end()) {
                Ok(record) => records.push(record),
                // Skipped, not retried forever: one unparseable line must not
                // wedge every record behind it. It stays in the file.
                Err(err) => log::warn!(
                    "unparseable break-glass audit line at byte {}: {err}",
                    offset - read as u64
                ),
            }
        }
        Ok((offset, records))
    }

    /// Identifies the file the offset belongs to.
    ///
    /// The log is append-only, so its opening bytes are fixed for as long as it
    /// is the same file. Hashing them is a portable stand-in for an inode —
    /// `MetadataExt::ino` is not available on the Windows build.
    fn prefix_hash(file: &mut std::fs::File) -> std::io::Result<String> {
        use std::io::Read;
        let here = file.stream_position()?;
        file.seek(SeekFrom::Start(0))?;
        let mut head = [0u8; 256];
        let mut filled = 0;
        while filled < head.len() {
            match file.read(&mut head[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        file.seek(SeekFrom::Start(here))?;
        let digest = sodiumoxide::crypto::hash::sha256::hash(&head[..filled]);
        Ok(digest.0.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// `(offset, prefix hash)`. The hash is `None` for a hand-written cursor
    /// holding a bare number, which is then trusted as-is.
    fn cursor(&self) -> (u64, Option<String>) {
        let Ok(text) = std::fs::read_to_string(&self.cursor_path) else {
            return (0, None);
        };
        let mut parts = text.trim().split_whitespace();
        let offset = parts.next().and_then(|n| n.parse::<u64>().ok()).unwrap_or(0);
        (offset, parts.next().map(str::to_owned))
    }

    /// Fsynced too. A cursor that is lost re-sends records the api already has,
    /// which its unique index absorbs; a cursor that is *ahead* of what the api
    /// received would lose them silently.
    fn set_cursor(&self, offset: u64) -> std::io::Result<()> {
        let prefix = match std::fs::File::open(&self.path) {
            Ok(mut file) => Self::prefix_hash(&mut file)?,
            Err(_) => String::new(),
        };
        let mut file = std::fs::File::create(&self.cursor_path)?;
        file.write_all(format!("{offset} {prefix}").as_bytes())?;
        file.sync_all()
    }

    /// Unreconciled records, for T3.7's console counter.
    pub fn pending_count(&self) -> usize {
        self.pending(usize::MAX).map(|(_, r)| r.len()).unwrap_or(0)
    }
}

/// Replays the local audit to `apps/api` once it is answering again — T3.6.
///
/// Runs as its own task, ticking slowly. Nothing depends on it being prompt:
/// the records are already durable, and this is the catch-up, not the delivery
/// path. It is also deliberately dumb — read a batch, POST it, advance the
/// cursor — because the interesting failure is not "the POST failed" (it will,
/// that is the premise) but "the cursor advanced past something the api never
/// received", so the cursor moves only after a 2xx.
pub struct Reconciler {
    audit: std::sync::Arc<AuditLog>,
    client: reqwest::Client,
    url: String,
    secret: String,
    every: Duration,
}

/// `POST` target on the api server. `apps/api/src/routes/internal/breakglass.ts`.
pub const RECONCILE_PATH: &str = "/api/internal/breakglass/reconcile";

impl Reconciler {
    /// `None` when there is nothing to reconcile *to* — break-glass disarmed, or
    /// no api configured. Both are ordinary, and neither should spawn a task
    /// that wakes up forever to do nothing.
    pub fn new(
        audit: std::sync::Arc<AuditLog>,
        api_url: &str,
        api_secret: &str,
        timeout: Duration,
        every: Duration,
        armed: bool,
    ) -> Option<Self> {
        if !armed || api_url.is_empty() || api_secret.is_empty() {
            return None;
        }
        let client = reqwest::Client::builder()
            // Generous next to the 300 ms connect budget: nobody is waiting on
            // this, and a slow api is better caught up with than given up on.
            .timeout(timeout.max(Duration::from_secs(5)))
            .no_proxy()
            .user_agent(format!("hbbs/{}", crate::version::VERSION))
            .build()
            .ok()?;
        Some(Self {
            audit,
            client,
            url: format!("{api_url}{RECONCILE_PATH}"),
            secret: api_secret.to_owned(),
            every,
        })
    }

    /// Never returns. Spawn it.
    pub async fn run(self) {
        let mut ticker = hbb_common::tokio::time::interval(self.every);
        // The default `Burst` behaviour would fire back-to-back ticks to catch
        // up after a long api outage, which is the one moment a stampede is
        // least welcome.
        ticker.set_missed_tick_behavior(hbb_common::tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match self.tick().await {
                Ok(0) => {}
                Ok(n) => log::info!("reconciled {n} break-glass audit record(s) to the api"),
                Err(err) => log::debug!("break-glass reconciliation deferred: {err:#}"),
            }
        }
    }

    /// One batch. Returns how many records the api accepted.
    pub async fn tick(&self) -> ResultType<usize> {
        let audit = self.audit.clone();
        // The read is blocking file I/O, and this runs on the same runtime that
        // brokers connections.
        let (offset, records) =
            hbb_common::tokio::task::spawn_blocking(move || audit.pending(RECONCILE_BATCH)).await??;
        if records.is_empty() {
            return Ok(0);
        }
        let count = records.len();
        let response = self
            .client
            .post(&self.url)
            .header(SECRET_HEADER, &self.secret)
            .json(&serde_json::json!({ "uses": records }))
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            bail!("{RECONCILE_PATH} answered {status}");
        }
        let audit = self.audit.clone();
        hbb_common::tokio::task::spawn_blocking(move || audit.set_cursor(offset)).await??;
        Ok(count)
    }
}

/// The header `apps/api` authenticates hbbs with, shared with `auth.rs`.
const SECRET_HEADER: &str = "x-hbbs-secret";

/// Timestamp in the shape `apps/api` stores, and a human reads.
pub fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Mints a capability the way `apps/api/src/scripts/mint-breakglass.ts` does.
///
/// **Unit-test support only.** hbbs holds no private key and must never mint
/// one in production; this exists so that the verifier can be driven with
/// capabilities that are real rather than hand-assembled, which is the only way
/// to catch the two ends disagreeing about what the signature covers.
/// `tests/t35_breakglass.rs` keeps its own copy for the same reason in reverse:
/// an independent re-implementation cannot hide a bug behind a shared helper.
#[cfg(test)]
pub fn mint_for_test(
    sk: &sign::SecretKey,
    admin_id: &str,
    to_id: &str,
    exp: i64,
    nonce: &str,
) -> String {
    let payload = format!(
        r#"{{"admin_id":"{admin_id}","to_id":"{to_id}","exp":{exp},"nonce":"{nonce}"}}"#
    );
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    let sig = sign::sign_detached(payload_b64.as_bytes(), sk);
    let sig_b64 = base64::encode_config(sig.as_ref(), base64::URL_SAFE_NO_PAD);
    format!("{PREFIX}{payload_b64}.{sig_b64}")
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

    /// A keypair and a minting function that follow `mint-breakglass.ts`
    /// exactly — including signing the base64url **text**, which is the detail
    /// the rest of this file turns on.
    fn keypair() -> (sign::PublicKey, sign::SecretKey) {
        sodiumoxide::init().ok();
        sign::gen_keypair()
    }

    fn mint(sk: &sign::SecretKey, admin: &str, device: &str, exp: i64, nonce: &str) -> String {
        mint_for_test(sk, admin, device, exp, nonce)
    }

    /// Every `Breakglass` in these tests writes a real audit file, because
    /// `decide` refuses a use it cannot record (T3.6) — so each needs a path of
    /// its own, or tests running in parallel would interleave their records.
    fn temp_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "bg-{tag}-{}-{}.log",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn armed(pk: sign::PublicKey) -> Breakglass {
        Breakglass::new(BreakglassConfig {
            pubkey: Some(pk),
            audit_log: temp_path("armed"),
            ..Default::default()
        })
    }

    fn in_mins(mins: i64) -> i64 {
        now() as i64 + mins * 60
    }

    #[test]
    fn a_token_is_a_capability_only_by_its_prefix() {
        assert!(looks_like("bg.abc.def"));
        assert!(!looks_like("a-perfectly-ordinary-access-token"));
        assert!(!looks_like(""));
    }

    #[test]
    fn it_is_off_until_a_public_key_is_configured() {
        let config = BreakglassConfig::from_lookup(lookup(&[])).unwrap();
        assert!(config.pubkey.is_none());

        let bg = Breakglass::new(config);
        assert!(!bg.enabled());
        let (_, sk) = keypair();
        let token = mint(&sk, "alice", "dev-1", in_mins(10), "n1");
        assert_eq!(bg.decide(&token, "dev-1", "1.2.3.4"), Outcome::refuse(NOT_ENABLED));
    }

    #[test]
    fn a_valid_capability_authorizes_once() {
        let (pk, sk) = keypair();
        let bg = armed(pk);
        let token = mint(&sk, "alice", "dev-1", in_mins(10), "nonce-1");

        match bg.decide(&token, "dev-1", "1.2.3.4") {
            Outcome::Allow(cap) => {
                assert_eq!(cap.admin_id, "alice");
                assert_eq!(cap.to_id, "dev-1");
                // The nonce is the conn_audit_ref, which is what makes a
                // break-glass session revocable like any other.
                assert_eq!(cap.nonce, "nonce-1");
            }
            other => panic!("refused a valid capability: {other:?}"),
        }
        // …and exactly once.
        assert_eq!(bg.decide(&token, "dev-1", "1.2.3.4"), Outcome::refuse(REPLAYED));
    }

    #[test]
    fn a_capability_for_another_device_is_refused() {
        let (pk, sk) = keypair();
        let bg = armed(pk);
        let token = mint(&sk, "alice", "dev-1", in_mins(10), "nonce-2");
        assert_eq!(
            bg.decide(&token, "dev-2", "1.2.3.4"),
            Outcome::refuse(WRONG_DEVICE)
        );
        // Refused, and **not spent** — the real device must still work.
        assert!(matches!(bg.decide(&token, "dev-1", "1.2.3.4"), Outcome::Allow(_)));
    }

    #[test]
    fn an_expired_capability_is_refused_and_not_spent() {
        let (pk, sk) = keypair();
        let bg = armed(pk);
        let token = mint(&sk, "alice", "dev-1", in_mins(-1), "nonce-3");
        assert_eq!(bg.decide(&token, "dev-1", "1.2.3.4"), Outcome::refuse(EXPIRED));
        assert_eq!(bg.spent_nonces(), 0);
    }

    #[test]
    fn a_capability_valid_for_longer_than_the_ceiling_is_refused() {
        let (pk, sk) = keypair();
        let bg = armed(pk);
        // The minter refuses over 4 hours; this is a year, which is what a
        // leaked private key would mint.
        let token = mint(&sk, "alice", "dev-1", in_mins(60 * 24 * 365), "nonce-4");
        assert_eq!(
            bg.decide(&token, "dev-1", "1.2.3.4"),
            Outcome::refuse(TOO_LONG_LIVED)
        );
    }

    #[test]
    fn the_minters_own_ceiling_is_still_accepted() {
        // 4 hours is what `mint-breakglass.ts` allows at most. If this fails,
        // the two ends have drifted and real capabilities are being refused.
        let (pk, sk) = keypair();
        let bg = armed(pk);
        let token = mint(&sk, "alice", "dev-1", in_mins(240), "nonce-5");
        assert!(matches!(bg.decide(&token, "dev-1", "1.2.3.4"), Outcome::Allow(_)));
    }

    #[test]
    fn a_forged_or_tampered_capability_is_refused() {
        let (pk, sk) = keypair();
        let (_, other_sk) = keypair();
        let bg = armed(pk);

        // Signed with the wrong key.
        let token = mint(&other_sk, "alice", "dev-1", in_mins(10), "nonce-6");
        assert_eq!(
            bg.decide(&token, "dev-1", "1.2.3.4"),
            Outcome::refuse(BAD_SIGNATURE)
        );

        // Signed correctly, then the payload swapped for one naming a different
        // device — the attack the signature exists to stop.
        let real = mint(&sk, "alice", "dev-1", in_mins(10), "nonce-7");
        let sig = real.rsplit('.').next().unwrap();
        let forged_payload = base64::encode_config(
            format!(
                r#"{{"admin_id":"alice","to_id":"dev-9","exp":{},"nonce":"nonce-7"}}"#,
                in_mins(10)
            ),
            base64::URL_SAFE_NO_PAD,
        );
        assert_eq!(
            bg.decide(&format!("{PREFIX}{forged_payload}.{sig}"), "dev-9", "1.2.3.4"),
            Outcome::refuse(BAD_SIGNATURE)
        );
    }

    #[test]
    fn malformed_capabilities_are_refused_as_capabilities() {
        let (pk, _) = keypair();
        let bg = armed(pk);
        // Never forwarded to the api as if it were a login token: an operator
        // who mistyped what they pasted must not be told their session expired.
        assert_eq!(bg.decide("bg.only-one-part", "dev-1", "ip"), Outcome::refuse(MALFORMED));
        assert_eq!(bg.decide("bg.a.b.c", "dev-1", "ip"), Outcome::refuse(MALFORMED));
        assert_eq!(
            bg.decide("bg.payload.not-a-signature", "dev-1", "ip"),
            Outcome::refuse(UNCHECKABLE)
        );
    }

    #[test]
    fn a_signed_payload_that_is_not_the_expected_json_is_refused() {
        let (pk, sk) = keypair();
        let bg = armed(pk);
        let payload_b64 = base64::encode_config("not json at all", base64::URL_SAFE_NO_PAD);
        let sig = sign::sign_detached(payload_b64.as_bytes(), &sk);
        let token = format!(
            "{PREFIX}{payload_b64}.{}",
            base64::encode_config(sig.as_ref(), base64::URL_SAFE_NO_PAD)
        );
        assert_eq!(
            bg.decide(&token, "dev-1", "1.2.3.4"),
            Outcome::refuse(MALFORMED_PAYLOAD)
        );
    }

    #[test]
    fn the_rate_limiter_stops_a_flood_before_the_crypto() {
        let (pk, sk) = keypair();
        let bg = Breakglass::new(BreakglassConfig {
            pubkey: Some(pk),
            rate_per_minute: 3,
            audit_log: temp_path("rate"),
            ..Default::default()
        });
        for i in 0..3 {
            let token = mint(&sk, "alice", "dev-1", in_mins(10), &format!("n{i}"));
            assert!(matches!(bg.decide(&token, "dev-1", "9.9.9.9"), Outcome::Allow(_)));
        }
        let token = mint(&sk, "alice", "dev-1", in_mins(10), "n-over");
        assert_eq!(
            bg.decide(&token, "dev-1", "9.9.9.9"),
            Outcome::refuse(RATE_LIMITED)
        );
        // Per address, not global: another operator is unaffected.
        let token = mint(&sk, "alice", "dev-1", in_mins(10), "n-other");
        assert!(matches!(bg.decide(&token, "dev-1", "8.8.8.8"), Outcome::Allow(_)));
    }

    #[test]
    fn a_public_key_that_is_not_one_refuses_to_boot() {
        assert!(BreakglassConfig::from_lookup(lookup(&[(KEY_PUBKEY, "not base64!!")])).is_err());
        // The whole SubjectPublicKeyInfo rather than the raw key — the mistake
        // the error message names.
        let der = base64::encode(vec![0u8; PUBKEY_LEN + 12]);
        assert!(BreakglassConfig::from_lookup(lookup(&[(KEY_PUBKEY, &der)])).is_err());
        // And a real one boots.
        let (pk, _) = keypair();
        let config =
            BreakglassConfig::from_lookup(lookup(&[(KEY_PUBKEY, &base64::encode(pk.as_ref()))]))
                .unwrap();
        assert_eq!(config.pubkey, Some(pk));
    }

    #[test]
    fn a_bad_number_refuses_to_boot_rather_than_defaulting() {
        let (pk, _) = keypair();
        let key = base64::encode(pk.as_ref());
        assert!(BreakglassConfig::from_lookup(lookup(&[
            (KEY_PUBKEY, key.as_str()),
            (KEY_MAX_TTL_SEC, "half an hour"),
        ]))
        .is_err());
        assert!(BreakglassConfig::from_lookup(lookup(&[
            (KEY_PUBKEY, key.as_str()),
            (KEY_RATE_PER_MINUTE, "0"),
        ]))
        .is_err());
    }

    #[test]
    fn padded_and_standard_base64_are_both_accepted() {
        // A capability is pasted by hand into a TOML file; the api's decoder is
        // lenient, so refusing here would be the two ends disagreeing.
        let (pk, sk) = keypair();
        let bg = armed(pk);
        let payload = format!(
            r#"{{"admin_id":"alice","to_id":"dev-1","exp":{},"nonce":"nonce-8"}}"#,
            in_mins(10)
        );
        let payload_b64 = base64::encode_config(&payload, base64::URL_SAFE_NO_PAD);
        let sig = sign::sign_detached(payload_b64.as_bytes(), &sk);
        let padded = base64::encode_config(sig.as_ref(), base64::URL_SAFE);
        assert!(matches!(
            bg.decide(&format!("{PREFIX}{payload_b64}.{padded}"), "dev-1", "1.2.3.4"),
            Outcome::Allow(_)
        ));
    }

    // ----------------------------------------------------------- T3.6

    fn read_lines(path: &Path) -> Vec<AuditRecord> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<AuditRecord>(l).unwrap())
            .collect()
    }

    #[test]
    fn every_use_is_on_disk_before_the_decision_comes_back() {
        let (pk, sk) = keypair();
        let path = temp_path("local-first");
        let bg = Breakglass::new(BreakglassConfig {
            pubkey: Some(pk),
            audit_log: path.clone(),
            ..Default::default()
        });

        let token = mint(&sk, "alice", "dev-1", in_mins(10), "audit-1");
        assert!(matches!(bg.decide(&token, "dev-1", "203.0.113.9"), Outcome::Allow(_)));

        // Read straight after the call returns — no flush, no sleep. That is
        // the property: the record is durable by the time the connection is.
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].admin_id, "alice");
        assert_eq!(lines[0].to_id, "dev-1");
        assert_eq!(lines[0].nonce, "audit-1");
        assert_eq!(lines[0].from_ip, "203.0.113.9");
        assert_eq!(lines[0].outcome, OUTCOME_USED);
    }

    #[test]
    fn a_replay_is_recorded_too() {
        // A replayed capability is exactly the kind of event somebody wants to
        // see afterwards, so it is filed rather than filtered.
        let (pk, sk) = keypair();
        let path = temp_path("replay");
        let bg = Breakglass::new(BreakglassConfig {
            pubkey: Some(pk),
            audit_log: path.clone(),
            ..Default::default()
        });
        let token = mint(&sk, "alice", "dev-1", in_mins(10), "audit-2");

        assert!(matches!(bg.decide(&token, "dev-1", "ip"), Outcome::Allow(_)));
        assert_eq!(bg.decide(&token, "dev-1", "ip"), Outcome::refuse(REPLAYED));

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].outcome, OUTCOME_USED);
        assert_eq!(lines[1].outcome, OUTCOME_REPLAY);
    }

    #[test]
    fn refusals_that_never_verified_are_not_written_to_the_file() {
        // This file is reachable by anyone who can open a TCP connection to the
        // rendezvous port. A file an attacker can grow is a file that stops
        // being writable when it matters.
        let (pk, sk) = keypair();
        let (_, other_sk) = keypair();
        let path = temp_path("noise");
        let bg = Breakglass::new(BreakglassConfig {
            pubkey: Some(pk),
            audit_log: path.clone(),
            ..Default::default()
        });

        let forged = mint(&other_sk, "mallory", "dev-1", in_mins(10), "audit-3");
        assert_eq!(bg.decide(&forged, "dev-1", "ip"), Outcome::refuse(BAD_SIGNATURE));
        assert_eq!(bg.decide("bg.nonsense", "dev-1", "ip"), Outcome::refuse(MALFORMED));
        let expired = mint(&sk, "alice", "dev-1", in_mins(-1), "audit-4");
        assert_eq!(bg.decide(&expired, "dev-1", "ip"), Outcome::refuse(EXPIRED));

        assert!(read_lines(&path).is_empty());
    }

    #[test]
    fn a_use_that_cannot_be_recorded_is_refused() {
        // The tradeoff stated in the module docs, as an assertion. The path is
        // a **directory**, so every append fails.
        let (pk, sk) = keypair();
        let dir = temp_path("unwritable");
        std::fs::create_dir_all(&dir).unwrap();
        let bg = Breakglass::new(BreakglassConfig {
            pubkey: Some(pk),
            audit_log: dir.clone(),
            ..Default::default()
        });

        let token = mint(&sk, "alice", "dev-1", in_mins(10), "audit-5");
        assert_eq!(
            bg.decide(&token, "dev-1", "ip"),
            Outcome::refuse(AUDIT_UNAVAILABLE)
        );

        // …and `BREAKGLASS_AUDIT_REQUIRED=N` is the documented lever.
        let bg = Breakglass::new(BreakglassConfig {
            pubkey: Some(pk),
            audit_log: dir.clone(),
            audit_required: false,
            ..Default::default()
        });
        let token = mint(&sk, "alice", "dev-1", in_mins(10), "audit-6");
        assert!(matches!(bg.decide(&token, "dev-1", "ip"), Outcome::Allow(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cursor_is_what_stops_a_record_being_sent_twice() {
        let path = temp_path("cursor");
        let log = AuditLog::new(&path);
        for i in 0..3 {
            log.append(&AuditRecord {
                at: timestamp(),
                admin_id: "alice".into(),
                to_id: "dev-1".into(),
                nonce: format!("n{i}"),
                from_ip: "ip".into(),
                outcome: OUTCOME_USED.to_owned(),
            })
            .unwrap();
        }

        let (offset, pending) = log.pending(10).unwrap();
        assert_eq!(pending.len(), 3);
        assert_eq!(log.pending_count(), 3);

        log.set_cursor(offset).unwrap();
        assert_eq!(log.pending(10).unwrap().1.len(), 0);

        // A new record after the cursor is the only thing sent next time.
        log.append(&AuditRecord {
            at: timestamp(),
            admin_id: "alice".into(),
            to_id: "dev-1".into(),
            nonce: "n3".into(),
            from_ip: "ip".into(),
            outcome: OUTCOME_USED.to_owned(),
        })
        .unwrap();
        let (_, pending) = log.pending(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].nonce, "n3");
    }

    #[test]
    fn a_batch_limit_leaves_the_rest_for_the_next_tick() {
        let path = temp_path("batch");
        let log = AuditLog::new(&path);
        for i in 0..5 {
            log.append(&AuditRecord {
                at: timestamp(),
                admin_id: "alice".into(),
                to_id: "dev-1".into(),
                nonce: format!("b{i}"),
                from_ip: "ip".into(),
                outcome: OUTCOME_USED.to_owned(),
            })
            .unwrap();
        }
        let (offset, first) = log.pending(2).unwrap();
        assert_eq!(first.len(), 2);
        log.set_cursor(offset).unwrap();
        let (_, second) = log.pending(2).unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].nonce, "b2");
    }

    #[test]
    fn a_truncated_file_replays_rather_than_going_silent() {
        // Log rotation, or a hand-edit. A cursor past the end would otherwise
        // leave the reconciler idle forever with records it never sent.
        let path = temp_path("rotated");
        let log = AuditLog::new(&path);
        log.append(&AuditRecord {
            at: timestamp(),
            admin_id: "alice".into(),
            to_id: "dev-1".into(),
            nonce: "r0".into(),
            from_ip: "ip".into(),
            outcome: OUTCOME_USED.to_owned(),
        })
        .unwrap();
        let (offset, _) = log.pending(10).unwrap();
        log.set_cursor(offset).unwrap();

        std::fs::write(&path, b"").unwrap();
        log.append(&AuditRecord {
            at: timestamp(),
            admin_id: "alice".into(),
            to_id: "dev-1".into(),
            nonce: "r1".into(),
            from_ip: "ip".into(),
            outcome: OUTCOME_USED.to_owned(),
        })
        .unwrap();

        let (_, pending) = log.pending(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].nonce, "r1");
    }

    #[test]
    fn a_half_written_line_is_left_for_the_next_tick() {
        // A crash mid-append. Sending a truncated record would be worse than
        // waiting for the process that is writing it.
        let path = temp_path("partial");
        let log = AuditLog::new(&path);
        log.append(&AuditRecord {
            at: timestamp(),
            admin_id: "alice".into(),
            to_id: "dev-1".into(),
            nonce: "p0".into(),
            from_ip: "ip".into(),
            outcome: OUTCOME_USED.to_owned(),
        })
        .unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(br#"{"at":"2026-09-15T00:00:00Z","admin_i"#).unwrap();
        drop(f);

        let (_, pending) = log.pending(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].nonce, "p0");
    }

    #[test]
    fn an_unparseable_line_does_not_wedge_the_records_behind_it() {
        let path = temp_path("garbage");
        let log = AuditLog::new(&path);
        std::fs::write(&path, b"this is not json\n").unwrap();
        log.append(&AuditRecord {
            at: timestamp(),
            admin_id: "alice".into(),
            to_id: "dev-1".into(),
            nonce: "g0".into(),
            from_ip: "ip".into(),
            outcome: OUTCOME_USED.to_owned(),
        })
        .unwrap();

        let (_, pending) = log.pending(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].nonce, "g0");
    }

    #[test]
    fn there_is_no_reconciler_without_somewhere_to_reconcile_to() {
        let log = std::sync::Arc::new(AuditLog::new(&temp_path("none")));
        let some = Duration::from_secs(60);
        assert!(Reconciler::new(log.clone(), "http://api", "s", some, some, false).is_none());
        assert!(Reconciler::new(log.clone(), "", "s", some, some, true).is_none());
        assert!(Reconciler::new(log.clone(), "http://api", "", some, some, true).is_none());
        assert!(Reconciler::new(log, "http://api", "s", some, some, true).is_some());
    }
}
