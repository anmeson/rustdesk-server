//! Registration ownership — TASK.md T3.5.2 and T3.5.3.
//!
//! Gating *connections* is not gating *registration*. Upstream's `RegisterPk`
//! arm answers `OK` to any well-formed request, so an unenrolled device can
//! claim a device id and appear online; the punch-hole and relay gates (T3.3,
//! T3.3b) then stop anyone reaching it, but the id is taken and the device is
//! listed. This module answers the other question: **is this device one of
//! ours?**
//!
//! Three things make it a different shape from `auth.rs`, and each one is a
//! constraint the code is built around rather than a preference:
//!
//! **1. It must not fail closed.** Decision D1 is about connection
//! authorization — live state, deny when unknown. Enrolment is durable state,
//! and if it failed closed, an `apps/api` outage would deregister every device
//! in the fleet, they would all drop offline, and break-glass would have nothing
//! left to connect to. So an unreachable api means *keep what we already knew*,
//! and a device we have never heard of is allowed to register while we find out.
//!
//! **2. It must not block.** `handle_udp` is awaited **inline** in `io_loop`
//! (`rendezvous_server.rs:339`) — unlike the TCP path, which spawns per
//! connection (`:1584`). An HTTP call in the `RegisterPk` arm would serialize
//! every datagram the server handles, for the whole fleet, behind one api round
//! trip. So the arm only ever reads an in-memory verdict, and the call happens
//! in a spawned task that writes the verdict for next time. Registration is a
//! 15 s keepalive loop (`REG_INTERVAL`), so "next time" is seconds away.
//!
//! **3. The answer has to survive a restart**, or every hbbs restart would give
//! the whole fleet a free interval of unchecked registration. It is cached in
//! the `peer` table's `user` and `status` columns, which upstream declares,
//! selects, indexes — and never writes. T3.5.3.
//!
//! **`ENROL_REQUIRED` ships off.** Unlike `AUTH_API_URL`, setting the api url is
//! deliberately *not* enough to turn this on: an existing deployment upgrading
//! hbbs would otherwise deregister every device that had not been through
//! `rustdesk --deploy` — a fleet-wide outage produced by installing a patch
//! release. Turning it on is a decision an operator makes once their fleet is
//! enrolled. Same reasoning as `BROKER_STRICT_IP` (T3.8).

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hbb_common::{bail, bytes::Bytes, log, tokio, ResultType};

use crate::auth::AuthConfig;
use crate::common::get_arg_opt;
use crate::database::Database;
use crate::peer::LockPeer;

/// `POST` target on the api server. `apps/api/src/routes/internal/enrolment.ts`.
const ENROLLED_PATH: &str = "/api/internal/enrolled";

/// The api server authenticates hbbs with this header, not with a bearer token.
const SECRET_HEADER: &str = "x-hbbs-secret";

/// How long a verdict is used before it is refreshed.
///
/// Three orders of magnitude longer than the authorization cache, because it is
/// a different kind of fact: "is this device ours" changes when an admin
/// deploys or deletes a device, not when a grant expires. The cost of a stale
/// answer is bounded and small — a deleted device keeps registering for up to
/// this long, and cannot be *connected to* for any of it, because that decision
/// is made separately and is not cached for more than 5 s.
pub const DEFAULT_CACHE_TTL_MS: u64 = 10 * 60 * 1_000;

/// Outbound calls allowed per minute, across all devices.
///
/// **This is the T3.5.2 trap, and it is a separate limit on purpose.**
/// `RegisterPk` is already rate-limited per ip (`check_ip_blocker`) and per peer
/// (`reg_pk`, 3 per 6 s), but neither bounds what *we* do: a thousand devices
/// registering after a network partition are a thousand distinct ids, each one
/// well within its own per-peer limit, and each one a cache miss. Without this,
/// recovering from an outage would arrive at `apps/api` as a stampede.
///
/// Over the limit, a refresh is simply skipped. That is safe in the direction it
/// fails: the device keeps whatever verdict it had, and an unknown device keeps
/// registering — never the reverse.
pub const DEFAULT_RATE_PER_MINUTE: u64 = 120;

const KEY_REQUIRED: &str = "ENROL_REQUIRED";
const KEY_CACHE_TTL_MS: &str = "ENROL_CACHE_TTL_MS";
const KEY_RATE_PER_MINUTE: &str = "ENROL_RATE_PER_MINUTE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentConfig {
    /// Whether a device must be enrolled before it may register.
    pub required: bool,
    pub cache_ttl: Duration,
    pub rate_per_minute: u64,
}

impl Default for EnrolmentConfig {
    fn default() -> Self {
        Self {
            required: false,
            cache_ttl: Duration::from_millis(DEFAULT_CACHE_TTL_MS),
            rate_per_minute: DEFAULT_RATE_PER_MINUTE,
        }
    }
}

impl EnrolmentConfig {
    pub fn from_args(auth: &AuthConfig) -> ResultType<Self> {
        Self::from_lookup(auth, |name| get_arg_opt(name))
    }

    /// Lookup passed in so the tests do not have to mutate the process
    /// environment, which is global and would make them race each other.
    fn from_lookup(auth: &AuthConfig, get: impl Fn(&str) -> Option<String>) -> ResultType<Self> {
        let required = flag(&get, KEY_REQUIRED).unwrap_or(false);
        let config = Self {
            required,
            cache_ttl: Duration::from_millis(millis(&get, KEY_CACHE_TTL_MS, DEFAULT_CACHE_TTL_MS)?),
            rate_per_minute: count(&get, KEY_RATE_PER_MINUTE, DEFAULT_RATE_PER_MINUTE)?,
        };
        config.validate(auth)?;
        Ok(config)
    }

    /// Refused at boot rather than at the first registration, for the same
    /// reason as `AuthConfig::validate`: a server that cannot check enrolment
    /// but thinks it is checking it is worse than one that will not start.
    fn validate(&self, auth: &AuthConfig) -> ResultType<()> {
        if !self.required {
            return Ok(());
        }
        if auth.api_url.is_empty() {
            bail!(
                "{KEY_REQUIRED} is on but AUTH_API_URL is not set. \
                 hbbs would have no way to tell an enrolled device from a stranger."
            );
        }
        if auth.api_secret.is_empty() {
            bail!(
                "{KEY_REQUIRED} is on but AUTH_API_SECRET is not set. \
                 The api server rejects an unauthenticated call, so no device could ever be confirmed."
            );
        }
        Ok(())
    }

    pub fn log(&self) {
        if !self.required {
            log::info!("{KEY_REQUIRED}=N, any device may claim an id (upstream behaviour)");
            return;
        }
        log::info!(
            "{KEY_REQUIRED}=Y {KEY_CACHE_TTL_MS}={} {KEY_RATE_PER_MINUTE}={}",
            self.cache_ttl.as_millis(),
            self.rate_per_minute,
        );
    }
}

/// `Y`/`N`, matching every other flag hbbs reads.
fn flag(get: &impl Fn(&str) -> Option<String>, name: &str) -> Option<bool> {
    let value = get(name)?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.eq_ignore_ascii_case("y") || value.eq_ignore_ascii_case("yes") || value == "1")
}

fn millis(get: &impl Fn(&str) -> Option<String>, name: &str, default: u64) -> ResultType<u64> {
    let raw = get(name).unwrap_or_default().trim().to_owned();
    if raw.is_empty() {
        return Ok(default);
    }
    match raw.parse::<u64>() {
        Ok(0) => bail!("{name} must be greater than 0"),
        Ok(value) => Ok(value),
        Err(_) => bail!("{name} must be a whole number of milliseconds, got {raw:?}"),
    }
}

fn count(get: &impl Fn(&str) -> Option<String>, name: &str, default: u64) -> ResultType<u64> {
    let raw = get(name).unwrap_or_default().trim().to_owned();
    if raw.is_empty() {
        return Ok(default);
    }
    match raw.parse::<u64>() {
        Ok(0) => bail!("{name} must be greater than 0"),
        Ok(value) => Ok(value),
        Err(_) => bail!("{name} must be a whole number, got {raw:?}"),
    }
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// What the `peer` row's `status` column means to us.
///
/// **The column is upstream's and upstream never writes it.** It is declared,
/// selected (`database.rs:96`) and indexed, and the only code that would have
/// read it is commented out (`peer.rs:39,52`, `disabled: v.status == Some(0)`).
/// We give it a meaning; `NULL` keeps meaning "nothing is known", which is what
/// every row written before this feature existed says.
pub const STATUS_REFUSED: i64 = 0;
pub const STATUS_ENROLLED: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Enrolment is off. Upstream's path, unchanged.
    Disabled,
    /// Confirmed by `apps/api`, possibly a while ago.
    Enrolled,
    /// `apps/api` said this device is not ours.
    Refused,
    /// Never confirmed either way. **Allowed to register** — see the header.
    Unknown,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enrolled => "enrolled",
            Self::Refused => "refused",
            Self::Unknown => "unknown",
        }
    }
}

/// The body of a 200 from the api server. `EnrolmentResponse` in
/// `apps/api/src/types.ts`.
///
/// `enrolled` is deliberately **not** `#[serde(default)]`: a body missing it is
/// a contract break, and it must not decode as a refusal. A refusal is only ever
/// something that explicitly said `"enrolled": false`.
#[derive(Debug, Clone, serde_derive::Deserialize)]
struct ApiEnrolment {
    enrolled: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
}

/// Holds the HTTP client and the outbound rate limit for the lifetime of the
/// process. The *verdicts* live on the peers themselves (T3.5.3), so there is
/// no cache here to go stale differently from the peer map.
pub struct Enrolment {
    config: EnrolmentConfig,
    auth: AuthConfig,
    /// `None` when enrolment is off, so the disabled path cannot make a call by
    /// accident.
    client: Option<reqwest::Client>,
    /// Ids with a refresh in flight. Three datagrams arriving together are one
    /// call, not three.
    inflight: Mutex<HashSet<String>>,
    /// Token bucket for the global limit above: `(tokens, refilled_at)`.
    budget: Mutex<(u64, Instant)>,
}

impl Enrolment {
    pub fn new(config: EnrolmentConfig, auth: AuthConfig) -> ResultType<Self> {
        let client = if config.required {
            Some(
                reqwest::Client::builder()
                    .timeout(auth.timeout)
                    .connect_timeout(auth.timeout)
                    // Same reasoning as `auth::build_client`: an ambient
                    // HTTP_PROXY would route the shared secret through whatever
                    // that variable names.
                    .no_proxy()
                    .user_agent(format!("hbbs/{}", crate::version::VERSION))
                    .build()?,
            )
        } else {
            None
        };
        let rate = config.rate_per_minute;
        Ok(Self {
            config,
            auth,
            client,
            inflight: Mutex::new(HashSet::new()),
            budget: Mutex::new((rate, Instant::now())),
        })
    }

    pub fn enabled(&self) -> bool {
        self.config.required
    }

    /// The verdict for a peer, read from memory only. **Never awaits anything**
    /// — this is called from `io_loop` (see the header).
    ///
    /// `checked_at` is the in-memory stamp, so a verdict loaded from the
    /// database at startup is treated as due for a refresh immediately while
    /// still being *used* — which is exactly the intent: warm, and re-verified
    /// once, without a window where the fleet is unchecked.
    pub fn verdict(&self, status: Option<i64>) -> Verdict {
        if !self.config.required {
            return Verdict::Disabled;
        }
        match status {
            Some(STATUS_ENROLLED) => Verdict::Enrolled,
            Some(STATUS_REFUSED) => Verdict::Refused,
            // Some other number is a value we did not write. Unknown, not
            // refused: guessing at a foreign encoding is how a fleet goes dark.
            Some(_) => Verdict::Unknown,
            None => Verdict::Unknown,
        }
    }

    pub fn stale(&self, checked_at: Instant) -> bool {
        checked_at.elapsed() >= self.config.cache_ttl
    }

    /// Takes one token from the global budget, or refuses.
    fn afford(&self) -> bool {
        let Ok(mut budget) = self.budget.lock() else {
            return false;
        };
        let (ref mut tokens, ref mut refilled_at) = *budget;
        if refilled_at.elapsed() >= Duration::from_secs(60) {
            *tokens = self.config.rate_per_minute;
            *refilled_at = Instant::now();
        }
        if *tokens == 0 {
            return false;
        }
        *tokens -= 1;
        true
    }

    fn claim(&self, id: &str) -> bool {
        match self.inflight.lock() {
            Ok(mut set) => set.insert(id.to_owned()),
            Err(_) => false,
        }
    }

    fn release(&self, id: &str) {
        if let Ok(mut set) = self.inflight.lock() {
            set.remove(id);
        }
    }

    /// One round trip. Anything other than a 2xx with a parseable body is an
    /// error, never a refusal — including the api server's own 401 and 400,
    /// whose bodies deliberately carry no `enrolled` field at all.
    async fn ask(&self, id: &str, uuid: &Bytes, pk: &Bytes) -> ResultType<ApiEnrolment> {
        let Some(client) = self.client.as_ref() else {
            bail!("enrolment is enabled but no http client was built");
        };
        let body = serde_json::json!({
            "id": id,
            // base64 of the raw bytes, which is how `POST /api/devices/deploy`
            // stores them. Confirmed byte-for-byte against a real client in
            // T3.5.1 — the uuid in Mongo and the uuid blob in hbbs's own peer
            // table are the same bytes.
            "uuid": base64::encode_config(uuid, base64::STANDARD),
            "pk": base64::encode_config(pk, base64::STANDARD),
        });
        let response = client
            .post(format!("{}{ENROLLED_PATH}", self.auth.api_url))
            .header(SECRET_HEADER, &self.auth.api_secret)
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            bail!("{ENROLLED_PATH} answered {status}: {}", clip(&detail, 200));
        }
        let raw = response.text().await?;
        serde_json::from_str::<ApiEnrolment>(&raw)
            .map_err(|err| hbb_common::anyhow::anyhow!(
                "{ENROLLED_PATH} answered unparseable json ({err}): {}",
                clip(&raw, 200)
            ))
    }
}

fn clip(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max {
        return text.to_owned();
    }
    text.chars().take(max).collect::<String>() + "…"
}

/// Asks `apps/api` about one device, in the background, and writes the answer
/// where the next `RegisterPk` will find it.
///
/// Spawned and never awaited by the caller — that is the whole point (header,
/// point 2). It is safe to call on every datagram: `claim` collapses concurrent
/// calls for one id, and `afford` bounds the total.
///
/// **A failed call writes nothing.** Not a refusal, not a "not enrolled", not
/// even a fresh timestamp: the peer keeps the verdict it had, and the next
/// registration tries again. That is T3.5.3's rule in one place.
pub(crate) fn refresh(
    enrolment: std::sync::Arc<Enrolment>,
    db: Database,
    peer: LockPeer,
    id: String,
    uuid: Bytes,
    pk: Bytes,
) {
    if !enrolment.enabled() {
        return;
    }
    if !enrolment.claim(&id) {
        return;
    }
    if !enrolment.afford() {
        enrolment.release(&id);
        log::debug!("enrol id={id} outcome=skipped reason=rate-limited");
        return;
    }
    tokio::spawn(async move {
        let started = Instant::now();
        let answer = enrolment.ask(&id, &uuid, &pk).await;
        enrolment.release(&id);
        match answer {
            Ok(api) => {
                let status = if api.enrolled {
                    STATUS_ENROLLED
                } else {
                    STATUS_REFUSED
                };
                let user = api.user_id.map(|u| u.into_bytes());
                {
                    let mut w = peer.write().await;
                    w.status = Some(status);
                    w.user = user.clone();
                    w.enrol_checked = Instant::now();
                }
                // Keyed on `id` rather than `guid` because the row may not exist
                // yet: a device registering for the first time is inserted by
                // `update_pk` in the same arm that spawned this, and the two
                // race. Zero rows updated is normal and not an error — the
                // in-memory verdict above is already correct, and the next
                // refresh persists it.
                if let Err(err) = db.set_peer_enrolment(&id, user.as_deref(), status).await {
                    log::warn!("enrol id={id} could not be cached: {err:#}");
                }
                log::info!(
                    "enrol id={id} outcome={} ms={:.1} reason={:?}",
                    if api.enrolled { "enrolled" } else { "refused" },
                    started.elapsed().as_secs_f64() * 1000.0,
                    api.reason.unwrap_or_default(),
                );
            }
            Err(err) => {
                // Loud, because the consequence is silent: every device keeps
                // the verdict it already had, and one that has never been
                // checked keeps registering. That is the designed behaviour
                // (T3.5.3) and it is indistinguishable from the feature being
                // off unless this line exists.
                log::error!(
                    "enrol id={id} outcome=unavailable ms={:.1}: {err:#} — \
                     keeping the cached verdict",
                    started.elapsed().as_secs_f64() * 1000.0
                );
            }
        }
    });
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

    fn configured_auth() -> AuthConfig {
        AuthConfig {
            api_url: "http://127.0.0.1:21114".to_owned(),
            api_secret: "secret".to_owned(),
            required: true,
            ..Default::default()
        }
    }

    #[test]
    fn ships_off_even_with_the_api_configured() {
        // The one difference from AUTH_REQUIRED, and it is deliberate: an
        // upgrade must not deregister a fleet that has never been deployed.
        let config = EnrolmentConfig::from_lookup(&configured_auth(), lookup(&[])).unwrap();
        assert!(!config.required);
    }

    #[test]
    fn refuses_to_start_without_somewhere_to_ask() {
        let err = EnrolmentConfig::from_lookup(
            &AuthConfig::default(),
            lookup(&[("ENROL_REQUIRED", "Y")]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("AUTH_API_URL"), "{err}");
    }

    #[test]
    fn refuses_to_start_without_a_secret() {
        let auth = AuthConfig {
            api_url: "http://127.0.0.1:21114".to_owned(),
            ..Default::default()
        };
        let err =
            EnrolmentConfig::from_lookup(&auth, lookup(&[("ENROL_REQUIRED", "Y")])).unwrap_err();
        assert!(err.to_string().contains("AUTH_API_SECRET"), "{err}");
    }

    #[test]
    fn a_bad_number_is_refused_rather_than_defaulted() {
        for pairs in [
            vec![("ENROL_CACHE_TTL_MS", "soon")],
            vec![("ENROL_CACHE_TTL_MS", "0")],
            vec![("ENROL_RATE_PER_MINUTE", "lots")],
            vec![("ENROL_RATE_PER_MINUTE", "0")],
        ] {
            assert!(
                EnrolmentConfig::from_lookup(&configured_auth(), lookup(&pairs)).is_err(),
                "{pairs:?} was accepted"
            );
        }
    }

    #[test]
    fn an_unwritten_status_column_is_unknown_not_refused() {
        let enrolment = Enrolment::new(
            EnrolmentConfig {
                required: true,
                ..Default::default()
            },
            configured_auth(),
        )
        .unwrap();
        // NULL is what every row written before this feature existed says.
        assert_eq!(enrolment.verdict(None), Verdict::Unknown);
        // And so is anything we did not write ourselves.
        assert_eq!(enrolment.verdict(Some(7)), Verdict::Unknown);
        assert_eq!(enrolment.verdict(Some(STATUS_ENROLLED)), Verdict::Enrolled);
        assert_eq!(enrolment.verdict(Some(STATUS_REFUSED)), Verdict::Refused);
    }

    #[test]
    fn with_enrolment_off_every_verdict_is_upstreams() {
        let enrolment = Enrolment::new(EnrolmentConfig::default(), AuthConfig::default()).unwrap();
        for status in [None, Some(STATUS_REFUSED), Some(STATUS_ENROLLED)] {
            assert_eq!(enrolment.verdict(status), Verdict::Disabled);
        }
    }

    #[test]
    fn the_budget_bounds_calls_not_devices() {
        let enrolment = Enrolment::new(
            EnrolmentConfig {
                required: true,
                rate_per_minute: 3,
                ..Default::default()
            },
            configured_auth(),
        )
        .unwrap();
        assert!(enrolment.afford());
        assert!(enrolment.afford());
        assert!(enrolment.afford());
        assert!(!enrolment.afford(), "the fourth call was not rate-limited");
    }

    #[test]
    fn one_id_is_asked_about_once_at_a_time() {
        let enrolment = Enrolment::new(
            EnrolmentConfig {
                required: true,
                ..Default::default()
            },
            configured_auth(),
        )
        .unwrap();
        assert!(enrolment.claim("123456789"));
        assert!(!enrolment.claim("123456789"), "a second call was allowed through");
        assert!(enrolment.claim("987654321"), "a different id was blocked");
        enrolment.release("123456789");
        assert!(enrolment.claim("123456789"));
    }
}
