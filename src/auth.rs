//! Connection authorization — configuration. TASK.md T3.1.
//!
//! This module is the whole of our footprint outside `rendezvous_server.rs`,
//! and it stays that way on purpose: `rendezvous_server.rs` changes in most
//! upstream releases and carries all of our merge risk, so everything that can
//! live beside it rather than inside it does. T3.2 adds the HTTP client and the
//! decision cache here; T3.3 adds the ~15 lines that call them.
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

use std::time::Duration;

use hbb_common::{bail, log, ResultType};

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
