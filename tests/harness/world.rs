//! The whole system, brought up in one call — TASK.md T5.1.
//!
//! Milestone 5 asks questions no single component can answer: a grant written in
//! the console must change what hbbs decides, a revocation must reach a session
//! already running, and a relay must carry bytes for a connection hbbs allowed
//! and none for one it refused. So the unit of these tests is not a server, it
//! is a **world**: a real `apps/api` on its own database, a real `hbbs` pointed
//! at it, a real `hbbr` sharing its key, and an admin already signed in.
//!
//! One world per test, and nothing shared between them. That costs a few seconds
//! of start-up per test and buys the only property that matters in an
//! authorization suite: a test that passes cannot have passed because of another
//! test's grant.
//!
//! The order below is forced and worth knowing before changing it:
//!
//!   1. `hbbr`'s **port** is allocated first, because hbbs takes the relay
//!      address as a boot argument (`-r`) and `ALWAYS_USE_RELAY` is useless
//!      without one.
//!   2. `apps/api` starts next, because hbbs validates its auth configuration
//!      before it binds anything and refuses to boot on a bad one (T3.1).
//!   3. `hbbs` starts third and **generates the licence key**.
//!   4. `hbbr` starts last, with that key — an `hbbr` with no key relays for
//!      anybody (docs/CONTEXT.md §7).

use std::time::Duration;

use hbb_common::tokio::time::sleep;

use super::{
    api::{api_with, Api, ClientApi, Console, SHARED_SECRET},
    hbbs_full,
    peer::{next_device_id, Brokerage, Controller, Device},
    relay::{hbbr_on, Hbbr},
    session::{next_conn_id, Session},
    Hbbs,
};
use serde_json::Value;
use super::free_port_block;

pub struct World {
    // Declaration order is drop order. The servers go before the api so that
    // hbbs is not still asking an api that has begun shutting down — which
    // produces a fail-closed denial in the log of a test that already passed.
    pub hbbs: Hbbs,
    pub hbbr: Hbbr,
    pub api: Api,
    pub console: Console,
    pub client: ClientApi,
}

/// Options that have to be decided before anything boots.
pub struct WorldBuilder {
    enrol_required: bool,
    always_use_relay: bool,
    auth_timeout_ms: u64,
    auth_cache_ttl_ms: Option<u64>,
    hbbs_args: Vec<String>,
    hbbs_env: Vec<(String, String)>,
    api_env: Vec<(String, String)>,
    breakglass: Option<String>,
    reconcile_sec: u64,
    enrol_cache_ttl_ms: Option<u64>,
}

impl Default for WorldBuilder {
    fn default() -> Self {
        Self {
            enrol_required: false,
            always_use_relay: false,
            // The 300 ms production default is right for production and wrong
            // here: several worlds, each with a Node process and a Mongo
            // connection, on one laptop turn scheduler jitter into a fail-closed
            // denial and a red test that is about nothing.
            auth_timeout_ms: 4_000,
            auth_cache_ttl_ms: None,
            hbbs_args: Vec::new(),
            hbbs_env: Vec::new(),
            api_env: Vec::new(),
            breakglass: None,
            enrol_cache_ttl_ms: None,
            // The 60 s production default is right for production and useless
            // here: reconciliation is the thing under test, not something to
            // wait a minute for.
            reconcile_sec: 1,
        }
    }
}

impl WorldBuilder {
    /// Registration ownership (Milestone 3.5). Off by default, as it ships.
    pub fn enrol_required(mut self, on: bool) -> Self {
        self.enrol_required = on;
        self
    }

    /// How long an enrolment verdict is used before hbbs re-checks it.
    ///
    /// Ten minutes in production, which is right — the question "is this device
    /// one of ours" is durable, and the cache is what stops every registration
    /// in the fleet becoming an api call. A test that wants to watch a verdict
    /// *change* has to turn it down, and one that wants to watch it **hold** has
    /// to leave it up.
    pub fn enrol_cache_ttl_ms(mut self, ms: u64) -> Self {
        self.enrol_cache_ttl_ms = Some(ms);
        self
    }

    /// Forces every connection onto the relay — T5.10's whole subject.
    pub fn always_use_relay(mut self, on: bool) -> Self {
        self.always_use_relay = on;
        self
    }

    pub fn auth_timeout_ms(mut self, ms: u64) -> Self {
        self.auth_timeout_ms = ms;
        self
    }

    /// How long a positive decision may be reused. Turn it down when the
    /// subject is whether a decision *changed*, because the cache is the
    /// difference between "revocation does not work" and "revocation takes up to
    /// five seconds to stop **new** connections".
    ///
    /// **Zero is not accepted** — `AUTH_CACHE_TTL_MS must be greater than 0` is
    /// a boot-time refusal (`auth.rs:223`), on the principle that a value
    /// bounding a security check is never silently replaced with a default. One
    /// millisecond is the floor and is effectively no reuse.
    pub fn auth_cache_ttl_ms(mut self, ms: u64) -> Self {
        assert!(ms > 0, "hbbs refuses to boot with AUTH_CACHE_TTL_MS=0; 1 is the floor");
        self.auth_cache_ttl_ms = Some(ms);
        self
    }

    pub fn hbbs_arg(mut self, arg: impl Into<String>) -> Self {
        self.hbbs_args.push(arg.into());
        self
    }

    pub fn hbbs_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.hbbs_env.push((key.into(), value.into()));
        self
    }

    pub fn api_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.api_env.push((key.into(), value.into()));
        self
    }

    /// Arms the emergency path on **both** servers with one public key.
    ///
    /// Both, because they do different halves of the same job and a world with
    /// only one armed would quietly test neither: hbbs verifies the capability
    /// locally — that is the point, it works when the api does not — and the api
    /// verifies it again on the ordinary path *and* is the thing hbbs eventually
    /// reconciles its local audit records to. Unset on either side means every
    /// capability is refused there (`breakglass.rs`, `env.ts`), which ships as
    /// the default on purpose.
    pub fn breakglass(mut self, pubkey: &str) -> Self {
        self.breakglass = Some(pubkey.to_owned());
        self
    }

    /// How often hbbs replays unacknowledged audit records to the api.
    pub fn reconcile_sec(mut self, secs: u64) -> Self {
        self.reconcile_sec = secs;
        self
    }

    pub async fn up(self) -> World {
        let relay_port = free_port_block();
        let relay_addr = format!("127.0.0.1:{relay_port}");

        let mut api_env: Vec<(&str, String)> = self
            .api_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        if let Some(pubkey) = &self.breakglass {
            api_env.push(("BREAKGLASS_PUBKEY", pubkey.clone()));
        }
        let api = api_with(&api_env).await;

        let mut args = vec![
            "--auth-api-url".to_owned(),
            api.base(),
            "--auth-api-secret".to_owned(),
            SHARED_SECRET.to_owned(),
            "--auth-timeout-ms".to_owned(),
            self.auth_timeout_ms.to_string(),
            "-r".to_owned(),
            relay_addr.clone(),
        ];
        if let Some(ttl) = self.auth_cache_ttl_ms {
            args.push("--auth-cache-ttl-ms".to_owned());
            args.push(ttl.to_string());
        }
        if self.enrol_required {
            args.push("--enrol-required".to_owned());
            args.push("Y".to_owned());
        }
        if let Some(ms) = self.enrol_cache_ttl_ms {
            args.push("--enrol-cache-ttl-ms".to_owned());
            args.push(ms.to_string());
        }
        if let Some(pubkey) = &self.breakglass {
            args.push("--breakglass-pubkey".to_owned());
            args.push(pubkey.clone());
            args.push("--breakglass-reconcile-sec".to_owned());
            args.push(self.reconcile_sec.to_string());
            // The audit log path is left at its default, `./breakglass-audit.log`,
            // which lands in hbbs's working directory — so `hbbs.dir()` finds it
            // and the default is what gets exercised.
        }
        args.extend(self.hbbs_args);

        let mut env: Vec<(&str, String)> = self
            .hbbs_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        if self.always_use_relay {
            // Not a CLI flag — `rendezvous_server.rs:253` reads it through
            // `get_arg`, which covers the environment but not `--always-use-relay`.
            env.push(("ALWAYS_USE_RELAY", "Y".to_owned()));
        }

        let hbbs = hbbs_full("_", &args, &env).await;
        let hbbr = hbbr_on(relay_port, &hbbs.key).await;
        let console = Console::login(&api).await;
        let client = ClientApi::new(&api);

        World { hbbs, hbbr, api, console, client }
    }
}

impl World {
    /// A world with authorization on, enrolment off, and nothing else unusual.
    pub async fn up() -> World {
        WorldBuilder::default().up().await
    }

    pub fn builder() -> WorldBuilder {
        WorldBuilder::default()
    }

    pub fn relay_addr(&self) -> String {
        self.hbbr.addr()
    }

    /// A signed-in user on their own machine.
    ///
    /// Built the long way round on purpose: the console creates the user, then
    /// the *client* signs in through `POST /api/login` to get the token. That is
    /// two real endpoints rather than a fixture, and it is the only way the
    /// token under test is the token a client would actually hold.
    pub async fn controller(&self, local_part: &str) -> Controller {
        self.controller_with_role(local_part, "user").await
    }

    pub async fn controller_with_role(&self, local_part: &str, role: &str) -> Controller {
        let email = format!("{local_part}-{}@test.invalid", next_device_id());
        let user_id = self.console.create_user(&email, role).await;
        let id = next_device_id();
        let token = self
            .client
            .login(&email, &id, &format!("uuid-{id}"))
            .await;
        Controller {
            user_id,
            email,
            token,
            id,
            hbbs_port: self.hbbs.port,
            key: self.hbbs.key.clone(),
        }
    }

    /// A device enrolled to `owner`, and registered with hbbs so it is online.
    ///
    /// Enrolment goes through `POST /api/devices/deploy`, which is
    /// `rustdesk --deploy` — and which sets `ownerUserId` as a side effect. That
    /// side effect is the "A → own device" row of T5.2, so it is worth being
    /// explicit that no fixture wrote it: the deploy did, exactly as it would on
    /// a real machine.
    pub async fn device(&self, owner: &Controller) -> Device {
        let id = next_device_id();
        let uuid = format!("uuid-{id}").into_bytes();
        let pk = format!("pk-{id}").into_bytes();
        // **Base64 at the api, raw bytes at hbbs, and they must be the same
        // bytes.** `RegisterPk.uuid` is a `bytes` field; hbbs base64-encodes it
        // before asking `/api/internal/enrolled` (`enrolment.rs:357`), so a
        // device deployed under the plain text of its uuid is a *different*
        // device to the api and answers `uuid belongs to another machine` —
        // which reads as an id conflict rather than as an encoding mistake.
        let result = self
            .client
            .deploy(&owner.token, &id, &base64::encode(&uuid), &base64::encode(&pk))
            .await;
        assert_eq!(result, "OK", "deploy of {id} for {} failed", owner.email);
        // `register_fully`, not `register`: with enrolment on, the first
        // `RegisterPk` is answered OK and deliberately not written down.
        Device::register_fully(&self.hbbs, &id, &uuid, &pk).await
    }

    /// A device nobody owns: enrolled, then unassigned from the console.
    ///
    /// The console is the only way to produce one, because deploying always
    /// claims ownership. It is the state a machine is left in after its owner
    /// leaves, and the case where *only* a grant can open it.
    pub async fn unowned_device(&self, deployer: &Controller) -> Device {
        let device = self.device(deployer).await;
        self.console.set_device_owner(&device.id, None).await;
        device
    }

    /// Turns a brokerage into a **live session**, as the controlled endpoint
    /// does: the `action: "new"` audit post that joins the decision row to a
    /// `conn_id`, then a first heartbeat so the device is on record as holding
    /// it.
    ///
    /// Everything about revocation runs through here. A brokered connection
    /// that never takes this step exists on the wire and nowhere else, so the
    /// console cannot show it, `enforceLiveSessionAccess` cannot see it, and a
    /// revoke reaches it only through the deliberate unattributed fallback.
    pub async fn session(&self, device: &Device, brokerage: &Brokerage) -> Session {
        let session = Session::open(
            &self.client,
            &device.id,
            &device.uuid_b64(),
            next_conn_id(),
            brokerage,
        )
        .await;
        let row = self.session_row(&device.id, session.conn_id).await;
        // The join either happened or it did not, and a test should be able to
        // say which: an unattributed session behaves differently under
        // revocation on purpose (`disconnect.ts`).
        let mut session = session;
        session.attributed = row
            .as_ref()
            .and_then(|row| row["fromUserId"].as_str())
            .is_some();
        session
    }

    /// The session-log row for one live connection, if the console can see it.
    ///
    /// There is no `connId` filter on `/api/admin/sessions` — the console has
    /// never needed one — so this filters the device's rows here rather than
    /// adding a query parameter no product screen would use.
    pub async fn session_row(&self, device_id: &str, conn_id: i64) -> Option<Value> {
        let page = self.console.sessions(&format!("deviceId={device_id}&pageSize=200")).await;
        page["sessions"]
            .as_array()?
            .iter()
            .find(|row| row["connId"].as_i64() == Some(conn_id))
            .cloned()
    }

    /// Waits for hbbs to have logged something, with the same polling the rest
    /// of the harness uses — `WriteMode::Async` means a line exists in the
    /// process before it exists in the file.
    pub async fn hbbs_logged(&self, needle: &str, ms: u64) -> bool {
        self.hbbs.wait_for_log(needle, ms).await
    }

    /// Lets a decision cache entry lapse. Reads better at a call site than a
    /// bare sleep, and names the thing being waited for.
    pub async fn let_auth_cache_lapse(&self, ttl_ms: u64) {
        sleep(Duration::from_millis(ttl_ms + 250)).await;
    }
}
