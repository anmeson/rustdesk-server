//! The real `apps/api`, spawned and driven — TASK.md T5.1.
//!
//! Milestone 3's suites answer hbbs with a stub (`harness::stub`), which is the
//! right tool for asserting on what hbbs does with an answer: a stub can return
//! garbage, a 503, or nothing at all. What it cannot do is *decide* anything, so
//! every Milestone 5 question — does a grant allow, does revoking it deny, does
//! an admin reach a machine nobody granted them — needs the real thing.
//!
//! So this spawns `apps/api/src/scripts/e2e-server.ts` on Node, against its own
//! MongoDB database, and talks to it over HTTP exactly as its two real callers
//! do:
//!
//!   - [`Console`] is `apps/web`: a Better Auth session cookie obtained by
//!     signing in, then `/api/admin/*`. Every fixture in Milestone 5 is built
//!     through it, so a fixture that cannot be built is a console bug the tests
//!     find for free.
//!   - [`ClientApi`] is the RustDesk client: `POST /api/login` for an
//!     `access_token`, `POST /api/devices/deploy` to enrol. These are the same
//!     requests captured off the wire in T0.5.2.
//!
//! There is deliberately no back door. Nothing here writes to Mongo directly,
//! and the api gets no test-only endpoint: if the console cannot express a
//! fixture, neither can an operator, and that is worth knowing before the tests
//! are written around it.

use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use hbb_common::tokio::time::sleep;
use serde_json::{json, Value};

use super::{free_port_block, TempDir};

/// Shared with hbbs as `--auth-api-secret`, and sent as `x-hbbs-secret`.
/// Long enough for the api's own `z.string().min(32)`.
pub const SHARED_SECRET: &str = "e2e-only-hbbs-shared-secret-not-for-real-use";

const ADMIN_EMAIL: &str = "e2e-admin@test.invalid";
const ADMIN_PASSWORD: &str = "e2e-admin-password-long-enough";
const READY: &str = "e2e-server ready";

/// Every fixture user shares this. `Console::create_user` sets it, `ClientApi`
/// signs in with it.
pub const USER_PASSWORD: &str = "e2e-user-password-long-enough";

/// A running `apps/api`, with its own database.
pub struct Api {
    child: Child,
    pub port: u16,
    pub db: String,
    /// Kept so a restart comes back configured the way it started.
    env: Vec<(String, String)>,
    ready_lines: usize,
    _dir: TempDir,
}

impl Api {
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self._dir.path().join("api.log")).unwrap_or_default()
    }

    fn ready_count(&self) -> usize {
        self.log().matches(READY).count()
    }

    /// How many requests this api has answered on `path`.
    ///
    /// Counted from the server's own request log rather than from anything hbbs
    /// reports, because the question T5.5 asks — "does an unenrolled device storm
    /// the api" — is about what actually *arrived*. hbbs's own counters would
    /// only prove hbbs believes it rate-limited itself.
    ///
    /// Fastify logs one `"url":"…"` line per incoming request at `NODE_ENV=production`.
    pub fn requests_to(&self, path: &str) -> usize {
        self.log().matches(&format!("\"url\":\"{path}\"")).count()
    }

    /// **Kills the api outright, leaving its database intact.**
    ///
    /// SIGKILL, and that is the point twice over. It is the honest shape of the
    /// outage break-glass exists for — a host that went away, not a service that
    /// was asked politely to stop — and it skips the SIGTERM handler that drops
    /// the database, so the world that comes back is the world that went down.
    pub fn kill_now(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Brings it back **on the same port, with the same database**.
    ///
    /// The port matters: hbbs is given the api's address at boot and never
    /// re-reads it, so an api that returns somewhere else is, to hbbs, an outage
    /// that never ended.
    pub async fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let extra: Vec<(&str, String)> =
            self.env.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let want = self.ready_count() + 1;
        self.child = command_for(
            &repo_root(),
            self._dir.path(),
            self.port,
            &self.db,
            &extra,
            true,
        )
        .spawn()
        .expect("could not respawn node");
        for _ in 0..600 {
            if self.ready_count() >= want {
                self.ready_lines = want;
                return;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("apps/api exited on restart: {status}\n{}", self.log());
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("apps/api never came back on {}\n{}", self.port, self.log());
    }

    /// True while nothing is listening — what hbbs sees during the outage.
    pub fn is_down(&self) -> bool {
        std::net::TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], self.port)),
            Duration::from_millis(200),
        )
        .is_err()
    }
}

impl Drop for Api {
    /// **SIGTERM, not `Child::kill`.** `kill` sends SIGKILL, and the server's
    /// SIGTERM handler is what drops its database. Falls back to SIGKILL if it
    /// does not go, because a leaked Node process holding a port is worse than a
    /// leaked database.
    ///
    /// A process that is **already dead** gets neither: `kill_now` is how T5.4
    /// produces an outage, and a server killed that way never ran its handler.
    /// So the database is dropped from here instead — without it every
    /// break-glass test left one behind, and a suite that litters on every run
    /// is a suite people stop running.
    fn drop(&mut self) {
        let already_gone = matches!(self.child.try_wait(), Ok(Some(_)));
        if !already_gone {
            let pid = self.child.id().to_string();
            let _ = Command::new("kill")
                .args(["-TERM", &pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut exited = false;
            while Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_)) => {
                        exited = true;
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                    Err(_) => break,
                }
            }
            if exited {
                return;
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        drop_database(&self.db);
    }
}

/// Drops one test database directly, for the case where the server that owned
/// it is not around to be asked.
///
/// Guarded on the `_test` suffix here as well as in `e2e-server.ts`: this one
/// runs without the server's own refusal in front of it, and the cost of getting
/// it wrong is somebody's fleet.
fn drop_database(db: &str) {
    if !db.ends_with("_test") {
        return;
    }
    let script = format!(
        r#"const {{MongoClient}}=require("mongodb");(async()=>{{const c=new MongoClient("mongodb://localhost:27017",{{serverSelectionTimeoutMS:3000}});await c.connect();await c.db({db:?}).dropDatabase();await c.close();}})().catch(()=>process.exit(1))"#
    );
    let _ = Command::new("node")
        .current_dir(repo_root().join("apps/api"))
        .args(["-e", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Where `apps/api` lives. Tests run with the crate root as their working
/// directory, and the crate is a submodule two levels down from the monorepo.
fn repo_root() -> std::path::PathBuf {
    let crate_root = std::env::current_dir().unwrap();
    let root = crate_root.join("../..").canonicalize().unwrap_or(crate_root);
    assert!(
        root.join("apps/api/package.json").exists(),
        "could not find apps/api from {root:?} — these tests must run from apps/rustdesk-server"
    );
    root
}

/// Boots `apps/api` against a private database and waits for it to accept.
///
/// `extra_env` overrides anything below it — `BREAKGLASS_PUBKEY` for T5.4, and
/// `CLIENT_TOKEN_TTL_SECONDS` for the token-expiry cases in T5.9.
pub async fn api_with(extra_env: &[(&str, String)]) -> Api {
    let port = free_port_block();
    // Per world, and dropped at both ends of its life (see e2e-server.ts). The
    // `_test` suffix is not decoration: the server refuses to start without it,
    // because it drops whatever it is pointed at.
    let db = format!("anmesondesk_e2e_{}_{}_test", std::process::id(), port);
    spawn_api(port, db, TempDir::new(), extra_env, false).await
}

async fn spawn_api(
    port: u16,
    db: String,
    dir: TempDir,
    extra_env: &[(&str, String)],
    reuse_db: bool,
) -> Api {
    let root = repo_root();

    // Built before anything below can panic, so a failed wait still reaps the
    // process and drops the database.
    let mut api = Api {
        child: command_for(&root, dir.path(), port, &db, extra_env, reuse_db)
            .spawn()
            .expect("could not spawn node — is it on PATH?"),
        port,
        db,
        env: extra_env.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        ready_lines: 0,
        _dir: dir,
    };
    // A restart appends to the same log, so "ready" has to mean *this* boot's
    // line and not the previous one — counting them is the cheapest way to say
    // that without parsing timestamps.
    let want = api.ready_count() + 1;

    // The ready line is printed after `listen` resolves, so it means the port is
    // accepting *and* the admin exists. A `/health` poll would only prove the
    // first, and a console sign-in racing the seed is a 401 that looks like a
    // broken guard.
    for _ in 0..600 {
        if api.ready_count() >= want {
            api.ready_lines = want;
            return api;
        }
        if let Ok(Some(status)) = api.child.try_wait() {
            panic!(
                "apps/api exited during startup: {status} (port {})\n{}",
                api.port,
                api.log()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "apps/api never became ready on {} — is mongod running?\n{}",
        api.port,
        api.log()
    );
}

/// The exact invocation, in one place, so a restart cannot drift from a boot.
fn command_for(
    root: &std::path::Path,
    dir: &std::path::Path,
    port: u16,
    db: &str,
    extra_env: &[(&str, String)],
    reuse_db: bool,
) -> Command {
    let log = dir.join("api.log");
    let mut cmd = Command::new("node");
    cmd.current_dir(root.join("apps/api"))
        // `env_clear` for the same reason hbbs gets it: a stray MONGODB_DB or
        // PORT in the developer's shell would otherwise point a test at the
        // fleet's own database.
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("NODE_ENV", "production")
        .env("PORT", port.to_string())
        .env("HOST", "127.0.0.1")
        .env("MONGODB_URI", "mongodb://localhost:27017")
        .env("MONGODB_DB", db)
        .env("PUBLIC_URL", format!("http://127.0.0.1:{port}"))
        .env("ADMIN_ORIGINS", format!("http://127.0.0.1:{port}"))
        .env("BETTER_AUTH_SECRET", "e2e-only-better-auth-secret-not-for-real-use")
        .env("HBBS_SHARED_SECRET", SHARED_SECRET)
        .env("E2E_ADMIN_EMAIL", ADMIN_EMAIL)
        .env("E2E_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .env("BREAKGLASS_AUDIT_LOG", dir.join("api-breakglass.log").display().to_string())
        .args(["--import", "tsx", "src/scripts/e2e-server.ts"])
        // Appended, not truncated: a restart must not throw away the log of the
        // run that preceded the outage.
        .stdout(Stdio::from(
            std::fs::File::options().create(true).append(true).open(&log).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::options().create(true).append(true).open(&log).unwrap(),
        ));
    if reuse_db {
        cmd.env("E2E_REUSE_DB", "1");
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd
}

pub async fn api() -> Api {
    api_with(&[]).await
}

// ---------------------------------------------------------------- console

/// `apps/web`'s side of the api: a signed-in admin driving `/api/admin/*`.
pub struct Console {
    http: reqwest::Client,
    base: String,
    cookie: String,
    pub admin_id: String,
}

impl Console {
    /// Signs the seeded admin in, the way a browser does.
    ///
    /// The cookie is not forged. `requireAdmin` resolves the session and re-reads
    /// the user on every request, so a hand-made cookie would exercise a
    /// different guard than the one that ships — and several Milestone 5 rows
    /// turn on that guard behaving.
    pub async fn login(api: &Api) -> Console {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let base = api.base();
        let response = http
            .post(format!("{base}/api/auth/sign-in/email"))
            .json(&json!({ "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD }))
            .send()
            .await
            .expect("could not reach the api to sign in");
        let cookie = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or("").to_owned())
            .collect::<Vec<_>>()
            .join("; ");
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        assert!(status.is_success(), "admin sign-in failed: {status} {body}");
        assert!(!cookie.is_empty(), "admin sign-in returned no cookie: {body}");
        let admin_id = body["user"]["id"].as_str().unwrap_or_default().to_owned();
        Console { http, base, cookie, admin_id }
    }

    /// A raw request, so a test can assert on a status the helpers hide.
    pub async fn request(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .header(reqwest::header::COOKIE, &self.cookie);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("console request failed");
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    pub async fn get(&self, path: &str) -> Value {
        let (status, body) = self.request(reqwest::Method::GET, path, None).await;
        assert!((200..300).contains(&status), "GET {path} -> {status} {body}");
        body
    }

    pub async fn post(&self, path: &str, body: Value) -> Value {
        let (status, body) = self.request(reqwest::Method::POST, path, Some(body)).await;
        assert!((200..300).contains(&status), "POST {path} -> {status} {body}");
        body
    }

    pub async fn patch(&self, path: &str, body: Value) -> Value {
        let (status, body) = self.request(reqwest::Method::PATCH, path, Some(body)).await;
        assert!((200..300).contains(&status), "PATCH {path} -> {status} {body}");
        body
    }

    /// Creates a user and returns its id. `role` is `"user"` or `"admin"`.
    pub async fn create_user(&self, email: &str, role: &str) -> String {
        let body = self
            .post(
                "/api/admin/users",
                json!({ "email": email, "password": USER_PASSWORD, "role": role }),
            )
            .await;
        body["user"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("no user id in {body}"))
            .to_owned()
    }

    pub async fn grant(&self, user_id: &str, device_id: &str) {
        self.post("/api/admin/grants", json!({ "userId": user_id, "deviceId": device_id }))
            .await;
    }

    /// A grant with an explicit expiry (RFC 3339) or a permission mask, for the
    /// rows in T5.2 and T5.3 that turn on one of them.
    pub async fn grant_with(&self, user_id: &str, device_id: &str, extra: Value) {
        let mut body = json!({ "userId": user_id, "deviceId": device_id });
        if let (Some(target), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                target.insert(key.clone(), value.clone());
            }
        }
        self.post("/api/admin/grants", body).await;
    }

    pub async fn revoke(&self, user_id: &str, device_id: &str) -> Value {
        self.post(
            "/api/admin/grants/revoke",
            json!({ "userId": user_id, "deviceId": device_id }),
        )
        .await
    }

    /// `None` clears the owner — the api reads `null` and "absent" as different
    /// things on this route on purpose.
    pub async fn set_device_owner(&self, device_id: &str, owner: Option<&str>) -> Value {
        self.patch(
            &format!("/api/admin/devices/{device_id}"),
            json!({ "ownerUserId": owner }),
        )
        .await
    }

    /// Disables (or re-enables) a user account.
    ///
    /// A disabled account is refused at `authorize()` **before** any grant is
    /// consulted (`services/authorize.ts:67`), which makes it the one refusal a
    /// user cannot fix by being granted something — T5.7's subject.
    pub async fn set_user_disabled(&self, user_id: &str, disabled: bool) -> Value {
        self.patch(&format!("/api/admin/users/{user_id}"), json!({ "disabled": disabled }))
            .await
    }

    pub async fn device(&self, device_id: &str) -> Value {
        self.get(&format!("/api/admin/devices/{device_id}")).await
    }

    pub async fn sessions(&self, query: &str) -> Value {
        self.get(&format!("/api/admin/sessions?{query}")).await
    }
}

// ---------------------------------------------------------------- client

/// The RustDesk client's side of the api.
pub struct ClientApi {
    http: reqwest::Client,
    base: String,
}

impl ClientApi {
    pub fn new(api: &Api) -> ClientApi {
        ClientApi {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap(),
            base: api.base(),
        }
    }

    /// `POST /api/login` — what the client does when a user signs in, and where
    /// the `access_token` every `PunchHoleRequest` carries comes from.
    ///
    /// `id` and `uuid` are the client's own, and sending them is not incidental:
    /// the route upserts the device as `pending` on first sign-in from it.
    pub async fn login(&self, email: &str, id: &str, uuid: &str) -> String {
        let body: Value = self
            .http
            .post(format!("{}/api/login", self.base))
            .json(&json!({
                "username": email,
                "password": USER_PASSWORD,
                "id": id,
                "uuid": uuid,
            }))
            .send()
            .await
            .expect("login request failed")
            .json()
            .await
            .unwrap_or(Value::Null);
        body["access_token"]
            .as_str()
            .unwrap_or_else(|| panic!("no access_token in {body}"))
            .to_owned()
    }

    /// `POST /api/login` when it is expected to **fail**.
    ///
    /// Returns the token on success and the api's own `error` string otherwise.
    /// T5.7 needs the failure: a disabled account is refused at the connect path
    /// as "your session has expired", and the only thing that stops that being
    /// misleading is what the client is told when it does sign in again.
    pub async fn try_login(&self, email: &str, id: &str, uuid: &str) -> Result<String, String> {
        let body: Value = self
            .http
            .post(format!("{}/api/login", self.base))
            .json(&json!({
                "username": email,
                "password": USER_PASSWORD,
                "id": id,
                "uuid": uuid,
            }))
            .send()
            .await
            .expect("login request failed")
            .json()
            .await
            .unwrap_or(Value::Null);
        match body["access_token"].as_str() {
            Some(token) => Ok(token.to_owned()),
            None => Err(body["error"].as_str().unwrap_or("no error field").to_owned()),
        }
    }

    /// `POST /api/devices/deploy` — `rustdesk --deploy --token <t>`. Enrols the
    /// device **and makes the token's user its owner**, which is how the
    /// "A → own device" row of T5.2 is set up without touching Mongo.
    ///
    /// Returns the client's four-way result string verbatim: `OK`,
    /// `NOT_ENABLED`, `INVALID_INPUT` or `ID_TAKEN`.
    pub async fn deploy(&self, token: &str, id: &str, uuid: &str, pk: &str) -> String {
        let body: Value = self
            .http
            .post(format!("{}/api/devices/deploy", self.base))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .json(&json!({ "id": id, "uuid": uuid, "pk": pk }))
            .send()
            .await
            .expect("deploy request failed")
            .json()
            .await
            .unwrap_or(Value::Null);
        body["result"]
            .as_str()
            .unwrap_or_else(|| panic!("no result in {body}"))
            .to_owned()
    }

    /// `POST /api/logout` — revokes the token it is sent with.
    ///
    /// The client calls this when a user signs out, and T5.9's subject is what
    /// it does *not* do: end a session that is already running.
    pub async fn logout(&self, token: &str) {
        self.http
            .post(format!("{}/api/logout", self.base))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .expect("logout failed");
    }

    /// The heartbeat the controlled device sends every 3 s — the channel a
    /// force-disconnect comes back on (decision D2). T5.3 drives it directly.
    pub async fn heartbeat(&self, body: Value) -> Value {
        self.http
            .post(format!("{}/api/heartbeat", self.base))
            .json(&body)
            .send()
            .await
            .expect("heartbeat failed")
            .json()
            .await
            .unwrap_or(Value::Null)
    }

    /// `POST /api/audit/conn` — how a session announces itself, and the only
    /// thing that joins a `conn_id` to the authorize decision that allowed it.
    pub async fn audit_conn(&self, body: Value) -> Value {
        self.http
            .post(format!("{}/api/audit/conn", self.base))
            .json(&body)
            .send()
            .await
            .expect("audit failed")
            .json()
            .await
            .unwrap_or(Value::Null)
    }
}
