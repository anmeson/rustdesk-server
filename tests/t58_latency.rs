//! T5.8 — what the login layer costs the connect path, measured both ways.
//!
//! A human is waiting on every one of these, so the question is not "does it
//! work" but "how much did it cost", and the number decides whether T3.2's two
//! knobs — `AUTH_TIMEOUT_MS` and `AUTH_CACHE_TTL_MS` — were set to the right
//! values or merely to plausible ones.
//!
//! **The baseline is produced here rather than quoted.** T0.5 established that
//! the unpatched path works; it recorded no latency figure, and a number from
//! another day on another machine would not be comparable to one taken now
//! anyway. So every comparison below runs twice in the same test, on the same
//! host, with the same fixtures: once against an `hbbs` with **no authorization
//! configured at all** — which is upstream's connect path, our two call sites
//! reduced to one branch each — and once against the real thing.
//!
//! Two layers are timed and they answer different questions:
//!
//!   - **the connect path end to end**, from A's `PunchHoleRequest` to A hearing
//!     back, which is what a person feels;
//!   - **the authorize step alone**, read from hbbs's own runtime console
//!     (`ad`, T3.7), which is the number `AUTH_TIMEOUT_MS` has to be larger
//!     than.
//!
//! **The assertions are deliberately loose and the report is the point.** These
//! are measurements taken on whatever machine is running them, alongside other
//! worlds; a tight bound here would fail for reasons that have nothing to do
//! with this code, and a perf test people learn to ignore is worse than none.
//! Run with `./scripts/e2e.sh t58_latency -- --nocapture` to read the table.

mod harness;

use std::time::{Duration, Instant};

use harness::{
    peer::{Controller, Device},
    world::World,
};
use hbb_common::{rendezvous_proto::*, tokio};

const WAIT: u64 = 8_000;

/// Enough that a p99 means something without the run taking a coffee break.
/// Each sample is a TCP connection, a brokerage, and a round trip on loopback.
const SAMPLES: usize = 200;

/// The production default (`auth.rs:37`) — the number this whole file exists to
/// judge. Not read from the binary: the point is to compare the measurement
/// against what ships, not against whatever this test happens to configure.
const PRODUCTION_TIMEOUT_MS: f64 = 300.0;

// ---------------------------------------------------------------- measuring

struct Samples {
    label: String,
    values: Vec<Duration>,
}

impl Samples {
    fn new(label: &str) -> Samples {
        Samples { label: label.to_owned(), values: Vec::with_capacity(SAMPLES) }
    }

    fn push(&mut self, value: Duration) {
        self.values.push(value);
    }

    /// Nearest-rank, which is the honest reading for a few hundred samples:
    /// interpolating between two measurements invents one that was never taken.
    fn percentile(&self, p: f64) -> f64 {
        assert!(!self.values.is_empty(), "{} has no samples", self.label);
        let mut sorted = self.values.clone();
        sorted.sort();
        let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
        sorted[rank.min(sorted.len()) - 1].as_secs_f64() * 1000.0
    }

    fn p50(&self) -> f64 {
        self.percentile(50.0)
    }

    fn p99(&self) -> f64 {
        self.percentile(99.0)
    }

    fn max(&self) -> f64 {
        self.percentile(100.0)
    }

    fn report(&self) {
        println!(
            "  {:<34} n={:<4} p50={:>7.2}ms  p99={:>7.2}ms  max={:>7.2}ms",
            self.label,
            self.values.len(),
            self.p50(),
            self.p99(),
            self.max()
        );
    }
}

/// `SAMPLES` complete direct connections, timed one at a time.
///
/// Sequential on purpose. Running them concurrently would measure how well this
/// laptop schedules two hundred tasks, which is not a number anybody deploying
/// this can use; one at a time is the shape of a person clicking connect.
async fn time_direct(who: &Controller, device: &mut Device, label: &str) -> Samples {
    let mut samples = Samples::new(label);
    for i in 0..SAMPLES {
        let started = Instant::now();
        let result = who.connect(device, ConnType::DEFAULT_CONN, WAIT).await;
        let took = started.elapsed();
        result.unwrap_or_else(|reason| panic!("{label}: sample {i} was refused: {reason}"));
        samples.push(took);
    }
    samples
}

/// hbbs's own timing of the authorize step, from the runtime console.
///
/// This is not the same number as the end-to-end one and must not be compared
/// with it: it excludes the TCP connect, the brokerage and B's answer, and it
/// counts every decision including the cached ones (`auth.rs:557`).
async fn authorize_timing(w: &World) -> (f64, f64) {
    let report = harness::console(w.hbbs.port, "ad").await;
    let field = |key: &str| -> f64 {
        report
            .split_whitespace()
            .find_map(|f| f.strip_prefix(key)?.trim_end_matches("ms").parse().ok())
            .unwrap_or_else(|| panic!("no {key} in the decision report:\n{report}"))
    };
    (field("latency_mean="), field("latency_max="))
}

/// A world, a user, and a device already proven to connect.
async fn ready(builder: harness::world::WorldBuilder) -> (World, Controller, Device) {
    let w = builder.up().await;
    let alice = w.controller("alice").await;
    let mut laptop = w.device(&alice).await;
    alice
        .connect(&mut laptop, ConnType::DEFAULT_CONN, WAIT)
        .await
        .expect("the warm-up connection was refused");
    (w, alice, laptop)
}

// ---------------------------------------------------------------- the number

/// **The headline: what authorization costs a connection, before and after.**
///
/// Three worlds, in one test, so that the three figures are taken under the same
/// conditions and are worth subtracting from each other:
///
///   1. no authorization — upstream's path, the T0.5 baseline in shape;
///   2. authorization on with the cache effectively off, so every connection is
///      a real round trip to `apps/api` and a Mongo lookup;
///   3. authorization on as it ships, where a repeat within `AUTH_CACHE_TTL_MS`
///      is answered from memory.
///
/// (3) is the number that matters in production, because a client retries a
/// handshake up to three times and a person reconnecting to the same machine
/// does it inside five seconds. (2) is the honest worst case.
#[tokio::test(flavor = "multi_thread")]
async fn what_authorization_costs_the_connect_path() {
    let (_base, alice, mut laptop) = ready(World::builder().authorization(false)).await;
    let baseline = time_direct(&alice, &mut laptop, "upstream (no authorization)").await;

    let (cold_world, alice, mut laptop) =
        ready(World::builder().auth_cache_ttl_ms(1)).await;
    let cold = time_direct(&alice, &mut laptop, "authorized, every one an api call").await;
    let (cold_mean, cold_max) = authorize_timing(&cold_world).await;

    let (warm_world, alice, mut laptop) = ready(World::builder()).await;
    let warm = time_direct(&alice, &mut laptop, "authorized, cache as it ships").await;
    let (warm_mean, warm_max) = authorize_timing(&warm_world).await;

    println!("\nT5.8 — connect path, {SAMPLES} samples each");
    baseline.report();
    cold.report();
    warm.report();
    println!(
        "  {:<34} mean={:>7.2}ms  max={:>7.2}ms   (hbbs's own timing)",
        "authorize step, no cache", cold_mean, cold_max
    );
    println!(
        "  {:<34} mean={:>7.2}ms  max={:>7.2}ms   (hbbs's own timing)",
        "authorize step, cache as it ships", warm_mean, warm_max
    );
    println!(
        "  added at p50: {:+.2}ms uncached, {:+.2}ms cached\n",
        cold.p50() - baseline.p50(),
        warm.p50() - baseline.p50()
    );

    // Loose, and each one is a statement about the design rather than about this
    // machine. A cached decision is a hash lookup under a mutex, so it must not
    // be measurable next to a TCP round trip.
    assert!(
        warm.p50() - baseline.p50() < 25.0,
        "a cached decision added {:.2}ms at p50 — that is not a hash lookup",
        warm.p50() - baseline.p50()
    );
    // And an uncached one is one loopback HTTP request and a couple of indexed
    // Mongo reads. If this is ever seconds, the api grew an external call.
    assert!(
        cold.p50() - baseline.p50() < 250.0,
        "an uncached decision added {:.2}ms at p50 — something on the api's authorize path is \
         doing more than two indexed lookups",
        cold.p50() - baseline.p50()
    );
}

/// Whether `AUTH_TIMEOUT_MS`'s shipped 300 ms is the right size.
///
/// The measurement is hbbs's own, over connections that all miss the cache, so
/// it is the api round trip and nothing else — exactly what the timeout bounds.
/// A p99 anywhere near 300 ms would mean the default is refusing connections
/// that are merely slow, which is decision D1 failing in the expensive
/// direction: users locked out by a working system.
#[tokio::test(flavor = "multi_thread")]
async fn the_authorize_step_fits_inside_the_timeout_that_ships() {
    let (w, alice, mut laptop) = ready(World::builder().auth_cache_ttl_ms(1)).await;
    // From zero, so the warm-up connection and the fixture's own calls are not
    // in the sample.
    harness::console(w.hbbs.port, "ad -").await;

    let samples = time_direct(&alice, &mut laptop, "authorized, every one an api call").await;
    let (mean, max) = authorize_timing(&w).await;

    println!("\nT5.8 — the authorize step alone, {SAMPLES} uncached decisions");
    samples.report();
    println!("  hbbs's own timing: mean={mean:.2}ms  max={max:.2}ms");
    println!(
        "  AUTH_TIMEOUT_MS ships at {PRODUCTION_TIMEOUT_MS:.0}ms — headroom at the worst \
         observed decision: {:.1}x\n",
        PRODUCTION_TIMEOUT_MS / max.max(0.01)
    );

    assert!(
        max < PRODUCTION_TIMEOUT_MS,
        "the slowest authorize took {max:.2}ms against a shipped timeout of \
         {PRODUCTION_TIMEOUT_MS:.0}ms — at that margin the default denies working connections"
    );
    // Stated as a ratio rather than a number so it keeps meaning something on a
    // faster or slower machine than this one.
    assert!(
        max < PRODUCTION_TIMEOUT_MS / 2.0,
        "the worst decision used more than half the shipped timeout ({max:.2}ms of \
         {PRODUCTION_TIMEOUT_MS:.0}ms); that is a tuning decision, not a passing test"
    );
}

/// What the cache is actually worth, inside one world so the only variable is
/// the TTL. Two claims: it is faster, and it is faster because the api is not
/// being asked — counted at the api's own request log rather than inferred.
#[tokio::test(flavor = "multi_thread")]
async fn the_decision_cache_is_what_keeps_the_second_connection_cheap() {
    let (w, alice, mut laptop) = ready(World::builder()).await;
    let before = w.api.requests_to("/api/internal/authorize");

    let warm = time_direct(&alice, &mut laptop, "authorized, cache as it ships").await;
    let asked = w.api.requests_to("/api/internal/authorize") - before;

    println!("\nT5.8 — the cache, over {SAMPLES} identical connections");
    warm.report();
    println!("  api requests: {asked}\n");

    // The TTL is 5 s and the loop is far shorter than that, so this is one
    // decision reused. A handful is fine — an entry can lapse mid-run — but one
    // per connection means the cache is not being hit at all.
    assert!(
        asked < SAMPLES / 4,
        "{asked} of {SAMPLES} connections reached the api; the decision cache is not working"
    );
}

/// The relay gate's own cost (T3.3b). It is a second chokepoint with a second
/// call site, so it gets its own number rather than being assumed to match the
/// punch gate's — and a connection that falls back to a relay pays both.
#[tokio::test(flavor = "multi_thread")]
async fn the_relay_gate_costs_about_the_same_as_the_punch_gate() {
    let (w, alice, mut laptop) = ready(World::builder().auth_cache_ttl_ms(1)).await;
    let relay = w.relay_addr();
    let key = w.hbbs.key.clone();

    // A tenth of the samples: each one opens two real relayed sockets through
    // hbbr and the assertion is a comparison, not a percentile to three figures.
    let n = SAMPLES / 10;
    let mut samples = Samples::new("relay gate, every one an api call");
    for i in 0..n {
        let started = Instant::now();
        let session = alice.connect_relayed(&mut laptop, &relay, &key, WAIT).await;
        let took = started.elapsed();
        session.unwrap_or_else(|reason| panic!("relay sample {i} was refused: {reason}"));
        samples.push(took);
    }

    let (mean, max) = authorize_timing(&w).await;
    println!("\nT5.8 — the relay gate, {n} samples");
    samples.report();
    println!("  hbbs's own timing across both gates: mean={mean:.2}ms  max={max:.2}ms\n");

    assert!(
        max < PRODUCTION_TIMEOUT_MS,
        "a decision on the relay gate took {max:.2}ms against a {PRODUCTION_TIMEOUT_MS:.0}ms timeout"
    );
}
