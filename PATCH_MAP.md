# Server Patch Map — `apps/rustdesk-server`

Every deliberate divergence from upstream `rustdesk/rustdesk-server` in this
tree: `hbbs` (rendezvous) and `hbbr` (relay).

**This file is written as patches are made, never retroactively.** It is the
checklist for re-applying our work after `git fetch upstream && git merge`. A
patch that is not in here will be silently lost at the next upstream bump.

Companion to [`apps/rustdesk/PATCH_MAP.md`](../rustdesk/PATCH_MAP.md), which
covers the client. The two forks share `libs/hbb_common` **byte-for-byte as a
submodule**, so a change there is a change to three repositories — see
[CLAUDE.md](../../CLAUDE.md).

---

## Fork base

| | |
|---|---|
| Upstream | `https://github.com/rustdesk/rustdesk-server.git` (`master`) |
| Base commit | `a7736be7bce2b3cffe4b27e3a9adbe3a6e8b6e63` ("Delete .github/dependabot.yml") |
| Declared version | `1.1.17` (`Cargo.toml`) |
| Base date | 2026-08-07 |
| `libs/hbb_common` submodule | `69cea8dafee147848ae88702029f4bf7df7224c3` |
| Working tree at base | clean — no modifications |

Update this block on every upstream merge, and re-verify every entry below.

---

## How to use this file

**Before merging upstream**

1. `git fetch upstream && git log --oneline HEAD..upstream/master -- src/rendezvous_server.rs src/main.rs`
   — those two files carry all of our merge risk. `src/auth.rs` is ours alone
   and cannot conflict.
2. Read the **Upstream dependency** column for each entry touching those paths.
   Entries marked ⚠ are the ones to check by hand.

**After merging**

3. Walk the table top to bottom. Confirm each patch still exists, still compiles,
   and still *does what it says*. A patch can survive a merge textually and be
   dead semantically — the dangerous shape here is the S3 authorization block
   ending up **after** the branch that emits `PunchHole` / `FetchLocalAddr`,
   which brokers the connection and then refuses it.
4. `cargo test` — `tests/t33_chokepoint.rs` drives the real binary over the real
   wire and is the cheapest proof the gate still gates.
5. Update the fork-base block and any changed line numbers.

**When adding a patch**

6. Add the row *in the same commit as the code*.
7. Prefer **Isolated** over **Structural**. New modules over edits to
   `rendezvous_server.rs`, which is all 1,400 lines of `hbbs` and changes every
   release.

### Column meanings

- **Type — Isolated:** additive; a new file, a new function, or a one-line hook.
  Re-applies cleanly in most merges.
- **Type — Structural:** modifies existing control flow or signatures. Expect
  conflicts; expect to re-read the surrounding upstream code each time.
- **Upstream dependency:** internal APIs, structs, or option keys this patch
  leans on that upstream may rename, move, or delete without notice.
  ⚠ marks a real, identified fragility — not just "upstream might change things".

---

## Patches

`hbbr` has **no** patches and is meant to keep none: it authorizes nothing and
cannot identify a session, so `hbbs` is the sole enforcement point
([CLAUDE.md](../../CLAUDE.md) non-negotiables).

| # | Status | File | What changed | Why | Type | Upstream dependency |
|---|---|---|---|---|---|---|
| S1 | applied 2026-09-15 (T3.1) | `src/auth.rs` (new), `src/lib.rs` (`pub mod auth;`) | `AuthConfig::from_args` — six `AUTH_*` keys read through the existing `get_arg` mechanism, validated at boot before any port binds | connection authorization needs configuring, and a misconfiguration must be a refusal to start rather than a fleet that silently cannot connect | Isolated | low — `common::get_arg` / `get_arg_or` are stable fork-local helpers |
| S2 | applied 2026-09-15 (T3.1) | `src/main.rs` (`:27-32`, `:39-40`) | six `--auth-*` rows in the clap arg string; `AuthConfig::from_args()?` + `.log()` before `RendezvousServer::start_with_bind` | same | Structural (small) | ⚠ medium — upstream edits this arg string whenever it adds a flag |
| S3 | applied 2026-09-15 (T3.2) | `src/auth.rs` | `Authorizer` — `POST /api/internal/authorize` over a process-wide `reqwest` client, plus a positive-decision cache keyed `(sha256(token), to_id, conn_type)` | one decision per connection, and a decision at all | Isolated | low — `reqwest` and `serde_json` were already dependencies |
| S4 | applied 2026-09-15 (T3.3) | `src/rendezvous_server.rs` (`:1`, `:89-95`, `:107-130`, `:161`) | `use crate::auth::…`; `authorizer: Arc<Authorizer>` field on `RendezvousServer`; `auth_config` parameter threaded through `start` / `start_with_bind`; `Authorizer::new` built inside the runtime, before any bind | the decision maker has to live somewhere with the lifetime of the process | Structural | ⚠ medium — `RendezvousServer`'s struct literal and `start_with_bind`'s signature both churn |
| S5 | applied 2026-09-15 (T3.3) | `src/rendezvous_server.rs` (`:757-831`, in `handle_punch_hole_request`) | the authorization call and its denial branch, placed after the licence-key / peer-exists / `OFFLINE` checks and before the `PUNCH_REQS` ring | **this is the security boundary.** A denial returns `Ok((msg_out, None))` carrying `PunchHoleResponse.other_failure`, in the same shape as the existing `LICENSE_MISMATCH` / `OFFLINE` / `ID_NOT_EXIST` branches | Structural | ⚠ **high** — upstream reorders this function's branches freely; see the ordering warning above |
| S6 | applied 2026-09-15 (T3.3) | `src/rendezvous_server.rs` (`:875-896`) | `control_permissions` and `controlled_context` set on the outbound `FetchLocalAddr` and `PunchHole` | `ControlledContext.conn_audit_ref` is the only handle tying a live session to the user who opened it; without it D2 revocation cannot find the session | Isolated | ⚠ medium — both fields already exist in upstream's proto and are unused by upstream, so upstream has no reason to keep them |
| S7 | applied 2026-09-15 (T3.3) | `tests/t33_chokepoint.rs` (new) | integration harness: spawns the real `hbbs`, speaks `RegisterPk` / `PunchHoleRequest` / `RequestRelay` at it, asserts on what A and B receive | a 🔴 gate with no automated proof is a gate nobody can merge upstream into with confidence | Isolated | low |
| S8 | applied 2026-09-15 (T3.3b) | `src/rendezvous_server.rs` (`:539-545` and new `handle_request_relay`, `:980-1071`) | the `RequestRelay` arm moved into a method that authorizes before forwarding; a denial answers A with `RelayResponse{refuse_reason}`; `controlled_context` and `control_permissions` are **overwritten** from the decision | **the second security boundary.** Without it the punch-hole gate is decorative — a stranger simply does not send a `PunchHoleRequest`. The overwrite matters on its own: these two fields arrive from A here, and a forged ref would let one session claim another user's decision row | Structural | ⚠ **high** — same file and same churn as S5 |
| S9 | applied 2026-09-15 (T3.3b) | `src/rendezvous_server.rs` (`:556-566`) | `rr.refuse_reason` cleared on a **forwarded** `RelayResponse` | that field is routed on a sender-supplied address and is the only attacker-reachable field that becomes text on a waiting user's screen. Nothing legitimate writes it — the client only reads it and OSS hbbs never set it — so forwarding it can only carry a stranger's words | Isolated | ⚠ medium — becomes wrong if upstream ever starts writing this field itself |
| S10 | applied 2026-09-15 (T3.4) | `src/rendezvous_server.rs` (`:52-88` `Sink`/`Handshake`, `key_exchange_offer`, the `KeyExchange` arm in `handle_tcp`, the offer + decrypt in `handle_listener_inner`, `send_to_sink`) | the server half of `secure_tcp`: `hbbs` now sends a signed `KeyExchange` unprompted on every TCP connection, and keys both directions if the client answers | **without it, login is unusable.** `secure_tcp` blocks waiting for a server that never spoke, so a client with a licence key *and* a token stalled `READ_TIMEOUT` (18 s, measured) and failed **every** outbound connection (T0.6). It also takes the login token out of cleartext | Structural | ⚠ **high** — `handle_tcp`'s signature, `handle_listener_inner`'s read loop and the `Sink` enum are all upstream's |
| S11 | applied 2026-09-15 (T3.4) | `tests/harness/` (new), `tests/t33_chokepoint.rs` | the S7 harness extracted into a shared module so T3.4's suite could spawn a real `hbbs` without copying it; `next_plaintext` added, mirroring the client's `get_next_nonkeyexchange_msg` | S7's tests are hand-rolled clients with none of the real client's tolerance for the new offer, so every one of them broke on it | Isolated | low |
| S12 | applied 2026-09-15 (T3.4) | `tests/t34_key_exchange.rs` (new) | 9 tests: the offer and its signature, the token's absence from the actual bytes written, both directions encrypted, plaintext clients still served, and a plaintext peer answering an encrypted controller | a 🔴 change to the connect path of every connection | Isolated | low |
| S13 | applied 2026-09-15 (T3.8) | `src/broker.rs` (new), `src/lib.rs` (`pub mod broker;`) | `BrokerLedger` — `A_addr → (peer id, peer ip)` with a 60 s TTL, plus `BrokerConfig` (`BROKER_VERIFY` on, `BROKER_STRICT_IP` off) read through the same `get_arg` mechanism as the `AUTH_*` keys | upstream routes three controller-bound messages on a sender-supplied address and checks nothing about who sent it; the ledger is what makes checking possible | Isolated | low — `common::get_arg_opt` only |
| S14 | applied 2026-09-15 (T3.8) | `src/main.rs` (`:33-34`, `:42-46`, `:57`) | two `--broker-*` rows in the clap arg string; `BrokerConfig::from_args()?` + `.log()`, threaded into `start_with_bind` | same | Structural (small) | ⚠ medium — same arg string as S2 |
| S15 | applied 2026-09-15 (T3.8) | `src/rendezvous_server.rs` (`:2`, `:122-128`, `:136-165`, `:196`) | `use crate::broker::{BrokerLedger, Verdict}`; `broker: Arc<BrokerLedger>` field; `broker_config` parameter on `start` / `start_with_bind` | the ledger needs the lifetime of the process, and must be *shared* — a per-clone ledger would not remember the brokerage the clone answering the response has to check | Structural | ⚠ medium — same churn as S4 |
| S16 | applied 2026-09-15 (T3.8) | `src/rendezvous_server.rs` (in `handle_punch_hole_request`, beside the `PUNCH_REQS` ring; and at the tail of `handle_request_relay`) | two `broker.record(try_into_v4(addr), peer_id, try_into_v4(peer_addr).ip())` calls, at the two points where hbbs actually introduces a controller to a peer | there is no third place a brokerage begins. The relay one is separate because the fallback arrives on a **fresh TCP connection** (`client.rs:1720`), so A waits at an address the punch path never wrote down | Isolated | ⚠ medium — must stay on the *allow* side of S5/S8, or a refused connection becomes answerable |
| S17 | applied 2026-09-15 (T3.8) | `src/rendezvous_server.rs` (`handle_hole_sent`, `handle_local_addr`, the `RelayResponse` arm in `handle_tcp`) | `broker.check(...)` before each forward; a `Verdict::Drop` returns without forwarding and without touching the sink | **this is the fix.** Without it a stranger who knows a waiting controller's address answers in the peer's place — and by naming an id hbbs does not know, hands A an empty peer key, which the client reads as "no identity to verify" (`apps/rustdesk/src/client.rs:1624-1634`) | Structural | ⚠ **high** — three separate sites in a file upstream reorders freely |
| S18 | applied 2026-09-15 (T3.8) | `tests/t33_chokepoint.rs` | `a_stranger_can_still_answer_a_waiting_controller` rewritten to assert the fix, plus 5 tests: the brokered peer still gets through, `LocalAddr` and id-bearing `RelayResponse` refused, the id-less fallback ack still forwarded, and `BROKER_VERIFY=N` restoring upstream's routing | a 🔴 change to the routing every brokered connection depends on | Isolated | low |
| S19 | applied 2026-09-15 (T3.5) | `src/breakglass.rs` (new), `src/lib.rs` (`pub mod breakglass;`) | ed25519 capability verification — `bg.<b64(payload)>.<b64(sig)>`, nonce store, per-ip and global rate limits, an `exp` ceiling — plus `BreakglassConfig` (`BREAKGLASS_PUBKEY` / `_MAX_TTL_SEC` / `_RATE_PER_MINUTE`) | decision D1's escape hatch: fail-closed means an `apps/api` outage locks you out of the machine you would fix it from. Verified **locally**, with no api call, because the api being down is the premise | Isolated | low — `sodiumoxide`, `base64` and `serde_json` were already dependencies |
| S20 | applied 2026-09-15 (T3.5) | `src/auth.rs` (`Authorizer` field, `new` / `new_with`, the branch in `authorize`) | a `bg.`-prefixed token is decided by `Breakglass` before the api is consulted, and **after** the decision cache so a punch retry is not a replay; the nonce becomes the `conn_audit_ref`; `DecisionSource::Breakglass` | every caller of `authorize` gets the emergency path for free and none of them has to know the token format — both chokepoints (S5, S8) were already calling it | Structural (small) | low — our own module |
| S21 | applied 2026-09-15 (T3.5) | `src/main.rs` (`:35-37`) | three `--breakglass-*` rows in the clap arg string | same | Structural (small) | ⚠ medium — same arg string as S2 and S14 |
| S22 | applied 2026-09-15 (T3.5) | `tests/t35_breakglass.rs` (new), `tests/harness/mod.rs` (`hbbs_expect_exit`, `wait_for_log`, stdout captured) | 7 tests against the real binary: authorizes while the api is down, never asks a healthy api, expired / wrong-device / forged / over-long refused, replay refused, punch retry not a replay, disarmed by default, a bad key refuses to boot | a 🔴 path that bypasses every authorization check needs proof it cannot be bypassed itself | Isolated | low |
| S23 | applied 2026-09-15 (T3.6) | `src/breakglass.rs` (`AuditLog`, `AuditRecord`, `Reconciler`, three more config keys) | every use appended and **fsynced** before the decision returns; a use that cannot be written is refused; a slow background task replays unacknowledged records to `POST /api/internal/breakglass/reconcile`, tracked by a cursor file that carries a hash of the log's opening bytes | the reason an operator is on this path is that `apps/api` is down, so an audit that went there first would fail exactly when it mattered — "every use is logged" would be quietly untrue | Isolated | low — `chrono`, `reqwest` and `serde_json` were already dependencies |
| S24 | applied 2026-09-15 (T3.6) | `src/rendezvous_server.rs` (`start_with_bind`), `src/auth.rs` (`breakglass_reconciler`), `src/main.rs` (`:38-40`) | the reconciler spawned as its own task, and three `--breakglass-audit-*` / `--breakglass-reconcile-sec` rows | it is not on any request path — the records are already durable, this only catches `apps/api` up | Structural (small) | ⚠ medium — same arg string as S2, S14, S21 |
| S25 | applied 2026-09-15 (T3.6) | `tests/t35_breakglass.rs`, `tests/harness/mod.rs` (`dir()`, `switchable()`) | 2 more integration tests — the record is on disk during the outage and the cursor has not moved; the api recovers and the record is replayed exactly once — plus 9 unit tests over the log and cursor | the failure this guards against is silent by nature: a record that is never written, or a cursor that advances past one the api never got | Isolated | low |
| S26 | applied 2026-09-15 (T3.7) | `src/auth.rs` (`DecisionStats`, `DeniedAttempt`, `AuthRequest.gate`, `record`, `authorize` split into `authorize` + `decide`) | one `key=value` log line per decision — allow *and* deny, with source, gate, latency and audit ref — plus counters and a bounded tail of recent refusals | **a refused connection leaves no row anywhere else** when the api was never asked, which is every no-token, fail-closed and break-glass refusal. Logged inside `authorize`, so a future chokepoint cannot be added and forget | Isolated | low — our own module |
| S27 | applied 2026-09-15 (T3.7) | `src/rendezvous_server.rs` (`check_cmd`, both chokepoints) | `auth-decisions(ad)` in the runtime console beside `punch-requests(pr)`, and the two ad-hoc denial log lines deleted in favour of S26's | `pr` answers "who was introduced to whom"; this answers the one it cannot — who was refused, from where, and why | Structural (small) | ⚠ medium — `check_cmd`'s match arms and the help string are upstream's |
| S28 | applied 2026-09-15 (T3.7) | `tests/t37_decision_log.rs` (new), `tests/harness/mod.rs` (`console`) | 5 tests: both outcomes logged with latency, the two gates named apart, a refusal the api never saw still recorded, and the console's summary / tail / paging / clear / help | the failure here is silence, which no other test would notice | Isolated | low |
| S29 | applied 2026-09-15 (T3.5.2) | `src/enrolment.rs` (new), `src/lib.rs` (`pub mod enrolment;`) | `EnrolmentConfig` (`ENROL_REQUIRED` / `_CACHE_TTL_MS` / `_RATE_PER_MINUTE`) and `Enrolment` — `POST /api/internal/enrolled` over its own `reqwest` client, a per-id in-flight guard and a global token bucket | upstream's `RegisterPk` answers `OK` to any well-formed request, so an unenrolled device claims an id and appears online. The rate limit is its own thing because `RegisterPk`'s existing per-ip and per-peer limits bound *the device*, not what hbbs does to `apps/api` | Isolated | low — `reqwest`, `base64` and `serde_json` were already dependencies |
| S30 | applied 2026-09-15 (T3.5.3) | `src/peer.rs` (`Peer.user`, `.status`, `.enrol_checked`; `PeerMap::get`), `src/database.rs` (`set_peer_enrolment`) | the enrolment verdict cached on the peer row, in the `user` and `status` columns upstream declares, selects and indexes but **never writes** | a verdict that lived only in memory would give the whole fleet a free interval of unchecked registration on every hbbs restart — and, more importantly, an `apps/api` outage has to leave hbbs holding something. `user`/`status` were already `select`ed by `get_peer`, so this needs no schema change and `sqlx`'s compile-time checks pass against the committed `db_v2.sqlite3` | Isolated | ⚠ medium — upstream owns these columns and gives `status` a different meaning in Pro (`disabled: v.status == Some(0)`, commented out at `peer.rs:39,52`). If upstream ever starts writing them, the two meanings collide |
| S31 | applied 2026-09-15 (T3.5.2) | `src/rendezvous_server.rs` (`:1`, the `enrolment` field, `start`/`start_with_bind`, and ~40 lines in the `RegisterPk` arm) | the verdict read, the `NOT_DEPLOYED` refusal, and the deferred first contact | **the registration boundary.** It reads memory only and spawns the api call, because `handle_udp` is awaited **inline** in `io_loop` (`:339`) while the TCP path spawns per connection (`:1584`) — an HTTP call here would put every datagram the server handles, for the whole fleet, behind one round trip | Structural | ⚠ **high** — same file and same churn as S5 and S8 |
| S32 | applied 2026-09-15 (T3.5.2) | `src/main.rs` (three `--enrol-*` rows, `EnrolmentConfig::from_args` + `.log()`) | same | the fourth block of rows in one arg string | Structural (small) | ⚠ medium — same arg string as S2, S14, S21, S24 |
| S33 | applied 2026-09-15 (T3.5.2) | `tests/t352_enrolment.rs` (new), `tests/harness/mod.rs` (`register_pk_on`, `udp_socket`, `enrol_args`, `enrolled`, `is_enrolment`) | 9 tests against the real binary: refused and told to deploy, enrolled and registered, the answer cached across six registrations, an api outage that deregisters nobody, a deployed device recovering on its own, a refused device not claiming the id, `AUTH_API_URL` alone not turning it on, a boot refusal, and an unparseable answer read as an outage | a 🔴 gate whose failure mode is a fleet going dark needs the outage cases proved, not only the refusal | Isolated | low |
| S34 | applied 2026-09-15 (T3.5.4) | `src/rendezvous_server.rs` (`update_addr`, `:849-925`) | the same enrolment verdict read on the **`RegisterPeer` heartbeat**, forcing `request_pk: true` for a refused peer | S31 alone does not reach a device that is *already* registered: a settled client sets `key_confirmed` and stops sending `RegisterPk` entirely, so un-enrolling it in the console left it showing online forever. `request_pk` walks the client back into the arm where `NOT_DEPLOYED` lives, and because `last_reg_time` is refreshed only when we are *not* asking, the device ages out through upstream's own `REG_TIMEOUT` rather than through anything of ours | Structural | ⚠ **high** — same file as S5/S8/S31, and this one is on the hottest path in the server |
| S35 | applied 2026-09-15 (T2.7) | `src/breakglass.rs` (`AuditRecord.exp`) | the capability's own expiry carried on every audit record and therefore into `POST /api/internal/breakglass/reconcile` | the console cannot learn it any other way. Capabilities are minted **offline**, so the only moment a server hears of one is when it is used — without this a reconciled record says an emergency access happened but not whether it is still happening. `#[serde(default)]`, because the audit log is append-only and may span an upgrade: a record that fails to parse wedges every record behind it | Isolated | low — our own format |
| S36 | applied 2026-09-15 (T5.1) | `tests/harness/api.rs`, `tests/harness/relay.rs`, `tests/harness/peer.rs`, `tests/harness/world.rs` (all new), `tests/harness/mod.rs` (`hbbs_full`), `tests/t51_harness.rs` (new) | the standing end-to-end harness: a real `apps/api` on its own MongoDB database, a real `hbbs` pointed at it, a real `hbbr` sharing its key, and two clients with two tokens — brought up together as a `World`, with fixtures built through the console's own API and sessions carried through the relay as bytes | every remaining Milestone 5 question needs something a stub cannot do: *decide*. A stub can return garbage or a 503, which is what S7's harness is for, but it cannot tell a grant from a revocation, and the bypass tests (T5.7) are worth nothing against a simulated relay | Isolated | low — test-only; it spawns the binaries and speaks the wire, and patches neither |
| S37 | applied 2026-09-15 (T5.2) | `tests/t52_matrix.rs` (new) | the multi-user matrix, every row on **both** gates: own device, another user's, a granted one with its permission mask, and an admin — plus the punch-then-relay-fallback pair and one device answering two users at once | the fork's own history is the argument: before T3.3b the punch gate was complete and `handle_request_relay` authorized nothing, so a matrix that tested one gate would have called that system correct. The two are also not symmetrical — different `from_id`, different refusal field, and the relay gate **overwrites** context that arrives from A | Isolated | low — test-only |


### Notes on the `S` rows

**S37 closes the last clause of T3.3b and corrects a row of the task board.**
The `connection_logs` count — one connect that falls back to a relay produces
exactly one row — is now asserted against Mongo rather than at the decision
layer, and the fallback is shown to carry the *same* `conn_audit_ref` as the
punch it continued. The corrected row is **admin → ungranted device = deny**:
`authorize()` consults ownership and grants and never the role, deliberately
since T1.6, and PLAN.md/TASK.md said otherwise until T5.2 ran it. The gap list
below keeps `BROKER_STRICT_IP`, which no single-host harness can reach.

**S36's harness reaches `hbbr` on the LAN address, not on loopback, and that is
not a preference.** `handle_connection` (`src/relay_server.rs:386-393`) answers
every non-websocket loopback connection with the runtime console instead of
relaying — no log line, no error, and a session that pairs with nobody. It is
upstream behaviour, `hbbr` stays unpatched, and the consequence is a deployment
note as much as a test one: an all-on-one-host `hbbs` configured with
`-r 127.0.0.1:21117` has working direct connections and every relayed one
hanging. Recorded in docs/CONTEXT.md §7, which did not say so before T5.1.

**S10 is where to look if clients hang after a merge.** Three things have to
stay together or the handshake half-works: the offer must be sent *before* the
read loop (the client speaks second, so nobody speaks at all if this moves);
the `KeyExchange` arm must `return true`, because `handle_tcp`'s tail is
`false` and closing the connection is right for upstream's one-shot messages
and fatal for a handshake; and the encryptor must stay *inside* `Sink`, because
the sink is parked in `tcp_punch` and sealed by whichever other connection
answers — `a_plaintext_peer_can_answer_an_encrypted_controller` (S12) is the
test that catches that last one.

**S10 is not behind a flag, and is safe unflagged in one direction only.** The
offer goes to every TCP connection, because at that point `hbbs` has not read a
byte and cannot tell who wants one. That is survivable because upstream's client
already skips an unsolicited `KeyExchange` on every read of this connection
(`get_next_nonkeyexchange_msg`, `apps/rustdesk/src/common.rs:1972-1993`), and
because a client that never answers keeps being served in plaintext — which is
required, not merely tolerated: the controlled device answers punches over short
write-only TCP connections that never call `secure_tcp`
(`apps/rustdesk/src/rendezvous_mediator.rs:627`, `:717`, `:995`).

**S5 is the row to check on every merge, and ordering is the whole risk.** The
patch must stay *after* the cheap checks (nothing that was going to be refused
anyway should spend an HTTP request) and *before* the branch that emits
`PunchHole` / `FetchLocalAddr` (which is the act of brokering the connection).
Textually surviving a merge in the wrong position produces a server that
authorizes after it has already introduced the peers.

**S2 and S4 change signatures, so they fail loudly.** `start_with_bind` gained a
parameter and `RendezvousServer` gained a field; a merge that drops either does
not compile. That is deliberate — the alternative, a global or a lazy static,
would let a bad merge produce a server that runs with authorization quietly off.

**Nothing here is behind a flag in the client sense.** The server equivalent is
`AUTH_REQUIRED`, which defaults to *on when `AUTH_API_URL` is set* and off
otherwise: with no `AUTH_API_URL` configured, `Authorizer::authorize` returns a
blind allow and the outbound messages go out byte-identical to upstream's
(`with_authorization_off_the_wire_is_unchanged`, S7).

**S17's ip layer is off by default, and that is a decision, not an oversight.**
`BROKER_VERIFY` (the id check) ships on because it compares two strings and is
blind to address family. `BROKER_STRICT_IP` ships **off** because B registers
over UDP and answers over a new TCP connection, so the port never matches and
even the ip is only usually the same — a dual-stack peer can register over IPv4
and answer over IPv6, and CGNAT hands different flows different public
addresses. Getting that wrong reads as "nobody can connect". Every mismatch is
logged whether or not it is enforced, which is how an operator finds out if
their fleet would survive turning it on. **Not verified against two real devices
on a real network** — see the T3.8 note in TASK.md.

**S16 and S17 are one patch in two halves and must move together.** A merge that
keeps the checks and drops the recording produces a server that brokers
connections and then refuses every answer to them — "nobody can connect", with
the cause in a log line nobody is reading yet. `the_brokered_peer_still_answers_its_waiting_controller`
(S18) is the test that catches it.

**S19 re-implements a wire format it does not own.** `mint-breakglass.ts`
mints capabilities, `services/breakglass.ts` verifies them, and this is the
third implementation of the same three lines. The detail that breaks silently is
that **the signature covers the base64url payload text, not the decoded JSON** —
both readings are plausible and only one has a test. `tests/t35_breakglass.rs`
keeps its own independent copy of the minter for exactly that reason: a shared
helper would let hbbs and its tests agree with each other while both disagreed
with production.

**S23's cursor is a byte offset plus a prefix hash, and the hash is not
decoration.** A byte offset alone cannot survive log rotation: rotate the file,
write one record of the same size, and the offset lands exactly at the new end —
so the reconciler goes *silently* idle with records it never sent. The log is
append-only, so its opening bytes are fixed while it is the same file; a changed
hash means a new one and the cursor resets. An inode would be the obvious
answer, and `MetadataExt::ino` is not on the Windows build.

**S27 puts who-was-refused on an unauthenticated port, and that is upstream's
design.** The runtime console rides the NAT-test port (`handle_listener2`) and
answers any **loopback** peer with no authentication at all. `auth-decisions`
adds source addresses and device ids to what it will hand out, so a deployment
that exposes that port — through a proxy, a container port mapping, an SSH
tunnel left open — is handing out a list of who tried to reach what.
`the_console_is_reachable_only_from_loopback` pins the branch.

**S31's first-contact branch is the one that is easy to read as a bug.** A
device hbbs has never heard of is answered `OK` and **not written to the peer
table** — not refused, and not registered either. Refusing would break T3.5.3's
rule; registering would let a stranger take the id before anyone knows whose it
is, which is the whole point of the task. The deferral costs one round trip and
uses upstream's own mechanism to collect it: a peer with no `pk` is answered
`request_pk: true` on its next heartbeat (`update_addr`, `:834`), so the client
sends `RegisterPk` again and by then the verdict has landed.
`an_enrolled_device_registers_exactly_as_upstream` (S33) asserts on the
`update_pk` log line for exactly this reason — every answer being `OK` does not
prove the device ended up registered.

**S29/S31 ship off (`ENROL_REQUIRED=N`) and that is deliberate.** Setting
`AUTH_API_URL` turns connection authorization on with no second switch (S1),
and the opposite choice is made here: an existing deployment upgrading hbbs
would otherwise start refusing every device that had never been through
`rustdesk --deploy` — a fleet-wide outage produced by installing a patch
release. `the_api_url_alone_does_not_turn_it_on` (S33) pins it.

**S34 is on the heartbeat path and must stay an in-memory read.** It exists
because S31 alone cannot reach a device that is already registered: a settled
client sets `key_confirmed` and stops sending `RegisterPk` entirely — it sends
`RegisterPeer` and nothing else (`apps/rustdesk/src/rendezvous_mediator.rs`).
This runs for every device every few seconds, so the verdict is read from the
peer under a lock and the api call is spawned, sharing S29's
`ENROL_RATE_PER_MINUTE` budget deliberately: two paths that each had their own
would add up to more than an operator asked for. `the_heartbeat_does_not_ask_the_api_every_beat`
(S33) is the test that catches a merge that turns this into a call per beat.

**`libs/hbb_common` is untouched** and should stay that way. Everything above
uses the proto exactly as upstream ships it: no field was added, and no field
changed meaning. That is what keeps "no proto change, no client change" true.

---

## Known gaps, not yet patched

| Site | What is wrong | Task |
|---|---|---|
| The relay-fallback `RelayResponse` (`handle_tcp`) | carries **no id** — `create_relay` sends it with `initiate = false` (`apps/rustdesk/src/rendezvous_mediator.rs:579-604`) — so S17's id layer has nothing to check and only `BROKER_STRICT_IP`, which ships off, separates a stranger's ack from the real peer's. It steers the controller nowhere (A keeps its own uuid and relay server, `client.rs:1750-1760`), so this is a race and not a redirection. Pinned by `the_relay_fallback_ack_carries_no_id_and_still_reaches_the_controller` (S18) | residual of **T3.8** |
| `BROKER_STRICT_IP` (S17) | implemented and **never run against two real devices on a real network**. The loopback harness cannot reach it — every party there shares 127.0.0.1 — so it is covered only by unit tests over `BrokerLedger::check`. The dual-stack and CGNAT cases the default protects against are therefore predicted, not observed. **T5.2 ran and could not reach it** — every party in that harness shares one host, so "the answer came from the peer's registered IP" cannot be made false there | **T5.10**, and honestly two machines on a real network |
| `breakglass::Breakglass` nonce store (S19) | **per process**: a capability spent against one hbbs can be spent again against another, or against the same one after a restart. Bounded by `exp` (minutes). Closing it means shared state between rendezvous servers | accepted, documented |
| `Enrolment`'s pk check | `apps/api` records a changed public key and does **not** refuse on it, because which key pair `rustdesk --deploy` reads on an installed host is not settled — T3.5.1 could not run the CLI (it needs `/Applications` + root). The strict reading of T3.5.2 is one line away in `services/enrolment.ts` | **T5.5** |
