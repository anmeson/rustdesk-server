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

### Notes on the `S` rows

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

**`libs/hbb_common` is untouched** and should stay that way. Everything above
uses the proto exactly as upstream ships it: no field was added, and no field
changed meaning. That is what keeps "no proto change, no client change" true.

---

## Known gaps, not yet patched

| Site | What is wrong | Task |
|---|---|---|
| The relay-fallback `RelayResponse` (`handle_tcp`) | carries **no id** — `create_relay` sends it with `initiate = false` (`apps/rustdesk/src/rendezvous_mediator.rs:579-604`) — so S17's id layer has nothing to check and only `BROKER_STRICT_IP`, which ships off, separates a stranger's ack from the real peer's. It steers the controller nowhere (A keeps its own uuid and relay server, `client.rs:1750-1760`), so this is a race and not a redirection. Pinned by `the_relay_fallback_ack_carries_no_id_and_still_reaches_the_controller` (S18) | residual of **T3.8** |
| `BROKER_STRICT_IP` (S17) | implemented and **never run against two real devices on a real network**. The loopback harness cannot reach it — every party there shares 127.0.0.1 — so it is covered only by unit tests over `BrokerLedger::check`. The dual-stack and CGNAT cases the default protects against are therefore predicted, not observed | **T5.2** / **T5.10** |
| `RegisterPk` (`:371-455`) | answers `OK` for any well-formed request: an unenrolled device can still claim an id and appear online | **T3.5.2** |
