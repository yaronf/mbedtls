# KeyUpdate Retransmit (and post-handshake message retransmit) Plan

**Status**: Open. Failing test in tree (`b5ae66e562`); fix not yet implemented.
**RFC reference**: RFC 9147 §5.8 (Retransmission), §7 (Acknowledgement Messages), §8 (KeyUpdate)
**Created**: 2026-05-10
**Related commits**:
- `aef837a508` — TIMEOUT propagation in `wait_ack_step` (Area 12 finding 6)
- `46f89e8f2c` — Re-arm retransmit timer for WAIT_ACK states
- `b5ae66e562` — Re-add KeyUpdate timeout test as known-failing

---

## Motivation

KeyUpdate is a post-handshake handshake message (HS type 24). RFC 9147 §5.8
(Retransmission) and §7 (Acknowledgement Messages) require **all** handshake
messages — including post-handshake ones — to follow flight retransmit /
ACK semantics: on retransmit-timer expiry without an ACK, the sender
retransmits; after the budget exhausts, the connection times out.

Today's mbedtls implementation (`ssl_tls13_write_key_update` at
`ssl_msg.c:7767`) does **not** honor this for KeyUpdate:

1. `mbedtls_ssl_write_handshake_msg_ext` explicitly skips appending KU to
   `handshake->flight` (the queue `mbedtls_ssl_resend` walks):

   ```c
   /* ssl_msg.c:3131 */
   /* Post-handshake messages (KeyUpdate) are not retransmitted
    * by the flight machinery — skip the flight append. */
   if (ssl->handshake != NULL &&
       hs_type != MBEDTLS_SSL_HS_KEY_UPDATE) {
       ssl_flight_append(ssl);
   }
   ```

2. After sending, the code only registers `(epoch, seq)` in
   `dtls13_pending_acks[]` for ACK *matching*; no retransmit timer is
   armed and no flight item exists to retransmit.

When the peer's ACK is lost, the sender's `dtls13_ku_ack_pending` flag
stays `1` forever, the new outbound transform sits in
`dtls13_transform_pending_out` indefinitely, and `mbedtls_ssl_read` loops
on corrupted/missing records without ever surfacing `TIMEOUT` to the
caller.

This is **not** a missing RFC feature — it's an RFC 9147 compliance bug.
The same gap likely exists for `NewConnectionId` and
`RequestConnectionId` (also post-handshake handshake messages); see
"Scope" below.

## Failing test

`tests/dtls13/cases/keyupdate.yaml` "KeyUpdate timeout: server ACK lost,
client retransmit budget exhausts" — committed as known-failing in
`b5ae66e562`. Asserts `client_handshake_timeout` ("handshake timeout"
log line) on a scenario where the proxy corrupts every s2c packet
starting from packet 8 (after the handshake is fully ACKed). Today the
client hangs in `mbedtls_ssl_read`; the test expects exit 1 with the
timeout log line.

## Why the obvious fix didn't work

Attempted in session 2026-05-10:

1. **Remove the `hs_type != KEY_UPDATE` exception** in `write_handshake_msg_ext`.
   Result: KU now appears in the flight (verified via debug print
   "DTLS 1.3: appending hs msg type 24 to retransmit flight").

2. **Call `mbedtls_ssl_send_flight_completed` after KU send** to set
   `retransmit_state = WAITING` and arm the timer.
   Result: `set_timer to 100 ms` fires; `retransmit_state = WAITING`
   logged.

3. **Adjust `flight_transmit`'s state check** from `state ==
   HANDSHAKE_OVER → FINISHED` to `state == HANDSHAKE_OVER && flight ==
   NULL → FINISHED`, so a non-empty flight in HANDSHAKE_OVER still
   re-arms the timer.

4. **Adjust `fetch_input`'s timeout choice** to use `retransmit_timeout`
   when `retransmit_state == WAITING`, regardless of state.

After all four, the client's `f_recv_timeout` still showed `0 ms`
(blocking) shortly after KU send. Instrumentation showed
`retransmit_state = WAITING` was set immediately after KU send, but at
the next f_recv_timeout call it had been cleared. The clear point was
not located in the time available; suspects:

- The previous handshake's flight items (still in the queue) get
  matched by an old ACK that processes asynchronously, triggering
  `process_ack`'s `all_acked → FINISHED` branch.
- A state machine transition (CLIENT_FINISHED_WAIT_ACK exit, NST
  receive, etc.) clears `retransmit_state` via a path I didn't
  enumerate.
- The client's `mbedtls_ssl_handshake` tail vs `mbedtls_ssl_read` entry
  has lifecycle bookkeeping that resets retransmit state.

Reverted all four changes; KU test remains failing.

## Architecture (current)

### Outbound paths

| Message              | Path                                        | Flight append? | Timer armed?         |
|----------------------|---------------------------------------------|----------------|----------------------|
| In-handshake (CH, SH, EE, Cert, CV, Finished) | `write_handshake_msg_ext` → `flight_append` → `flush_output` → caller arms via `flight_transmit` (initial) or `send_flight_completed` (from finalize_server_hello, write_hello_retry_request, write_server_finished, write_client_finished)              | Yes            | Yes                   |
| NewSessionTicket     | `write_handshake_msg_ext`                   | Yes (no exception) | No explicit arm; relies on… [actually, NST works — let me check] |
| KeyUpdate            | `ssl_tls13_write_key_update` → `start/finish_handshake_msg` → `flush_output`           | **No** (excluded by `hs_type != KEY_UPDATE`) | No                   |
| NewConnectionId      | `ssl_tls13_write_new_connection_id` → `start/finish_handshake_msg` | Yes (no exception in code today) | Probably no — uses `dtls13_pending_acks[]` only |
| RequestConnectionId  | `ssl_tls13_write_request_connection_id`     | Yes? | Probably no |

Note: NST's working retransmit was empirically confirmed in the
NST_WAIT_ACK timeout test. NST goes through `write_handshake_msg_ext`,
gets appended to flight (no exclusion for it). The server's
`write_new_session_ticket` calls `mbedtls_ssl_send_flight_completed` (or
similar) which arms the timer. KeyUpdate doesn't have an analogous arm.

### Retransmit state model

- `retransmit_state ∈ {PREPARING, SENDING, WAITING, FINISHED}`
- Set sites (`grep retransmit_state =`):
  - `flight_transmit`: → `WAITING` after sending a flight; → `FINISHED` if
    handshake is over (now: `state == HANDSHAKE_OVER && flight == NULL`)
  - `send_flight_completed`: → `WAITING` (or `FINISHED` if last received
    was Finished)
  - `recv_flight_completed`: → `PREPARING` (or `FINISHED` if last
    received was Finished)
  - `process_ack`: → `FINISHED` if `all_acked`; → `SENDING` if partial
    ACK
  - `mbedtls_ssl_dtls13_wait_ack_step`: → `FINISHED` on implicit ACK
  - `ssl_handshake_init`: → `WAITING` or `PREPARING` depending on flight
- The `WAITING` value is what `fetch_input` checks (post-fix at L2117)
  to decide between `retransmit_timeout` (continue retransmits) and
  `read_timeout` (block forever).

### ACK matching for post-handshake messages

`dtls13_pending_acks[]` (size 2) holds `(epoch, seq, type)` for
post-handshake messages awaiting ACK. On ACK receive,
`process_ack` walks the slots and dispatches per-type actions
(`PENDING_ACK_KEY_UPDATE` → install pending outbound transform;
`PENDING_ACK_NEW_CONNECTION_ID` → clear `dtls13_cid_update_ack_pending`).

This mechanism is parallel to the flight-item ACK matching done by
`ssl_dtls13_ack_mark_flight_item`. They serve different purposes:
- Flight-item ACKs drive **retransmit progress** (which items have been
  seen).
- Pending-ACK slots drive **state-machine progress** (e.g. install the
  new outbound transform now that the peer has confirmed it can decrypt).

For the retransmit fix, we need both to fire on the relevant ACK: the
flight-item ACK marks the KU as acked (so retransmit stops); the
pending-ACK slot dispatches `key_update_install_outbound`.

## Proposed design

### Goal

When the peer's ACK of a KeyUpdate is lost:
1. The KU sender's retransmit timer fires.
2. `mbedtls_ssl_resend` walks the flight, finds the unacked KU, retransmits.
3. Timer doubles up to `hs_timeout_max`; eventually `ssl_double_retransmit_timeout` exhausts the budget.
4. `mbedtls_ssl_read` returns `MBEDTLS_ERR_SSL_TIMEOUT` to the caller.

### High-level changes

1. **Stop excluding KeyUpdate from the flight append** (`ssl_msg.c:3133-3134`).
   Remove the `hs_type != MBEDTLS_SSL_HS_KEY_UPDATE` check. KU goes
   through the same flight machinery as in-handshake messages.

2. **Arm the retransmit timer after KU send.** In
   `ssl_tls13_write_key_update`, after the `flush_output` call, call
   `mbedtls_ssl_send_flight_completed(ssl)` (DTLS path only).

3. **Investigate and fix the WAITING-cleared-by-prior-ACK issue.**
   This is the unresolved blocker. Options to investigate:
   - Clear the previous flight (`flight_free`) before appending the new
     KU item so old ACKs can't "all-ack" the queue.
   - Replace flight reuse with a per-message flight (one flight per KU
     send), distinct from the handshake's main flight. Cleaner separation
     but bigger change.

4. **Update `flight_transmit`'s state check** to keep the timer armed
   when there's an active flight, even in HANDSHAKE_OVER. (Already
   prototyped, didn't ship — depends on (3) above for correctness.)

5. **Update `fetch_input`'s timeout choice** so post-handshake retransmit
   is observable. (Already prototyped.)

### Recommended approach (broad scope): extend dtls13_pending_acks[] with retransmit data

`dtls13_pending_acks[]` already tracks `(epoch, seq, type)` for post-hs
messages and dispatches per-type on-ACK actions (KU install, NCI ack
clear). Extend each slot to carry the data needed to retransmit:

- `unsigned char *bytes` (record bytes for retransmit; allocated on send)
- `size_t bytes_len`
- `uint32_t retransmit_timeout_ms` (current backoff value, doubled on expiry)
- `mbedtls_ms_time_t next_retransmit_at` (deadline)
- `uint8_t retransmit_count` (for budget cap)

Operation:
- After sending a post-hs HS message, populate the slot (existing
  `ssl_dtls13_register_pending_ack` already does the (epoch, seq, type)
  part) AND save the record bytes + initialise the backoff state.
- A single timer drives the next wakeup, set to the soonest
  `next_retransmit_at` across all active slots.
- On timer expiry: walk slots, retransmit any whose deadline passed,
  double their `retransmit_timeout_ms`. If any slot's `retransmit_count`
  exceeds the equivalent of `hs_timeout_max`, surface
  `MBEDTLS_ERR_SSL_TIMEOUT`.
- On `process_ack` matching a slot's (epoch, seq): existing per-type
  dispatch fires; free the bytes and clear the slot.
- On budget exhaustion: connection enters a fatal-error state; the next
  `mbedtls_ssl_read` returns TIMEOUT.

This is the right design under broad scope:
- Same code path handles KeyUpdate, NewConnectionId, RequestConnectionId
  (and any future post-hs HS message types) uniformly.
- Already integrated with the per-type ACK dispatch.
- Adding a new message type = register on send + slot uses generic
  retransmit; no per-type retransmit code.
- Single timer + on-expiry scan is the standard pattern.

Trade-offs:
- `dtls13_pending_acks[]` becomes load-bearing for retransmit, not just
  ACK matching — heavier responsibility, more invariants to maintain.
- Each slot allocates a bytes buffer; needs cleanup paths in
  `session_reset` and `ssl_free`.
- `MBEDTLS_SSL_DTLS13_MAX_PENDING_ACKS` (currently 2) must cover the
  worst case of overlapping post-hs messages. Probably stays at 2 for
  KU + NCI; bumping to 3 if RCI must overlap with both.

### Alternative (rejected for broad scope): per-message flight slot

A separate post-hs retransmit slot distinct from both
`handshake->flight` and `dtls13_pending_acks[]`. Smaller surgery for a
single message type, but multiplies linearly with each new post-hs HS
message type — wrong choice when fixing all three at once.

### Alternative (rejected): direct reuse of `handshake->flight`

Initially attempted in this session. Failed because prior handshake
ACKs / state transitions clear `retransmit_state` on the shared flight,
so a post-hs KU appended to the same queue gets its retransmit context
wiped. Could probably be made to work with careful state separation,
but the abstraction is wrong: a handshake flight is one *flight* (a
contiguous group of related messages), whereas post-hs messages are
independent and shouldn't share a queue.

## Scope

**Decision: broad scope** — fix all three post-hs HS messages
(KeyUpdate, NewConnectionId, RequestConnectionId) symmetrically via a
single mechanism. Eliminates the class of bug rather than fixing one
instance.

The chosen design (extend `dtls13_pending_acks[]` with retransmit data)
scales well to broad scope because it's already type-aware: adding a
new post-hs message type means registering on send and providing the
on-ACK dispatch; the retransmit machinery is shared.

Strict-scope (just KU) was considered and rejected — it would leave
two more instances of the same RFC 9147 §7 compliance gap, and the
scaling concern only points more strongly toward the shared-mechanism
design.

## Test plan — TDD: write failing tests first

The first commit of this work should be **failing tests for every
in-scope scenario**. The implementation commits then make them pass
one by one. This locks in scope and provides a regression suite.

### First commit: failing tests

1. **Already in tree (failing today)** — `tests/dtls13/cases/keyupdate.yaml`
   "KeyUpdate timeout: server ACK lost, client retransmit budget
   exhausts". Asserts `client_handshake_timeout`. (Committed in
   `b5ae66e562`.)

2. **Add: NewConnectionId timeout** — symmetric to the KU test. Client
   triggers `send_new_cid=1`; proxy corrupts s2c after the post-handshake
   point so server's ACK of NCI is lost. Server's NCI retransmit
   eventually surfaces TIMEOUT. Asserts `server_handshake_timeout`.

3. **Add: server-initiated KeyUpdate timeout** — server triggers
   `key_update=1`; proxy corrupts c2s after the post-handshake point so
   client's ACK of server's KU is lost. Server's KU retransmit
   eventually surfaces TIMEOUT. Asserts `server_handshake_timeout`.

4. **Add: KeyUpdate retransmit progress (positive case)** — client sends
   KU; proxy uses `drop=2` so ~50% of packets drop randomly, but
   `MAX_HOLD=2` ensures the same packet isn't dropped indefinitely.
   Client retransmits at least once before a non-dropped retransmission
   gets through and is ACKed. Verifies retransmit *progress*, not just
   budget exhaustion. Asserts `client_key_update_acked`.

### Subsequent commits: implementation, one test at a time

Each implementation commit should be expected to flip exactly one
failing test to passing, with no regressions in the existing 56 tests.
A reviewer can verify the diff against the matching test.

### Regression tests to verify continue to pass

- All existing keyupdate.yaml tests (basic KU send/ack, double KU, etc.)
- NST_WAIT_ACK timeout test (commit `46f89e8f2c`)
- All other 56 dtls13 tests in the suite

## In-scope (revised)

- **KeyUpdate retransmit** (client- and server-initiated) — primary fix.
- **NewConnectionId retransmit** — same gap, same mechanism. Symmetric
  fix is essentially free given the chosen design.
- **RequestConnectionId retransmit** — same.
- **Reciprocal KU on `update_requested=1`** — the reciprocal KU send
  goes through the same path; automatically covered.

## Out of scope

- **KeyUpdate during a still-pending KU ACK** — already handled by the
  `dtls13_ku_ack_pending` guard returning `WANT_WRITE`. No change needed.
- **Changing the retransmit budget** (`hs_timeout_min`, `hs_timeout_max`)
  for post-hs messages specifically. Use the same configuration as the
  handshake retransmit; if separate tuning is desired, that's a
  follow-up.
- **Per-message-type retransmit policies** (e.g. KU retransmit fewer
  times than a handshake message). Treat all post-hs HS messages
  identically; per-type policy can be a follow-up.

## Answers to the open questions (decided up front)

### Q1: What clears `retransmit_state` post-KU on the shared flight?

**Dissolved by the design choice.** With the chosen design
(`dtls13_pending_acks[]` slot extension), the new retransmit state
lives on the slot, not on the shared `handshake->flight` /
`handshake->retransmit_state`. Nothing the handshake state machine does
will affect it. We don't need to find the offender for the rejected
"direct flight reuse" approach.

If for some reason we're forced back to the shared-flight design later,
the bisection plan would be: instrument every `retransmit_state =`
write site with a unique log tag, run the failing KU test, and find the
write that fires after `send_flight_completed → WAITING` and before the
first `f_recv_timeout: 0` line.

### Q2: Same `mbedtls_ssl_set_timer` or a separate timer?

**Same.** mbedtls's BIO API exposes one timer per `mbedtls_ssl_context`
(`f_set_timer` / `f_get_timer`). We share it.

The dispatcher needs to compute the next wakeup as
`min(handshake_retransmit_deadline, min(slot.next_retransmit_at))`
whenever any deadline changes (slot register, slot ACK, slot
retransmit, handshake state transitions). On timer expiry, the wakeup
handler walks the active deadlines and fires the one(s) whose deadline
has passed.

This is a small bookkeeping addition to the existing single-timer
machinery. The post-hs slots own their own deadline state; the timer
itself stays a single resource.

### Q3: Share `handshake->flight` or use a separate queue?

**Separate.** This is the core of the chosen design. Sharing the
handshake flight queue is what failed in this session due to lifecycle
coupling. The slot extension in `dtls13_pending_acks[]` gives clean
isolation: post-hs messages are independent (each KU/NCI/RCI is its
own logical "flight of one"), so they shouldn't share the queue meant
for grouped handshake messages.
