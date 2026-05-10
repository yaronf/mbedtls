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

## Why the obvious fix didn't work — and the misdiagnosis

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
`retransmit_state = WAITING` set immediately after KU send. The
inference at the time was "WAITING got cleared between the KU send and
the next `f_recv_timeout` call" — and several suspects were enumerated
for that clear (stale handshake-flight ACK, state-machine transitions,
read/handshake lifecycle bookkeeping). Step 4 was thought to be in place.

**That diagnosis was wrong.** Re-reading the code:

- `fetch_input` (`ssl_msg.c:2110-2114`) selects the timeout via
  `ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER`, **not** via
  `retransmit_state`. After the handshake, `ssl->state ==
  HANDSHAKE_OVER`, so the retransmit-timeout branch is unreachable
  regardless of what `retransmit_state` holds. The default
  `read_timeout = 0` (blocking) wins, hence `f_recv_timeout: 0`.
- `retransmit_state` was *never* cleared. It stayed at `WAITING` —
  `fetch_input` just doesn't consult it post-handshake.
- Step 4's intended change (consult `retransmit_state` rather than
  `state`) was the right idea but the prototype attempted in this
  session evidently did not land correctly; the read path continued
  using `read_timeout`. Whether step 4 was incorrectly written or got
  reverted alongside the others wasn't recorded.

So the "shared-flight reuse" path failed for a fixable reason — an
incomplete step 4 — not because of any state-machine coupling between
the handshake flight and post-hs messages. The original "Q1 dissolved
by the design choice" framing carried this misdiagnosis forward; see
§Q1 below for the corrected answer.

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

### High-level changes (slot-based design)

1. **Add `dtls13_post_hs_retransmit[]`** alongside `dtls13_pending_acks[]`
   in `mbedtls_ssl_context`, sized `MBEDTLS_SSL_DTLS13_MAX_POST_HS_RETRANSMIT
   = 3`. Bump `MBEDTLS_SSL_DTLS13_MAX_PENDING_ACKS` from 2 to 3 to keep
   the arrays aligned.

2. **Replace `register_pending_ack`'s overwrite-slot-0 fallback** with
   an error return so callers can fail the send rather than silently
   dropping a pending retransmit.

3. **Capture record bytes at send time.** In `ssl_tls13_write_key_update`,
   `ssl_tls13_write_new_connection_id`,
   `ssl_tls13_write_request_connection_id`: after `flush_output`, call
   `ssl_dtls13_register_post_hs_retransmit(bytes, len)` alongside the
   existing `ssl_dtls13_register_pending_ack`. The bytes copy is the
   freshly built record (epoch, seq, ciphertext) — captured before
   `out_buf` is reused.

4. **Drive the timer.** Recompute the next deadline as
   `min(existing handshake deadline, min(post_hs_retransmit slot
   deadlines))` on every event that changes a deadline. On expiry,
   walk slots, retransmit any past-due, double their backoff, surface
   `TIMEOUT` if any exceeds `hs_timeout_max`.

5. **Match ACKs to retransmit slots.** In `ssl_dtls13_process_ack`,
   after the existing `dtls13_pending_acks[]` walk, walk
   `dtls13_post_hs_retransmit[]` for the same `(epoch, seq)`, free
   bytes, clear the slot, recompute the timer.

6. **Update `fetch_input`'s timeout choice** so the post-handshake
   retransmit timer is honored — see §Q1 for the exact change.

7. **Surface budget-exhaust as TIMEOUT.** Set a fatal-error flag when
   any slot exceeds `hs_timeout_max`; the next `mbedtls_ssl_read` (or
   `_write`) returns `MBEDTLS_ERR_SSL_TIMEOUT`. Clear the
   `ku_ack_pending` / `cid_update_ack_pending` flags as part of error
   cleanup so a subsequent reset is well-defined.

Steps 1–2 do not depend on the rest and can land first as
preconditions; step 6 is the minimal `fetch_input` fix that step 3
onward depends on.

### Recommended approach (broad scope): sibling retransmit array, not slot extension

`dtls13_pending_acks[]` today tracks `(epoch, seq, type)` for post-hs
messages and dispatches per-type on-ACK actions (KU install, NCI ack
clear). It is a **dispatch table** — "when ACK X arrives, do Y" —
indexed by sent record number. Its lifetime is "alive from send until
ACK arrives or session resets."

The retransmit machinery has a different lifetime: "alive from send
until ACK arrives **or budget exhausts** (which can be tens of seconds
in the fail case, ending in a fatal-error transition the dispatch
table doesn't know about)." Cramming retransmit fields into the
dispatch slots would make one struct responsible for two unrelated
jobs.

Use a **sibling array** instead:

```c
typedef struct {
    mbedtls_ssl_dtls13_pending_ack_type_t type;  /* 0 == empty */
    uint64_t sent_epoch;
    uint64_t sent_seq;
    unsigned char *bytes;                         /* record bytes for retransmit */
    size_t bytes_len;
    uint32_t retransmit_timeout_ms;               /* current backoff */
    mbedtls_ms_time_t next_retransmit_at;         /* absolute deadline */
    uint8_t retransmit_count;                     /* budget cap */
} mbedtls_ssl_dtls13_post_hs_retransmit;

#define MBEDTLS_SSL_DTLS13_MAX_POST_HS_RETRANSMIT 3
mbedtls_ssl_dtls13_post_hs_retransmit
    dtls13_post_hs_retransmit[MBEDTLS_SSL_DTLS13_MAX_POST_HS_RETRANSMIT];
```

The `(epoch, seq, type)` fields are duplicated between the two arrays
on purpose: `dtls13_pending_acks[]` keeps its single-job role, the new
array drives retransmit. A successful match clears both (single ACK
matches both — a small loop in `process_ack` after the existing slot
walk).

Operation:
- After sending a post-hs HS message, the existing
  `ssl_dtls13_register_pending_ack` populates a `pending_acks[]` slot.
  A new sibling `ssl_dtls13_register_post_hs_retransmit(bytes, len)`
  populates a `post_hs_retransmit[]` slot. Both calls happen at the
  same site (right after `flush_output` in
  `ssl_tls13_write_key_update`, `ssl_tls13_write_new_connection_id`,
  `ssl_tls13_write_request_connection_id`).
- A single timer drives the next wakeup, set to the soonest
  `next_retransmit_at` across all active retransmit slots (recomputed
  on every event that changes a deadline: register, ACK match,
  retransmit, handshake state transition).
- On timer expiry: walk retransmit slots, retransmit any whose deadline
  passed, double their `retransmit_timeout_ms`. If any slot's
  `retransmit_count` exceeds `hs_timeout_max`, surface
  `MBEDTLS_ERR_SSL_TIMEOUT` to the next `mbedtls_ssl_read`.
- On `process_ack` matching a `(epoch, seq)`: the existing dispatch
  walk in `pending_acks[]` runs; afterward, walk
  `post_hs_retransmit[]` for the same `(epoch, seq)`, free its bytes,
  clear the slot, recompute the next-deadline.
- On budget exhaustion: free the slot, set a fatal-error flag the next
  read/write surfaces as `MBEDTLS_ERR_SSL_TIMEOUT`.

Why this is right under broad scope:
- Same code path handles KeyUpdate, NewConnectionId, RequestConnectionId
  (and any future post-hs HS message types) uniformly.
- Adding a new message type = register on send (two calls, both
  alongside an existing pending-ack registration) + the existing
  per-type dispatch in `pending_acks[]` already fires on match.
- Single timer + on-expiry scan is the standard pattern.
- Each struct keeps a single responsibility.

Trade-offs:
- Two parallel arrays instead of one richer one. The duplication of
  `(epoch, seq, type)` is acceptable: it's three uint64s per slot,
  with `MAX_POST_HS_RETRANSMIT = 3` that's ~72 bytes overhead — and it
  preserves the conceptual split.
- Each retransmit slot allocates a bytes buffer; needs cleanup paths
  in `session_reset`, `ssl_close_notify`, and `ssl_free`. Specifically:
  - **`session_reset` mid-retransmit**: walk and free all bytes, cancel
    timer, zero the array.
  - **`ssl_close_notify` while unACKed**: same — drop in-flight
    retransmits.
  - **`mbedtls_ssl_session_save`/`_load`**: post-hs retransmit state
    is connection state, not session state. Do **not** serialize.
    Add an explicit assertion.
  - **OOM at register time**: surface `MBEDTLS_ERR_SSL_ALLOC_FAILED`
    from the send path. Better the application sees the failure than
    a "sent but never delivered" phantom message.
- `MBEDTLS_SSL_DTLS13_MAX_POST_HS_RETRANSMIT = 3`: KU + NCI + RCI can
  realistically overlap (server with CID enabled mid-NCI fan-out when
  the AEAD-limit triggers a KU). 2 is not enough.

### Existing `register_pending_ack` overflow fallback is a correctness bug

`ssl_dtls13_register_pending_ack` at `ssl_msg.c:7647-7657` currently
does:

```c
for (i = 0; i < MBEDTLS_SSL_DTLS13_MAX_PENDING_ACKS; i++) {
    if (slots[i].type == type ||
        slots[i].type == MBEDTLS_SSL_DTLS13_PENDING_ACK_NONE) {
        break;
    }
}
/* If no free slot, overwrite slot 0 (should not happen with
 * MAX_PENDING_ACKS=2 and only two message types …). */
if (i == MBEDTLS_SSL_DTLS13_MAX_PENDING_ACKS) {
    i = 0;
}
```

Today this is defensive-but-unreachable. Under the new design,
overwriting slot 0 silently **drops a pending retransmit**, and once
RCI is added, "only two message types" is no longer true. Replace the
fallback with returning `MBEDTLS_ERR_SSL_INTERNAL_ERROR` (or similar)
so callers can fail the send rather than lose the message. The
`bumping MAX_PENDING_ACKS to 3` change should be applied to the
existing dispatch array as well, so the array sizes stay aligned.

### Alternative (rejected for broad scope): per-message flight slot

A separate post-hs retransmit slot distinct from both
`handshake->flight` and `dtls13_pending_acks[]`. Smaller surgery for a
single message type, but multiplies linearly with each new post-hs HS
message type — wrong choice when fixing all three at once.

### Alternative (viable, not chosen): direct reuse of `handshake->flight`

Initially attempted in this session and reverted. The original write-up
claimed it failed because prior handshake ACKs / state transitions
clear `retransmit_state` on the shared flight; that diagnosis was
wrong (see Q1). The actual failure was an incomplete `fetch_input`
timeout-selection change, which is a small follow-up.

So shared-flight reuse is technically viable. It would need:

1. Steps 1–4 from the original attempt (KU joins flight,
   `send_flight_completed` arms timer, `flight_transmit` and
   `fetch_input` aware of `flight != NULL` post-handshake).
2. A per-message **flight prune on ACK** policy: today
   `mbedtls_ssl_handshake_wrapup` retains the last flight "in case we
   need to resend it" (singular). Under shared reuse, a post-hs KU
   appended to that retained flight stays appended forever; the next
   KU joins, etc. The flight grows. The current `process_ack`
   `all_acked → retransmit_state = FINISHED` branch still fires (good)
   but the flight items themselves are never freed. Need a free-acked-
   items pass on each ACK or at the start of each post-hs send.
3. A KU-budget exhaust → `MBEDTLS_ERR_SSL_TIMEOUT` surface path
   (currently `fetch_input` returns TIMEOUT only when `state !=
   HANDSHAKE_OVER`; needs the same broadening as Q1's fix).

Why we still pick the slot-based design instead:

- **Conceptual fit.** A handshake flight is a *flight* — a contiguous
  group of related messages sent together. Post-hs messages are
  independent (KU is its own logical flight-of-one; NCI is another).
  Reusing the queue muddies what a "flight" means.
- **Lifetime separation.** Handshake-flight items have one well-defined
  lifetime (alive until the handshake completes plus a brief
  retention window). Post-hs items have a different one (alive until
  ACKed or budget exhausts). Sharing one queue means one set of
  invariants doing two unrelated jobs.
- **Scaling.** Adding NCI/RCI as additional shared-flight users
  requires more flight-management bookkeeping; slot-based scales by
  registering a new slot type with the existing dispatch.

But the gap is narrower than the original framing suggested. If the
slot-based design hits an unexpected obstacle, shared-flight is a
realistic fallback.

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

## Test plan — TDD: failing tests committed, implementation pending

Three failing tests have been committed (`cabbe587ca`, 2026-05-10).
Implementation commits should flip them to passing one at a time. This
locks in scope and provides a regression suite.

### Failing tests in tree (today)

1. `tests/dtls13/cases/keyupdate.yaml` — "KeyUpdate timeout:
   client-initiated, server ACK lost". `corrupt_after_pkt: 7
   corrupt_dir: s2c` (handshake + NST through clean; corrupts server's
   KU ACK). Asserts `client_handshake_timeout`. Originally committed in
   `b5ae66e562`; renamed in `cabbe587ca`.

2. `tests/dtls13/cases/keyupdate.yaml` — "KeyUpdate timeout:
   server-initiated, client ACK lost". `corrupt_after_pkt: 8
   corrupt_dir: c2s` (handshake + NST_ACK + HTTP through clean;
   corrupts client's KU ACK). Asserts `server_handshake_timeout`.

3. `tests/dtls13/cases/cid-update.yaml` — "NewConnectionId timeout:
   server-initiated, client ACK lost". `corrupt_after_pkt: 8
   corrupt_dir: c2s`, `send_new_cid: 1` on the server. Asserts
   `server_handshake_timeout`.

### Why threshold 8 for the c2s tests (calibration trap)

Initial drafts used `corrupt_after_pkt: 4 corrupt_dir: c2s` for the
server-initiated tests. These PASSED — but **for the wrong reason**.
With threshold 4, the corruption fires before the client's NST ACK
reaches the server, so the server times out in NST_WAIT_ACK (already
fixed in `46f89e8f2c`) — not in KU/NCI retransmit (the bug we're
trying to catch). The test would have stayed green even if the KU/NCI
fix never landed.

Threshold 8 lets c2s packets 1–8 (handshake CH + Finished+ACK + NST
ACK + HTTP request) through clean, isolating the KU/NCI ACK path.

If you ever add more post-handshake server-initiated retransmit tests,
calibrate the threshold the same way: count c2s packets through the
last "already-fixed" timeout milestone, then add 1.

### Slot-overflow test (new)

Send three overlapping post-hs messages (server-initiated NCI burst
while a KU is in flight, RCI from the client at the same time) and
assert one of:

- (a) clean `MBEDTLS_ERR_SSL_ALLOC_FAILED` from the send path that
  couldn't register — the application observes the failure.
- (b) connection-level TIMEOUT if a registered message hits its budget.

What we explicitly do **not** want: silent drop of one message while
the others march on. This guards against a regression where someone
"fixes" the new register-overflow error by reverting to the old
overwrite-slot-0 behavior.

### Positive retransmit-progress test (deferred)

A test for retransmit *progress* (KU sent, peer ACK dropped once,
retransmit succeeds) was considered but not added in `cabbe587ca`. It
requires the proxy to randomly drop a single encrypted record, which
udp_proxy's `drop=N` cannot do today (the random-drop path explicitly
excludes `ApplicationData`, which is how DTLS 1.3 encrypted records
classify).

Options when adding this test:
- Extend `corrupt_after_pkt` with a `corrupt_count=N` cap that
  corrupts only the first N triggered packets, then lets subsequent
  packets through. A retransmit after the corruption stops would be
  non-corrupt and would get through.
- Extend `drop=N` to include ApplicationData (would need a new option
  or a flag to override the existing exclusion).
- Add a dedicated `drop_post_hs_pkt=N` option that drops only the Nth
  packet matching some pattern, deterministically.

This is out of scope for the failing-test commit. Defer to the
implementation PR.

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

## API contract change: prolonged WANT_WRITE under retransmit

Today, `mbedtls_ssl_send_key_update` returns `MBEDTLS_ERR_SSL_WANT_WRITE`
while a previous KU is unACKed (`dtls13_ku_ack_pending == 1`). With the
new retransmit, "previous KU is unACKed" can mean "the retransmit
machinery is still trying for up to `hs_timeout_max`," which under
default settings is tens of seconds.

This is intentional, but applications need to know:

- Observing prolonged `WANT_WRITE` on a KU call is **expected** during
  ACK loss. It means retransmit is in progress.
- On budget exhaust, the connection enters a fatal-error state. The
  next `mbedtls_ssl_read` (or `_write`) returns
  `MBEDTLS_ERR_SSL_TIMEOUT`, and the `ku_ack_pending` flag clears as
  part of error cleanup.
- An application that polls KU in a tight loop while seeing `WANT_WRITE`
  will burn CPU but not deadlock — it eventually sees TIMEOUT.

Documented here so the API contract is captured before integrators
write workarounds.

## Out of scope

- **KeyUpdate during a still-pending KU ACK** — already handled by the
  `dtls13_ku_ack_pending` guard returning `WANT_WRITE`. No code change
  needed; see "API contract change" above for the behavior under
  retransmit.
- **Changing the retransmit budget** (`hs_timeout_min`, `hs_timeout_max`)
  for post-hs messages specifically. Use the same configuration as the
  handshake retransmit; if separate tuning is desired, that's a
  follow-up.
- **Per-message-type retransmit policies** (e.g. KU retransmit fewer
  times than a handshake message). Treat all post-hs HS messages
  identically; per-type policy can be a follow-up.

## Answers to the open questions (decided up front)

### Q1: What clears `retransmit_state` post-KU on the shared flight?

**Nothing clears it.** The premise of the question was wrong (see
"Why the obvious fix didn't work — and the misdiagnosis" above). After
`send_flight_completed` sets `retransmit_state = WAITING`, that value
is preserved through the next `mbedtls_ssl_read` entry. The bug we
observed (`f_recv_timeout: 0`, blocking read) comes from `fetch_input`
selecting its timeout based on `ssl->state != HANDSHAKE_OVER`, not on
`retransmit_state`. Post-handshake, `ssl->state == HANDSHAKE_OVER`, so
the retransmit-timeout branch is unreachable and `read_timeout = 0`
(blocking) is used.

The fix is to broaden `fetch_input`'s timeout selection: also use
`retransmit_timeout` when `retransmit_state == WAITING`. Concretely,
change the check at `ssl_msg.c:2110` from

```c
if (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    timeout = ssl->handshake->retransmit_timeout;
} else {
    timeout = ssl->conf->read_timeout;
}
```

to

```c
if (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER ||
    (ssl->handshake != NULL &&
     ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_WAITING)) {
    timeout = ssl->handshake->retransmit_timeout;
} else {
    timeout = ssl->conf->read_timeout;
}
```

(plus a NULL-guard on `ssl->handshake` for the existing branch, since
`handshake` is no longer guaranteed alive post-wrapup in all paths —
see `mbedtls_ssl_handshake_wrapup` at `ssl_tls.c:7539-7550` which
**keeps** the handshake structure alive in DTLS specifically so a
post-handshake retransmit can use it. Code today reaches
`ssl->handshake->retransmit_timeout` for non-HANDSHAKE_OVER states only
because the same wrapup code path runs in that order.)

This change has implications for the **design choice** between
shared-flight reuse and the slot-based design (see §Recommended
approach). The shared-flight design is no longer "broken by state
coupling" — it's a viable alternative on its merits.

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
