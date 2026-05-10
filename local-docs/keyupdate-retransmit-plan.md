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

So the "shared-flight reuse" path failed for two reasons, only the
first of which was visible at the time:

1. The `fetch_input` timeout selection wasn't actually consulting
   `retransmit_state` post-handshake (the missed step 4). Easy fix.

2. The handshake structure is freed at `ssl_msg.c:7202` on the first
   inbound non-handshake record after `HANDSHAKE_OVER`, *before* any
   post-hs KU/NCI/RCI is typically sent. So even with step 4 fixed,
   shared-flight reuse needs the handshake structure to survive long
   enough to hold the flight — which it does not. This was discovered
   later in the same session when a second shared-flight prototype
   crashed with server SIGSEGV; see §Alternative (rejected): reuse
   handshake->flight for the full story.

The original "Q1 dissolved by the design choice" framing carried only
the first misdiagnosis forward; §Q1 below gives the corrected answer.

Reverted all four changes; KU test remains failing.

## Architecture (current)

### Outbound paths

| Message              | Path                                        | Flight append? | Timer armed?         |
|----------------------|---------------------------------------------|----------------|----------------------|
| In-handshake (CH, SH, EE, Cert, CV, Finished) | `write_handshake_msg_ext` → `flight_append` → `flush_output` → caller arms via `flight_transmit` (initial) or `send_flight_completed` (from finalize_server_hello, write_hello_retry_request, write_server_finished, write_client_finished)              | Yes            | Yes                   |
| NewSessionTicket     | `write_handshake_msg_ext`                   | Yes (no exception) | No explicit arm; relies on… [actually, NST works — let me check] |
| KeyUpdate            | `ssl_tls13_write_key_update` → `start/finish_handshake_msg` → `flush_output`           | **No** (excluded by `hs_type != KEY_UPDATE`) | No                   |
| NewConnectionId      | `ssl_tls13_write_new_connection_id` → `start/finish_handshake_msg` | Yes (no exception in code today) | Probably no — uses `dtls13_pending_acks[]` only |
| RequestConnectionId  | `ssl_tls13_write_request_connection_id`     | No (no exception today; never tested under loss) | No — does **not** even register a `dtls13_pending_acks[]` slot today (only sets `dtls13_req_cid_pending`) |

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
flight-item ACK marks the post-hs message as acked (so retransmit
stops); the pending-ACK slot dispatches the per-type action
(`key_update_install_outbound`, `cid_update_ack_pending = 0`, etc.).

### RCI asymmetry: not registered today, different on-ACK semantics

`RequestConnectionId` is the asymmetric case among the three post-hs
HS messages this plan addresses:

- **Today, RCI does not register a `dtls13_pending_acks[]` slot.**
  `ssl_tls13_write_request_connection_id` (`ssl_msg.c:8418`) only sets
  `dtls13_req_cid_pending = 1` and flushes the record. There is no
  on-ACK hook for RCI in `process_ack` and no slot to match.
- **RCI's "fulfilled" condition is not the ACK** — it's the peer
  responding with `NewConnectionId`. `dtls13_req_cid_pending` is
  cleared by NCI receipt, not by the record-layer ACK of our RCI.
- Consequently, even after we wire RCI into the new retransmit
  machinery, the on-ACK dispatch for RCI is essentially a no-op (just
  clears the retransmit slot — `req_cid_pending` stays set until NCI
  arrives). The dispatch case in `process_ack` exists to terminate
  retransmit, not to advance application state.

Implication for the unified design: KU and NCI need both a dispatch
case **and** a retransmit slot; RCI needs **a brand-new dispatch case
plus** a retransmit slot. This makes RCI a slightly larger lift than
the others, not a smaller one.

The per-message-type retransmit semantics are still uniform: send →
register retransmit slot → on ACK match, free slot; on budget
exhaust, surface TIMEOUT. The dispatch table just gets a third entry
where the on-ACK action happens to be a no-op.

## Proposed design

### Goal

When the peer's ACK of a post-handshake handshake message (KeyUpdate,
NewConnectionId, or RequestConnectionId) is lost:

1. The sender's retransmit timer fires.
2. The retransmit machinery finds the unacked message and retransmits.
3. Timer doubles up to `hs_timeout_max`; eventually
   `ssl_double_retransmit_timeout` exhausts the budget.
4. `mbedtls_ssl_read` returns `MBEDTLS_ERR_SSL_TIMEOUT` to the caller.

### High-level changes (sibling-array design)

The chosen design adds a `dtls13_post_hs_retransmit[]` array to
`mbedtls_ssl_context`, parallel to the existing `dtls13_pending_acks[]`
dispatch table. Slot fields hold the message bytes (plaintext + HS
header), original send epoch, sent-record ring, and per-message
backoff state. See §Recommended approach for the rationale, and
§"Alternative (rejected): reuse handshake->flight" for the design we
ruled out after a build failure exposed a structural lifetime
mismatch.

**Preconditions (already landed in the working tree, uncommitted):**

- Bumped `MBEDTLS_SSL_DTLS13_MAX_PENDING_ACKS` from 2 to 3 to cover
  KU + NCI + RCI overlap. Added `MBEDTLS_SSL_DTLS13_PENDING_ACK_
  REQUEST_CONNECTION_ID` enumerator (RCI gets a dispatch case for
  the first time — see §RCI asymmetry above).
- Replaced `ssl_dtls13_register_pending_ack`'s overwrite-slot-0
  fallback with an error return (`MBEDTLS_ERR_SSL_INTERNAL_ERROR`)
  so callers can fail the send rather than silently dropping a
  pending message. Both KU and NCI call sites updated to propagate.

**Implementation steps (in order):**

1. **Add the slot struct and array** to `mbedtls_ssl_context`:

   ```c
   typedef struct {
       mbedtls_ssl_dtls13_pending_ack_type_t type;       /* 0 == empty */
       uint16_t                              send_epoch; /* original send epoch */
       uint64_t                              sent_records[8];      /* ring of recent (epoch,seq) */
       uint8_t                               sent_record_epoch[8]; /* low byte of epoch per slot */
       uint8_t                               sent_record_count;
       unsigned char                        *bytes;               /* plaintext + HS header */
       size_t                                bytes_len;
       uint32_t                              retransmit_timeout_ms;
       mbedtls_ms_time_t                     next_retransmit_at;
       uint8_t                               retransmit_count;
   } mbedtls_ssl_dtls13_post_hs_retransmit;

   #define MBEDTLS_SSL_DTLS13_MAX_POST_HS_RETRANSMIT 3
   /* in mbedtls_ssl_context: */
   mbedtls_ssl_dtls13_post_hs_retransmit
       dtls13_post_hs_retransmit[MBEDTLS_SSL_DTLS13_MAX_POST_HS_RETRANSMIT];
   ```

   The array lives on `ssl_context` (not `handshake_params`) so its
   lifetime is independent of handshake teardown. This is the central
   reason for choosing this design — see §Alternative (rejected).

2. **Capture record bytes at send time, and bring RCI into the
   dispatch table.** In `ssl_tls13_write_key_update` and
   `ssl_tls13_write_new_connection_id`: after `flush_output`, call a
   new helper `ssl_dtls13_register_post_hs_retransmit(type,
   plaintext, len, send_epoch)` alongside the existing
   `register_pending_ack`. In `ssl_tls13_write_request_connection_id`:
   add the `register_pending_ack` call (RCI doesn't register today —
   see §RCI asymmetry) plus the retransmit-slot registration. The
   plaintext + HS header is what we need; the helper duplicates it
   onto the heap and records the original epoch so retransmits go
   through `ssl_dtls13_retx_epoch_switch`-equivalent logic at send
   time.

3. **Drive the timer.** Recompute the next deadline as the soonest
   `next_retransmit_at` across all occupied retransmit slots whenever
   any deadline changes (slot register, slot ACK match, slot
   retransmit, etc.). On expiry, walk slots, retransmit any past-due
   (re-encrypt + send fresh record under the recorded epoch), double
   `retransmit_timeout_ms`. If any slot's `retransmit_count` exceeds
   the `hs_timeout_max` budget equivalent, surface
   `MBEDTLS_ERR_SSL_TIMEOUT` and clear pending flags.

4. **Match ACKs against retransmit slots.** In
   `ssl_dtls13_process_ack`, after the existing
   `dtls13_pending_acks[]` walk, walk
   `dtls13_post_hs_retransmit[]` for the same `(epoch, seq)` (across
   each slot's `sent_records[]` ring), free `bytes`, clear the slot,
   recompute the next-deadline. Add an explicit
   `MBEDTLS_SSL_DTLS13_PENDING_ACK_REQUEST_CONNECTION_ID` case to the
   dispatch switch — the on-ACK action is a slot-clear no-op
   (`dtls13_req_cid_pending` is cleared by NCI receipt, not by ACK).

5. **Surface budget exhaustion as TIMEOUT.** Set a fatal-error flag
   when any slot exceeds budget; the next `mbedtls_ssl_read` (or
   `_write`) returns `MBEDTLS_ERR_SSL_TIMEOUT`. Clear the
   `dtls13_ku_ack_pending`, `dtls13_cid_update_ack_pending`, and
   `dtls13_req_cid_pending` flags as part of error cleanup so a
   subsequent reset is well-defined.

6. **Cleanup paths.** Free `bytes` for any occupied slot in:
   - `mbedtls_ssl_session_reset` (mid-retransmit reset).
   - `mbedtls_ssl_close_notify` (drop in-flight retransmits).
   - `mbedtls_ssl_free` (final teardown).
   `mbedtls_ssl_session_save`/`_load` must **not** serialise this
   array — it's connection state, not session state.

7. **Tests.** The three failing tests in tree (`cabbe587ca`) become
   passing as steps 2–5 land. Add a slot-overflow test (see §Pending-
   ack overflow test) that asserts `MBEDTLS_ERR_SSL_INTERNAL_ERROR`
   when register_pending_ack runs out of slots.

### Recommended approach (broad scope): sibling retransmit array

`dtls13_pending_acks[]` today is a **dispatch table** — "when ACK X
arrives, do Y" — indexed by sent record number. Its lifetime is "alive
from send until ACK arrives or session resets."

The retransmit machinery has a different lifetime: "alive from send
until ACK arrives **or budget exhausts** (which can be tens of seconds
in the fail case, ending in a fatal-error transition the dispatch
table doesn't know about)." The two concerns belong in separate
structs.

Use a **sibling array** in `mbedtls_ssl_context`:

```c
typedef struct {
    mbedtls_ssl_dtls13_pending_ack_type_t type;       /* 0 == empty */
    uint16_t                              send_epoch;
    uint64_t                              sent_records[8];
    uint8_t                               sent_record_epoch[8];
    uint8_t                               sent_record_count;
    unsigned char                        *bytes;     /* plaintext + HS header */
    size_t                                bytes_len;
    uint32_t                              retransmit_timeout_ms;
    mbedtls_ms_time_t                     next_retransmit_at;
    uint8_t                               retransmit_count;
} mbedtls_ssl_dtls13_post_hs_retransmit;

#define MBEDTLS_SSL_DTLS13_MAX_POST_HS_RETRANSMIT 3
mbedtls_ssl_dtls13_post_hs_retransmit
    dtls13_post_hs_retransmit[MBEDTLS_SSL_DTLS13_MAX_POST_HS_RETRANSMIT];
```

The struct mirrors the relevant fields of `mbedtls_ssl_flight_item`
(plaintext bytes, send_epoch, sent_records ring) plus per-message
backoff state. The `(epoch, seq, type)` fields are partially
duplicated with `dtls13_pending_acks[]` on purpose: the dispatch
table keeps its single-job role, the new array drives retransmit. A
successful match clears both (single ACK matches both — small loop
in `process_ack` after the existing slot walk).

Operation:

- After sending a post-hs HS message, the existing
  `register_pending_ack` populates a `pending_acks[]` slot. A new
  sibling `register_post_hs_retransmit(type, plaintext, len, epoch)`
  populates a `post_hs_retransmit[]` slot.
- A single timer drives the next wakeup, set to the soonest
  `next_retransmit_at` across all active retransmit slots.
- On timer expiry: walk slots, retransmit any past-due (re-encrypt
  the plaintext under the recorded epoch via the epoch pool, send
  fresh record), append the new (epoch, seq) to the slot's
  `sent_records` ring, double `retransmit_timeout_ms`. If
  `retransmit_count` exceeds the budget equivalent, surface
  `MBEDTLS_ERR_SSL_TIMEOUT`.
- On `process_ack` matching a slot's ring: free `bytes`, clear the
  slot, recompute the timer-next-deadline.
- On budget exhaustion: free the slot, set a fatal-error flag the
  next read/write surfaces as `MBEDTLS_ERR_SSL_TIMEOUT`.

Why this is right under broad scope:

- Same code path handles KU, NCI, RCI uniformly.
- Adding a new post-hs HS message type means registering on send +
  providing per-type dispatch in `pending_acks[]`; retransmit code is
  shared.
- Single timer + on-expiry scan is the standard pattern.
- Each struct keeps a single responsibility.

Trade-offs:

- Two parallel arrays instead of one; small `(epoch, seq, type)`
  duplication. ~72 bytes overhead at `MAX = 3`.
- Each retransmit slot allocates a `bytes` buffer; needs cleanup
  paths in `session_reset`, `ssl_close_notify`, `ssl_free`. (See
  step 6 above.)
- Re-implements 3 fields and 1 ring-walk that already exist on
  `flight_item`. The duplication is the cost of avoiding a lifetime
  dependency on the handshake structure (see §Alternative
  (rejected): reuse handshake->flight).
- `mbedtls_ssl_session_save`/`_load` must explicitly **not**
  serialise this array (it's connection state, not session state).

### Existing `register_pending_ack` overflow fallback is a correctness bug

`ssl_dtls13_register_pending_ack` at `ssl_msg.c:7647-7657` previously
did "if no free slot, overwrite slot 0." That silently dropped a
pending retransmit, and once RCI is added, "only two message types"
is no longer true. The fallback has been replaced with returning
`MBEDTLS_ERR_SSL_INTERNAL_ERROR` so callers can fail the send rather
than lose the message. `MAX_PENDING_ACKS` was bumped from 2 to 3 to
cover the worst overlap of distinct types (KU + NCI + RCI).

(Both changes are already in the working tree as preconditions for
the implementation steps above.)

### Alternative (rejected): reuse `handshake->flight`

Append KU/NCI/RCI to `handshake->flight` and let the existing flight
machinery (`flight_transmit`, `mbedtls_ssl_resend`,
`ssl_dtls13_retx_epoch_switch`, `ssl_dtls13_ack_mark_flight_item`)
handle storage, retransmit, and ACK matching. Mostly "stop the
existing exclusions" + add a "trim acked items" pass — the smallest
diff on paper.

Briefly chosen mid-session and reverted (see attempt log below).
The structural reason for rejection: **the handshake structure does
not survive long enough.** `ssl_msg.c:7202` frees `ssl->handshake` on
the first inbound non-handshake record after `state ==
HANDSHAKE_OVER`. In typical client/server flows that's the first
AppData record — well before the application calls `mbedtls_ssl_
send_key_update`. By the time KU/NCI/RCI is sent, `ssl->handshake ==
NULL`, so:

- `ssl_flight_append` is gated by `handshake != NULL` (correct, can't
  append to a freed list head) → message is sent without flight
  retention → no retransmit possible.
- Any helper that touches `ssl->handshake->retransmit_timeout` /
  `retransmit_state` SIGSEGVs on NULL deref (this is exactly what
  test runs on the shared-flight prototype showed: server exit 139
  on every test that sends NCI/KU successfully post-handshake).

Three sub-options for fixing the lifetime:

(a) **Keep `handshake` alive forever post-completion** under DTLS
    1.3. Several KB of state per connection in steady state.
    Rejected: too much memory.

(b) **Refactor flight/retransmit fields out of `handshake_params`
    into `mbedtls_ssl_context`.** ~115+ reference sites across
    `ssl_msg.c` / `ssl_tls.c` / `ssl_tls13_*.c`, plus impact on the
    DTLS 1.2 path which still uses `handshake->flight`. ~200 LOC of
    mechanical churn with non-trivial regression risk on a path I am
    not actively exercising.

(c) **Conditionally retain `handshake` while a post-hs message is
    in flight** by gating the `ssl_msg.c:7202` free on "any
    `dtls13_pending_acks[]` slot occupied." Doesn't help: the free
    fires on the first AppData record, *before* any post-hs send;
    by the time the first KU is sent, `handshake` is already gone.
    Re-allocating on demand is option (d).

(d) **Allocate a stripped-down handshake structure on demand** at
    the start of each post-hs send. Complex; mirrors the cost of (a)
    transiently and adds allocation/free churn.

None of these are clean. Plus the original "we get the flight
machinery for free" argument was inflated: a precondition to using
it is fixing the lifetime issue, which costs ~200 LOC. The sibling
array is ~250 LOC of new code with no lifetime entanglement and no
DTLS 1.2 risk surface. Net: sibling array wins.

#### Attempt log (for posterity)

Implemented in working tree, then reverted:

1. Dropped the KU flight-append exclusion at `ssl_msg.c:3133-3134`.
   Test suite still 56 PASS / 3 expected-FAIL.
2. Added `ssl_dtls13_post_hs_arm_retransmit` helper (3 lines:
   `reset_retransmit_timeout`, `set_timer`, `retransmit_state =
   WAITING`). Inlined rather than reusing
   `mbedtls_ssl_send_flight_completed` because the latter has an
   `ssl->in_msg[0] == HS_FINISHED` branch that misfires when no
   inbound record has overwritten the buffer since the server's
   Finished was received.
3. Wired the helper into KU, NCI, RCI write paths. Also added RCI
   to the dispatch table (new `register_pending_ack` call + new
   `process_ack` case).
4. Test suite: server SIGSEGV (exit 139) on every test that
   successfully sends NCI/KU post-handshake. Cause: the helper
   dereferences `ssl->handshake` after the post-handshake AppData
   path has freed it. Reverted all of (1)–(3).

The test failure surface was characteristic — exit 139 on tests
where post-hs sends succeeded — and led to discovering the
post-handshake `handshake` free at `ssl_msg.c:7202`. That's the
piece I missed during the plan-A → plan-B re-evaluation.

### Alternative (rejected for broad scope): per-message flight slot

A single post-hs retransmit slot distinct from both
`handshake->flight` and `dtls13_pending_acks[]`. Smaller surgery for a
single message type, but multiplies linearly with each new post-hs HS
message type — wrong choice when fixing all three at once. The
sibling array (the chosen design) generalises this from "one slot"
to "an array of `MAX_POST_HS_RETRANSMIT` slots" while keeping
identical semantics per slot.

## Scope

**Decision: broad scope** — fix all three post-hs HS messages
(KeyUpdate, NewConnectionId, RequestConnectionId) symmetrically via a
single mechanism. Eliminates the class of bug rather than fixing one
instance.

The chosen design (sibling `dtls13_post_hs_retransmit[]` array for
storage + retransmit; keep `dtls13_pending_acks[]` for state-machine
dispatch) scales well to broad scope because both arrays are
type-aware: adding a new post-hs message type means adding an
enumerator and a dispatch case; the retransmit slot is generic
(plaintext + epoch + ring + backoff).

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

### Pending-ack overflow test (new)

Trigger four concurrently-unACKed post-hs messages of distinct types
(KU + NCI + RCI = the 3 we accept, plus a hypothetical fourth — most
realistic: a second KU triggered by the AEAD limit while NCI/RCI are
both still in flight, even though the existing `dtls13_ku_ack_pending`
guard would normally prevent it). The fourth send should fail with
`MBEDTLS_ERR_SSL_INTERNAL_ERROR` from `register_pending_ack`'s no-
free-slot path.

What we explicitly do **not** want: silent drop of one message while
the others march on. This guards against a regression where someone
"fixes" the new register-overflow error by reverting to the old
overwrite-slot-0 behavior.

Note: under the shared-flight design, the flight itself can hold an
unbounded number of items if the trim-on-ACK pass is buggy. Add a
secondary assertion that `flight_item` count stays ≤ 3 (matching
`MAX_PENDING_ACKS`) across a long-running sequence of post-hs sends
under normal (no-loss) conditions.

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

(plus a NULL-guard on `ssl->handshake` for the existing branch — it
is freed at `ssl_msg.c:7202` on the first inbound non-handshake record
after `state == HANDSHAKE_OVER`. Under the chosen sibling-array design
the post-hs retransmit machinery does not depend on `ssl->handshake`,
so the NULL case is fine: `state != HANDSHAKE_OVER` is enough to
trigger the retransmit-timeout branch during the handshake itself, and
post-handshake the new branch keys on retransmit-slot occupancy
instead.)

Note: the original plan flipped briefly to "reuse `handshake->flight`"
based on the observation that the flight machinery already encodes
everything RFC 9147 §5.8/§7.2 requires. That flip was reverted after
implementation crashed (server SIGSEGV) — the handshake structure
is freed before post-handshake KU/NCI/RCI sends, leaving the shared-
flight retransmit machinery without a flight to retransmit. See
§Alternative (rejected): reuse handshake->flight for the full story.

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

**Separate.** Final answer after a brief plan-flip mid-session.

The plan-flip story (worth recording so the rationale is durable):

1. Initial answer: **Separate.** Sibling array; conceptual
   cleanliness; lifetime independence from handshake teardown.

2. After re-reading `mbedtls_ssl_flight_item` and seeing that it
   already encodes plaintext storage, epoch tracking, sent-record
   ring, and cross-epoch retransmit — flipped to **Share** to avoid
   reimplementing ~200 LOC. The argument was "the substrate already
   exists; reuse it."

3. Implementation attempt in working tree: dropped the KU
   flight-append exclusion, added a `post_hs_arm_retransmit` helper,
   wired KU/NCI/RCI to it. Build was clean; tests crashed (server
   exit 139). Cause: `ssl_msg.c:7202` frees `ssl->handshake` on the
   first inbound non-handshake record after `state ==
   HANDSHAKE_OVER` — which fires *before* any post-handshake KU/NCI/
   RCI is sent in normal flows. The shared-flight design implicitly
   required the handshake structure to survive past that point.

4. Lifetime fix options:
   - Keep `handshake` alive forever in DTLS 1.3 — too much memory
     per connection (rejected by user).
   - Refactor flight/retransmit fields out of `handshake_params` —
     ~115 reference sites, touches DTLS 1.2.
   - Re-allocate on demand — mirrors the cost of "keep alive" plus
     allocation churn.

   None were acceptable.

5. **Flipped back to Separate.** The "we get the flight machinery
   for free" claim was inflated: free in a vacuum, but not after
   factoring in the lifetime fix. The sibling array's ~250 LOC of
   duplication is the price of avoiding any handshake-lifetime
   dependency, and that price is lower than the alternatives.

So: post-hs messages don't fit the conceptual definition of a
"flight" (a contiguous group of related messages sent together)
**and** they outlive the handshake structure that owns the flight
queue. Both arguments point the same way: separate data structure
in `mbedtls_ssl_context`, parallel to `dtls13_pending_acks[]`.
