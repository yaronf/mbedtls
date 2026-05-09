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

### Recommended approach: per-post-hs-message ACK and dedicated timer

The simplest path that avoids interaction with prior handshake state:

- Keep a small **post-handshake retransmit slot** distinct from
  `handshake->flight`. The slot holds the bytes of the most recently
  sent post-hs handshake message, its (epoch, seq), and its retransmit
  count.
- After sending a post-hs HS message, populate the slot and arm a
  dedicated timer (or reuse the existing retransmit_timer if no flight
  is active).
- On timer expiry: re-encrypt and resend the slot's bytes; double the
  timeout.
- On `process_ack` matching the slot's (epoch, seq): clear the slot and
  cancel the timer.
- On budget exhaustion: surface `MBEDTLS_ERR_SSL_TIMEOUT` from
  `mbedtls_ssl_read`.

This avoids reusing the handshake flight (which has state lifecycle
complications post-wrapup) and gives a clean RFC §7 compliance for
post-hs HS messages.

Trade-off: slightly more code than option (3) reusing the flight, but
isolated from the handshake state machine.

### Alternative: extend dtls13_pending_acks[] with retransmit data

`dtls13_pending_acks[]` already tracks `(epoch, seq, type)` for
post-hs messages. Extend each slot with:
- `unsigned char *bytes` (record bytes for retransmit)
- `size_t bytes_len`
- `uint32_t retransmit_timeout_ms` (current backoff)
- `mbedtls_ms_time_t next_retransmit_at`

A single timer scans all slots on expiry; the soonest `next_retransmit_at`
drives the next wakeup. This is more uniform across KU / NCI / RCI but
requires touching every per-type code path.

## Scope

Strict-scope (just KU): only fix KeyUpdate retransmit. Leaves NCI/RCI
gaps for future work. Smaller diff, faster to land.

Broad-scope: fix all three post-hs HS messages (KU, NewConnectionId,
RequestConnectionId) symmetrically. Larger but eliminates the class of
bug. Recommended if the chosen approach scales (pending-acks-with-data
does; per-message-flight-slot does).

## Test plan

- Re-enable the existing failing test
  `tests/dtls13/cases/keyupdate.yaml` "KeyUpdate timeout: server ACK
  lost, client retransmit budget exhausts" — must PASS post-fix.
- Add symmetric test for NewConnectionId timeout if broad-scope.
- Add a positive test: client sends KU, server ACK is dropped once
  (`drop=2` randomly), client retransmits and the second send is acked.
  This verifies retransmit *progress*, not just budget exhaustion.
- Verify no regression in:
  - existing keyupdate.yaml tests (basic KU send/ack)
  - NST_WAIT_ACK timeout test (commit `46f89e8f2c`)
  - all 56 dtls13 tests in the suite

## Out of scope

- Server-initiated KeyUpdate retransmit (server side has the same gap;
  fix is symmetric but requires the server-side test driver).
- Reciprocal KU on `update_requested=1` — the reciprocal KU send goes
  through the same path so it's automatically covered.
- KeyUpdate during a still-pending KU ACK — already handled by the
  `dtls13_ku_ack_pending` guard returning `WANT_WRITE`.

## Open questions

1. What clears `retransmit_state == WAITING` in the post-KU read loop?
   This is the immediate blocker and must be answered before any of the
   above approaches will work cleanly.
2. Should the post-hs retransmit timer be the same `mbedtls_ssl_set_timer`
   as the handshake one, or a separate timer? The current handshake
   timer is a single resource; reusing it is simpler but couples post-hs
   timing to handshake-completion bookkeeping.
3. Is it acceptable to share `handshake->flight` for post-hs messages,
   or should post-hs use a separate queue? Sharing gives free
   integration with `mbedtls_ssl_resend`; separating gives clean
   isolation. Recommendation: separate, given the lifecycle issues seen
   in this attempt.
