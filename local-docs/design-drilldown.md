# DTLS 1.3 Design Drill-Down

Three areas identified as under-specified in the phased plan.

---

## 1. Record Layer Integration

### Existing read path (ssl_msg.c)

```
mbedtls_ssl_read_record()              line 4003
  ssl_get_next_record()                line 4666
    mbedtls_ssl_fetch_input()          -- reads datagram from network
    ssl_parse_record_header()          line 3529
      -- reads type byte, version, epoch (2B), seq (6B) into rec->ctr
      -- rec_epoch = MBEDTLS_GET_UINT16_BE(rec->ctr, 0)  line 3701
      -- anti-replay check             line 3734
    ssl_prepare_record_content()       line 3778
      mbedtls_ssl_decrypt_buf()        line 1269
        ssl_extract_add_data_from_record()  line 567  <-- AAD built here
        psa_aead_decrypt()
```

### Existing write path (ssl_msg.c)

```
mbedtls_ssl_write_record()             line 2646
  -- writes type, version, seq from cur_out_ctr
  mbedtls_ssl_encrypt_buf()            line 783
    ssl_extract_add_data_from_record()      <-- AAD built here
    psa_aead_encrypt()
  mbedtls_ssl_flush_output()           -- sends to network
```

### Where DTLS 1.3 dispatch goes

The first byte of an incoming datagram determines record format. This check
belongs at the top of `ssl_parse_record_header()`, before any existing parsing.

```
ssl_parse_record_header():
  buf[0] == 20/21/22/23/24/25/26  --> DTLSPlaintext (existing path, mostly unchanged)
  buf[0] & 0xE0 == 0x20           --> DTLSCiphertext 1.3 (new path)
  else                            --> reject silently
```

The DTLS 1.3 path needs a new function, e.g. `ssl_parse_dtls13_record_header()`,
that fills `mbedtls_record` from the unified header and returns the number of
header bytes consumed. The rest of the read path (decrypt, deliver) then runs
on the populated `mbedtls_record` as today.

For writes, `mbedtls_ssl_write_record()` needs a parallel branch: if DTLS 1.3
and epoch > 0, emit DTLSCiphertext unified header instead of the current DTLS
1.2 fixed header.

### AAD change

`ssl_extract_add_data_from_record()` (line 567) currently builds:
`epoch(2) || seq(6) || type(1) || version(2) || length(2)` for DTLS.

For DTLS 1.3 it must instead use the raw unified header bytes (the exact bytes
on the wire, before sequence number decryption). Cleanest approach: pass the
raw header bytes and their length as additional parameters, gated on
`rec->tls_version == MBEDTLS_SSL_VERSION_DTLS1_3`.

### New context fields needed

On `mbedtls_ssl_context` (ssl.h):
```c
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    /* DTLS 1.3: per-epoch highest successfully deprotected record sequence
     * number, used for epoch reconstruction (§4.2.2). Indexed by the low
     * 2 bits of the epoch, matching the on-wire epoch bits in DTLSCiphertext. */
    uint64_t dtls13_epoch_max_seq[4];

    /* DTLS 1.3: full 64-bit epoch for the current inbound epoch.
     * (in_epoch already holds the 16-bit wire value for DTLS 1.2.) */
    uint64_t in_epoch_full;
#endif
```

The `dtls13_epoch_max_seq[4]` array is indexed by `epoch & 0x3` (the 2 epoch
bits in the ciphertext header). On epoch transition, the slot is reset to 0.

---

## 2. Transform Slot Model

### Current state

`mbedtls_ssl_context` holds:
- `transform_in`  — active inbound transform (pointer, heap-allocated)
- `transform_out` — active outbound transform
- `transform_negotiate` — being negotiated (TLS 1.2)
- `transform_application` — TLS 1.3 application-data transform

`mbedtls_ssl_handshake_params` holds:
- `alt_transform_out` — one previous outbound transform kept for retransmission
- `alt_out_ctr[8]` — epoch/counter for retransmit

For DTLS 1.2 this is sufficient: at any time there is one active inbound
transform, one active outbound transform, and one alt for retransmitting old
flight messages.

### What DTLS 1.3 requires

- Records from epoch N-1 (and in theory N-2) may arrive after epoch N is active
  due to reordering. The spec says implementations SHOULD retain old keys up to
  MSL (~120s), but also states they MAY discard them.
- During KeyUpdate, the receiver must keep the pre-update keys until the first
  successful decryption with new keys (§8).
- On write, retransmissions MUST use the same epoch as the original (§4.2.1).

### Design: circular epoch pool

Add to `mbedtls_ssl_handshake_params` (and retained post-handshake on the
context):

```c
#define MBEDTLS_SSL_DTLS13_EPOCH_POOL_SIZE  4

typedef struct {
    uint64_t                epoch;      /* full 64-bit epoch value */
    mbedtls_ssl_transform  *transform;  /* NULL = slot empty */
    /* monotonic timestamp (ms) when this epoch was superseded, for MSL eviction */
    uint64_t                retired_at_ms;
} mbedtls_ssl_dtls13_epoch_slot;
```

Stored as a fixed array on `mbedtls_ssl_context`:

```c
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    mbedtls_ssl_dtls13_epoch_slot dtls13_epoch_pool[MBEDTLS_SSL_DTLS13_EPOCH_POOL_SIZE];
#endif
```

Operations:
- **Install**: when a new epoch becomes active, push the old `transform_in` into
  the pool (evicting the oldest slot if full). Set `transform_in` to the new
  transform.
- **Lookup for decrypt**: when the epoch bits of an incoming record don't match
  `in_epoch`, search the pool for a matching full epoch (reconstructed per
  §4.2.2). If found, decrypt with that transform. If not found, discard.
- **Evict**: on pool insertion, if all slots are occupied, evict the slot with
  the oldest `retired_at_ms`. Optionally, evict any slot where
  `now - retired_at_ms > MSL_MS`.
- **Retransmit**: retransmission of handshake messages uses `alt_transform_out`
  (existing mechanism, unchanged). The pool is only for inbound reorder handling.

Outbound retransmission (`alt_transform_out` / `alt_out_ctr`) is unchanged from
the current model — it holds exactly one previous outbound transform, which is
sufficient because we only retransmit the last flight.

### Impact on existing transform pointers

`transform_in` and `transform_out` remain the active transforms. No existing
callsite that dereferences them needs to change. The pool is an additional lookup
path in `ssl_prepare_record_content()` when the primary decrypt fails due to
epoch mismatch.

---

## 3. ACK + Retransmit Surgery

### What needs tracking

To process an incoming ACK, we need to answer: "which flight item(s) were
transmitted in record number R?" Currently `mbedtls_ssl_flight_item` has no
record number field — it stores the message bytes but not when/how they were
sent.

To send a useful ACK, we need: "which record numbers from the current incoming
flight have I received and successfully processed?"

### New fields on mbedtls_ssl_flight_item

```c
struct mbedtls_ssl_flight_item {
    unsigned char *p;               /* message, including handshake headers */
    size_t         len;
    unsigned char  type;
    mbedtls_ssl_flight_item *next;

    /* DTLS 1.3: record numbers of transmissions of this message.
     * A message may be retransmitted multiple times with different record
     * numbers (each retransmit is a new record). We track the last
     * MBEDTLS_SSL_DTLS13_MAX_RECORDS_PER_MSG transmissions. */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint64_t  sent_records[MBEDTLS_SSL_DTLS13_MAX_RECORDS_PER_MSG]; /* seq# */
    uint8_t   sent_record_epoch[MBEDTLS_SSL_DTLS13_MAX_RECORDS_PER_MSG];
    uint8_t   sent_record_count;  /* how many entries are valid */
    bool      acked;              /* true if any sent_records[] was ACKed */
#endif
};
```

`MBEDTLS_SSL_DTLS13_MAX_RECORDS_PER_MSG` can be small (e.g., 4) — we only need
to track enough retransmissions to correctly process ACKs. Older entries can be
overwritten (ring buffer within the array).

### New fields for incoming ACK tracking (what to put in our ACKs)

Add to `mbedtls_ssl_handshake_params`:

```c
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    /* DTLS 1.3: record numbers received from the peer's current flight
     * that we have processed or buffered. Sent in outgoing ACK messages. */
    struct {
        uint64_t epoch;
        uint64_t seq;
    } dtls13_received_records[MBEDTLS_SSL_DTLS13_MAX_ACK_RECORDS];
    uint8_t dtls13_received_record_count;
#endif
```

`MBEDTLS_SSL_DTLS13_MAX_ACK_RECORDS`: suggest 16. The spec says implementations
SHOULD ACK as many records as fit; 16 covers any realistic flight size.

This array is cleared when we start a new flight (i.e., when we transition from
WAITING to PREPARING on receipt of the next flight's first message).

### Retransmit state machine changes

The existing states in `mbedtls_ssl_handshake_params`:
```
MBEDTLS_SSL_RETRANS_PREPARING
MBEDTLS_SSL_RETRANS_SENDING
MBEDTLS_SSL_RETRANS_WAITING
MBEDTLS_SSL_RETRANS_FINISHED
```
These states are correct for DTLS 1.3 as well. The changes are:

**In `mbedtls_ssl_flight_transmit()` (line 2240):**
- Before sending a flight item, check `item->acked`. If true, skip it.
- After sending, record the outbound `cur_out_ctr` value in
  `item->sent_records[]` / `item->sent_record_epoch[]`.

**New function: `ssl_dtls13_process_ack()`:**
```
ssl_dtls13_process_ack(ssl, ack_record_numbers[], count):
  for each record_number in ack_record_numbers:
    for each flight_item in ssl->handshake->flight:
      if record_number matches any entry in flight_item->sent_records[]:
        flight_item->acked = true
  if all flight items are acked:
    cancel retransmit timer
    transition to FINISHED (if final flight) or PREPARING (if more flights)
  else:
    transition to SENDING to retransmit unacked items
```

**ACK injection (non-blocking I/O):**

The open question about non-blocking I/O is real. The cleanest solution is a
pending-ACK flag on the context:

```c
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint8_t dtls13_ack_pending;  /* set when an ACK needs to be sent */
#endif
```

At the top of `mbedtls_ssl_read_record()`, before attempting to read new data,
check `dtls13_ack_pending`. If set, build and send the ACK from
`dtls13_received_records[]`, then clear the flag. This ensures ACKs are sent on
the next I/O call without requiring a separate `ssl_ack()` API.

The flag is set when:
- A partial flight is received (out-of-order fragment detected)
- The final flight of the handshake is received (MUST ACK)
- A post-handshake message is received and processed

### Post-handshake FSM linked list

For post-handshake message reliability, add to `mbedtls_ssl_context`:

```c
typedef struct mbedtls_ssl_dtls13_hs_fsm {
    uint8_t   msg_type;         /* HandshakeType of the message being tracked */
    uint8_t   state;            /* PREPARING / SENDING / WAITING / FINISHED */
    uint32_t  retransmit_timeout;
    unsigned char *msg;         /* heap copy of the message for retransmit */
    size_t    msg_len;
    uint64_t  sent_records[MBEDTLS_SSL_DTLS13_MAX_RECORDS_PER_MSG];
    uint8_t   sent_record_epoch[MBEDTLS_SSL_DTLS13_MAX_RECORDS_PER_MSG];
    uint8_t   sent_record_count;
    struct mbedtls_ssl_dtls13_hs_fsm *next;
} mbedtls_ssl_dtls13_hs_fsm;

/* on mbedtls_ssl_context: */
mbedtls_ssl_dtls13_hs_fsm *dtls13_post_hs_fsm;
```

Lookup on ACK receipt: linear scan by checking whether the ACKed record numbers
appear in any FSM node's `sent_records[]`. Lookup on incoming response message:
linear scan by `msg_type` and (for CertificateRequest responses) by
`certificate_request_context`. Both are O(n) over a list that in practice has
1–3 nodes.

---

## Summary of new fields / structs

| Location | Addition | Purpose |
|---|---|---|
| `mbedtls_ssl_transform` | `sn_key[32]`, `sn_key_len` | Sequence number encryption key |
| `mbedtls_ssl_context` | `dtls13_epoch_pool[4]` | Past inbound transforms for reorder |
| `mbedtls_ssl_context` | `in_epoch_full` (uint64) | Full epoch (not just 16-bit wire value) |
| `mbedtls_ssl_context` | `dtls13_epoch_max_seq[4]` | Per-epoch highest deprotected seq# |
| `mbedtls_ssl_context` | `dtls13_ack_pending` (uint8) | Pending ACK flag for non-blocking I/O |
| `mbedtls_ssl_context` | `dtls13_post_hs_fsm` (ptr) | Post-handshake FSM linked list |
| `mbedtls_ssl_flight_item` | `sent_records[]`, `acked` | Record# tracking for ACK processing |
| `mbedtls_ssl_handshake_params` | `dtls13_received_records[]` | Incoming records to include in ACK |
| New struct | `mbedtls_ssl_dtls13_epoch_slot` | Epoch pool entry |
| New struct | `mbedtls_ssl_dtls13_hs_fsm` | Post-handshake retransmit FSM node |
