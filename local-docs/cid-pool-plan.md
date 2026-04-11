# CID Pool Plan

**Status**: Partially implemented (inbound pool done; outbound pool pending)
**RFC reference**: RFC 9147 §9 (Connection ID), §11 (Security — address migration)
**Created**: 2026-04-10
**Updated**: 2026-04-11

---

## Motivation

Currently we send a single CID in each NewConnectionId message and hold only one
`own_cid` in `mbedtls_ssl_context`. The RFC allows (and SHOULD-level recommends)
sending a pool of CIDs so the peer can rotate to a fresh one when its local address
changes, without waiting for a round trip.

Without a pool:
- Address migration always reuses the same CID, leaking correlation across paths.
- The peer has no spare CID to switch to atomically; it must request one first.

With symmetric inbound + outbound pools of size N:
- We send N CIDs in each NewConnectionId — one IMMEDIATE (in use now) and N-1 SPAREs.
- The peer stores our CIDs in their outbound pool; on address change they promote a
  spare to active with no round trip.
- We accept inbound records bearing any CID in our inbound pool.
- When a spare is consumed, we replenish automatically.
- Symmetrically, when the peer sends us a NewConnectionId with multiple CIDs, we store
  their CIDs in our outbound pool; on our own address change we promote a spare from
  that pool and immediately start sending with the new CID.
- A public API `mbedtls_ssl_dtls13_rotate_cids()` rotates **both** directions:
  our inbound CID (preventing linkability of inbound stream) and our outbound CID
  (preventing linkability of outbound stream).

Pool size is controlled by a single compile-time constant:

```c
#define MBEDTLS_SSL_DTLS13_CID_POOL_SIZE  2
```

All pool logic loops over `MBEDTLS_SSL_DTLS13_CID_POOL_SIZE`; no hardcoded 1-or-2
branches.

---

## Design

### 1. Data structures

#### 1a. Inbound CID pool (already implemented)

```c
/* include/mbedtls/ssl.h */
typedef struct {
    unsigned char cid[MBEDTLS_SSL_CID_IN_LEN_MAX];
    uint8_t       cid_len;
    uint8_t       active;   /* 1 = valid entry, 0 = empty slot */
} mbedtls_ssl_dtls13_cid_entry;
```

Fields in `mbedtls_ssl_context` (guarded by `MBEDTLS_SSL_DTLS_CONNECTION_ID`):

```c
mbedtls_ssl_dtls13_cid_entry dtls13_own_cid_pool[MBEDTLS_SSL_DTLS13_CID_POOL_SIZE];
uint8_t dtls13_own_cid_active_idx;
uint8_t dtls13_own_cid_pool_ready;
```

Initialised at HANDSHAKE_OVER: slot 0 from `own_cid`, slots 1..N-1 from
`psa_generate_random()`.

#### 1b. Outbound CID pool (to be added)

Reuse the same `mbedtls_ssl_dtls13_cid_entry` struct (CID bytes + len + active flag),
but use `MBEDTLS_SSL_CID_OUT_LEN_MAX` as the max length.  Add to
`mbedtls_ssl_context`:

```c
mbedtls_ssl_dtls13_cid_entry dtls13_peer_cid_pool[MBEDTLS_SSL_DTLS13_CID_POOL_SIZE];
uint8_t dtls13_peer_cid_active_idx;
uint8_t dtls13_peer_cid_pool_ready;
```

`dtls13_peer_cid_pool[dtls13_peer_cid_active_idx]` is the CID currently in
`transform_out->out_cid`. The remaining active slots are spares for future use.

The pool is initialised from `transform_out->out_cid` (the CID negotiated during
the handshake) at HANDSHAKE_OVER — slot 0 active, slots 1..N-1 empty (filled later
by incoming NewConnectionId messages).

---

### 2. Inbound CID matching (already implemented)

`transform->in_cid` is the primary match. On `UNEXPECTED_CID` at the call site in
`ssl_prepare_record_content`, scan `dtls13_own_cid_pool` with `mbedtls_ct_memcmp`.
On match: update `transform->in_cid`, retry decrypt, trigger replenishment.

No changes needed here.

---

### 3. Outbound NewConnectionId — send N CIDs (already implemented)

`ssl_tls13_write_new_connection_id` iterates over all active pool slots and encodes
them. The loop is generalized over `MBEDTLS_SSL_DTLS13_CID_POOL_SIZE`.

No changes needed here.

---

### 4. handle_new_connection_id — store outbound pool (to be implemented)

Currently reads only the first CID and discards the rest. Change to:

1. Parse all CID entries in the list (loop over `list_len` bytes, one entry per
   `(cid_len_byte || cid_bytes)` pair), up to `MBEDTLS_SSL_DTLS13_CID_POOL_SIZE`.
   Entries beyond the pool size are accepted on the wire but not stored (no error).
2. Validate each `cid_len` against `MBEDTLS_SSL_CID_OUT_LEN_MAX` and against the
   expected `out_cid_len` (all entries must share the same length — enforced by our
   own send side, and we should reject mismatches with `illegal_parameter`).
3. Read the usage byte (single byte after the list, unchanged).
4. Populate `dtls13_peer_cid_pool`:
   - Slot `active_idx` ← first CID in the list (IMMEDIATE — use now).
   - Remaining slots ← subsequent CIDs in the list, in order, up to pool size - 1.
   - Mark each populated slot `active = 1`; zero unused slots.
5. Update `transform_out->out_cid` from `dtls13_peer_cid_pool[active_idx]` (and
   `dtls13_transform_pending_out` if set — existing logic unchanged).
6. Also update `dtls13_peer_cid_pool_ready = 1`.

Parsing loop sketch:

```c
const unsigned char *list_end = p + list_len;
int slot = 0;
memset(ssl->dtls13_peer_cid_pool, 0, sizeof(ssl->dtls13_peer_cid_pool));
while (p < list_end && slot < MBEDTLS_SSL_DTLS13_CID_POOL_SIZE) {
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, list_end, 1);
    uint8_t entry_cid_len = *p++;
    if (entry_cid_len != expected_cid_len) { /* illegal_parameter */ }
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, list_end, entry_cid_len);
    ssl->dtls13_peer_cid_pool[slot].cid_len = entry_cid_len;
    memcpy(ssl->dtls13_peer_cid_pool[slot].cid, p, entry_cid_len);
    ssl->dtls13_peer_cid_pool[slot].active = 1;
    p += entry_cid_len;
    slot++;
}
/* Skip any remaining entries beyond pool size */
p = list_end;
```

The usage byte and all existing post-parse logic (update `transform_out->out_cid`,
update pending transform, ACK) remain unchanged.

---

### 5. Pool replenishment (inbound — already implemented)

When secondary CID match detects peer switched to a spare inbound CID:
1. Update `active_idx` to the matched slot.
2. Generate fresh random CID for vacated slot.
3. Send NewConnectionId to replenish peer's outbound pool.

No changes needed here.

---

### 6. rotate_cids — rotate both directions (to be extended)

Current implementation rotates only the inbound pool. Extend to:

1. **Inbound rotation** (already done): promote spare inbound slot to `active_idx`,
   generate new random CID for vacated slot, send NewConnectionId to peer.

2. **Outbound rotation** (to add): promote spare from `dtls13_peer_cid_pool` to
   `active_idx`, update `transform_out->out_cid` (and pending transform if set)
   immediately. No message to peer needed — we already hold their spare CID.

   If outbound pool has no spare (all slots empty or `pool_ready == 0`), skip
   outbound rotation silently. The caller can check: if inbound rotation was sent but
   outbound pool was empty, the outbound stream still uses the old CID. Caller may
   request a new CID from peer via `RequestConnectionId` in this case.

   Sketch:

   ```c
   /* Rotate outbound CID if we have a spare */
   if (ssl->dtls13_peer_cid_pool_ready) {
       uint8_t next = (ssl->dtls13_peer_cid_active_idx + 1)
                      % MBEDTLS_SSL_DTLS13_CID_POOL_SIZE;
       if (ssl->dtls13_peer_cid_pool[next].active) {
           ssl->dtls13_peer_cid_active_idx = next;
           ssl->transform_out->out_cid_len =
               ssl->dtls13_peer_cid_pool[next].cid_len;
           memcpy(ssl->transform_out->out_cid,
                  ssl->dtls13_peer_cid_pool[next].cid,
                  ssl->dtls13_peer_cid_pool[next].cid_len);
           if (ssl->dtls13_transform_pending_out != NULL) {
               ssl->dtls13_transform_pending_out->out_cid_len =
                   ssl->dtls13_peer_cid_pool[next].cid_len;
               memcpy(ssl->dtls13_transform_pending_out->out_cid,
                      ssl->dtls13_peer_cid_pool[next].cid,
                      ssl->dtls13_peer_cid_pool[next].cid_len);
           }
           /* Mark vacated slot empty — peer will replenish via NewConnectionId */
           ssl->dtls13_peer_cid_pool[ssl->dtls13_peer_cid_active_idx ^ 1].active = 0;
           MBEDTLS_SSL_DEBUG_MSG(2, ("outbound CID rotated to pool slot %u", next));
       }
   }
   ```

   Note: the vacated slot comment above uses `^ 1` as shorthand — in the generalized
   version use the old `active_idx` value (saved before update) to clear it.

---

### 7. Connection teardown

On `mbedtls_ssl_free` / early abort: zero both pools.
`mbedtls_ssl_context` zeroing already covers this (pool fields are embedded, not
heap-allocated). Confirm no separate free needed.

---

## Changes by file

| File | Change |
|------|--------|
| `include/mbedtls/ssl.h` | Add `dtls13_peer_cid_pool`, `dtls13_peer_cid_active_idx`, `dtls13_peer_cid_pool_ready` to `mbedtls_ssl_context` |
| `library/ssl_misc.h` | Init outbound pool at HANDSHAKE_OVER from `transform_out->out_cid` |
| `library/ssl_msg.c` | `ssl_tls13_handle_new_connection_id`: parse full list, populate outbound pool |
| `library/ssl_msg.c` | `mbedtls_ssl_dtls13_rotate_cids`: add outbound rotation step |

No new test infrastructure needed beyond what was already added — the `rotate_cid`
test cases (TC-2, TC-3, TC-5) already exercise the rotation path and will cover the
outbound rotation once implemented. TC-5 (address migration with CID rotation) is the
primary correctness test.

---

## Already implemented (inbound pool)

- `mbedtls_ssl_dtls13_cid_entry` struct and `MBEDTLS_SSL_DTLS13_CID_POOL_SIZE` macro
- `dtls13_own_cid_pool`, `dtls13_own_cid_active_idx`, `dtls13_own_cid_pool_ready` fields
- Pool init at HANDSHAKE_OVER (ssl_misc.h)
- Secondary CID match in `ssl_prepare_record_content` (ssl_msg.c:5451–5543)
- `ssl_tls13_write_new_connection_id` generalized to send all active pool slots
- `mbedtls_ssl_dtls13_rotate_cids` (inbound rotation only)
- Forward declaration of `ssl_tls13_write_new_connection_id` before `ssl_prepare_record_content`
- Test infrastructure: assertions, `rotate_cid=N` option in ssl_client2/ssl_server2
- Test cases in `cid-update.yaml`

## Still to implement (outbound pool)

1. Add `dtls13_peer_cid_pool[MBEDTLS_SSL_DTLS13_CID_POOL_SIZE]`, `dtls13_peer_cid_active_idx`,
   `dtls13_peer_cid_pool_ready` to `mbedtls_ssl_context` (ssl.h)
2. Init outbound pool at HANDSHAKE_OVER (ssl_misc.h)
3. Parse full CID list in `handle_new_connection_id` and populate outbound pool (ssl_msg.c)
4. Extend `rotate_cids` to also rotate outbound CID from pool (ssl_msg.c)

---

## Design decisions

1. **Pool vs transform**: `transform->in_cid` / `transform->out_cid` remain the hot-path
   single values. Pools live at `ssl` level. No change to decrypt/encrypt function
   signatures.

2. **Pool size 2**: One IMMEDIATE + one SPARE. Sufficient for single-hop address
   migration. Generalized over `MBEDTLS_SSL_DTLS13_CID_POOL_SIZE` — change the define
   to increase.

3. **CID length uniformity**: All pool entries (both inbound and outbound) must share
   the same length. Enforced by our send side; validated on receive.

4. **Auto-replenishment (inbound)**: Triggered automatically on spare consumption.
   The outbound pool is replenished by the peer sending a new NewConnectionId — we
   cannot generate their CIDs ourselves.

5. **DTLS 1.2 compatibility**: Both pools are DTLS 1.3 only. DTLS 1.2 continues using
   `own_cid` and `transform_out->out_cid` directly.

6. **Symmetry**: Both pools are the same size, same struct, same loop structure.
   The only asymmetry: inbound spares are self-generated (random); outbound spares
   come from the peer.
