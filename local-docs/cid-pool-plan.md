# CID Pool Plan

**Status**: Planned
**RFC reference**: RFC 9147 §9 (Connection ID), §11 (Security — address migration)
**Created**: 2026-04-10

---

## Motivation

Currently we send a single CID in each NewConnectionId message and hold only one
`own_cid` in `mbedtls_ssl_context`. The RFC allows (and SHOULD-level recommends)
sending a pool of CIDs so the peer can rotate to a fresh one when its local address
changes, without waiting for a round trip.

Without a pool:
- Address migration always reuses the same CID, leaking correlation across paths.
- The peer has no spare CID to switch to atomically; it must request one first.

With a pool of 2:
- We send 2 CIDs in each NewConnectionId — one IMMEDIATE (in use now) and one SPARE.
- The peer can switch to the spare CID on address change with no round trip.
- We accept inbound records bearing any CID in our pool.
- When a spare is consumed, we replenish by sending a fresh NewConnectionId.
- A new public API `mbedtls_ssl_dtls13_rotate_own_cid()` lets the application
  signal "I changed address — switch to a spare CID now."

---

## Design

### 1. New data structure: inbound CID pool

Replace the single `own_cid` / `own_cid_len` fields with a small pool in
`mbedtls_ssl_context`:

```c
/* include/mbedtls/ssl.h */
#define MBEDTLS_SSL_DTLS13_CID_POOL_SIZE  2

typedef struct {
    unsigned char cid[MBEDTLS_SSL_CID_IN_LEN_MAX];
    uint8_t       cid_len;
    uint8_t       active;   /* 1 = valid entry, 0 = empty slot */
} mbedtls_ssl_dtls13_cid_entry;
```

Added to `mbedtls_ssl_context` (guarded by `MBEDTLS_SSL_DTLS_CONNECTION_ID`):

```c
mbedtls_ssl_dtls13_cid_entry dtls13_own_cid_pool[MBEDTLS_SSL_DTLS13_CID_POOL_SIZE];
uint8_t dtls13_own_cid_active_idx;   /* index of the "current" (IMMEDIATE) CID */
```

`own_cid` / `own_cid_len` remain for DTLS 1.2 and pre-pool handshake use; the pool
is DTLS 1.3 post-handshake only. At HANDSHAKE_OVER the pool is initialised from
`own_cid`:

```c
pool[0] = { own_cid, own_cid_len, active=1 };  /* IMMEDIATE */
pool[1] = { <random>, own_cid_len, active=1 };  /* SPARE — generated now */
active_idx = 0;
```

The random SPARE CID is generated using `mbedtls_ssl_conf_rng`.

### 2. Inbound CID matching (ssl_msg.c:1430)

Keep `transform->in_cid` as the primary match (unchanged). When `UNEXPECTED_CID` is
returned at the call site in `ssl_msg.c` (where `ssl` is available), do a secondary
check against `ssl->dtls13_own_cid_pool`. If a pool entry matches:

1. Copy that entry's CID into `transform->in_cid` / `transform->in_cid_len`.
2. Call `mbedtls_ssl_decrypt_buf` again — the primary match will now succeed.
3. Trigger replenishment (see §4).

The CID match in `mbedtls_ssl_decrypt_buf` occurs before AEAD, so `UNEXPECTED_CID`
is returned before any decryption is attempted — a second call is safe and correct.
No changes to `mbedtls_ssl_decrypt_buf`'s signature or internals.

### 3. Outbound NewConnectionId — send 2 CIDs

`ssl_tls13_write_new_connection_id` currently sends 1 CID. Change it to:

```c
/* Compute body for 2 CIDs */
size_t body_len = 2 /* list_len */
                + (1 + cid_len) /* IMMEDIATE entry */
                + (1 + cid_len) /* SPARE entry */
                + 1;            /* usage byte */

/* Encode: list_len covers both entries */
MBEDTLS_PUT_UINT16_BE(2 * (1 + cid_len), buf, 0);
buf[2] = cid_len; memcpy(buf + 3, pool[active_idx].cid, cid_len);      /* IMMEDIATE */
buf[3 + cid_len] = cid_len; memcpy(buf + 4 + cid_len, pool[spare_idx].cid, cid_len); /* SPARE */
buf[4 + 2*cid_len] = usage;
```

Usage byte (outbound): our choice — IMMEDIATE when we want the peer to switch now,
SPARE to offer for future use. On receive, the usage byte is the *peer's* decision;
we act on it (switch to IMMEDIATE CID now, store SPARE) without influencing it.

### 4. Pool replenishment

Detection happens in the secondary CID match (§2): when a pool entry other than
`active_idx` matches an inbound record, the peer has switched to a spare CID.
At that point:

1. Mark the matched entry as the new `active_idx`.
2. Generate a fresh random CID into the vacated slot.
3. Send a new NewConnectionId (if not already pending) to replenish the peer's pool.

This is fully automatic — the application is not involved.

### 5. Public API: `mbedtls_ssl_dtls13_rotate_own_cid`

```c
/* include/mbedtls/ssl.h */

/**
 * \brief   Switch to the next spare inbound CID from the pool and send a
 *          NewConnectionId to the peer offering a fresh spare.
 *
 *          Call this when a local address change is detected, to prevent
 *          CID-based correlation across paths (RFC 9147 §9 / §11).
 *
 *          This is a no-op if CID was not negotiated or if no spare is
 *          available (pending ACK on previous NewConnectionId).
 *
 * \param ssl   SSL context (must be post-handshake DTLS 1.3).
 * \return      0 on success, MBEDTLS_ERR_SSL_* on error.
 */
int mbedtls_ssl_dtls13_rotate_own_cid(mbedtls_ssl_context *ssl);
```

Implementation:
1. Rotate `active_idx` to the spare.
2. Generate a new random CID for the vacated slot.
3. Call `ssl_tls13_write_new_connection_id(ssl, SSL_CID_USAGE_IMMEDIATE)` to tell
   the peer to switch to the new IMMEDIATE CID and offer the new SPARE.

### 6. Handle receive side: accept both CIDs during transition

Between the time we rotate (step 5) and the time the peer's in-flight records
arrive, the peer may still be sending with the old CID. The pool match (step 2)
handles this naturally — both old and new CIDs are valid until the peer switches.

---

## Changes by file

| File | Change |
|------|--------|
| `include/mbedtls/ssl.h` | Add `mbedtls_ssl_dtls13_cid_entry`, `MBEDTLS_SSL_DTLS13_CID_POOL_SIZE`, pool fields in `mbedtls_ssl_context`, `mbedtls_ssl_dtls13_rotate_own_cid` declaration |
| `library/ssl_msg.c` | `ssl_tls13_write_new_connection_id`: send 2 CIDs; add secondary pool match in decrypt path; pool replenishment in `ssl_tls13_handle_new_connection_id` |
| `library/ssl_tls.c` | Implement `mbedtls_ssl_dtls13_rotate_own_cid`; init pool at HANDSHAKE_OVER or first post-HS NewConnectionId send |
| `library/ssl_misc.h` | `mbedtls_ssl_dtls13_sync_post_hs_seq` call site — init pool at `HANDSHAKE_OVER` |
| `tests/dtls13/cases/cid-update.yaml` | New test cases (see Testing section below) |
| `tests/dtls13/runners/mbedtls.yaml` | New assertions for pool/rotation (see Testing section below) |
| `programs/ssl/ssl_client2.c` | Add `rotate_cid=N` option: call `mbedtls_ssl_dtls13_rotate_own_cid()` after N exchanges |
| `programs/ssl/ssl_server2.c` | Same, add `rotate_cid=N` |

---

## Testing

### New assertions needed in `runners/mbedtls.yaml`

| Assertion | Pattern to match |
|-----------|-----------------|
| `client_cid_rotated` | `-c "own CID rotated"` (debug log in `rotate_own_cid`) |
| `server_cid_rotated` | `-s "own CID rotated"` |
| `client_pool_replenished` | `-c "CID pool replenished"` (debug log after spare consumed) |
| `server_pool_replenished` | `-s "CID pool replenished"` |
| `client_spare_cid_consumed` | `-c "peer switched to spare CID"` |
| `server_spare_cid_consumed` | `-s "peer switched to spare CID"` |
| `client_new_cid_list_2` | `-c "NewConnectionId sent.*2 CIDs"` |
| `server_new_cid_list_2` | `-s "NewConnectionId sent.*2 CIDs"` |

### New test cases in `cid-update.yaml`

**TC-1: NewConnectionId sends 2 CIDs (pool send)**
Verify the wire format change: server sends NewConnectionId and the client log shows
it received 2 CIDs in the list. No rotation triggered — just confirms the new send
format. Assert `server_new_cid_list_2`, `client_new_cid_received`.

**TC-2: Client rotates CID — peer sees new CID in use**
`client rotate_cid=2`: after 2 exchanges the client calls `rotate_own_cid`, which
promotes spare to active and sends NewConnectionId(IMMEDIATE) offering both entries.
Server receives it, switches outbound CID, ACKs, then sends app data. We assert:
- `client_cid_rotated`
- `server_new_cid_received` (server received the NewConnectionId)
- `client_new_cid_acked` (server ACKs the NewConnectionId sent by the client)
- Continued data exchange succeeds (exit: 0, multiple exchanges after rotation).

**TC-3: Server rotates CID — symmetric of TC-2**
Same with `server rotate_cid=2`.

**TC-4: Auto-replenishment after spare consumed**
Client sends NewConnectionId with 2 CIDs. Server switches to spare (simulated via
`send_new_cid` on server side then client consuming it). Assert `client_pool_replenished`:
client detects its spare was consumed and automatically sends a new NewConnectionId.
This tests the auto-replenishment path without any explicit `rotate_cid` call.

**TC-5: Address migration with CID rotation**
Builds on the existing `cid_change_addr` test. Client calls `rotate_own_cid` in the
`cid_change_addr` handler (after rebinding), so the new path uses a fresh CID.
Assert:
- `client_addr_changed`
- `server_addr_migrated`
- `client_cid_rotated` (CID rotated at the same time as address change)
- Continued exchanges succeed with the new CID on the new address.
This is the primary privacy-motivated test case.

**TC-6: Pool exhausted — rotate blocked by pending ACK**
Client calls `rotate_own_cid` twice in rapid succession (before the first ACK
arrives). The second call must be a no-op (pending ACK guard). Assert that only one
`client_cid_rotated` log appears and the connection remains healthy.

**TC-7: Inbound record accepted on both pool CIDs during transition**
3d proxy test with packet reordering. Client rotates CID; some records from before
the rotation arrive after it. The server must accept records bearing the old CID
(still in pool) and the new CID simultaneously, without `CID mismatch` errors.
Use `proxy 3d` with low drop/delay to create overlap. Assert no `server_cid_mismatch`
and successful exchange.

**TC-8: Bad NewConnectionId with 2-entry list — malformed second entry**
New `bad_new_cid=4` variant: valid first CID, second entry truncated. Server must
reject with `decode_error`. Assert `server_new_cid_not_accepted`.

### WolfSSL interop

wolfSSL 5.9.0 is not currently compiled with `WOLFSSL_DTLS_CID` — CID is a no-op in
the test binary (see `wolfssl-interop-notes.md` §Phase 5.8).

After inspecting the wolfssl source (`src/dtls.c`, `src/tls.c`), wolfssl implements
CID only as a handshake extension (negotiated in CH/EE via `TLSX_CONNECTION_ID`).
It does **not** implement the RFC 9147 §9 NewConnectionId post-handshake message
(type 0x41). There is no `SendNewConnectionId`, no pool, no rotation mechanism.

Consequences:

- **All TC-1 through TC-8 stay `skip_runners: [wolfssl]` permanently** — wolfssl
  cannot send or receive the NewConnectionId post-handshake message.

- **What a CID-enabled wolfssl rebuild would unlock**: the existing basic CID tests
  in `cid.yaml` (negotiation, basic exchange) and the functional `cid-update.yaml`
  tests that exercise NewConnectionId as an mbedtls↔mbedtls exchange. Those currently
  fail only because CID isn't compiled in, not because of missing protocol support on
  the wolfssl side. The new pool tests are unaffected.

- **Action**: rebuild wolfSSL with `--enable-dtls13 --enable-cid` (or equivalent),
  verify `WOLFSSL_DTLS_CID` is defined, then run `cid.yaml` and the non-bad-message
  `cid-update.yaml` tests against wolfssl to confirm basic CID negotiation interop.
  Pool-specific tests remain mbedtls-only.

### Regression
All existing CID tests (TC in `cid-update.yaml`) must continue to pass unchanged —
they exercise the single-CID path which must remain valid.

---

## Design decisions

1. **Pool vs transform**: `transform->in_cid` is the single value checked in
   `mbedtls_ssl_decrypt_buf`. The pool lives at `ssl` level. The secondary-check
   approach avoids touching the decrypt path's hot function signature. Preferred.

2. **Pool size 2**: One IMMEDIATE + one SPARE. Sufficient for single-hop address
   migration. Larger pools increase memory but add little value for typical DTLS
   deployments.

3. **CID length uniformity**: All pool entries must have the same length (enforced by
   `mbedtls_ssl_conf_cid()`'s `len` parameter). No length negotiation needed.

4. **Auto-replenishment**: Should be automatic (triggered on peer CID switch
   detection) to keep the pool full without application involvement. The application
   only needs to call `rotate_own_cid` explicitly on local address change.

5. **DTLS 1.2 compatibility**: Pool is DTLS 1.3 only (`#if PROTO_TLS1_3`). DTLS 1.2
   continues using `own_cid` directly. No change to DTLS 1.2 paths.

---

## Rough size estimate

~200 lines of library code, ~50 lines of test infrastructure, ~8 new test cases.
