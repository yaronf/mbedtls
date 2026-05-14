# Ultrareview findings — 2026-05-13

Source: `/ultrareview` run against the `dtls13` branch (vs `development`).
Scope: 112 files changed, ~30k insertions — i.e. the **whole** DTLS 1.3
work (279 commits), not just the cookie effort. Triage below filters
to the findings actually in scope for this branch.

7 findings: 5 normal-severity, 2 nits. None are in the cookie commits
themselves (Phase 1 steps 1–5 and Phase 2 steps 1–3); all live in
broader DTLS 1.3 code that predates the cookie work.

The findings are recorded **as reported** — line numbers are a snapshot
and need to be verified against the current tree before acting on each
one (the codebase has moved since the review snapshot was taken).

---

## Triage summary


| #   | id             | severity | file             | trigger                                  | fix size |
| --- | -------------- | -------- | ---------------- | ---------------------------------------- | -------- |
| 1   | bug_007        | normal   | ssl_msg.c        | 5 unsolicited peer KeyUpdates → UAF      | small    |
| 2   | bug_001        | normal   | ssl_msg.c        | peer sends DTLS 1.3 short-seq record     | one byte |
| 3   | bug_008        | normal   | ssl_msg.c        | post-HS msg > remaining datagram, MTU    | one line |
| 4   | merged_bug_006 | normal   | ssl_msg.c        | post-HS retransmit timeout / epoch evict | medium   |
| 5   | bug_011        | normal   | ssl_msg.c        | PSA hash failure on DTLS 1.3 xscript     | one line |
| 6   | bug_003        | nit      | build-dbg/tests/ | `.gitignore` violation                   | git rm   |
| 7   | bug_005        | nit      | ssl_msg.c        | dev-debug breadcrumbs                    | delete   |


Recommended order: 1 → 2 → 3 → 5 → 4 → (nits last as a cleanup pass).
Rationale: 1 is remote-attacker-triggerable UAF, 2 is a spec-compliance
interop break, 3 is a public-API NULL deref, 5 is trivial. 4 is the
biggest fix surface and is in my own recent work, so I want to read
the cited paths carefully before patching.

Pre-fix step for each: verify the cited file:line still describes the
current code. The ultrareview snapshot may not match HEAD.

---

## 1. bug_007 — Use-after-free in DTLS 1.3 outbound transform on inbound-only KeyUpdate flood

- **Severity:** normal (but remote-attacker-triggerable)
- **File / lines:** `library/ssl_msg.c:8302-8315`
- **Sibling site:** `library/ssl_msg.c:8327` (symmetric outbound-only case)

### Summary

After DTLS 1.3 handshake completion, `transform_in`, `transform_out`,
and `transform_application` all point to the same transform struct
(set at `ssl_tls13_generic.c:1261-1264`).
`ssl_dtls13_retire_transform_to_pool()` only clears the explicitly-
passed alias pointer when retiring a transform into the 4-slot epoch
pool, so on a peer-driven KeyUpdate the inbound handler clears
`transform_in` and `transform_application` but leaves `transform_out`
pointing at the pool-owned struct. After 5 inbound-only KeyUpdates the
pool (size 4) evicts and `mbedtls_free`s that struct; the next
`mbedtls_ssl_write()` then encrypts through the freed transform —
a use-after-free in cryptographic state, reachable post-handshake from
any peer (RFC 8446 §4.6.3 / RFC 9147 §8 impose no KU rate limit).

The symmetric outbound-only case exists in `ssl_msg.c:8327`
(`ssl_dtls13_key_update_install_outbound`).

### Trigger sequence (inbound flood)

1. Handshake completes. `transform_in = transform_out =
  transform_application = X` (epoch 3); pool empty.
2. Peer sends `KeyUpdate(update_not_requested)`. `ssl_tls13_handle_key_update`
  derives `Z` and calls
   `retire_transform_to_pool(ssl, &transform_application, &transform_in)`.
   `transform_application` cleared, `X` inserted into pool, `transform_in = Z`.
   `transform_out` still points at `X`.
3. KU #2–#4 retire `Z`, `V`, `W` into the pool. Pool = `[X, Z, V, W]`.
4. KU #5: pool full; `epoch_pool_insert` evicts the slot with the
  lowest `retired_epoch` (`ssl_msg.c:10248-10262`):
   No alias scan against `ssl->transform_{in,out,application}` before
   free. `transform_out` is now dangling.
5. Next `mbedtls_ssl_write` → `write_record` → `encrypt_buf(ssl,
  transform_out, …)`dereferences`psa_alg`,` psa_key_enc`,`  iv_enc`, AEAD limit counters → UAF on cryptographic state.

### Why existing safeguards don't catch it

- `ssl_dtls13_free_epoch_if_orphan()` only runs in `session_reset_msg_layer`
/ `ssl_free` (`ssl_tls.c:1412`, `5426`) — not during normal KU.
- `epoch_pool_contains` is consulted on subsequent retires to avoid
double-insert; it never runs before eviction.
- Per-epoch auth-fail limit is unrelated; benign KU records authenticate.

### Suggested fix

Teach `ssl_dtls13_retire_transform_to_pool` to also clear the
cross-direction pointer when it aliases the retiring struct. For the
inbound retire path, additionally check `ssl->transform_out == *transform_p` and NULL it; symmetric for the outbound path.

Defence-in-depth: in `ssl_dtls13_epoch_pool_insert` just before
`mbedtls_free` on eviction, scan `ssl->transform_{in,out,application}`
for the to-be-freed pointer and reconcile any survivor.

---

## 2. bug_001 — DTLS 1.3 SNE applies wrong mask byte for 1-byte sequence numbers

- **Severity:** normal
- **File / lines:** `library/ssl_msg.c:4994-4999`

### Summary

`ssl_dtls13_sne_apply()` XORs the on-wire seq byte with `mask[1]` in
the 1-byte branch, but RFC 9147 §4.2.3 specifies the *leading* byte
of the mask — `mask[0]` — for a 1-byte seq. The misleading comment
("low byte of mask") suggests "low byte (big-endian)" was conflated
with "leading byte".

### Manifestation

- **Outbound (write):** `mbedtls_ssl_write_record` always sets the `S`
bit (`0x2C | epoch_bits | cid_bit` → S=1), so the 1-byte branch is
unreachable on the write path. Outbound records are unaffected.
- **Inbound (read):** `ssl_parse_dtls13_record_header` honours the
on-wire S bit: `long_seq = (type_byte >> 3) & 1; seq_len = long_seq ? 2 : 1;`. A peer using S=0 (RFC 9147 §5.2 / §4.1 explicitly permits
mixing) hits the buggy branch on decrypt.

### Trigger

Concrete inbound record from a compliant peer using short-seq form:
`mask = [0xA3, 0x5C, ...]`, plaintext seq `0x12`.

- Peer encrypts: `wire_seq = 0x12 XOR mask[0] = 0xB1`.
- We receive, set `seq_len = 1`, copy `0xB1` into `seq_in_header[0]`.
- 1-byte branch executes `seq_in_header[0] ^= mask[1] = 0xB1 XOR 0x5C = 0xED`. (Correct would be `0xB1 XOR 0xA3 = 0x12`.)
- AEAD nonce built from `0xED` instead of `0x12`. Auth fails. Record
discarded. After enough failures, badmac limit closes the connection.

### Impact

Silent interop break with any RFC-compliant DTLS 1.3 peer (wolfSSL,
OpenSSL, picotls, BoringSSL configured for S=0) that picks short-seq.
mbedtls-to-mbedtls handshakes never exercise the bug because we always
write S=1 — which is why internal interop testing missed it.

### Suggested fix

One-byte change at `ssl_msg.c:4995`:

```c
-    seq_in_header[0] ^= mask[1]; /* use low byte of mask for 1-byte seq */
+    seq_in_header[0] ^= mask[0]; /* RFC 9147 §4.2.3: leading byte */
```

Test: extend the interop tests (against a peer that emits short-seq)
with a short-seq case.  A local SNE roundtrip unit test cannot
demonstrate the bug: mbedtls's write path always sets `S=1` (2-byte
seq), so the 1-byte branch is unreachable from our writer.  The bug
lives only in the decrypt path; only a peer that *emits* short-seq
exercises it.

---

## 3. bug_008 — NULL dereference of `ssl->handshake` in DTLS 1.3 fragmentation path for post-handshake messages

- **Severity:** normal
- **File / lines:** `library/ssl_msg.c:3268-3297` (entry condition at 3277-3279)

### Summary

`mbedtls_ssl_write_handshake_msg_ext`'s entry guard at `3001-3014`
explicitly permits `ssl->handshake == NULL` when `hs_type` is one of
`MBEDTLS_SSL_HS_KEY_UPDATE`, `MBEDTLS_SSL_HS_NEW_CONNECTION_ID`,
`MBEDTLS_SSL_HS_REQUEST_CONNECTION_ID` (all DTLS 1.3 post-handshake
messages reachable from `mbedtls_ssl_dtls13_send_new_connection_id`,
`mbedtls_ssl_dtls13_request_connection_id`, `mbedtls_ssl_send_key_update`
after `handshake_wrapup_free_hs_transform`).

The fragmentation entry condition has a NULL guard on the *second*
clause of the OR but not the first:

```c
if (ssl->out_msglen > (size_t) ret ||
    (ssl->handshake != NULL &&
     ssl->handshake->dtls13_frag_off > 0)) {
```

If a post-HS message body exceeds remaining datagram payload (low
MTU, dgram_packing, or large NewConnectionId), the first clause
fires with `handshake == NULL`, and at L3297 `size_t frag_off = ssl->handshake->dtls13_frag_off;` immediately NULL-derefs.

### Trigger configuration

1. DTLS 1.3 handshake completes with CID, `cid_len = 32`.
2. App calls `mbedtls_ssl_set_mtu(ssl, 80)` (realistic on LoRaWAN/PPP).
3. Peer sends app data → `handle_message_type` reaches `HANDSHAKE_OVER`
  branch → `handshake_wrapup_free_hs_transform` → `ssl->handshake = NULL`.
4. App calls `mbedtls_ssl_dtls13_send_new_connection_id(ssl)`.
5. NewConnectionId body (~69 B with cid_len=32 and pool of 2) +
  12 B HS header = 81 B; remaining payload ~58 B. First clause fires.
6. L3297 dereferences NULL → SIGSEGV.

### Suggested fix

Mirror the existing L3419-3422 guard:

```c
if (ssl->handshake != NULL &&
    (ssl->out_msglen > (size_t) ret ||
     ssl->handshake->dtls13_frag_off > 0)) {
```

If post-HS messages legitimately need to fragment, a follow-up should
add a post-HS fragmentation path that stores the resume offset on the
post-HS retransmit slot rather than on `handshake`. (Open question:  
do current post-HS messages ever exceed an MTU in any supported  
configuration? If not, the guard alone is a complete fix.) -- Support fragmentation even if it's only used by future HS messages.

---

## 4. merged_bug_006 — Incomplete cleanup in `ssl_dtls13_post_hs_handle_timeout` error paths

- **Severity:** normal
- **File / lines:** `library/ssl_msg.c:8214-8243` (budget-exhaust), `8246-8254` (retransmit-one fail)
- **Provenance:** in my recent post-handshake-retransmit work. Read carefully before patching.

### Two sub-bugs

#### (a) Transform leak on budget exhaust (8214-8243)

The budget-exhausted branch clears `dtls13_ku_ack_pending`,
`dtls13_cid_update_ack_pending`, `dtls13_req_cid_pending` and zeros
every retransmit slot — but leaves `ssl->dtls13_transform_pending_out`
and `ssl->dtls13_ku_pending_secret` intact. The transform was
allocated by `ssl_tls13_write_key_update` (`ssl_msg.c:8472`:
`ssl->dtls13_transform_pending_out = new_transform;` — unconditional
assignment with no free of any prior pointer).

The only overwrite guard is the early-return at `8390-8394` checking
`dtls13_ku_ack_pending`. The budget-exhaust branch cleared that flag,
so the guard no longer fires. If the caller ignores
`MBEDTLS_ERR_SSL_TIMEOUT` and keeps writing, the next AEAD-limit-
triggered KU overwrites the pointer and the old transform leaks.
Each leak is ~hundreds of bytes plus PSA key handles; bounded only
by `session_reset` / `ssl_free`.

The in-source comment at `8390-8391` acknowledges the constraint:
"cannot overwrite the pending transform without leaking it" —
the budget-exhaust path violates exactly this.

#### (b) Pending flag leak on retransmit-one failure (8246-8254)

`ssl_dtls13_post_hs_retransmit_one` can return INTERNAL_ERROR when
the original send-epoch has been evicted from the 4-slot
`dtls13_epoch_pool` (`8096-8105`: `ssl_dtls13_retx_epoch_switch`
returns 1 on evict). Reachable on long-lived sessions with sustained
rekeying: pool size 4 with fixed `send_epoch` (RFC 9147 §7.2) means
rapid KUs can evict the slot's epoch.

The failure branch only calls `ssl_dtls13_clear_post_hs_retransmit_slot(slot)`,
which only frees `slot->bytes` and zeros the slot. It does NOT touch
`ssl->dtls13_ku_ack_pending` / `dtls13_cid_update_ack_pending` /
`dtls13_req_cid_pending`. The public predicates
`mbedtls_ssl_dtls13_key_update_pending` / `_new_connection_id_pending`
(public inline at `include/mbedtls/ssl.h:5613`, `5626`) read those
flags directly.

After this branch executes, the slot is gone (no future retransmit
possible) but the predicate returns non-zero indefinitely. The
documented drain idiom

```c
while (mbedtls_ssl_dtls13_key_update_pending(ssl)) {
    mbedtls_ssl_read(...);
}
```

loops forever until `session_reset`.

The in-source comment at `8249` says: "Clear the slot's pending flag
so the application doesn't hang" — but only the slot struct is
cleared, not the per-context flag that the predicates actually read.
The comment describes the correct intent; the implementation falls
short.

### Suggested fix

In **both** branches, before/after `clear_post_hs_retransmit_slot(slot)`,
switch on `slot->type` to clear the matching per-context flag, AND
free `dtls13_transform_pending_out` + zeroize
`dtls13_ku_pending_secret` for KU slots:

```c
switch (slot->type) {
    case MBEDTLS_SSL_DTLS13_PENDING_ACK_KEY_UPDATE:
        ssl->dtls13_ku_ack_pending = 0;
        mbedtls_ssl_transform_free(ssl->dtls13_transform_pending_out);
        mbedtls_free(ssl->dtls13_transform_pending_out);
        ssl->dtls13_transform_pending_out = NULL;
        mbedtls_platform_zeroize(ssl->dtls13_ku_pending_secret,
                                 sizeof(ssl->dtls13_ku_pending_secret));
        break;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    case MBEDTLS_SSL_DTLS13_PENDING_ACK_NEW_CONNECTION_ID:
        ssl->dtls13_cid_update_ack_pending = 0;
        break;
    case MBEDTLS_SSL_DTLS13_PENDING_ACK_REQUEST_CONNECTION_ID:
        ssl->dtls13_req_cid_pending = 0;
        break;
#endif
    default: break;
}
ssl_dtls13_clear_post_hs_retransmit_slot(slot);
```

This satisfies the cleanup pattern already used by
`session_reset_msg_layer` / `ssl_free`.

---

## 5. bug_011 — Missing error check on `add_hs_msg_to_checksum` in DTLS 1.3 transcript update

- **Severity:** normal
- **File / lines:** `library/ssl_msg.c:3149-3162`

### Summary

`mbedtls_ssl_write_handshake_msg_ext`'s DTLS 1.3 transcript-update
branch stores `add_hs_msg_to_checksum`'s return in `ret` but never
checks it before falling through. The parallel else-branch (DTLS 1.2 /
TLS) correctly checks `update_checksum`'s return and propagates the
error.

A PSA hash-backend failure (`ALLOC_FAILED`, transient PSA, BAD_STATE)
is silently ignored. The stale/incorrect transcript hash then flows
into PSK binders, Finished MAC, and CertificateVerify signing —
surfacing later as `bad_record_mac` / `decode_error` / Finished
mismatch that masks the original cause.

Not directly attacker-triggerable (failure mode is local PSA-backend
or host resource exhaustion), but silent crypto-state corruption is a
class the library otherwise treats seriously, and the fix is trivial.

### Suggested fix -- isn't there a macro we can use to force error checking?

Mirror the else-branch:

```c
size_t body_len = ssl->out_msglen - 12;
ret = mbedtls_ssl_add_hs_msg_to_checksum(
          ssl, hs_type, ssl->out_msg + 12, body_len);
if (ret != 0) {
    MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_add_hs_msg_to_checksum", ret);
    return ret;
}
```

---

## 6. bug_003 (nit) — Build-directory artifacts checked into source tree under `build-dbg/`

- **Severity:** nit
- **Files:** `build-dbg/tests/run-3d-sweep.sh`, `build-dbg/tests/run-hrr3d.sh`

### Summary

Two tracked shell scripts under `build-dbg/tests/` while the same
branch adds `/build-*/` to `.gitignore` (line 53). Canonical
build-dir-agnostic versions exist at `tests/run-3d-sweep.sh` and
`tests/run-hrr3d.sh`. The `build-dbg/` copies hard-code
`$SCRIPT_DIR/../programs/...` paths that only resolve from inside an
out-of-tree build — looks like a stray `git add`.

### Suggested fix

```sh
git rm build-dbg/tests/run-3d-sweep.sh build-dbg/tests/run-hrr3d.sh
```

---

## 7. bug_005 (nit) — Stray `DBG`-prefixed debug messages in `ssl_buffer_message`

- **Severity:** nit
- **File / lines:** `library/ssl_msg.c:6171`, `6175`
- **Related:** `library/ssl_tls13_generic.c:86` (same anti-pattern,
separate occurrence — leftover dev breadcrumb in my own
`fetch_handshake_msg` work, worth removing in the same pass)

### Summary

Two `MBEDTLS_SSL_DEBUG_MSG` calls with `"DBG ssl_buffer_message:"`
prefix — obvious leftover dev breadcrumbs. No other debug message in
the file uses this style. L6171 fires unconditionally at level 1 on
every buffered handshake message, polluting customer debug logs;
L6175 is a `should never happen` path that already has the
conventional message right below it.

### Suggested fix

Either delete or rewrite in the prose style used elsewhere in the
file (e.g. `buffering handshake message: type=%u seq=%u (next expected=%u)`).

Same pass: remove the `DBG fetch_hs_msg: ...` log at
`ssl_tls13_generic.c:86` introduced during the post-handshake
retransmit work.