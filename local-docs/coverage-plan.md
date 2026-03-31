# Phase 7 Item 8: Coverage Gap Closure Plan

**Goal:** ≥80% branch coverage on new DTLS 1.3 lines (baseline: 72.7% after Phase 6.2).

Each section describes the uncovered paths, the root cause of the gap, and the concrete
test(s) needed to close it. Tests are grouped by file and use the ssl-opt.sh / dtls13
integration test framework unless otherwise noted.

---

## 1. `ssl_tls13_server.c` — HRR + Cookie Failure Paths

### 1a. `f_cookie_write` callback error
**Path:** `ssl_tls13_write_server_hello_body()` ~line 2487
**Condition:** `f_cookie_write` returns non-zero during HRR generation.
**Gap cause:** Requires a custom cookie callback that injects a failure — not exercised
by any current test.
**Test approach:** Unit test or ssl-opt.sh with a custom server configuration that uses
a mock `f_cookie_write` returning an error on the second call (first call succeeds to
produce the HRR challenge; second would produce the cookie in the ServerHello — but the
write path in question is actually called during the HRR ServerHello write). Simpler
alternative: use `bad_ad` or `inject_clihlo` proxy options to corrupt the HRR, causing
the server's cookie write to run in a degraded state. **Decision:** ssl-opt.sh unit test
that replaces the cookie callbacks with error-injecting variants.

### 1b. Invalid cookie in second ClientHello
**Path:** Cookie check in ClientHello processing ~line 1723
**Condition:** `f_cookie_check` returns non-zero (client sent wrong/expired cookie).
**Gap cause:** The HRR path is tested (hrr-cookie.yaml) but the "cookie check fails"
branch is not — all current tests use valid cookies.
**Test approach:** Integration test where the proxy corrupts the cookie bytes in the
second ClientHello (after HRR). Server should reject with `handshake_failure` and the
connection should fail.
**Test:** `hrr-cookie.yaml` case: "HRR cookie: corrupted cookie in second ClientHello"
— proxy `bad_ad` is not fine-grained enough; need `delay`/drop of second ClientHello
and manual injection, OR a new proxy flag to corrupt a specific record. Alternative:
use `ssl-opt.sh` with `--force-bad-cookie` server option if available.
**Feasibility note:** Requires either proxy-level cookie corruption or a new server
parameter `bad_cookie_on_retry=1` that causes the cookie check callback to return
failure. The latter is simpler. Add `bad_cookie_on_retry` param to `ssl_server2`.

### 1c. Second HRR attempt (double-HRR detection)
**Path:** `ssl_tls13_prepare_hello_retry_request()` ~line 2606
**Condition:** `hello_retry_request_flag` already set when a second HRR would be sent.
**Gap cause:** RFC 9147 prohibits a second HRR; the code returns
`MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE` here. No test forces a second HRR.
**Test approach:** Force the server into a state where key share negotiation fails
twice — e.g., configure the server with a very restrictive group list that doesn't
match the client's updated key_share in the second ClientHello. The server would try
to send a second HRR and hit this path.
**Test:** ssl-opt.sh: server `groups=secp256r1`, client offers `secp384r1` first, then
`secp521r1` second (still not matching) → server hits double-HRR detection.

---

## 2. `ssl_tls13_server.c` — EncryptedExtensions CID Buffer Error

**Path:** `mbedtls_ssl_write_cid_ext()` buffer overflow check ~line 1871
**Condition:** Output buffer has insufficient space when writing the CID extension inside
EncryptedExtensions.
**Gap cause:** Buffer overflow checks in extension writers are hard to trigger via
normal handshake — the buffer is sized generously. Requires artificially constraining
the buffer.
**Test approach:** This is most practical as a unit test that calls
`mbedtls_ssl_write_cid_ext()` directly with a buffer of fewer than 5 bytes. A
ssl-opt.sh approach would require `max_content_len` to be very small AND CID enabled,
which is hard to arrange without breaking the handshake before reaching
EncryptedExtensions.
**Decision:** Unit test in `tests/ssl-utils.c` or similar; low priority since this is a
`CHK_BUF_PTR` guard that follows the same pattern as 50+ other guards throughout the
codebase. Mark as "low-priority / defensive guard" and close if coverage target is met
without it.

---

## 3. `ssl_msg.c` — KeyUpdate Error and Cleanup Paths

### 3a. Malformed incoming KeyUpdate (bad length)
**Path:** `ssl_tls13_handle_key_update()` ~line 7638
**Condition:** KeyUpdate message body length ≠ `hs_hdr_len + 1`.
**Gap cause:** No test sends a malformed KeyUpdate.
**Test approach:** Integration test using the proxy to corrupt/truncate the KeyUpdate
message. The `bad_ad` proxy option corrupts ApplicationData; KeyUpdate is a Handshake
record (type 24). Need `bad_hs_body=1` proxy option, or inject via a custom record
in ssl-opt.sh with `force_bad_keyupdate=1` in `ssl_client2`.
**Simpler alternative:** New ssl_client2 parameter `bad_keyupdate=1` that sends a
KeyUpdate with an extra/missing byte in the body. Server should respond with a
`decode_error` alert and close the connection.
**Test:** `keyupdate.yaml`: "server rejects malformed KeyUpdate (bad length)" —
connection must fail with exit code 1 and assert `server_keyupdate_decode_error`.

### 3b. Invalid `update_requested` value in KeyUpdate
**Path:** `ssl_tls13_handle_key_update()` ~line 7648
**Condition:** `update_requested` byte is not 0 or 1.
**Test approach:** Same as 3a — `bad_keyupdate=2` sends `update_requested=2`.
Server responds with `illegal_parameter` alert.

### 3c. Pending KeyUpdate (second KeyUpdate before first ACKed)
**Path:** `ssl_tls13_write_key_update()` ~line 7515
**Condition:** `dtls13_transform_pending_out != NULL` when a second KeyUpdate is sent.
**Test approach:** Force client or server to send two KeyUpdates in rapid succession
without waiting for the ACK on the first. Could use `key_update=1` with a custom
sequence, or add a `double_keyupdate=1` option to ssl_client2 that calls the KeyUpdate
write twice back-to-back. The second call should return `WANT_WRITE` (pending ACK) and
not corrupt state.
**Priority:** Medium — exercises a guard that is important for state machine correctness.

### 3d. KeyUpdate secret derivation failure (PSA injection)
**Path:** `mbedtls_ssl_tls13_update_traffic_secret()` failure path, cleanup at ~line 7610
**Gap cause:** PSA failure injection is not used in any current DTLS 1.3 tests.
**Decision:** Low priority — PSA failure injection requires test infrastructure that
doesn't exist today. Defer to fuzz testing (item 9).

---

## 4. `ssl_msg.c` — CID Post-Handshake Message Parsing Errors

### 4a. NewConnectionId: truncated / malformed message
**Path:** `ssl_tls13_handle_new_connection_id()` ~lines 7896–7933
**Conditions covered:**
- Message too short (< 2 bytes for `list_len`)
- `list_len = 0`
- `cid_len > MBEDTLS_SSL_CID_OUT_LEN_MAX`
- Inconsistent length fields
- Invalid `usage` value

**Gap cause:** CID tests use well-formed NewConnectionId messages from `ssl_client2`.
No test sends a malformed one.
**Test approach:** New ssl_client2 parameter `bad_new_cid=<type>` that sends a
NewConnectionId with a specific malformation. Alternatively, use the proxy to corrupt
the CID message body (similar to `bad_ad` but targeted at post-HS handshake records).
**Tests needed (add to `cid-update.yaml`):**
- "NewConnectionId: truncated message" → server closes with `decode_error`
- "NewConnectionId: invalid usage byte" → server closes with `illegal_parameter`
- "NewConnectionId: CID too long" → server closes with `illegal_parameter`

### 4b. RequestConnectionId: truncated / overflow
**Path:** `ssl_tls13_handle_request_connection_id()` ~lines 8021–8032
**Test approach:** Same approach — `bad_req_cid=<type>` parameter.
**Tests needed:**
- "RequestConnectionId: empty message" → `decode_error`
- "RequestConnectionId: too many requests" → `too_many_cids_requested`

**Priority:** Medium. CID is a DTLS 1.3 extension and these are well-defined error
paths in RFC 9147.

---

## 5. `ssl_msg.c` — SNE AES Path

**Path:** `ssl_dtls13_sne_compute_mask()` AES-ECB branch ~lines 4688–4728
**Condition:** Transform uses AES (not ChaCha20) as the AEAD algorithm.
**Gap cause:** Current tests use default cipher suite selection; if the default happens
to be AES-GCM, this path IS exercised. Need to confirm.
**Investigation needed:** Run existing tests with `force_ciphersuite=TLS1-3-AES-128-GCM-SHA256`
and check coverage. If not already covered, add a test case with
`force_ciphersuite=TLS1-3-AES-128-GCM-SHA256` to the handshake suite to force the
AES SNE path explicitly.
**Test:** `handshake.yaml`: new case "DTLS 1.3 handshake: force AES-128-GCM (AES SNE path)"
with `ciphersuite: TLS1-3-AES-128-GCM-SHA256` on both sides.
**Priority:** High — if this path is genuinely uncovered, it's a significant gap since
AES-GCM is the most common cipher suite.

---

## 6. `ssl_msg.c` — Cross-Epoch Retransmit Eviction

**Path:** `ssl_dtls13_retx_epoch_switch()` returns 1 (epoch evicted) at ~line 2469
**Condition:** A retransmit flight references an epoch that has been evicted from the
4-slot epoch pool.
**Gap cause:** Normal operation never evicts an epoch that's still needed for
retransmit — the pool size (4) accommodates the full epoch ladder (0, 1, 2, 3). To
hit the eviction path, we'd need 5+ distinct epochs during a single retransmit window,
which requires multiple KeyUpdates while a retransmit is pending.
**Test approach:**
1. Complete a DTLS 1.3 handshake (epochs 0–3)
2. Drop the server's Finished ACK (proxy `drop=1`) so server retransmit starts
3. While server is retransmitting, client sends 2 KeyUpdates to advance epochs to 5
4. Pool now holds epochs 1,2,3,4 — epoch 0 (needed for retransmit) is evicted
5. Verify server logs "retransmit epoch evicted" and skips that flight item
6. Connection eventually completes or times out gracefully

**Feasibility:** Hard to orchestrate deterministically with the current proxy. The
`drop=N` option drops 1-in-N packets; reliably dropping only the ACK is difficult.
**Decision:** Defer until proxy gains more surgical drop capability, or add a dedicated
`drop_client_ack=1` proxy option. Document as known gap.

---

## 7. `ssl_msg.c` — `dtls13_wait_ack_step` Implicit-ACK Path

**Path:** Implicit-ACK detection ~lines 8803–8811 (server receives ApplicationData
before explicit ACK for its final flight).
**Gap cause:** Normal handshake completes via explicit ACK. Implicit-ACK requires the
client to send application data before the ACK, which the current `ssl_client2` doesn't
do by default.
**Test approach:** Modify the client to send application data immediately after
receiving the server Finished, before sending the ACK. Add a `skip_final_ack=1`
parameter to `ssl_client2` that suppresses the explicit ACK and immediately sends
application data. The server should detect the implicit ACK, cancel its retransmit
timer, and advance to `HANDSHAKE_OVER`.
**Test:** `handshake.yaml`: "DTLS 1.3 implicit ACK: client sends data before ACK"
with `skip_final_ack=1` on client, verify handshake completes and
`server_implicit_ack` assertion fires.
**Priority:** High — implicit-ACK is an RFC 9147 §7 mechanism and important for
practical interoperability (not all peers send explicit ACKs).

---

## Implementation Order

| Priority | Item | Effort | Notes |
|----------|------|--------|-------|
| High | 5: SNE AES path | Low — may just need a ciphersuite param | Check if already covered first |
| High | 7: Implicit ACK | Medium — needs ssl_client2 change | Important for interop |
| Medium | 3a/3b: Bad KeyUpdate | Medium — needs ssl_client2 change | Well-defined error path |
| Medium | 4: CID parse errors | Medium — needs ssl_client2 changes | Multiple sub-cases |
| Medium | 1b: Bad cookie | Medium — needs server param or proxy feature | |
| Low | 1c: Double HRR | Low — groups config | Niche failure mode |
| Low | 3c: Pending KeyUpdate | Low | Guards state machine |
| Defer | 2: CID buffer overflow | Low coverage gain | Unit test candidate |
| Defer | 3d: PSA injection | Requires new infra | Fuzz target (item 9) |
| Defer | 6: Epoch eviction | Hard to orchestrate | Needs proxy work |
| Defer | 1a: f_cookie_write fail | Requires mock callback | Unit test candidate |

---

## Acceptance Criteria

- `≥80%` branch coverage on new DTLS 1.3 lines (`ssl_msg.c`, `ssl_tls13_server.c`,
  `ssl_tls13_generic.c`, `ssl_misc.h`) as measured by lcov after all tests run.
- All new test cases pass with 0 FAILs.
- No regressions in existing 38 dtls13 integration tests.
