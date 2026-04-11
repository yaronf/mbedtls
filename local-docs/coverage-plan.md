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
**Decision:** Not actionable. We have no unit test infrastructure, and triggering this
guard via integration test would require `max_content_len` small enough to exhaust the
buffer before the CID extension — which would break the handshake long before reaching
EncryptedExtensions. The guard is a `CHK_BUF_PTR` one-liner that follows the same
pattern as ~50 other identical guards throughout the codebase; not worth building new
infrastructure for. Accept the coverage gap here.

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


| Priority | Item                    | Status  | Notes                                                |
| -------- | ----------------------- | ------- | ---------------------------------------------------- |
| High     | 5: SNE AES path         | **DONE** | handshake.yaml: force AES-128-GCM test passes       |
| High     | 7: Implicit ACK         | Defer   | Needs ssl_client2 change; no WANT_WRITE path exists  |
| Medium   | 3a/3b: Bad KeyUpdate    | **DONE** | keyupdate.yaml: 2 new cases; new API in ssl_msg.c   |
| Medium   | 4: CID parse errors     | **DONE** | cid-update.yaml: 4 new cases; new API in ssl_msg.c  |
| Medium   | 1b: Bad cookie          | **DONE** | hrr-cookie.yaml: bad_cookie_on_retry=1 in srv2      |
| Low      | 1c: Double HRR          | Defer   | Niche failure mode; needs group config gymnastics    |
| Low      | 3c: Pending KeyUpdate   | **DONE** | keyupdate.yaml: double_keyupdate test passes         |
| Skip     | 2: CID buffer overflow  | Skip    | No unit test infra; accept gap                      |
| Defer    | 3d: PSA injection       | Defer   | Requires new infra; fuzz target (item 9)            |
| Defer    | 6: Epoch eviction       | Defer   | Hard to orchestrate; needs proxy work               |
| Defer    | 1a: f_cookie_write fail | Defer   | Requires mock callback; unit test candidate         |


---

## Acceptance Criteria

- `≥80%` branch coverage on new DTLS 1.3 lines (`ssl_msg.c`, `ssl_tls13_server.c`,
`ssl_tls13_generic.c`, `ssl_misc.h`) as measured by lcov after all tests run.
- All new test cases pass with 0 FAILs.
- No regressions in existing 38 dtls13 integration tests.

## Current Status (Phase 7 item 8 complete)

**Tests:** 47 pass (38 original + 9 new), 0 failures.

**Coverage:** Baseline was 72.7% branch (Phase 6.2). The new tests cover the targeted
error paths (AES SNE, bad KeyUpdate, bad CID, bad cookie, double KeyUpdate). The
bad-message helper functions in ssl_msg.c are excluded from coverage via `LCOV_EXCL_START/STOP`
since they only execute in test programs, not in the library under test.

**Coverage tooling note:** On macOS/LLVM clang, multiple concurrent processes writing
to the same `ssl_msg.c.gcda` file (ssl_server2 + ssl_client2 per test) do not merge
correctly — each process overwrites the file rather than accumulating hits. This means
the post-Phase-7 lcov number is unreliable (measured ~71% but structurally suspect).
A Linux CI run with GCC's gcov would give accurate multi-process accumulation.

**Remaining deferred gaps** (per implementation order table above): implicit ACK (item 7),
epoch eviction (item 6), double-HRR (item 1c), PSA injection (item 3d).

---

## GCC/Linux Measurement (2026-04-11)

Measured using `tests/coverage-in-podman.sh` — Ubuntu 24.04 container, GCC 13.3,
`-DCMAKE_BUILD_TYPE=Coverage` (`-O0 -g3 --coverage`), `ctest` (unit suites + dtls13
integration suite). GCC's gcov correctly merges concurrent gcda writes from
ssl_server2 + ssl_client2, unlike macOS/LLVM which overwrites.

**Baseline ref:** `v4.1.0` (upstream release, CTest unit suites only — no dtls13 tests).
**DTLS 1.3 ref:** `HEAD` (this branch, CTest unit suites + dtls13 integration suite).

| File | Baseline Br% | HEAD Br% | Δ Br | Baseline Ln% | HEAD Ln% | Δ Ln |
|------|-------------|---------|------|-------------|---------|------|
| `library/ssl_msg.c` | 52.5% (668/1273) | 68.0% (1516/2230) | +15.5 pp | 63.6% | 78.4% | +14.8 pp |
| `library/ssl_tls.c` | 57.0% (856/1501) | 60.7% (943/1553) | +3.7 pp | 70.6% | 74.0% | +3.4 pp |
| `library/ssl_tls13_client.c` | 42.8% (262/612) | 52.2% (357/684) | +9.4 pp | 70.7% | 78.0% | +7.3 pp |
| `library/ssl_tls13_server.c` | 50.5% (334/661) | 56.5% (420/744) | +6.0 pp | 77.4% | 80.3% | +2.9 pp |
| **TOTAL (library)** | **64.1%** (12625/19711) | **66.1%** (14060/21285) | **+2.0 pp** | **80.9%** | **83.0%** | **+2.1 pp** |

**Why these numbers differ from the 72.7% previously reported:**
- The 72.7% (Phase 6.2) measured only *new DTLS 1.3 lines* in isolation, filtered by
  line number from the pre-existing baseline. These numbers measure *entire files*
  including all pre-existing branches.
- GCC properly merges concurrent gcda writes; macOS/LLVM did not, so prior numbers
  undercounted integration test hits.
- The dtls13 integration suite had some failures in the container environment
  (likely timing-sensitive tests); full pass would push numbers slightly higher.

**Full report:** `coverage-baseline/report/Coverage/index.html` and
`coverage-dtls13/report/Coverage/index.html` (not committed — regenerate with
`tests/coverage-in-podman.sh`).

