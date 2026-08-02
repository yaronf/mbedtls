# Merge Plan: dtls13 → mbedtls 4.2.0

Branch: `dtls13`  
Target tag: `mbedtls-4.2.0` (`ece41aa84d`, 2026-07-01)  
Date: 2026-08-02  
Status: **merged** — message style matching `a43cfaadf3`:
`Merge: mbedtls 4.2.0 into dtls13 branch`.

---

## Scope

~283 upstream commits since `mbedtls-4.1.0`. Submodules `framework` and
`tf-psa-crypto` advanced to the 4.2.0 / TF-PSA-Crypto 1.2.0 pointers
(`dde0c4a0e4`, `73c5da561c`). Five content conflicts; remaining SSL files
auto-merged and spot-checked.

---

## Conflict resolutions

### `include/mbedtls/ssl.h`

Kept DTLS 1.3 typedefs/macros (`mbedtls_ssl_dtls13_*`, cookie-secret API) from
ours, and upstream’s session-reset script warning comment before
`struct mbedtls_ssl_context`.

### `library/ssl_tls13_generic.c`

Took upstream `mbedtls_ssl_tls13_fetch_handshake_msg` rewrite (per-type record
boundary checks). Re-applied DTLS path: `mbedtls_ssl_hs_hdr_len(ssl)`,
`in_msg_seq++`, `mbedtls_ssl_dtls_advance_buffering(ssl)`, and `return 0` on
success (not a hardcoded TLS header offset of 4).

### `programs/ssl/ssl_client2.c`

Kept both upstream `badmac_limit` CLI option and our DTLS 1.3 `aead_limit` /
`auth_fail_limit` knobs.

### `tests/suites/test_suite_ssl.function` / `.data`

Kept both sides (same approach as 4.1.0): DTLS 1.3 helpers/tests (cookie-secret,
mock timer) plus upstream additions (NST mem, early-data drop, record-boundary
alignment, `tls_tweak_in_msglen`).

---

## Auto-merge review notes

- **`ssl_tls.c` `session_reset`:** Upstream clears `alert_reason`/`alert_type`,
  `badmac_seen`, and `dtls_srtp_info`. DTLS 1.3 epoch-pool / post-HS retransmit
  resets remain intact. CID length rejection in `ssl_context_load` is present.
- **`ssl_tls13_client.c`:** Upstream HRR `selected_group` validation applies to
  shared TLS 1.3 client code; DTLS HRR/cookie-secret path still exercised by
  unit + integration tests (no separate DTLS-only fork of this check).
- Transcript-hash failure propagation and NST/policy/ECDHE-PSK fixes came in via
  auto-merge; no double-handling spotted against prior ultrareview fixes.

---

## Post-merge verification

- Build: Debug cmake (`ENABLE_TESTING=ON`), portable cmake 3.31.6 (WSL aarch64;
  system cmake not installed).
- Unit: `test_suite_ssl.dtls13` 45/45 PASS; `test_suite_ssl` 948/948 PASS
  (146 skipped).
- Integration: full `tests/dtls13/dtls13-tests.sh` — all executed cases PASS
  (handshake, HRR/cookie, KeyUpdate, CID, PSK, proxy/loss, version negotiation,
  stateless cluster).

---

## Follow-ons (optional)

- Confirm HRR `selected_group` edge cases specifically under DTLS cookie-secret
  HRR (unit coverage exists for cookie crypto; stream test
  `tls13_hrr_then_tls12_second_client_hello` remains TLS-only).
- Consider a DTLS analogue of that HRR→1.2 downgrade unit test (carried from
  4.1.0 notes).
