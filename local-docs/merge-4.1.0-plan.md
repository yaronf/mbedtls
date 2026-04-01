# Merge Plan: dtls13 → mbedtls 4.1.0

Branch: `dtls13`  
Target tag: `mbedtls-4.1.0`  
Date: 2026-04-01  
Status: merge in progress (`git merge mbedtls-4.1.0 --no-commit --no-ff`)

---

## Scope

454 commits from upstream, 174 files changed (+4162/-30916 lines net). All
automatic merges completed; 4 files have conflicts, 2 of which are partially
resolved.

---

## What Changed in 4.1.0 (merge-relevant subset)

### Security fixes

1. **TLS 1.3 HRR second ClientHello** (`ssl_tls13_server.c`) — a MITM could
   force a resumption handshake to fall back to TLS 1.2 with an all-zero master
   secret, bypassing client authentication. The upstream fix adds a validation
   check in the server's second ClientHello handler.
   **Action:** Verify our DTLS 1.3 HRR path does not have an analogous
   vulnerability. The fix is in the TLS stream path; the DTLS 1.3 HRR code is
   separate but worth a targeted review.
   **Follow-on test:** Consider adding a DTLS 1.3 analogue of the new upstream
   unit test `tls13_hrr_then_tls12_second_client_hello` to the integration test
   suite. See test conflict section below.

2. **TLS 1.2 signature algorithm check** (`ssl_tls12_client.c`) — client
   accepted server key exchange signed with an algorithm not in its advertised
   list. CVE-2026-25834. **Affects DTLS 1.2 equally:** `ssl_tls12_client.c` is
   shared between TLS 1.2 and DTLS 1.2 with no transport-specific branching
   around the signature algorithm validation (`ssl_parse_signature_algorithm()`
   at line ~1738, called from `ssl_parse_server_key_exchange()`). The fix was
   taken automatically and covers both transports.

3. **x509 `NULL` deref / buffer underflow** — CVE-2026-25833 and related.
   Taken automatically.

### Bugfixes

1. **Fragmented DTLS 1.2 ClientHello reassembly** — new code block in
   `ssl_msg.c`. Conflict 1 in `ssl_msg.c` was already resolved by taking the
   upstream block (correct choice: our branch had nothing there).

2. **General `ssl_buffering_shift_slots` refactor** — upstream replaced our
   single-slot `mbedtls_ssl_dtls_advance_buffering()` with a more general
   static helper. See conflict resolution below.

### New features

- `mbedtls_ssl_get_fatal_alert()` — new public API for retrieving the fatal
  alert type after `MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE`. **DTLS-safe:**
  implementation reads generic context fields (`in_fatal_alert_recv`,
  `in_fatal_alert_type`) set by the shared alert parsing path in `ssl_msg.c`;
  no epoch or DTLS-specific state involved. No action needed on our side.
- `mbedtls_ssl_get_supported_group_list()` — new public API. No impact.

### API / type changes

- `mbedtls_timing_get_timer()` return type changed from `unsigned long` to
  `unsigned long long`. Our timer comparisons in `ssl_tls.c` should be fine
  (widening), but verify during build.

---

## Conflict Status

### `library/ssl_client.c` — RESOLVED

Conflict was our PSK checksum logic wrapping `write_handshake_msg_ext` vs.
upstream's simpler call. Kept our version. The `dtls13_psk_checksum_done`
variable is declared inside `#if defined(MBEDTLS_SSL_PROTO_DTLS) && ...` and
the usage at line ~1005 is inside the same DTLS transport branch at runtime, so
TLS-only builds are not affected — but the preprocessor guards are not
identical (usage guard omits `MBEDTLS_SSL_PROTO_DTLS`). A TLS 1.3 PSK +
no-DTLS build would get a compile error on the undeclared variable. **Action:**
widen the variable's declaration guard to `#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)` and add a
`#if defined(MBEDTLS_SSL_PROTO_DTLS)` runtime guard around the assignment so
non-DTLS builds initialise it to the safe default (1 = always checksum).

### `library/ssl_msg.c` — 2/3 RESOLVED, 1 REMAINING

**Resolved:**
- Conflict 1 (~line 3851): took upstream's fragmented DTLS 1.2 ClientHello
  reassembly block.
- Conflict 2 (~line 6586): took upstream's removal of the
  `MBEDTLS_PUT_UINT16_BE(rec.data_len, ...)` write (upstream restructured the
  code to not write this at all; our guard was rendered moot).

**Remaining (line ~9270):**

Our HEAD:
```c
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
void mbedtls_ssl_dtls_advance_buffering(mbedtls_ssl_context *ssl)
{
    // frees slot 0, shifts remaining slots down by 1
    ssl_buffering_free_slot(ssl, 0);
    for (offset = 0; offset + 1 < MBEDTLS_SSL_MAX_BUFFERED_HS; ...)
        *hs_buf = *(hs_buf + 1);
    memset(hs_buf, 0, ...);
}
#endif
```

Upstream 4.1.0:
```c
static void ssl_buffering_shift_slots(mbedtls_ssl_context *ssl, unsigned shift)
{
    // frees first `shift` slots, shifts rest left by `shift`
}
```

`shift > 1` is used in exactly one place: the fragmented DTLS 1.2 ClientHello
path (line ~3872), where the server may receive a ClientHello with
`message_seq > 0` after multiple retransmission round-trips and needs to skip
ahead by `recv_msg_seq` slots at once. DTLS 1.3 always advances by 1 (no
HelloVerifyRequest round-trips, sequential message consumption), so the
existing callers in `ssl_tls13_generic.c` remain correct.

**Resolution (Option A — recommended):** Take 4.1.0's `ssl_buffering_shift_slots`
as the implementation, and add a thin public wrapper:

```c
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
void mbedtls_ssl_dtls_advance_buffering(mbedtls_ssl_context *ssl)
{
    ssl_buffering_shift_slots(ssl, 1);
}
#endif
```

This avoids touching callers in `ssl_tls13_generic.c` and preserves the
declared symbol in `ssl_misc.h`.

### `tests/suites/test_suite_ssl.function` — NOT RESOLVED

Our HEAD adds (after line 6147): DTLS 1.3 unit tests —
`ssl_dtls13_sne_key_derivation`, `ssl_dtls13_sne_mask_aes`,
`ssl_dtls13_sne_mask_chacha20`, `dtls13_handshake`, `dtls13_post_hs_idle_timeout`.

Upstream adds: `ssl_get_alert_after_fatal`, `verify_result_without_handshake`,
`tls13_hrr_then_tls12_second_client_hello`.

**Resolution:** Keep both — our DTLS 1.3 tests first, then the three upstream
tests appended. No functional overlap.

**Follow-on (post-merge, tracked separately):** Add a DTLS 1.3 analogue of
`tls13_hrr_then_tls12_second_client_hello` to the DTLS integration test suite
(`tests/dtls13/cases/`). The upstream test exercises the HRR→TLS 1.2 downgrade
attack in TLS stream mode; a DTLS 1.3 variant would verify the same protection
holds for the DTLS HRR path.

### `tests/suites/test_suite_ssl.data` — NOT RESOLVED

Our HEAD adds: test data entries for the DTLS 1.3 SNE tests, handshake, and
timeout test.

Upstream adds: data entries for `ssl_get_alert_after_fatal`,
`verify_result_without_handshake`, `tls13_hrr_then_tls12_second_client_hello`,
and 4 `send_invalid_sig_alg` entries.

**Resolution:** Keep both — our entries first, then upstream entries appended.

---

## Post-Conflict Steps

1. Resolve `ssl_msg.c` conflict 3 (Option A wrapper).
2. Resolve `test_suite_ssl.function` conflict (concatenate both sides).
3. Resolve `test_suite_ssl.data` conflict (concatenate both sides).
4. Fix `ssl_client.c` PSK checksum guard mismatch (see ssl_client.c section).
5. Verify `ssl_misc.h` still declares `mbedtls_ssl_dtls_advance_buffering` (no
   change needed under Option A).
6. Build with DTLS 1.3 enabled (standard config). Watch for:
   - `unsigned long long` vs `unsigned long` timer comparison warnings.
   - Any new symbols from 4.1.0 conflicting with our additions.
7. Build with DTLS 1.3 disabled (verify non-DTLS builds are not broken,
   especially the PSK checksum guard fix).
8. Run unit tests: `tests/suites/test_suite_ssl` — confirm our DTLS 1.3 tests
   pass alongside the new upstream tests.
9. Run DTLS 1.3 integration tests per standard invocation (see memory:
   `reference_test_invocation.md`).
10. Commit the merge.

---

## Risk Assessment

| Area | Risk | Notes |
|------|------|-------|
| `ssl_buffering_shift_slots` refactor | Low | Thin wrapper; zero churn in callers |
| HRR security fix applicability to DTLS 1.3 | Low | DTLS HRR path is separate; targeted review + follow-on integration test needed |
| PSK checksum guard mismatch in ssl_client.c | Medium | Would be a compile error in TLS 1.3 PSK + no-DTLS builds; fix is straightforward |
| Test file merges | Low | Purely additive, no overlap |
| `timing.c` return type widening | Low | `unsigned long long` ≥ `unsigned long`; narrowing casts would be the risk |
| CVE-2026-25834 DTLS 1.2 coverage | None | Shared code path confirmed; fix covers both transports automatically |
| New `ssl_get_fatal_alert()` API | None | DTLS-safe; additive; we do not call it |
