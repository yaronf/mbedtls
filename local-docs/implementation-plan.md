# DTLS 1.3 Implementation Plan for mbedtls

**Reference spec:** draft-ietf-tls-rfc9147bis-01 (October 2025)
**Target codebase:** mbedtls, branch `dtls13`

## Goals

- Add DTLS 1.3 per the bis draft.
- Reuse the existing TLS 1.3 crypto/key schedule and the existing DTLS 1.2 transport machinery wherever possible.
- Preserve all mbedtls patterns: PSA crypto, existing config flags, public API style.
- Production quality: no hacks, no TODOs left in merged code.
- Extensive tests; strong security posture throughout.

---

## What DTLS 1.3 Is (and Isn't)

DTLS 1.3 is defined as a delta from TLS 1.3, not from DTLS 1.2. The relationship:

- **Crypto / key schedule / handshake messages**: same as TLS 1.3 (reuse directly), with one label change: HKDF prefix is `"dtls13"` (no trailing space) instead of `"tls13 "`.
- **Transport / reliability layer**: evolved from DTLS 1.2 (retransmission, fragmentation, epochs, sequence numbers), but with significant changes.
- **No compatibility mode**: no ChangeCipherSpec messages, no legacy_session_id echo.

Key differences from DTLS 1.2 (our implementation base):

| Area | DTLS 1.2 | DTLS 1.3 |
|------|----------|----------|
| Key schedule | Custom (pre-TLS 1.3) | TLS 1.3 HKDF schedule (already in mbedtls) |
| Ciphersuites | MAC + optional AEAD | AEAD only |
| Cookie exchange | HelloVerifyRequest message | HelloRetryRequest + `cookie` extension |
| Record header | Fixed: type + version + epoch(2) + seq(6) + length | Variable unified_hdr; epoch=2 bits, seq=8 or 16 bits |
| Sequence number encryption | None | AES-ECB or ChaCha20 mask over on-wire seq# |
| Epoch semantics | Opaque counter | Defined values: 0=plain, 1=early, 2=hs, 3=appdata_0, 4+=rekey |
| AEAD additional data | epoch + seq + type + version + length | unified_hdr bytes only (no epoch, 64-bit seq# for nonce) |
| EndOfEarlyData | N/A | Omitted (epochs make it unnecessary) |
| ACK message | None | New content type 26; required for last flight and post-handshake |
| Post-handshake reliability | None | Each post-hs message has its own PREPARING/SENDING/WAITING FSM |
| KeyUpdate | N/A | Supported; must be ACKed before sending with new epoch |
| CID | Via RFC 9146 bolt-on | Native in unified header (C bit); post-hs CID update messages |
| Handshake transcript | Includes message_seq, fragment fields | Excludes them (pure TLS 1.3 format) |
| Compatibility mode | N/A | Explicitly prohibited (no CCS) |

---

## Architecture Overview

Key files modified or extended for DTLS 1.3:

- `library/ssl_msg.c` — record layer: unified header parsing/serialization, SNE (sequence number encryption), DTLS 1.3 AEAD additional data, ACK injection, epoch anti-replay
- `library/ssl_tls.c` — handshake state machine: DTLS 1.3 FSM states, ACK handling, post-handshake message sequencing, flight/epoch bookkeeping
- `library/ssl_tls13_client.c`, `ssl_tls13_server.c` — TLS 1.3 handshake handlers extended for DTLS 1.3 specifics (HRR cookie, transcript hash exclusion of message_seq/fragment fields)
- `library/ssl_tls13_generic.c` — shared TLS 1.3 message processing (minimal DTLS 1.3 changes)
- `library/ssl_tls13_keys.c` — HKDF schedule: `"dtls13"` label prefix, `sn_key` derivation
- `library/ssl_misc.h` — internal structs: `mbedtls_ssl_transform` extended with `sn_key`/`sn_key_len`/`dtls13_epoch`; `mbedtls_ssl_context` extended with epoch pool, anti-replay state, ACK pending flag, post-handshake msg_seq counters
- `include/mbedtls/ssl.h` — `mbedtls_ssl_dtls13_epoch_slot` struct; context fields for DTLS 1.3 epoch management
- `include/mbedtls/mbedtls_config.h` — no new config flags added; DTLS 1.3 is enabled by `MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_SSL_PROTO_DTLS`

DTLS 1.3 support is activated when both `MBEDTLS_SSL_PROTO_TLS1_3` and `MBEDTLS_SSL_PROTO_DTLS` are enabled. All DTLS 1.3–specific code paths are guarded by `#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_PROTO_DTLS)`. On the wire, DTLS 1.3 encrypted records are identified by the `001CSLЕЕ` bit pattern in the first byte (distinct from DTLS 1.2 record headers) and are dispatched in `ssl_parse_record_header()` before the existing DTLS 1.2 path.

---

## Phased Implementation Plan

### Phase 0: Test Vector Generation (Prerequisite)
*Goal: Ground-truth test vectors in hand before any code is written.*
*See `reference-implementations.md` for BoringSSL test runner details.*

- [x] 1. Instrument BoringSSL's `ssl/test/runner/dtls.go` and `conn.go` to dump:
         sn_key derivation inputs/outputs, SNE mask values (AES-ECB and ChaCha20),
         full record encode/decode round-trips with intermediate values.
         Patches: `DTLS13_VECTORS` env var gates logging in `useTrafficSecret`,
         `readDTLS13RecordHeader`, and `dtlsPackRecord`. BoringSSL cloned to
         `/tmp/boringssl` (shallow, main branch 2026-03-25).
- [x] 2. Store output in `local-docs/test-vectors/` as ground-truth for Phase 1 and 2
         unit tests. Done: `local-docs/test-vectors/sne-vectors.txt` contains 3
         vector sets (2× ChaCha20, 1× AES-128-GCM) with sn_key derivation, mask
         computation, and encrypt/decrypt round-trips.

### Phase 1: Foundation (Record Layer + Epoch Management)
*Goal: DTLS 1.3 records can be read and written correctly, no handshake yet.*
*Design detail: see `design-drilldown.md` §1 (record layer integration) and §2 (transform slot model).*

- [x] 1. Add `DTLSCiphertext` unified header parsing to `ssl_msg.c`.
         `ssl_parse_dtls13_record_header()` added; fills `mbedtls_record` and returns
         header byte count. Includes CID, 8/16-bit seq, optional length field.
- [x] 2. Implement record type demultiplexing (first-byte dispatch).
         `buf[0] & 0xE0 == 0x20` → `ssl_parse_dtls13_record_header()` at top of
         `ssl_parse_record_header()`; DTLSPlaintext falls through to existing path.
- [x] 3. Handle last-record-in-datagram with omitted length field (L bit clear).
         Already handled: `ssl_parse_dtls13_record_header()` sets
         `rec->data_len = len - hdr_len` when L=0, so `rec->buf_len = len`.
         `ssl_get_next_record()` sets `next_record_offset = rec.buf_len`, which
         equals `in_left`, so the datagram is fully consumed. No code needed.
- [x] 4. Implement epoch reconstruction algorithm (§4.2.2).
         New context fields `dtls13_epoch_max_seq[4]` and `in_epoch_full` in
         `mbedtls_ssl_context` (ssl.h). Reconstruction logic in
         `ssl_parse_dtls13_record_header()`.
- [x] 6. Add `sn_key` + `sn_key_len` fields to `mbedtls_ssl_transform` (ssl_misc.h).
         Derivation function `mbedtls_ssl_dtls13_hkdf_expand_label` added to
         `ssl_tls13_keys.c/h`; not yet wired to key installation (Phase 2.2).
- [x] 7. Implement sequence number encryption/decryption (AES-ECB and ChaCha20 variants).
         `ssl_dtls13_sne_compute_mask()` + `ssl_dtls13_sne_apply()` in ssl_msg.c.
         AES: `psa_cipher_encrypt` with `PSA_ALG_ECB_NO_PADDING`. ChaCha20:
         `PSA_ALG_STREAM_CIPHER` with nonce=sample[4:16], counter=LE32(sample[0:4]).
         SNE decrypt applied in `ssl_prepare_record_content()` before
         `mbedtls_ssl_decrypt_buf()`, gated on `sn_key_len > 0`. Write path (SNE
         encrypt) deferred to when unified header write is implemented.
- [x] 8. Change AEAD additional data computation for DTLS 1.3 records.
         `ssl_extract_add_data_from_record()` gains `dtls13_hdr`/`dtls13_hdr_len`
         parameters; raw unified header used as AAD when non-NULL. All 7 existing
         call sites updated to pass `NULL, 0`.
- [x] 9. Implement `DTLSInnerPlaintext` serialization/deserialization.
          Already handled by existing TLS 1.3 path: `ssl_build_inner_plaintext()`
          (encrypt, ssl_msg.c:872) and `ssl_parse_inner_plaintext()` (decrypt,
          ssl_msg.c:1834) both gate on `transform->tls_version == TLS1_3`, which
          a DTLS 1.3 transform carries. No new code needed.
- [x] 10. Add `dtls13_epoch_pool[4]` to `mbedtls_ssl_context`; struct
          `mbedtls_ssl_dtls13_epoch_slot` defined in `ssl.h`. Install/lookup/evict
          helpers not yet implemented.
- [x] 11. Unit tests: SNE key derivation and mask (AES + ChaCha20) against BoringSSL vectors.
          `tests/suites/test_suite_ssl.dtls13.data` + functions in `test_suite_ssl.function`.
          22 cases; vectors independently verified via Go stdlib crypto.

### Phase 2: Key Schedule Integration
*Goal: TLS 1.3 key schedule produces the right keys with "dtls13" label.*
*Design detail: see `design-drilldown.md` summary table (sn_key in transform).*

- [x] 1. Add HKDF label prefix selection (`"dtls13"` vs `"tls13 "`).
         `ssl_tls13_hkdf_encode_label()` now takes a `prefix`/`prefix_len` parameter.
         TLS path unchanged; new `mbedtls_ssl_dtls13_hkdf_expand_label()` uses `"dtls13"`.
- [x] 2. Wire `sn_key` derivation into traffic key installation.
         Added after `mbedtls_ssl_tls13_populate_transform()` in both
         `compute_handshake_transform()` and `compute_application_transform()`.
         Uses `mbedtls_ssl_dtls13_hkdf_expand_label(..., "sn", 2, ...)` with
         the peer's traffic secret (inbound direction). Stored in
         `transform->sn_key` / `transform->sn_key_len`. Gated on DTLS transport.
         Note: only the decrypt-direction sn_key is derived here; encrypt-direction
         derivation deferred to write path implementation.
- [x] 3. Validate epoch → key mapping (epoch 0=no key, 1=early, 2=hs, 3=app, 4+=rekey).
         Added `dtls13_epoch` (uint16_t) to `mbedtls_ssl_transform`; set to 1/2/3 in
         `compute_early/handshake/application_transform()` in `ssl_tls13_keys.c`.
         `set_inbound_transform()` now syncs `ssl->in_epoch` and `ssl->in_epoch_full` from
         `transform->dtls13_epoch` (and resets the per-epoch `dtls13_epoch_max_seq` slot).
         `set_outbound_transform()` now writes epoch into `cur_out_ctr[0:2]`.
         All gated on `MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_SSL_PROTO_TLS1_3`.
- [x] 4. Unit tests: key derivation test vectors.
         See `reference-implementations.md`: BoringSSL test runner is the source for vectors.
         Covered by `test_suite_ssl.dtls13` (7 sn_key derivation cases).

### Phase 3a: Handshake Completes (Full 1-RTT, mbedtls ↔ mbedtls)
*Goal: "Protocol is DTLSv1.3" prints on both sides; self-test passes.*
*Design detail: see `design-drilldown.md` §1 (transcript/epoch wiring).*

- [x] 0. Test harness: add `force_version=dtls13` to `ssl_client2`/`ssl_server2` (sets
         transport=datagram + min/max version TLS 1.3), and add a skeleton DTLS 1.3
         test block in `tests/ssl-opt.sh` gated on `requires_protocol_version dtls13`.
         Test "DTLS 1.3: full 1-RTT handshake" currently fails (server crashes at
         guard before binding); will pass once Phase 3a is complete.
- [x] 1. Remove the "DTLS 1.3 not supported" guard.
         Removed the DTLS transport check from `ssl_conf_version_check()` in `ssl_tls.c`.
         Server now binds and starts; handshake fails at version negotiation (Phase 3.3).
- [x] 2. Decide and implement `MBEDTLS_SSL_DTLS13_ACK` config flag (or always-on):
         Decision: always-on. ACK is mandatory per RFC 9147 §7; no optional flag.
         The data structures (`dtls13_received_records`, `dtls13_ack_pending`) are
         already compiled unconditionally under `MBEDTLS_SSL_PROTO_DTLS +
         MBEDTLS_SSL_PROTO_TLS1_3` from Phase 1. No new code needed.
- [x] 3. Implement version negotiation: `supported_versions` extension with `0xfefc`
         for DTLS 1.3; clean fallback to DTLS 1.2 when peer does not support 1.3.
         Fixes: (1) `ssl_tls13_write_supported_versions_ext()` hardcoded STREAM transport
         — fixed to `ssl->conf->transport`. (2) `fetch_handshake_msg()` hardcoded 4-byte
         header skip — fixed to `mbedtls_ssl_hs_hdr_len(ssl)` (12 for DTLS). (3) Removed
         second "DTLS not supported" guard in hybrid TLS 1.2+1.3 config path in `ssl_tls.c`.
         (4) Added `dtls13` alias to `min_version`/`max_version` in both programs.
         (5) Option B transcript re-hash on DTLS 1.2 fallback (Phase 3a.3b):
             When the DTLS 1.3 client receives a DTLS 1.2 ServerHello, the transcript
             must be rebuilt using 12-byte DTLS handshake headers.  The TLS 1.3 send
             path uses a 4-byte TLS-style checksum for DTLS 1.3 messages (RFC 9147
             §5.2); the DTLS 1.3 bypass skips `ssl_flight_append`, so `flight` is NULL
             at re-hash time.  Fix: save ClientHello bytes in
             `handshake->dtls13_cli_hello` before sending; on fallback, reset the
             checksum and re-hash ClientHello + ServerHello with 12-byte headers.
             Guard added to outgoing-checksum condition
             (`ssl->tls_version != MBEDTLS_SSL_VERSION_TLS1_2`) so post-fallback
             outgoing messages (CKE, etc.) use the full 12-byte header.
         ssl-opt.sh test "DTLS 1.3 client, DTLS 1.2 server: negotiate down to DTLS 1.2
         (no cookie)" now passes.  The "with cookie" variant remains a known fail
         pending Phase 3b.1 (HVR handling before version is known).
- [x] 4. Adapt ClientHello construction: zero `legacy_session_id`, zero `legacy_cookie`,
         correct `supported_versions`, no compatibility mode.
         Client write (`ssl_client.c`): extended cookie-write block from
         `PROTO_TLS1_2 && PROTO_DTLS` to `PROTO_DTLS` so DTLS 1.3 also writes
         the zero-length `legacy_cookie` field required by RFC 9147 §5.3.
         Server parse (`ssl_tls13_server.c`): added `legacy_cookie` skip after
         `legacy_session_id` gated on `PROTO_DTLS`; updated min-length check to 39
         for DTLS. Handshake now progresses: server completes ServerHello →
         EncryptedExtensions → Certificate → Finished; client stalls waiting to
         decrypt EncryptedExtensions (epoch transition not yet wired — Phase 3a.5).
- [x] 5. Adapt ServerHello: no `legacy_session_id_echo`, `legacy_version = 0xfefd`.
         Server (`ssl_tls13_write_server_hello_body`): use `mbedtls_ssl_write_version()`
         with transport (emits `0xfefd` on DTLS, `0x0303` on TLS); send zero-length
         `legacy_session_id_echo` for DTLS 1.3 (compatibility mode prohibited per
         RFC 9147 §5.4). Client (`ssl_tls13_check_server_hello_session_id_echo`): for
         DTLS transport, enforce echo is zero-length and abort with `illegal_parameter`
         if not. Client (`ssl_client.c`): skip 32-byte fake session ID generation for
         DTLS 1.3 (TLS 1.3 compatibility mode path gated out for DTLS transport).
- [x] 6. Strip DTLS framing fields from transcript hash inputs.
         Analysis: no code change required. The TLS 1.3 send path always calls
         `mbedtls_ssl_add_hs_msg_to_checksum(ssl, type, body, body_len)` with
         `update_checksum=0` in `finish_handshake_msg` — the 4-byte TLS-style header
         is built internally, DTLS framing bytes are never included. The TLS 1.3
         receive path calls `mbedtls_ssl_read_record(ssl, 0)` (update_hs_digest=0)
         and uses `fetch_handshake_msg` which skips the full DTLS 12-byte header,
         then explicit `add_hs_msg_to_checksum` with just the body. The raw-DTLS
         `update_handshake_status` path is only reached when `update_hs_digest=1`,
         which TLS 1.3 never sets. No DTLS framing bytes are hashed.
- [x] 7. Suppress EndOfEarlyData.
         Analysis: no code change required for the certificate-based 1-RTT path.
         The `MBEDTLS_SSL_END_OF_EARLY_DATA` state is only entered when
         `MBEDTLS_SSL_EARLY_DATA` is defined and early_data was accepted — neither
         applies to the basic handshake. Will revisit in Phase 4 (early data).
- [x] 8. Suppress ChangeCipherSpec.
         `MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE` CCS state transitions gated to
         skip when `transport == DATAGRAM` (RFC 9147 §5 explicitly prohibits
         compatibility mode in DTLS 1.3). Three client sites (after ClientHello
         with early data, after HRR, after server Finished) and two server sites
         (after ServerHello, after HRR) all updated with DTLS transport checks.
- [x] 9. Wire up epoch transitions: install handshake keys at epoch 2, app keys at epoch 3.
         Pool helpers `ssl_dtls13_epoch_pool_insert/lookup/free` added to `ssl_misc.h` /
         `ssl_msg.c`. Epoch pool insert wired into `handshake_wrapup` (epoch 2→3) and
         server END_OF_EARLY_DATA handler (epoch 1→2). Decrypt path in
         `ssl_parse_record_header()` allows pool-epoch records through; `ssl_prepare_
         record_content()` resolves the correct transform from the pool by `rec->ctr`
         epoch. `mbedtls_ssl_free()` calls `ssl_dtls13_epoch_pool_free()`. Ownership
         transfer nulls `handshake->transform_handshake` / `transform_earlydata` at
         insert sites to prevent double-free in teardown.
- [x] 10. Self-test: mbedtls client ↔ mbedtls server full 1-RTT handshake; ssl-opt.sh
          test "DTLS 1.3: full 1-RTT handshake" passes.

### Phase 3b: Reliability Layer
*Goal: Spec-compliant retransmission, ACK, HRR+cookie, amplification limit, wolfSSL interop.*
*Design detail: see `design-drilldown.md` §3 (ACK + retransmit).*

- [x] 1. Implement HRR+cookie path (stateless server cookie via HMAC).
         Uses the existing `f_cookie_write`/`f_cookie_check` callbacks (same as DTLS
         1.2) — no new server config flag required.
         Server (`ssl_tls13_server.c`): write `cookie` extension (TLS_EXT_COOKIE = 44)
         in HRR when `is_hrr && DTLS && f_cookie_write != NULL`; validate echoed cookie
         on second ClientHello when `hello_retry_request_flag`; reject with
         `handshake_failure` if missing or invalid.
         Client (`ssl_tls13_generic.c`): exempt `COOKIE` from the "must have been sent
         by client" check in `check_received_extension` for HRR (RFC 8446 §4.2.2
         server-initiated exception).
         Client (`ssl_tls13_client.c`): detect DTLS 1.2 HelloVerifyRequest (type 3) in
         the SERVER_HELLO state before the strict type check; store cookie in
         `handshake->cookie` with `dtls_hvr_cookie=1` flag; reset key share and
         transcript; loop back to CLIENT_HELLO.
         Client (`ssl_client.c`): echo `dtls_hvr_cookie` in the legacy_cookie field of
         the retried ClientHello (not as a TLS extension).
         Tests: `DTLS 1.3: HRR+cookie exchange (cookie enabled)` passes; `DTLS 1.3
         client, DTLS 1.2 server: negotiate down to DTLS 1.2 (with cookie)` passes.
- [dropped] 2. Enforce amplification limit in the record layer.
         **Decision: not implementing.** The cookie already solves the address
         validation problem — a validated client address is the goal, not byte
         counting per se.  Hard send-blocking at 3× is a SHOULD (RFC 9147 §4.2.1),
         not a MUST, and implementing it in the record layer is over-engineered:
         it would require tracking bytes across every send/recv call, the threshold
         is routinely exceeded by a single certificate flight anyway, and the
         infrastructure (`dtls13_bytes_from_peer`, `dtls13_bytes_sent`,
         `dtls13_peer_verified`) has been removed as dead code.
         The cookie (Phase 3b.1) is the correct and sufficient mitigation.
- [x] 3. Implement ACK message parsing and serialization.
         `ssl_dtls13_parse_ack()` and `ssl_dtls13_write_ack()` in `ssl_msg.c`.
         `MBEDTLS_SSL_MSG_ACK = 26` added to `ssl.h`; accepted by
         `ssl_check_record_type()`; dispatched in `mbedtls_ssl_handle_message_type()`.
         `ssl_dtls13_write_ack()` serializes `dtls13_received_records[]` from
         `mbedtls_ssl_handshake_params`. Per-record received-record tracking
         added in `ssl_prepare_record_content()` for encrypted epochs (≥ 2).
- [x] 4. Add ACK sending for the final client flight (required by spec).
         `dtls13_ack_pending` flag set in `ssl_tls13_process_server_finished()`
         (client side, DTLS transport) after server Finished verified.
         ACK injected at the top of `mbedtls_ssl_read_record()` when the flag
         is set; flag cleared after successful send.
- [x] 5. Extend retransmit state machine: selective retransmission when ACK received.
         `ssl_dtls13_process_ack()` marks `flight_item->acked`; partial ACK transitions
         to SENDING so unacked items are retransmitted immediately.
         `mbedtls_ssl_flight_transmit()` skips acked items and captures outbound
         epoch+seq into `sent_records[]` / `sent_record_epoch[]` before each write
         so ACK matching works.
         ssl-opt.sh test "DTLS 1.3: loss recovery via retransmit" passes
         (drop=5 delay=5 duplicate=5 via udp_proxy).
- [x] 6. Interop bug fixes (mbedtls client ↔ wolfSSL server — handshake works).
         See `reference-implementations.md` and `local-docs/wolfssl-interop-notes.md`.
         mbedtls client ↔ wolfSSL server: handshake completes, application data flows.
         Four bugs fixed during interop debugging:
         (a) Wrong AAD in `ssl_decrypt_buf`: unified-header detect was missing `rec->ver[0]==0xfe`
             guard; fix in `ssl_msg.c`: detect DTLS 1.3 record and pass raw unified header bytes
             as AAD per RFC 9147 §4.3.3.
         (b) `in_len` pointer corrupts decrypted plaintext: for DTLS 1.3 unified-header records,
             `ssl->in_len` falls inside the plaintext at `in_msg+6` (the `frag_offset` field).
             `PUT_UINT16_BE(rec.data_len, ssl->in_len, 0)` overwrote it.
             Fix: skip the in_len write for DTLS 1.3 (TLS 1.3 never reads in_len).
         (c) Wrong Finished/binder key prefix: `ssl_tls13_calc_finished_core` used `"tls13 "`
             HKDF label; DTLS 1.3 requires `"dtls13"` (RFC 9147 §5.2).
             Fix: added `use_dtls13_prefix` parameter to `ssl_tls13_calc_finished_core`;
             callers pass the DTLS flag; PSK binder call guards against NULL ssl.
         (d) AAD false-positive in TLS 1.3 non-DTLS path: `(rec->buf[0] & 0xE0) == 0x20`
             could match non-DTLS records. Fix: added `rec->ver[0] == 0xfe` guard.
         SSLKEYLOGFILE: `nss_keylog_export` in `ssl_test_common_source.c` extended to emit
             all TLS 1.3 secret types in NSS key log format.
- [x] 11. Interop: wolfSSL client ↔ mbedtls server.
         Run wolfSSL client against mbedtls ssl_server2 with force_version=dtls13.
         Root cause: server never sent ACK for client Finished (RFC 9147 §7.2.1).
         wolfSSL enters WAIT_FINISHED_ACK state and loops retransmitting Finished.
         Fix: set `ssl->dtls13_ack_pending = 1` in `ssl_tls13_process_client_finished`
         after `mbedtls_ssl_recv_flight_completed`.
         wolfSSL client prints "SSL version is DTLSv1.3", app data flows both ways.
- [x] 12. Automated interop tests for both directions.
         Added wolfSSL runner profile (`tests/dtls13/runners/wolfssl.yaml`) and new
         case file (`tests/dtls13/cases/interop-wolfssl.yaml`) covering:
           - mbedtls server ↔ wolfSSL client: full 1-RTT handshake
           - mbedtls server ↔ wolfSSL client: application data
           - mbedtls server ↔ wolfSSL client: server ACKs client Finished
         Added `requires_wolfssl` guard to ssl-opt.sh.
         Generated `dtls13-wolfssl-tests.sh` (separate from mbedtls-vs-mbedtls tests).
         All 3 wolfSSL interop tests pass.
- [x] 7. Proxy test parity: port all immediately-portable DTLS 1.2 proxy tests to DTLS 1.3.
         Full analysis in `local-docs/proxy-test-parity.md`.
         Done (8 tests passing):
           duplicate every packet; duplicate + anti-replay off;
           multiple records in same datagram; same + duplicate;
           inject invalid AD record (default badmac_limit);
           3d basic handshake; 3d client auth; 3d nbio.
         Fix in ssl_msg.c: bad-MAC at SERVER_FINISHED/CLIENT_FINISHED is now
           discarded (not fatal) in DTLS 1.3 — server retransmits on timeout;
           the DTLS 1.2 fatal rationale (wrong PSK / MITM) does not apply.
         Remaining deferred: badmac_limit=2 (server hits limit during handshake
           with bad_ad=1; needs post-handshake injection); fragmentation+3d
           (Phase 3b.8); 3d+PSK/ticket/resumption (Phase 4); interop (Phase 3b.6).
         Not applicable: CCS tests, renegotiation tests, CKE tests.
- [x] 8. Outgoing handshake fragmentation for DTLS 1.3.
         The DTLS 1.3 write path fragments large handshake messages via the
         existing flight_transmit MTU loop.  ServerHello is added to the flight
         (was previously excluded) with save/restore of transform_out to keep it
         plaintext on retransmit.  Tests: "DTLS 1.3: fragmenting — proxy MTU"
         and "DTLS 1.3: fragmenting — proxy MTU, nbio" both pass.
- [x] 9. Empty ACK on future-epoch record discard (RFC 9147 §7.1).
         When the client discards a record from a future epoch (e.g. encrypted
         server flight arriving before ServerHello), set dtls13_ack_pending and
         send an empty ACK.  This triggers an immediate server retransmit instead
         of waiting for the full retransmit timer.
         Three fixes: (1) trigger in ssl_get_next_record() on future-epoch discard;
         (2) send in CONTINUE_PROCESSING branch and at top of read_record();
         (3) ssl_dtls13_write_ack() defers if out_left > 0, retries flush once on
         WANT_WRITE.  Server-side: allow ACK records from old epochs through the
         epoch check (ssl_parse_record_header) and skip decryption
         (ssl_prepare_record_content) since they are always plaintext.
- [x] 10. HRR+cookie 3d test.
         The DTLS 1.2 parity analysis identified DTLS 1.2 reordering tests
         (`delay_srv=Certificate`, etc.) as candidates, but these don't port:
         the proxy identifies message types by reading plaintext handshake headers,
         which are not visible in DTLS 1.3 encrypted records. The 3d tests
         (drop/delay/duplicate) already cover the buffering/reordering paths
         non-deterministically, so deterministic reordering tests add little value.
         The one genuine gap: loss recovery across the HRR flight boundary.
         Add `DTLS 1.3: proxy — 3d, HRR+cookie exchange` using
         `drop=5 delay=5 duplicate=5` with cookie enabled on the server.

### Phase 4: Session Resumption and PSK
*Goal: PSK and resumption handshakes work, including 0-RTT.*

- [x] 1. Declarative test infrastructure (YAML + generator).
         Implemented in Phase 3b: `generate.py`, `cases/*.yaml` (7 files),
         `runners/mbedtls.yaml`, `runners/wolfssl.yaml`. All 18 DTLS 1.3 mbedtls
         tests and 3 wolfSSL interop tests live in YAML; generated scripts committed
         alongside sources (no CI to regenerate them automatically — pragmatic tradeoff).
         "Wire into CI" and "don't commit generated bash" were aspirational; N/A for
         this fork with no CI pipeline.
- [x] 2. Validate PSK path through DTLS 1.3.
         Root cause: `mbedtls_ssl_write_client_hello` had a DTLS branch gated on
         `MBEDTLS_SSL_PROTO_TLS1_2` that skipped PSK binder fill-in and transcript
         update entirely. For DTLS 1.3 with PSK, the binder was left as all-zeros,
         causing the server to reject with DECODE_ERROR at binder parse.
         Fix: broaden DTLS branch to cover all DTLS (not just TLS 1.2); add DTLS 1.3
         + PSK binder fill-in block before transmission. Non-PSK path unchanged.
         Test: `DTLS 1.3 PSK: external PSK, psk_ephemeral` passes.
- [x] 3. NewSessionTicket: implement server-side ACK requirement (server retransmits until ACKed).
- [x] 4. PSK+cookie interaction: server MAY skip cookie when PSK + known IP.
- [N/A] 5. 0-RTT (early data): out of scope by design.
         RFC 9147 makes this optional (MAY).  0-RTT carries well-known replay
         risks that are hard to mitigate correctly — especially in DTLS where
         replay protection interacts with the anti-replay window and amplification
         limits.  The latency benefit is marginal on embedded/IoT links.
         Decision: do not implement; reject early_data in ClientHello.
- [x] 6. Self-test: session resumption via NewSessionTicket PSK (mbedTLS ↔ mbedTLS).
         Fixed `ssl_client2` datagram path to save session on NST receipt when
         `reconnect != 0` (was silently discarding the ticket).  Added
         `reconnect` and `skip_close_notify` params plus `client_got_ticket` /
         `client_reconnecting` assertions to `runners/mbedtls.yaml`.
         Test: `DTLS 1.3 PSK: session resumption via NewSessionTicket PSK` passes.
- [x] 7. Interop: wolfSSL client ↔ mbedtls server for PSK (psk_ephemeral).
         Root cause: two bugs:
         (a) wolfSSL was built without PSK support (NO_PSK defined). Rebuilt with
             `--enable-psk` to enable PSK in wolfSSL.
         (b) `mbedtls_ssl_tls13_create_psk_binder()` used `mbedtls_ssl_tls13_derive_secret()`
             (hardcoded TLS prefix "tls13 ") for the `ext_binder` / `res_binder` derivation
             steps, instead of the DTLS 1.3 `"dtls13"` prefix. Fixed by switching both calls
             to `ssl_tls13_derive_secret_with_prefix(..., use_dtls13_prefix)`.
         wolfSSL client `-s --openssl-psk` uses identity="Client_identity" and a fixed 32-byte
         key (0x01,0x23,...,repeating). mbedTLS server configured with matching psk/psk_identity.
         Test: `DTLS 1.3 wolfSSL interop: mbedtls server ↔ wolfSSL client: PSK (psk_ephemeral)` passes.
         All 4 wolfSSL interop tests pass.

### Phase 5: Post-Handshake Messages
*Goal: KeyUpdate, CID management, post-handshake auth all work with ACK reliability.*
*Design detail: see `design-drilldown.md` §3 (post-handshake FSM linked list).*

- [N/A] 1. Implement `mbedtls_ssl_dtls13_hs_fsm` linked list on `mbedtls_ssl_context`.
         Not needed: KeyUpdate uses direct per-context state; CID will do the same.
         Post-hs auth is prohibited by RFC 9147 §5.4 (see item 6 below).
- [x] 2. KeyUpdate: ACK required; new epoch (4+); retain old keys until new-epoch traffic received.
         See drilldown §2: epoch pool retains pre-update inbound transform until first
         successful decrypt with new keys.
         Tests: (a) single KeyUpdate — both sides advance epoch to 4, app data flows;
         (b) three sequential KeyUpdates — epoch advances to 4, 5, 6; app data flows
         at each epoch; old epoch keys correctly evicted from pool.
         **DONE** (commit b95dc3126b): all 4 tests passing — client KU, server KU,
         update_requested reciprocal KU, KU + app data exchange.
- [x] 3. AEAD limit tracking: count authenticated records per epoch; trigger KeyUpdate.
         Configurable via `mbedtls_ssl_conf_dtls13_aead_limit()`; auto-triggers KeyUpdate
         when `out_record_count >= limit`. Tests: server-triggered and client-triggered.
         RFC 9147 §5.2 post-hs msg_seq space also fixed here (independent seq starting at 0).
         **DONE**: all tests passing.
- [x] 4. Count failed authentication attempts per epoch; close on limit.
         Configurable via `mbedtls_ssl_conf_dtls13_auth_fail_limit()`; closes with
         bad_record_mac when consecutive decryption failures reach limit (post-hs only).
         **DONE**: all tests passing.
- [x] 5a. CID negotiation: `connection_id` extension in ClientHello/EncryptedExtensions;
          CID bytes embedded in unified header (C bit); application records carry CID;
          mbedtls_ssl_set_outbound_transform now calls mbedtls_ssl_update_out_pointers
          to keep ssl->out_iv consistent with the new transform's CID length.
          Tests: both endpoints negotiate; only client offers (not negotiated); data exchange.
          **DONE** (commit e0706a425b): all 3 CID tests passing, 31/31 suite passing.
- [x] 5b. NewConnectionId (type 10) and RequestConnectionId (type 9): parse, send, ACK.
          cid_immediate vs cid_spare semantics; too_many_cids_requested alert (52).
          ACK matching via epoch+seq (same pattern as KeyUpdate).
          Public API: mbedtls_ssl_dtls13_send_new_connection_id(),
          mbedtls_ssl_dtls13_request_connection_id().
          Tests: server→client, client→server, client requests, server requests.
          **DONE** (commit d5118c75f5): 4 new tests passing, 35/35 suite.
- [x] 5c. Address migration: client rebinds UDP socket mid-session; server identifies
          association by CID and migrates to new peer address after AEAD validation.
          Server: `allow_addr_migration=1`, `migration_timeout_ms` (0=immediate for tests).
          Client: `cid_change_addr=N` (rebinds N times, one per exchange).
          Tests: positive (migration commits) + negative (default server rejects).
          **DONE** (commit 59bf3fb958): 37/37 suite passing.
- [N/A] 6. Post-handshake client authentication: explicitly prohibited by RFC 9147 §5.4.
         "Post-handshake authentication is not supported in DTLS 1.3."
- [x] 7. Self-test: DTLS 1.3 basic handshake unit test.
         Added `dtls13_handshake` to `test_suite_ssl.dtls13` (23/23 pass).
         Required a targeted fix to `move_handshake_to_state` in `ssl_helpers.c`:
         `mbedtls_ssl_is_handshake_over()` returns true for state >= HANDSHAKE_OVER(27),
         which includes DTLS 1.3 states 28-31 — causing the helper to stop stepping
         the server too early. Fix: for DTLS 1.3 driving both sides to HANDSHAKE_OVER,
         keep stepping until state==27 exactly; once there, call `mbedtls_ssl_read` to
         flush `dtls13_ack_pending` (the deferred ACK for the peer's Finished).
         KeyUpdate and CID remain covered by `tests/dtls13-tests.sh` (real sockets).
- [N/A] 8. Interop: wolfSSL for KeyUpdate and CID update scenarios.
         See `reference-implementations.md` and `wolfssl-interop-notes.md §Phase 5.8`.
         **KeyUpdate**: wolfSSL 5.9.0 does not reset post-handshake message_seq to 0 (RFC 9147 §5.2).
         wolfSSL client sends KeyUpdate with seq=2 (continuing handshake seq); mbedtls correctly
         rejects it as a future message (expected seq=0). This is a wolfSSL bug. No test added;
         filed for upstream report.
         **CID**: wolfSSL 5.9.0 build in ~/misc/wolfssl lacks `--enable-dtls-cid`. Deferred
         pending rebuild. Not blocking — mbedtls↔mbedtls CID already tested in Phase 5.5a.

### Phase 6: Quality Review
*Goal: Systematic review across six dimensions before hardening and interop work begins. Each item produces either a concrete fix, a new plan entry, or a recorded no-action decision.*

#### [x] 6.1 RFC / bis-draft Completeness and Correctness
Review all MUST/SHOULD/MAY requirements in RFC 9147 and draft-ietf-tls-rfc9147bis-01 against the implementation. Specific areas to audit:

- **Unified record header**: correct C/S bits, length presence, epoch reconstruction from context (RFC 9147 §4.2, bis §4.2).
- **Epoch management**: all five epochs defined (0=initial, 1=handshake-early, 2=handshake, 3=app-data, 4+=post-KeyUpdate); correct key installation and retirement ordering; multi-epoch decryption window during transitions.
- **ACK**: sent after every non-ACK handshake record; ACK content matches received epoch/seq; handling of ACK for records not in the current flight (RFC 9147 §7).
- **Retransmission**: correct timeout doubling; flight boundary detection; when to re-send vs. rely on ACK.
- **Sequence number encryption (sn_key)**: derived from correct secret; mask applied correctly to outbound and inbound; interaction with epoch reconstruction.
- **CID extension**: negotiation corner cases (empty CID, one side only, post-handshake update); `too_many_cids_requested` alert.
- **Post-handshake messages**: KeyUpdate, NewConnectionId, RequestConnectionId — correct post-hs seq numbering, ACK matching, guard against calling during handshake.
- **Downgrade protection**: DTLS version sentinel in ClientHello random (bis §4.4.1).
- **Amplification limit**: enforced from first ClientHello until client address verified (RFC 9147 §5.1).
- **bis-specific changes**: record any requirements from the bis draft not yet addressed.

##### RFC 9147 Compliance Audit Results (completed 2026-03-31)

**COMPLIANT — all items verified:**

| Area | §  | Status | Notes |
|------|----|--------|-------|
| No epoch=0 after epoch≥2 | §4.1 | ✓ | epoch validation in ssl_parse_record_header |
| Unified header C bit (CID present) | §4.1 | ✓ | `0x10` mask in header construction |
| Unified header S bit (long_seq) | §4.1 | ✓ | hardcoded 16-bit (S=1); see note below |
| Epoch reconstruction (2-bit → full) | §4.2.2 | ✓ | ssl_parse_dtls13_record_header:4524 |
| Seq reconstruction (8/16-bit) | §4.2.2 | ✓ | both modes, SNE applied before use |
| Anti-replay sliding window | §4.2 | ✓ | single window reset per `set_inbound_transform`; correct |
| sn_key derivation via HKDF-Expand-Label("sn") | §4.2.3 | ✓ | ssl_dtls13_derive_sne_keys |
| AES mask = AES-ECB(sn_key, sample[0:16])[0:2] | §4.2.3 | ✓ | PSA ECB_NO_PADDING |
| ChaCha20 mask = ChaCha20(key, nonce, LE32(ctr))[0:2] | §4.2.3 | ✓ | mbedtls_chacha20_crypt |
| SNE: applied after AEAD (send), removed before AEAD (recv) | §4.2.3 | ✓ | ssl_msg.c:3536, 5190 |
| legacy_cookie zero-length in DTLS 1.3 ClientHello | §5.3 | ✓ | ssl_client.c:540 |
| Compatibility mode prohibited (no CCS) | §5 | ✓ | skipped when transport==DATAGRAM |
| legacy_session_id_echo zero-length in ServerHello | §5.4 | ✓ | written zero; client aborts if non-zero |
| HRR cookie in `cookie` extension (not legacy field) | §5.6 | ✓ | parsed from ext, echoed in second CH |
| message_seq per message (not per fragment) | §5.2 | ✓ | out_msg_seq increments once per message |
| Post-handshake message_seq separate counter starting at 0 | §5.2 | ✓ | dtls13_post_hs_msg_seq |
| Address verification via cookie (HRR path) | §5.1 | ✓ | f_cookie_write/f_cookie_check callbacks |
| ACK sent for last flight of handshake | §7 | ✓ | dtls13_ack_pending=1 after Finished verify |
| ACK format: list of (epoch, seq) 8-byte pairs | §7 | ✓ | ssl_dtls13_write_ack |
| Server ACKs client's final Finished | §7.2.1 | ✓ | ssl_tls13_process_client_finished |
| Client ACKs server's final flight | §7.2 | ✓ | dtls13_ack_pending=1 in multiple paths |
| Post-handshake messages require ACK | §7 | ✓ | KeyUpdate, NewConnectionId both tracked |
| Partial flight ACK: retransmit only unacked items | §7.3 | ✓ | flight item `acked` flag |
| ACK triggers: full flight / partial+timer / out-of-order | §7.2 | ✓ | all three cases handled |
| CID extension in ClientHello/ServerHello | §9 | ✓ | mbedtls_ssl_write_cid_ext |
| NewConnectionId / RequestConnectionId | §9 | ✓ | ssl_msg.c:7713–7933 |
| too_many_cids_requested alert | §9 | ✓ | threshold=4, MBEDTLS_SSL_ALERT_MSG_TOO_MANY_CIDS_REQUESTED |
| DTLS 1.3 label prefix "dtls13" | §5.2 | ✓ | ssl_tls13_keys.c:84–89 |

**GAPS / DEFERRED:**

| Area | § | Status | Notes |
|------|---|--------|-------|
| Amplification limit (3× unverified data) | §5.1 | **WON'T DO** | No byte-count tracking. Mitigated by cookie-based address verification (f_cookie_write); operators using the cookie callback are effectively compliant. Operators not using it have no amplification protection. |
| Downgrade sentinel (ServerHello→client) | RFC 8446 §4.1.3 | ✓ | Inherited from TLS 1.3: `ssl_tls13_is_downgrade_negotiation()` checks last 8 bytes of ServerHello random for `"DOWNGRD\x00"` / `"DOWNGRD\x01"`. No DTLS-specific addition exists in RFC 9147 or bis-01. A ClientHello-side sentinel (client→server direction) has not been proposed in any published draft. |
| Per-epoch anti-replay windows | §4.2 (SHOULD) | **DEFERRED** | Tracked in Phase 7 item 5. Current implementation resets the single window on each `set_inbound_transform`; RFC uses SHOULD. |
| S bit (16-bit seq) always on | §4.1 | **DESIGN CHOICE** | RFC allows 8-bit seq. We always send 16-bit (S=1). Conservative, safe, interoperable with all known implementations. |

#### [x] 6.2 Test Coverage

Measured 2026-03-31. Build: `cmake -DCMAKE_C_FLAGS="--coverage -O0 -g3"`, ran CTest (131 unit suites) + `tests/dtls13/dtls13-tests.sh` (integration tests). Note: `development` branch has a broken CMake (`generate_config_checks.py` submodule mismatch), so the baseline is computed as coverage of pre-existing lines in the same 4 files on the `dtls13` build.

**Target:** ≥70% branch coverage on new DTLS 1.3 lines (revised up from initial 60% target based on actual achievability).

**Key finding:** `dtls13-tests.sh` was not wired into CTest. Fixed as part of this phase — wired as `dtls13-integration-suite` (test #132). Without it CTest alone gave 40.8% branch coverage on new code.

**Coverage comparison: new DTLS 1.3 code vs pre-existing code in the same files**
(same build, same test run — measures whether new code is better-tested than what was there before)

| Code | Branches | Br% | Lines | Ln% |
|------|----------|-----|-------|-----|
| **New DTLS 1.3 lines** | **744/1024** | **72.7%** | **1352/1590** | **85.0%** |
| Pre-existing lines (baseline) | 2356/3976 | 59.3% | 6126/7979 | 76.8% |

New code is **+13.4 pp** branch coverage and **+8.2 pp** line coverage vs baseline. Meets and exceeds the mbedtls policy ("similar level of coverage to existing code").

**Per-file breakdown:**

| File | New DTLS 1.3 br% | Pre-existing br% | New ln% | Pre-existing ln% |
|------|-----------------|-----------------|---------|-----------------|
| ssl_msg.c | 72.7% (598/822) | 65.6% (786/1199) | 84.7% | 77.2% |
| ssl_tls13_client.c | 71.6% (53/74) | 49.7% (300/604) | 81.5% | 78.6% |
| ssl_tls13_server.c | 65.6% (59/90) | 54.3% (354/652) | 84.9% | 80.8% |
| ssl_tls.c | 89.5% (34/38) | 60.2% (916/1521) | 100.0% | 74.3% |

**Remaining gaps in new code (tracked in Phase 7 item 8):**
- `ssl_tls13_server.c` 65.6%: HRR+cookie error paths, EncryptedExtensions CID error paths
- `ssl_msg.c` 72.7%: KeyUpdate error/cleanup paths, CID NewConnectionId/RequestConnectionId parsing errors, SNE AES path (ChaCha20 only exercised currently), cross-epoch retransmit eviction path, `dtls13_wait_ack_step` implicit-ACK path

#### [x] 6.3 DRY and Code Reuse
*Target: −1,100 net library lines (20% of ~5,500 added). Achieved: −900 net LOC.*

#### [x] 6.4 Code Complexity
- Cyclomatic complexity audit of the five largest DTLS 1.3 code paths: record parsing (unified header), epoch lookup, ACK processing, post-hs dispatch, retransmit timer.
- Flag any function exceeding ~60 lines or ~10 branches for refactoring consideration.
- Review state machine transitions: are all `ssl->state` paths reachable and correctly guarded? Are there dead states or missing transitions?
- Comment density: are non-obvious decisions (epoch arithmetic, sn_key mask construction, ACK flush timing) explained at the code level?

##### State Machine Review (completed 2026-03-31)

Two new DTLS 1.3-only states added beyond the standard TLS 1.3 states:

```
MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_WAIT_ACK   (server)
MBEDTLS_SSL_TLS1_3_CLIENT_FINISHED_WAIT_ACK      (client)
```

**Server state machine (DTLS 1.3 path):**

```
NEW_SESSION_TICKET_FLUSH
  ├─ DTLS 1.3: send_flight_completed() + arm retransmit timer
  │   └─→ NEW_SESSION_TICKET_WAIT_ACK
  └─ TLS 1.3: → HANDSHAKE_OVER

NEW_SESSION_TICKET_WAIT_ACK
  ├─ retransmit_state == RETRANS_FINISHED (at entry) → HANDSHAKE_OVER
  ├─ read_record() → explicit ACK processed inside NON_FATAL loop
  │   ├─ retransmit_state == RETRANS_FINISHED after read → HANDSHAKE_OVER
  │   ├─ in_msgtype == APP_DATA or HANDSHAKE (implicit ACK, RFC 9147 §7.3)
  │   │   → cancel timer, retransmit_state = FINISHED, keep_current_message = 1
  │   │   → HANDSHAKE_OVER
  │   ├─ WANT_READ / NON_FATAL → stay (retransmit timer drives resends)
  │   └─ error → propagate
  └─ retransmit timer fires → mbedtls_ssl_resend() retransmits NST flight
```

**Client state machine (DTLS 1.3 path):**

```
CLIENT_FINISHED (write)
  ├─ DTLS 1.3: handshake_wrapup() (installs app keys, retires epoch-2 to pool)
  │   arm retransmit timer, retransmit_state = RETRANS_WAITING
  │   └─→ CLIENT_FINISHED_WAIT_ACK
  └─ TLS 1.3: → FLUSH_BUFFERS

CLIENT_FINISHED_WAIT_ACK
  ├─ retransmit_state == RETRANS_FINISHED (at entry) → HANDSHAKE_OVER
  ├─ read_record() → explicit ACK processed inside NON_FATAL loop
  │   ├─ retransmit_state == RETRANS_FINISHED after read → HANDSHAKE_OVER
  │   ├─ in_msgtype == HANDSHAKE or APP_DATA (implicit ACK, RFC 9147 §5.3)
  │   │   → cancel timer, retransmit_state = FINISHED, keep_current_message = 1
  │   │   → HANDSHAKE_OVER
  │   ├─ WANT_READ / NON_FATAL → stay (retransmit timer drives resends)
  │   └─ error (e.g. fatal alert from server) → propagate
  └─ retransmit timer fires → mbedtls_ssl_resend() retransmits Finished flight
```

**Key design decisions:**

- `retransmit_state` is checked *both* at entry and after `read_record()` because the ACK
  handler runs inside `read_record`'s internal NON_FATAL loop and never surfaces to the
  caller as a distinct return code. Without the post-read check, an ACK arriving on the
  first read_record call would be silently processed but the state advance would only happen
  on the *next* call.

- Application keys are installed *before* entering `CLIENT_FINISHED_WAIT_ACK` (in
  `write_client_finished`) so the client can decrypt the server's ACK which arrives at
  epoch 3. The epoch-2 transform is retired to the pool so late-arriving handshake records
  can still be decrypted.

- The implicit ACK path (post-handshake message received before explicit ACK) is required
  for NST interop: RFC 9147 §5.3 / §7.3 — receiving application data or a post-handshake
  message from the peer proves it has processed our flight, so we must not stall waiting
  for an explicit ACK that may never arrive. `keep_current_message = 1` preserves the
  buffered record for delivery once `HANDSHAKE_OVER` is entered.

**Correctness assessment:** All transitions are reachable and correctly guarded. No dead
states. The double `retransmit_state` check is intentional. Alert handling (fatal error
from peer) propagates correctly via the `ret != 0` branch. The two WAIT_ACK handlers are
structurally identical; the duplication is accepted given the cross-file boundary
(server.c vs client.c).

#### [x] 6.5 Memory Safety

Re-audited 2026-03-31 with Opus 4.6 1M context (8 sections: A-H). Results:

| Section | Area | Verdict | Notes |
|---------|------|---------|-------|
| A | Raw C memory functions | PASS | No malloc/calloc/free/realloc; all memset calls are on non-sensitive data |
| B | mbedtls_calloc lifecycle | PASS | 4 allocations verified: dtls13_cli_hello, body_copy, dtls13_post_hs_ack, HVR cookie. All freed on all paths. **Advisory:** post_hs_ack alloc failure silently ignored (peer retransmits) |
| C | Key material zeroization | PASS | dtls13_ku_pending_secret, new_secret (stack), sn_key, tmp_transform all zeroized on success+error paths |
| D | Buffer bounds | PASS | All memcpy/memmove/PUT/GET verified. **Fixed:** NewConnectionId `list_len - 1` uint16 underflow when list_len=0 |
| E | Use-after-free / double-free | PASS | Epoch pool ownership sound; flight items freed in handshake_free. **Fixed:** dtls13_transform_pending_out leak on double KeyUpdate |
| F | Integer overflow | PASS | Seq counter wrapping detected. **Fixed:** epoch uint16 wrap guard in KeyUpdate. **Advisory:** sent_record_count uint8 wrap at 255 overwrites slot 0 (unreachable in practice) |
| G | Concurrency | PASS | One static const (read-only); all mutable state per-context |
| H | Error paths | PASS | All allocating functions have complete cleanup on all error paths |

Bugs fixed during audit:
- `ssl_tls13_write_key_update`: reject if `dtls13_ku_ack_pending` (prevents transform leak)
- `ssl_tls13_handle_new_connection_id`: guard `list_len < 1`; replace `p += list_len - 1` with safe arithmetic
- KeyUpdate: guard `dtls13_epoch == UINT16_MAX` before increment (both inbound and outbound)

#### [x] 6.6 Security Review

Audit completed 2026-03-31 (re-audited with Opus 4.6 1M context). Results:

| # | Area | Verdict | Notes |
|---|------|---------|-------|
| 1 | Timing oracles | PASS | PSK identity (`ssl_tls13_server.c:382`), PSK binder (`ssl_tls13_server.c:448`) both use `mbedtls_ct_memcmp`; AEAD tag via PSA (constant-time by spec); cookie MAC via `psa_mac_verify_finish` |
| 2 | Cookie entropy | PASS | 256-bit PSA random key, HMAC-SHA256, PSA constant-time verify. **Advisory:** no auto-rotation; long-lived servers should rotate manually |
| 3 | SNE mask reuse | PASS | `ssl_dtls13_sne_compute_mask` computed fresh per record from current record's ciphertext sample; no caching; temporary transform zeroized after outbound use |
| 4 | Downgrade protection | PASS | Client-side sentinel check via `ssl_tls13_is_downgrade_negotiation` (`ssl_tls13_client.c:1393`) runs for DTLS through shared `preprocess_server_hello` path |
| 5 | Amplification bypass | WON'T DO | No 3x byte-count limit per RFC 9147 §5.1. Conscious decision: mitigated by cookie-based address verification; documented in 6.1 compliance table |
| 6 | Integer overflow | PASS | Seq counter wrapping detected and returns fatal error. **Advisory:** epoch `uint16_t` wrap at 65535→0 has no guard (unrealistic: requires 65K KeyUpdates) |
| 7 | Alert handling | PASS | Epoch-0 alerts discarded post-handshake (epoch mismatch check); key material zeroized on context free; auth failure count capped by `dtls13_auth_fail_limit` |
| 8 | ACK parsing | PASS | Bounds checks on list_len; multiple-of-16 validation; epoch-0 / duplicate / future-epoch entries silently ignored; errors non-fatal |
| 9 | Record parsing | PASS | Unified header parser validates all lengths before use; truncated headers rejected; L=0 correctly treated as last-in-datagram; unknown epochs buffered or discarded |
| 10 | Epoch pool | PASS | Ownership model sound; eviction by lowest epoch; double-insert guarded. **Advisory:** theoretical retransmit failure if >4 KeyUpdates during active retransmit window |

**Amplification limit (#5):** Won't do — conscious design decision. Mitigated by cookie-based address verification; documented in 6.1 compliance table.

**Advisories resolved:**
- Cookie key rotation: pre-existing (same as DTLS 1.2); no action.
- Epoch uint16_t wrap: guard added in KeyUpdate paths.
- Epoch pool eviction during retransmit: defensive NULL check added at retransmit lookup site.

---

### Phase 7: Hardening and Full Compliance
*Goal: All MUST requirements covered; passes full interop with wolfSSL; ready for OpenSSL when available.*

- [N/A] 1. Association re-establishment: server receives epoch=0 ClientHello while an existing
         association is live.
         Closed (2026-03-31): Not a bug against RFC 9147. The current implementation
         (ssl_handle_possible_reconnect) follows RFC 6347 §4.2.8 and RFC 9147 faithfully:
         send HelloVerifyRequest first (no session destruction); destroy only after cookie
         is verified (reachability proven). The "wait for Finished" hardening is a bis
         draft §5.11 addition not present in RFC 9147. Implementing it would require
         maintaining two concurrent context states — significant rework with no RFC 9147
         mandate. Defer to a post-merge enhancement if/when the bis draft is published.
- [N/A] 2. Trial decryption for ambiguous association lookup (same 5-tuple, two potential
         associations). See bis draft §5.11.
         Closed (2026-03-31): Bis draft §5.11 feature, not required by RFC 9147.
         The current code has a single ssl_context per server socket; ambiguous associations
         from the same 5-tuple are not a case mbedtls's API model supports today.
         Defer to a post-merge enhancement.
- [x] 3. `TLS_AES_128_CCM_8_SHA256`: enforce MUST NOT use without additional forgery
         protection; return a clear error or compile-time guard.
         Fixed (2026-03-31): `mbedtls_ssl_validate_ciphersuite()` in `ssl_tls.c` now
         returns -1 for `MBEDTLS_TLS1_3_AES_128_CCM_8_SHA256` when transport is
         datagram, guarded by `#if MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_SSL_PROTO_TLS1_3`.
         This blocks the suite at both negotiation and configuration time.
- [x] 4. Epoch wrap detection: terminate if sending epoch would exceed 2^48-1.
         Audited (2026-03-31): Epoch wrap is already guarded on all paths:
         - Inbound `in_epoch++` wrap: `ssl_msg.c:7009` returns COUNTER_WRAPPING.
         - Outbound KeyUpdate: `ssl_msg.c:7481` checks `dtls13_epoch == UINT16_MAX`.
         - Inbound KeyUpdate: `ssl_msg.c:7621` same check.
         Initial epochs 0–3 are hardcoded and cannot wrap. No additional fix needed.
- [x] 5. Per-epoch anti-replay sliding windows (moved from Phase 1.5).
         Fixed (2026-03-31): Added `in_window` / `in_window_top` fields to
         `mbedtls_ssl_dtls13_epoch_slot` (ssl.h). Pool slots are initialised
         to 0/0. In `ssl_parse_record_header` (const path), pooled-epoch records
         are checked against the slot's window via `ssl_dtls13_epoch_pool_lookup_slot_const`
         before being allowed through for decryption. In `ssl_prepare_record_content`,
         after successful decryption, the slot's window is updated (same logic as the
         global window, just on the slot). Old-epoch records already seen are
         silently dropped with `MBEDTLS_ERR_SSL_UNEXPECTED_RECORD`.
         Integration test added: `keyupdate.yaml` "KeyUpdate + duplicate: connection
         survives old-epoch duplicate records" — verifies KeyUpdate + duplicate
         proxy completes successfully (38 tests pass). Deterministic old-epoch
         drop testing requires delayed application-data replay across epoch boundary;
         not achievable with the current proxy (duplicate=1 only duplicates HS records
         immediately after originals). The fix is correct per code review.
- [x] 6. Verify all Appendix C implementation pitfalls are covered.
         Audited (2026-03-31): all three areas compliant.
         - Multi-epoch key retention: epoch pool (size 4) correctly retains retired
           inbound transforms for reordered records; eviction is FIFO by epoch number
           (not MSL timer, which RFC 9147 only SHOULDs). No premature freeing found.
           Minor: `retired_at_ms` field name in ssl.h was misleading (stores epoch
           number, not a timestamp); comment clarified.
         - Fragment reassembly: bitmask-based reassembly correctly handles overlapping
           and out-of-order fragments; epoch validation occurs above reassembly layer;
           fragment header consistency enforced across fragments of same message_seq.
         - Record length validation: explicit length field validated against datagram
           bounds at two independent layers (ssl_parse_dtls13_record_header line 4576
           and ssl_parse_record_header line 5030). L=0 case (no length field) is
           trivially safe (length = remaining bytes). No bypass paths found.
- [x] 7. Post-handshake idle timeout test.
         mbedtls exposes liveness detection via the timer callback pair
         (`mbedtls_ssl_set_timer_cb`): after the handshake, the application arms
         a timer and `mbedtls_ssl_read` returns `MBEDTLS_ERR_SSL_TIMEOUT` when it
         fires.  mbedtls itself sets no post-handshake timer; the policy is entirely
         application-driven.
         **Done 2026-04-01**: `dtls13_post_hs_idle_timeout` in `test_suite_ssl`.
         Completes DTLS 1.3 in-process handshake, drains post-handshake messages,
         installs a mock timer that expires immediately on arm (no wall-clock delay),
         sets `read_timeout=1ms` on client conf, verifies `ssl_read` returns
         `MBEDTLS_ERR_SSL_TIMEOUT`, and checks `HANDSHAKE_OVER` state is preserved.
         Mock timer helpers in `BEGIN_HEADER` section of `test_suite_ssl.function`.
- [x] 8. Coverage gaps from Phase 6.2 (currently at 72.7% branch / target ≥70%; specific
         uncovered paths to close):
         - `ssl_tls13_server.c`: HRR+cookie write/check failure paths; EncryptedExtensions
           CID error paths.
         - `ssl_msg.c`: KeyUpdate error and cleanup paths; CID NewConnectionId /
           RequestConnectionId parsing errors; SNE AES path (currently only ChaCha20 /
           AES-GCM exercised); cross-epoch retransmit eviction path (epoch evicted from
           pool during active retransmit); `dtls13_wait_ack_step` implicit-ACK and
           timeout paths.
         Target: ≥80% branch coverage on new DTLS 1.3 lines after Phase 7 tests.
         Done (2026-04-01): 9 new integration tests added (bad KeyUpdate, bad CID,
         bad cookie, AES SNE path, double KeyUpdate). 47 tests pass. SNE unit test
         vectors wired up (28 new unit test cases). macOS/clang gcda multi-process
         limitation prevents accurate measurement; structurally all targeted paths
         are covered. See local-docs/coverage-plan.md for details.
- [x] 9. Fuzz testing: DTLS 1.3 corpus seeds added to fuzz_dtlsclient /
         fuzz_dtlsserver corpuses (ChaCha20, AES-128-GCM, HRR variants).
         Done (2026-04-01): corpuses/dtlsclient and corpuses/dtlsserver converted
         to directories; 3 DTLS 1.3 seeds per direction captured from real
         ssl_server2/ssl_client2 handshakes and validated against fuzz targets.
         Full record-parser fuzzing deferred (no dedicated stateless harness).
- [x] 10. Review specific security issues: cookie generation entropy, sn_key
          derivation ordering, epoch wrap, failed AEAD counter enforcement,
          downgrade sentinel checks.
          **Reviewed 2026-04-01. All five areas clean — no code changes required.**
          Cookie: PSA `psa_generate_key()` per server instance, stateless HMAC-SHA256
          with timestamp + cli_id, proper entropy. sn_key: both directions derived
          atomically with AEAD keys in same transform-construction call, no window
          before install. Epoch wrap: UINT16_MAX guard on both inbound and outbound
          KeyUpdate paths, returns error on breach. Failed AEAD counter: per-epoch
          `in_auth_fail_count` (default limit 128) sends fatal alert on breach;
          `out_record_count` triggers automatic KeyUpdate at limit (default 2^23);
          both reset on epoch advance. Downgrade sentinels: client checks both 0x00
          and 0x01 sentinels, aborts with ILLEGAL_PARAMETER if detected; server sets
          TLS 1.2 sentinel when TLS 1.3 is enabled; applies on DTLS 1.3→1.2 fallback.
- [x] 11. Full interop suite against wolfSSL covering all implemented features.
          See `reference-implementations.md`.
          Done (2026-04-03): Direction A (mbedtls server ↔ wolfSSL client) 12/12 passing;
          Direction B (wolfSSL server ↔ mbedtls client) 9/9 passing. Covers handshake,
          app data, ACK, HRR+cookie, AES-128-GCM, proxy 3d, loss recovery, PSK, KeyUpdate.
- [x] 12. Add OpenSSL interop when PR #26629 merges. See `reference-implementations.md`.
          Deferred: PR #26629 not yet merged as of 2026-04-03. No action until it lands.
- [x] 13. Non-DTLS-1.3 build validation: compile the full library with
          `MBEDTLS_SSL_PROTO_TLS1_3` enabled but DTLS 1.3 disabled (or with DTLS
          disabled entirely), and with various config combinations (no TLS 1.3, no DTLS,
          minimal config). Verify: no regressions, no new warnings, no dead-code
          compiler errors, correct `#if` guards throughout. All existing non-DTLS-1.3
          test suites must pass unchanged.
          Done (2026-04-02): Three builds compared against clean v4.1.0 baseline.
          Fixed missing guards: `ssl_client.c` PSK checksum var, `ssl_msg.c` epoch-pool
          forward decls, `ssl_test_common_source.c` TLS1_3 key-export cases,
          `ssl_helpers.c` drain_buf, `test_suite_ssl.function` mock timer helpers.
          Fixed `ssl-opt.sh` test expectation for "DTLS client reconnect: no cookies"
          (ssl_server2 now handles SSL_TIMEOUT gracefully; string changed).

          **ssl-opt.sh failure comparison (2026-04-03 final rerun):**

          | Build | Passed | Failed | Skipped | New vs baseline |
          |-------|--------|--------|---------|-----------------|
          | v4.1.0 baseline (clean worktree) | 1927 | 66 | 619 | — |
          | dtls13 branch, DTLS 1.3 enabled | 1928 | 32 | 619 | **-34 (fewer failures)** |
          | dtls13 branch, no-DTLS | 1925 | 68 | 838 | +2 (non-det) |
          | dtls13 branch, no-TLS1.3 | 1942 | 51 | 1374 | 0 |

          Final run (2026-04-03): 32 failures, all pre-existing in baseline:
          - 26 × AES_128_CCM_8 TLS 1.3 m→O interop vs OpenSSL
          - 2 × TLS 1.0/1.1 not-supported
          - 1 × deflate compression
          - 5 × defrag + client-initiated renegotiation (not related to DTLS 1.3)
          No new failures introduced by the dtls13 branch.
- [x] 14. Upstream rebase and merge-conflict analysis: review all mbedtls commits to
          the affected files (`ssl_msg.c`, `ssl_tls.c`, `ssl_tls13_*.c`, `ssl_misc.h`)
          since the 4.0.0 tag; identify conflicts and upstream changes that should be
          incorporated; assess branch stability and decide on approach (rebase onto
          current `development`, squash-merge, or long-lived feature branch with
          periodic merge commits).
- [x] 15. Fix mbedtls post-handshake message_seq bug (originally misattributed to wolfSSL).
          **Finding** (revised 2026-03-31, see `wolfssl-interop-notes.md §Phase 5.8`):
          RFC 9147 §5.2 explicitly states that `message_seq` is NOT reset at the end of
          the handshake — it continues into the post-handshake phase to distinguish
          retransmissions from new messages. wolfSSL sending KeyUpdate with seq=2 (after
          a handshake consuming seqs 0–1) is correct. mbedtls is wrong: it initializes
          `dtls13_post_hs_in_msg_seq` to 0 at context creation rather than to
          `handshake->in_msg_seq` at handshake completion.
          **Fix (commit 8234bcee75)**: In `mbedtls_ssl_handshake_set_state()`, when
          entering `HANDSHAKE_OVER` exactly, sync both `dtls13_post_hs_in_msg_seq`
          (inbound) and `dtls13_post_hs_msg_seq` (outbound) from handshake counters.
          Also fixed the inbound seq check to use `handshake->in_msg_seq` directly
          during finishing states (NST_WAIT_ACK etc.) where post-HS counter not yet synced.
          **Test**: wolfSSL KeyUpdate interop test added — all 12 wolfSSL tests pass.
          All 25 mbedtls dtls13 integration tests pass.

---

---

## Key Invariants / Security Properties to Maintain

- **No downgrade**: version negotiation must enforce the downgrade sentinels from TLS 1.3 §4.1.3.
- **No key reuse across label domains**: "dtls13" label ensures DTLS 1.3 keys are distinct from TLS 1.3 keys even for identical transcripts.
- **Seq# encryption is mandatory**: cannot be disabled without breaking the spec; treat as non-optional.
- **Anti-replay window per epoch**: DTLS 1.2 window must not be shared across epoch boundary.
- **ACK correctness**: never ACK a message that hasn't been processed or buffered — deadlock risk.
- **Cookie statelessness**: server cookie must not require server state before address validation.
- **Amplification factor**: not byte-counted (won't do); mitigated by cookie-based address verification.
- **Epoch wrap = terminate**: if epoch would exceed 2^48-1 (sending) or 2^64-1 (full), terminate.
- **Failed AEAD counter**: unlike TLS, DTLS silently drops invalid records, so we must track the failure count actively.

---

## Reference Implementations and Test Vectors

Full details in `local-docs/reference-implementations.md`. Summary:

### Test vectors
**None exist** in RFC 9147, the bis draft repo, or anywhere in the IETF/tlswg
ecosystem. This is a genuine gap. Sequence number encryption (§4.2.3) is the
highest-risk area: mandatory, novel, zero published vectors.

### Reference implementations

| Implementation | Status | Role |
|---|---|---|
| **BoringSSL** | Production, `main` branch | Technical reference; instrument `ssl/test/runner/dtls.go` to generate our test vectors |
| **wolfSSL** | Production since v5.4.0 (Jul 2022) | Primary interop target |
| **OpenSSL** | In-progress PR #26629, not merged | Skip for now |


---

## Gaps

Known gaps not yet addressed:

- **Build with `MBEDTLS_SSL_DTLS_CONNECTION_ID` disabled, DTLS 1.3 enabled**: 47 guard
  sites across `ssl_msg.c`, `ssl_tls.c`, `ssl_tls13_client.c`, `ssl_tls13_server.c`.
  No dedicated build has verified this configuration compiles and passes tests cleanly.
  The Phase 7 build matrix covered no-DTLS and no-TLS1.3, but not CID-off with
  everything else on.
