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

## Architecture Overview (Current mbedtls)

Relevant files:

- `library/ssl_tls.c` — core handshake state machine, DTLS retransmission
- `library/ssl_msg.c` — record layer: read/write/encrypt/decrypt, flight buffering
- `library/ssl_tls13_client.c`, `ssl_tls13_server.c` — TLS 1.3 handshake handlers
- `library/ssl_tls13_generic.c` — shared TLS 1.3 message processing
- `library/ssl_tls13_keys.c` — TLS 1.3 key derivation (HKDF schedule)
- `library/ssl_misc.h` — all internal structs: `mbedtls_record`, `mbedtls_ssl_transform`, epoch/ctr handling
- `include/mbedtls/ssl.h` — public API
- `include/mbedtls/mbedtls_config.h` — config flags

The DTLS 1.3 "not yet supported" guard is in `ssl_tls.c` at the transport=DATAGRAM + TLS1_3_only check.

---

## What Needs to Be Built

### 1. Record Layer (ssl_msg.c, ssl_misc.h)

This is the deepest change. DTLS 1.3 has a completely new wire format for encrypted records.

**1a. Unified header parsing/serialization**
- Parse `DTLSCiphertext` unified header: first byte `001CSLЕЕ`, optional CID, 8 or 16-bit sequence number, optional length field.
- Emit unified header on write.
- Demux incoming records: type byte 32–63 → DTLSCiphertext; 21/22/26 → DTLSPlaintext; else reject.
- Distinguish DTLS 1.2 records (type byte is a content type like 20/23/25) from DTLS 1.3 encrypted records (001... prefix).

**1b. Epoch reconstruction**
- Receiver has only 2 epoch bits and 8 or 16 seq bits in the ciphertext header.
- Reconstruct full 64-bit epoch and sequence number per §4.2.2: pick the candidate closest to (highest_deprotected + 1).
- Maintain per-epoch highest-deprotected sequence number.

**1c. Sequence number encryption / decryption**
- New `sn_key` derived via `HKDF-Expand-Label(Secret, "sn", "", key_length)` per epoch.
- On write: encrypt the on-wire seq# bytes by XOR with AES-ECB(sn_key, ciphertext[0..15]) or ChaCha20(sn_key, ct[0..3], ct[4..15]).
- On read: decrypt seq# with same mask (symmetric), then proceed with AEAD.
- Must be applied only to `DTLSCiphertext`, not `DTLSPlaintext`.

**1d. AEAD additional data change**
- DTLS 1.2: `epoch || seq || type || version || length` (13 bytes).
- DTLS 1.3: just the unified header bytes (2–N bytes, before seq# decryption). No epoch in AEAD nonce computation.
- AEAD nonce: still uses the 64-bit sequence number (after reconstruction), XORed with the IV — same pattern as TLS 1.3.

**1e. DTLSInnerPlaintext**
- On write: serialize as `content || content_type || padding`.
- On read: strip trailing zeros to find real content type.

**1f. Multi-record datagrams**
- Multiple records per datagram already partially supported. DTLS 1.3 adds the case where the last record can omit the length field. Need to handle this in the read loop.

**1g. Anti-replay per epoch**
- Already implemented for DTLS 1.2. Extend to maintain a per-epoch sliding window. On epoch transition, initialize a new window for the new epoch. Retain old windows per §4.2.1 guidance (up to MSL).

### 2. Epoch Management (ssl_misc.h, ssl_tls.c)

DTLS 1.3 has well-defined epoch semantics (0=plain, 1=early, 2=hs, 3=appdata, 4+=rekey). The current mbedtls epoch is a 2-byte field inside `ctr[0..1]` of `mbedtls_record`. This is sufficient for DTLS 1.2 but needs extension:

- Track the full 64-bit epoch internally (wire format only shows 2 low-order bits in ciphertext, full 16-bit epoch in plaintext).
- Install/activate keys at the right epoch transitions during handshake.
- Support retaining keys from previous epochs for reordering window (SHOULD retain up to MSL).
- `alt_transform_out` already exists for retransmission; may need generalization to support multiple retained epochs.

### 3. Key Schedule Integration (ssl_tls13_keys.c)

Mostly reuse, but:

- Change HKDF label prefix from `"tls13 "` to `"dtls13"` when in DTLS mode. Add a flag/parameter to `HKDF-Expand-Label` wrappers, or use a per-context prefix string.
- Add `sn_key` derivation (one per epoch, per direction).
- Ensure `client_early_traffic_secret` maps to epoch 1; `[sender]_handshake_traffic_secret` to epoch 2; `[sender]_application_traffic_secret_0` to epoch 3; subsequent to 4+.

### 4. Handshake State Machine (ssl_tls.c, ssl_tls13_client.c, ssl_tls13_server.c)

Most TLS 1.3 handshake message handling can be reused directly. DTLS 1.3 divergences:

**4a. Remove the "DTLS 1.3 not supported" guard.**

**4b. No compatibility mode**
- Skip sending/expecting ChangeCipherSpec.
- Enforce `legacy_session_id_echo` is empty in ServerHello (abort with `illegal_parameter` if not).
- Set `legacy_session_id` to zero-length in ClientHello for DTLS 1.3.
- Set `legacy_cookie` to zero-length in ClientHello for DTLS 1.3.

**4c. Cookie exchange via HelloRetryRequest**
- Replace `HelloVerifyRequest` path with TLS 1.3 `HelloRetryRequest + cookie extension` path.
- Server: on initial ClientHello without prior proof of reachability, generate stateless cookie (HMAC of client address + transcript hash), send HRR.
- Client: on receiving HRR with cookie, re-send ClientHello with `cookie` extension.
- Server: validate cookie, reject with `illegal_parameter` if invalid.
- DTLS 1.3 client MUST abort on a second HRR in the same connection.

**4d. EndOfEarlyData omission**
- Do not send or expect EndOfEarlyData in DTLS 1.3 (epoch change signals end of early data).
- Remove from transcript.

**4e. Handshake transcript excludes DTLS framing fields**
- The transcript hash is computed over TLS 1.3-style Handshake messages (no `message_seq`, `fragment_offset`, `fragment_length`). This is opposite of DTLS 1.2.
- When feeding handshake messages into the transcript hash, strip the DTLS framing fields first.

**4f. Version negotiation**
- DTLS 1.3 version value is `0xfefc` in `supported_versions` extension.
- `legacy_version` in ClientHello MUST be `{254, 253}` (DTLSv1.2).
- Downgrade sentinels from TLS 1.3 apply.

**4g. Retransmission / flight state machine**
- DTLS 1.2 uses "retransmit entire flight on timer". DTLS 1.3 keeps this but adds selective retransmission based on ACKs: skip records that have been ACKed.
- Need to track which record numbers were used for which handshake messages/fragments.
- State machine: PREPARING → SENDING → WAITING → (FINISHED or back). Same shape as DTLS 1.2, but WAITING now has the ACK-based exit path in addition to timeout and next-flight-received.

### 5. ACK Message (new)

Content type 26 (`ack`). This is entirely new.

**5a. Parsing**
- `ACK { RecordNumber record_numbers<0..2^16-1> }` where `RecordNumber = { uint64 epoch; uint64 sequence_number }`.
- Parse incoming ACK records in the record layer; deliver to handshake layer.

**5b. Sending**
- Send ACK when: (a) partial flight received (out-of-order fragment or delayed rest), (b) receiving the last flight (MUST ACK).
- ACK uses the highest available sending epoch (but not epoch 1; use epoch 0 if stuck in early data).
- Post-handshake: ACK each received-and-processed handshake record.

**5c. Processing received ACKs**
- Mark acknowledged records; remove from retransmission queue.
- If partial ACK received, retransmit only unacknowledged records.
- If full ACK received, cancel all retransmissions for that flight.

### 6. Post-Handshake Messages

DTLS 1.3 requires reliability for all post-handshake messages via independent per-message PREPARING/SENDING/WAITING state machines:

- **NewSessionTicket**: server sends, client ACKs.
- **KeyUpdate**: must be ACKed before sending with new epoch. Both sides must retain old keys until new-epoch traffic is successfully received. Epoch increments to 4+.
- **NewConnectionId / RequestConnectionId**: new DTLS 1.3 messages (handshake types 10/9). Sender sends, receiver ACKs.
- **Post-handshake client auth**: existing TLS 1.3 mechanism; needs ACK wrapping for DTLS.

### 7. Connection ID Updates

DTLS 1.3 CID is native in the unified header. RFC 9146 CID for DTLS 1.2 is a different mechanism. For DTLS 1.3:

- Negotiate CID via `connection_id` extension in ClientHello/ServerHello.
- CID in unified header via C bit.
- `NewConnectionId` and `RequestConnectionId` post-handshake messages (new, not in DTLS 1.2).
- `cid_immediate` vs `cid_spare` semantics.

### 8. AEAD Limits

- Track authenticated record count per epoch; initiate KeyUpdate before limit.
- Track failed authentication attempts per epoch; close connection if exceeded (GCM/CHACHA: 2^36; CCM: 2^23.5).
- `TLS_AES_128_CCM_8_SHA256`: MUST NOT be used without additional forgery protection. Flag or disallow.

### 9. Config / Feature Flags

- No new top-level config flag needed initially: DTLS 1.3 is enabled when both `MBEDTLS_SSL_PROTO_DTLS` and `MBEDTLS_SSL_PROTO_TLS1_3` are defined.
- May want `MBEDTLS_SSL_DTLS13_SEQUENCE_NUMBER_ENCRYPTION` (on by default, but allow opt-out for constrained environments if spec allows? — actually the spec mandates it, so probably not).
- `MBEDTLS_SSL_DTLS_CONNECTION_ID` already exists; extend to cover DTLS 1.3 unified-header CID.
- New feature: `MBEDTLS_SSL_DTLS13_ACK` or just always-on when DTLS 1.3 is enabled.
- Post-handshake CID management may be a separate flag.

### 10. API Changes

Minimal API changes desired. Likely additions:

- New error codes: e.g., for epoch wrap, too_many_cids_requested.
- Possibly expose ACK-related state for applications that need fine-grained control.
- No new connect/accept API: DTLS 1.3 uses same `mbedtls_ssl_handshake()` entry point.

---

## Detailed Design

The three areas where the phase steps alone are insufficient to start coding
have been drilled down in `local-docs/design-drilldown.md`:

1. **Record layer integration** — exact dispatch point in `ssl_parse_record_header()`,
   AAD change, new context fields (`dtls13_epoch_max_seq[4]`, `in_epoch_full`).
2. **Transform slot model** — circular array of 4 `mbedtls_ssl_dtls13_epoch_slot`
   entries on `mbedtls_ssl_context` for retaining past inbound epochs; outbound
   retransmit model (`alt_transform_out`) unchanged.
3. **ACK + retransmit surgery** — new fields on `mbedtls_ssl_flight_item`
   (`sent_records[]`, `acked`), incoming record tracking for ACK content
   (`dtls13_received_records[]`), non-blocking ACK injection via
   `dtls13_ack_pending` flag, post-handshake FSM linked list design.

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
- [ ] 3. Handle last-record-in-datagram with omitted length field (L bit clear).
         Read loop in `ssl_get_next_record()` must consume remainder of datagram when
         no length field is present.
- [x] 4. Implement epoch reconstruction algorithm (§4.2.2).
         New context fields `dtls13_epoch_max_seq[4]` and `in_epoch_full` in
         `mbedtls_ssl_context` (ssl.h). Reconstruction logic in
         `ssl_parse_dtls13_record_header()`.
- [ ] 5. Implement per-epoch anti-replay sliding windows.
         See drilldown §2: epoch pool allows maintaining separate windows per retained
         epoch; existing `in_window`/`in_window_top` covers the active epoch only.
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
- [ ] 9. Implement `DTLSInnerPlaintext` serialization/deserialization.
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
- [ ] 3. Validate epoch → key mapping (epoch 0=no key, 1=early, 2=hs, 3=app, 4+=rekey).
- [x] 4. Unit tests: key derivation test vectors.
         See `reference-implementations.md`: BoringSSL test runner is the source for vectors.
         Covered by `test_suite_ssl.dtls13` (7 sn_key derivation cases).

### Phase 3: Basic Handshake (Full 1-RTT, Certificate-Based)
*Goal: A full DTLS 1.3 handshake completes between mbedtls client and server, and interops with wolfSSL.*
*Design detail: see `design-drilldown.md` §1 (transcript/epoch wiring), §3 (ACK + retransmit).*

- [ ] 1. Remove the "DTLS 1.3 not supported" guard.
- [ ] 2. Decide and implement `MBEDTLS_SSL_DTLS13_ACK` config flag (or always-on):
         ACK is mandatory for correct operation; leaning toward always-on when
         `MBEDTLS_SSL_PROTO_DTLS` + `MBEDTLS_SSL_PROTO_TLS1_3` are both defined.
- [ ] 3. Implement version negotiation: `supported_versions` extension with `0xfefc`
         for DTLS 1.3; clean fallback to DTLS 1.2 when peer does not support 1.3.
- [ ] 4. Adapt ClientHello construction: zero `legacy_session_id`, zero `legacy_cookie`,
         correct `supported_versions`, no compatibility mode.
- [ ] 5. Adapt ServerHello: no `legacy_session_id_echo`, `legacy_version = 0xfefd`.
         Enforce client aborts with `illegal_parameter` if `legacy_session_id_echo` non-empty.
- [ ] 6. Strip DTLS framing fields from transcript hash inputs.
         See drilldown §1: identify all `ssl_update_checksum` call sites in
         `ssl_tls13_generic.c` and client/server files; strip `message_seq`,
         `fragment_offset`, `fragment_length` before hashing for DTLS 1.3.
- [ ] 7. Implement HRR+cookie path (stateless server cookie via HMAC).
- [ ] 8. Suppress EndOfEarlyData.
- [ ] 9. Suppress ChangeCipherSpec.
- [ ] 10. Enforce amplification limit: server MUST NOT send more than 3x bytes received
          before address is validated (cookie exchange or completed handshake).
- [ ] 11. Wire up epoch transitions: install handshake keys at epoch 2, app keys at epoch 3.
          See drilldown §2: push old `transform_in` into `dtls13_epoch_pool` on each
          transition rather than freeing it; `alt_transform_out` handles outbound retransmit.
- [ ] 12. Implement ACK message parsing and serialization.
          See drilldown §3: `ACK { RecordNumber record_numbers<0..2^16-1> }`;
          `RecordNumber = { uint64 epoch; uint64 seq }`.
- [ ] 13. Add ACK sending for the final client flight (required by spec).
          See drilldown §3: set `dtls13_ack_pending` flag; ACK injected at top of
          `mbedtls_ssl_read_record()` from `dtls13_received_records[]`.
- [ ] 14. Extend retransmit state machine: selective retransmission when ACK received.
          See drilldown §3: new `ssl_dtls13_process_ack()` marks `flight_item->acked`;
          `mbedtls_ssl_flight_transmit()` skips acked items. New fields `sent_records[]`
          and `acked` on `mbedtls_ssl_flight_item`.
- [ ] 15. Self-test: mbedtls client ↔ mbedtls server full 1-RTT handshake, verify
          record transcript and epoch transitions.
- [ ] 16. Interop: mbedtls client ↔ wolfSSL server, and wolfSSL client ↔ mbedtls server.
          See `reference-implementations.md`.

### Phase 4: Session Resumption and PSK
*Goal: PSK and resumption handshakes work, including 0-RTT.*

- [ ] 1. Validate PSK path through DTLS 1.3 (should largely reuse TLS 1.3 PSK code).
- [ ] 2. NewSessionTicket: implement server-side ACK requirement (server retransmits until ACKed).
- [ ] 3. PSK+cookie interaction: server MAY skip cookie when PSK + known IP.
- [ ] 4. 0-RTT (early data): epoch 1 handling; no EndOfEarlyData; server drops epoch 1 keys
         after first epoch 3 data arrives.
- [ ] 5. Self-test: resumption handshake, 0-RTT data delivery.
- [ ] 6. Interop: wolfSSL client ↔ mbedtls server and vice versa for PSK, resumption, 0-RTT.
         See `reference-implementations.md`.

### Phase 5: Post-Handshake Messages
*Goal: KeyUpdate, CID management, post-handshake auth all work with ACK reliability.*
*Design detail: see `design-drilldown.md` §3 (post-handshake FSM linked list).*

- [ ] 1. Implement `mbedtls_ssl_dtls13_hs_fsm` linked list on `mbedtls_ssl_context`.
         See drilldown §3 for full struct definition and lookup semantics.
- [ ] 2. KeyUpdate: ACK required; new epoch (4+); retain old keys until new-epoch traffic received.
         See drilldown §2: epoch pool retains pre-update inbound transform until first
         successful decrypt with new keys.
- [ ] 3. AEAD limit tracking: count authenticated records per epoch; trigger KeyUpdate.
- [ ] 4. Count failed authentication attempts per epoch; close on limit.
- [ ] 5. NewConnectionId (type 10) and RequestConnectionId (type 9): parse, send, ACK.
         Implement `cid_immediate` vs `cid_spare` semantics.
         Add `too_many_cids_requested` alert (value 52).
- [ ] 6. Post-handshake client authentication: CertificateRequest → Certificate →
         CertificateVerify → Finished exchange with ACK wrapping for DTLS reliability.
- [ ] 7. Self-test: KeyUpdate exchange, CID negotiation and update, post-handshake auth,
         limit enforcement.
- [ ] 8. Interop: wolfSSL for KeyUpdate and CID update scenarios.
         See `reference-implementations.md`.

### Phase 6: Hardening and Full Compliance
*Goal: All MUST requirements covered; passes full interop with wolfSSL; ready for OpenSSL when available.*

- [ ] 1. Association re-establishment: server receives epoch=0 ClientHello while an existing
         association is live. MUST NOT destroy old association until new client proves
         reachability (cookie exchange or verified Finished). See bis draft §5.11.
- [ ] 2. Trial decryption for ambiguous association lookup (same 5-tuple, two potential
         associations). See bis draft §5.11.
- [ ] 3. `TLS_AES_128_CCM_8_SHA256`: enforce MUST NOT use without additional forgery
         protection; return a clear error or compile-time guard.
- [ ] 4. Epoch wrap detection: terminate if sending epoch would exceed 2^48-1.
- [ ] 5. Verify all Appendix C implementation pitfalls are covered:
         - Multi-epoch key retention during key transitions.
         - Fragment reassembly correctness with out-of-order and overlapping fragments.
         - Explicit record length validation within datagram bounds.
         - Amplification limit enforced from the first ClientHello.
- [ ] 6. Fuzz testing: record parser (unified header, epoch reconstruction, fragment
         reassembly), ACK parser.
- [ ] 7. Security review: cookie generation entropy, sn_key derivation ordering, epoch
         wrap, failed AEAD counter enforcement, downgrade sentinel checks.
- [ ] 8. Full interop suite against wolfSSL covering all implemented features.
         See `reference-implementations.md`.
- [ ] 9. Add OpenSSL interop when PR #26629 merges. See `reference-implementations.md`.

---

## Key Invariants / Security Properties to Maintain

- **No downgrade**: version negotiation must enforce the downgrade sentinels from TLS 1.3 §4.1.3.
- **No key reuse across label domains**: "dtls13" label ensures DTLS 1.3 keys are distinct from TLS 1.3 keys even for identical transcripts.
- **Seq# encryption is mandatory**: cannot be disabled without breaking the spec; treat as non-optional.
- **Anti-replay window per epoch**: DTLS 1.2 window must not be shared across epoch boundary.
- **ACK correctness**: never ACK a message that hasn't been processed or buffered — deadlock risk.
- **Cookie statelessness**: server cookie must not require server state before address validation.
- **Amplification factor**: server MUST NOT send more than 3x bytes received before address validated.
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

### Plan

- **Before Phase 1**: instrument BoringSSL's test runner to dump sn_key derivation
  values and SNE mask outputs (AES and ChaCha20). Store as ground-truth unit test
  vectors in `local-docs/test-vectors/`.
- **End of Phase 3**: interop test against wolfSSL (full handshake, cert-based).
- **End of Phase 4**: extend wolfSSL interop to PSK, resumption, 0-RTT.
- **When OpenSSL PR merges**: add as second interop target.

---

## Open Questions

1. **API for ACK**: ACK send/receive should be fully internal and invisible to
   the application. The non-blocking I/O interaction needs careful design: an ACK
   may need to be sent before the application has called `mbedtls_ssl_write`, so
   the record layer must be able to inject ACK records independently. Defer final
   design to Phase 3 when the handshake FSM is being wired up.

2. **`MBEDTLS_SSL_DTLS_SRTP` compatibility**: Likely unaffected (DTLS-SRTP uses
   DTLS only for key establishment, then hands off to SRTP). Needs a short
   research spike before Phase 6, not urgent.
