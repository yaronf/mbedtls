# DTLS 1.3 Test Inventory

**Last updated:** 2026-03-25 (updated after Phase 3b.2–3b.4)
**Branch:** `dtls13`

Tests are grouped by type.  Status: `[pass]` = currently passing, `[fail]` = currently failing (expected), `[todo]` = not yet written.

---

## Unit Tests — `tests/suites/test_suite_ssl.dtls13`

Run with: `./tests/test_suite_ssl.dtls13` (from the build directory)

These cover cryptographic primitives in isolation, with test vectors from BoringSSL.
See `local-docs/test-vectors/sne-vectors.txt` for vector provenance.

### sn_key derivation (`ssl_dtls13_sne_key_derivation`)

Verifies `HKDF-Expand-Label(traffic_secret, "sn", "", key_len)` using the `"dtls13"` label prefix.


| #   | Test name                                               | Status |
| --- | ------------------------------------------------------- | ------ |
| 1   | AES-128-GCM, epoch 2 (BoringSSL vec set 1)              | [pass] |
| 2   | AES-128-GCM, epoch 3 (BoringSSL vec set 1)              | [pass] |
| 3   | ChaCha20-Poly1305, epoch 2 (BoringSSL vec set 1)        | [pass] |
| 4   | ChaCha20-Poly1305, epoch 3 server (BoringSSL vec set 1) | [pass] |
| 5   | ChaCha20-Poly1305, epoch 2 client (BoringSSL vec set 1) | [pass] |
| 6   | ChaCha20-Poly1305, epoch 3 client (BoringSSL vec set 1) | [pass] |
| 7   | ChaCha20-Poly1305, epoch 2 (BoringSSL vec set 2)        | [pass] |


### SNE mask — AES-128-GCM (`ssl_dtls13_sne_mask_aes`)

Verifies `mask = AES-ECB(sn_key, sample)[0:2]` and `enc_seq = plain_seq XOR mask`.


| #   | Test name                          | Status |
| --- | ---------------------------------- | ------ |
| 8   | epoch 2, seq 0 encrypt (vec set 3) | [pass] |
| 9   | epoch 2, seq 1 encrypt (vec set 3) | [pass] |
| 10  | epoch 2, seq 2 encrypt (vec set 3) | [pass] |
| 11  | epoch 2, seq 3 encrypt (vec set 3) | [pass] |
| 12  | epoch 3, seq 0 encrypt (vec set 3) | [pass] |
| 13  | epoch 3, seq 1 encrypt (vec set 3) | [pass] |
| 14  | epoch 3, seq 2 encrypt (vec set 3) | [pass] |
| 15  | epoch 3, seq 0 decrypt (vec set 3) | [pass] |


### SNE mask — ChaCha20-Poly1305 (`ssl_dtls13_sne_mask_chacha20`)

Verifies ChaCha20 mask: `counter = LE32(sample[0:4])`, `nonce = sample[4:16]`,
`mask = ChaCha20(sn_key, nonce, counter, 0)[0:2]`.


| #   | Test name                                    | Status |
| --- | -------------------------------------------- | ------ |
| 16  | epoch 2, seq 0 encrypt (BoringSSL vec set 1) | [pass] |
| 17  | epoch 3, seq 0 encrypt (BoringSSL vec set 1) | [pass] |
| 18  | epoch 3, seq 1 encrypt (BoringSSL vec set 1) | [pass] |
| 19  | epoch 2, seq 0 encrypt (BoringSSL vec set 2) | [pass] |
| 20  | epoch 3, seq 0 encrypt (BoringSSL vec set 2) | [pass] |
| 21  | epoch 3, seq 1 encrypt (BoringSSL vec set 2) | [pass] |
| 22  | epoch 2, seq 0 decrypt (BoringSSL vec set 1) | [pass] |


**Total: 22 / 22 passing**

---

## Integration Tests — `tests/ssl-opt.sh`

Run with: `./ssl-opt.sh -f "DTLS 1.3"` (from `build/tests/`)

These use `ssl_client2` / `ssl_server2` over loopback UDP.

### Handshake and Application Data


| Test name                                                    | Expected outcome                                      | Status | Blocked by                                                               |
| ------------------------------------------------------------ | ----------------------------------------------------- | ------ | ------------------------------------------------------------------------ |
| DTLS 1.3: full 1-RTT handshake                               | Both sides print "Protocol is DTLSv1.3"               | [pass] | —                                                                        |
| DTLS 1.3: bidirectional application data (2 exchanges)       | Client sends 51 bytes, reads 144 bytes; 2 round trips | [pass] | —                                                                        |
| DTLS 1.3: client ACKs server Finished flight                 | Client debug log shows "=> write ACK"                 | [pass] | —                                                                        |
| DTLS 1.3 client, DTLS 1.2 server: negotiate down to DTLS 1.2 | Both sides print "Protocol is DTLSv1.2"               | [fail] | ClientHello transcript hash when max_version=dtls13 but server picks 1.2 |


### Planned — to be added as phases complete


| Test name                                             | Phase | Notes                                                                                                               |
| ----------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------- |
| DTLS 1.3: HRR+cookie exchange                         | 3b.1  | Server sends cookie in HRR; client echoes it; second ClientHello accepted                                          |
| DTLS 1.3: amplification limit enforced                | 3b.2  | Blocked on 3b.1 (cookie). After cookie lands: verify dtls13_bytes_sent ≤ 3× dtls13_bytes_from_peer pre-validation  |
| DTLS 1.3: loss recovery via retransmit                | 3b.5  | Inject packet loss via udp_proxy; handshake completes                                                              |
| DTLS 1.3: per-epoch anti-replay                       | 1.5   | Replay a post-handshake record via udp_proxy; silently dropped, connection stays live                              |
| DTLS 1.3: session resumption (PSK)                    | 4     | Both sides print "Protocol is DTLSv1.3", resumed                                                                   |
| DTLS 1.3: 0-RTT early data                            | 4     | Client sends data before server Finished                                                                            |
| DTLS 1.3: KeyUpdate (single)                          | 5.2   | Both sides complete KeyUpdate; epoch advances to 4; app data flows                                                 |
| DTLS 1.3: KeyUpdate (3 sequential)                    | 5.2   | Client triggers 3 KeyUpdates; epoch advances 4→5→6; app data flows at each; old keys evicted                       |
| DTLS 1.3: CID negotiation                             | 5.5   | CID extension in ClientHello/ServerHello; records use CID format; app data flows                                   |
| DTLS 1.3: CID — address change continuity             | 5.5   | Peer changes src IP/port mid-session (udp_proxy remap); session continues via CID; app data flows                  |
| DTLS 1.3: CID update (NewConnectionId)                | 5.5   | Peer sends NewConnectionId + retire_prior_to; both ends switch to new CID; old CID silently dropped                |
| DTLS 1.3: CID — too_many_cids_requested               | 5.5   | Server returns too_many_cids_requested (alert 52) when RequestConnectionId count exceeds limit                     |
| DTLS 1.3: post-handshake client auth                  | 5.6   | Server sends CertificateRequest post-handshake                                                                     |


---

## Interop Tests (manual / future CI)

See `local-docs/reference-implementations.md` for setup instructions.


| Scenario                               | Phase | Status |
| -------------------------------------- | ----- | ------ |
| mbedtls client ↔ wolfSSL server        | 3.16  | [todo] |
| wolfSSL client ↔ mbedtls server        | 3.16  | [todo] |
| mbedtls client ↔ wolfSSL server, PSK   | 4.6   | [todo] |
| mbedtls client ↔ wolfSSL server, 0-RTT | 4.6   | [todo] |


---

## Coverage gaps / known missing tests

- **Transcript hash correctness**: no unit test verifying that DTLS framing fields are
  stripped before hashing. Should add a test vector derived from a known BoringSSL or
  wolfSSL transcript.
- **Amplification limit** (Phase 3b.2): enforcement blocked on HRR+cookie (Phase 3b.1).
  Pre-cookie, the server's flight routinely exceeds 3× a ClientHello. The planned test
  requires cookie support to be meaningful.
- **Anti-replay** (Phase 1.5): per-epoch sliding windows not yet implemented. Test
  (replayed record silently dropped) assigned to Phase 1.5.
- **AEAD limit / KeyUpdate trigger** (Phase 5.3): no test for automatic KeyUpdate when
  record count approaches AEAD confidentiality limit.
- **Epoch pool correctness**: no unit test for `dtls13_epoch_pool` retain/lookup logic.
  Should be added when Phase 3.11 lands.
- **CID address-change continuity** (Phase 5.5): requires udp_proxy address-remap
  capability; test design documented but not yet written.
- **DTLS 1.2 fallback** (known fail): ClientHello transcript hash uses 4-byte TLS
  header when `max_version=dtls13` but server picks 1.2; fix tracked under Option B
  (re-hash after ServerHello) — not yet implemented.

