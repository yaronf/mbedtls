# DTLS 1.3 Test Inventory

**Last updated:** 2026-04-03 (Direction B wolfSSL interop expanded to 9 cases; all tests passing)
**Branch:** `dtls13`

Tests are grouped by type. Status: `pass` = currently passing, `fail` = currently failing (expected), `todo` = not yet written.

---

## Unit Tests — `tests/suites/test_suite_ssl.dtls13`

Run all:
```
cd build-dbg && ./tests/test_suite_ssl.dtls13
```

**Total: 23 / 23 passing**

### sn_key derivation (`ssl_dtls13_sne_key_derivation`)

| #   | Test name                                               | Status |
| --- | ------------------------------------------------------- | ------ |
| 1   | AES-128-GCM, epoch 2 (BoringSSL vec set 1)              | pass |
| 2   | AES-128-GCM, epoch 3 (BoringSSL vec set 1)              | pass |
| 3   | ChaCha20-Poly1305, epoch 2 (BoringSSL vec set 1)        | pass |
| 4   | ChaCha20-Poly1305, epoch 3 server (BoringSSL vec set 1) | pass |
| 5   | ChaCha20-Poly1305, epoch 2 client (BoringSSL vec set 1) | pass |
| 6   | ChaCha20-Poly1305, epoch 3 client (BoringSSL vec set 1) | pass |
| 7   | ChaCha20-Poly1305, epoch 2 (BoringSSL vec set 2)        | pass |

### SNE mask — AES-128-GCM (`ssl_dtls13_sne_mask_aes`)

| #   | Test name                          | Status |
| --- | ---------------------------------- | ------ |
| 8   | epoch 2, seq 0 encrypt (vec set 3) | pass |
| 9   | epoch 2, seq 1 encrypt (vec set 3) | pass |
| 10  | epoch 2, seq 2 encrypt (vec set 3) | pass |
| 11  | epoch 2, seq 3 encrypt (vec set 3) | pass |
| 12  | epoch 3, seq 0 encrypt (vec set 3) | pass |
| 13  | epoch 3, seq 1 encrypt (vec set 3) | pass |
| 14  | epoch 3, seq 2 encrypt (vec set 3) | pass |
| 15  | epoch 3, seq 0 decrypt (vec set 3) | pass |

### SNE mask — ChaCha20-Poly1305 (`ssl_dtls13_sne_mask_chacha20`)

| #   | Test name                                    | Status |
| --- | -------------------------------------------- | ------ |
| 16  | epoch 2, seq 0 encrypt (BoringSSL vec set 1) | pass |
| 17  | epoch 3, seq 0 encrypt (BoringSSL vec set 1) | pass |
| 18  | epoch 3, seq 1 encrypt (BoringSSL vec set 1) | pass |
| 19  | epoch 2, seq 0 encrypt (BoringSSL vec set 2) | pass |
| 20  | epoch 3, seq 0 encrypt (BoringSSL vec set 2) | pass |
| 21  | epoch 3, seq 1 encrypt (BoringSSL vec set 2) | pass |
| 22  | epoch 2, seq 0 decrypt (BoringSSL vec set 1) | pass |

### post_hs_msg_seq sync (`ssl_dtls13_post_hs_msg_seq_sync`)

| #   | Test name                  | Status |
| --- | -------------------------- | ------ |
| 23  | basic handshake             | pass |

---

## Integration Tests — `tests/dtls13/dtls13-tests.sh`

Run from the build-dbg tests directory via the symlink:
```
cd build-dbg/tests/dtls13 && ./dtls13-tests.sh
```

Run a single test by filter:
```
cd build-dbg/tests/dtls13 && ./dtls13-tests.sh -f "full 1-RTT"
```

Tests are defined as YAML case files under `tests/dtls13/cases/` and
generated into `dtls13-tests.sh` and `dtls13-wolfssl-tests.sh` via
`python3 tests/dtls13/generate.py`.

**Total: 47 mbedtls-only + 12 wolfSSL Direction A + 9 wolfSSL Direction B = 68 integration tests, all passing**
(wolfSSL tests require `WOLFSSL_DIR=~/misc/wolfssl`)

### Handshake (`cases/handshake.yaml`)

| Test name                                                    | Status |
| ------------------------------------------------------------ | ------ |
| `DTLS 1.3: full 1-RTT handshake`                             | pass |
| `DTLS 1.3: bidirectional application data (2 exchanges)`     | pass |
| `DTLS 1.3: client ACKs server Finished flight`               | pass |
| `DTLS 1.3: force AES-128-GCM ciphersuite (AES SNE path)`    | pass |

### HRR+Cookie (`cases/hrr-cookie.yaml`)

| Test name                                                                  | Status |
| -------------------------------------------------------------------------- | ------ |
| `DTLS 1.3: HRR+cookie exchange (cookie enabled)`                           | pass |
| `DTLS 1.3: HRR+cookie: bad cookie on retry causes server handshake_failure`| pass |

### Version Negotiation (`cases/version-negotiation.yaml`)

| Test name                                                                   | Status |
| --------------------------------------------------------------------------- | ------ |
| `DTLS 1.3: negotiate down to DTLS 1.2 (no cookie)`                         | pass |
| `DTLS 1.3: negotiate down to DTLS 1.2 (with cookie)`                       | pass |

### PSK (`cases/psk.yaml`)

| Test name                                                                                 | Status |
| ----------------------------------------------------------------------------------------- | ------ |
| `DTLS 1.3 PSK: external PSK, psk_ephemeral key exchange`                                 | pass |
| `DTLS 1.3 PSK: session resumption via NewSessionTicket PSK`                               | pass |
| `DTLS 1.3 PSK: PSK with cookie enabled — no HRR/cookie exchange (RFC 9147 §5.1)`         | pass |

### KeyUpdate (`cases/keyupdate.yaml`)

| Test name                                                              | Status |
| ---------------------------------------------------------------------- | ------ |
| `DTLS 1.3: client sends KeyUpdate (update_not_requested)`              | pass |
| `DTLS 1.3: server sends KeyUpdate (update_not_requested)`              | pass |
| `DTLS 1.3: client sends KeyUpdate (update_requested) — server reciprocates` | pass |
| `DTLS 1.3: KeyUpdate followed by application data exchange`            | pass |
| `DTLS 1.3: AEAD limit auto-triggers KeyUpdate on server`               | pass |
| `DTLS 1.3: AEAD limit auto-triggers KeyUpdate on client`               | pass |
| `DTLS 1.3: KeyUpdate + duplicate: connection survives old-epoch duplicate records` | pass |
| `DTLS 1.3: auth-fail limit: server closes after too many bad MACs`     | pass |
| `DTLS 1.3: bad KeyUpdate: body too long triggers server decode_error`  | pass |
| `DTLS 1.3: bad KeyUpdate: invalid update_requested value triggers illegal_parameter` | pass |
| `DTLS 1.3: double KeyUpdate: second blocked by pending-ACK guard`      | pass |

### CID (`cases/cid.yaml`)

| Test name                                                        | Status |
| ---------------------------------------------------------------- | ------ |
| `DTLS 1.3 CID: both endpoints offer CID — negotiated`           | pass |
| `DTLS 1.3 CID: only client offers CID — not negotiated (server disabled)` | pass |
| `DTLS 1.3 CID: basic exchange with CID enabled`                  | pass |

### CID Update (`cases/cid-update.yaml`)

| Test name                                                                                   | Status |
| ------------------------------------------------------------------------------------------- | ------ |
| `DTLS 1.3 CID update: CID update: server sends NewConnectionId, client receives and ACKs`  | pass |
| `DTLS 1.3 CID update: CID update: client sends NewConnectionId, server receives and ACKs`  | pass |
| `DTLS 1.3 CID update: CID update: client requests new CID from server`                     | pass |
| `DTLS 1.3 CID update: CID update: server requests new CID from client`                     | pass |
| `DTLS 1.3 CID update: CID update: client rebinds socket (address migration)`               | pass |
| `DTLS 1.3 CID update: CID update: client address change rejected by default server (no migration)` | pass |
| `DTLS 1.3 CID update: bad NewConnectionId: truncated body triggers server decode_error`    | pass |
| `DTLS 1.3 CID update: bad NewConnectionId: list_len=0 triggers server decode_error`        | pass |
| `DTLS 1.3 CID update: bad NewConnectionId: cid_len too large triggers server illegal_parameter` | pass |
| `DTLS 1.3 CID update: bad RequestConnectionId: empty body triggers server decode_error`    | pass |

### Proxy — Basic (`cases/proxy-basic.yaml`)

| Test name                                                                          | Status |
| ---------------------------------------------------------------------------------- | ------ |
| `DTLS 1.3: proxy - duplicate every packet`                                         | pass |
| `DTLS 1.3: proxy - duplicate every packet, anti-replay off`                        | pass |
| `DTLS 1.3: proxy - multiple records in same datagram`                              | pass |
| `DTLS 1.3: proxy - multiple records in same datagram, duplicate every packet`      | pass |
| `DTLS 1.3: proxy - inject invalid AD record, default badmac_limit`                 | pass |

### Proxy — 3D (`cases/proxy-3d.yaml`)

| Test name                                      | Status | Notes |
| ---------------------------------------------- | ------ | ----- |
| `DTLS 1.3: proxy - 3d, basic handshake`        | pass | occasionally flaky (~5%) |
| `DTLS 1.3: proxy - 3d, client auth`            | pass | |
| `DTLS 1.3: proxy - 3d, nbio`                  | pass | occasionally flaky (~20%) |
| `DTLS 1.3: loss recovery via retransmit`       | pass | |
| `DTLS 1.3: proxy - 3d, HRR+cookie exchange`   | pass | occasionally flaky (~20%) |

### Fragmentation (`cases/fragmentation.yaml`)

| Test name                                    | Status |
| -------------------------------------------- | ------ |
| `DTLS 1.3: fragmenting — proxy MTU`          | pass |
| `DTLS 1.3: fragmenting — proxy MTU, nbio`   | pass |

---

## wolfSSL Interop Tests

### Direction A — `tests/dtls13/dtls13-wolfssl-tests.sh`

mbedtls server ↔ wolfSSL client.

Run with:
```
cd build-dbg/tests/dtls13 && WOLFSSL_DIR=~/misc/wolfssl ./dtls13-wolfssl-tests.sh
```

#### Shared handshake cases

| Test name                                        | Status |
| ------------------------------------------------ | ------ |
| `DTLS 1.3: full 1-RTT handshake`                 | pass |
| `DTLS 1.3: bidirectional application data (2 exchanges)` | pass |
| `DTLS 1.3: client ACKs server Finished flight`   | pass |
| `DTLS 1.3: HRR+cookie exchange (cookie enabled)` | pass |
| `DTLS 1.3: proxy - 3d, basic handshake`          | pass |
| `DTLS 1.3: loss recovery via retransmit`          | pass |
| `DTLS 1.3: proxy - 3d, HRR+cookie exchange`      | pass |
| `DTLS 1.3 PSK: external PSK, psk_ephemeral key exchange` | pass |
| `DTLS 1.3 PSK: PSK with cookie enabled — no HRR/cookie exchange (RFC 9147 §5.1)` | pass |

#### wolfSSL-specific cases (`cases/interop-wolfssl.yaml`)

| Test name                                                               | Status |
| ----------------------------------------------------------------------- | ------ |
| `DTLS 1.3 wolfSSL interop: A: HRR — wolfSSL client triggers HelloRetryRequest` | pass |
| `DTLS 1.3 wolfSSL interop: A: reconnect after NewSessionTicket`         | pass |
| `DTLS 1.3 wolfSSL interop: A: wolfSSL client sends KeyUpdate after handshake` | pass |

### Direction B — `tests/dtls13/dtls13-wolfssl-dirb-tests.sh`

wolfSSL server ↔ mbedtls client.

Run with:
```
cd build-dbg/tests/dtls13 && WOLFSSL_DIR=~/misc/wolfssl ./dtls13-wolfssl-dirb-tests.sh
```

Connection params: `server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem`.
wolfSSL cert SAN includes `dNSName=example.com` and `iPAddress=127.0.0.1`.

#### Direction B cases (`cases/interop-wolfssl-dirb.yaml`)

| Test name                                                                                         | Status | Notes |
| ------------------------------------------------------------------------------------------------- | ------ | ----- |
| `DTLS 1.3 wolfSSL interop Direction B: full 1-RTT handshake`                                  | pass | |
| `DTLS 1.3 wolfSSL interop Direction B: application data exchange`                              | pass | |
| `DTLS 1.3 wolfSSL interop Direction B: client ACKs server Finished flight`                    | pass | |
| `DTLS 1.3 wolfSSL interop Direction B: HRR+cookie (wolfSSL sends cookie by default)`          | pass | |
| `DTLS 1.3 wolfSSL interop Direction B: force AES-128-GCM ciphersuite`                         | pass | |
| `DTLS 1.3 wolfSSL interop Direction B: proxy — 3d, basic handshake`                           | pass | |
| `DTLS 1.3 wolfSSL interop Direction B: loss recovery via retransmit`                          | pass | |
| `DTLS 1.3 wolfSSL interop Direction B: external PSK`                                          | pass | |
| `DTLS 1.3 wolfSSL interop Direction B: mbedtls client sends KeyUpdate (update_not_requested)` | pass | |

