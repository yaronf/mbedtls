# DTLS 1.3 Reference Implementations and Test Vectors

Research date: 2026-03-25

## Test Vectors

**None exist anywhere.** RFC 9147 has no test vectors. The bis draft repo
(https://github.com/tlswg/dtls13-spec) contains only spec source. No companion
test vector document exists in the IETF/tlswg ecosystem — unlike TLS 1.3, which
has https://github.com/tlswg/draft-ietf-tls-tls13-vectors.

Sequence number encryption (§4.2.3) is particularly under-documented: the RFC
specifies the mechanism but provides zero example values.

## Reference Implementations

### BoringSSL — Best technical reference

- DTLS 1.3 is in production on `main`; no versioned releases.
- Key files:
  - `ssl/dtls_record.cc` — unified header, epoch reconstruction, replay detection,
    record number encryption
  - `ssl/ssl_versions.cc` — version negotiation, `DTLS1_3_VERSION` in `kDTLSVersions`
  - `ssl/test/runner/dtls.go` — separate Go test-runner implementation (not
    production quality, but exercises all DTLS 1.3 paths and is readable)
- **How to use**: instrument `dtls.go` to log intermediate values (sn_key, SNE
  mask, reconstructed seq#) and use the output as ground-truth unit test vectors.

### wolfSSL — Primary interop target

- DTLS 1.3 since v5.4.0 (July 2022); the first production DTLS 1.3 implementation.
- Subsequent improvements:
  - v5.6.0: stateless ClientHello parsing
  - v5.6.2: authentication/integrity-only cipher suites
  - 0-RTT/early data support included
- GitHub: https://github.com/wolfSSL/wolfssl
- **How to use**: spin up a wolfSSL server/client and test interop at end of Phase 3
  (basic handshake) and Phase 4 (PSK/resumption/0-RTT).

### OpenSSL — Not yet usable

- DTLS 1.3 in-progress on branch `feature/dtls-1.3`, PR #26629 (last updated
  Feb 2026), depends on PRs #25119 and #25668 not yet merged.
- Tracking issue: https://github.com/openssl/openssl/issues/13900
- No target release announced. Skip for now; revisit when merged.

## Interop Infrastructure

No dedicated DTLS 1.3 interop server or event exists (no equivalent to
https://tls13.ulfheim.net/). Informal interop has occurred during wolfSSL's
development against draft versions.

## Action Items

1. **Generate test vectors from BoringSSL**: instrument `ssl/test/runner/dtls.go`
   to dump sn_key derivation inputs/outputs and SNE mask values for both AES and
   ChaCha20 variants. Store in `local-docs/test-vectors/`.

2. **wolfSSL interop at Phase 3**: set up client/server cross-testing after the
   basic handshake is functional.

3. **wolfSSL interop at Phase 4**: extend to PSK, resumption, 0-RTT.

4. **Track OpenSSL PR #26629**: once merged, add OpenSSL as a second interop
   target.
