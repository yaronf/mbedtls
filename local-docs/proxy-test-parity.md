# DTLS 1.3 Proxy Test Parity Analysis

**Date:** 2026-03-26

This document maps every existing DTLS 1.2 udp_proxy test to its DTLS 1.3
status: directly portable, needs adaptation, blocked on a future phase, or
not applicable.

---

## Existing DTLS 1.2 proxy tests (full inventory)

### A. Duplicate / pack tests (lines ~11376–11422)

| Test name | Proxy params | 1.3 status |
|---|---|---|
| `DTLS proxy: reference` | (bare proxy) | portable — add as baseline |
| `DTLS proxy: duplicate every packet` | `duplicate=1` | portable |
| `DTLS proxy: duplicate every packet, server anti-replay off` | `duplicate=1` | portable |
| `DTLS proxy: multiple records in same datagram` | `pack=50` | portable |
| `DTLS proxy: multiple records in same datagram, duplicate every packet` | `pack=50 duplicate=1` | portable |

### B. Bad-MAC / badmac_limit tests (lines ~11424–11474)

| Test name | Proxy params | 1.3 status |
|---|---|---|
| `DTLS proxy: inject invalid AD record, default badmac_limit` | `bad_ad=1` | portable (AEAD tag corruption concept applies to 1.3; `badmac_limit` option works for both) |
| `DTLS proxy: inject invalid AD record, badmac_limit 1` | `bad_ad=1` | portable |
| `DTLS proxy: inject invalid AD record, badmac_limit 2` | `bad_ad=1` | portable |
| `DTLS proxy: inject invalid AD record, badmac_limit 2, exchanges 2` | `bad_ad=1` | portable |

### C. CCS / reordering tests (lines ~11476–11666)

| Test name | Proxy params | 1.3 status |
|---|---|---|
| `DTLS proxy: delay ChangeCipherSpec` | `delay_ccs=1` | **not applicable** — no CCS in DTLS 1.3 |
| `DTLS reordering: Buffer out-of-order handshake message on client` | `delay_srv=ServerHello` | **adapt**: use `delay_srv=EncryptedExtensions` |
| `DTLS reordering: Buffer out-of-order handshake message fragment on client` | `delay_srv=ServerHello` | **adapt**: use `delay_srv=EncryptedExtensions` |
| `DTLS reordering: Buffer out-of-order hs msg before reassembling next` | `delay_srv=Certificate delay_srv=Certificate` | **adapt**: use `delay_srv=Certificate` (1.3 Certificate is same message type) |
| `DTLS reordering: Buffer out-of-order hs msg before reassembling next, free buffered msg` | `delay_srv=Certificate delay_srv=Certificate` | **adapt** |
| `DTLS reordering: Buffer out-of-order handshake message on server` | `delay_cli=Certificate` | **adapt**: client Certificate message exists in 1.3 (client auth) |
| `DTLS reordering: Buffer out-of-order CCS message on client` | `delay_srv=NewSessionTicket` | **not applicable** — CCS semantics; NST in 1.3 is post-handshake |
| `DTLS reordering: Buffer out-of-order CCS message on server` | `delay_cli=ClientKeyExchange` | **not applicable** — no CKE in 1.3 |
| `DTLS reordering: Buffer encrypted Finished message` | `delay_ccs=1` | **not applicable** — no CCS in 1.3 |
| `DTLS reordering: Buffer encrypted Finished message, drop for fragmented NewSessionTicket` | `delay_ccs=1 delay_srv=NewSessionTicket` | **not applicable** |

### D. 3d handshake tests (lines ~11674–11911)

| Test name | Proxy params | 1.3 status |
|---|---|---|
| `DTLS proxy: 3d, "short" PSK handshake` | `drop=5 delay=5 duplicate=5` | **Phase 4** (PSK) |
| `DTLS proxy: 3d, "short" ECDHE-RSA handshake` | `drop=5 delay=5 duplicate=5` | portable (becomes "3d, basic handshake") |
| `DTLS proxy: 3d, "short" (no ticket, no cli_auth) FS handshake` | `drop=5 delay=5 duplicate=5` | portable |
| `DTLS proxy: 3d, FS, client auth` | `drop=5 delay=5 duplicate=5` | portable |
| `DTLS proxy: 3d, FS, ticket` | `drop=5 delay=5 duplicate=5` | **Phase 4** (session tickets) |
| `DTLS proxy: 3d, max handshake (FS, ticket + client auth)` | `drop=5 delay=5 duplicate=5` | **Phase 4** (tickets) |
| `DTLS proxy: 3d, max handshake, nbio` | `drop=5 delay=5 duplicate=5` | **Phase 4** (tickets in srv cmd) |
| `DTLS proxy: 3d, min handshake, resumption` | `drop=5 delay=5 duplicate=5` | **Phase 4** (PSK resumption) |
| `DTLS proxy: 3d, min handshake, resumption, nbio` | `drop=5 delay=5 duplicate=5` | **Phase 4** |
| `DTLS proxy: 3d, min handshake, client-initiated renego` | `drop=5 delay=5 duplicate=5` | **not applicable** — no renegotiation in 1.3 |
| `DTLS proxy: 3d, min handshake, client-initiated renego, nbio` | `drop=5 delay=5 duplicate=5` | **not applicable** |
| `DTLS proxy: 3d, min handshake, server-initiated renego` | `drop=5 delay=5 duplicate=5` | **not applicable** |
| `DTLS proxy: 3d, min handshake, server-initiated renego, nbio` | `drop=5 delay=5 duplicate=5` | **not applicable** |
| `DTLS proxy: 3d, openssl server` | `drop=5 delay=5 duplicate=5 protect_hvr=1` | **Phase 3b.6** (interop) |
| `DTLS proxy: 3d, openssl server, fragmentation` | `drop=5 delay=5 duplicate=5 protect_hvr=1` | **Phase 3b.6** |
| `DTLS proxy: 3d, openssl server, fragmentation, nbio` | `drop=5 delay=5 duplicate=5 protect_hvr=1` | **Phase 3b.6** |
| `DTLS proxy: 3d, gnutls server` | `drop=5 delay=5 duplicate=5` | **Phase 3b.6** |
| `DTLS proxy: 3d, gnutls server, fragmentation` | `drop=5 delay=5 duplicate=5` | **Phase 3b.6** |
| `DTLS proxy: 3d, gnutls server, fragmentation, nbio` | `drop=5 delay=5 duplicate=5` | **Phase 3b.6** |

### E. Fragmentation + 3d tests (lines ~10608–10648)

| Test name | Proxy params | 1.3 status |
|---|---|---|
| `DTLS fragmenting: proxy MTU + 3d` | `mtu=512 drop=8 delay=8 duplicate=8` | portable (DTLS 1.3 supports handshake fragmentation) |
| `DTLS fragmenting: proxy MTU + 3d, nbio` | `mtu=512 drop=8 delay=8 duplicate=8` | portable |

### F. Connection ID + 3d tests (lines ~2983–3505)

| Test name | Proxy params | 1.3 status |
|---|---|---|
| `Connection ID, 3D: Cli+Srv enabled, Cli+Srv CID nonempty` | `drop=5 delay=5 duplicate=5 bad_cid=1` | **Phase 5.5** (CID) |
| `Connection ID, 3D+MTU: Cli+Srv enabled, Cli+Srv CID nonempty` | `mtu=800 drop=5 delay=5 duplicate=5 bad_cid=1` | **Phase 5.5** |
| `Connection ID, 3D+MTU: ..., renegotiate with different CID` | `mtu=800 drop=5 delay=5 duplicate=5 bad_cid=1` | **not applicable** — no renegotiation in 1.3; CID update uses NewConnectionId instead |
| `Connection ID, 3D+MTU: ..., renegotiate without CID` | `drop=5 delay=5 duplicate=5 bad_cid=1` | **not applicable** |
| `Connection ID, 3D+MTU: ..., CID on renegotiation` | `mtu=800 drop=5 delay=5 duplicate=5 bad_cid=1` | **not applicable** |
| `Connection ID, 3D: ..., Cli disables on renegotiation` | `drop=5 delay=5 duplicate=5 bad_cid=1` | **not applicable** |
| `Connection ID, 3D: ..., Srv disables on renegotiation` | `drop=5 delay=5 duplicate=5 bad_cid=1` | **not applicable** |

---

## Summary by disposition

### Portable now (no unimplemented features required)

These can be added immediately as DTLS 1.3 variants.  All use
`force_version=dtls13` in place of the 1.2 ciphersuite/version constraints.

1. `DTLS 1.3: proxy — duplicate every packet`
2. `DTLS 1.3: proxy — duplicate every packet, anti-replay off`
3. `DTLS 1.3: proxy — multiple records in same datagram`
4. `DTLS 1.3: proxy — multiple records in same datagram, duplicate every packet`
5. `DTLS 1.3: proxy — inject invalid AD record, default badmac_limit`
6. `DTLS 1.3: proxy — inject invalid AD record, badmac_limit 2`
7. `DTLS 1.3: proxy — 3d, basic handshake`
8. `DTLS 1.3: proxy — 3d, client auth`
9. `DTLS 1.3: proxy — 3d, nbio`
10. `DTLS 1.3: fragmenting — proxy MTU + 3d`
11. `DTLS 1.3: fragmenting — proxy MTU + 3d, nbio`

Notes on the badmac_limit tests: items 1–2 of the 1.2 `badmac_limit` suite
(limit=1 and limit=2-with-2-exchanges) trigger connection failure; the concept
is the same in 1.3 — AEAD auth failure increments the same counter.  We port
default-limit (succeeds) and limit=2 (succeeds); the fatal-failure variants
are low-priority and skipped for now.

### Needs adaptation (future phases)

| Tests | Blocking phase |
|---|---|
| Reordering via `delay_srv=EncryptedExtensions`, `delay_srv=Certificate` | 3b.7 (new sub-phase, message-specific reordering for 1.3) |
| 3d + PSK handshake | Phase 4 |
| 3d + session ticket (FS, ticket; max handshake; nbio) | Phase 4 |
| 3d + resumption (+nbio) | Phase 4 |
| 3d + openssl/gnutls server | Phase 3b.6 (interop) |
| CID + 3d (basic) | Phase 5.5 |

### Not applicable (DTLS 1.3 architectural differences)

- CCS-dependent tests (`delay_ccs`, CCS-as-epoch-marker reordering) — no CCS in DTLS 1.3
- Renegotiation tests — no renegotiation in DTLS 1.3
- `delay_cli=ClientKeyExchange` — no CKE in DTLS 1.3
- CID renegotiation variants — CID lifecycle differs (NewConnectionId)
- `protect_hvr=1` proxy flag — HVR is DTLS 1.2 only

---

## New tests with no 1.2 analogue

These test DTLS 1.3-specific behavior and should be added as 1.3 features land:

| Test name | Phase | Notes |
|---|---|---|
| `DTLS 1.3: proxy — 3d, HRR+cookie exchange` | 3b.7 | loss during cookie round-trip |
| `DTLS 1.3: proxy — delay_srv=EncryptedExtensions` | 3b.7 | out-of-order EE before Certificate |
| `DTLS 1.3: proxy — delay_srv=Certificate` | 3b.7 | Certificate arrives before EE |
| `DTLS 1.3: proxy — 3d, PSK handshake` | 4 | once PSK path is wired |
| `DTLS 1.3: proxy — 3d, session resumption` | 4 | once NewSessionTicket / PSK resumption land |
| `DTLS 1.3: proxy — CID, 3d` | 5.5 | once CID extension is implemented |
