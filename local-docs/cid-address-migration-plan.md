# CID Address Migration Plan

**Status**: Planned
**RFC reference**: RFC 9147 §9 (Connection ID); §11 (Security Considerations — address migration).

---

## Problem Statement

In real deployments, a DTLS client can change its IP address and/or port mid-session (NAT rebind, network interface change, mobile handoff). The server must be able to continue the session using the CID to identify the association rather than the 5-tuple.

We simulate this by having a single test client close and reopen its UDP socket, which gives it a new ephemeral source port. The underlying mechanism and server-side handling are identical to a real IP/port change.

Currently `mbedtls_net_accept` for UDP calls `connect(bind_ctx->fd, &client_addr)` which locks the socket to the original 5-tuple at the kernel level (`net_sockets.c:377`). Datagrams from a new source are silently dropped.

---

## RFC Constraints

RFC 9147 §11 states:

> DTLS implementations MUST NOT update the address they send to in response to packets from a different address unless they first perform some reachability test; no such test is defined in this specification.

No reachability test is defined in RFC 9147. Our migration condition:

- At least 1 second of silence from the old address, AND
- At least 1 AEAD-validated packet received from the new address within that period.

AEAD success proves the sender holds the session keys (proof of ownership). The silence window guards against reflection attacks and transient path flaps.

A note on why a formal reachability check has value beyond what AEAD provides: an active reachability probe (e.g. a challenge-response exchange to the new address before committing migration) is observable by on-path network devices such as firewalls with DoS protection. A firewall can see the probe and the response, confirm that the new address is genuinely reachable and bidirectional, and use that as a signal to update its state and allow traffic from the new address. AEAD success is invisible to the firewall (it only sees ciphertext), so a purely AEAD-based migration appears to the network as unsolicited traffic from a new source — potentially triggering blocking. This is a protocol-level argument for a standardized reachability mechanism; it does not affect our test implementation.

RFC 9147 §9 states implementations SHOULD use a fresh CID when changing paths. We intentionally do not implement this: applications often cannot detect a local address change in time to prevent correlation, making the guidance impractical. We reuse the existing CID across the address change.

---

## Address Migration Decision: Timer Heuristic

When a datagram arrives from a *new* source address with a known CID:

1. Record the new candidate address, start a 1-second migration timer. `candidate_validated` starts false.
2. Every time a datagram arrives from the *old* address, restart the timer (old path is still live — do not migrate yet).
3. Every time `mbedtls_ssl_read` returns `> 0` and `last_src_addr == candidate`: set `candidate_validated = true`. (AEAD success is inferred from the library delivering data.)
4. When the timer fires and `candidate_validated == true`: commit migration — update the stored peer address, log the event.
5. If a *third* address appears before the timer fires, it replaces the candidate, `candidate_validated` resets to false, and the timer restarts.

Migration commits only when the old path has been quiet for a full second and at least one AEAD-authenticated packet from the new address has been observed.

---

## Design

Three layers of change — no library (libmbedtls) modifications required.

### 1. Client: `cid_change_addr=N` option (`ssl_client2.c`)

- New `opt.cid_change_addr` integer (default 0).
- After each exchange iteration, if `cid_change_addr > 0` and CID was negotiated:
  - `mbedtls_net_free(&server_fd)` — close the old socket.
  - `mbedtls_net_connect(&server_fd, server_addr, server_port, MBEDTLS_NET_PROTO_UDP)` — open a new socket. New ephemeral source port; same destination.
  - Decrement `cid_change_addr`.
  - Log `"address changed"`.
  - The `io_ctx.net` pointer already points to `&server_fd` so the BIO automatically uses the new fd. No TLS state changes.

### 2. Server: `allow_addr_migration=1` boolean flag (`ssl_server2.c`)

When `allow_addr_migration=1` and CID is negotiated, replace the default BIO with a custom recv/send pair backed by a migration context. The server always receives via `recvfrom` on the unconnected `listen_fd` — there is no separate connected socket for receiving. `client_fd` (as produced by `mbedtls_net_accept`) is repurposed or abandoned for recv; all sends use `sendto(listen_fd, ..., &peer_addr)`.

```c
typedef struct {
    int          listen_fd;              /* unconnected UDP socket, bound to server port */
    struct sockaddr_storage peer_addr;   /* current authoritative peer address */
    socklen_t    peer_addr_len;
    struct sockaddr_storage candidate;   /* pending new address */
    socklen_t    candidate_len;
    struct sockaddr_storage last_src_addr; /* src addr of most recent datagram returned by recv_cb */
    socklen_t    last_src_addr_len;
    int          candidate_validated;    /* set by main loop after mbedtls_ssl_read > 0 with last_src == candidate */
    struct timespec candidate_since;     /* time of last valid packet from old address; reset on each old-addr recv; initialized to now when candidate first appears */
    long         migration_timeout_ms;   /* default 1000 */
} migration_ctx_t;
```

Custom `recv_cb(ctx, buf, len)`:

1. Call `recvfrom(listen_fd, buf, len, 0, &src_addr, &src_len)` (blocking, or `MSG_DONTWAIT` if nbio).
   - On `EAGAIN`: return `MBEDTLS_ERR_SSL_WANT_READ`.
2. Record `last_src_addr = src_addr`. Compare `src_addr` to `peer_addr`:
   - **Same as current peer**: if a migration candidate is active, restart `candidate_since` (old path still live).
   - **Same as existing candidate**: no state change (validation happens in main loop after AEAD).
   - **New address**: set as candidate, `candidate_validated = false`, record `candidate_since = now`.
3. Return the data in all cases — the library runs AEAD. If AEAD fails the record is silently discarded by the library; `candidate_validated` remains false until `mbedtls_ssl_read` confirms delivery.

**AEAD and candidate validation**: the app has no visibility into AEAD outcome inside `recv_cb` — it hands raw bytes to the library, which either returns data from `mbedtls_ssl_read` (AEAD passed) or silently discards and returns `WANT_READ` (AEAD failed). Therefore `candidate_validated` must be set by the main loop, not inside `recv_cb`:

- `recv_cb` records `last_src_addr` (the source address of the most recently returned datagram).
- After `mbedtls_ssl_read` returns `> 0` (application data delivered), the main loop checks: if `last_src_addr == candidate`, set `candidate_validated = true`.

This ensures only AEAD-authenticated packets count toward migration.

Custom `send_cb(ctx, buf, len)`:

- `sendto(listen_fd, buf, len, 0, &peer_addr, peer_addr_len)`.

**Timer check**: after each `mbedtls_ssl_read` call in the main loop (whether it returns data or `WANT_READ`), check:

```c
if (mctx.candidate_validated) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - mctx.candidate_since.tv_sec) * 1000
                    + (now.tv_nsec - mctx.candidate_since.tv_nsec) / 1000000;
    if (elapsed_ms >= mctx.migration_timeout_ms) {
        mctx.peer_addr     = mctx.candidate;
        mctx.peer_addr_len = mctx.candidate_len;
        mctx.candidate_validated = 0;
        mbedtls_printf("  . Address migrated to new peer\n");
    }
}
```

`select`/`poll` in the main idle loop should watch `listen_fd` (the single recv socket).

### 3. Test case (`tests/dtls13/cases/cid-update.yaml`)

Note on termination: DTLS is UDP — `close_notify` is best-effort and cannot be relied upon for server termination. The server uses `read_timeout` instead: after the client finishes and goes quiet, the server's next `mbedtls_ssl_read` times out and the server exits cleanly.

This requires a small ssl_server2 change: `MBEDTLS_ERR_SSL_TIMEOUT` currently falls into the `default:` case in the read loop's error switch (ssl_server2.c:3904) which does `goto reset`, looping back to wait for a new client — the process never exits. Add an explicit case:

```c
case MBEDTLS_ERR_SSL_TIMEOUT:
    mbedtls_printf(" timed out waiting for client\n");
    ret = 0;
    goto close_notify;
```

The client drives session length via `exchanges`; the server's `exchanges` is set high enough to never be the limiting factor.

```yaml
- name: "CID update: client rebinds socket (address migration)"
  server:
    debug_level: 3
    cid: 1
    cid_val: "deadbeef"
    allow_addr_migration: 1
    exchanges: 999
    read_timeout: 3000
  client:
    debug_level: 3
    cid: 1
    cid_val: "cafebabe"
    cid_change_addr: 2
    exchanges: 4
  expect:
    exit: 0
    assert:
      - server_dtls13_negotiated
      - client_dtls13_negotiated
      - server_cid_negotiated
      - client_cid_negotiated
      - client_addr_changed
      - server_addr_migrated

- name: "CID update: client address change rejected by default server (no migration)"
  # Default server behavior: connected UDP socket filters by 5-tuple.
  # After client rebinds, server's recv drops packets from the new source.
  # Server times out; client stalls after the rebind. Neither side completes
  # the post-rebind exchange — verifying that migration is opt-in.
  server:
    debug_level: 3
    cid: 1
    cid_val: "deadbeef"
    exchanges: 999
    read_timeout: 3000
  client:
    debug_level: 3
    cid: 1
    cid_val: "cafebabe"
    cid_change_addr: 1
    exchanges: 4
  expect:
    exit: 0
    assert:
      - server_dtls13_negotiated
      - client_dtls13_negotiated
      - server_cid_negotiated
      - client_cid_negotiated
      - client_addr_changed
      - server_addr_not_migrated
```

### 4. Runner updates (`tests/dtls13/runners/mbedtls.yaml`)

- Add `cid_change_addr` and `allow_addr_migration` to `param_map`.
- Add assertions:
  - `client_addr_changed`: `-c "address changed"`
  - `server_addr_migrated`: `-s "Address migrated to new peer"`
  - `server_addr_not_migrated`: `-S "Address migrated to new peer"`

---

## Session Flow

```
Client                                   Server
  |── Handshake (port 50001) ───────────→|
  |                                       |  peer_addr = :50001
  |── AppData (port 50001) ──────────────→|  recvfrom src=:50001 → same as peer, deliver
  |←── AppData reply (sendto :50001) ────|
  |                                       |
  | [close fd, new fd → port 50002]       |
  | log "address changed"                 |
  |                                       |
  |── AppData (port 50002) ──────────────→|  recvfrom src=:50002 → new candidate, timer T=now
  |                                       |  ssl_read > 0 → candidate_validated=true
  |                                       |  (server still sends to :50001 during window)
  |←── AppData reply (sendto :50001) ────|  [lost — client no longer listening on :50001]
  |                                       |
  |  [1s silence from :50001]             |  timer fires, candidate_validated=true
  |                                       |  peer_addr ← :50002, log "Address migrated"
  |── AppData (port 50002) ──────────────→|  recvfrom src=:50002 → same as peer_addr now
  |←── AppData reply (sendto :50002) ────|  [delivered]
  |                                       |
  | [close fd, new fd → port 50003]       |  second migration, same path
  ...
```

---

## Implementation Steps (in order)

1. **`ssl_client2.c`**: Add `DFL_CID_CHANGE_ADDR 0`, `USAGE_CID_CHANGE_ADDR`, `opt.cid_change_addr`; parse argument; after each exchange when value > 0 and CID negotiated, `mbedtls_net_free` + `mbedtls_net_connect` + decrement + log `"address changed"`.
2. **`ssl_server2.c`**:
   - Add `MBEDTLS_ERR_SSL_TIMEOUT` case in the read loop error switch → `goto close_notify` with `ret=0` (prerequisite for `read_timeout`-based termination).
   - Add `allow_addr_migration` boolean; when set and CID negotiated, allocate `migration_ctx_t`, install custom `recv_cb`/`send_cb`; add timer-check + commit-migration logic in main loop after each `mbedtls_ssl_read`. Ensure `select`/`poll` watches `listen_fd`.
3. **`cid-update.yaml`**: Add the migration test case above.
4. **`mbedtls.yaml`**: Add `cid_change_addr`, `allow_addr_migration` to param_map; add `client_addr_changed` / `server_addr_migrated` assertions.
5. **Regenerate** `dtls13-tests.sh`.

---

## Key Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Replies lost during 1s migration window | Acceptable per RFC — no seamless cutover required. Client retransmits if using reliable app protocol; for test purposes exchanges after migration verify the session is live. |
| Spoofed new-source packet sets candidate | Candidate address is recorded in `recv_cb` before AEAD, but `candidate_validated` is only set by the main loop after `mbedtls_ssl_read > 0`. An attacker cannot forge an AEAD-valid packet, so `candidate_validated` never becomes true for a spoofed candidate. |
| Multiple candidates race | Latest candidate wins; timer restarts on each new address. |
| `listen_fd` receives connection attempts from unrelated new clients | Not a concern in single-client test. |
| Non-blocking mode spin | `recv_cb` returns `MBEDTLS_ERR_SSL_WANT_READ` on `EAGAIN`; main loop uses `select`/`poll` on `listen_fd` — no busy-wait. |

---

## Out of Scope

- Library-level migration API (e.g. `mbedtls_ssl_update_peer_addr()`): not needed for test coverage.
- Server-initiated address change: relevant for websocket-like scenarios (server behind a proxy/load-balancer that changes source address), but out of scope for now.
- ICMP unreachable handling on old socket after client rebind.
- Fresh CID per path (RFC §9 SHOULD): intentionally not implemented (see RFC Constraints above).
- Pre-AEAD DoS protection: a migration-capable server cannot drop packets from unknown sources before AEAD, because any new source address could be a legitimate migration candidate — the first packet from that address is what establishes it as a candidate. Dropping it would break migration. The only pre-AEAD filter that doesn't require record parsing (to extract the CID) is per-source rate limiting, which is a production concern beyond the scope of this implementation. AEAD is the effective DoS gate: forged packets are discarded by the library at negligible cost.
