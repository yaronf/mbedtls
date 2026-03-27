# DTLS 1.3: "proxy — 3d, nbio" Flakiness

## Problem Statement

The test `DTLS 1.3: proxy — 3d, nbio` fails intermittently (~40% of runs in recent stress
testing: 2 of 5 failed).  The failure is always `bad client exit code (expected 0, got 1)`,
meaning the client handshake times out.

Test parameters:
```
proxy:  drop=5 delay=5 duplicate=5   (each packet independently: 20% drop, 20% delay, 20% dup)
server: dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 nbio=2 debug_level=2
client: dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 nbio=2 debug_level=2
```

---

## Root Cause Analysis

### What actually happens in a failing run

1. **t=0 ms** — Client sends ClientHello.  Proxy forwards it (and may duplicate it).
2. **t=~7 ms** — Server responds with flight 1 (ServerHello + EncryptedExtensions +
   Certificate + CertificateVerify + Finished).  The proxy **drops** ServerHello
   but forwards the epoch-2 records (EE, Cert, CertVerify, Finished).
3. **t=~7 ms** — Client receives the epoch-2 records.  At this point the client is in
   `SERVER_HELLO` state (epoch 0 expected).  It correctly discards them with
   `"record from another epoch: expected 0, received 2"`.
4. **t=500 ms** — Client retransmit timer fires; client retransmits ClientHello.
5. **t=~532 ms** — Server retransmits its flight.  The proxy now **drops** ServerHello
   again (or drops a later critical message), and may also drop the retransmitted
   epoch-2 records.
6. At each retransmit the timeout doubles (500 → 1000 → 2000 → 4000 → 8000 → 16000 → 20000 ms).
   With `hs_timeout_max=20000` there are at most ~7 retransmit levels.  Once the max is
   reached, `ssl_double_retransmit_timeout` returns -1 and the handshake is declared timed out.

### Why this is worse than it looks

The proxy applies each packet modifier **independently and uniformly**.  With `drop=5` (20%
drop rate) the probability that a specific single packet survives is 0.8.  The server's
first flight contains at minimum 3 distinct UDP datagrams that all need to reach the client
(ServerHello is epoch-0 plaintext; the rest are epoch-2).  The probability that **all**
survive one exchange is ≤ 0.8³ ≈ 51%, so there is a ≥ 49% chance of at least one drop
per exchange.

The issue is compounded by **nbio=2 (non-blocking I/O)**:

- In blocking I/O (nbio=0 or nbio=1), `ssl_read_record` waits inside `f_recv_timeout` for
  the kernel to deliver a packet.  The OS does the waiting, so the retry loop runs only when
  data actually arrives.
- In `nbio=2`, `f_recv` returns `WANT_READ` immediately if no packet is available.  The
  handshake retry loop in `ssl_client2`/`ssl_server2` spins at full CPU speed: thousands of
  `f_recv` calls per millisecond.  This has two observable effects:
  1. **Log explosion** — millions of log lines per second, making the logs useless for
     debugging.  A temporary `mbedtls_net_usleep(1000)` hack was added specifically to
     throttle the spin enough to produce readable logs during this investigation (see
     Pre-merge Cleanup in the plan).  Without it, investigating the failure at all was
     impractical.
  2. **Timing distortion** — the retransmit timer fires based on wall-clock time, but when
     the process is spinning on CPU, scheduling jitter is amplified and the effective
     retransmit interval varies widely.

### The state machine gap

After the client discards the epoch-2 records at step 3, it has **no pending data** and
returns to the spin loop.  The server's retransmitted ServerHello (t=532 ms, 111 bytes)
arrives at the client's UDP socket.  Under nbio=2, the client will pick it up only on the
next `f_recv` call — which happens immediately, since the spin is continuous.  In principle
this should work.  In practice the proxy's `delay=5` modifier (20% chance to delay each
packet by ~100 ms) can push the ServerHello past the client's next retransmit boundary,
causing both sides to independently restart the exchange with fresh random values — making
previous epoch-2 records permanently invalid.

When this cascade happens enough times to exhaust the retransmit doubling sequence
(500 → 1000 → ... → 20000 ms max), the handshake times out.

---

## Proposed Solutions

### Option A — Increase `hs_timeout_max` and add a retry wrapper in the test

**Idea:** The current `hs_timeout=500-20000` gives ~7 retransmit attempts.  With 20% per-packet
drop the geometric probability of exhausting all attempts is non-trivial.  Raising `hs_timeout`
to `500-60000` (the library default) gives ~10 attempts, dropping the per-handshake failure
probability by roughly an order of magnitude.  Additionally, wrap the test in a small retry
loop (run it up to 3 times; pass if any attempt succeeds).

**Pros:**
- Minimal code change — just test parameters.
- Does not touch the library.
- The retry wrapper pattern is already used elsewhere in ssl-opt.sh for inherently flaky tests.

**Cons:**
- Does not fix the underlying issue; just makes it less likely to surface.
- A very unlucky run can still fail 3 times in a row.
- Adds latency to the test (each failed attempt can take up to 60 s of timeout).
- The retry wrapper is a test-quality smell acknowledged in mbedtls upstream guidelines.

---

### Option B — Fix the nbio=2 event loop: use `select`/`poll` with a short timeout

**Idea:** In `programs/ssl/ssl_client2.c` and `ssl_server2.c`, replace the busy-spin
(`while (WANT_READ) { ... }`) in the nbio=2 branch with a `select()`/`poll()` call on the
underlying socket fd with a short timeout (e.g. 1 ms or the remaining DTLS retransmit
interval).  This is the correct fix for the log explosion and timing distortion.

Implementation sketch:
```c
} else if (opt.nbio == 2) {
    /* Wait up to 1 ms for data before retrying, to avoid busy-spin. */
    fd_set read_fds;
    struct timeval tv = { 0, 1000 };   /* 1 ms */
    FD_ZERO(&read_fds);
    FD_SET(server_fd.fd, &read_fds);   /* or client_fd.fd */
    select(server_fd.fd + 1, &read_fds, NULL, NULL, &tv);
}
```

**Pros:**
- Correct, not a hack.  Removes the `mbedtls_net_usleep` placeholder.
- Eliminates the timing distortion that exacerbates the drop cascade.
- Directly addresses the pre-merge cleanup item.

**Cons:**
- Requires knowing the socket fd — currently buried inside `mbedtls_net_context`.
  `mbedtls_net_context.fd` is public (`int fd` is the first member), so it's accessible
  but slightly awkward.
- Still does not change the fundamental probability of packet loss exhausting retransmits.
  Combine with Option A's timeout increase for full robustness.
- Test programs only — no library change needed.

---

### Option C — Implement selective client-side ACK / smarter retransmit in the library

**Idea:** The real problem is that when the client has received and accepted some epoch-2
records but not yet the ServerHello (which was dropped), it has no mechanism to tell the
server "I already have EE/Cert/CertVerify/Finished — just resend ServerHello."  Instead,
both sides retransmit their entire flights blindly.

DTLS 1.3 (RFC 9147 §7) defines an ACK message precisely for this case.  If the client sent
an ACK listing the records it has successfully decrypted, the server could retransmit only
what's missing.  This is Phase 3c work (ACK implementation) but would make the protocol
fundamentally more resilient, not just the test.

A lighter-weight variant: **track received-but-unusable records** on the client side, and
suppress retransmit of the corresponding server messages when the server retransmits.  This
is partial without full ACK but would shrink the effective drop surface.

**Pros:**
- Correct long-term fix; brings the implementation closer to spec.
- Makes all 3d tests (not just nbio) more robust.
- ACK is already on the roadmap (Phase 3c).

**Cons:**
- Significant library work (ACK send/receive state machine, per-epoch record tracking).
- Cannot be done before Phase 3b is closed out.
- Overkill for unblocking the current test.

---

## Recommendation

Short-term (to unblock Phase 3b): **Option B** (fix the event loop) plus increasing
`hs_timeout_max` in the test to 60000.  This removes the pre-merge cleanup item and
significantly reduces the failure probability without changing test semantics.

Long-term: **Option C** (ACK) as part of Phase 3c.  Once ACK is implemented, the 3d+nbio
test should pass reliably even with aggressive drop rates.
