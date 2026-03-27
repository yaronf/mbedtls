# DTLS 1.3 3d Test: Statistical Analysis of Failure Under drop=5 delay=5 duplicate=5

**Date:** 2026-03-27

---

## Setup

Test parameters (from `DTLS 1.3: proxy — 3d, basic handshake`):

- `drop=5 delay=5 duplicate=5`
- `hs_timeout=500-20000` (min 500ms, max 20000ms) — **see naming note below**
- `client_needs_more_time 4` (watchdog ×4, irrelevant to protocol budget)

### Naming note: `hs_timeout` is the retransmit timer, not a handshake deadline

`hs_timeout` is inherited from DTLS 1.2 (RFC 6347 §4.1.1.1). The name is misleading:
it is **not** a wall-clock deadline on the whole handshake. It is the initial value
of the **per-flight retransmit timer on the sender side** — how long a sender waits
before retransmitting its current outgoing flight if no response arrives. After each
timeout, the timer doubles (exponential backoff) up to `hs_timeout_max`, at which
point the **sender** gives up and fails the handshake.

The receiver has no corresponding deadline — it simply waits for the next incoming
datagram indefinitely (or until its own outgoing flight times out). The two sides'
timers are independent and unsynchronized. Either side can exhaust its retransmit
budget first, regardless of the other side's state.

The actual maximum handshake duration is an emergent property of the retransmit
schedule, not an explicit parameter. With `hs_timeout=500-20000`, the sequence is
500→1000→2000→4000→8000→16000→20000ms (capped), giving a total budget of ~51
seconds before either side's sender gives up (see Retransmit Budget table below).

`client_needs_more_time 4` multiplies the **test watchdog** deadline by 4. This
prevents the test harness from killing a slow process, but has no effect on the
protocol's retransmit budget — the SSL `hs_timeout_max` is unchanged.

---

## Proxy Mechanics

### Per-datagram decision tree

For each arriving datagram the proxy runs this decision tree in order.
ApplicationData and CID records are always forwarded unconditionally; only handshake
datagrams are subject to the rules below. The probabilities below assume `drop=5
delay=5 duplicate=5`; with other values, substitute 1/N for each parameter.

1. **Drop** with probability 1/5 → datagram is silently discarded.
2. **Else delay** with probability 1/5 → datagram is queued in a buffer of up to 5
   entries and flushed to the destination the next time any datagram is forwarded
   (i.e. the delay duration is one "forward event", not a wall-clock duration).
3. **Else forward** → delivered immediately; then independently:
   **Duplicate** with probability 1/5 → the same datagram is sent a second time.

Drop and delay are mutually exclusive (else-if chain). Duplicate is an independent
check that only applies to forwarded packets.

### The `held[]` anti-starvation mechanism

Without a safety valve, drop=5 could theoretically prevent a datagram from ever
getting through (probability (1/5)^N for N consecutive drops). The `held[]` array
prevents this.

`held[]` is a global array of 2048 counters. Each datagram is mapped to a counter
by `datagram_size % 2048` — i.e. all datagrams of the same byte-length share the
same counter, regardless of direction or content. The counter is called `held[id]`.

**The rule:** drop and delay are only permitted when `held[id] < HOLD_MAX` where
`HOLD_MAX = 2`. Each time a datagram of size S is dropped or delayed, `held[S%2048]`
is incremented. Once the counter reaches 2, all subsequent datagrams of the same
size are **always forwarded**, regardless of the drop/delay random outcome.

**Consequences:**
- Any given datagram size can be interfered with at most twice before it is
  guaranteed through. Permanent loss of a flight due to drops alone is impossible.
- The counter is **never reset** during a session. Once `held[id]` reaches 2 for
  a given size, all datagrams of that size pass freely for the rest of the session.
- The counter is **shared across both directions** and across all retransmits.
  If server→client and client→server datagrams happen to be the same size, they
  share a counter. A server datagram being dropped or delayed increments the
  same counter as a client datagram of that size — so server interference
  actually helps the client: the counter reaches 2 sooner, after which all
  same-size datagrams (including the client's) are always forwarded.
- The counter is **not per-message** or per-sequence-number. All ClientHello
  retransmits have the same size and thus share the same counter. After two
  ClientHello-sized datagrams have been held, all subsequent ones pass freely —
  including retransmits from later in the handshake if they happen to be the same
  size.

**Practical effect with drop=5 delay=5:**
The first two datagrams of any given size that arrive at the proxy face a combined
~36% chance of being held (drop + delay). After two have been held, the remainder
pass freely. So the worst case for any single flight is two consecutive holds, which
happens with probability (1/5)² = 4%. Beyond that the path is clear.

---

## DTLS 1.3 Basic Handshake Flight Structure

A full 1-RTT certificate-based handshake has these flights:

```
Client                          Server
  |--- Flight 1: CH ----------->|   1 datagram (epoch 0, plaintext)
  |                              |
  |<-- Flight 2: SH+EE+CV+SF --|   2-4 datagrams (SH epoch 0; EE+CV+SF epoch 2)
  |--- ACK (empty, epoch 0) --->|   triggers early server retransmit if needed
  |                              |
  |--- Flight 3: CF ----------->|   1 datagram (epoch 2, encrypted)
  |<-- ACK ----------------------|   (server ACKs CF; not strictly required by spec)
```

Flight 2 is the critical one: ServerHello is plaintext (epoch 0), the rest are
encrypted (epoch 2). The client sends an empty ACK after processing Flight 2 to
tell the server it received it.

**Records per flight:**
- Flight 1 (CH): 1 datagram, 1 record
- Flight 2 (SH+EE+CertVerify+SF): typically 2–3 datagrams with `dgram_packing=0`
  (one record per datagram): ServerHello, EncryptedExtensions, Certificate,
  CertificateVerify, ServerFinished — 5 records, 5 datagrams
- ACK from client: 1 datagram (epoch 0, plaintext)
- Flight 3 (CF): 1 datagram, 1 record
- ACK from server: 1 datagram

Total in-flight datagrams across the full handshake: ~10

---

## Retransmit Budget

The total budget before handshake failure is:
`sum(min * 2^i for i in 0..N-1) + max`, where N is the number of doublings before
hitting `max`. With `hs_timeout=500-20000`, the retransmit sequence is:

| Attempt | Wait before retransmit | Cumulative time |
|---------|------------------------|-----------------|
| 0       | (initial send)          | 0               |
| 1       | 500 ms                  | 0.5 s           |
| 2       | 1000 ms                 | 1.5 s           |
| 3       | 2000 ms                 | 3.5 s           |
| 4       | 4000 ms                 | 7.5 s           |
| 5       | 8000 ms                 | 15.5 s          |
| 6       | 16000 ms                | 31.5 s          |
| 7       | 20000 ms (capped)       | 51.5 s          |
| 8       | — already at max → TIMEOUT | —            |

So a side has **7 retransmit attempts** before the handshake fails, with a total
budget of ~51.5 seconds. After the second retransmit, MTU auto-reduces to 508 bytes
(RFC 6347 §4.1.1.1).

**ACK and the retransmit budget:** A partial ACK triggers immediate selective
retransmission of unacknowledged items and resets `retransmit_timeout` to
`hs_timeout_min` (per RFC 9147 §7.3 and our fix). A full ACK (all items
acknowledged) cancels the retransmit timer entirely. An ACK therefore does
restore budget for the current flight — confirmed progress gives the sender a
fresh doubling sequence.

---

## Failure Probability Analysis

### Single datagram survival probability

For one datagram, using the proxy decision tree:

- P(drop) = 1/5 = 0.20 (provided `held < 2`)
- P(delay | not dropped) = 1/5 = 0.20
- P(forward) = 1 - P(drop) - P(delay) ≈ 0.64 on first attempt

But after being held once (`held=1`), the same datagram on its next transmission:
- P(drop) = 1/5 still applies (held < 2)
- After being held twice (`held=2`), it is **always forwarded** regardless

So each unique datagram is delivered within at most 3 transmission attempts at the
proxy level (held at most twice). The proxy alone does not cause permanent loss.

**The real failure mode is retransmit budget exhaustion.**

**Why retransmits use a new record sequence number:** DTLS requires each transmitted
record to carry a monotonically increasing sequence number, even if it is a
retransmit of the same handshake message. This is mandated by the anti-replay
mechanism: the receiver maintains a sliding window of seen sequence numbers and
silently discards any record whose sequence number falls within that window. Without
this rule a replayed record — delivered late by the network after the original was
already processed — would be accepted and interpreted as a new message. So yes,
every retransmit is a new record with a new sequence number, even though the
payload is identical.

This means duplicate delivery (via the proxy's duplicate=5 feature) does not cause
re-processing: if seq=N is delivered twice, the receiver processes it once and
records seq=N in the anti-replay window; the second copy is silently discarded.

The problematic interaction occurs when duplicates and drops combine:

1. Client sends CH at seq=N.
2. Proxy duplicates it → server receives seq=N twice, processes once, sends reply.
3. Server's reply is dropped by proxy. Client times out and retransmits seq=N+1.
4. Proxy duplicates seq=N+1 → server processes once, sends reply.
5. Server's reply is dropped again. Client retransmits seq=N+2.
6. Proxy drops seq=N+2 (P=1/5). held[id] becomes 1.
7. Client retransmits seq=N+3. Proxy drops again (P=1/5). held[id] becomes 2.
8. Client retransmits seq=N+4. held[id]=2 → always forwarded. Server processes,
   sends reply. If the reply also gets through, the handshake proceeds.

Steps 6–7 each consume one timer doubling cycle. By step 8, the client's
retransmit timer has already doubled twice (from 500ms to 2000ms), and if the
reply at step 8 is also dropped, it doubles again to 4000ms. The held[] mechanism
guarantees eventual delivery of the client datagram, but does not guarantee the
server's reply will also get through. Each round trip requires **both** directions
to succeed.

**Probability of exhausting the budget on one flight:**
Each round trip succeeds only if both the client datagram and the server reply
get through the proxy. P(round trip succeeds) ≈ 0.64² ≈ 0.41. P(round trip
fails) ≈ 0.59. For all 7 retransmit attempts on one flight to fail:
(0.59)^7 ≈ 1.6%. With 3 independent flights: P(any one exhausts budget) ≈
1 - (1 - 0.016)^3 ≈ 4.7%.

This is lower than the observed ~20% failure rate, which is explained by the
cumulative budget exhaustion model in the next section.

### Root cause: bi-directional stall at the final flight

The held[] mechanism guarantees the client's datagram eventually gets through
(at most 2 consecutive holds). The real failure mode is not permanent datagram
loss but **bi-directional stall at the final flight boundary**.

Observed in seed=53 server log: client at `CLIENT_FINISHED` state retransmitting
its final flight (seq=41,42), server also at `CLIENT_FINISHED` state retransmitting
its Finished flight, but neither side's retransmit gets through simultaneously.
Both sides burn their retransmit budgets waiting for acknowledgement of their own
last flight.

For a stall to persist, BOTH directions must fail on the same retransmit cycle:
- P(one direction fails) ≈ 0.36 (drop + delay)
- P(both directions fail simultaneously) ≈ 0.36² ≈ 0.13

For k consecutive stall cycles: (0.13)^k. For 3 cycles: ~0.2%. For 2 cycles: ~1.7%.

This still does not cleanly explain a 20% failure rate in isolation. The doubling
timer is the amplifier: once a side has burned through 500ms + 1000ms + 2000ms
on one flight, it has only 4s + 8s + 16s + 20s remaining. A second flight that
also encounters even one or two stall cycles can push total elapsed time past the
~51s budget. The failures are not individual catastrophic stalls — they are
cumulative budget exhaustion across multiple flights each experiencing modest delay.

---

## Conclusion

The ~20% observed failure rate is **higher than the per-flight model predicts**
(~4.7% per run assuming 3 independent flights, each with P(exhaust) ≈ 1.6%).
The model likely underestimates because independence between flights does not
hold: the proxy's `held[]` counters accumulate across the session, and
flight-level interactions (e.g. server retransmitting while client is also
retransmitting) create correlated failures not captured by the single-flight model.

Key fix applied (commit on branch `dtls13`):

**ACK reset is now gated on actual progress.** A partial ACK listing at least
one newly-acknowledged record triggers an immediate retransmit and resets
`retransmit_timeout` to `hs_timeout_min` — confirmed progress justifies a
fresh doubling sequence. An empty ACK (no record numbers) or one listing only
already-seen records does not reset the timer, as it carries no evidence of
forward progress. This is consistent with RFC 9147 §7.3 and avoids spurious
retransmits on empty ACKs (which the client sends during Flight 2 processing
before it has the epoch-2 keys to decrypt the server's records).

Note: `send_flight_completed()` already resets `retransmit_timeout` to
`hs_timeout_min` at each flight transition, so there is no shared budget
across flights — each flight starts with a full 7-attempt doubling sequence.

**`client_needs_more_time 4` is irrelevant to the protocol.** It only extends
the test watchdog. The SSL retransmit budget is fixed by `hs_timeout_max=20000ms`
regardless. The total handshake budget (~51s) is entirely determined by the
retransmit schedule, not by any watchdog setting.
