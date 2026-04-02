# Failure Analysis: DTLS 1.3 proxy - 3d, HRR+cookie exchange

**Test parameters:** drop=8, delay=8, duplicate=8, hs_timeout=500-20000, max_resend=5  
**Seed:** 1775047209  
**Outcome:** client times out in ENCRYPTED_EXTENSIONS state; server times out in CLIENT_FINISHED state

---

## Message-by-Message Timeline

Time values are ms from proxy log. "→" = forwarded, "~" = delayed, "×" = dropped, "2×" = duplicated.

| Time (ms) | Actor  | Event                                                                 | Notes |
|-----------|--------|-----------------------------------------------------------------------|-------|
| 0         | Client | **Sends** ClientHello[0] (msg_seq=0, epoch=0, 203 B)                 | First CH, no cookie |
| 0         | Proxy  | ClientHello[0] (203 B) → Server                                       | forwarded |
| 0         | Proxy  | ClientHello[0] (203 B) ~ delayed                                      | duplicate delayed copy |
| 0         | Server | **Receives** ClientHello[0], no cookie → sends **HRR** (msg_seq=0, epoch=0, 115 B) | |
| 0         | Proxy  | HRR/ServerHello (115 B) → Client                                      | forwarded |
| 0         | Proxy  | HRR/ServerHello (115 B) 2× Client                                     | duplicated |
| 0         | Client | **Receives** HRR, clears CH[0] flight, advances in_msg_seq to 1       | |
| 0         | Client | **Sends** ClientHello[1] (msg_seq=1, epoch=0, 306 B) + retransmits CH[0] (seq=1) as initial flight item | |
| ~0        | Proxy  | ClientHello[1] (306 B) → Server                                       | forwarded |
| ~0        | Proxy  | ClientHello[0] delayed copy (203 B) → Server                         | delayed copy now delivered |
| ~0        | Server | **Receives** CH[0] delayed copy (msg_seq=0): **out-of-sequence**, drops it | expected msg_seq=1 |
| ~0        | Server | **Receives** CH[1] (msg_seq=1): **cookie verified**, proceeds to full handshake | |
| ~0        | Client | **Receives** duplicate HRR (msg_seq=0): **out-of-sequence** (expected 1), drops | |
| ~0        | Client | Timeout (500 ms) → retransmits CH[1] at epoch=0, seq=3 and seq=4     | |
| ~1516     | Client | **Receives** (delayed) second copy of CH[1] (306 B) back: ignored (own packet?) | |
| ~1516     | Proxy  | CH[1] (306 B) ~ delayed                                               | another delayed copy |
| ~1517     | Proxy  | CH[1] (306 B) → Server                                               | forwarded |
| ~1517     | Server | **Sends** ServerHello (msg_seq=1, epoch=0, 115 B) → real ServerHello (not HRR) | |
| ~1517     | Proxy  | Unknown/ACK (15 B) → Client                                          | server ACK |
| ~1518     | Proxy  | ServerHello (115 B) → Client                                         | forwarded |
| ~1526     | Proxy  | ServerHello (176 B) → Client                                         | **EncryptedExtensions** (epoch=2) |
| ~1527     | Proxy  | ApplicationData (37 B) → Client                                      | Certificate fragment (epoch=2) |
| ~1527     | Proxy  | ApplicationData (885 B) → Client                                     | Certificate (epoch=2) |
| ~1541     | Proxy  | ApplicationData (309 B) → Client                                     | CertificateVerify (epoch=2) |
| ~1541     | Proxy  | ApplicationData (69 B) → Client                                      | Finished (epoch=2) |
| ~1518     | Client | **Receives** ServerHello (msg_seq=1, 115 B): **accepted**, clears CH[1] flight | flight=NULL from here |
| ~1526     | Client | **Receives** ServerHello/EncryptedExtensions (176 B, epoch=2): **bad MAC** | **BUG A** — see below |
| ~1527     | Client | **Receives** ApplicationData (37 B, epoch=2): **bad MAC**            | **BUG A** |
| ~1527     | Client | **Receives** ApplicationData (885 B, epoch=2): **bad MAC**           | **BUG A** |
| ~1541     | Client | **Receives** ApplicationData (309 B, epoch=2): **bad MAC**           | **BUG A** |
| ~1541     | Client | **Receives** ApplicationData (69 B, epoch=2): **bad MAC**            | **BUG A** |
| ~1526     | Client | **Receives** ServerHello (176 B, epoch=0): epoch mismatch (expected 2), drops | **BUG B** — delayed HRR duplicate |
| ~2048     | Server | Timeout → retransmits flight: epoch=0 seq=5,6 (ServerHello), epoch=2 seq=4–7 (EE+Cert+CV+Fin) | |
| ~2048     | Proxy  | ServerHello (115 B) × dropped                                        | |
| ~2048     | Proxy  | ServerHello (176 B) → Client                                         | epoch=0, seq=6 |
| ~2048     | Proxy  | ApplicationData (37 B) → Client                                      | epoch=2, seq=4 |
| ~2048     | Proxy  | ApplicationData (885 B) → Client                                     | epoch=2, seq=5 |
| ~2049     | Proxy  | ApplicationData (309 B) → Client                                     | epoch=2, seq=6 |
| ~2049     | Proxy  | ApplicationData (69 B) → Client                                      | epoch=2, seq=7 |
| ~2048     | Client | ServerHello (176 B, epoch=0): epoch mismatch (expected 2), drops     | |
| ~2048     | Client | ApplicationData (37 B, epoch=2): **bad MAC**                         | **BUG A** |
| ~2048     | Client | ApplicationData (885 B, epoch=2): **bad MAC**                        | **BUG A** |
| ~2049     | Client | ApplicationData (309 B, epoch=2): **bad MAC**                        | **BUG A** |
| ~2049     | Client | ApplicationData (69 B, epoch=2): **bad MAC**                         | **BUG A** |
| ~2500     | Client | Timeout → `mbedtls_ssl_resend`: **no flight to retransmit** → timer cancelled, not re-armed | **BUG C** |
| ~3056–33099 | Server | 4 more retransmit rounds (1s, 2s, 4s, 8s intervals), same pattern    | all epoch=2 records → bad MAC on client |
| ~33099    | Server | Timeout (max_resend=5 exceeded) → `MBEDTLS_ERR_SSL_TIMEOUT`          | handshake fails |
| ~2500+    | Client | Receiving server retransmits but all bad-MAC, exhausts max retransmit count → `MBEDTLS_ERR_SSL_TIMEOUT` | |

---

## Identified Bugs

### BUG A — epoch=2 records arrive with bad MAC immediately after ServerHello

**What happens:** The server sends its full flight in order: ServerHello (epoch=0) then
EncryptedExtensions through Finished (epoch=2). The proxy forwards all of them. The client
receives the ServerHello first (at line 222 in client log), processes it, advances to
`ENCRYPTED_EXTENSIONS` state. Then immediately receives the already-queued epoch=2 records —
but they all fail MAC verification.

**Why bad MAC:** The server's epoch=2 flight items were encrypted using the server's
application-traffic keys derived from the *first* complete handshake context (after
receiving CH[1] at t≈1516). However, the client received a *second* ServerHello before
those records arrived (there was a retransmit of CH[1] that the server also processed,
re-running the handshake from scratch on the server side — see proxy log lines 14–17 vs
26–27). The epoch=2 records in flight were encrypted with the *first* server handshake
context; the client's epoch=2 keys were derived from the *second* handshake. Keys don't
match → bad MAC on every epoch=2 record.

**Root cause:** The server processes CH[1] **twice** — once at t≈0 (from the first
forwarded copy) and once at t≈1517 (from a delayed copy). The first pass produces a
complete flight and sends it. Then a second copy of CH[1] arrives and the server starts
over (the `=> handshake` at server log line 97 shows a second pass). The second
ServerHello and its epoch=2 flight use *fresh* keys. The client ultimately receives the
second ServerHello (which it accepts) but the epoch=2 records it receives are from the
*first* pass with mismatched keys.

This is a **key-mismatch between client and first server pass** caused by the server
executing the handshake twice for the same client. RFC 9147 §4.2.1 requires the server to
use a cookie to confirm client reachability before processing a second full CH — this test
has `cookies=1` (groups=secp384r1 forces HRR which forces cookie). However the server
apparently starts a second full handshake on receiving the delayed CH[1] copy *after*
having already sent its flight. This may indicate the server does not properly discard
a retransmit of a message it already processed at the same msg_seq.

### BUG B — delayed epoch=0 HRR/ServerHello retransmit arrives after client expects epoch=2

**What happens:** Proxy delays a copy of the ServerHello (epoch=0, seq=6) and delivers
it while the client is already in `ENCRYPTED_EXTENSIONS` (epoch=2). Client logs:
`record from another epoch: expected 2, received 0` — correctly drops it.

**This is correct behavior** — the epoch-mismatch discard is right. However the volume of
these spurious epoch=0 records hitting the client contributes to timer noise and masks the
arrival of the real epoch=2 records (BUG A makes those useless anyway). Not a code bug, but
a stress factor that interacts badly with BUG A.

### BUG C — client timer not re-armed after "no flight to retransmit"

**What happens:** After the client times out in `ENCRYPTED_EXTENSIONS` state, `mbedtls_ssl_resend`
is called, finds `flight == NULL`, sets `retransmit_state = RETRANS_WAITING`, and returns.
At this point (ssl_msg.c:2130) the timer was already cancelled with `set_timer(ssl, 0)`.
`mbedtls_ssl_resend` does not re-arm the timer. The next `f_recv_timeout` call uses
`retransmit_timeout` (the doubled value) as its timeout argument directly, not via the
timer mechanism — so it works once, but subsequent calls after receiving records reset
and eventually the client loops with a permanently expired state.

**Actual impact in this trace:** The client does continue receiving records after
each "no flight" timeout (because `f_recv_timeout` uses `retransmit_timeout` as a
direct timeout, not the timer). The real failure driver is BUG A (bad-MAC records).
BUG C contributes to the client being unable to trigger any meaningful retransmit
response to the server's retransmits, accelerating the timeout.

---

## Root-Cause Summary

The primary failure is **BUG A**: the server processes the same second ClientHello twice
(from a delayed proxy duplicate), generating two sets of epoch=2 keys. The client
synchronises with the *second* set; all epoch=2 records from the *first* set arrive with
bad MAC. The connection cannot recover because the correctly-keyed records never arrive
(they were either dropped by the proxy on the second pass, or the server's second-pass
flight is retransmitted at even later timeouts when the client has already given up).

**BUG C** is a real but lower-priority issue: the timer management in the "no flight to
retransmit" path is incorrect, but in this specific trace it is not the proximate cause
of the failure.

---

## RFC 9147 Alignment

### BUG A — RFC 9147 §5.8.1 item 3 and §5.2

**§5.8.1 item 3** (WAITING state, retransmitted peer flight):
> "When a DTLS implementation in the WAITING state reads a retransmitted flight from
> the peer when none of the messages that it sent in response to that flight have been
> acknowledged: transitions to SENDING state, where it retransmits the flight."

A duplicate CH[1] (msg_seq=1, already consumed, `in_msg_seq` now 2) arriving while the
server is in WAITING with an unsatisfied outgoing flight is exactly "a retransmitted
flight from the peer." The RFC mandates retransmitting the server's own flight.
Re-running the handshake (and re-deriving epoch=2 keys) is non-compliant.

**§5.2** (message_seq processing):
> "If `message_seq` is less than the `next_receive_seq` value: MUST discard without
> further processing."

After advancing `in_msg_seq` to 2, a CH[1] at msg_seq=1 has msg_seq < next_receive_seq
and MUST be discarded without being passed to handshake logic — not re-processed.

### BUG C — RFC 9147 §5.8.1 item 1

**§5.8.1 item 1** (WAITING state, timer expiry):
> "Upon timer expiry: retransmits the flight, adjusts and **re-arms** the retransmit
> timer."

Re-arming is explicit and mandatory. In the `flight == NULL` case the endpoint cannot
retransmit (no flight), but the timer must still be re-armed so the WAITING state
persists with an active timer until an incoming message advances the state.

---

## Fix Direction

**BUG A:** In `ssl_msg.c`, the DTLS 1.3 duplicate-message handler (the block entered
when `recv_msg_seq < in_msg_seq` while in WAITING) must check whether
`retransmit_state == RETRANS_WAITING && flight != NULL` and, if so, retransmit the
existing flight instead of falling through to ACK scheduling. The server currently
skips the retransmit path for all DTLS 1.3 duplicates (comment: "ACK-driven"), but
RFC §5.8.1 item 3 requires flight retransmission on duplicate-peer-flight regardless
of the DTLS version.

**Implementation:** `library/ssl_msg.c` in the `recv_msg_seq != in_msg_seq` block,
before the existing DTLS 1.2 `in_flight_start_seq - 1` check: add a DTLS 1.3-specific
branch that calls `mbedtls_ssl_resend()` when `retransmit_state == RETRANS_WAITING &&
flight != NULL`.

**BUG C:** In `mbedtls_ssl_flight_transmit`, when `flight == NULL`, add
`mbedtls_ssl_set_timer(ssl, ssl->handshake->retransmit_timeout)` before returning so
the timer is re-armed per RFC §5.8.1 item 1.

**Implementation:** `library/ssl_msg.c` in the `flight == NULL` early-return path
(RETRANS_WAITING branch at the top of `mbedtls_ssl_flight_transmit`).
