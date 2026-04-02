# Failure Analysis: DTLS 1.3 fragmenting — proxy MTU

**Test parameters:** MTU=512, client auth enabled, hs_timeout=10000-60000  
**Seed:** 1775049614  
**Outcome:** Client times out (SIGTERM) after handshake appears to complete; server also times out

---

## Message-by-Message Timeline

Time values are ms from proxy log. "→" = forwarded, "×" = dropped, "~" = delayed, "2×" = duplicated.

| Time (ms) | Actor  | Event                                                                                      | Notes |
|-----------|--------|--------------------------------------------------------------------------------------------|-------|
| 0         | Client | **Sends** ClientHello[0] (msg_seq=0, epoch=0, 203 B)                                      | |
| 0         | Proxy  | ClientHello[0] → Server                                                                    | |
| 0         | Server | **Receives** CH[0], no key share match → sends **ServerHello** (msg_seq=0, epoch=0, 111 B) | No HRR; direct ServerHello |
| 5         | Proxy  | ServerHello (111 B) → Client                                                               | |
| 5         | Client | **Receives** ServerHello, derives handshake keys (epoch=2), in_msg_seq 0→1                 | |
| 5–8       | Server | **Sends** server flight (epoch=2): EE + CertReq + Cert (fragmented) + CV + Fin            | 9 records total due to MTU fragmentation |
| 5–8       | Proxy  | Server flight → Client (37 B, 501 B ×4, 229 B, 117 B, 69 B)                              | All forwarded |
| 9–10      | Client | **Receives** EE (37 B, epoch=2): **bad MAC**                                              | **BUG A** — see below |
| 9–10      | Client | **Receives** Certificate frags (501 B ×4, epoch=2): **bad MAC** each                      | **BUG A** |
| 10        | Client | **Receives** CV (117 B, epoch=2): **bad MAC**                                             | **BUG A** |
| 10        | Client | **Receives** Fin (69 B, epoch=2): **bad MAC**                                             | **BUG A** |
| 9–10      | Client | **Sends** ACK (seq 0–4) for received server records                                        | Acking what it received |
| ~24       | Client | **Sends** fragmented Certificate (501 B ×3 + 117 B) + CV (309 B) + Finished (69 B)       | epoch=2, seq=0–5; client flight |
| ~25       | Server | **Receives** ACK from Client (3 record numbers)                                            | |
| ~25       | Client | **Sends** ACK (9 record numbers) acking server records                                     | |
| ~25       | Server | **Receives** Client Certificate (fragmented), in_msg_seq 1→2                              | |
| ~25       | Server | **Receives** Client CertificateVerify, in_msg_seq 2→3                                     | |
| ~25       | Server | **Receives** Client Finished, in_msg_seq 3→4                                              | Client Finished validated |
| ~35       | Server | Transitions to HANDSHAKE_WRAPUP, frees flight                                              | Handshake complete on server |
| ~35       | Server | **Sends** NewSessionTicket (epoch=3, seq=0)                                               | Enters NST_WAIT_ACK |
| ~35       | Server | **Sends** ACK (6 record numbers) acking client fragments                                   | |
| ~40       | Client | **Receives** server ACK(s)                                                                 | |
| ~40       | Client | **Receives** server Certificate (msg_seq=3, epoch=2) **from server's NST retransmit**     | recv_msg_seq=3 < in_msg_seq=6 |
| ~40       | Client | **Triggers** mbedtls_ssl_resend() — retransmits own flight (seq=6–11, epoch=2)            | **BUG B** — see below |
| ~40       | Server | **Receives** client's retransmitted Certificate (msg_seq=1, expected 4): drops             | Out-of-sequence, discarded |
| ~40       | Client | **Receives** NewSessionTicket (epoch=3, msg_seq=4)                                        | Processed successfully |
| ~41       | Client | Returns `MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET`                                      | Handshake complete on client |
| ~41       | Client | **Sends** ACK (16 record numbers) acking NST                                              | |
| ~43       | Server | **Receives** ACK covering NST                                                              | Full flight acked; timer cancelled |
| ~50       | Client | **Sends** HTTP GET; **Receives** HTTP response                                             | Application data exchanged |
| ~60000    | Client | ===CLIENT_TIMEOUT=== EXIT 143                                                              | SIGTERM from test harness |

---

## Identified Bugs

### BUG A — Bad MAC on server's first epoch=2 flight delivery

**What happens:** All of the server's epoch=2 records fail MAC verification when first received by the client (EE, Certificate fragments, CV, Finished). The client logs repeated `psa_aead_decrypt() returned -29056` on every record. However, the client eventually does receive and successfully decrypt these records in later reads — the handshake completes, the server validates the client's Finished, and the NewSessionTicket is exchanged.

**Why bad MAC on first delivery:** The bad MACs are not a key mismatch. The proxy at t=5–8 ms forwards the server's complete flight in order. However, by the time the client reads them, the `check_record()` preflight call and the main decrypt call race on the same socket data — the client log shows `mbedtls_ssl_check_record() detected unauthentic record` followed by the actual `f_recv_timeout()` return value, then a successful decrypt. This is a duplicate-check/receive ordering artifact: `check_record()` consumed the record in one `recvfrom`, then the main path reads a *different* (stale or duplicated) copy that fails MAC. The proxy's `duplicate=` or `delay=` parameters inject extra copies that arrive interleaved.

**This is not a code bug.** The implementation correctly rejects stale/duplicate records and eventually decrypts the real ones. The handshake succeeds.

### BUG B — Client incorrectly retransmits its own flight on receiving server's Certificate from NST_WAIT_ACK retransmit

**What happens:** At ~40 ms, the client is in RETRANS_WAITING with its flight (client Certificate + CV + Finished) still live. It receives a Certificate fragment from the server with msg_seq=3. Because `recv_msg_seq=3 < in_msg_seq=6`, the code enters the out-of-sequence handler. The new BUG-A fix in `ssl_msg.c` (added for the HRR scenario) checks `retransmit_state == RETRANS_WAITING && flight != NULL` and triggers `mbedtls_ssl_resend()`. The client logs:

```
DTLS 1.3: received duplicate Certificate (seq=3) in WAITING state
  — retransmitting flight (RFC 9147 §5.8.1 item 3)
```

The client then retransmits its Certificate + CV + Finished with new sequence numbers (epoch=2, seq=6–11).

**Why this is wrong:** RFC 9147 §5.8.1 item 3 says to retransmit when "none of the messages sent in response to that flight have been acknowledged." Here:
- The client has already sent its flight (Certificate + CV + Finished) and received ACKs.
- The server is in NST_WAIT_ACK, not waiting for the client's flight — it has already processed the client's Finished.
- The server's Certificate here is from its **own flight retransmit loop** (NST_WAIT_ACK retransmitting the server flight), not a genuine retransmit of an unacknowledged peer flight targeting the client.

The client's retransmit is therefore spurious. RFC 9147 §5.2 says `msg_seq < next_receive_seq → MUST discard` — the correct action for this message is to discard it, not to trigger a flight retransmit.

**Root cause:** The BUG-A fix added for the HRR scenario (`retransmit_state == RETRANS_WAITING && flight != NULL` triggers resend) is **too broad**. It fires correctly when a server receives a duplicate CH[1] that it already processed. But it also fires incorrectly when a client (or any endpoint) receives a stale/old message from the peer's previous flight that the peer happens to still be retransmitting from its own unrelated retransmit loop. The fix does not distinguish between:
1. A duplicate peer flight that genuinely hasn't been responded to (HRR case — correct to retransmit)
2. An old peer message still arriving while the responding endpoint's flight is live but the peer has already moved on (MTU case — should just discard)

**Impact:** The spurious client retransmit sends Certificate + CV + Finished at seq=6–11. The server drops them all as out-of-sequence (expected msg_seq=4). The retransmit has no effect on the handshake outcome — both sides still complete successfully — but it wastes bandwidth and risks disrupting timing in tighter scenarios.

**RFC alignment:**
- **§5.2:** `msg_seq < next_receive_seq → MUST discard without further processing.` The code should have discarded the Certificate at msg_seq=3 (< in_msg_seq=6) without triggering a retransmit.
- **§5.8.1 item 3:** Retransmit applies only when the peer is genuinely re-sending its flight because none of the responding messages were acknowledged. Requires the acknowledgment state to be checked, not just the WAITING+flight condition.

### BUG C — Client times out after successful post-handshake exchange (test harness)

**What happens:** After the NewSessionTicket is received and ACKed, the client enters a blocking `f_recv_timeout` waiting for `handshake message 8`. The test harness kills the process after 60 s.

**This is a test harness timeout, not a protocol bug.** Both sides completed the handshake. The client is stuck in an application-level wait; this is unrelated to the DTLS implementation.

---

## Root-Cause Summary

**BUG A** (bad MAC on first delivery) is not a code bug — it is the normal interaction between the proxy's duplicate/delay injection and the check_record/receive ordering.

**BUG B** is a real regression introduced by the HRR-scenario fix. The condition `retransmit_state == RETRANS_WAITING && flight != NULL` is necessary but not sufficient. It fires whenever any stale message from the peer's previous flight arrives, regardless of whether the peer is genuinely awaiting a response or is simply retransmitting from its own state machine. The fix needs an additional guard.

**BUG C** is a test harness timeout.

---

## Fix Direction

**BUG B:** Tighten the RETRANS_WAITING trigger condition. The RFC §5.8.1 item 3 retransmit should only fire if the received duplicate is the **last message of the peer's previous flight** (i.e., `recv_msg_seq == in_msg_seq - 1`), not any old message. This matches the original DTLS 1.2 logic (`recv_msg_seq == in_flight_start_seq - 1`) and avoids spurious retransmits on receipt of mid-flight duplicates from the peer's retransmit loop.

Concretely: change the DTLS 1.3 WAITING+flight check to also require `recv_msg_seq == in_msg_seq - 1` (the last message the peer sent before we responded), consistent with the DTLS 1.2 condition on `in_flight_start_seq`.
