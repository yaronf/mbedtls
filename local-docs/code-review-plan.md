# DTLS 1.3 Code Review Plan

**Branch:** `dtls13`
**Created:** 2026-04-03
**Status:** in progress

Each area has a focus question, specific line ranges to read, and what to look for.
Areas are ordered roughly by risk — start at the top.

---

## Area 1: Unified Record Header — parsing and construction (RFC 9147 §4.1) ✓ DONE

**Focus:** Is the epoch extraction, CID flag, and sequence number reconstruction
correct for all combinations of header bits?

**Primary code:**
- `ssl_msg.c:4573–4698` — `ssl_parse_dtls13_record_header()`: full inbound parsing
- `ssl_msg.c:1083–1121` — outbound `dtls13_unified_hdr` construction (inside `mbedtls_ssl_encrypt_buf`)
- `ssl_msg.c:4629–4657` — epoch reconstruction from 2-bit on-wire field (window arithmetic)
- `ssl_msg.c:4895–4960` — `ssl_parse_record_header()` DTLS dispatcher: epoch accept/reject logic

**What to look for:**
- Epoch bits (bits 0–1 of byte 0): correctly distinguish epoch 0 (plaintext) from epochs 1–3?
- Epoch reconstruction window arithmetic: off-by-one at boundaries (e.g. epoch 3→4 transition)?
- Outbound header byte (1107): bit packing of C/S/L/epoch bits matches RFC §4.3.3 Figure 4?
- Length field: absent means record runs to end of datagram — handled correctly?
- CID read: `cid_len` from conf, not packet — already verified safe.

---

## Area 2: Sequence Number Encryption (SNE) — key derivation and mask application (RFC 9147 §4.2.3) ✓ DONE

**Focus:** Is the SNE key derived with the correct label, and is the mask applied
at the right point (after AEAD) on both encrypt and decrypt paths?

**Primary code:**
- `ssl_tls13_keys.c:226–289` — `mbedtls_ssl_dtls13_hkdf_expand_label()`: label prefix
- `ssl_msg.c:4715–4832` — `ssl_dtls13_sne_compute_mask()`: AES-ECB and ChaCha20 mask generation
- `ssl_msg.c:4849–4872` — `ssl_dtls13_sne_apply()`: XOR application
- `ssl_msg.c:3417–3438` — outbound SNE apply call site (after AEAD encrypt)
- `ssl_msg.c:5346–5389` — inbound SNE apply call site (before seq reconstruction)

**What to look for:**
- Label string: `"dtls13sn"` (prefix `"dtls13"` + label `"sn"`, no space) — confirmed by BoringSSL vectors.
- Ciphertext sample: AES uses first 16 bytes of ciphertext; ChaCha20 uses bytes 0–15 as counter/nonce input.
- Order of operations on encrypt: AAD computed with plaintext seq, AEAD runs, *then* SNE XORs the on-wire header.
- Order on decrypt: SNE XOR applied *before* AEAD decryption.
- `sn_key` zeroized on transform free.

---

## Area 3: Epoch Pool — lifetime, eviction, and counter integrity (RFC 9147 §4.2.1) ✓ DONE

**Focus:** Are retired transforms correctly retained and evicted, and are their
sequence counters preserved accurately for retransmit?

**Primary code:**
- `ssl_msg.c:9128–9181` — `ssl_dtls13_epoch_pool_insert()`: slot eviction and insert
- `ssl_msg.c:9200–9242` — `ssl_dtls13_epoch_pool_lookup_slot()` / `ssl_dtls13_epoch_pool_free()`
- `ssl_msg.c:7581–7595` — call site where old transform is retired into pool
- `ssl_msg.c:9262–9290` — `mbedtls_ssl_set_inbound_transform()`: `in_epoch_full` sync

**What to look for:**
- Eviction policy: oldest slot evicted on overflow — could the evicted epoch still be needed for retransmit of an in-flight message?
- Counter preservation: when a slot is inserted, is the `out_ctr` for that epoch saved correctly so retransmit can resume without replaying?
- `in_epoch_full`: updated only when `dtls13_epoch != 0` — does this correctly handle the DTLS 1.2 fallback case?
- All slots freed on connection teardown — no transform leak on early abort?

---

## Area 4: KeyUpdate — ACK-pending guard and secret lifecycle (RFC 9147 §8) ✓ DONE

**Focus:** Is a second KeyUpdate correctly blocked while one is pending, and is the
pending secret handled safely from derivation through installation through zeroization?

**Primary code:**
- `ssl_msg.c:7643–7765` — `ssl_tls13_write_key_update()`: send path, sets `dtls13_ku_ack_pending`
- `ssl_msg.c:7774–7899` — `ssl_tls13_handle_key_update()`: receive path, inbound epoch install
- `ssl_msg.c:7664` — guard: block send if `dtls13_ku_ack_pending` already set
- `ssl_msg.c:7040–7057` — ACK receive: clears `dtls13_ku_ack_pending`, installs new outbound epoch
- `ssl_tls13_keys.c:2303–2404` — `mbedtls_ssl_tls13_compute_key_update_transform()`: secret derivation

**What to look for:**
- Guard at 7662: is it checked before every KeyUpdate send, including the auto-trigger path?
- Label: `HKDF-Expand-Label(secret, "traffic upd", "", hash_len)` — exact string in `ssl_tls13_keys.c`.
- Pending secret: zeroized immediately after new transform installation — including on error paths?
- New outbound epoch installed only after ACK received (7039–7056), not at send time?
- Peer-initiated KeyUpdate (7772–7898): when `update_requested`, does the reciprocal send go through the same guard?

---

## Area 5: ACK Generation and Matching (RFC 9147 §7) ✓ DONE

**Focus:** Is the ACK record correctly constructed and do received ACKs correctly
clear only the matching flight items?

**Primary code:**
- `ssl_msg.c:6689–6759` — `ssl_dtls13_write_ack()`: ACK frame construction and send
- `ssl_msg.c:6809–6927` — `ssl_dtls13_process_ack()`: ACK receive and flight-item matching
- `ssl_msg.c:6856` — KeyUpdate ACK match
- `ssl_msg.c:7039–7056` — outbound epoch install after ACK clears KeyUpdate pending

**What to look for:**
- ACK format: list of (epoch, seq_no) pairs — matches RFC §7.3?
- Matching: ACKs are record-level (epoch + seq of the *sent record*), not message-level — is the match key correct?
- Partial ACK: if only some flight items are ACKed, only those are dropped — no premature state clear?
- Handshake ACK (`dtls13_ack_pending`) vs post-handshake ACK: are both paths consistent?
- Deferred Finished ACK: sent before any application data — ordering guaranteed?

---

## Area 6: Post-Handshake Message Sequencing (RFC 9147 §5.2) ✓ DONE

**Focus:** Is `message_seq` correctly continuous across the handshake/post-handshake
boundary, and are duplicates and out-of-order messages handled correctly?

**Primary code:**
- `ssl_msg.c:3022–3024` — outbound post-HS `message_seq` stamping and increment
- `ssl_msg.c:3909–3961` — inbound `message_seq` validation and future-message handling
- `ssl_msg.c:8582–8596` — inbound seq advance after message consume
- `ssl_misc.h:1523–1549` — `mbedtls_ssl_dtls13_sync_post_hs_seq()` and `mbedtls_ssl_handshake_set_state()`: sync at `HANDSHAKE_OVER`

**What to look for:**
- RFC 9147 §5.2: `message_seq` must NOT reset at handshake end — is the sync-from-handshake correct?
- Duplicate detection: same seq received twice must be silently dropped, not error?
- Fragment resume (`dtls13_frag_off > 0`): `message_seq` must not re-increment on retry?
- KeyUpdate and NewConnectionId post-HS messages: do they correctly advance the seq counter?

---

## Area 7: Fragmentation and Retransmit Epoch Switching ✓ DONE

**Focus:** On retransmit, is the correct epoch and counter restored, and does
fragment-resume skip the epoch-stamp and seq-increment steps?

**Primary code:**
- `ssl_msg.c:2433–2495` — `ssl_dtls13_retx_epoch_switch()`: save active epoch, install flight epoch
- `ssl_msg.c:2499–2515` — `ssl_dtls13_retx_epoch_restore()`: restore after retransmit
- `ssl_msg.c:2294–2352` — epoch stamping on first send (the `dtls13_send_epoch` field, in `ssl_flight_append`)
- `ssl_msg.c:3031–3331` — fragment send loop: `dtls13_frag_off` resume guards

**What to look for:**
- Epoch stamping: happens once on first send — is there a guard preventing re-stamp on retransmit?
- Epoch restore: happens on all code paths out of retransmit loop, including error?
- Fragment resume: on WANT_WRITE retry, skips seq-stamp and epoch-stamp — does it also skip flight-item append?
- Flight item list freed on connection abort — no leak?

---

## Area 8: AEAD and Auth-Fail Limits (RFC 9147 §4.5.2–4.5.3) ✓ DONE

**Focus:** Are per-epoch counters correctly maintained, reset at epoch transitions,
and do they fire at the right thresholds?

**Primary code:**
- `ssl_msg.c:1171` — `out_record_count++` (per encrypted record sent)
- `ssl_msg.c:8948–8963` — auto-KeyUpdate trigger check
- `ssl_msg.c:6615–6621` — `in_auth_fail_count` increment and limit check
- `ssl_msg.c:9349` — `in_auth_fail_count` reset on new inbound epoch
- `ssl.h:3198` / `ssl.h:3212` — `mbedtls_ssl_conf_dtls13_aead_limit()` / `mbedtls_ssl_conf_dtls13_auth_fail_limit()`

**What to look for:**
- `out_record_count` incremented per encrypted record (not per byte) — correct per RFC §4.5.1?
- Default thresholds: 2^23 for AES-GCM, 2^36 for ChaCha20-Poly1305 — are defaults set correctly per ciphersuite?
- Counter reset: `out_record_count` resets at epoch advance; `in_auth_fail_count` resets on new inbound epoch install — both happening?
- Auth-fail closure: alert sent before connection close?
- Counter width: are they 64-bit to safely reach 2^36?

---

## Area 9: NewConnectionId / RequestConnectionId (RFC 9147 §9) ✓ DONE

**Focus:** Is the single-outstanding-message invariant enforced, are both inbound
and outbound CID pools populated and maintained correctly, and is the usage byte
(IMMEDIATE vs SPARE) respected on the receive path?

**Primary code:**
- `ssl_msg.c:8123–8233` — `ssl_tls13_write_new_connection_id()`: count active inbound pool slots, encode with loop, set `dtls13_cid_update_ack_pending`
- `ssl_msg.c:8239–8382` — `ssl_tls13_handle_new_connection_id()`: parse full CID list, populate outbound pool, respect usage byte, update `transform_out->out_cid` only on IMMEDIATE
- `ssl_msg.c:8388–8415` — `ssl_tls13_write_request_connection_id()`: send request
- `ssl_msg.c:8421–8458` — `ssl_tls13_handle_request_connection_id()`: respond with NewConnectionId(SPARE)
- `ssl_msg.c:8481–8582` — `mbedtls_ssl_dtls13_rotate_cids()`: rotate both inbound and outbound CIDs simultaneously
- `ssl_msg.c:6996–7003` — ACK dispatch: clear `dtls13_cid_update_ack_pending`, reset `dtls13_req_cid_count`
- `ssl_msg.c:5451–5543` — secondary inbound CID pool match (inside `ssl_prepare_record_content` 5290–5776)

**What to look for:**
- Guard: second NewConnectionId blocked while `dtls13_cid_update_ack_pending` set — checked in both `write_new_connection_id` (L8146) and `rotate_cids` (L8498)?
- Usage byte (L8327–8372): IMMEDIATE installs first CID as active outbound and updates `transform_out`; SPARE fills spare slots without touching `transform_out`. Are these branches correct?
- Outbound pool on SPARE receive: spare slots are filled starting from `(active_idx + 1) % POOL_SIZE` — does the loop correctly avoid overwriting the active slot?
- CID propagation to pending transform: on IMMEDIATE path (L8344–8349), `dtls13_transform_pending_out` also updated — present on SPARE path? (It shouldn't be needed on SPARE — confirm.)
- `rotate_cids` (L8481): rotates outbound pool first (no message needed — we hold the peer's spare), then sends NewConnectionId(IMMEDIATE) for inbound rotation. Are both transform_out and dtls13_transform_pending_out updated on outbound rotate?
- 0-length CID: `cid_len == 0` is valid per RFC (signals "stop using CID on this direction") — is it accepted in the handle path, and does setting `out_cid_len = 0` have any downstream effect on subsequent records?
- RequestConnectionId response (L8436): calls `write_new_connection_id(SPARE)` — but `write_new_connection_id` returns `INTERNAL_ERROR` if `dtls13_cid_update_ack_pending` is set, so a pending NCI causes the response to be silently dropped. Is this the right behaviour?
- ACK matching: `ssl_dtls13_register_pending_ack` at L8228, cleared at L7001. Does `dtls13_req_cid_count` reset correctly on both the ACK path (L7002) and on receiving a NewConnectionId from the peer (L8375)?
- Write loop correctness (L8155–8210): active slot count computed before buffer allocation; encoding loop iterates all pool slots. Verify the `off` pointer cannot overrun `buf + body_len` (all slots share `ssl->own_cid_len` — confirm).
- Inbound pool secondary match (L5451–5543): on spare match, updates `transform->in_cid`, retries decrypt, triggers replenishment. Is replenishment guarded against `dtls13_cid_update_ack_pending`?

---

## Area 10: WAIT_ACK States and Timer Logic (RFC 9147 §5.7–5.8) ✓ DONE

**Focus:** Are the WAIT_ACK states reachable and exitable on all paths, and does
the retransmit timer fire and reset correctly?

**Primary code:**
- `ssl_msg.c:9519–9567` — `mbedtls_ssl_dtls13_wait_ack_step()`: core WAIT_ACK loop
- `ssl_tls13_client.c:3391–3397` — `CLIENT_FINISHED_WAIT_ACK` state handler
- `ssl_tls13_server.c:3844–3855` — `NST_WAIT_ACK` state handler
- `ssl_tls13_client.c:2935–2945` — entry into `CLIENT_FINISHED_WAIT_ACK`
- `ssl_tls13_server.c:3832` — entry into `NST_WAIT_ACK`

**What to look for:**
- Timer: `mbedtls_ssl_set_timer` called on entry to WAIT_ACK, cleared on exit?
- Partial ACK: only unACKed flight items retransmitted — no deadlock if ACK is lost entirely?
- Timeout in WAIT_ACK: max retransmit count respected before giving up?
- NST WAIT_ACK: if client never ACKs NST, does connection proceed anyway (NST is optional)?
- State cleanup: flight items freed on connection abort while in WAIT_ACK?

---

## Area 11: Transcript Hash — DTLS header stripping and nbio-retry guard (RFC 9147 §5.2) ✓ DONE

**Focus:** On all message types (Certificate, CertificateVerify, Finished, ClientHello,
ServerHello), is the transcript hash fed exactly the bytes RFC 9147 §5.2 requires, and
does nbio retry never double-hash any message?

**Primary code:**
- `ssl_tls13_generic.c:67–103` — `mbedtls_ssl_tls13_fetch_handshake_msg()`: DTLS `in_msg_seq++` and `advance_buffering` on consume
- `ssl_tls13_generic.c:838–854` — `mbedtls_ssl_tls13_write_certificate()`: nbio guard before `add_hs_msg_to_checksum`
- `ssl_tls13_generic.c:1046–1061` — `mbedtls_ssl_tls13_write_certificate_verify()`: same nbio guard
- `ssl_tls13_generic.c:1232–1248` — `mbedtls_ssl_tls13_write_finished_message()`: same nbio guard
- `ssl_msg.c:3057–3094` — outbound transcript hash: skip 8 DTLS-only header bytes for DTLS 1.3, guard on `dtls13_frag_off > 0`
- `ssl_tls13_client.c:1503–1522` — DTLS 1.2 fallback re-hash: reset checksum, re-feed CH from `dtls13_cli_hello`, re-feed SH from `in_msg` (full 12-byte DTLS header)

**What to look for:**
- RFC 9147 §5.2: transcript uses 4-byte TLS-style header (type + length), not the 8 extra DTLS bytes — is the 12-byte skip in `ssl_msg.c:3081–3083` applied to all outbound HS messages, including Certificate and CertificateVerify?
- For inbound messages, is `ssl_tls13_fetch_handshake_msg` the single call site for `add_hs_msg_to_checksum`, and does it correctly strip the 8 DTLS-only bytes before hashing?
- nbio guard: `dtls13_frag_off > 0` is the sentinel for "all fragments queued, awaiting final flush" — does the guard in `ssl_tls13_generic.c` match the guard in `ssl_msg.c`? Could `frag_off == 0` on first entry but be non-zero on a mid-fragment WANT_WRITE retry?
- DTLS 1.2 fallback re-hash (`ssl_tls13_client.c:1503`): `dtls13_cli_hello` holds the outgoing CH with the 12-byte DTLS header — is that correct for DTLS 1.2 transcript (which does use the full header), or does it have the wrong format?
- `in_msg_seq` advance in `fetch_handshake_msg`: called once per consumed message — is it protected against double-advance if the caller retries on WANT_WRITE?

---

## Area 12: Handshake State Machine — DTLS 1.3 states and version downgrade (RFC 9147 §5.3–§5.6)

**Focus:** Are the new DTLS 1.3 handshake states correctly reachable and exitable on both
client and server, and does the DTLS 1.2 downgrade path leave no DTLS 1.3 state behind?

**Primary code:**
- `ssl_tls13_client.c:2062–2180` — `ssl_tls13_process_server_hello()`: HelloVerifyRequest detection and DTLS 1.2 HVR handling; DTLS 1.3 state transitions post-ServerHello
- `ssl_tls13_client.c:1464–1540` — `ssl_tls13_preprocess_server_hello()`: DTLS 1.2 fallback transcript re-hash (Option B) at L1503–1523
- `ssl_tls13_client.c:2917–2951` — `ssl_tls13_write_client_finished()`: entry into `CLIENT_FINISHED_WAIT_ACK` for DTLS, vs. direct `HANDSHAKE_OVER` for TLS
- `ssl_tls13_client.c:3331–3410` — top-level `handshake_client_step()`: new DTLS 1.3 state cases at L3391
- `ssl_tls13_server.c:2544–2556` — `ssl_tls13_finalize_server_hello()`: computes handshake transform (epoch-2 keys) at L2547
- `ssl_tls13_server.c:2787–2796` — encrypted extensions writer: DTLS-only guard on outbound transform switch (skipped mid-fragment); `dtls13_post_hs_msg_seq` init
- `ssl_tls13_server.c:2347–2542` — `ssl_tls13_write_server_hello_body()`: ServerHello construction
- `ssl_tls13_server.c:2636–2720` — `ssl_tls13_write_hello_retry_request()`: HRR cookie and DTLS-specific field handling
- `ssl_tls13_server.c:3076–3130` — `ssl_tls13_write_server_finished()`: epoch advance and WAIT_ACK entry
- `ssl_tls13_server.c:3685–3870` — `handshake_server_step()`: new DTLS 1.3 state cases at L3853 including `NST_WAIT_ACK`
- `ssl_tls13_server.c:1234–1760` — `ssl_tls13_parse_client_hello()`: legacy_cookie parse at L1331; cookie extension validate at L1704

**What to look for:**
- HelloVerifyRequest handling (client L2074–2132): HVR cookie stored in `dtls13_hvr_cookie` and echoed in the legacy_cookie field on the second ClientHello (not as an extension). Is the memory for the cookie correctly allocated and freed on both the retry path and abort?
- DTLS 1.3 compatibility mode prohibition (client L1606–1616): server must send zero-length `legacy_session_id_echo`. Alert correct (`illegal_parameter`)?
- DTLS 1.2 fallback (client L1503–1523): After receiving a TLS 1.2 ServerHello, `dtls13_cli_hello` is re-fed into `update_checksum` (full 12-byte DTLS header). Is `dtls13_cli_hello` freed here, or is it leaked if the connection is aborted mid-downgrade?
- Server hello body DTLS block (server L2547): This is where epoch 2 keys are installed (`compute_handshake_transform`, `setup_sne_keys`, `set_inbound_transform`). Is epoch 2 correctly installed before Encrypted Extensions is written?
- `dtls13_post_hs_msg_seq` init (server): initialized from `handshake->out_msg_seq` at `HANDSHAKE_OVER` — is there a matching init on the client side?
- Cookie extension parse (server L1704–1753): on second ClientHello with `hello_retry_request_flag`, cookie is validated via `f_cookie_check`. What happens if cookie is absent (extension missing) — is `missing_extension` fatal alert sent?
- State machine completeness: does every new DTLS 1.3 state in `handshake_client_step` / `handshake_server_step` have a matching case in the state enum (`ssl_misc.h`) and in the debug name table?

**Findings (2026-04-25/26):**

1. **Explicit timer at `ssl_tls13_client.c:2942` is intentional.**
   `ssl_tls13_write_client_finished` calls `mbedtls_ssl_tls13_handshake_wrapup` before entering `CLIENT_FINISHED_WAIT_ACK`. Wrapup marks the handshake as done, so `mbedtls_ssl_flight_transmit` sees `mbedtls_ssl_is_handshake_over() == 1` and sets `retransmit_state = FINISHED` instead of arming the timer. The explicit `mbedtls_ssl_set_timer` at L2942 is the only thing that arms the retransmit timer for the WAIT_ACK state.

2. **`ssl_tls13_reset_key_share` call at `ssl_tls13_client.c:2140` was unguarded. FIXED.**
   The HVR path called `ssl_tls13_reset_key_share` with no `MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED` guard. In a PSK-only build `offered_group_id == 0` so the function returned `MBEDTLS_ERR_SSL_INTERNAL_ERROR`, causing a false handshake failure. PSK-only DTLS 1.3 is RFC-valid.
   **Fix:** wrapped L2140–2142 in `#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)`. Did not add `#error` in `check_config.h` — PSK-only DTLS 1.3 is a legitimate build configuration.

3. **No tests for PSK-only DTLS 1.3. ADDED.**
   All existing PSK tests used `tls13_kex_modes=psk_ephemeral` (or unspecified, which defaults to `psk_all`).
   **Fix:** added `tls13_kex_modes` runner option, `server_psk_only` assertion (matches `"key exchange mode: psk$"`), and a new `psk.yaml` case forcing both endpoints to `tls13_kex_modes=psk`. The new test exercises the exact path that finding 2 fixed.
   Test currently fails for an unrelated reason: ssl_free SIGTRAP after successful protocol completion — same pre-existing crash as the other 3 PSK tests in the baseline failure set. Protocol-level negotiation succeeds.

4. **`f_cookie_write`/`f_cookie_check` API insufficient for RFC 9147 §5.1 transcript binding — design issue.**
   RFC 9147 §5.1 says the DTLS 1.3 HRR cookie SHOULD be bound to the first ClientHello transcript, to prevent an attacker replaying a valid cookie against a manipulated second ClientHello (different cipher suites, key shares, etc.). The reference `mbedtls_ssl_cookie_write` (`ssl_cookie.c:117`) computes HMAC(timestamp || cli_id) where cli_id = client IP+port only — no transcript hash.
   More critically, the callback signature `f_cookie_write(ctx, p, end, cli_id, cli_id_len)` has no transcript hash parameter, so no callback implementation can satisfy the RFC requirement. The API was designed for DTLS 1.2 where transcript binding was not required.
   **Options:**
   - (a) Stack-owned cookie construction with application-supplied secret key — add a config API (e.g., `mbedtls_ssl_conf_dtls_cookie_secret(conf, key, key_len)`); the stack owns the HMAC construction including transcript binding, but the application injects the cluster-wide secret. Fixes the transcript-binding gap, supports cluster deployments, eliminates misconfiguration risk. Deprecates the write/check callbacks for DTLS 1.3. API-additive rather than breaking.
   - (b) New DTLS 1.3-specific callback type with a transcript hash parameter — clean but API-breaking; still leaves transcript binding to the application.
   - (c) Concatenate transcript hash into `cli_id` before calling — no API change, but silently breaks callers using the reference `mbedtls_ssl_cookie_check` (which doesn't know the format changed).
   - (d) Accept the limitation — document that DTLS 1.3 cookie provides reachability only; transcript consistency is not verified. Weakened but RFC-permissible (SHOULD not MUST).
   **Status:** open design decision; needs resolution before Area 12 can be closed. Option (a) is preferred.

5. **`MBEDTLS_SSL_EARLY_DATA` + `MBEDTLS_SSL_PROTO_DTLS` combination now rejected at compile time. DONE.**
   RFC 9147 §5.6 prohibits 0-RTT/early data in DTLS 1.3. Added `#error` to `library/mbedtls_check_config.h` to catch this misconfiguration at build time.

6. **WAIT_ACK timeout silently swallowed by `mbedtls_ssl_dtls13_wait_ack_step`. FIXED.**
   The shared WAIT_ACK helper (`ssl_msg.c:9482`) was converting `MBEDTLS_ERR_SSL_TIMEOUT` to `MBEDTLS_ERR_SSL_WANT_READ`, alongside the legitimate WANT_READ/NON_FATAL retry signals.  But `read_record` only returns TIMEOUT after `ssl_double_retransmit_timeout` exhausts the budget — it's a dead-peer signal, not a retry signal.  Both `NST_WAIT_ACK` and `CLIENT_FINISHED_WAIT_ACK` would have looped forever on a dead peer rather than surfacing the error.  The previous NST_WAIT_ACK case in `ssl_tls13_server.c` had a "swallow TIMEOUT, proceed to HANDSHAKE_OVER" branch that was actually unreachable code (the helper had already converted it).
   **Fix:** in `wait_ack_step`, exclude `TIMEOUT` from the WANT_READ conversion; cancel the timer and return `MBEDTLS_ERR_SSL_TIMEOUT` to the caller. Remove the dead "proceeding anyway" branch from the NST_WAIT_ACK case in `ssl_tls13_server.c`. CLIENT_FINISHED_WAIT_ACK side now also surfaces TIMEOUT correctly (previously also unreachable).

7. **Zero-length HVR cookie not rejected — `ssl_tls13_client.c:2108`. FIXED.**
   RFC 6347 requires the HVR cookie to be non-empty. `mbedtls_calloc(1, 0)` was called without checking `cookie_len > 0` first; on implementations where `calloc(1,0)` returns NULL this caused a spurious `MBEDTLS_ERR_SSL_ALLOC_FAILED` instead of `MBEDTLS_ERR_SSL_DECODE_ERROR`. Fixed by combining the zero-length check into the existing bounds check at L2108.

---

## Area 13: Connection Teardown — epoch pool and pending transform cleanup (RFC 9147 §4.2.1)

**Focus:** Are all DTLS 1.3 heap-allocated objects (epoch pool transforms,
`dtls13_transform_pending_out`, `dtls13_ku_pending_secret`, `dtls13_post_hs_ack`,
`dtls13_cli_hello`) freed on every exit path, including early abort?

**Primary code:**
- `ssl_tls.c:1316–1352` — `mbedtls_ssl_session_reset_msg_layer()`: DTLS 1.3 teardown block: epoch pool drain, pending_out free, pending_secret zeroize
- `ssl_tls.c:979–1012` — `ssl_handshake_init()`: DTLS renegotiation `transform_negotiate` aliasing fix
- `ssl_tls.c:5274–5317` — `mbedtls_ssl_free()`: top-level free — does it call `session_reset_msg_layer` or separately free DTLS 1.3 objects?
- `ssl_tls13_generic.c:1255–1268` — `mbedtls_ssl_tls13_handshake_wrapup()`: epoch-2 transform retirement into pool on handshake completion
- `ssl_tls.c:4589–4598` — `mbedtls_ssl_handshake_free()`: does it free `dtls13_cli_hello`?

**What to look for:**
- `transform_in` / `transform_out` vs `transform_application` aliasing (ssl_tls.c:1322–1337): after KeyUpdate, `transform_in` and `transform_out` diverge from `transform_application`. The drain-to-pool logic guards with `!= transform_application && !ssl_dtls13_epoch_pool_contains()`. Is the `_contains()` check necessary, or can a transform be in the pool and also aliased by `transform_in`/`transform_out`?
- `transform_negotiate` aliasing on DTLS renegotiation (ssl_tls.c:981–1010): when `wrapup_free_hs_transform` defers promotion, `transform_out == transform_negotiate`. The fix completes the deferred promotion on next `ssl_handshake_init`. What if `ssl_free()` is called between the deferred point and the promotion? Is there a double-free risk?
- `dtls13_cli_hello` lifecycle: allocated in `ssl_msg.c:3161`, freed in `ssl_tls13_client.c:2130` (on HVR path) and presumably in `mbedtls_ssl_handshake_free()`. Verify it is freed on: (a) successful downgrade to DTLS 1.2, (b) abort before ServerHello, (c) `mbedtls_ssl_session_reset()`.
- `dtls13_post_hs_ack` lifecycle: allocated in ACK write path — freed in `session_reset_msg_layer`? Verify no leak on early abort.
- `ssl_dtls13_epoch_pool_free()` call sites: called in `session_reset_msg_layer` — is it also called (or redundantly safe to call) from `mbedtls_ssl_free()`?

**Findings:**

1. **Pointless insert-then-free in `session_reset_msg_layer` and `mbedtls_ssl_free` — `ssl_tls.c:1327–1336` and `ssl_tls.c:5290–5299`. FIXED.**
   `transform_in`/`transform_out` were inserted into the epoch pool only to be freed immediately by `ssl_dtls13_epoch_pool_free`. Fixed both call sites to free them directly (with `mbedtls_ssl_transform_free` + `mbedtls_free`) instead of routing through the pool. The `_contains()` guard is still needed to avoid double-freeing transforms already in the pool.


---

## Area 14: ssl_misc.h and ssl.h — new struct fields and API surface (RFC 9147 §4–§9)

**Focus:** Are the new fields in `mbedtls_ssl_context`, `mbedtls_ssl_config`,
`mbedtls_ssl_handshake_params`, `mbedtls_ssl_transform`, and `mbedtls_ssl_flight_item`
correctly sized, documented, and initialized?

**Primary code:**
- `ssl_misc.h:875–965` — new `mbedtls_ssl_handshake_params` fields: `dtls13_frag_off`, `dtls13_pending_seq`, `dtls13_cli_hello`/`_len`, `dtls13_hvr_cookie`/`_len`, `dtls13_epoch0_out_ctr`, `dtls13_post_hs_ack`
- `ssl_misc.h:1108–1203` — new `mbedtls_ssl_transform` fields: `dtls13_epoch`, `sn_key`, `sn_key_len`, AEAD limit counters (`out_record_count`, `in_auth_fail_count`), inbound CID for epoch pool (`in_cid`, `in_cid_len`)
- `ssl_misc.h:1265–1346` — `mbedtls_ssl_flight_item` new fields: `dtls13_send_epoch`, `sent_records[]`, `sent_record_epoch[]`, `sent_record_count`
- `ssl_misc.h:1516–1588` — new inline helpers: `mbedtls_ssl_dtls13_sync_post_hs_seq()`, `mbedtls_ssl_handshake_set_state()` DTLS 1.3 extension
- `ssl.h:1813–1912` — new `mbedtls_ssl_context` fields: epoch pool, CID pool, KeyUpdate state, post-HS sequencing
- `ssl.h:1601–1677` — new `mbedtls_ssl_config` fields: DTLS 1.3 limits, CID pool size

**What to look for:**
- `sn_key` in `mbedtls_ssl_transform` (ssl_misc.h:~1150): is its size `MBEDTLS_SSL_DTLS13_SNE_KEY_MAX_LEN` large enough for all ciphersuites (AES-128 needs 16 bytes, AES-256 needs 32)? Is `sn_key_len` always set before use and correctly zeroed on transform free?
- `sent_records[]` array in `mbedtls_ssl_flight_item`: size is `MBEDTLS_SSL_DTLS13_MAX_RECORDS_PER_FLIGHT_ITEM` — is that constant defined to cover the maximum retransmit count before timeout? A flight item that's retransmitted more times than the array size silently wraps the ring — is the wrap-around logic correct?
- `dtls13_epoch_pool` array in `ssl_context`: is `MBEDTLS_SSL_DTLS13_EPOCH_POOL_SIZE` sufficient? A too-small pool causes premature epoch eviction, breaking retransmit for old epochs.
- `dtls13_peer_cid_pool` and `dtls13_own_cid_pool` in `ssl_context`: are pool sizes documented and matched between the two directions? Is `dtls13_peer_cid_active_idx` bounds-checked on all access paths?
- New public API in `ssl.h` (`mbedtls_ssl_conf_dtls13_aead_limit`, `mbedtls_ssl_conf_dtls13_auth_fail_limit`, `mbedtls_ssl_dtls13_rotate_cids`): are all parameters validated, and do the functions guard against being called on TLS (non-datagram) connections?

**Findings:**

1. **`dtls13_received_records` in `handshake_params` was a layering violation. FIXED.**
   Record sequence number tracking lived in `mbedtls_ssl_handshake_params`, but record-layer state belongs on `mbedtls_ssl_context`. The dual-path dispatch (`hs != NULL ? hs->dtls13_received_records : pa->...`) for the during-handshake vs post-handshake cases was a symptom.
   **Fix:** moved `dtls13_received_records[]` and `dtls13_received_record_count` to `mbedtls_ssl_context`. Removed the lazily-allocated `mbedtls_ssl_dtls13_post_hs_ack` typedef and the `dtls13_post_hs_ack` pointer from the context. Producer at `ssl_msg.c:5715` collapsed to single path; consumer at `ssl_msg.c:6788` (`ssl_dtls13_write_ack`) likewise; clears count after sending instead of allocating/freeing. Also fixed a latent bug: handshake `dtls13_received_record_count` was never reset after sending an ACK (only post-hs was), causing silent record drops after 16 entries during long handshakes.
   Side benefit: the comment and guard at `ssl_msg.c:7170-7180` (about not freeing `handshake` while ACK is pending because ACK needs handshake state) is no longer required — comment updated, `!ssl->dtls13_ack_pending` guard removed.

2. **`MBEDTLS_SSL_DTLS13_MAX_RECORDS_PER_FLIGHT_ITEM` increased from 4 to 8. FIXED.**
   `ssl_misc.h:1425`: with 4 slots (1 original + 3 ring), retransmit 4+ would evict earlier entries causing unnecessary retransmits when the peer ACKs an evicted record number. The default timer doubling allows ~6 retransmits before timeout; 8 slots (1 original + 7 ring) covers all retransmits without eviction.

3. **`sn_key`/`sn_key_enc` fields guarded by `MBEDTLS_SSL_PROTO_DTLS` only — FIXED.**
   These are DTLS 1.3-only fields but were guarded by just `MBEDTLS_SSL_PROTO_DTLS`, wasting space in DTLS 1.2-only builds. Fixed to `MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_SSL_PROTO_TLS1_3`; inner `#if TLS1_3` block for `dtls13_epoch` and AEAD counters folded into the outer guard.

---

## Area 15: ssl_client.c — ClientHello construction and cookie echo (RFC 9147 §5.3, §5.6) ✓ DONE

**Focus:** Is the DTLS 1.3 ClientHello correctly constructed (legacy_cookie field,
supported_versions, CID extension) and does the HVR cookie echo end up in the right place?

**Primary code:**
- `ssl_client.c:510–551` — `ssl_write_client_hello_body()`: legacy_cookie field write (zero-length for DTLS 1.3 first flight, HVR cookie on retry)
- `ssl_client.c:922–990` — `mbedtls_ssl_write_client_hello()`: DTLS 1.3 specific pre/post send operations (epoch stamping, `dtls13_cli_hello` save timing relative to `write_handshake_msg_ext`)
- `ssl_tls13_client.c:574–581` — `ssl_tls13_write_cookie_ext()`: HVR cookie suppressed when `dtls_hvr_cookie` is set (echoed in legacy field instead)
- `ssl_tls13_client.c:1178–1196` — CID extension write in `mbedtls_ssl_tls13_write_client_hello_exts()`

**What to look for:**
- Legacy cookie field (L510–551): first ClientHello writes one zero byte (`cookie_len = 0`). On HVR retry, the stored cookie is written here. Is the stored cookie length bounds-checked against the output buffer?
- `dtls13_cli_hello` save timing (L922–990): `write_handshake_msg_ext` is called after `ssl_write_client_hello_body`, and `dtls13_cli_hello` is saved inside `write_handshake_msg_ext` (ssl_msg.c:3155–3169). This means `dtls13_cli_hello` contains the post-header-insertion 12-byte-header form. On HVR retry, is the existing `dtls13_cli_hello` freed before a new one is saved, or does the `== NULL` guard (ssl_msg.c:3160) prevent the update and leave stale CH data for the re-hash?
- `supported_versions` extension (ssl_tls13_client.c:74–90): for DTLS, `DTLS_VERSION_1_3 (0xFEFC)` and `DTLS_VERSION_1_2 (0xFEFD)` — are the byte values correct (DTLS version encoding is inverted relative to TLS)?
- CID extension in ClientHello: only written when `negotiate_cid == MBEDTLS_SSL_CID_ENABLED`. Is this the right condition, or should it also depend on `own_cid_len > 0`?

---

## Area 16: ssl_server2.c and ssl_client2.c — post-handshake API usage and fault injection (RFC 9147 §8, §9)

**Focus:** Is every new DTLS 1.3 API called with correct arguments and in the correct
program state? Do the fault-injection paths (bad_keyupdate, bad_new_cid, double_keyupdate,
bad_cookie_on_retry) produce the right outcomes without leaking resources or hanging?

**Primary code:**
- `ssl_server2.c:4200–4265` — KeyUpdate send loop: `mbedtls_ssl_send_key_update()` + drain loop on `dtls13_key_update_pending()`
- `ssl_server2.c:4245–4265` — NewConnectionId / RequestConnectionId send after handshake
- `ssl_server2.c:4515–4535` — `rotate_cid` countdown: calls `mbedtls_ssl_dtls13_rotate_cids()` after N exchanges
- `ssl_server2.c:1367–1540` — `migration_ctx_t` + `migration_recv()` + `migration_check_timer()`: address-migration recv shim, candidate tracking, commit logic
- `ssl_server2.c:3246–3255` — `bad_cookie_on_retry`: installs `bad_cookie_check` as `f_cookie_check` to force rejection on second ClientHello
- `ssl_client2.c:2618–2740` — client-side KeyUpdate, `bad_keyupdate`, `double_keyupdate`, NewConnectionId, `bad_new_cid`, `bad_req_cid`, `cid_change_addr`, `rotate_cid`
- `ssl_client2.c:2888–2960` — `rotate_cid` and `cid_change_addr` per-exchange logic; NST handling on `RECEIVED_NEW_SESSION_TICKET`

**What to look for:**
- KeyUpdate drain loop (server2 L4225): `while (mbedtls_ssl_dtls13_key_update_pending(&ssl))` calls `ssl_read` waiting for the ACK. What happens if `ssl_read` returns a non-WANT_READ error (e.g. connection reset)? The loop breaks with `ret <= 0` and continues — is that correct, or should it goto reset/exit? If the ACK is lost permanently, does the library's retransmit machinery eventually surface `TIMEOUT`?
- double_keyupdate (client2 L2638–2657): first KeyUpdate sent (L2640), immediately followed by a second (L2649) before ACK arrives. The library must reject the second. Is the expected error code correct, and does the test harness assert it? After the rejected send, does the pending guard clear correctly for future exchanges?
- bad_keyupdate (client2 L2663–2672): sends a raw malformed KeyUpdate. Verify the malformed message is crafted at the wire level, bypassing `mbedtls_ssl_send_key_update` — otherwise the library rejects it before it reaches the peer.
- Address migration (server2 L1367–1540): `migration_recv()` replaces `f_recv`. Migration is committed after `migration_timeout_ms` of old-address silence AND at least one authenticated packet from the new address. Key risk: the "authenticated packet" signal comes from `ssl_read` returning app data — ACKs and handshake messages also surface via `ssl_read`. Could a non-app-data record trigger a premature commit? Is `migration_check_timer` called (with `app_data_received=0`) during the ACK/KeyUpdate drain loops to advance the timer without committing?
- bad_cookie_on_retry (server2 L3249–3253): installs `bad_cookie_check` (always returns -1). On second ClientHello the server sends `handshake_failure` and calls `goto reset`. Verify the test harness checks both exit codes and that the client surfaces a fatal alert, not a hang.
- rotate_cid countdown (both programs): `--opt.rotate_cid == 0` triggers exactly once then stays at 0. Confirm this is intentional — not a bug where rotation should repeat every N exchanges.
- NST handling in client2 (L2368–2415): on `RECEIVED_NEW_SESSION_TICKET` the client calls `continue` in the read loop. Verify this does not skip the `cid_change_addr` / `rotate_cid` logic that appears later in the loop body.

**Findings:**

1. **`send_bad_*` fault-injection functions exposed in public API. FIXED.**
   `ssl_msg.c:8655`, `8699`, `8763` and corresponding declarations in `include/mbedtls/ssl.h:5485–5501`: `mbedtls_ssl_dtls13_send_bad_keyupdate`, `mbedtls_ssl_dtls13_send_bad_new_connection_id`, `mbedtls_ssl_dtls13_send_bad_request_connection_id` were declared in the public `ssl.h` header. These access library internals (`start_handshake_msg`, `transform_out`) so they can't be moved out of the library, but they should not be in the public API.
   **Fix:** renamed to `mbedtls_ssl_dtls13_test_send_bad_*` (with `_test_` infix to signal intent), removed declarations from public `ssl.h`, added them to internal `library/ssl_misc.h` with a "TEST ONLY, DO NOT USE IN PRODUCTION" warning header. The `ssl_client2.c` test program forward-declares the prototypes inline (cannot include `ssl_misc.h` since `library/` is not in its include path) — keeps the library symbol exported but out of the public API surface.

2. **`rotate_cid` option mutated at runtime — FIXED.**
   `ssl_server2.c` and `ssl_client2.c` previously decremented `opt.rotate_cid` in the exchange loop. Replaced with a local `rotate_cid_countdown` variable in both programs, keeping `opt` immutable. Also simplified the cryptic `--opt.rotate_cid == 0` idiom to `rotate_cid_countdown == 1` / `rotate_cid_countdown = 0`.
