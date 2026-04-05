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

## Area 3: Epoch Pool — lifetime, eviction, and counter integrity (RFC 9147 §4.2.1)

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

## Area 4: KeyUpdate — ACK-pending guard and secret lifecycle (RFC 9147 §8)

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

## Area 5: ACK Generation and Matching (RFC 9147 §7)

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

## Area 6: Post-Handshake Message Sequencing (RFC 9147 §5.2)

**Focus:** Is `message_seq` correctly continuous across the handshake/post-handshake
boundary, and are duplicates and out-of-order messages handled correctly?

**Primary code:**
- `ssl_msg.c:3022–3025` — outbound post-HS `message_seq` stamping and increment
- `ssl_msg.c:3938–3955` — inbound `message_seq` validation
- `ssl_msg.c:8532` — inbound seq advance after message consume
- `ssl_tls.c` — `mbedtls_ssl_handshake_set_state()`: sync of `dtls13_post_hs_in_msg_seq` at `HANDSHAKE_OVER`

**What to look for:**
- RFC 9147 §5.2: `message_seq` must NOT reset at handshake end — is the sync-from-handshake correct?
- Duplicate detection: same seq received twice must be silently dropped, not error?
- Fragment resume (`dtls13_frag_off > 0`): `message_seq` must not re-increment on retry?
- KeyUpdate and NewConnectionId post-HS messages: do they correctly advance the seq counter?

---

## Area 7: Fragmentation and Retransmit Epoch Switching

**Focus:** On retransmit, is the correct epoch and counter restored, and does
fragment-resume skip the epoch-stamp and seq-increment steps?

**Primary code:**
- `ssl_msg.c:2433–2495` — `ssl_dtls13_retx_epoch_switch()`: save active epoch, install flight epoch
- `ssl_msg.c:2499–2515` — `ssl_dtls13_retx_epoch_restore()`: restore after retransmit
- `ssl_msg.c:2288–2336` — epoch stamping on first send (the `dtls13_send_epoch` field)
- `ssl_msg.c:3031–3255` — fragment send loop: `dtls13_frag_off` resume guards

**What to look for:**
- Epoch stamping: happens once on first send — is there a guard preventing re-stamp on retransmit?
- Epoch restore: happens on all code paths out of retransmit loop, including error?
- Fragment resume: on WANT_WRITE retry, skips seq-stamp and epoch-stamp — does it also skip flight-item append?
- Flight item list freed on connection abort — no leak?

---

## Area 8: AEAD and Auth-Fail Limits (RFC 9147 §4.5.2–4.5.3)

**Focus:** Are per-epoch counters correctly maintained, reset at epoch transitions,
and do they fire at the right thresholds?

**Primary code:**
- `ssl_msg.c:1171` — `out_record_count++` (per encrypted record sent)
- `ssl_msg.c:8891–8896` — auto-KeyUpdate trigger check
- `ssl_msg.c:6608–6615` — `in_auth_fail_count` increment and limit check
- `ssl_msg.c:9284` — `in_auth_fail_count` reset on new inbound epoch
- `ssl_tls.c` — `mbedtls_ssl_dtls13_set_aead_limit()` / `mbedtls_ssl_dtls13_set_auth_fail_limit()`

**What to look for:**
- `out_record_count` incremented per encrypted record (not per byte) — correct per RFC §4.5.1?
- Default thresholds: 2^23 for AES-GCM, 2^36 for ChaCha20-Poly1305 — are defaults set correctly per ciphersuite?
- Counter reset: `out_record_count` resets at epoch advance; `in_auth_fail_count` resets on new inbound epoch install — both happening?
- Auth-fail closure: alert sent before connection close?
- Counter width: are they 64-bit to safely reach 2^36?

---

## Area 9: NewConnectionId / RequestConnectionId (RFC 9147 §9)

**Focus:** Is the single-outstanding-message invariant enforced, and is the CID
propagated to subsequently installed transforms?

**Primary code:**
- `ssl_msg.c:7958–8013` — `ssl_tls13_write_new_connection_id()`: send and set pending flag
- `ssl_msg.c:8019–8111` — `ssl_tls13_handle_new_connection_id()`: receive and apply new CID
- `ssl_msg.c:8117–8144` — `ssl_tls13_write_request_connection_id()`: send request
- `ssl_msg.c:8150–8187` — `ssl_tls13_handle_request_connection_id()`: respond with NewConnectionId

**What to look for:**
- Guard: second NewConnectionId blocked while `dtls13_cid_update_ack_pending` set?
- CID propagation: when KeyUpdate follows a CID update, does the new transform carry the updated CID?
- 0-length CID: valid per RFC (means "stop using CID") — handled in handle path?
- RequestConnectionId response path (8150–8187): always sends a NewConnectionId in reply?
- ACK matching for CID update: same (epoch, seq) mechanism as KeyUpdate ACK?

---

## Area 10: WAIT_ACK States and Timer Logic (RFC 9147 §5.7–5.8)

**Focus:** Are the WAIT_ACK states reachable and exitable on all paths, and does
the retransmit timer fire and reset correctly?

**Primary code:**
- `ssl_msg.c:9064–9112` — `mbedtls_ssl_dtls13_wait_ack_step()`: core WAIT_ACK loop
- `ssl_tls13_client.c:3391–3420` — `CLIENT_FINISHED_WAIT_ACK` state handler
- `ssl_tls13_server.c:3845–3880` — `NST_WAIT_ACK` state handler
- `ssl_tls13_client.c:2935–2945` — entry into `CLIENT_FINISHED_WAIT_ACK`
- `ssl_tls13_server.c:3833` — entry into `NST_WAIT_ACK`

**What to look for:**
- Timer: `mbedtls_ssl_set_timer` called on entry to WAIT_ACK, cleared on exit?
- Partial ACK: only unACKed flight items retransmitted — no deadlock if ACK is lost entirely?
- Timeout in WAIT_ACK: max retransmit count respected before giving up?
- NST WAIT_ACK: if client never ACKs NST, does connection proceed anyway (NST is optional)?
- State cleanup: flight items freed on connection abort while in WAIT_ACK?
