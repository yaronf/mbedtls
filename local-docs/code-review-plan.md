# DTLS 1.3 Code Review Plan

**Branch:** `dtls13`
**Created:** 2026-04-03
**Status:** in progress

Each area has a focus question, the primary files/functions to read, and what to look for.
Areas are ordered roughly by risk — start at the top.

---

## Area 1: Unified Record Header — parsing and construction (RFC 9147 §4.1)

**Focus:** Is the epoch extraction, CID flag, and sequence number reconstruction
correct for all combinations of header bits?

**Primary code:**
- `library/ssl_msg.c:4566–4692` — `ssl_parse_dtls13_record_header()`: inbound unified header parsing (epoch reconstruction, seq, CID, length)
- `library/ssl_msg.c:3433–3681` — `mbedtls_ssl_write_record()`: outbound unified header construction (`dtls13_unified_hdr` block starting at line 3530)
- `library/ssl_msg.c:4875–5214` — `ssl_parse_record_header()` DTLS path: dispatcher that calls `ssl_parse_dtls13_record_header()` and handles epoch filtering
- `library/ssl_msg.c:808–1382` — `mbedtls_ssl_encrypt_buf()`: where `dtls13_unified_hdr` is built and passed to AEAD (lines 1083–1121)
- `library/ssl_misc.h` — unified header bit constants

**What to look for:**
- Epoch bits (bits 0–1 of byte 0): do we correctly distinguish epoch 0 (plaintext) from epochs 1–3?
- Sequence number reconstruction: 8-bit or 16-bit on-wire seq expanded to 48-bit — is the window-based reconstruction correct?
- CID field: present only when C bit set — does the parser handle absent vs. present correctly?
- Length field: optional (L bit); missing length means record extends to end of datagram — is that handled?
- Off-by-one in header offset arithmetic.

---

## Area 2: Sequence Number Encryption (SNE) — key derivation and mask application (RFC 9147 §4.2.3)

**Focus:** Is the SNE key derived with the correct label and applied at the right
point on both encrypt and decrypt paths?

**Primary code:**
- `library/ssl_tls13_keys.c` — `mbedtls_ssl_dtls13_hkdf_expand_label()`, SNE key derivation
- `library/ssl_msg.c` — outbound XOR (encrypt), inbound XOR (decrypt)
- `library/ssl_misc.h` — `sn_key`/`sn_key_len` in `mbedtls_ssl_transform`

**What to look for:**
- Label must be `"dtls13 sn"` (not `"tls13 ..."`) — check exact string.
- Ciphertext sample offset: for AES-GCM the sample starts at byte 0 of ciphertext; for
  ChaCha20-Poly1305 it starts at byte 0 too — verify against RFC §4.2.3 Figure 5.
- XOR must cover exactly the on-wire seq bytes (byte 1, and byte 2 if S=1) — not the epoch bits.
- Decrypt: mask is derived from ciphertext *before* AEAD decryption — order of operations matters.
- SNE key zeroized on transform free.

---

## Area 3: Epoch Pool — lifetime, eviction, and counter integrity (RFC 9147 §4.2.1)

**Focus:** Are retired transforms correctly retained and evicted, and are their
sequence counters preserved for retransmit?

**Primary code:**
- `library/ssl_msg.c` — epoch pool insert, lookup, free
- `library/ssl_misc.h` — `mbedtls_ssl_dtls13_epoch_pool_t`, pool API
- `library/ssl_tls.c` — pool teardown on connection close

**What to look for:**
- Pool capacity: 4 slots. Overflow evicts oldest — is eviction of an epoch still needed for retransmit safe?
- Counter sync: when a slot is inserted, is the current `out_ctr` for that epoch saved correctly?
- On retransmit epoch switch (`ssl_dtls13_retx_epoch_switch`): does restoring the counter correctly resume from where retransmit left off without replaying?
- Epoch-0 counter: tracked separately in `dtls13_epoch0_out_ctr` — is it saved/restored correctly across handshake epoch transitions?
- All pool slots freed on connection teardown (no transform leak).

---

## Area 4: KeyUpdate — ACK-pending guard and secret lifecycle (RFC 9147 §8)

**Focus:** Is the guard against double-KeyUpdate enforced, and is the pending
secret handled safely from derivation through installation through zeroization?

**Primary code:**
- `library/ssl_tls13_keys.c` — `mbedtls_ssl_tls13_compute_key_update_transform()`
- `library/ssl_msg.c` — KeyUpdate send, ACK reception, new epoch installation
- `library/ssl_misc.h` — `dtls13_ku_ack_pending`, `dtls13_ku_pending_secret`

**What to look for:**
- Guard: is a second KeyUpdate blocked while `dtls13_ku_ack_pending` is set?
- Label: `HKDF-Expand-Label(secret, "traffic upd", "", hash_len)` — exact string check.
- Pending secret: stored in `dtls13_ku_pending_secret`; must be zeroized immediately after
  new transform installation — even on error paths.
- New epoch installed only after ACK received (not immediately after send).
- Inbound KeyUpdate from peer: old inbound epoch must stay in pool long enough for
  reordered records; when is it evicted?
- `update_not_requested` vs `update_requested`: does the peer-initiated path correctly
  trigger a reciprocal KeyUpdate when requested?

---

## Area 5: ACK Generation and Matching (RFC 9147 §7)

**Focus:** Is the ACK record correctly constructed, and does the matching logic
correctly clear only the acknowledged flight items?

**Primary code:**
- `library/ssl_msg.c` — ACK frame construction, transmission, reception/matching
- `library/ssl_misc.h` — `dtls13_received_records`, `dtls13_ack_pending`

**What to look for:**
- ACK record format: list of (epoch, seq_no) pairs — matches RFC §7.3?
- Buffer: 16-entry fixed array; overflow silently drops oldest — is this acceptable?
  Could an attacker force ACK loss by flooding?
- Matching: on receipt of an ACK, does the code match by (epoch, seq) of the *sent*
  record, not the message? (ACKs are record-level, not message-level.)
- Handshake ACK (`dtls13_ack_pending`) vs post-handshake ACK (`dtls13_post_hs_ack`):
  are both paths exercised and consistent?
- Deferred ACK: after Finished verify, ACK must be sent before application data —
  is the ordering guaranteed?

---

## Area 6: Post-Handshake Message Sequencing (RFC 9147 §5.2)

**Focus:** Is `message_seq` correctly maintained across the handshake/post-handshake
boundary, and are duplicate/out-of-order messages correctly handled?

**Primary code:**
- `library/ssl_msg.c` — outbound `message_seq` stamping, inbound validation
- `library/ssl_misc.h` — `dtls13_post_hs_in_msg_seq`, `dtls13_post_hs_msg_seq`
- `library/ssl_tls13_generic.c` — seq advance after message consume

**What to look for:**
- RFC 9147: `message_seq` is *not* reset between handshake and post-handshake phases —
  is the transition correctly handled (no reset)?
- Duplicate detection: same `message_seq` received twice must be silently dropped,
  not cause an error.
- Out-of-order: seq gap ≤ MBEDTLS_SSL_MAX_BUFFERED_HS (6) — is the window check correct?
- Double-increment bug: on fragmented resend, `message_seq` must not be incremented again.
- Interaction with KeyUpdate and NewConnectionId: do those post-HS messages correctly
  advance the seq counter?

---

## Area 7: Fragmentation and Retransmit Epoch Switching

**Focus:** On retransmit, is the correct epoch and counter restored, and does
fragment-resume correctly skip seq/epoch-stamp steps?

**Primary code:**
- `library/ssl_msg.c` — `ssl_dtls13_retx_epoch_switch()`, epoch stamping on first send,
  `dtls13_frag_off` resume logic
- `library/ssl_misc.h` — flight item epoch/counter fields

**What to look for:**
- Epoch stamping: must happen exactly once per message on first send — is there a guard
  preventing re-stamp on retransmit?
- Retransmit epoch switch: saves active epoch, installs flight item's epoch, sends,
  restores — does the restore happen on all code paths including error?
- Fragment resume (`dtls13_frag_off`): on WANT_WRITE retry, resumes mid-fragment without
  re-incrementing `out_msg_seq` or re-stamping epoch — verify.
- Flight item list: freed on handshake completion — any leak on early connection abort?

---

## Area 8: AEAD and Auth-Fail Limits (RFC 9147 §4.5.2–4.5.3)

**Focus:** Are the per-epoch counters correctly maintained, reset at epoch
transitions, and do they fire at the right thresholds?

**Primary code:**
- `library/ssl_msg.c` — outbound record count check, inbound auth-fail increment
- `library/ssl_tls.c` — limit configuration APIs
- `library/ssl_misc.h` — `out_record_count`, `in_auth_fail_count` in transform

**What to look for:**
- `out_record_count` incremented per encrypted record sent, not per byte — is that correct?
- Auto-KeyUpdate threshold: 2^23 for AES-GCM, 2^36 for ChaCha20-Poly1305 (RFC §5.5) —
  are the defaults correct per ciphersuite?
- Counter reset: `out_record_count` resets at epoch advance; `in_auth_fail_count` resets
  on new inbound epoch install — is both reset happening?
- Auth-fail limit: connection terminated (not just alert) after limit — is the closure
  clean (alert sent first)?
- Integer overflow: are counters wide enough (64-bit) to reach 2^36 without wrapping?

---

## Area 9: NewConnectionId / RequestConnectionId (RFC 9147 §9)

**Focus:** Is the single-outstanding-message invariant enforced, and is the CID
correctly propagated to any subsequently installed transforms?

**Primary code:**
- `library/ssl_msg.c` — NewConnectionId send, ACK matching, RequestConnectionId handling
- `library/ssl_misc.h` — `dtls13_cid_update_ack_pending`
- `library/ssl_tls13_server.c`, `ssl_tls13_client.c` — CID update trigger points

**What to look for:**
- Guard: second NewConnectionId blocked while `dtls13_cid_update_ack_pending` set?
- CID propagation: when KeyUpdate follows a CID update, does the new transform carry
  the updated CID?
- RequestConnectionId response: server/client must respond with NewConnectionId —
  is the response path wired?
- CID length: 0-length CID is valid (means "stop using CID") — is that handled?
- ACK matching: by (epoch, seq) of the NewConnectionId record — same mechanism as KeyUpdate ACK.

---

## Area 10: Handshake State Machine — WAIT_ACK States and Timer Logic (RFC 9147 §5.7–5.8)

**Focus:** Are the new WAIT_ACK states reachable and exitable on all code paths,
and does the retransmit timer fire and reset correctly?

**Primary code:**
- `library/ssl_tls13_client.c` — `CLIENT_FINISHED_WAIT_ACK` state
- `library/ssl_tls13_server.c` — `NST_WAIT_ACK`, server Finished WAIT_ACK
- `library/ssl_msg.c` — `mbedtls_ssl_dtls13_wait_ack_step()`, flight ACK clearing
- `include/mbedtls/ssl.h` — WAIT_ACK state enum values

**What to look for:**
- Both client and server enter WAIT_ACK after sending their final flight — is there a
  path where the state is skipped (e.g., on immediate ACK)?
- Timer: is `mbedtls_ssl_set_timer` called when entering WAIT_ACK, and cleared on exit?
- Partial ACK: if only some flight items are ACKed, only those items are dropped from
  the retransmit list — does the state machine handle partial ACK without deadlock?
- Timeout: on timer expiry in WAIT_ACK, full flight retransmit — is the max retransmit
  count respected?
- NST (NewSessionTicket) WAIT_ACK: NST is optional — if client never ACKs, should the
  connection still proceed? Is there a timeout fallback?
- State cleanup: on connection abort while in WAIT_ACK, are flight items freed?
