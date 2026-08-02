# wolfSSL Interop Notes

## Source location

```
~/misc/wolfssl/
```

Cloned from https://github.com/wolfSSL/wolfssl (main branch).

---

## Building

### Basic DTLS 1.3 build (Apple Silicon — must disable ASM)

The wolfSSL inline assembly uses explicit register names (`x3`, `x8`, etc.) that
Apple clang rejects on ARM64.  `--disable-asm` suppresses all inline asm.

```sh
cd ~/misc/wolfssl
./configure --disable-asm --enable-dtls13 --enable-dtls
make -j4
```

### With SSLKEYLOGFILE output (for key comparison / Wireshark)

Requires `--enable-keylog-export` (defines `HAVE_SECRET_CALLBACK` +
`WOLFSSL_SSLKEYLOGFILE`) **and** `-DSHOW_SECRETS` (wires the callback in
`InitSSL`).  Without both, the keylog file is never written.

```sh
./configure --disable-asm --enable-dtls13 --enable-dtls \
    --enable-keylog-export \
    CFLAGS="-DSHOW_SECRETS"
make -j4
```

Output file: `sslkeylog.log` in the **working directory** at runtime (defaults to
`wolfssl/` if server is run from there).  To change the path, set
`WOLFSSL_SSLKEYLOGFILE_OUTPUT` as a string literal at configure time:

```sh
CFLAGS="-DSHOW_SECRETS -DWOLFSSL_SSLKEYLOGFILE_OUTPUT='\"/tmp/wolfssl_keylog.txt\"'"
```

Note: the extra quoting layers are required to pass a C string literal through
the shell → configure → CFLAGS → compiler pipeline.  Verify with:

```sh
grep WOLFSSL_SSLKEYLOGFILE_OUTPUT wolfssl/options.h
```

The value must look like `"/tmp/wolfssl_keylog.txt"` (with double quotes) for
the C compiler to accept it as a string literal.

---

## Running

The server and client examples **must be run from the wolfSSL source directory**
so they can find certificates in `./certs/`.

```sh
cd ~/misc/wolfssl

# DTLS 1.3 server (loops, no client auth, verbose)
./examples/server/server -u -v 4 -i -p 4433 -d

# DTLS 1.3 client
./examples/client/client -u -v 4 -p 4433 -d
```

Key flags:
- `-u`  UDP / DTLS transport
- `-v 4`  force TLS/DTLS 1.3 (`-v 3` = 1.2, `-v -1` = negotiate)
- `-i`  loop (server accepts multiple connections)
- `-d`  disable peer certificate verification (useful for testing)
- `-p PORT`  port number
- `-b`  **server:** bind any interface (not debug!). **client:** benchmark N connections
- `-Y`  server: pre-generate P-256 key share (recommended for Dir B interop)
- `-h` / `--help`  full flag list

For verbose wolfSSL tracing, rebuild with debug options / `DEBUG_WOLFSSL` — there is no `-b` debug switch on the examples.

Self-test (both sides from same dir):

```sh
./examples/server/server -u -v 4 -i -p 4433 -d &
sleep 0.5
./examples/client/client -u -v 4 -p 4433 -d
```

---

## Interop with mbedtls

### mbedtls client ↔ wolfSSL server

```sh
# Terminal 1 — wolfSSL server
cd ~/misc/wolfssl
./examples/server/server -u -v 4 -i -p 4433 -d

# Terminal 2 — mbedtls client
BUILD=~/misc/mbedtls-dtls13/build-dbg
$BUILD/programs/ssl/ssl_client2 \
    dtls=1 server_addr=127.0.0.1 server_port=4433 \
    force_version=dtls13 debug_level=2
```

`server_addr=127.0.0.1` is required: on macOS `localhost` resolves to `::1`
(IPv6) but wolfSSL server binds to IPv4 only.

### With key material comparison

mbedtls side:

```sh
$BUILD/programs/ssl/ssl_client2 \
    dtls=1 server_addr=127.0.0.1 server_port=4433 \
    force_version=dtls13 \
    nss_keylog=1 nss_keylog_file=/tmp/mbedtls_keylog.txt
```

wolfSSL side (requires SHOW_SECRETS build above):

```sh
cd ~/misc/wolfssl
./examples/server/server -u -v 4 -i -p 4433 -d
# keylog written to ./sslkeylog.log
```

---

## Current interop status (2026-03-28)

### mbedtls client ↔ wolfSSL server: **WORKING**

Full handshake + application data.

### wolfSSL client ↔ mbedtls server: **WORKING**

Full handshake + application data + PSK (psk_ephemeral):
- mbedtls server prints `Protocol is DTLSv1.3`
- wolfSSL client prints `SSL version is DTLSv1.3`, `SSL cipher suite is TLS_AES_256_GCM_SHA384`
- Application data flows both directions.
- PSK with `-s --openssl-psk`: mbedtls server prints `key exchange mode: psk_ephemeral`.

**wolfSSL build requirement for PSK:** must include `--enable-psk` in configure flags.
Without it, `NO_PSK` is defined and the `-s`/`--openssl-psk` flags are compiled out.

### Direction B flake: connected-UDP ICMP (`-0x4C`) [mitigated]

On WSL/Linux, `ssl_client2` uses a **connected** UDP socket. The wolfSSL example
server (`-u -i`) sets `clientfd == sockfd` and `CloseSocket`s it right after the
app reply + `wolfSSL_shutdown`. Late client ACKs then elicit ICMP port-unreachable,
which surfaces as `ECONNREFUSED` / `MBEDTLS_ERR_NET_RECV_FAILED` (`-0x4C`) — even
when the reply datagram is already queued. `debug_level≥2` (needed for ACK/HRR
asserts) widens the race; `debug_level=0` and `-Y` (P-256) shrink it.

Mitigations:
- Runner uses `-Y` and keeps client debug at 0 unless an assert needs library lines.
- `mbedtls_net_recv` retries once after `ECONNREFUSED` / `WSAECONNREFUSED` so a
  queued datagram can still be read.

---

## Bugs fixed (all merged to `dtls13` branch)

### (a) Wrong AAD in `ssl_decrypt_buf` [fixed]

`ssl_extract_add_data_from_record` was called with `NULL, 0` for the DTLS 1.3
unified header, causing it to fall through to the legacy `type||version||length`
AAD instead of the raw unified header bytes (RFC 9147 §4.3.3).

Fix: detect `(rec->buf[0] & 0xE0) == 0x20` and pass `rec->buf[0..data_offset-1]`
as AAD.

### (b) Wrong nonce: epoch included in DTLS 1.3 nonce [fixed]

`ssl_build_record_nonce` was XOR-ing the full 8-byte `rec->ctr` (including
epoch bytes [0..1]) into the static IV.  RFC 9147 §4.2 says only the 48-bit
per-epoch sequence number is XOR'd.

Fix: for DTLS 1.3, use `rec->ctr + 2` (skip epoch) as the dynamic IV on both
encrypt and decrypt paths.

### (c) SNE AAD restore was wrong [fixed]

After SNE-decrypting the sequence field, the code restored the encrypted seq
bytes to `rec->buf` before calling `mbedtls_ssl_decrypt_buf`, under the
mistaken assumption that AAD must use the on-wire (encrypted) seq.

RFC 9147 §4.2.3: the sender applies SNE *after* AEAD; the receiver reverses
SNE *before* AEAD; AAD uses the unified header with the **plaintext** sequence
number (post-SNE reversal).

Fix: remove the restore.  After `ssl_dtls13_sne_apply`, `rec->buf[1..2]` hold
the plaintext seq and are used directly as AAD.

### (d) Legacy DTLS header on encrypt path [fixed]

`mbedtls_ssl_write_record` was writing a 13-byte legacy DTLS 1.2 header
(`17 fe fd epoch seq len`) for all records including DTLS 1.3 epoch ≥2 records.
wolfSSL does not recognise these as DTLS 1.3 records.

Fix: after `mbedtls_ssl_encrypt_buf` returns, write the 5-byte DTLS 1.3
unified header at `out_hdr`, `memmove` ciphertext to follow it, and set
`protected_record_size = 5 + len`.  Also:
- Build the unified header AAD in `mbedtls_ssl_encrypt_buf` (plaintext seq).
- Derive outbound SNE key (`sn_key_enc`) from local write secret; apply SNE
  to seq field in the transmitted header after AEAD.

### (e) Server never sent ACK for client Finished [fixed]

RFC 9147 §7.2.1: the server MUST send an ACK for the client's final Finished
flight after verifying it.  wolfSSL enters `WAIT_FINISHED_ACK` state and keeps
retransmitting its Finished if no ACK arrives, causing an infinite retransmit
loop.

The mbedtls server's `ssl_tls13_process_client_finished` freed the server
flight and advanced the state machine, but never set `ssl->dtls13_ack_pending`.
The `dtls13_ack_pending` flag was only set for discarded future-epoch records
(empty ACK path), not for successfully-verified Finished messages.

Fix: set `ssl->dtls13_ack_pending = 1` in `ssl_tls13_process_client_finished`
after `mbedtls_ssl_recv_flight_completed`.  The ACK is emitted at the top of
the next `ssl_read_record` call.

---

### (f) Wrong HKDF label prefix in PSK binder derivation [fixed]

`mbedtls_ssl_tls13_create_psk_binder()` derived the `ext_binder` / `res_binder`
key using `mbedtls_ssl_tls13_derive_secret()`, which hardcodes the TLS 1.3 label
prefix `"tls13 "`.  For DTLS 1.3 the prefix must be `"dtls13"` (RFC 9147 §5.2).
wolfSSL correctly uses `"dtls13"` for binder key derivation in DTLS 1.3 mode, so
the binder HMAC never matched and the server rejected the ClientHello with
`DECODE_ERROR`.

Fix: replace both `mbedtls_ssl_tls13_derive_secret()` calls in
`mbedtls_ssl_tls13_create_psk_binder()` with `ssl_tls13_derive_secret_with_prefix()`
passing `use_dtls13_prefix` (already derived from `ssl->conf->transport` at the top
of that function).

---

## Automated tests (4.7 — complete)

wolfSSL interop tests are automated via the YAML test framework:

- Runner: `tests/dtls13/runners/wolfssl.yaml`
- Cases: `tests/dtls13/cases/interop-wolfssl.yaml` (4 test cases)
- Generated script: `tests/dtls13/dtls13-wolfssl-tests.sh`
- Guard: `requires_wolfssl` in `tests/ssl-opt.sh` (skips if `WOLFSSL_DIR` not set)

To run:

```sh
WOLFSSL_DIR=~/misc/wolfssl ./build-dbg/tests/dtls13/dtls13-wolfssl-tests.sh
```

All 4 tests pass (full handshake, application data, server ACKs Finished, PSK psk_ephemeral).

## Phase 5.8 — KeyUpdate and CID interop findings (2026-03-30)

### KeyUpdate: mbedtls post-handshake message_seq counter starts at 0 — MBEDTLS BUG

**FINDING REVISED 2026-03-31**: The original attribution to wolfSSL was incorrect.

RFC 9147 §5.2 states explicitly:
> "Note: In DTLS 1.2, the message_seq was reset to zero in case of a rehandshake
> (i.e., renegotiation). On the surface, a rehandshake in DTLS 1.2 shares similarities
> with a post-handshake message exchange in DTLS 1.3. However, in DTLS 1.3 the
> message_seq is **not** reset, to allow distinguishing a retransmission from a
> previously sent post-handshake message from a newly sent post-handshake message."

wolfSSL 5.9.0 continues the handshake `message_seq` counter into the post-handshake
phase (sending KeyUpdate with seq=2 after a handshake that consumed seqs 0 and 1).
This is **correct per the RFC**.

mbedtls uses a separate `dtls13_post_hs_in_msg_seq` counter (`ssl_context`, `ssl.h:1790`)
initialized to 0 at context creation and incremented independently. This is **wrong**:
it expects seq=0 for the first post-handshake message regardless of the handshake
sequence count, causing wolfSSL's seq=2 KeyUpdate to be buffered as a "future" message.

Reproduction: `wolfssl client -u -v 4 -d -p 4433 -I` (the `-I` flag triggers
`wolfSSL_update_keys()` after the handshake). The mbedtls server receives:

```
received future KeyUpdate (type=24) seq=2 (next expected=0)
```

The server's handshake ends with `in_msg_seq=2` (Finished consumed seq=1 → seq=2).
wolfSSL sends KeyUpdate with seq=2. mbedtls buffers it as "future", ACKs it, but
never processes it — the connection stalls in a retransmit loop.

**Root cause**: mbedtls bug — both `dtls13_post_hs_in_msg_seq` (inbound) and
`dtls13_post_hs_msg_seq` (outbound) should be initialized to `handshake->in_msg_seq`
and `handshake->out_msg_seq` respectively at handshake completion, not to 0.

**Fix (implemented 2026-03-31, commit 8234bcee75)**:
- In `mbedtls_ssl_handshake_set_state()` (ssl_misc.h): when transitioning to
  `MBEDTLS_SSL_HANDSHAKE_OVER` exactly, sync both post-HS counters from handshake
  counters.
- In `ssl_msg.c` seq check: use `handshake->in_msg_seq` (not `dtls13_post_hs_in_msg_seq`)
  when state is not exactly `HANDSHAKE_OVER` — during finishing states (NST_WAIT_ACK etc.)
  the post-HS counter is not yet synced.
- Added wolfSSL KeyUpdate interop test: `dtls13-wolfssl-tests.sh` case
  "A: wolfSSL client sends KeyUpdate after handshake".

**Verification**: All 25 mbedtls dtls13 integration tests pass. All 12 wolfSSL
interop tests pass (including new KeyUpdate test). wolfSSL client -I now
completes with exit=0 (no more retransmit loop).

**Status**: FIXED (Phase 7 item 15 complete).

### CID: not compiled into wolfSSL 5.9.0 build

The wolfSSL build in `~/misc/wolfssl` was configured without `--enable-dtls-cid`.
The `WOLFSSL_DTLS_CID` preprocessor macro is not defined, so the `--cid` client
flag is a no-op and CID extension is never sent.

To test CID interop, wolfSSL would need to be rebuilt:
```sh
./configure --disable-asm --enable-dtls13 --enable-dtls --enable-dtls-cid
make -j4
```

**Resolution**: CID interop with wolfSSL deferred pending wolfSSL rebuild.
Not blocking — mbedtls↔mbedtls CID tests already pass (Phase 5.5a).
