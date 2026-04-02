# DTLS Renegotiation Failure Analysis: `psa_alg=0x00000000` in `ssl_swap_epochs`

**Date**: 2026-04-02  
**Branch**: dtls13  
**Test**: "Renegotiation: DTLS, client-initiated" (ssl-opt.sh)  
**Symptom**: Server returns `MBEDTLS_ERR_SSL_INTERNAL_ERROR (-0x6c00)` during `mbedtls_ssl_flight_transmit` on the renegotiation flight.  
**Log**: `/tmp/renego-fix3.log`

---

## Executive Summary

After a DTLS 1.2 initial handshake completes, `ssl->transform_out` and `ssl->transform_negotiate` **alias the same heap struct**. When renegotiation starts, `ssl_handshake_init` frees the struct via `transform_negotiate`, zeroing it (via `mbedtls_platform_zeroize`). `transform_out` is left as a dangling pointer into zeroed freed memory. When the renegotiation flight is transmitted, `ssl_swap_epochs` tries to use `transform_out` and finds `psa_alg == 0`, causing an `INTERNAL_ERROR`.

---

## Message-Level Trace

### Phase 1: Initial handshake completes (log lines 1–725)

Normal DTLS 1.2 handshake. Key events:

| Line | Event |
|------|-------|
| ~600 | Server sends Finished, calls `mbedtls_ssl_write_finished` |
| 7563 (ssl_tls.c) | `ssl->transform_out = ssl->transform_negotiate` — **alias created** |
| 7539 (ssl_tls.c) | `ssl->handshake->alt_transform_out = ssl->transform_out` (the old epoch-0 transform, or NULL) |
| 711 | `<= write finished` |
| 714 | `server state: 14` (FLUSH_BUFFERS) |
| 716 | State: FLUSH_BUFFERS → HANDSHAKE_WRAPUP |
| 720 | `=> handshake wrapup` |
| **722** | `"skip freeing handshake and transform"` — **wrapup skips `wrapup_free_hs_transform`** because `flight != NULL` |
| 723 | State: HANDSHAKE_WRAPUP → HANDSHAKE_OVER |

At this point:
- `ssl->transform_out` → struct at address `0x101787450` (with valid `psa_alg`)
- `ssl->transform_negotiate` → **same address** `0x101787450`
- `ssl->handshake` still alive (flight kept for potential retransmit)

### Phase 2: Server reads post-handshake data, receives renegotiation ClientHello (log lines 726–800)

| Line | Event |
|------|-------|
| 726 | `ok` — handshake complete, application proceeds |
| 734 | Server calls `mbedtls_ssl_read` |
| 741–797 | Server receives and decrypts encrypted ClientHello (DTLS epoch 1) |
| 798 | Handshake message type=1 (ClientHello) recognized — triggers renegotiation |
| 800 | `=> renegotiate` |

### Phase 3: `ssl_handshake_init` for renegotiation (log line 801)

`mbedtls_ssl_start_renegotiation` → `ssl_handshake_init`:

```c
// ssl_tls.c:981
if (ssl->transform_negotiate) {
    mbedtls_ssl_transform_free(ssl->transform_negotiate);
    // ** This frees AND ZEROES the struct at 0x101787450 **
    // ** ssl->transform_out still points to 0x101787450 **
    ssl->transform_negotiate = NULL;   // fix attempt: now allocates fresh struct
}
...
ssl->transform_negotiate = mbedtls_calloc(1, sizeof(mbedtls_ssl_transform));
// New allocation at some address != 0x101787450
...
mbedtls_ssl_transform_init(ssl->transform_negotiate);  // zeros the NEW struct (benign)
...
ssl->handshake->alt_transform_out = ssl->transform_out;
// ** assigns 0x101787450 — the freed, zeroed struct — to alt_transform_out **
```

Debug print at line 801:
```
ssl_tls.c:1084: |2| ssl_handshake_init: transform_out=0x101787450 psa_alg=0x00000000
```

`psa_alg` is zero because `mbedtls_ssl_transform_free` called `mbedtls_platform_zeroize` on the whole struct. The pointer is dangling — the memory is freed but not yet reallocated.

### Phase 4: Renegotiation handshake proceeds (log lines 802–1031)

The server successfully:
- Parses the renegotiation ClientHello
- Selects `TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256`
- Writes ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
- Appends all to the flight queue

No problem up to the flight transmit.

### Phase 5: Flight transmit hits the bug (log lines 1031–1037)

| Line | Event |
|------|-------|
| 1029 | `=> mbedtls_ssl_flight_transmit` |
| 1031 | `"skip swap epochs"` — because `alt_transform_out == transform_out` (both point to `0x101787450`) |
| 1032 | `"Unsupported psa_alg=0x00000000"` — `mbedtls_ssl_get_record_expansion` fails |
| 1033 | `mbedtls_ssl_flight_transmit() returned -27648 (-0x6c00)` |

The "skip swap epochs" logic in `ssl_flight_transmit`:
```c
// ssl_msg.c
if (ssl->handshake->alt_transform_out == ssl->transform_out) {
    MBEDTLS_SSL_DEBUG_MSG(3, ("skip swap epochs"));
} else {
    // actually swap epoch/transform
}
```

Since both `alt_transform_out` and `transform_out` are the same dangling pointer (`0x101787450`), the swap is skipped. Then `mbedtls_ssl_get_record_expansion` is called with `transform_out` which has `psa_alg=0`, and returns `INTERNAL_ERROR`.

---

## Root Cause Chain

```
mbedtls_ssl_write_finished (initial handshake)
  └─ ssl->transform_out = ssl->transform_negotiate       [alias created]

ssl_handshake_wrapup (initial handshake)
  └─ flight != NULL  →  skip wrapup_free_hs_transform    [alias NOT broken]
     (transform_negotiate NOT nulled, transform NOT promoted)

ssl_handshake_init (renegotiation)
  ├─ mbedtls_ssl_transform_free(ssl->transform_negotiate)
  │    └─ mbedtls_platform_zeroize(struct at 0x101787450)  [struct zeroed]
  │    └─ ssl->transform_out now DANGLING into zeroed freed memory
  ├─ ssl->transform_negotiate = NULL                      [fix clears alias]
  ├─ ssl->transform_negotiate = calloc(...)               [new alloc, different addr]
  └─ ssl->handshake->alt_transform_out = ssl->transform_out
       └─ = 0x101787450  [dangling]

ssl_flight_transmit (renegotiation flight)
  └─ alt_transform_out == transform_out  →  skip swap
  └─ mbedtls_ssl_get_record_expansion(ssl->transform_out)
       └─ transform_out->psa_alg == 0  →  INTERNAL_ERROR
```

---

## Why the First Fix Was Insufficient

The fix `ssl->transform_negotiate = NULL` after the free was correct in preventing `mbedtls_ssl_transform_init` from zeroing the same address again. However, it does not fix the problem that `ssl->transform_out` still points to the freed struct.

The fix eliminated the double-zeroing path but not the original dangling-pointer problem.

---

## The Real Problem

After `ssl_handshake_wrapup` skips `wrapup_free_hs_transform`, the SSL context is in a state where:
- `ssl->transform` is still the old (pre-handshake) transform, or NULL on first handshake
- `ssl->transform_negotiate` is the newly-negotiated transform (valid)
- `ssl->transform_out` = `ssl->transform_negotiate` (the new valid transform)

This state is **intentional**: the flight for the Finished message needs `transform_out` to remain live for retransmit. However, when renegotiation begins, `ssl_handshake_init` must not free `transform_negotiate` without also updating `transform_out`.

---

## Correct Fix

`ssl_handshake_init` frees `transform_negotiate`. At that point it must also null `transform_out` if it aliases `transform_negotiate`, so that `alt_transform_out` is assigned NULL rather than a dangling pointer.

In `ssl_handshake_init`, after freeing `transform_negotiate` and before `alt_transform_out` is assigned:

```c
if (ssl->transform_negotiate) {
    mbedtls_ssl_transform_free(ssl->transform_negotiate);
    ssl->transform_negotiate = NULL;

    /* If transform_out aliases transform_negotiate (DTLS: wrapup skipped
     * wrapup_free_hs_transform because flight was pending), null it too.
     * ssl_handshake_init is about to assign transform_out to alt_transform_out;
     * a dangling pointer there will cause ssl_swap_epochs to skip the swap
     * and later pass a zeroed struct to mbedtls_ssl_get_record_expansion. */
    // SEE BELOW: actually the correct fix is further down, where alt_transform_out is assigned
}
```

But there is a subtlety: the purpose of `alt_transform_out` is to allow epoch-0 retransmits. For renegotiation, by the time `ssl_handshake_init` runs, the Finished flight has been successfully received (the client sent a renegotiation ClientHello in the post-handshake epoch, proving they received the Finished). So the old flight/transform are no longer needed.

**The minimal correct fix** is in `ssl_handshake_init`, before the `alt_transform_out` assignment:

```c
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        /* If transform_out was pointing to the just-freed transform_negotiate
         * (happens when wrapup_free_hs_transform was skipped due to pending flight),
         * null it so alt_transform_out below doesn't inherit a dangling pointer. */
        if (ssl->transform_out == ssl->transform_negotiate_was) {   // pseudo-code
            ssl->transform_out = NULL;
        }
        ssl->handshake->alt_transform_out = ssl->transform_out;
        ...
    }
#endif
```

Since we already null `ssl->transform_negotiate` before this block, we can't compare after the fact. The fix needs to happen **before** the free, or use the address comparison before nulling:

```c
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform_negotiate) {
        /* Save the address before freeing for the alias check below */
        mbedtls_ssl_transform *freed_transform = ssl->transform_negotiate;
        mbedtls_ssl_transform_free(ssl->transform_negotiate);
        ssl->transform_negotiate = NULL;

        /* DTLS: wrapup_free_hs_transform may have been skipped (flight pending),
         * leaving transform_out aliasing the now-freed struct. Null it. */
        if (ssl->transform_out == freed_transform) {
            ssl->transform_out = NULL;
        }
    }
#endif
```

Or equivalently, check before freeing:

```c
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform_negotiate) {
        /* DTLS: wrapup may have been skipped leaving transform_out aliasing
         * transform_negotiate. Clear the alias before freeing. */
        if (ssl->transform_out == ssl->transform_negotiate) {
            ssl->transform_out = NULL;
        }
        mbedtls_ssl_transform_free(ssl->transform_negotiate);
        ssl->transform_negotiate = NULL;
    }
#endif
```

This is the cleanest form: check for the alias, null `transform_out` before freeing, then free normally.

---

## Verification

After the fix:
- `ssl->transform_out = NULL` at renegotiation start
- `ssl->handshake->alt_transform_out = NULL`
- In `ssl_flight_transmit`: `alt_transform_out (NULL) != transform_out (NULL)` — wait, both NULL means the condition is still equal...

**Additional consideration**: when both are NULL, "skip swap epochs" fires again. But this time `transform_out` is NULL and `mbedtls_ssl_get_record_expansion` would check `ssl->transform_out != NULL` before using it.

Check `ssl_flight_transmit` behavior when `transform_out == NULL` (epoch 0, unencrypted):
- Line 2383: `skip swap epochs` fires when equal — meaning no transform change is needed
- For epoch 0, `transform_out = NULL` is the correct state (plaintext)
- `mbedtls_ssl_get_record_expansion` with `NULL` transform returns a fixed expansion (0 bytes overhead for plaintext)

So `transform_out = NULL` for the renegotiation flight is actually correct — the renegotiation ServerHello/Certificate/etc. go out in epoch 1 (the current epoch) with the existing transform. Wait — epoch 1 is the current epoch from the initial handshake. The renegotiation hasn't switched epochs yet.

**Revised understanding**: For DTLS renegotiation, the server's outgoing flight (ServerHello through ServerHelloDone) should be sent in epoch 1 (the current outgoing epoch, using the existing cipher). By setting `transform_out = NULL`, we lose the existing epoch-1 cipher.

The correct behavior: `alt_transform_out` should be the **previous epoch** transform (or NULL for epoch-0 retransmits), and `transform_out` should be the **current epoch** cipher. For renegotiation, the new handshake messages go out in epoch 1 (plaintext-equivalent for epoch-1 cipher).

Actually for DTLS renegotiation: the server's renegotiation flight is sent unencrypted (epoch 0 style) — no, that's wrong. After initial handshake, epoch 1 is the active cipher. The renegotiation ServerHello etc. go out in epoch 1.

The problem is more subtle: we need `transform_out` to remain valid (pointing to the epoch-1 cipher) but we've freed the struct it points to. The real fix is: don't free `transform_negotiate` in `ssl_handshake_init` when it's still being used as `transform_out`.

**The real correct fix** requires `wrapup_free_hs_transform` to NOT skip in the renegotiation case, OR to properly promote `transform_negotiate → transform` before `ssl_handshake_init` runs.

This is captured in the investigation notes below.

---

## Investigation Notes: Why Wrapup Skips Free

`ssl_handshake_wrapup` (ssl_tls.c:7460–7468):
```c
if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
    ssl->handshake->flight != NULL) {
    MBEDTLS_SSL_DEBUG_MSG(3, ("skip freeing handshake and transform"));
} else
    mbedtls_ssl_handshake_wrapup_free_hs_transform(ssl);
```

`wrapup_free_hs_transform` does:
```c
ssl->transform = ssl->transform_negotiate;   // promote: transform_negotiate → transform
ssl->transform_negotiate = NULL;
```

When wrapup is skipped, `ssl->transform` remains the OLD pre-handshake transform (or NULL), and `ssl->transform_negotiate` remains the new valid cipher. `ssl->transform_out` = `ssl->transform_negotiate` (set in `write_finished`).

The alternative fix is: in `ssl_handshake_init`, before freeing `transform_negotiate`, do what `wrapup_free_hs_transform` would have done: promote `transform_negotiate → transform` and leave `transform_out` pointing to the promoted struct.

```c
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform_negotiate) {
        /* DTLS: if wrapup_free_hs_transform was skipped (flight pending), we
         * need to complete the epoch promotion now before reinitializing for
         * the new handshake. The old transform_negotiate is the active outgoing
         * cipher (transform_out aliases it). Promote it to ssl->transform so
         * it stays valid, and leave transform_out pointing to it. */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
            ssl->transform_out == ssl->transform_negotiate) {
            /* Complete the promotion that wrapup skipped */
            if (ssl->transform) {
                mbedtls_ssl_transform_free(ssl->transform);
                mbedtls_free(ssl->transform);
            }
            ssl->transform = ssl->transform_negotiate;
            ssl->transform_negotiate = NULL;
            /* transform_out already points to ssl->transform — leave it */
        } else
#endif
        {
            mbedtls_ssl_transform_free(ssl->transform_negotiate);
            ssl->transform_negotiate = NULL;
        }
    }
#endif
```

This is the most semantically correct fix: it completes the deferred promotion, after which `transform_out` points to a properly owned struct under `ssl->transform`, and `ssl->transform_negotiate` is NULL and will be freshly allocated.

---

## Next Steps

1. Implement the alias-check fix in `ssl_handshake_init` (promote-before-free variant)
2. Revert debug prints from `ssl_msg.c` and `ssl_tls.c`
3. Run single renegotiation test to confirm fix
4. Run all 22 failing renegotiation tests
