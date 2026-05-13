/*
 *  Stack-managed DTLS cookie construction (HVR for DTLS 1.2,
 *  HRR for DTLS 1.3) keyed off the application-supplied secret
 *  configured via mbedtls_ssl_conf_dtls_cookie_secret().
 *
 *  See local-docs/cookie-impl-plan.md §1.2 and §1.4 for the wire
 *  format and helper-call surface.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "ssl_misc.h"

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/error.h"
#include "mbedtls/psa_util.h"

#include <string.h>

static int local_err_translation(psa_status_t status)
{
    return psa_status_to_mbedtls(status, psa_to_ssl_errors,
                                 ARRAY_LENGTH(psa_to_ssl_errors),
                                 psa_generic_status_to_mbedtls);
}
#define PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)

/* Match the reference cookie implementation: HMAC-SHA-256 truncated to
 * 28 bytes when SHA-256 is available, else HMAC-SHA-384 truncated to
 * 28 bytes.  See ssl_cookie.c COOKIE_HMAC_LEN. */
#if defined(PSA_WANT_ALG_SHA_256)
#define COOKIE_SECRET_HMAC_ALG  PSA_ALG_HMAC(PSA_ALG_SHA_256)
#elif defined(PSA_WANT_ALG_SHA_384)
#define COOKIE_SECRET_HMAC_ALG  PSA_ALG_HMAC(PSA_ALG_SHA_384)
#else
#error "DTLS cookie secret needs SHA-256 or SHA-384"
#endif

#define COOKIE_SECRET_HMAC_LEN  28
#define COOKIE_SECRET_HMAC_TRUNC \
    PSA_ALG_TRUNCATED_MAC(COOKIE_SECRET_HMAC_ALG, COOKIE_SECRET_HMAC_LEN)

/* Import the application's raw secret into a transient PSA HMAC key.
 * Caller must call psa_destroy_key on the returned key id.  Returns 0
 * on success or a translated mbedtls error. */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_cookie_secret_import_key(
    const unsigned char *secret, size_t secret_len,
    mbedtls_svc_key_id_t *key_id_out)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, COOKIE_SECRET_HMAC_TRUNC);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(secret_len));

    status = psa_import_key(&attributes, secret, secret_len, key_id_out);
    if (status != PSA_SUCCESS) {
        return PSA_TO_MBEDTLS_ERR(status);
    }
    return 0;
}

/* Current cookie timestamp.  Seconds since epoch if MBEDTLS_HAVE_TIME;
 * else 0 (timeout window is effectively infinite — same caveat as
 * MBEDTLS_SSL_COOKIE_TIMEOUT in the reference impl). */
static uint32_t ssl_cookie_secret_now(void)
{
#if defined(MBEDTLS_HAVE_TIME)
    return (uint32_t) mbedtls_time(NULL);
#else
    return 0;
#endif
}

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
/* ------------------------------------------------------------------ */
/* TEST-ONLY: fault injection for DTLS 1.3 HRR cookie writes.         */
/* Process-global, single-use (consumed on next write).  Used by      */
/* ssl_server2 to drive negative-path integration tests.              */
/* ------------------------------------------------------------------ */
static int      g_test_hrr_cookie_fault_mode;       /* 0 = disabled */
static uint32_t g_test_hrr_cookie_expire_seconds;

void mbedtls_ssl_dtls13_test_set_hrr_cookie_fault(int fault_mode,
                                                  uint32_t expire_seconds)
{
    g_test_hrr_cookie_fault_mode    = fault_mode;
    g_test_hrr_cookie_expire_seconds = expire_seconds;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

/* ------------------------------------------------------------------ */
/* DTLS 1.2 HVR cookie (no transcript binding)                        */
/* ------------------------------------------------------------------ */

/* Wire format:
 *     timestamp (4 BE) || HMAC(secret, timestamp || cli_id)[0..28]
 * Total: 32 bytes.  Matches the reference impl's wire format with the
 * key now coming from the application-supplied secret. */
#define SSL_DTLS12_HVR_COOKIE_LEN  (4 + COOKIE_SECRET_HMAC_LEN)

int mbedtls_ssl_dtls12_hvr_cookie_write_from_secret(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *cli_id, size_t cli_id_len,
    unsigned char **p, unsigned char *end)
{
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_status_t status;
    psa_status_t abort_status;
    size_t out_len = 0;
    unsigned char ts_be[4];
    uint32_t t;
    int ret;

    if (secret == NULL || cli_id == NULL || p == NULL || *p == NULL ||
        end == NULL || end < *p) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if ((size_t) (end - *p) < SSL_DTLS12_HVR_COOKIE_LEN) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    ret = ssl_cookie_secret_import_key(secret, secret_len, &key_id);
    if (ret != 0) {
        return ret;
    }

    t = ssl_cookie_secret_now();
    MBEDTLS_PUT_UINT32_BE(t, ts_be, 0);
    MBEDTLS_PUT_UINT32_BE(t, *p, 0);

    status = psa_mac_sign_setup(&op, key_id, COOKIE_SECRET_HMAC_TRUNC);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, ts_be, 4);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cli_id, cli_id_len);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_sign_finish(&op, *p + 4, COOKIE_SECRET_HMAC_LEN,
                                 &out_len);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }

    *p += SSL_DTLS12_HVR_COOKIE_LEN;
    ret = 0;

exit:
    abort_status = psa_mac_abort(&op);
    if (ret == 0 && abort_status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(abort_status);
    }
    (void) psa_destroy_key(key_id);
    return ret;
}

int mbedtls_ssl_dtls12_hvr_cookie_check_from_secret(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *cli_id, size_t cli_id_len,
    const unsigned char *cookie, size_t cookie_len,
    uint32_t timeout_seconds)
{
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_status_t status;
    psa_status_t abort_status;
    uint32_t t_cookie, t_now;
    int ret;

    if (secret == NULL || cli_id == NULL || cookie == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (cookie_len != SSL_DTLS12_HVR_COOKIE_LEN) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ret = ssl_cookie_secret_import_key(secret, secret_len, &key_id);
    if (ret != 0) {
        return ret;
    }

    status = psa_mac_verify_setup(&op, key_id, COOKIE_SECRET_HMAC_TRUNC);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cookie, 4);   /* timestamp */
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cli_id, cli_id_len);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_verify_finish(&op, cookie + 4, COOKIE_SECRET_HMAC_LEN);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        /* Cookie is well-formed but its HMAC doesn't match — wrong
         * secret, tampered cookie, or a stale issuance key. */
        ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        goto exit;
    }
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }

    /* HMAC OK — check freshness. */
    t_cookie = MBEDTLS_GET_UINT32_BE(cookie, 0);
    t_now    = ssl_cookie_secret_now();
    if (timeout_seconds != 0 &&
        (uint32_t) (t_now - t_cookie) > timeout_seconds) {
        ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        goto exit;
    }
    ret = 0;

exit:
    abort_status = psa_mac_abort(&op);
    if (ret == 0 && abort_status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(abort_status);
    }
    (void) psa_destroy_key(key_id);
    return ret;
}

/* ------------------------------------------------------------------ */
/* DTLS 1.3 HRR cookie (carries ciphersuite_id + H(ClientHello1))     */
/* ------------------------------------------------------------------ */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

/* Wire format:
 *     ciphersuite_id (2 BE) || timestamp (4 BE) || ch1_hash (hash_len)
 *     || HMAC(secret, timestamp || cli_id || ciphersuite_id || ch1_hash)[0..28]
 *
 * Total: 6 + ch1_hash_len + 28 bytes.
 *
 * The hash length is determined by the ciphersuite's transcript hash;
 * caller passes it explicitly because the helper does not crack the
 * ciphersuite_id. */

#define SSL_DTLS13_HRR_COOKIE_FIXED_LEN  (2 + 4 + COOKIE_SECRET_HMAC_LEN)

int mbedtls_ssl_dtls13_hrr_cookie_write_from_secret(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *cli_id, size_t cli_id_len,
    uint16_t ciphersuite_id,
    const unsigned char *ch1_hash, size_t ch1_hash_len,
    unsigned char **p, unsigned char *end)
{
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_status_t status;
    psa_status_t abort_status;
    size_t out_len = 0;
    unsigned char ts_be[4];
    unsigned char cs_be[2];
    uint32_t t;
    size_t cookie_len = SSL_DTLS13_HRR_COOKIE_FIXED_LEN + ch1_hash_len;
    int ret;

    if (secret == NULL || cli_id == NULL || ch1_hash == NULL ||
        p == NULL || *p == NULL || end == NULL || end < *p) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ch1_hash_len == 0 || ch1_hash_len > PSA_HASH_MAX_SIZE) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if ((size_t) (end - *p) < cookie_len) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    ret = ssl_cookie_secret_import_key(secret, secret_len, &key_id);
    if (ret != 0) {
        return ret;
    }

    t = ssl_cookie_secret_now();
    /* TEST ONLY: mode 2 — backdate the timestamp so the verifier sees
     * the cookie as expired.  Consumed on use. */
    if (g_test_hrr_cookie_fault_mode == 2) {
        t -= g_test_hrr_cookie_expire_seconds;
        g_test_hrr_cookie_fault_mode = 0;
    }
    MBEDTLS_PUT_UINT16_BE(ciphersuite_id, cs_be, 0);
    MBEDTLS_PUT_UINT32_BE(t, ts_be, 0);

    /* Write the cookie out:
     *   ciphersuite_id || timestamp || ch1_hash || HMAC */
    MBEDTLS_PUT_UINT16_BE(ciphersuite_id, *p, 0);
    MBEDTLS_PUT_UINT32_BE(t, *p, 2);
    memcpy(*p + 6, ch1_hash, ch1_hash_len);

    /* HMAC input: timestamp || cli_id || ciphersuite_id || ch1_hash. */
    status = psa_mac_sign_setup(&op, key_id, COOKIE_SECRET_HMAC_TRUNC);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, ts_be, 4);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cli_id, cli_id_len);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cs_be, 2);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, ch1_hash, ch1_hash_len);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_sign_finish(&op, *p + 6 + ch1_hash_len,
                                 COOKIE_SECRET_HMAC_LEN, &out_len);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }

    /* TEST ONLY: mode 1 — corrupt the last HMAC byte so the verifier
     * rejects the cookie.  Consumed on use. */
    if (g_test_hrr_cookie_fault_mode == 1) {
        (*p)[cookie_len - 1] ^= 0xFF;
        g_test_hrr_cookie_fault_mode = 0;
    }

    *p += cookie_len;
    ret = 0;

exit:
    abort_status = psa_mac_abort(&op);
    if (ret == 0 && abort_status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(abort_status);
    }
    (void) psa_destroy_key(key_id);
    return ret;
}

int mbedtls_ssl_dtls13_hrr_cookie_check_from_secret(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *cli_id, size_t cli_id_len,
    const unsigned char *cookie, size_t cookie_len,
    size_t ch1_hash_len,
    uint32_t timeout_seconds,
    uint16_t *ciphersuite_id_out,
    const unsigned char **ch1_hash_out)
{
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_status_t status;
    psa_status_t abort_status;
    uint16_t cs;
    uint32_t t_cookie, t_now;
    unsigned char cs_be[2];
    int ret;

    if (secret == NULL || cli_id == NULL || cookie == NULL ||
        ciphersuite_id_out == NULL || ch1_hash_out == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ch1_hash_len == 0 || ch1_hash_len > PSA_HASH_MAX_SIZE) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (cookie_len != SSL_DTLS13_HRR_COOKIE_FIXED_LEN + ch1_hash_len) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    cs       = MBEDTLS_GET_UINT16_BE(cookie, 0);
    t_cookie = MBEDTLS_GET_UINT32_BE(cookie, 2);
    MBEDTLS_PUT_UINT16_BE(cs, cs_be, 0);

    ret = ssl_cookie_secret_import_key(secret, secret_len, &key_id);
    if (ret != 0) {
        return ret;
    }

    status = psa_mac_verify_setup(&op, key_id, COOKIE_SECRET_HMAC_TRUNC);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cookie + 2, 4);     /* timestamp */
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cli_id, cli_id_len);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cs_be, 2);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_update(&op, cookie + 6, ch1_hash_len);
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }
    status = psa_mac_verify_finish(&op, cookie + 6 + ch1_hash_len,
                                   COOKIE_SECRET_HMAC_LEN);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        /* Cookie HMAC mismatch — wrong secret, tampered cookie, or
         * stale key. */
        ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        goto exit;
    }
    if (status != PSA_SUCCESS) { ret = PSA_TO_MBEDTLS_ERR(status); goto exit; }

    /* HMAC OK — check freshness. */
    t_now = ssl_cookie_secret_now();
    if (timeout_seconds != 0 &&
        (uint32_t) (t_now - t_cookie) > timeout_seconds) {
        ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        goto exit;
    }

    *ciphersuite_id_out = cs;
    *ch1_hash_out       = cookie + 6;
    ret = 0;

exit:
    abort_status = psa_mac_abort(&op);
    if (ret == 0 && abort_status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(abort_status);
    }
    (void) psa_destroy_key(key_id);
    return ret;
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* MBEDTLS_SSL_DTLS_HELLO_VERIFY && MBEDTLS_SSL_SRV_C */
