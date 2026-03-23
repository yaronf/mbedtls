/**
 * \file ssl_attestation.h
 *
 * \brief TLS stack interface to the attestation shim (§5.3 of
 *        draft-fossati-seat-early-attestation-03).
 *
 * This header defines the callback types and configuration struct that
 * connect the mbedtls TLS handshake to an attestation provider (the
 * "Early Attestation Shim" in the draft's Figure 2).  The provider is
 * responsible for producing and verifying CMW-encoded Evidence; it may
 * be implemented as a synthetic test harness or a real TEE interface.
 *
 * The TLS stack passes to the provider:
 *   - The attestation binder (derived from the transcript and the TLS
 *     Identity Key per §5.1.1); this serves as the freshness nonce.
 *   - The TLS Identity Key public component in DER format (TIK-C or
 *     TIK-S depending on which peer is attesting).
 *
 * The provider returns (on generate) or consumes (on verify) an opaque
 * CMW byte string that will be placed in / read from the Attestation
 * extension of the Certificate message (§4.1).
 *
 * Nothing in this header depends on QCBOR or any CMW internals; the
 * CMW encoding is entirely the provider's responsibility.
 */

#ifndef MBEDTLS_SSL_ATTESTATION_H
#define MBEDTLS_SSL_ATTESTATION_H

#include "mbedtls/build_info.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief   Callback type: generate attestation Evidence.
 *
 *          Called by the TLS stack when it is about to write the
 *          Attestation extension into the Certificate message.
 *
 * \param p_attest      Opaque context pointer supplied by the caller
 *                      when registering the callback.
 * \param binder        Attestation binder value (c_attest_binder or
 *                      s_attest_binder per §5.1.1).  Not secret.
 * \param binder_len    Length of \p binder in bytes (== hash output
 *                      length of the negotiated PRF).
 * \param tik_pub_der   TLS Identity Key public component, DER-encoded
 *                      SubjectPublicKeyInfo (TIK-C or TIK-S).
 * \param tik_pub_der_len  Length of \p tik_pub_der in bytes.
 * \param cmw_buf       Output buffer for the CMW-encoded Evidence blob.
 * \param cmw_buf_size  Size of \p cmw_buf in bytes.
 * \param cmw_len       On success, set to the number of bytes written
 *                      into \p cmw_buf.
 *
 * \return  0 on success.
 *          A non-zero error code on failure; the TLS stack will send
 *          an \c unsupported_evidence alert and abort the handshake.
 */
typedef int mbedtls_ssl_generate_evidence_t(
    void *p_attest,
    const unsigned char *binder,
    size_t binder_len,
    const unsigned char *tik_pub_der,
    size_t tik_pub_der_len,
    unsigned char *cmw_buf,
    size_t cmw_buf_size,
    size_t *cmw_len);

/**
 * \brief   Callback type: verify attestation Evidence received from peer.
 *
 *          Called by the TLS stack after parsing the Attestation
 *          extension from the peer's Certificate message.
 *
 * \param p_attest      Opaque context pointer.
 * \param binder        The binder the stack computed for this peer
 *                      (c_attest_binder or s_attest_binder per §5.1.1).
 * \param binder_len    Length of \p binder in bytes.
 * \param tik_pub_der   Peer's TLS Identity Key public component,
 *                      DER-encoded SubjectPublicKeyInfo, extracted from
 *                      the peer's end-entity certificate.
 * \param tik_pub_der_len  Length of \p tik_pub_der in bytes.
 * \param cmw           The raw CMW byte string from the peer's
 *                      Attestation extension.
 * \param cmw_len       Length of \p cmw in bytes.
 *
 * \return  0 if the Evidence is valid and the peer is trusted.
 *          A non-zero error code on any failure (binder mismatch,
 *          untrusted ROT, malformed CMW, etc.); the TLS stack will
 *          send an \c unsupported_evidence alert and abort.
 */
typedef int mbedtls_ssl_verify_evidence_t(
    void *p_attest,
    const unsigned char *binder,
    size_t binder_len,
    const unsigned char *tik_pub_der,
    size_t tik_pub_der_len,
    const unsigned char *cmw,
    size_t cmw_len);

/**
 * \brief   Per-endpoint attestation configuration.
 *
 *          One instance covers a single TLS endpoint (client or server).
 *          Set in \c mbedtls_ssl_config via
 *          mbedtls_ssl_conf_attestation().
 *
 *          All pointer fields default to NULL (attestation disabled).
 */
typedef struct mbedtls_ssl_attestation_conf {
    /**
     * Whether this endpoint will offer Evidence in its own Certificate
     * message.  Requires \c f_generate_evidence to be set.
     */
    int offer_evidence;

    /**
     * Whether this endpoint will request Evidence from the peer (i.e.
     * include evidence_request in ClientHello / evidence_proposal in
     * EncryptedExtensions).
     */
    int request_peer_evidence;

    /**
     * Whether Evidence from the peer is mandatory.  If set and the
     * peer does not provide Evidence, the handshake is aborted with
     * \c unsupported_evidence.
     */
    int require_peer_evidence;

    /** Callback: produce a CMW Evidence blob.  NULL if not attesting. */
    mbedtls_ssl_generate_evidence_t *f_generate_evidence;

    /** Callback: verify a CMW Evidence blob from the peer.  NULL if
     *  not acting as a relying party. */
    mbedtls_ssl_verify_evidence_t *f_verify_evidence;

    /** Opaque context passed to both callbacks. */
    void *p_attest;
} mbedtls_ssl_attestation_conf;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_SSL_ATTESTATION_H */
