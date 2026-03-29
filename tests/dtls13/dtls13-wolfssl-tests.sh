#!/bin/sh
# AUTO-GENERATED — do not edit.
# Regenerate: python3 tests/dtls13/generate.py --runner runners/wolfssl.yaml --emit
#
# Standalone DTLS 1.3 integration test script.
# Designed to run from the same directory as ssl-opt.sh (typically
# build-dbg/tests/ or any cmake build's tests/ directory).
#
# Sources ssl-opt.sh for infrastructure (run_test, requires_*, etc.) without
# executing its main body, then runs all DTLS 1.3 tests and exits with $FAILS.
#
# Usage (from build tests directory):
#   ./dtls13-wolfssl-tests.sh [-f FILTER] [-e EXCLUDE] [other ssl-opt.sh flags]

set -u

ORIGINAL_PWD=$PWD
if ! cd "$(dirname "$0")"; then
    exit 125
fi

SSL_OPT_SOURCE_ONLY=1
export SSL_OPT_SOURCE_ONLY

# shellcheck source=ssl-opt.sh
. ./ssl-opt.sh "$@"

# ======================================================================
# Cases from: fragmentation.yaml
# ======================================================================

# ======================================================================
# Cases from: handshake.yaml
# ======================================================================

requires_wolfssl
run_test    "DTLS 1.3: full 1-RTT handshake" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3"

requires_wolfssl
run_test    "DTLS 1.3: bidirectional application data (2 exchanges)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none exchanges=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "Read from client:" \
            -c "SSL version is DTLSv1.3"

requires_wolfssl
run_test    "DTLS 1.3: client ACKs server Finished flight" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -c "SSL version is DTLSv1.3"

# ======================================================================
# Cases from: hrr-cookie.yaml
# ======================================================================

requires_wolfssl
requires_config_enabled MBEDTLS_SSL_DTLS_HELLO_VERIFY
run_test    "DTLS 1.3: HRR+cookie exchange (cookie enabled)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none groups=secp384r1 debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "cookie verified"

# ======================================================================
# Cases from: interop-wolfssl.yaml
# ======================================================================

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop: A: HRR — wolfSSL client triggers HelloRetryRequest" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT -J" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "write hello retry request"

requires_wolfssl
requires_config_enabled MBEDTLS_SSL_SESSION_TICKETS
run_test    "DTLS 1.3 wolfSSL interop: A: reconnect after NewSessionTicket" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT -r" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "write new session ticket"

# ======================================================================
# Cases from: proxy-3d.yaml
# ======================================================================

client_needs_more_time 4
requires_wolfssl
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - 3d, basic handshake" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none dgram_packing=0 hs_timeout=500-20000 debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3"

client_needs_more_time 4
requires_wolfssl
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: loss recovery via retransmit" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none debug_level=2 hs_timeout=250-20000" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3"

client_needs_more_time 4
requires_wolfssl
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
requires_config_enabled MBEDTLS_SSL_DTLS_HELLO_VERIFY
run_test    "DTLS 1.3: proxy - 3d, HRR+cookie exchange" \
            -p "$P_PXY drop=8 delay=8 duplicate=8" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none groups=secp384r1 dgram_packing=0 hs_timeout=500-20000 debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "cookie verified"

# ======================================================================
# Cases from: proxy-basic.yaml
# ======================================================================

# ======================================================================
# Cases from: psk.yaml
# ======================================================================

requires_wolfssl
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "DTLS 1.3 PSK: external PSK, psk_ephemeral key exchange" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef psk_identity=Client_identity debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT -s --openssl-psk" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "key exchange mode: psk_ephemeral"

requires_wolfssl
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
requires_config_enabled MBEDTLS_SSL_DTLS_HELLO_VERIFY
run_test    "DTLS 1.3 PSK: PSK with cookie enabled — no HRR/cookie exchange (RFC 9147 §5.1)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef psk_identity=Client_identity cookies=1 debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT -s --openssl-psk" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "key exchange mode: psk_ephemeral" \
            -S "write hello retry request" \
            -S "cookie verified"

if [ $FAILS -gt 255 ]; then
    FAILS=255
fi
exit $FAILS
