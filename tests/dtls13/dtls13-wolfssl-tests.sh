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
# Cases from: interop-wolfssl.yaml
# ======================================================================

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop: mbedtls server ↔ wolfSSL client: full handshake" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop: mbedtls server ↔ wolfSSL client: application data" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "Read from client:"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop: mbedtls server ↔ wolfSSL client: server ACKs client Finished" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "=> write ACK"

requires_wolfssl
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "DTLS 1.3 wolfSSL interop: mbedtls server ↔ wolfSSL client: PSK (psk_ephemeral)" \
            "$P_SRV dtls=1 force_version=dtls13 auth_mode=none psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef psk_identity=Client_identity debug_level=2" \
            "cd $WOLFSSL_DIR && $WOLFSSL_CLI -u -v 4 -d -p +SRV_PORT -s --openssl-psk" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "SSL version is DTLSv1.3" \
            -s "key exchange mode: psk_ephemeral"

if [ $FAILS -gt 255 ]; then
    FAILS=255
fi
exit $FAILS
