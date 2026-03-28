#!/bin/sh
# AUTO-GENERATED — do not edit.
# Regenerate: python3 tests/dtls13/generate.py --runner runners/mbedtls.yaml --emit
#
# Standalone DTLS 1.3 integration test script.
# Designed to run from the same directory as ssl-opt.sh (typically
# build-dbg/tests/ or any cmake build's tests/ directory).
#
# Sources ssl-opt.sh for infrastructure (run_test, requires_*, etc.) without
# executing its main body, then runs all DTLS 1.3 tests and exits with $FAILS.
#
# Usage (from build tests directory):
#   ./dtls13-tests.sh [-f FILTER] [-e EXCLUDE] [other ssl-opt.sh flags]

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

requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
requires_max_content_len 2048
run_test    "DTLS 1.3: fragmenting — proxy MTU" \
            -p "$P_PXY mtu=512" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2 auth_mode=required crt_file=$DATA_FILES_PATH/server7_int-ca.crt key_file=$DATA_FILES_PATH/server7.key hs_timeout=10000-60000 mtu=512" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2 crt_file=$DATA_FILES_PATH/server8_int-ca2.crt key_file=$DATA_FILES_PATH/server8.key hs_timeout=10000-60000 mtu=512" \
            0 \
            -s "found fragmented DTLS handshake message" \
            -c "found fragmented DTLS handshake message" \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -C "error"

requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
requires_max_content_len 2048
run_test    "DTLS 1.3: fragmenting — proxy MTU, nbio" \
            -p "$P_PXY mtu=512" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2 auth_mode=required crt_file=$DATA_FILES_PATH/server7_int-ca.crt key_file=$DATA_FILES_PATH/server7.key hs_timeout=10000-60000 mtu=512 nbio=2" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2 crt_file=$DATA_FILES_PATH/server8_int-ca2.crt key_file=$DATA_FILES_PATH/server8.key hs_timeout=10000-60000 mtu=512 nbio=2" \
            0 \
            -s "found fragmented DTLS handshake message" \
            -c "found fragmented DTLS handshake message" \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -C "error"

# ======================================================================
# Cases from: handshake.yaml
# ======================================================================

requires_protocol_version dtls13
run_test    "DTLS 1.3: full 1-RTT handshake" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_protocol_version dtls13
run_test    "DTLS 1.3: bidirectional application data (2 exchanges)" \
            "$P_SRV dtls=1 force_version=dtls13 exchanges=2" \
            "$P_CLI dtls=1 force_version=dtls13 exchanges=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "Read from client: 51 bytes read" \
            -c "Read from server: 144 bytes read"

requires_protocol_version dtls13
run_test    "DTLS 1.3: client ACKs server Finished flight" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "=> write ACK"

# ======================================================================
# Cases from: hrr-cookie.yaml
# ======================================================================

requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_DTLS_HELLO_VERIFY
run_test    "DTLS 1.3: HRR+cookie exchange (cookie enabled)" \
            "$P_SRV dtls=1 force_version=dtls13 groups=secp384r1 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "received HelloRetryRequest message" \
            -s "cookie verified"

# ======================================================================
# Cases from: proxy-3d.yaml
# ======================================================================

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - 3d, basic handshake" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - 3d, client auth" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 auth_mode=required debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - 3d, nbio" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 nbio=2 debug_level=1" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 nbio=2 debug_level=1" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: loss recovery via retransmit" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2 hs_timeout=250-20000" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2 hs_timeout=250-20000" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

client_needs_more_time 4
requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
requires_config_enabled MBEDTLS_SSL_DTLS_HELLO_VERIFY
run_test    "DTLS 1.3: proxy - 3d, HRR+cookie exchange" \
            -p "$P_PXY drop=8 delay=8 duplicate=8" \
            "$P_SRV dtls=1 force_version=dtls13 groups=secp384r1 dgram_packing=0 hs_timeout=500-20000 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "received HelloRetryRequest message" \
            -s "cookie verified"

# ======================================================================
# Cases from: proxy-basic.yaml
# ======================================================================

requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
not_with_valgrind
run_test    "DTLS 1.3: proxy - duplicate every packet" \
            -p "$P_PXY duplicate=1" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2 hs_timeout=10000-20000" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2 hs_timeout=10000-20000" \
            0 \
            -c "record from another epoch" \
            -s "record from another epoch" \
            -S "resend" \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - duplicate every packet, anti-replay off" \
            -p "$P_PXY duplicate=1" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2 anti_replay=0" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2" \
            0 \
            -c "record from another epoch" \
            -s "record from another epoch" \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - multiple records in same datagram" \
            -p "$P_PXY pack=50" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2" \
            0 \
            -c "next record in same datagram" \
            -s "next record in same datagram"

requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - multiple records in same datagram, duplicate every packet" \
            -p "$P_PXY pack=50 duplicate=1" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 debug_level=2" \
            0 \
            -c "next record in same datagram" \
            -s "next record in same datagram"

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - inject invalid AD record, default badmac_limit" \
            -p "$P_PXY bad_ad=1" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 debug_level=1 hs_timeout=500-10000" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 debug_level=1 hs_timeout=500-10000" \
            0 \
            -c "discarding invalid record (mac)" \
            -s "discarding invalid record (mac)" \
            -S "too many records with bad MAC" \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

# ======================================================================
# Cases from: psk.yaml
# ======================================================================

requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "DTLS 1.3 PSK: external PSK, psk_ephemeral key exchange" \
            "$P_SRV dtls=1 force_version=dtls13 psk=abc123 psk_identity=Client_identity auth_mode=required debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 psk=abc123 psk_identity=Client_identity debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "key exchange mode: psk_ephemeral"

requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
requires_config_enabled MBEDTLS_SSL_DTLS_HELLO_VERIFY
run_test    "DTLS 1.3 PSK: PSK with cookie enabled — no HRR/cookie exchange (RFC 9147 §5.1)" \
            "$P_SRV dtls=1 force_version=dtls13 psk=abc123 psk_identity=Client_identity auth_mode=required cookies=1 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 psk=abc123 psk_identity=Client_identity debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "key exchange mode: psk_ephemeral" \
            -C "received HelloRetryRequest message" \
            -S "cookie verified"

# ======================================================================
# Cases from: version-negotiation.yaml
# ======================================================================

requires_protocol_version dtls13
requires_protocol_version dtls12
run_test    "DTLS 1.3 client, DTLS 1.2 server: negotiate down to DTLS 1.2 (no cookie)" \
            "$P_SRV dtls=1 force_version=dtls12 cookies=0" \
            "$P_CLI dtls=1 min_version=dtls12 max_version=dtls13" \
            0 \
            -s "Protocol is DTLSv1.2" \
            -c "Protocol is DTLSv1.2"

requires_protocol_version dtls13
requires_protocol_version dtls12
run_test    "DTLS 1.3 client, DTLS 1.2 server: negotiate down to DTLS 1.2 (with cookie)" \
            "$P_SRV dtls=1 force_version=dtls12" \
            "$P_CLI dtls=1 min_version=dtls12 max_version=dtls13" \
            0 \
            -s "Protocol is DTLSv1.2" \
            -c "Protocol is DTLSv1.2"

if [ $FAILS -gt 255 ]; then
    FAILS=255
fi
exit $FAILS
