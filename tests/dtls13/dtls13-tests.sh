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

# When the dtls13/ directory is a symlink into a build tree (e.g.
# build-dbg/tests/dtls13 -> <repo>/tests/dtls13), the shell resolves ".."
# against the *real* path, so ssl-opt.sh's defaults for DATA_FILES_PATH and
# P_SRV/P_CLI/P_PXY/P_QUERY all point into the source tree rather than the
# build tree.  Detect this once and patch up any unset variables.
# Use the logical (symlink-preserving) path so that ".." stays in the build
# tree rather than escaping through the symlink into the source tree.
_script_logical=$(cd "$(dirname "$0")" && pwd)    # logical path of dtls13/
_build_tests=$(dirname "$_script_logical")         # …/tests
_build_root=$(dirname "$_build_tests")             # …  (the cmake build root)
_build_programs="$_build_root/programs"

if [ -z "${DATA_FILES_PATH:-}" ] && [ -d "$_build_root/framework/data_files" ]; then
    DATA_FILES_PATH="$_build_root/framework/data_files"
    export DATA_FILES_PATH
fi
if [ -z "${P_SRV:-}" ] && [ -f "$_build_programs/ssl/ssl_server2" ]; then
    P_SRV="$_build_programs/ssl/ssl_server2"
    export P_SRV
fi
if [ -z "${P_CLI:-}" ] && [ -f "$_build_programs/ssl/ssl_client2" ]; then
    P_CLI="$_build_programs/ssl/ssl_client2"
    export P_CLI
fi
if [ -z "${P_PXY:-}" ] && [ -f "$_build_programs/test/udp_proxy" ]; then
    P_PXY="$_build_programs/test/udp_proxy"
    export P_PXY
fi
if [ -z "${P_QUERY:-}" ] && [ -f "$_build_programs/test/query_compile_time_config" ]; then
    P_QUERY="$_build_programs/test/query_compile_time_config"
    export P_QUERY
fi
unset _script_logical _build_tests _build_root _build_programs

SSL_OPT_SOURCE_ONLY=1
export SSL_OPT_SOURCE_ONLY

# shellcheck source=ssl-opt.sh
. ./ssl-opt.sh "$@"

# ======================================================================
# Cases from: cid.yaml
# ======================================================================

requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_DTLS_CONNECTION_ID
run_test    "DTLS 1.3 CID: CID: both endpoints offer CID — negotiated" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=3 cid=1 cid_val=deadbeef" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=3 cid=1 cid_val=cafebabe" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "Use of Connection ID has been negotiated." \
            -c "Use of Connection ID has been negotiated."

requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_DTLS_CONNECTION_ID
run_test    "DTLS 1.3 CID: CID: only client offers CID — not negotiated (server disabled)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=3" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=3 cid=1 cid_val=cafebabe" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -S "Use of Connection ID has been negotiated." \
            -C "Use of Connection ID has been negotiated."

requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_DTLS_CONNECTION_ID
run_test    "DTLS 1.3 CID: CID: basic exchange with CID enabled" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=3 cid=1 cid_val=aabbccdd exchanges=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=3 cid=1 cid_val=11223344 exchanges=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "Use of Connection ID has been negotiated." \
            -c "Use of Connection ID has been negotiated."

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
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_protocol_version dtls13
run_test    "DTLS 1.3: bidirectional application data (2 exchanges)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 exchanges=2" \
            "$P_CLI dtls=1 force_version=dtls13 exchanges=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "Read from client: 51 bytes read" \
            -c "Read from server: 144 bytes read"

requires_protocol_version dtls13
run_test    "DTLS 1.3: client ACKs server Finished flight" \
            -p "" \
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
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 groups=secp384r1 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "received HelloRetryRequest message" \
            -s "cookie verified"

# ======================================================================
# Cases from: keyupdate.yaml
# ======================================================================

requires_protocol_version dtls13
run_test    "DTLS 1.3 KeyUpdate: client sends KeyUpdate (update_not_requested)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2 key_update=1" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "KeyUpdate sent" \
            -c "ACK: KeyUpdate acknowledged" \
            -c "KeyUpdate: new outbound transform installed" \
            -s "KeyUpdate received" \
            -s "KeyUpdate: new inbound transform installed"

requires_protocol_version dtls13
run_test    "DTLS 1.3 KeyUpdate: server sends KeyUpdate (update_not_requested)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2 key_update=1" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "KeyUpdate sent" \
            -s "ACK: KeyUpdate acknowledged" \
            -s "KeyUpdate: new outbound transform installed" \
            -c "KeyUpdate received" \
            -c "KeyUpdate: new inbound transform installed"

requires_protocol_version dtls13
run_test    "DTLS 1.3 KeyUpdate: client sends KeyUpdate (update_requested) — server reciprocates" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2 key_update=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "KeyUpdate sent" \
            -s "KeyUpdate received" \
            -s "KeyUpdate sent" \
            -s "ACK: KeyUpdate acknowledged" \
            -s "KeyUpdate: new outbound transform installed" \
            -c "KeyUpdate received" \
            -c "KeyUpdate: new inbound transform installed"

requires_protocol_version dtls13
run_test    "DTLS 1.3 KeyUpdate: KeyUpdate followed by application data exchange" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2 key_update=1 exchanges=2" \
            "$P_CLI dtls=1 force_version=dtls13 exchanges=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "KeyUpdate sent" \
            -s "ACK: KeyUpdate acknowledged" \
            -s "KeyUpdate: new outbound transform installed"

requires_protocol_version dtls13
run_test    "DTLS 1.3 KeyUpdate: AEAD limit auto-triggers KeyUpdate on server" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2 aead_limit=3 exchanges=4" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2 exchanges=4" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "AEAD limit reached" \
            -s "KeyUpdate sent" \
            -s "ACK: KeyUpdate acknowledged" \
            -s "KeyUpdate: new outbound transform installed" \
            -c "KeyUpdate received" \
            -c "KeyUpdate: new inbound transform installed"

requires_protocol_version dtls13
run_test    "DTLS 1.3 KeyUpdate: AEAD limit auto-triggers KeyUpdate on client" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2 exchanges=4" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2 aead_limit=3 exchanges=4" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "AEAD limit reached" \
            -c "KeyUpdate sent" \
            -c "ACK: KeyUpdate acknowledged" \
            -c "KeyUpdate: new outbound transform installed" \
            -s "KeyUpdate received" \
            -s "KeyUpdate: new inbound transform installed"

requires_protocol_version dtls13
run_test    "DTLS 1.3 KeyUpdate: auth-fail limit: server closes after too many bad MACs" \
            -p "$P_PXY bad_ad=1" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2 auth_fail_limit=1 exchanges=2" \
            "$P_CLI dtls=1 force_version=dtls13 debug_level=2 exchanges=2" \
            1 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "auth-fail limit reached"

# ======================================================================
# Cases from: proxy-3d.yaml
# ======================================================================

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - 3d, basic handshake" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 read_timeout=5000 max_resend=5 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - 3d, client auth" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 auth_mode=required debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 read_timeout=5000 max_resend=5 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

client_needs_more_time 4
requires_config_enabled MBEDTLS_SSL_PROTO_DTLS
run_test    "DTLS 1.3: proxy - 3d, nbio" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "$P_SRV dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 nbio=2 debug_level=1" \
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 nbio=2 read_timeout=5000 max_resend=5 debug_level=1" \
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
            "$P_CLI dtls=1 force_version=dtls13 dgram_packing=0 hs_timeout=500-20000 read_timeout=5000 max_resend=5 debug_level=2" \
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
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 psk=abc123 psk_identity=Client_identity debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 psk=abc123 psk_identity=Client_identity debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -s "key exchange mode: psk_ephemeral"

requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
requires_config_enabled MBEDTLS_SSL_SESSION_TICKETS
run_test    "DTLS 1.3 PSK: session resumption via NewSessionTicket PSK" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 debug_level=2" \
            "$P_CLI dtls=1 force_version=dtls13 reconnect=1 skip_close_notify=1 debug_level=2" \
            0 \
            -s "Protocol is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "got new session ticket (datagram)." \
            -c "Reconnecting with saved session..." \
            -s "key exchange mode: psk_ephemeral"

requires_protocol_version dtls13
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
requires_config_enabled MBEDTLS_SSL_DTLS_HELLO_VERIFY
run_test    "DTLS 1.3 PSK: PSK with cookie enabled — no HRR/cookie exchange (RFC 9147 §5.1)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls13 psk=abc123 psk_identity=Client_identity cookies=1 debug_level=2" \
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
            -p "" \
            "$P_SRV dtls=1 force_version=dtls12 cookies=0" \
            "$P_CLI dtls=1 min_version=dtls12 max_version=dtls13" \
            0 \
            -s "Protocol is DTLSv1.2" \
            -c "Protocol is DTLSv1.2"

requires_protocol_version dtls13
requires_protocol_version dtls12
run_test    "DTLS 1.3 client, DTLS 1.2 server: negotiate down to DTLS 1.2 (with cookie)" \
            -p "" \
            "$P_SRV dtls=1 force_version=dtls12" \
            "$P_CLI dtls=1 min_version=dtls12 max_version=dtls13" \
            0 \
            -s "Protocol is DTLSv1.2" \
            -c "Protocol is DTLSv1.2"

if [ $FAILS -gt 255 ]; then
    FAILS=255
fi
exit $FAILS
