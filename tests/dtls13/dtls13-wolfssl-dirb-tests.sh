#!/bin/sh
# AUTO-GENERATED — do not edit.
# Regenerate: python3 tests/dtls13/generate.py --runner runners/wolfssl-dirb.yaml --emit
#
# Standalone DTLS 1.3 integration test script.
# Designed to run from the same directory as ssl-opt.sh (typically
# build-dbg/tests/ or any cmake build's tests/ directory).
#
# Sources ssl-opt.sh for infrastructure (run_test, requires_*, etc.) without
# executing its main body, then runs all DTLS 1.3 tests and exits with $FAILS.
#
# Usage (from build tests directory):
#   ./dtls13-wolfssl-dirb-tests.sh [-f FILTER] [-e EXCLUDE] [other ssl-opt.sh flags]

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

# ssl-opt.sh sets DOG_DELAY inside its main() body which we skip.
# Set it here so that client_needs_more_time() works correctly.
: "${DOG_DELAY:=20}"
CLI_DELAY_FACTOR=1
SRV_DELAY_SECONDS=0

# ======================================================================
# Cases from: interop-wolfssl-dirb.yaml
# ======================================================================

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: full 1-RTT handshake" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=0" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: application data exchange" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=0" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "Read from server:"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: client ACKs server Finished flight" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=2" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "=> write ACK"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: HRR+cookie (wolfSSL sends cookie by default)" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=2" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "received HelloRetryRequest message"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: force AES-128-GCM ciphersuite" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT -l TLS_AES_128_GCM_SHA256" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=0 force_ciphersuite=TLS1-3-AES-128-GCM-SHA256" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_wolfssl
not_with_valgrind
run_test    "DTLS 1.3 wolfSSL interop Direction B: proxy — 3d, basic handshake" \
            -p "$P_PXY drop=5 delay=5 duplicate=5" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=0 hs_timeout=1000-10000" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_wolfssl
not_with_valgrind
client_needs_more_time 2
run_test    "DTLS 1.3 wolfSSL interop Direction B: loss recovery via retransmit" \
            -p "$P_PXY drop=8 delay=8 duplicate=8" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=0 hs_timeout=1000-16000" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: external PSK" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT -s" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=3 psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef psk_identity=Client_identity" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "Selected key exchange mode: psk_ephemeral"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: mbedtls client sends KeyUpdate (update_not_requested)" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -i -Y -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=2 key_update=1" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "KeyUpdate sent" \
            -c "ACK: KeyUpdate acknowledged" \
            -c "KeyUpdate: new outbound transform installed"

# DTLS 1.3 stateless-cookie cluster test (T6 of Phase 2 — see
# local-docs/cookie-impl-plan.md §2.5.6).  This is a multi-process
# scenario (two ssl_server2 instances + udp_proxy with mid-stream
# redirect) that doesn't fit the single-server `run_test` shape, so
# it lives in a standalone script and is invoked here as a synthetic
# test entry that integrates with ssl-opt.sh's TESTS/PASSES/FAILS
# counters.  print_name handles TESTS++; we just emit PASS/FAIL.
# Honor -f/-e like run_test so Direction B filters do not always pull
# this mbedtls↔mbedtls cluster case in.
if [ -x "$(dirname "$0")/cluster-test.sh" ] && \
   ! is_excluded "DTLS 1.3: stateless cluster (CH1 → server A, CH2 → server B)"; then
    print_name "DTLS 1.3: stateless cluster (CH1 → server A, CH2 → server B)"
    cluster_log="$(mktemp -t cluster-test.XXXXXX)"
    if "$(dirname "$0")/cluster-test.sh" >"$cluster_log" 2>&1; then
        record_outcome "PASS"
        rm -f "$cluster_log"
    else
        record_outcome "FAIL" "cluster test failed"
        echo "  ! cluster test failed; output:"
        cat "$cluster_log" | sed 's/^/  ! /'
        rm -f "$cluster_log"
        FAILS=$(( FAILS + 1 ))
    fi
fi

if [ $FAILS -gt 255 ]; then
    FAILS=255
fi
exit $FAILS
