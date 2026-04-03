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
run_test    "DTLS 1.3 wolfSSL interop Direction B: B: full 1-RTT handshake" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -b -i -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=2" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: B: application data exchange" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -b -i -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=2" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "Read from server:"

requires_wolfssl
run_test    "DTLS 1.3 wolfSSL interop Direction B: B: mbedtls client sends KeyUpdate (update_not_requested)" \
            -p "" \
            "cd $WOLFSSL_DIR && exec stdbuf -oL $WOLFSSL_SRV -u -v 4 -d -b -i -p $SRV_PORT" \
            "$P_CLI dtls=1 force_version=dtls13 server_addr=127.0.0.1 server_name=example.com ca_file=$WOLFSSL_DIR/certs/ca-cert.pem debug_level=2 key_update=1" \
            0 \
            -s "SSL version is DTLSv1.3" \
            -c "Protocol is DTLSv1.3" \
            -c "KeyUpdate sent" \
            -c "ACK: KeyUpdate acknowledged" \
            -c "KeyUpdate: new outbound transform installed"

if [ $FAILS -gt 255 ]; then
    FAILS=255
fi
exit $FAILS
