#!/bin/sh
# DTLS 1.3 stateless-cookie cluster test (T6 of Phase 2 — see
# local-docs/cookie-impl-plan.md §2.5.6).
#
# Proves the *cluster property* of the stateless DTLS 1.3 server:
# any server with the right cookie secret can complete a handshake
# initiated against any other server in the cluster, because all the
# state needed to continue is in the cookie itself.
#
# Topology:
#
#     client ─UDP─▶ udp_proxy ─UDP─▶ server A          (CH1 → HRR)
#                       │
#                       └─UDP─▶ server B               (CH2 → SH/EE/Cert/CV/Fin)
#
# udp_proxy initially forwards to server A.  After it has seen one
# server-to-client packet (the HRR), it tears down the connection to
# server A and reconnects to server B for all subsequent traffic.
# The client never sees the switch.  Both servers are configured
# with the same dtls_cookie_secret; neither has a copy of the other's
# handshake state.
#
# A non-stateless implementation (Phase 1 behaviour) would fail here:
# server B has no handshake_params matching this client and would
# either drop the CH2 or send an alert.  A stateless implementation
# (Phase 2) recovers the transcript from the cookie and completes the
# handshake using server B's keying material.
#
# Run from the build's tests/dtls13/ directory or pass binaries via
# the P_SRV / P_CLI / P_PXY env vars (compatible with dtls13-tests.sh).
#
# Exit codes:
#   0  — handshake completed end-to-end via server B
#   1  — handshake failed (cluster property broken)
#   2  — environment / setup error

set -u

# Locate binaries.  When sourced from dtls13-tests.sh's environment,
# P_SRV / P_CLI / P_PXY may already be set — possibly with extra
# args appended by ssl-opt.sh (e.g. "ssl_server2 server_addr=...
# allow_sha1=1").  Strip everything after the first space to get the
# bare binary path.  If unset, infer from the script's location
# (works inside the cmake build tree where this script is a symlink
# into ../../tests/dtls13).
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BUILD_TESTS=$(dirname "$SCRIPT_DIR")
BUILD_ROOT=$(dirname "$BUILD_TESTS")
: "${P_SRV:=$BUILD_ROOT/programs/ssl/ssl_server2}"
: "${P_CLI:=$BUILD_ROOT/programs/ssl/ssl_client2}"
: "${P_PXY:=$BUILD_ROOT/programs/test/udp_proxy}"
: "${DATA_FILES_PATH:=$BUILD_ROOT/framework/data_files}"
SRV_BIN="${P_SRV%%[	 ]*}"
CLI_BIN="${P_CLI%%[	 ]*}"
PXY_BIN="${P_PXY%%[	 ]*}"

for bin in "$SRV_BIN" "$CLI_BIN" "$PXY_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "cluster-test: missing or non-executable: $bin" >&2
        exit 2
    fi
done

# Shared cookie secret — value doesn't matter, only that both servers use it.
SECRET=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

# Ports.  Picked from the same range ssl-opt.sh uses (10000-19999) but
# offset to avoid clashing with concurrent test runs.
PORT_A=12200
PORT_B=12201
PORT_PXY=12202

# Per-run scratch dir for logs and synchronisation.
SCRATCH=$(mktemp -d -t cluster-test.XXXXXX) || { echo "mktemp failed" >&2; exit 2; }
trap 'kill $SRV_A_PID $SRV_B_PID $PXY_PID 2>/dev/null; wait 2>/dev/null; rm -rf "$SCRATCH"' EXIT INT TERM

echo "  . Spawning server A on UDP/127.0.0.1/$PORT_A ..."
$SRV_BIN server_addr=127.0.0.1 server_port=$PORT_A dtls=1 force_version=dtls13 \
       groups=secp384r1 cookies=0 dtls_cookie_secret=$SECRET debug_level=2 \
       > "$SCRATCH/srv-A.log" 2>&1 &
SRV_A_PID=$!

echo "  . Spawning server B on UDP/127.0.0.1/$PORT_B ..."
$SRV_BIN server_addr=127.0.0.1 server_port=$PORT_B dtls=1 force_version=dtls13 \
       groups=secp384r1 cookies=0 dtls_cookie_secret=$SECRET debug_level=2 \
       > "$SCRATCH/srv-B.log" 2>&1 &
SRV_B_PID=$!

# Wait for both servers to bind by polling the bind log line.
i=0
while [ $i -lt 50 ]; do
    if grep -q "Waiting for a remote connection" "$SCRATCH/srv-A.log" 2>/dev/null && \
       grep -q "Waiting for a remote connection" "$SCRATCH/srv-B.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
    i=$((i + 1))
done
if [ $i -ge 50 ]; then
    echo "cluster-test: servers did not become ready within 5s" >&2
    cat "$SCRATCH/srv-A.log" "$SCRATCH/srv-B.log" >&2
    exit 2
fi

echo "  . Spawning udp_proxy on UDP/127.0.0.1/$PORT_PXY (A → B after first S→C pkt)"
$PXY_BIN listen_addr=127.0.0.1 listen_port=$PORT_PXY \
       server_addr=127.0.0.1 server_port=$PORT_A \
       upstream_b_addr=127.0.0.1 upstream_b_port=$PORT_B \
       redirect_after_s2c=1 \
       > "$SCRATCH/pxy.log" 2>&1 &
PXY_PID=$!

i=0
while [ $i -lt 50 ]; do
    if grep -q "Bind on UDP" "$SCRATCH/pxy.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
    i=$((i + 1))
done

echo "  . Client → proxy on UDP/127.0.0.1/$PORT_PXY"
# auth_mode=none: ssl_server2's built-in cert isn't trusted by ssl_client2's
# default CA set; we're testing handshake completion, not authentication.
$CLI_BIN server_addr=127.0.0.1 server_port=$PORT_PXY dtls=1 force_version=dtls13 \
       auth_mode=none debug_level=2 \
       > "$SCRATCH/cli.log" 2>&1
CLI_RC=$?

# Give the proxy/servers a moment to finish post-handshake teardown so
# the logs settle before we read them.
sleep 0.2

# Pass criteria:
#   1. client exits 0 (handshake completed and read application data)
#   2. client log shows "Read from server" (data round-trip)
#   3. server A handled exactly one HRR ("hello verification requested")
#      and never reached SERVER_HELLO (since it was redirected away)
#   4. server B's log shows it processed CH2 and reached
#      MBEDTLS_SSL_SERVER_HELLO (the "secret-path-used" assertion)
PASS=1
if [ "$CLI_RC" -ne 0 ]; then
    echo "  FAIL: client exited $CLI_RC (expected 0)"
    PASS=0
fi
if ! grep -q "Read from server" "$SCRATCH/cli.log"; then
    echo "  FAIL: client did not complete application-data read"
    PASS=0
fi
if ! grep -q "hello verification requested" "$SCRATCH/srv-A.log"; then
    echo "  FAIL: server A did not emit HRR signaling"
    PASS=0
fi
if grep -q "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" "$SCRATCH/srv-A.log"; then
    echo "  FAIL: server A advanced past HRR (should have reset instead)"
    PASS=0
fi
if ! grep -q "HRR cookie (secret) verified" "$SCRATCH/srv-B.log"; then
    echo "  FAIL: server B did not verify a recovered HRR cookie"
    PASS=0
fi
if ! grep -q "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" "$SCRATCH/srv-B.log"; then
    echo "  FAIL: server B did not reach SERVER_HELLO"
    PASS=0
fi

if [ "$PASS" = "1" ]; then
    echo "DTLS 1.3 cluster test (stateless cookie, CH1→A / CH2→B): PASS"
    exit 0
else
    echo "DTLS 1.3 cluster test: FAIL"
    echo "  --- server A log ($SCRATCH/srv-A.log) ---"
    tail -20 "$SCRATCH/srv-A.log"
    echo "  --- server B log ($SCRATCH/srv-B.log) ---"
    tail -20 "$SCRATCH/srv-B.log"
    echo "  --- proxy log ($SCRATCH/pxy.log) ---"
    tail -10 "$SCRATCH/pxy.log"
    echo "  --- client log ($SCRATCH/cli.log) ---"
    tail -20 "$SCRATCH/cli.log"
    # Keep the scratch dir for inspection on failure.
    trap - EXIT INT TERM
    kill $SRV_A_PID $SRV_B_PID $PXY_PID 2>/dev/null
    wait 2>/dev/null
    echo "  (scratch dir preserved at $SCRATCH)"
    exit 1
fi
