#!/bin/sh
# Run the HRR+cookie 3d test across multiple seeds.
# Stops on first failure and preserves logs for investigation.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG=/tmp/hrr3d-run.log

# Locate binaries: prefer build-dbg, fall back to build.
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
for BUILD_DIR in "$REPO_ROOT/build-dbg" "$REPO_ROOT/build" "$SCRIPT_DIR/.."; do
    if [ -x "$BUILD_DIR/programs/ssl/ssl_server2" ]; then
        break
    fi
done
P_SRV="$BUILD_DIR/programs/ssl/ssl_server2"
P_CLI="$BUILD_DIR/programs/ssl/ssl_client2"
P_PXY="$BUILD_DIR/programs/test/udp_proxy"

rm -f "$LOG"

# Kill stale DTLS processes from any prior interrupted run.
pkill -f "ssl_server2.*dtls" 2>/dev/null || true
pkill -f "ssl_client2.*dtls" 2>/dev/null || true
pkill -f "udp_proxy" 2>/dev/null || true
sleep 0.3

for seed in 51 53 200 201 202 203 204 205 206 207 208 209 210; do
    SRV_PORT=$(( (seed % 1000) + 21000 ))
    PXY_PORT=$(( SRV_PORT + 10000 ))
    SRV_LOG="/tmp/hrr3d-srv-$seed.log"
    CLI_LOG="/tmp/hrr3d-cli-$seed.log"
    PXY_LOG="/tmp/hrr3d-pxy-$seed.log"

    echo "=== seed=$seed start $(date +%H:%M:%S) ===" | tee -a "$LOG"

    "$P_PXY" listen_addr=127.0.0.1 listen_port=$PXY_PORT \
        server_addr=127.0.0.1 server_port=$SRV_PORT \
        drop=8 delay=8 duplicate=8 seed=$seed \
        > "$PXY_LOG" 2>&1 &
    PXY_PID=$!

    "$P_SRV" server_addr=127.0.0.1 server_port=$SRV_PORT \
        dtls=1 force_version=dtls13 groups=secp384r1 dgram_packing=0 \
        hs_timeout=500-20000 debug_level=2 \
        > "$SRV_LOG" 2>&1 &
    SRV_PID=$!

    for i in $(seq 1 20); do
        if lsof -i UDP:$SRV_PORT -a -p $SRV_PID > /dev/null 2>&1; then break; fi
        if ! kill -0 $SRV_PID 2>/dev/null; then
            echo "  server exited early (port conflict?)" | tee -a "$LOG"; break
        fi
        sleep 0.1
    done

    "$P_CLI" server_addr=127.0.0.1 server_port=$PXY_PORT \
        dtls=1 force_version=dtls13 dgram_packing=0 \
        hs_timeout=500-20000 debug_level=2 \
        > "$CLI_LOG" 2>&1
    CLI_EXIT=$?

    kill $SRV_PID $PXY_PID 2>/dev/null || true
    wait $SRV_PID $PXY_PID 2>/dev/null || true

    echo "=== seed=$seed end $(date +%H:%M:%S) ===" | tee -a "$LOG"

    if [ $CLI_EXIT -eq 0 ] && \
       grep -q "Protocol is DTLSv1.3" "$CLI_LOG" && \
       grep -q "cookie verified" "$SRV_LOG" && \
       grep -q "received HelloRetryRequest" "$CLI_LOG"; then
        echo "PASS seed=$seed" | tee -a "$LOG"
        rm -f "$SRV_LOG" "$CLI_LOG" "$PXY_LOG"
    else
        echo "FAILED at seed=$seed — logs: $SRV_LOG $CLI_LOG $PXY_LOG" | tee -a "$LOG"
        exit 1
    fi
done

echo "All seeds passed." | tee -a "$LOG"
