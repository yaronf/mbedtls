#!/bin/sh
# Sweep the DTLS 1.3 3d basic handshake test across multiple seeds.
# Runs the test binaries directly — no ssl-opt.sh overhead.
# Usage: ./run-3d-sweep.sh [first_seed [last_seed]]
# Defaults: seeds 50..69

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
P_SRV="$SCRIPT_DIR/../programs/ssl/ssl_server2"
P_CLI="$SCRIPT_DIR/../programs/ssl/ssl_client2"
P_PXY="$SCRIPT_DIR/../programs/test/udp_proxy"

FIRST_SEED="${1:-50}"
LAST_SEED="${2:-69}"

LOG="$SCRIPT_DIR/3d-sweep.log"
rm -f "$LOG"

pkill -f "ssl_server2.*dtls" 2>/dev/null || true
pkill -f "ssl_client2.*dtls" 2>/dev/null || true
pkill -f "udp_proxy" 2>/dev/null || true
sleep 0.3

PASS=0; FAIL=0

for seed in $(seq "$FIRST_SEED" "$LAST_SEED"); do
    SRV_PORT=$(( (seed % 1000) + 20000 ))
    PXY_PORT=$(( SRV_PORT + 10000 ))
    SRV_LOG="$SCRIPT_DIR/3d-srv-$seed.log"
    CLI_LOG="$SCRIPT_DIR/3d-cli-$seed.log"
    PXY_LOG="$SCRIPT_DIR/3d-pxy-$seed.log"

    echo "=== seed=$seed start $(date +%H:%M:%S) ===" | tee -a "$LOG"

    # Start proxy
    "$P_PXY" listen_addr=127.0.0.1 listen_port=$PXY_PORT \
        server_addr=127.0.0.1 server_port=$SRV_PORT \
        drop=5 delay=5 duplicate=5 seed=$seed \
        > "$PXY_LOG" 2>&1 &
    PXY_PID=$!

    # Start server
    "$P_SRV" server_addr=127.0.0.1 server_port=$SRV_PORT \
        dtls=1 force_version=dtls13 dgram_packing=0 \
        hs_timeout=500-20000 debug_level=2 \
        > "$SRV_LOG" 2>&1 &
    SRV_PID=$!

    # Wait for server to be ready
    for i in $(seq 1 20); do
        if grep -q "bind" "$SRV_LOG" 2>/dev/null || \
           lsof -i UDP:$SRV_PORT -a -p $SRV_PID > /dev/null 2>&1; then
            break
        fi
        if ! kill -0 $SRV_PID 2>/dev/null; then
            echo "  server exited early (port conflict?)" | tee -a "$LOG"
            break
        fi
        sleep 0.1
    done

    # Run client
    "$P_CLI" server_addr=127.0.0.1 server_port=$PXY_PORT \
        dtls=1 force_version=dtls13 dgram_packing=0 \
        hs_timeout=500-20000 debug_level=2 \
        > "$CLI_LOG" 2>&1
    CLI_EXIT=$?

    # Stop server and proxy
    kill $SRV_PID $PXY_PID 2>/dev/null || true
    wait $SRV_PID $PXY_PID 2>/dev/null || true

    echo "=== seed=$seed end $(date +%H:%M:%S) ===" | tee -a "$LOG"

    # Check result
    if [ $CLI_EXIT -eq 0 ] && \
       grep -q "Protocol is DTLSv1.3" "$CLI_LOG" && \
       grep -q "Protocol is DTLSv1.3" "$SRV_LOG"; then
        echo "PASS seed=$seed" | tee -a "$LOG"
        PASS=$((PASS+1))
        # Clean up logs on pass to save space
        rm -f "$SRV_LOG" "$CLI_LOG" "$PXY_LOG"
    else
        echo "FAIL seed=$seed (cli_exit=$CLI_EXIT) — logs: $SRV_LOG $CLI_LOG $PXY_LOG" | tee -a "$LOG"
        FAIL=$((FAIL+1))
    fi
done

echo "" | tee -a "$LOG"
echo "=== RESULTS: $PASS pass, $FAIL fail out of $((PASS+FAIL)) ===" | tee -a "$LOG"
