#!/bin/sh
# Run the HRR+cookie 3d test across multiple seeds.
# Stops on first failure and preserves logs for investigation.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG=/tmp/hrr3d-run.log

# Kill stale DTLS processes from any prior interrupted run.
pkill -f "ssl_server2.*dtls" 2>/dev/null || true
pkill -f "ssl_client2.*dtls" 2>/dev/null || true
pkill -f "udp_proxy" 2>/dev/null || true
sleep 0.3

cd "$SCRIPT_DIR"

for seed in 51 53 200 201 202 203 204 205 206 207 208 209 210; do
    echo "=== seed=$seed ===" | tee -a "$LOG"
    if ! ./ssl-opt.sh -f "3d, HRR" --seed "$seed" --preserve-logs >> "$LOG" 2>&1; then
        echo "FAILED at seed=$seed — logs in $LOG and o-XXX-1.log" | tee -a "$LOG"
        exit 1
    fi
    echo "PASS seed=$seed" | tee -a "$LOG"
done

echo "All seeds passed." | tee -a "$LOG"
