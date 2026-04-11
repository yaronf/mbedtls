#!/usr/bin/env bash
# coverage-in-podman.sh
#
# Measure and compare branch coverage between:
#   BASELINE  — upstream v4.1.0, default config
#   DTLS13    — this branch (dtls13), default config (includes DTLS 1.3)
#
# Both builds use GCC + CMAKE_BUILD_TYPE=Coverage (-O0 -g3 --coverage) inside
# a plain Ubuntu 24.04 container so that gcda merging works correctly.
# (macOS/LLVM gcda overwriting produces incorrect cumulative counts.)
#
# Output:
#   coverage-baseline/Coverage/index.html   — lcov HTML for v4.1.0
#   coverage-dtls13/Coverage/index.html     — lcov HTML for dtls13 branch
#   coverage-diff.txt                       — per-file branch/line summary diff
#
# Prerequisites:
#   podman (or docker — set DOCKER=docker)
#   git (the repo must be clean enough to archive both refs)
#
# Usage:
#   cd <repo-root>
#   tests/coverage-in-podman.sh
#
# Environment overrides:
#   BASELINE_REF   git ref for baseline  (default: v4.1.0)
#   DTLS13_REF     git ref for DTLS 1.3  (default: HEAD)
#   DOCKER         container runtime     (default: podman)
#   JOBS           parallel make jobs    (default: nproc)

set -euo pipefail

BASELINE_REF="${BASELINE_REF:-v4.1.0}"
DTLS13_REF="${DTLS13_REF:-HEAD}"
DOCKER="${DOCKER:-podman}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="docker.io/library/ubuntu:24.04"
# Set SKIP_BASELINE=1 to reuse an existing coverage-baseline/ (saves ~10 min on reruns)
SKIP_BASELINE="${SKIP_BASELINE:-0}"

# Directories written into the repo root (gitignored via .gitignore or local)
OUT_BASELINE="$REPO_ROOT/coverage-baseline"
OUT_DTLS13="$REPO_ROOT/coverage-dtls13"
OUT_DIFF="$REPO_ROOT/coverage-diff.txt"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

log() { echo "[coverage-in-podman] $*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found in PATH"; exit 1; }
}

# Create a tar archive of a git ref (includes submodules at the committed SHAs)
archive_ref() {
    local ref="$1" dest="$2"
    log "Archiving $ref → $dest"
    mkdir -p "$dest"
    # git archive doesn't include submodules; we use a worktree export instead
    git worktree add --detach "$dest/worktree" "$ref" 2>/dev/null
    # initialise submodules inside the worktree
    git -C "$dest/worktree" submodule update --init --recursive --depth 1 2>/dev/null || true
}

cleanup_worktree() {
    local dest="$1"
    git worktree remove --force "$dest/worktree" 2>/dev/null || true
}

# --------------------------------------------------------------------------
# Container script executed inside the Ubuntu container.
# Receives: SRC (path to source inside container), OUT (path for reports),
#           JOBS, and optionally RUN_DTLS13_TESTS=1.
# --------------------------------------------------------------------------

container_script() {
cat <<'CONTAINER_EOF'
#!/usr/bin/env bash
set -euo pipefail

SRC="${SRC:?}"
OUT="${OUT:?}"
JOBS="${JOBS:-4}"

# Install build deps (quiet)
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    gcc g++ cmake make \
    python3 python3-jinja2 python3-jsonschema python3-cryptography python3-asn1crypto \
    perl lcov git libssl-dev \
    >/dev/null 2>&1

cd "$SRC"

# Configure
cmake -B build-cov \
    -DCMAKE_C_COMPILER=gcc \
    -DCMAKE_BUILD_TYPE=Coverage \
    -DENABLE_TESTING=ON \
    -DGEN_FILES=ON \
    2>&1 | tail -5

# Build
cmake --build build-cov -j"$JOBS" 2>&1 | tail -10

cd build-cov

# Run all tests via CTest. On the dtls13 branch this includes:
#   - unit test suites (tests 1–131)
#   - dtls13-integration-suite (test 132): cmake registered this with
#     WORKING_DIRECTORY=build-cov/tests/dtls13 so auto-detection of
#     P_SRV/P_CLI/P_PXY works without any env vars (see reference_test_invocation.md).
# On the baseline (v4.1.0) there is no test 132; ctest just runs the unit suites.
ctest --output-on-failure -j"$JOBS" 2>&1 | tail -30 || true

# lcov.sh must run from the build directory where .gcno/.gcda files live.
# It writes Coverage/ into CWD (build-cov/) and cleans up Coverage/tmp/*.info.
# Patch: save final.info before lcov.sh removes it by intercepting via a
# wrapper that copies the file after lcov generates it but before cleanup.
# Simpler: run lcov capture steps manually, then call genhtml ourselves.

lcov_dirs=""
for d in library tf-psa-crypto/core tf-psa-crypto/drivers/builtin; do
    [ -d "$d" ] && lcov_dirs="$lcov_dirs --directory $d"
done

mkdir -p "$OUT"
lcov --rc branch_coverage=1 --capture $lcov_dirs -o "$OUT/final.info" 2>&1 | tail -5
genhtml --title "mbedtls coverage" --legend --branch-coverage \
    -o "$OUT/Coverage" "$OUT/final.info" 2>&1 | tail -5

echo "[coverage] Done. Report: $OUT/Coverage/index.html"
CONTAINER_EOF
}

# --------------------------------------------------------------------------
# Extract a summary line per file from an lcov .info file
# --------------------------------------------------------------------------
summarise_info() {
    local info="$1" label="$2"
    echo "=== $label ==="
    # SF: source file, BRH: branch hits, BRF: branch found, LH: line hits, LF: line found
    python3 - "$info" "$REPO_ROOT" <<'PYEOF'
import sys, os

info_path = sys.argv[1]
repo_root = sys.argv[2]

files = {}
cur = None
with open(info_path) as f:
    for line in f:
        line = line.rstrip()
        if line.startswith("SF:"):
            p = line[3:]
            # Paths are /src/... (container root). Strip leading /src/ to get
            # repo-relative paths like library/ssl_msg.c.
            if p.startswith("/src/"):
                p = p[5:]
            else:
                p = os.path.relpath(p, repo_root)
            cur = p
            files[cur] = {"BRH": 0, "BRF": 0, "LH": 0, "LF": 0}
        elif cur and line.startswith("BRH:"):
            files[cur]["BRH"] = int(line[4:])
        elif cur and line.startswith("BRF:"):
            files[cur]["BRF"] = int(line[4:])
        elif cur and line.startswith("LH:"):
            files[cur]["LH"] = int(line[3:])
        elif cur and line.startswith("LF:"):
            files[cur]["LF"] = int(line[3:])

HDR = f"{'File':<35} {'Br%':>6} {'Br hits/found':>16} {'Ln%':>6} {'Ln hits/found':>16}"
SEP = "-" * len(HDR)

def fmt_row(label, d):
    br_pct = 100*d["BRH"]/d["BRF"] if d["BRF"] else 0.0
    ln_pct = 100*d["LH"]/d["LF"]   if d["LF"]  else 0.0
    return (f"{label:<35} {br_pct:>5.1f}% {d['BRH']:>7}/{d['BRF']:<7}"
            f" {ln_pct:>5.1f}% {d['LH']:>7}/{d['LF']:<7}")

# --- Key files ---
key_files = [
    "library/ssl_msg.c",
    "library/ssl_tls.c",
    "library/ssl_tls13_client.c",
    "library/ssl_tls13_server.c",
]
print(HDR)
print(SEP)
for kf in key_files:
    d = files.get(kf)
    if d is None:
        print(f"{kf:<35} {'N/A':>6}")
    else:
        print(fmt_row(kf, d))

# --- Total across all library files (library/ only, excludes tests/programs) ---
total = {"BRH": 0, "BRF": 0, "LH": 0, "LF": 0}
for path, d in files.items():
    if path.startswith("library/") or path.startswith("tf-psa-crypto/"):
        for k in total:
            total[k] += d[k]
print(SEP)
print(fmt_row("TOTAL (library)", total))
PYEOF
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

require_cmd "$DOCKER"
require_cmd git

log "Pulling image $IMAGE..."
"$DOCKER" pull "$IMAGE" >/dev/null

# Write the container script under the repo root (podman VM mounts ~/misc)
TMPSCRIPT=$(mktemp "$REPO_ROOT/.cov-container-XXXXXX.sh")
trap "rm -f $TMPSCRIPT" EXIT
container_script > "$TMPSCRIPT"
chmod +x "$TMPSCRIPT"

# --- BASELINE ---
if [ "$SKIP_BASELINE" = "1" ] && [ -f "$OUT_BASELINE/final.info" ]; then
    log "Skipping baseline build (SKIP_BASELINE=1, found existing $OUT_BASELINE/final.info)"
else
    log "Setting up baseline worktree ($BASELINE_REF)..."
    rm -rf "$OUT_BASELINE"
    archive_ref "$BASELINE_REF" "$OUT_BASELINE"

    log "Running baseline coverage build in container..."
    "$DOCKER" run --rm \
        -v "$OUT_BASELINE/worktree:/src:z" \
        -v "$TMPSCRIPT:/run-coverage.sh:z" \
        -e SRC=/src \
        -e OUT=/src/cov-out \
        -e JOBS="$JOBS" \
        "$IMAGE" bash /run-coverage.sh

    mv "$OUT_BASELINE/worktree/cov-out" "$OUT_BASELINE/report"
    cp "$OUT_BASELINE/report/final.info" "$OUT_BASELINE/final.info"

    cleanup_worktree "$OUT_BASELINE"
    log "Baseline done → $OUT_BASELINE"
fi

# --- DTLS 1.3 ---
log "Setting up dtls13 worktree ($DTLS13_REF)..."
rm -rf "$OUT_DTLS13"
archive_ref "$DTLS13_REF" "$OUT_DTLS13"

log "Running dtls13 coverage build in container..."
"$DOCKER" run --rm \
    -v "$OUT_DTLS13/worktree:/src:z" \
    -v "$TMPSCRIPT:/run-coverage.sh:z" \
    -e SRC=/src \
    -e OUT=/src/cov-out \
    -e JOBS="$JOBS" \
    "$IMAGE" bash /run-coverage.sh

mv "$OUT_DTLS13/worktree/cov-out" "$OUT_DTLS13/report"
cp "$OUT_DTLS13/report/final.info" "$OUT_DTLS13/final.info"

cleanup_worktree "$OUT_DTLS13"
log "DTLS 1.3 done → $OUT_DTLS13"

# --- DIFF ---
log "Generating coverage diff..."
{
    echo "Coverage comparison: $BASELINE_REF vs $DTLS13_REF"
    echo "Generated: $(date -u)"
    echo ""
    if [ -f "$OUT_BASELINE/final.info" ]; then
        summarise_info "$OUT_BASELINE/final.info" "BASELINE ($BASELINE_REF)"
    else
        echo "BASELINE final.info not found — check $OUT_BASELINE"
    fi
    echo ""
    if [ -f "$OUT_DTLS13/final.info" ]; then
        summarise_info "$OUT_DTLS13/final.info" "DTLS 1.3 ($DTLS13_REF)"
    else
        echo "DTLS13 final.info not found — check $OUT_DTLS13"
    fi
} | tee "$OUT_DIFF"

log "Diff written to $OUT_DIFF"
log "HTML reports:"
log "  Baseline : $OUT_BASELINE/report/Coverage/index.html"
log "  DTLS 1.3 : $OUT_DTLS13/report/Coverage/index.html"
