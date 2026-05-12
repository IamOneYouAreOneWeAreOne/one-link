#!/usr/bin/env bash
# Linux-side verification gates for the file engine v2 stack.
#
# Run from inside WSL2 (Ubuntu) against the Windows repo mounted at
# /mnt/c/Users/Alex/Projects/Coherence/One_link. The script:
#
#   1. Sniffs the host (cargo + python availability + filesystem).
#   2. Installs rust + python deps if needed (idempotent).
#   3. Builds the native crates that need Linux verification.
#   4. Runs cargo test --workspace --release on Linux.
#   5. Runs the Phase A1 ingest-throughput harness on the Linux side
#      where NTFS isn't the WAL-write bottleneck.
#   6. Attempts the FUSE mount round-trip (best-effort; libfuse may
#      not be installed).
#
# Output: human-readable status + per-gate result. Writes a JSON
# report to /mnt/c/Users/Alex/Projects/Coherence/One_link/_wsl_linux_report.json
# so the Windows side can read it.
#
# Usage from Windows:
#   wsl bash /mnt/c/Users/Alex/Projects/Coherence/One_link/scripts/wsl_linux_gates.sh

set -e -o pipefail

REPO=/mnt/c/Users/Alex/Projects/Coherence/One_link
REPORT=$REPO/_wsl_linux_report.json
NATIVE=$REPO/native

# Pretty banner.
banner() {
    echo
    echo "=================================================================="
    echo "  $*"
    echo "=================================================================="
}

# Append a key-value pair to the JSON report. Quick-and-dirty; we
# write a flat single-object JSON without proper escaping. Safe for
# values that don't contain quotes / newlines (status strings).
write_report_kv() {
    local key="$1"
    local value="$2"
    if [ ! -f "$REPORT" ]; then
        echo "{" > "$REPORT"
        echo "  \"$key\": \"$value\"" >> "$REPORT"
    else
        # Strip trailing close-brace, append comma + entry, close.
        sed -i '$d' "$REPORT" 2>/dev/null || true
        echo "  ,\"$key\": \"$value\"" >> "$REPORT"
    fi
}

# Reset report.
echo "{" > "$REPORT"
echo "  \"start_ts\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"" >> "$REPORT"
echo "}" >> "$REPORT"

# ── 1. host sniff ─────────────────────────────────────────────────
banner "1. host sniff"
echo "kernel: $(uname -r)"
echo "distro: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME)"
echo "cpu:    $(nproc) cores"
echo "mem:    $(free -h | awk '/^Mem:/ {print $2}')"
echo "repo:   $REPO ($(test -d $REPO && echo OK || echo MISSING))"
write_report_kv "kernel" "$(uname -r)"
write_report_kv "cpu_cores" "$(nproc)"

if ! test -d "$REPO"; then
    echo "FATAL: repo not visible at $REPO"
    write_report_kv "fatal" "repo_not_visible"
    exit 2
fi

# ── 2. rust toolchain ──────────────────────────────────────────────
banner "2. rust toolchain"
if ! command -v cargo >/dev/null 2>&1; then
    if test -f "$HOME/.cargo/env"; then
        # shellcheck source=/dev/null
        . "$HOME/.cargo/env"
    fi
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not present — installing rustup ..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --no-modify-path
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env"
fi
cargo --version
write_report_kv "cargo_version" "$(cargo --version)"

# ── 3. native build ────────────────────────────────────────────────
banner "3. native build (release)"
cd "$NATIVE"
BUILD_LOG=/tmp/ol_wsl_build.log
echo "building ol_chunk + ol_aead + ol_coherence_field + ol_chunk_store ..."
if cargo build --release \
        -p ol_chunk -p ol_aead -p ol_coherence_field -p ol_chunk_store \
        -p ol_wal -p ol_fountain -p ol_fec -p ol_bloom \
        > "$BUILD_LOG" 2>&1; then
    echo "  BUILD OK"
    write_report_kv "native_build" "OK"
else
    echo "  BUILD FAILED (see $BUILD_LOG):"
    tail -30 "$BUILD_LOG"
    write_report_kv "native_build" "FAILED"
fi

# ── 4. cargo test workspace ────────────────────────────────────────
banner "4. cargo test --workspace --release"
TEST_LOG=/tmp/ol_wsl_test.log
# Test only the crates that are pure-Rust + don't need windows-specific
# pyo3 wheels. Skip one_link_native (pyo3) since it needs the python
# headers + maturin and isn't the Linux-side gate's primary target.
TEST_CRATES="-p ol_chunk -p ol_aead -p ol_coherence_field -p ol_chunk_store -p ol_wal -p ol_fountain -p ol_fec -p ol_bloom -p ol_capability -p ol_crdt -p ol_routing -p ol_prefetch -p ol_homology"
if cargo test --release $TEST_CRATES > "$TEST_LOG" 2>&1; then
    PASS_COUNT=$(grep -E "test result: ok" "$TEST_LOG" | wc -l)
    echo "  TESTS OK ($PASS_COUNT test groups)"
    write_report_kv "cargo_test" "PASS"
    write_report_kv "cargo_test_groups" "$PASS_COUNT"
else
    echo "  TESTS FAILED (last 40 lines of $TEST_LOG):"
    tail -40 "$TEST_LOG"
    write_report_kv "cargo_test" "FAILED"
fi

# ── 5. python deps (for ingest harness) ────────────────────────────
banner "5. python harness deps"
PY=$(command -v python3 || true)
if [ -z "$PY" ]; then
    echo "python3 not installed — skipping ingest harness"
    write_report_kv "python_available" "no"
else
    "$PY" --version
    write_report_kv "python_version" "$($PY --version)"
fi

# ── 6. ingest throughput on Linux NVMe (or ext4) ────────────────────
banner "6. CDC ingest throughput (Linux)"
INGEST_LOG=/tmp/ol_wsl_ingest.log
if [ -n "$PY" ] && [ -f "$REPO/scripts/ingest_throughput_harness.py" ]; then
    # The harness imports from one_link_native which requires the
    # pyo3 wheel build. Without it the harness skips cleanly. We
    # don't insist on the wheel; the cargo benches above already
    # cover the pure-Rust paths.
    if "$PY" -c "import one_link_native" 2>/dev/null; then
        cd "$REPO"
        if "$PY" scripts/ingest_throughput_harness.py --bytes 256M > "$INGEST_LOG" 2>&1; then
            cat "$INGEST_LOG" | tail -15
            write_report_kv "ingest_harness" "RAN"
        else
            echo "  ingest harness exited non-zero"
            tail -20 "$INGEST_LOG"
            write_report_kv "ingest_harness" "FAILED"
        fi
    else
        echo "  one_link_native not importable from Linux python; ingest harness skipped"
        echo "  (build via: maturin develop --release -m native/one_link_native/Cargo.toml from Linux)"
        write_report_kv "ingest_harness" "SKIP_no_wheel"
    fi
else
    write_report_kv "ingest_harness" "SKIP_no_python"
fi

# ── 7. FUSE mount round-trip (best-effort) ──────────────────────────
banner "7. FUSE mount round-trip (best-effort)"
if test -d /sys/fs/fuse; then
    if command -v fusermount3 >/dev/null 2>&1 || command -v fusermount >/dev/null 2>&1; then
        echo "  libfuse tools present"
        # The actual ol_fuse mount test requires the crate's example/
        # binary to exist + the user to be in the fuse group. We
        # document the readiness here; the actual mount-and-fsx-linux
        # work is a follow-up cycle.
        write_report_kv "fuse_libfuse" "present"
        # Try to build the ol_fuse crate (Linux gate).
        cd "$NATIVE"
        if cargo build --release -p ol_fuse > /tmp/ol_fuse_build.log 2>&1; then
            echo "  ol_fuse crate builds OK on Linux"
            write_report_kv "ol_fuse_linux_build" "OK"
        else
            echo "  ol_fuse build failed (check /tmp/ol_fuse_build.log)"
            tail -20 /tmp/ol_fuse_build.log
            write_report_kv "ol_fuse_linux_build" "FAILED"
        fi
    else
        echo "  libfuse tools NOT installed (apt install libfuse3-dev fuse3 to enable)"
        write_report_kv "fuse_libfuse" "missing"
    fi
else
    echo "  /sys/fs/fuse not present — FUSE not supported on this kernel"
    write_report_kv "fuse_kernel" "missing"
fi

# ── 8. report ──────────────────────────────────────────────────────
banner "summary"
write_report_kv "end_ts" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Report written to: $REPORT"
echo "Tail of report:"
cat "$REPORT"
echo
echo "Run from Windows side via:"
echo "  wsl bash /mnt/c/Users/Alex/Projects/Coherence/One_link/scripts/wsl_linux_gates.sh"
