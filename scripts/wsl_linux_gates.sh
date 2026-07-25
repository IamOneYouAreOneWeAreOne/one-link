#!/usr/bin/env bash
# Strict Linux/WSL verification gates for the file-engine stack.
#
# This script never installs toolchains or packages. Provision the pinned Rust
# toolchain and Linux/FUSE prerequisites explicitly before running it.

set -euo pipefail

readonly REQUIRED_RUST_VERSION="1.96.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="${ONE_LINK_REPO:-$(cd -- "${SCRIPT_DIR}/.." && pwd -P)}"
NATIVE="${REPO}/native"
REPORT="${ONE_LINK_WSL_REPORT:-${REPO}/_wsl_linux_report.json}"

declare -a REPORT_KEYS=("start_ts")
declare -a REPORT_VALUES=("$(date -u +%Y-%m-%dT%H:%M:%SZ)")

banner() {
    echo
    echo "=================================================================="
    echo "  $*"
    echo "=================================================================="
}

record_result() {
    REPORT_KEYS+=("$1")
    REPORT_VALUES+=("$2")
}

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

write_report() {
    local report_dir report_tmp index separator
    report_dir="$(dirname -- "$REPORT")"
    report_tmp="${REPORT}.tmp.$$"
    mkdir -p -- "$report_dir"
    {
        echo "{"
        separator=""
        for ((index = 0; index < ${#REPORT_KEYS[@]}; index++)); do
            printf '%s  "%s": "%s"' \
                "$separator" \
                "$(json_escape "${REPORT_KEYS[$index]}")" \
                "$(json_escape "${REPORT_VALUES[$index]}")"
            separator=$',\n'
        done
        echo
        echo "}"
    } > "$report_tmp"
    mv -f -- "$report_tmp" "$REPORT"
}

finish() {
    local exit_code=$?
    trap - EXIT
    set +e
    record_result "end_ts" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    record_result "exit_code" "$exit_code"
    if write_report; then
        echo "Report written to: $REPORT"
        cat -- "$REPORT"
    else
        echo "FATAL: could not write report to $REPORT" >&2
        if [[ "$exit_code" -eq 0 ]]; then
            exit_code=3
        fi
    fi
    exit "$exit_code"
}
trap finish EXIT

fail_gate() {
    local report_key="$1"
    local reason="$2"
    local exit_code="${3:-1}"
    record_result "$report_key" "FAILED: $reason"
    echo "FATAL [$report_key]: $reason" >&2
    exit "$exit_code"
}

require_command() {
    local command_name="$1"
    command -v "$command_name" >/dev/null 2>&1 || \
        fail_gate "host_tools" "required command is missing: $command_name" 2
}

load_existing_rust_environment() {
    if ! command -v cargo >/dev/null 2>&1 && \
       [[ -n "${HOME:-}" && -r "${HOME}/.cargo/env" ]]; then
        # Loading an already-provisioned environment is allowed; this script
        # intentionally never downloads or installs Rust.
        # shellcheck source=/dev/null
        . "${HOME}/.cargo/env"
    fi
}

verify_pinned_rust() {
    local rustc_version cargo_version
    load_existing_rust_environment
    require_command cargo
    require_command rustc
    rustc_version="$(rustc --version)"
    cargo_version="$(cargo --version)"
    if [[ "$rustc_version" != "rustc ${REQUIRED_RUST_VERSION} "* ]]; then
        fail_gate "rust_toolchain" \
            "expected rustc ${REQUIRED_RUST_VERSION}, found ${rustc_version}; provision the pinned toolchain explicitly" 2
    fi
    if [[ "$cargo_version" != "cargo ${REQUIRED_RUST_VERSION} "* ]]; then
        fail_gate "rust_toolchain" \
            "expected cargo ${REQUIRED_RUST_VERSION}, found ${cargo_version}; provision the pinned toolchain explicitly" 2
    fi
    record_result "rustc_version" "$rustc_version"
    record_result "cargo_version" "$cargo_version"
}

banner "1. host and repository"
[[ "$(uname -s)" == "Linux" ]] || fail_gate "host_os" "this gate requires Linux/WSL" 2
[[ -d "$REPO" ]] || fail_gate "repo" "repository is not visible at $REPO" 2
[[ -f "$NATIVE/Cargo.toml" && -f "$NATIVE/Cargo.lock" ]] || \
    fail_gate "native_workspace" "native Cargo workspace or lockfile is missing at $NATIVE" 2
[[ -f "$REPO/scripts/ingest_throughput_harness.py" ]] || \
    fail_gate "ingest_harness" "scripts/ingest_throughput_harness.py is missing" 2
[[ -x "$SCRIPT_DIR/wsl_fuse_mount_test.sh" || -f "$SCRIPT_DIR/wsl_fuse_mount_test.sh" ]] || \
    fail_gate "fuse_gate" "scripts/wsl_fuse_mount_test.sh is missing" 2
require_command uname
require_command nproc
require_command python3
record_result "kernel" "$(uname -r)"
record_result "cpu_cores" "$(nproc)"
record_result "repo" "$REPO"
record_result "host_tools" "PASS"

banner "2. pinned Rust toolchain"
verify_pinned_rust
record_result "rust_toolchain" "PASS"
rustc --version
cargo --version

banner "3. native release build"
readonly BUILD_LOG="${TMPDIR:-/tmp}/one-link-wsl-build.log"
cd -- "$NATIVE"
if cargo build --locked --release \
        -p ol_chunk -p ol_aead -p ol_coherence_field -p ol_chunk_store \
        -p ol_wal -p ol_fountain -p ol_fec -p ol_bloom \
        > "$BUILD_LOG" 2>&1; then
    record_result "native_build" "PASS"
    echo "native release build: PASS"
else
    tail -n 40 -- "$BUILD_LOG" >&2 || true
    fail_gate "native_build" "cargo build failed; full log: $BUILD_LOG"
fi

banner "4. native release tests"
readonly TEST_LOG="${TMPDIR:-/tmp}/one-link-wsl-test.log"
TEST_CRATES=(
    -p ol_chunk -p ol_aead -p ol_coherence_field -p ol_chunk_store
    -p ol_wal -p ol_fountain -p ol_fec -p ol_bloom
    -p ol_capability -p ol_crdt -p ol_routing -p ol_prefetch -p ol_homology
)
if cargo test --locked --release "${TEST_CRATES[@]}" > "$TEST_LOG" 2>&1; then
    PASS_COUNT="$(grep -c -E 'test result: ok' "$TEST_LOG" || true)"
    [[ "$PASS_COUNT" -gt 0 ]] || \
        fail_gate "cargo_test" "cargo exited successfully but reported no passing test groups"
    record_result "cargo_test" "PASS"
    record_result "cargo_test_groups" "$PASS_COUNT"
    echo "native release tests: PASS ($PASS_COUNT groups)"
else
    tail -n 50 -- "$TEST_LOG" >&2 || true
    fail_gate "cargo_test" "cargo test failed; full log: $TEST_LOG"
fi

banner "5. Python/native import"
PYTHON_VERSION="$(python3 --version 2>&1)"
record_result "python_version" "$PYTHON_VERSION"
if python3 -c 'import one_link_native' >/dev/null 2>&1; then
    record_result "native_import" "PASS"
    echo "one_link_native import: PASS"
else
    fail_gate "native_import" \
        "one_link_native is not importable; build the pinned Linux wheel before running this gate"
fi

banner "6. CDC ingest throughput"
readonly INGEST_LOG="${TMPDIR:-/tmp}/one-link-wsl-ingest.log"
cd -- "$REPO"
if python3 scripts/ingest_throughput_harness.py --bytes 256M > "$INGEST_LOG" 2>&1; then
    tail -n 20 -- "$INGEST_LOG"
    record_result "ingest_harness" "PASS"
else
    tail -n 30 -- "$INGEST_LOG" >&2 || true
    fail_gate "ingest_harness" "throughput harness failed; full log: $INGEST_LOG"
fi

banner "7. FUSE mount round-trip"
readonly FUSE_LOG="${TMPDIR:-/tmp}/one-link-wsl-fuse.log"
if ONE_LINK_REPO="$REPO" "$SCRIPT_DIR/wsl_fuse_mount_test.sh" > "$FUSE_LOG" 2>&1; then
    tail -n 30 -- "$FUSE_LOG"
    record_result "fuse_mount_round_trip" "PASS"
else
    tail -n 50 -- "$FUSE_LOG" >&2 || true
    fail_gate "fuse_mount_round_trip" "strict mount test failed; full log: $FUSE_LOG"
fi

banner "summary"
record_result "overall" "PASS"
echo "All strict Linux/WSL gates passed."
