#!/usr/bin/env bash
# Post-build Linux verification runs. This script only uses explicitly
# provisioned dependencies; it never installs or changes a toolchain.

set -euo pipefail

readonly REQUIRED_RUST_VERSION="1.96.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="${ONE_LINK_REPO:-$(cd -- "${SCRIPT_DIR}/.." && pwd -P)}"
NATIVE="${REPO}/native"

banner() {
    echo
    echo "=================================================================="
    echo "  $*"
    echo "=================================================================="
}

die() {
    echo "FATAL: $*" >&2
    exit 1
}

if ! command -v cargo >/dev/null 2>&1 && \
   [[ -n "${HOME:-}" && -r "${HOME}/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    . "${HOME}/.cargo/env"
fi

[[ "$(uname -s)" == "Linux" ]] || die "this script requires Linux/WSL"
[[ -f "$NATIVE/Cargo.toml" && -f "$NATIVE/Cargo.lock" ]] || \
    die "native Cargo workspace or lockfile is missing at $NATIVE"
command -v cargo >/dev/null 2>&1 || \
    die "cargo is missing; provision Rust ${REQUIRED_RUST_VERSION} explicitly"
command -v rustc >/dev/null 2>&1 || \
    die "rustc is missing; provision Rust ${REQUIRED_RUST_VERSION} explicitly"
[[ "$(rustc --version)" == "rustc ${REQUIRED_RUST_VERSION} "* ]] || \
    die "rustc ${REQUIRED_RUST_VERSION} is required; found $(rustc --version)"
[[ "$(cargo --version)" == "cargo ${REQUIRED_RUST_VERSION} "* ]] || \
    die "cargo ${REQUIRED_RUST_VERSION} is required; found $(cargo --version)"

if [[ -n "${ONE_LINK_VENV:-}" ]]; then
    [[ -f "${ONE_LINK_VENV}/bin/activate" ]] || \
        die "ONE_LINK_VENV does not contain bin/activate: ${ONE_LINK_VENV}"
    # shellcheck source=/dev/null
    . "${ONE_LINK_VENV}/bin/activate"
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "Python command is missing: $PYTHON_BIN"
export PYTHONIOENCODING=utf-8
cd -- "$REPO"

banner "0. native import sanity"
"$PYTHON_BIN" -c 'from one_link_native import chunk, store, coherence_field, bloom, fountain, fec, aead, wal, routing, prefetch, homology, ratchet, pqkem, capability, crdt; print("all 15 submodules OK")'

banner "1. CDC ingest throughput (Linux NVMe path, 1 GiB)"
"$PYTHON_BIN" scripts/ingest_throughput_harness.py --bytes 1G 2>&1 | tail -n 10

banner "2. Phase E fragile-swarm live demo"
"$PYTHON_BIN" scripts/phase_e_live_demo.py 2>&1 | tail -n 15

banner "3. Phase E cross-domain calibration demo"
"$PYTHON_BIN" scripts/phase_e_cross_domain_demo.py 2>&1 | tail -n 25

banner "4. adversarial fuzz (8 regimes, quick)"
"$PYTHON_BIN" scripts/adversarial_field_fuzz.py --quick 2>&1 | tail -n 15

banner "5. Bloom-init savings"
"$PYTHON_BIN" scripts/bloom_init_savings_measure.py 2>&1 | tail -n 15

banner "6. fountain stress (200 seeds, K=512, 5% loss)"
"$PYTHON_BIN" scripts/fountain_k1024_stress.py --seeds 200 2>&1 | tail -n 10

banner "7. production-readiness audit"
"$PYTHON_BIN" scripts/production_readiness_audit.py 2>&1 | tail -n 22

banner "8. coherence-field Helmholtz bench"
BENCH_LOG="$(mktemp "${TMPDIR:-/tmp}/one-link-bench.XXXXXX")"
cleanup() {
    rm -f -- "$BENCH_LOG"
}
trap cleanup EXIT
cd -- "$NATIVE"
if cargo bench --locked -p ol_coherence_field --bench coherence_field_bench -- \
        --quick 'helmholtz_solve|matvec' > "$BENCH_LOG" 2>&1; then
    grep -m 12 -E 'time:' "$BENCH_LOG" || \
        die "benchmark completed without any timing samples; log: $BENCH_LOG"
else
    tail -n 50 -- "$BENCH_LOG" >&2 || true
    die "coherence-field benchmark failed; log: $BENCH_LOG"
fi

banner "ALL LINUX GATES PASSED"
