#!/usr/bin/env bash
# Post-build Linux verification runs.

set -e
set -o pipefail

REPO=/mnt/c/Users/Alex/Projects/Coherence/One_link
VENV=/root/ol_venv

cd "$REPO"
# shellcheck source=/dev/null
. "$VENV/bin/activate"
# shellcheck source=/dev/null
. "$HOME/.cargo/env"
export PYTHONIOENCODING=utf-8

banner() {
    echo
    echo "=================================================================="
    echo "  $*"
    echo "=================================================================="
}

banner "0. native import sanity"
python -c 'from one_link_native import chunk, store, coherence_field, bloom, fountain, fec, aead, wal, routing, prefetch, homology, ratchet, pqkem, capability, crdt; print("all 15 submodules OK")'

banner "1. CDC ingest throughput (Linux NVMe path, 1 GiB)"
python scripts/ingest_throughput_harness.py --bytes 1G 2>&1 | tail -10

banner "2. Phase E fragile-swarm live demo"
python scripts/phase_e_live_demo.py 2>&1 | tail -15

banner "3. Phase E cross-domain calibration demo"
python scripts/phase_e_cross_domain_demo.py 2>&1 | tail -25

banner "4. Adversarial fuzz (8 regimes, quick)"
python scripts/adversarial_field_fuzz.py --quick 2>&1 | tail -15

banner "5. Bloom-init savings"
python scripts/bloom_init_savings_measure.py 2>&1 | tail -15

banner "6. Fountain stress (200 seeds, K=512, 5% loss)"
python scripts/fountain_k1024_stress.py --seeds 200 2>&1 | tail -10

banner "7. Production-readiness audit"
python scripts/production_readiness_audit.py 2>&1 | tail -22

banner "8. coherence-field Helmholtz bench"
cd /root/ol_native_linux
cargo bench -p ol_coherence_field --bench coherence_field_bench -- --quick 'helmholtz_solve|matvec' 2>&1 | grep -E "time:" | head -12

banner "ALL LINUX GATES COMPLETE"
