# ADR-0019: Multi-Armed Bandit auto-tuning — Beta-Bernoulli Thompson sampling

**Status:** ACCEPTED (Phase C-2)
**Phase:** C (item #5: multi-armed bandit auto-tuning)
**Depends on:** ADR-0013 (TransferEngine)
**Supersedes:** the EMA route-memory in `One_link/src/one_link/transfer_brain.py`

---

## Context

The Phase C plan (line 137):

> Multi-armed bandit auto-tuning — per peer-pair, per knob (chunk size, parallelism, FEC ratio, prefetch window, pacing, compression threshold). MUST explicitly subsume or replace existing `transfer_brain.py` EMA route memory; two policies cannot coexist.

Acceptance gate (line 288):

> Bandit converges on known-optimum peer-pair within ≤200 interactions in simulation.

The shipping `transfer_brain.py` EMA does **exponential moving average** over observed throughput, which is a degenerate bandit: zero exploration, all exploitation. Once a knob value gets a lucky high reading, the EMA locks onto it. Bad in steady-state; catastrophic when the true optimum drifts (network conditions change, peer hardware upgrades).

## Decision

**Ship `ol_bandit`: Beta-Bernoulli Thompson sampling, one Bandit per (peer-pair, knob).**

### Algorithm

For each `Bandit` over `K` arms (candidate knob values):

1. Maintain `(α_i, β_i)` per arm, initialized to `(1, 1)` (uniform prior).
2. `select`: for each arm, sample `θ_i ~ Beta(α_i, β_i)`; return `argmax θ_i`.
3. `update(arm_idx, reward)`: `α_{idx} += reward`, `β_{idx} += (1 - reward)` for `reward ∈ [0, 1]`.

### Why Thompson sampling?

| Approach | Pros | Cons | Decision |
|---|---|---|---|
| ε-greedy (existing chat-engine standard) | Simple, well-understood | ε is a tuning parameter; doesn't adapt to remaining uncertainty | Reject |
| UCB1 | Bounded regret proof | Pessimistic; over-explores early | Reject |
| **Thompson sampling** | Bayesian-optimal Bayes regret; naturally balances explore/exploit | Slightly more complex (Beta sampler) | **Accept** |
| LinUCB / contextual | Handles context (peer features) | 10× more state per arm | Defer to Phase D |

Thompson sampling has [Russo & Van Roy 2014]'s theoretical Bayes-optimal regret bound and empirically dominates ε-greedy + UCB on most real workloads.

### Beta-Bernoulli with reward scaling

Real rewards are continuous in `[0, 1]` (e.g. normalized throughput, success indicator). We treat continuous `r` as a Bernoulli-thinned success fraction: `α += r`, `β += (1 - r)`. This is the standard "Beta-Bernoulli with reward scaling" approximation; it preserves the closed-form posterior + remains valid as a Bayesian update.

### Knob ↔ Bandit mapping

The daemon owns a `HashMap<(PeerFingerprint, KnobId), Bandit>`. Knob IDs:

| KnobId | Arms (representative) |
|---|---|
| ChunkSize | {16, 32, 64, 128, 256 KiB} |
| Parallelism | {1, 2, 4, 8, 16} streams |
| FecRatio | {EPHEMERAL, STANDARD, ARCHIVAL} per ADR-0018 |
| PrefetchWindow | {0, 4, 16, 64} chunks |
| Pacing | {sender-paced, receiver-credit, none} |
| CompressionThreshold | {disabled, ≥4 KiB, ≥16 KiB, always} |

Independent bandit per knob (orthogonality assumption); contextual / joint bandits are a Phase D upgrade.

### Replacing `transfer_brain.py` EMA

The migration:

1. `ol_bandit` ships and stabilizes (this ADR, Phase C-2).
2. `transfer_brain.py` adds a `bandit_native` adapter that proxies to `ol_bandit`.
3. The EMA path is deleted; `transfer_brain.py.choose_knob()` consults the bandit directly.
4. State migration: existing EMA values become a one-shot prior `(α, β) = (ema * 100, (1 - ema) * 100)` — large pseudo-count so the bandit doesn't immediately explore away from a proven knob.

Per the plan ("two policies cannot coexist"), the EMA gets deleted in the same PR that lands the adapter.

### Falsifiable acceptance number

> **Bandit converges on known-optimum peer-pair within ≤200 interactions in simulation.**

`ol_bandit/tests/acceptance.rs::adr0019_bandit_converges_within_200_interactions`:

- 5-arm bandit, arm probabilities `{0.20, 0.40, 0.55, 0.70, 0.85}`. Arm 4 is optimal.
- Run 200 simulated interactions × 100 random seeds.
- Assert ≥95% of seeds end with `best_arm() == 4`.
- Also assert ≥60% of pulls in the second half went to the optimal arm (exploiting).

**PASSED.**

## Consequences

**Positive:**
- Bayesian-optimal regret on stationary workloads.
- No tuning knobs (no ε, no UCB constant) — the prior + reward fully specify behavior.
- Drift-tolerant: posterior mass shifts as new rewards land. Catastrophic stale-lock-in of EMA is gone.
- Tiny state: `2 × K` floats per (peer, knob); maybe 100 bytes per bandit.

**Negative:**
- Gamma + Beta sampling adds ~200 ns per `select` call. Negligible against transfer cost.
- Reward must be `[0, 1]`-normalized. Daemons that have throughput in raw bytes must normalize against a known max — design choice, not algorithm limitation.

## Verification

1. **Acceptance gate**: ≥95% optimal-arm convergence × 100 seeds in 200 rounds (`adr0019_bandit_converges_within_200_interactions`). PASSED.
2. **Tighter gap**: 4-arm bandit with `{0.55, 0.60, 0.65, 0.70}` converges in 500 rounds at ≥75% (`bandit_handles_small_arm_gap`). PASSED.
3. **Property tests**: any `(α, β)` Beta sample is in `(0, 1)`; any Gamma sample is positive + finite.
4. **Error gates**: invalid rewards / out-of-range arms rejected loudly.

## References

- Russo & Van Roy, "Learning to Optimize via Posterior Sampling" (2014).
- Marsaglia & Tsang, "A Simple Method for Generating Gamma Variables" (ACM TOMS 2000).
- `FILE_ENGINE_V2_PLAN.md` lines 137 (item #5) + 288 (acceptance).
