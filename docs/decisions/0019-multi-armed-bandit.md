# ADR-0019: Multi-Armed Bandit auto-tuning — Beta-Bernoulli Thompson sampling

**Status:** ACCEPTED (Phase C-2 primitive); production integration is route selection only
**Phase:** C (item #5: multi-armed bandit auto-tuning)
**Depends on:** ADR-0013 (TransferEngine)
**Supersedes:** EMA ranking for the route-choice axis in `One_link/src/one_link/transfer_brain.py`; EMA statistics remain cost/reliability inputs and the rollback path

---

## Context

The original Phase C design target was:

> Multi-armed bandit auto-tuning — per peer-pair, per knob (chunk size, parallelism, FEC ratio, prefetch window, pacing, compression threshold). MUST explicitly subsume or replace existing `transfer_brain.py` EMA route memory; two policies cannot coexist.

That target describes a future controller family, not the shipping
integration. The generic sampler exists, but the production runtime currently
maps **candidate routes** to arms. There are no production bandit control loops
for chunk size, parallelism, FEC ratio, prefetch window, pacing, or compression
threshold.

Primitive acceptance gate:

> Bandit converges on a known-optimum synthetic arm within ≤200 interactions in simulation.

The shipping `transfer_brain.py` EMA does **exponential moving average** over observed throughput, which is a degenerate bandit: zero exploration, all exploitation. Once a knob value gets a lucky high reading, the EMA locks onto it. Bad in steady-state; catastrophic when the true optimum drifts (network conditions change, peer hardware upgrades).

## Decision

**Ship `ol_bandit`: a policy-neutral Beta-Bernoulli Thompson-sampling primitive.**

The crate owns posterior sampling and updates only. Callers own arm meaning,
reward normalization, state lifetime, safety constraints, and rollback.

### Production-active integration

`AdaptiveTransferBrain` creates a `BanditRouteSelector` whose arms are the
candidate route names observed for a decision. A successful route observation
is normalized against the 1 Gbit/s reward ceiling; a failed observation records
zero reward. With at least two candidates, `decide()` Thompson-samples one route
and then runs the existing cost-based mode selection within that route.

The existing EMA route statistics still provide bandwidth, latency,
reliability, energy, and confidence inputs. Setting
`ONE_LINK_BANDIT_ROUTE_PICKER=0`, a missing native module, or an isolated bandit
error uses the legacy multi-route Pareto path. This is an explicit safety
fallback, not a second learned route-ranking controller.

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

### Controller scope

Only the first row is production-active:

| Controller | Representative arms | Runtime status |
|---|---|---|
| Route selection | candidate route names | **Production-active** via `BanditRouteSelector` |
| Chunk size | {16, 32, 64, 128, 256 KiB} | Deferred; no production control loop |
| Parallelism | {1, 2, 4, 8, 16} streams | Deferred; no production control loop |
| FEC ratio | {EPHEMERAL, STANDARD, ARCHIVAL} per ADR-0018 | Deferred; no production control loop |
| Prefetch window | {0, 4, 16, 64} chunks | Deferred; no production control loop |
| Pacing | {sender-paced, receiver-credit, none} | Deferred; no production control loop |
| Compression threshold | {disabled, ≥4 KiB, ≥16 KiB, always} | Deferred; no production control loop |

Independent per-peer/per-knob bandits remain a possible future design. They
must not be advertised as shipped until their call sites, state persistence,
bounded actions, rollback behavior, and end-to-end tests exist.

### Route-axis migration

The implemented migration is:

1. `ol_bandit` ships and stabilizes (this ADR, Phase C-2).
2. `transfer_brain.py` adds a `bandit_native` adapter that proxies to `ol_bandit`.
3. `AdaptiveTransferBrain.observe()` records route outcomes in a
   `BanditRouteSelector` when the native module is available.
4. `AdaptiveTransferBrain.decide()` uses the Thompson-sampled route before
   cost-based transfer-mode selection.
5. EMA observations remain descriptive inputs and support the explicit
   rollback path. No EMA-to-posterior state migration is implemented.

No production `choose_knob()` API exists. The six proposed non-route knobs are
therefore outside the completed migration.

### Falsifiable acceptance number

> **The generic bandit converges on a known-optimum synthetic arm within ≤200 interactions in simulation.**

`ol_bandit/tests/acceptance.rs::adr0019_bandit_converges_within_200_interactions`:

- 5-arm bandit, arm probabilities `{0.20, 0.40, 0.55, 0.70, 0.85}`. Arm 4 is optimal.
- Run 200 simulated interactions × 100 random seeds.
- Assert ≥95% of seeds end with `best_arm() == 4`.
- Also assert ≥60% of pulls in the second half went to the optimal arm (exploiting).

**PASSED.** This verifies the generic sampler and the route-selector building
block; it is not evidence that deferred knob controllers are wired.

## Consequences

**Positive:**
- Bayesian-optimal regret on stationary workloads.
- No tuning knobs (no ε, no UCB constant) — the prior + reward fully specify behavior.
- Thompson sampling continues to explore uncertain arms, reducing hard stale-lock-in compared with greedy ranking.
- Tiny state: `2 × K` floats per route selector; maybe 100 bytes per bandit.

**Negative:**
- Gamma + Beta sampling adds ~200 ns per `select` call. Negligible against transfer cost.
- Reward must be `[0, 1]`-normalized. Daemons that have throughput in raw bytes must normalize against a known max — design choice, not algorithm limitation.
- The posterior has no decay or sliding window, so rapid adaptation to non-stationary links is not guaranteed; production claims are limited to the tested stationary-reward model.

## Verification

1. **Primitive acceptance gate**: ≥95% optimal-arm convergence × 100 seeds in 200 rounds (`adr0019_bandit_converges_within_200_interactions`). PASSED.
2. **Tighter gap**: 4-arm bandit with `{0.55, 0.60, 0.65, 0.70}` converges in 500 rounds at ≥75% (`bandit_handles_small_arm_gap`). PASSED.
3. **Property tests**: any `(α, β)` Beta sample is in `(0, 1)`; any Gamma sample is positive + finite.
4. **Error gates**: invalid rewards / out-of-range arms rejected loudly.
5. **Production route wiring**: `tests/unit/test_bandit_route_selector_migration.py` verifies route-arm updates, convergence, authoritative route narrowing, single-route behavior, and rollback.

## References

- Russo & Van Roy, "Learning to Optimize via Posterior Sampling" (2014).
- Marsaglia & Tsang, "A Simple Method for Generating Gamma Variables" (ACM TOMS 2000).
- `FILE_ENGINE_V2_PLAN.md` lines 137 (item #5) + 288 (acceptance).
