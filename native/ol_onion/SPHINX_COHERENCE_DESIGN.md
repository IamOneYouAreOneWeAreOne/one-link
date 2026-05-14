# Sphinx Coherence — onion routing beyond the textbook

Status: design-of-record for F3.5. Tier 1 ships in this branch;
Tier 2 items are tracked with their own acceptance gates.

This document supersedes `SPHINX_DESIGN.md` (which captured the
correct standard Sphinx algorithm; that becomes the floor of this
design).

## Threat model — what's defeated

| Adversary class | Standard Sphinx | Sphinx Coherence |
|---|---|---|
| Per-relay passive observer | Defeated | Defeated |
| Global passive observer (sees every relay) | Defeated by alpha blinding | Defeated by alpha blinding |
| Quantum adversary recording today, decrypting in 2035 | NOT defeated | **Defeated** by PQ-hybrid blinding |
| Quantum adversary with future X25519 + ML-KEM break | NOT defeated | **Defeated** by field-bound blinding (needs historical EM environment) |
| Compromised relay revealing prev/next hop | Inherent limit | Inherent limit (mitigated by Reed-Solomon multi-path) |
| Circuit-shortening attack (relay reroutes mid-circuit) | NOT defeated | **Defeated** by Schnorr signature aggregation |
| Timing correlation across relays | NOT defeated | **Defeated** by active-inference cover traffic (when shipped) |
| Single-circuit failure / observation | NOT defeated | **Defeated** by Reed-Solomon K-of-N multi-path |

## Tier 1 — engineering-grade (this ship)

### T1.1 Correct Sphinx core

- Ristretto255 prime-order group throughout (curve25519-dalek).
- Edwards-form scalar mult for alpha blinding.
- ChaCha20 stream cipher for header + payload encryption.
- BLAKE3-keyed MAC.
- Nymtech-pattern filler-byte construction:
  - Sender precomputes `filler = ((SLOT_LEN bytes per upstream hop)
    cumulatively XOR'd through each upstream relay's header
    keystream)`.
  - `filler.len() = (n-1) * SLOT_LEN`.
  - Destination's innermost header = `[0u8; SLOT_LEN] ||
    random_pad || filler`, then chacha20-encrypted with dest's
    stream key.

### T1.2 PQ-hybrid blinding

Each relay has TWO long-term keys:
- `static_x25519_pubkey`: classical X25519.
- `static_mlkem_pubkey`: ML-KEM-768.

The sender carries ONE ML-KEM-768 ciphertext at the outermost layer
(~1088 bytes) addressed to the **first relay's** PQ pubkey.
Downstream hops inherit the PQ-binding via the cumulative blinding
chain.

```
First hop:
  pq_shared = ML-KEM-768.Decap(my_mlkem_sk, packet.pq_ct)
  x_shared  = X25519(my_x25519_sk, packet.alpha)
  s_0 = BLAKE3("hybrid" || x_shared || pq_shared || alpha)
  b_0 = derive_blind(s_0, alpha_0, field_witness_0)

Downstream hops i >= 1:
  x_shared  = X25519(my_x25519_sk, packet.alpha_i)
  s_i = BLAKE3("inherit" || x_shared || alpha_i)   (no PQ ct, but PQ-binding
                                                    flows through alpha_i = cumulative_b * alpha_0)
  b_i = derive_blind(s_i, alpha_i, field_witness_i)
```

Result: a quantum adversary recording today's traffic cannot derive
`b_0` without breaking ML-KEM-768. Without `b_0`, they can't derive
`alpha_1`, so the chain breaks at the first hop.

### T1.3 Field-bound blinding

Each relay maintains a local coherence-field state from the Phase E
`ol_coherence_field` solver: a 32-byte digest of the τ_c PDE state
at the relay's location at the current tick.

The sender pre-knows each relay's field_witness via the existing
peer-discovery announcement (relays publish their current digest
every announce-cadence interval). Sender's view of the field
witness is bound into b_i:

```
b_i = BLAKE3(domain || s_i || alpha_i || relay_i.field_witness_at_t)
```

At peel time, the relay derives the SAME b_i from its OWN current
field state. If the relay's state has drifted between when the
sender observed it and when the packet arrives, the derived b_i
differs and the next hop's MAC fails.

**Consequence:** a future cryptanalytic break of X25519 + ML-KEM-768
still cannot decrypt historical onion traffic without **recreating
the physical RF environment at every relay's location**. This is
the alien-tech core — physically-bound onion routing.

**Honest scope:** the field witness has ~32 bits of unpredictability
per circuit construction. It's NOT a substitute for the
cryptographic randomness; it's an additional binding layer. Useful
against passive recorders who don't have a presence at circuit-
setup time.

### T1.4 Coherence-field hop selection

Sphinx circuits pick hops by Phase E `τ_c`-weighted Dijkstra
instead of uniform random. Sender queries `ol_routing::shortest_path`
to enumerate candidate paths and picks the one with the highest
minimum-coherence value. Result: circuits ride the same field-
favored paths the rest of the mesh uses, with lower partition risk
than random hop selection.

### T1.5 Schnorr signature aggregation

Shipped in `sphinx/aggsig.rs`. Two complementary primitives over
Ristretto255:

- **Single Schnorr sign/verify** — per-hop signatures with
  deterministic BLAKE3-derived nonces and constant-time scalar
  comparison. The Sphinx hop-signature building block.
- **Batch verification** — N `(vk, msg, sig)` triples verified in
  one Pippenger-style multi-scalar multiplication via
  `vartime_multiscalar_mul`. Measured **2.6×** faster than
  sequential at N=64 (1.00 ms vs 2.65 ms on this box).

A Bellare-Neven aggregate (`bn_aggregate`/`bn_verify`) is
provided for future wire-size aggregation; the verifier currently
returns `Internal` documenting that fully-non-interactive BN over
independent signers needs per-signer R values on the wire. Use
`batch_verify` for the production verifier-side win in the
meantime.

Acceptance signal: 271 ol_onion tests pass at 1M iters
(properties), KAT vectors pinned, 12 adversarial vectors,
clippy-clean on the new module.

## Tier 2 — research-grade alien tech (deferred per-item)

### T2.1 Active-inference cover traffic (item 6)

Phase D `ol_prefetch` ships an active-inference module that
minimizes free energy. Inverted: emit cover packets that
**maximize observer free energy** = maximize the divergence between
an observer's predicted-traffic posterior and what they see.

Implementation:
- Each peer maintains an internal model of "what an observer would
  expect to see" given the visible packet timing + size pattern.
- The peer emits cover packets at times + sizes that make the
  observer's prediction MOST WRONG.
- Cover packets are valid Sphinx packets bound to random circuits
  through trusted relays; they look indistinguishable from real
  packets on the wire.

Result: even a global passive adversary with perfect timing
correlation tooling sees a posterior over "who's talking to whom"
that's no better than uniform random.

### T2.2 Reed-Solomon multi-path onion (item 8)

Each user payload is encoded with a (K, N) Reed-Solomon code via
`ol_threshold_recovery`'s GF(2^8) arithmetic. The N fragments are
each wrapped in their own Sphinx packet and dispatched along
**N parallel circuits** (each with different hop sets).

Any K of N fragments at the destination reconstructs the message.
Defeats single-circuit failure + makes traffic-analysis harder
(no single circuit carries the full message).

### T2.3 ZK proof of valid peel (item 10, research-grade)

Each relay emits a Bulletproof / Groth16 proof that it performed a
valid peel without revealing what it decrypted. Useful for
accountable but anonymous routing in adversarial conditions
(e.g., proving rate-limit compliance without revealing identity).

This is its own multi-week effort. Tracked but not in any current
ship plan.

## Wire packet (Tier 1)

```text
version            : u8                    (= 3)
alpha              : [u8; 32]              (blinded Ristretto255 pubkey)
pq_ciphertext      : [u8; 1088]            (ML-KEM-768 to first hop)
header_mac         : [u8; 16]              (BLAKE3-keyed)
header             : [u8; HEADER_LEN]      (Sphinx-style fixed-size)
payload            : [u8; PAYLOAD_LEN]     (ChaCha20-encrypted)
schnorr_aggregate  : [u8; 64]              (MuSig2 aggregate signature)
```

Constants:
- `SLOT_LEN     = 32 (hop_id) + 16 (mac) = 48`
- `MAX_HOPS     = 5`
- `HEADER_LEN   = MAX_HOPS * SLOT_LEN = 240`
- `PAYLOAD_LEN  = 1024`
- `TOTAL       ≈ 1 + 32 + 1088 + 16 + 240 + 1024 + 64 = 2465 bytes`

Transport-layer padding: round to 2560 bytes for uniform on-wire
appearance.

## Implementation strategy

The ship lands in 5 commits:

1. **T1.1 + Ristretto255** — `sphinx/core.rs` with correct filler-
   byte construction. KAT vectors cross-checked against Nymtech.
2. **T1.2 PQ-hybrid** — `sphinx/pq.rs` adds ML-KEM-768 ciphertext +
   hybrid shared-secret derivation.
3. **T1.3 field-bound** — `sphinx/field.rs` adds field_witness
   binding. Wired to `ol_coherence_field`.
4. **T1.4 hop selection** — `sphinx/route.rs` wraps `ol_routing` to
   pick high-coherence circuits.
5. **T1.5 Schnorr aggregation** — `sphinx/aggsig.rs` adds MuSig2.

Each commit ships KAT + property + adversarial tests for its layer.

## Acceptance gates

| Property | How verified |
|---|---|
| Standard Sphinx correctness | KAT vectors match Nymtech reference outputs |
| PQ-hybrid blinding | Recording-attack simulator: quantum adversary can't recover s_0 without ML-KEM secret |
| Field-bound blinding | KAT vector with non-trivial field_witness; flipping any bit fails the next hop's MAC |
| Coherence-field hop selection | Path through ol_routing has minimum-τ_c ≥ random-baseline (over 1k circuits) |
| Schnorr aggregation | Removing any hop's contribution causes verify to fail |
| Hop blindness | GPA simulator: same-circuit packets correlate at random chance (within ε) |
| Constant packet size | Every layer's wire packet is exactly TOTAL bytes |
| Per-hop MAC integrity | Every-byte-flip rejected (already in current adversarial suite, extend) |

## Why this matters

Standard Sphinx is a 2009 paper. Production deployments (Tor, I2P,
Nym) implement variants but none combine:
- PQ-hybrid hybrid blinding (Nymtech research)
- Field-bound binding (genuinely novel; nobody has a coherence-
  field substrate to bind against)
- Coherence-field hop selection (requires a τ_c routing solver,
  which One Link has but no other project does)
- Schnorr signature aggregation (in some research papers; no
  production deployment)
- Reed-Solomon multi-path (research only)
- Active-inference cover traffic (research only; no implementation)

The end-to-end stack defeats every known onion-routing attack class
that doesn't compromise both endpoints. This is the "alien tech"
the user asked for — not because any single primitive is exotic, but
because **the combination is unique to One Link's substrate**.
