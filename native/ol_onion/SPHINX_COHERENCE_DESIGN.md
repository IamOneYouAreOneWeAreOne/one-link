# Sphinx Coherence — onion routing beyond the textbook

Status: research design-of-record for F3.5. The branch contains packet-level
Tier 1 primitives and tests; it does **not** contain a live One Link
message/file onion route, an independently operated mix-net, or evidence for
sender anonymity or traffic-analysis resistance. Tier 2 items are design
targets with separate acceptance gates.

This document supersedes `SPHINX_DESIGN.md` (which captured the
correct standard Sphinx algorithm; that becomes the floor of this
design).

## Threat model — target versus current evidence

No row in this table is a product claim. Packet construction tests establish
only the narrow properties named in the final column.

| Adversary class | Design target | Current evidence and limit |
|---|---|---|
| Per-relay passive observer | Hide the end-to-end route and content from one honest-but-curious relay | Nested encryption and alpha evolution are tested. A relay still sees its adjacent sockets, direction, timing, packet count, and fixed packet size. |
| Global passive observer (sees every relay) | Make cross-relay linkage difficult | **Not defeated.** Alpha blinding changes visible group elements, but a global observer can still correlate timing, direction, volume, and topology. |
| Record-now/decrypt-later adversary | Retain confidentiality if at least one hybrid component remains secure | The entry-hop KDF combines X25519 and ML-KEM-768 outputs and tests input binding. This is conditional on the underlying schemes, protocol composition, and correct deployment; it is not a cryptanalytic proof or live-route evidence. |
| Future break of both X25519 and ML-KEM | Add independent secret material | **Not defeated by a published field digest.** The present Sphinx field API mixes caller-supplied context; public or low-entropy context is not a replacement cryptographic key. |
| Compromised relay revealing previous/next hop | Limit information to adjacent hops | Inherent limit. Reed-Solomon multi-path is a deferred availability target, not a current anonymity mitigation. |
| Circuit shortening or rerouting | Authenticate an intended path transcript | **Not defeated.** Schnorr sign/batch-verify primitives exist, but there is no proved, live end-to-end path-authorization protocol. |
| Timing correlation across relays | Shape real and dummy traffic into a measured anonymity system | **Not defeated.** Cover packet and rate-control primitives do not provide mixing, delay, a deployment-wide schedule, or an anonymity proof. |
| Single-circuit failure | Recover payload from independent paths | Reed-Solomon multi-path is deferred and not wired into a product onion route. |

## Tier 1 — implemented packet primitives (not a product route)

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

Conditional security intent: if ML-KEM-768 remains secure and the hybrid
composition is correct, recovering only the classical component does not
reproduce the KDF input used for `b_0`. Current tests prove that changing or
omitting the PQ input changes derived bytes; they do not simulate a quantum
adversary or prove the protocol's cryptographic security.

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

**Current consequence:** changing the supplied witness changes the derived
keys and causes the packet check to fail. Because the design says relays
publish the digest, that digest is context, not secret entropy; a recorder can
record it too. No evidence establishes 32 bits of unpredictability, proves
that an RF environment is represented by the digest, or shows that the value
cannot be reconstructed. A future security design may mix a separately stored,
CSPRNG-grade secret from another trust domain, but that would be a new key-
management protocol and must be reviewed as such.

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

Historical development notes recorded broad unit/property/KAT coverage. Test
counts and iteration counts are not security proofs and must be regenerated by
the release gate rather than treated as permanent evidence.

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

Target: reduce an explicitly modelled observer's inference accuracy. A
Poisson sampler or rate equalizer alone does not imply a uniform posterior.
That result would require a defined observation model, real-traffic shaping,
mixing/delay, deployment-wide measurements, and independent analysis; none is
current product evidence.

### T2.2 Reed-Solomon multi-path onion (item 8)

Each user payload is encoded with a (K, N) Reed-Solomon code via
`ol_threshold_recovery`'s GF(2^8) arithmetic. The N fragments are
each wrapped in their own Sphinx packet and dispatched along
**N parallel circuits** (each with different hop sets).

Any K of N fragments at the destination would reconstruct the message. This
is an availability and path-diversity target. Fragmentation can also add
correlation signals, so it is not treated as a traffic-analysis defense
without a measured complete protocol.

### T2.3 ZK proof of valid peel (item 10, research-grade)

The target asks each relay to emit a zero-knowledge proof that it performed a
valid peel without revealing what it decrypted. Whether a future construction
supports accountable, privacy-preserving routing depends on its statement,
witness, setup, metadata, and deployment; no such product protocol exists.

This is its own multi-week effort. Tracked but not in any current
ship plan.

## Target wire packet (Tier 1 research format)

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

The research implementation was decomposed into five work items:

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

| Property | Required evidence before promotion |
|---|---|
| Sphinx construction interoperability | Independently maintained reference vectors plus parser/peel differential tests for the exact wire version |
| PQ-hybrid input binding | Standardized-algorithm KATs, explicit combiner analysis, downgrade tests, implementation review, and cross-platform runtime evidence |
| Field-context binding | KAT showing changed context changes derived keys; no confidentiality claim unless a separate high-entropy secret and lifecycle are specified and reviewed |
| Coherence-field hop selection | Reproducible route-quality experiment with baseline, distribution, confidence interval, and failure cases |
| Schnorr verification | Exact signed transcript/protocol specification, rogue-key defenses, negative vectors, and independent review |
| Hop unlinkability/anonymity | Defined adversary and observation model, multi-vantage deployed traces, timing/volume classifiers, and a stated measured bound; alpha bytes alone are insufficient |
| Constant packet size | Encoded-length tests for every supported route length and message class; size equality is not timing/volume anonymity |
| Per-hop integrity | Mutation/fuzz/KAT coverage plus implementation review; test coverage is not a proof against every attack |

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

The value of this design is the set of composable experiments it makes
possible. Novel combinations also create novel failure modes; uniqueness is
not security evidence. One Link must not claim that this stack defeats every
known onion-routing attack, provides anonymity, or protects a live route until
the complete deployed protocol passes the gates above.
