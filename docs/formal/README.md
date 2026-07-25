# Formal verification (Phase D #7)

Per [`FILE_ENGINE_V2_PLAN.md`](../FILE_ENGINE_V2_PLAN.md) Phase D item #7:

> Formal verification of safety-critical state machines. TLA+ or
> Coq models of pairing, capability grant, key rotation,
> revocation. Verified properties: no double-grant, no key reuse,
> no downgrade, no replay.

## Layout

- `Capability.tla` — TLA+ specification of capability minting, attenuation,
  root-key rotation, revocation, and adversarial replay validation
  (ADR-0021 + ADR-0027).
- `Capability.cfg` — explicit finite TLC instance with two granters, two
  subjects, two rights, three root keys, three capability IDs, and at most two
  minted capabilities. The bound still admits duplicate-grant attempts,
  strict attenuation, key rotation, acceptance, revocation, and replay.
- `PairQr.tla` — TLA+ specification of the pair-by-QR Factor-1
  trust state machine (Phase F2 / Coherence Mesh). Models Inviter +
  Scanner + an active network attacker; verifies that the Scanner
  cannot reach Done with a forged transcript and that cross-invite
  response replay cannot be accepted by an inviter.
- `PairQr.cfg` — TLC config for the pair-by-QR spec (2 inviters,
  1 scanner, 2 invites, AttackerOn = TRUE). Two inviter-owned invites retain
  the cross-invite replay surface while keeping the blocking state space
  compact.
- `Onion.tla` — TLA+ specification of the onion-circuit relay state
  machine (Phase F3 / Coherence Mesh row 5). Models sender + N
  relays + destination + active attacker; verifies layer
  confidentiality, hop blindness, integrity on relay, and delivery
  fidelity even while attacker actions are enabled.
- `Onion.cfg` — TLC config for the onion spec (3 relays + dest +
  2 payloads, AttackerOn = TRUE).
- `ConfidentialAttestation.tla` / `.cfg` — signed attestation issuance,
  deadline-at-acceptance, challenge consumption, signer/claim binding, and
  bounded-time service quiescence.
- `DeviceMeshSelfRouting.tla` / `.cfg` — two-replica announcement ingestion
  with deterministic equal-timestamp tie breaking and latest-wins safety.
- `DeviceMeshState.tla` / `.cfg` — bounded adversarial drop, replay, and
  reorder exploration for the authenticated CRDT mirror.
- `models.json` — exhaustive model-to-config inventory and the immutable TLC
  release URL/SHA-256 authority. A new `.tla` or `.cfg` file fails validation
  until it is explicitly enrolled here.

## Verified safety invariants

| Invariant | Meaning |
|---|---|
| `NoDoubleGrant` | Two live capability IDs cannot represent the same `(granter, subject, root-rights)` grant. |
| `NoKeyReuse` | Active root keys are unique and a retired root key can never become active again. The runtime intentionally uses one active capability root to derive multiple cap IDs; this invariant concerns key-epoch rotation, not normal derivation. |
| `NoDowngrade` | Every attenuated effective-right set remains a subset of its immutable root-right set. |
| `NoReplay` | A revoked or never-minted capability presentation cannot produce an accepted validation decision. |
| `NoUnverifiedConfirm` (pair-by-QR) | A Scanner only reaches Done when the confirm it accepted commits to the transcript it locally computed. |
| `NoCrossInviteReplay` (pair-by-QR) | An Inviter never advances state on a response that wasn't bound to its specific invite. |
| `SAS_AgreementOnHonestRun` (pair-by-QR) | Two honest peers that both reach Done hold byte-identical chain keys. |
| `StateTypesOk` (pair-by-QR) | State variables only take values from the declared enums (catches off-by-one Rust enum extensions). |
| `NoLayerLeakage` (onion) | A payload is delivered to a destination only if the sender actually sent it; attacker cannot inject arbitrary payloads. |
| `HopBlindness` (onion) | Every relay sees an outcome from the same {None, Forward, Deliver, Failed} set; no label leaks hop position. |
| `IntegrityOnRelay` (onion) | A Failed peel at one hop does not propagate a successful Delivery downstream from that branch. |
| `DeliveryFidelity` (onion) | Even with attacker actions enabled, every delivered payload originates from the sender. |
| `INV_no_past_deadline` (attestation) | The recorded acceptance time never exceeds the signed deadline. |
| `INV_nonce_at_most_once` (attestation) | A verifier consumes a challenge nonce for at most one accepted document. |
| `Convergence` (mesh state/routing) | Replicas with equal accepted-operation sets have equal derived state. |
| `SignatureRequired` (mesh state) | Every applied operation names a sequence already emitted by its authenticated owner. |

## Running TLC

```bash
# Download the exact jar named in models.json, verify its SHA-256, then run:
python scripts/run_formal_models.py \
  --manifest docs/formal/models.json \
  --jar /path/to/tla2tools.jar \
  --output-dir .formal-results
```

The runner checks every committed model, rejects unlisted, case-colliding, or
module/filename/config-mismatched files, isolates Java option injection,
applies per-model timeouts, uses ephemeral state databases, records the exact
Java runtime plus model/config/log hashes, and writes JSON evidence. CI binds
the evidence to `GITHUB_SHA` and rejects a checkout mismatch.
`.github/workflows/formal_verification.yml` runs
the complete inventory on every push and pull request. `release.yml` invokes
the same reusable gate against the exact tag and refuses publication when it
does not pass. Larger configs remain finite but may require a reviewed timeout
increase in `models.json`.

## What this DOES verify

- Each listed state machine preserves its configured invariants across every
  reachable state in its documented finite instance.
- A model-checked counterexample (if any) is a concrete sequence of
  actions that breaks one of the invariants — directly usable as a
  regression test.

## What this DOES NOT verify

- The HMAC chain itself (covered by ADR-0021's 1M-iter soundness
  property test in Rust).
- A general proof for arbitrary domain sizes, or implementation equivalence
  between TLA+ actions and Python/Rust runtime code.
- The wire-format encoding of grants / macaroons (covered by Rust
  unit tests).
- The cap_store gossip / propagation layer (covered by ol_crdt
  lattice-laws gate).
- Max-min route selection or routing-table pruning. `DeviceMeshSelfRouting`
  proves announcement validation, latest-sequence convergence, and expiry for
  its finite instance; those additional algorithms require separate models.

## Related ADRs

- ADR-0021: Capability layer (macaroon HMAC chain).
- ADR-0027: Shadow → authoritative cutovers including macaroon
  wire advertisement.
- ADR-0030 (this commit): formal-verification scaffold.
