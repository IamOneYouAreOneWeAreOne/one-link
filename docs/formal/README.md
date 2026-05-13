# Formal verification (Phase D #7)

Per [`FILE_ENGINE_V2_PLAN.md`](../FILE_ENGINE_V2_PLAN.md) Phase D item #7:

> Formal verification of safety-critical state machines. TLA+ or
> Coq models of pairing, capability grant, key rotation,
> revocation. Verified properties: no double-grant, no key reuse,
> no downgrade, no replay.

## Layout

- `Capability.tla` — TLA+ specification of the capability grant + revoke +
  attenuation state machine (ADR-0021 + ADR-0027).
- `Capability.cfg` — TLC model-check config (Granters, Subjects, Scopes,
  RootKeys, MaxClock). Production verification runs TLC over this finite
  space on every change to the capability state machine.
- `pair_qr.tla` — TLA+ specification of the pair-by-QR Factor-1
  trust state machine (Phase F2 / Coherence Mesh). Models Inviter +
  Scanner + an active network attacker; verifies that the Scanner
  cannot reach Done with a forged transcript and that cross-invite
  response replay cannot be accepted by an inviter.
- `PairQr.cfg` — TLC config for the pair-by-QR spec (2 inviters,
  2 scanners, 2 invites, AttackerOn = TRUE).
- `onion.tla` — TLA+ specification of the onion-circuit relay state
  machine (Phase F3 / Coherence Mesh row 5). Models sender + N
  relays + destination + active attacker; verifies layer
  confidentiality, hop blindness, integrity on relay, and delivery
  fidelity on honest runs.
- `Onion.cfg` — TLC config for the onion spec (3 relays + dest +
  2 payloads, AttackerOn = TRUE).

## Verified safety invariants

| Invariant | Meaning |
|---|---|
| `NoKeyReuse` | A single granter's cap_ids are all distinct. |
| `NoDoubleGrant` | No two grant records share a `(granter, cap_id)` pair. |
| `NoReplay` | A revoked `(granter, subject, scope)` tuple never appears in `ActiveGrants` after revocation lands. |
| `ClockMonotonic` | Logical clock is non-decreasing. |
| `NoUnverifiedConfirm` (pair-by-QR) | A Scanner only reaches Done when the confirm it accepted commits to the transcript it locally computed. |
| `NoCrossInviteReplay` (pair-by-QR) | An Inviter never advances state on a response that wasn't bound to its specific invite. |
| `SAS_AgreementOnHonestRun` (pair-by-QR) | Two honest peers that both reach Done hold byte-identical chain keys. |
| `StateTypesOk` (pair-by-QR) | State variables only take values from the declared enums (catches off-by-one Rust enum extensions). |
| `NoLayerLeakage` (onion) | A payload is delivered to a destination only if the sender actually sent it; attacker cannot inject arbitrary payloads. |
| `HopBlindness` (onion) | Every relay sees an outcome from the same {None, Forward, Deliver, Failed} set; no label leaks hop position. |
| `IntegrityOnRelay` (onion) | A Failed peel at one hop does not propagate a successful Delivery downstream from that branch. |
| `DeliveryFidelity` (onion) | On honest runs (no attacker action), every delivered payload originates from the sender. |

## Running TLC

```bash
# Install TLA+ tools (https://github.com/tlaplus/tlaplus/releases)
java -jar tla2tools.jar -workers auto -config Capability.cfg Capability.tla
```

A fresh run completes in seconds on the default config. Larger configs
(more granters / subjects / longer clock horizon) take longer but are
finite — TLC exhausts the state space rather than running indefinitely.

## What this DOES verify

- The state machine's transitions preserve the four safety invariants
  across every reachable state.
- A model-checked counterexample (if any) is a concrete sequence of
  actions that breaks one of the invariants — directly usable as a
  regression test.

## What this DOES NOT verify

- The HMAC chain itself (covered by ADR-0021's 1M-iter soundness
  property test in Rust).
- The wire-format encoding of grants / macaroons (covered by Rust
  unit tests).
- The cap_store gossip / propagation layer (covered by ol_crdt
  lattice-laws gate).

## Related ADRs

- ADR-0021: Capability layer (macaroon HMAC chain).
- ADR-0027: Shadow → authoritative cutovers including macaroon
  wire advertisement.
- ADR-0030 (this commit): formal-verification scaffold.
