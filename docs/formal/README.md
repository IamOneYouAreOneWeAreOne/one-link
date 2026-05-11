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

## Verified safety invariants

| Invariant | Meaning |
|---|---|
| `NoKeyReuse` | A single granter's cap_ids are all distinct. |
| `NoDoubleGrant` | No two grant records share a `(granter, cap_id)` pair. |
| `NoReplay` | A revoked `(granter, subject, scope)` tuple never appears in `ActiveGrants` after revocation lands. |
| `ClockMonotonic` | Logical clock is non-decreasing. |

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
