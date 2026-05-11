# ADR-0027: Shadow → authoritative cutovers (bandit + folder mirror + macaroon)

**Status:** ACCEPTED (Phase C-3 cutover completion)
**Phase:** C-3
**Depends on:** ADR-0019 (bandit), ADR-0021 (capability layer), ADR-0022 (CRDT folders), ADR-0024 (Phase C-3 wiring status), ADR-0026 (native transfer capability)

---

## Context

The Phase C-3 daemon-migration commits (`25675d1` + `27e8e6c`) shipped five native primitives wired as **shadow / dual-issue** call sites. The shadow posture (per [ADR-0024](0024-phase-c3-wiring-status.md)) was safe but didn't deliver value to production: the bandit accumulated state but never drove decisions; the folder mirror observed merges but legacy stayed authoritative; the macaroon was minted but never shipped on the wire.

This ADR records the cutover completion that promotes these from shadow / dual-issue to actually-in-the-loop. Each cutover ships with a rollback escape flag for production incident response.

## Decisions

### #1 Bandit route picker (authoritative — replaces EMA)

Per [stress-test #3 of FILE_ENGINE_V2_PLAN.md](../FILE_ENGINE_V2_PLAN.md), the bandit MUST REPLACE (not coexist with) the EMA route memory. Done.

`AdaptiveTransferBrain.decide()` now consults the `BanditRouteSelector` built up by `observe()`. With ≥2 candidate routes and an initialized bandit:

```python
if self._bandit is not None and len(candidate_routes) > 1:
    bandit_pick = self._bandit.select_route()
    if bandit_pick in candidate_routes:
        candidate_routes = (bandit_pick,)
```

The Pareto frontier still picks the MODE (hash/fixed/CDC/swarm) within the chosen route — the bandit's exploration / exploitation Thompson sampling drives route choice; cost-based Pareto drives mode choice. Two complementary signals, neither overrides the other.

**Rollback**: `ONE_LINK_BANDIT_ROUTE_PICKER=0` forces legacy multi-route Pareto.

**Verification**: a brain seeded with 200 biased observations (lan: 800 Mbps reward, wan: 10 Mbps) picks "lan" in ≥80% of 50 sampled `decide()` calls — confirming the bandit's exploration tail is bounded around the converged best arm.

### #2 Folder mirror active cross-check (gate for full authoritative cutover)

The folder mirror was a pure observer in `25675d1`. After this commit it ACTIVELY VALIDATES that the native folder's `contains_path(file_path)` agrees with the legacy merge winner decision. Mismatches bump `_native_mirror_divergence` + log a warning. `native_mirror_stats()` surfaces the counter for operator monitoring.

**Why not full authoritative cutover yet**: legacy `merge_manifest_entries` uses vclock + edit-wins-deletion (live entry beats concurrent tombstone via vector-clock concurrency). `ol_crdt.Folder.merge` uses OR-set add-wins-via-fresh-tag (any new add survives any prior remove, regardless of vclock). These can disagree on edge cases. A safe full cutover requires either:

1. Updating `ol_crdt::Folder` to mirror daemon semantics (vclock-aware OR-set), OR
2. Updating daemon to ol_crdt semantics (the daemon's manifest receive loop is rewritten to consume the native folder's present-set as the source of truth).

The active cross-check is the gate. After a measurable production window of zero divergence events, a future commit (one-line swap in `FolderEngine._handle_remote_manifest`) flips the legacy `merge_manifest_entries` call to the native `Folder.merge` path.

### #3 Macaroon advertisement on CAPABILITY_GRANT (forward-compatible field)

The `_last_minted_macaroon` slot was populated by the dual-issue migration but never shipped on the wire. After this commit `daemon.send_share_grant()` adds `macaroon_b64` to the `CAPABILITY_GRANT` message dict whenever the macaroon was minted:

```python
grant_fields = {"grant_b64": grant_b64}
if self._last_minted_macaroon is not None:
    grant_fields["macaroon_b64"] = (
        base64.urlsafe_b64encode(self._last_minted_macaroon)
        .rstrip(b"=").decode("ascii")
    )
await self.send_to(peer, [make_msg("CAPABILITY_GRANT", ..., **grant_fields)])
```

Receivers that understand the new format can verify the macaroon directly; legacy receivers ignore the unknown key (the daemon's CAPABILITY_GRANT handler reads `grant_b64` specifically — extra keys are silently dropped). Wire is forward-compatible by construction.

Receiver-side handling that prefers macaroon over legacy grant lands in a follow-up commit once macaroon issuance has been live long enough to populate cap-stores across the network.

## Verification

- **85 unit tests pass** (was 78; added 4 bandit-decide + 1 folder-cross-check + 2 macaroon-wire).
- **2,952 daemon regression tests pass / 0 failed**.
- **mypy clean** on all new code in `transfer_brain.py` + `foldersync.py` + `cap_migration.py` + `native_transfer.py` (pre-existing errors on `object`-typed internals not introduced by this commit).

## What's still deferred

Per the user directive "everything truly completed and wired" before Phase D begins, this ADR closes:

| Shadow path (pre-`b141715`) | Status |
|---|---|
| Bandit observe-only, never drives | ✅ Authoritative (via `BanditRouteSelector.select_route()` in `decide()`) |
| Folder mirror observes silently | ✅ Active cross-check + divergence counter |
| Macaroon stashed in `_last_minted_macaroon` | ✅ Shipped on wire as `macaroon_b64` |
| Per-chunk ratchet activated | ✅ via `FILE_NATIVE_CHUNK` cutover (ADR-0026) |
| PQ-hybrid `default_kem()` activated | ✅ via `Channel.establish_native_transfer()` derivation (ADR-0025) + FILE_NATIVE_CHUNK default-on (this commit + 5c62a64) |

Remaining for follow-up (not blockers for Phase D):

- Full authoritative folder cutover — requires the semantic reconciliation step described above.
- Receiver-side macaroon verification preference — requires a tracking window of widespread macaroon issuance.
- Bandit's mode-level selection (currently Pareto still handles mode) — could move to a per-(route, mode) bandit if data warrants.

## References

- ADR-0019 (Multi-armed bandit auto-tuning)
- ADR-0021 (Capability layer — macaroon issuance)
- ADR-0022 (CRDT folders — Folder.merge semantics)
- ADR-0024 (Phase C-3 wiring status — the shadow posture this completes)
- ADR-0026 (NATIVE_TRANSFER_V1 capability — companion cutover)
- `FILE_ENGINE_V2_PLAN.md` stress-tests #3, #4
