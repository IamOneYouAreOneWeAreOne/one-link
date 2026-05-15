# ADR-0034: Doctrine of Invisibility sweep (v0.21.0-alpha legacy surfaces)

**Status:** ACCEPTED (cleanup work itemised)
**Phase:** Tier α-pre of Living Presence
**Companion:** [DOCTRINE_OF_INVISIBILITY.md](../DOCTRINE_OF_INVISIBILITY.md),
[LIVING_PRESENCE_ARCHITECTURE.md](../LIVING_PRESENCE_ARCHITECTURE.md)

---

## Context

The Doctrine of Invisibility lint ([tests/test_doctrine_of_invisibility.py](../../tests/test_doctrine_of_invisibility.py))
landed in Tier α-pre with a fresh scan of the current user surface.
Five legitimate violations were identified in `src/one_link/web/index.html`
that predate the doctrine and cannot be removed within the same PR
without expanding scope:

| Line | Clause | Surface | Replacement plan |
|---|---|---|---|
| 4369–4376 | §3.1.a | "Advanced mode" toggle + help text in settings | Remove the toggle. Surfaces it gates either ship by default or are removed entirely. |
| 5811 | §3.6.c | `reachLabel(p)` returns `"on Wi-Fi"` for LAN | Replace with `"Local network"`. Doctrine path-class language. |
| 5814 | §3.6.c | Same function, private-address fallback returns `"on Wi-Fi"` | Same — `"Local network"`. |
| 6081 | §3.2.a | Update install toast says `"reconnecting"` | Drop the word. Just say `"Installing update…"`. The WebSocket reconnect is engine work, not user-facing. |
| 12283–12296 | §3.2.a | `showReconnectBanner()` writes `"Reconnecting to One Link…"` into the offline banner | Replace with capsule-mode fallback per [LIVING_PRESENCE_ARCHITECTURE.md §3](../LIVING_PRESENCE_ARCHITECTURE.md). Silent prewarm; never name the network. |

Each violation has an inline `doctrine-ok: §X.Y (ADR-0034) — …` annotation
so the lint passes today, while preserving a documented cleanup target.

## Decision

The cleanup ships as part of the Tier α-pre **legacy doctrine sweep**, a
dedicated follow-up PR rather than expanding the present PR's scope.

Acceptance: each of the five violations either has its surface removed
or its language replaced. The lint annotation is removed in the same
commit; the lint must pass strictly afterwards.

## Consequences

- The lint passes today with five annotated grandfathers.
- New code adding a §3 violation fails the lint immediately.
- Cleanup work is scoped: five concrete strings + one removed toggle.
- Future doctrine clauses added to [DOCTRINE_OF_INVISIBILITY.md §3](../DOCTRINE_OF_INVISIBILITY.md)
  may surface additional legacy violations; each gets the same
  grandfather + ADR treatment, with the cleanup itemised here or in
  a successor ADR.

## Reviewed

- 2026-05-14: filed alongside the doctrine lint PR.
