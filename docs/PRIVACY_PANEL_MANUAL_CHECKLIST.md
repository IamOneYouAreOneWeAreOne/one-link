# Privacy panel manual checklist — May 16 2026

Pixel + click-flow verification for the May 15-16 sovereignty bundle
(3-tier presets, Privacy panel, P2P version gossip, live-switch
update-check loop). Python-side `tests/test_sovereignty.py` already
locks the contract (34 tests / 0 failed) — this list covers the
things automated tests can't see.

## Pre-flight

| | |
|---|---|
| Daemon up on 7117 | `curl -H "Authorization: Bearer $(cat ~/AppData/Local/Coherence/One_link/ui.token)" http://127.0.0.1:7117/api/me` returns the identity JSON |
| Sovereignty endpoint live | `GET /api/sovereignty/status` returns `preset.name = "just_works"` on a fresh install |
| Daemon log clean | `tail -20 dev-daemon.err.log` shows no Traceback since boot |

## Trigger affordance

- [ ] The 🔒 lock icon is visible in the top bar, BETWEEN the presence pill and the gear ⚙.
- [ ] Hovering the 🔒 icon shows the title "Privacy (sovereignty preset, outbound audit)".
- [ ] The icon does NOT crowd the existing chrome (presence pill, gear).
- [ ] Clicking 🔒 opens the Privacy panel.
- [ ] Pressing Ctrl+Shift+P from anywhere in the page also opens it.
- [ ] Pressing Ctrl+Shift+P while the panel is already open does NOT toggle it closed (open is idempotent — pressing again just re-renders).

## Panel layout (just-opened state)

- [ ] Modal centered on screen, blurred backdrop.
- [ ] Title bar reads "🔒 Privacy" (lock glyph + word).
- [ ] Close button × top-right.
- [ ] Three preset cards visible in a vertical stack:
  - **Just Works** (active, purple highlight, ✓ checkmark) — first
  - **Quiet** — second
  - **Off-grid** — third
- [ ] Each card shows: bold preset label, italics description (~2 lines), one-line "↗ <outbound summary>" in monospace.
- [ ] **Live feature state** section below preset cards shows 4 rows:
  - Update check (GitHub Releases) — ON · from preset
  - WebRTC STUN servers — ON · from preset · 3 server(s)
  - mDNS LAN discovery — ON · from preset
  - Rendezvous (third-party relay) — OFF · from preset
- [ ] **Recent outbound calls** section shows: 0 or 1 entry (likely the boot-time update-check probe to api.github.com).
- [ ] Promise text at bottom: "If this list is empty, the daemon has made zero outbound calls..."

## Preset switching

1. Click the **Quiet** card.
- [ ] Card swap is instant — Quiet highlights purple + ✓, Just Works loses highlight.
- [ ] Toast bottom-right reads "Sovereignty preset: quiet".
- [ ] Feature state grid re-renders to: Update check OFF · STUN list empty · mDNS ON · Rendezvous OFF.
- [ ] Sources for `update_check` + `stun_servers` flip to "preset" (still preset-driven, just on a stricter tier).

2. Click **Off-grid**.
- [ ] All four features OFF.
- [ ] mDNS discovery now reads OFF.

3. Click **Just Works** again.
- [ ] Back to the green/ON state for update check + STUN + mDNS.

4. Close the panel + reopen.
- [ ] Active preset persists (Just Works highlighted again — DB-stored).

## Outbound-call audit

Force an update check via Settings → Check now (or `curl POST /api/update/check?fresh=1`):
- [ ] On `just_works`: the call succeeds, a NEW entry appears in the outbound log table with destination "api.github.com (Releases)", kind chip "update_check".
- [ ] Switch to `quiet`, click "Check now" again: the call short-circuits to status=disabled and NO new outbound entry appears.
- [ ] Switch back to `just_works`: the next 6h-loop tick (or manual ?fresh=1) DOES re-poll, proving the loop honored the runtime switch without a daemon restart.

## P2P version gossip

(Requires a paired peer running a different version — Computer 2 if available.)
- [ ] If Computer 2 is on the SAME version, the Privacy panel shows NO "Update available (from peer)" section.
- [ ] If Computer 2 is on a NEWER version (e.g., 0.22 while local is 0.21), the panel shows an orange-tinted row: "A paired peer (Computer 2) is running 0.22 · you: 0.21".
- [ ] The hint copy ends with "This hint came from a paired peer's handshake — no call to GitHub or any third party was made to learn this." (sovereignty messaging is intact).
- [ ] When Computer 2 is on an OLDER version, no hint appears (no false downgrade prompt).
- [ ] Pending / rejected peers reporting a fake-newer version do NOT drive the hint (only pinned peers count).

## Dismissal

- [ ] Pressing **Escape** closes the panel.
- [ ] Clicking the dark backdrop (outside the white modal) closes it.
- [ ] Clicking the × close button closes it.
- [ ] After dismissal, the rest of the UI (sidebar, chat, files, etc.) is fully interactive — no residual blur, no captured focus.

## Doctrine of Invisibility

- [ ] The panel never appears unprompted — only when the user clicks 🔒 or hits Ctrl+Shift+P.
- [ ] No banner / toast about the panel exists at idle.
- [ ] Main UI doesn't reference "sovereignty" or "privacy" anywhere except the 🔒 icon's title attribute.

## Visual fit & finish

- [ ] Modal width ~720px on desktop; clamps to 92vw on smaller screens.
- [ ] Modal max-height 88vh; body scrolls if content overflows.
- [ ] Preset cards hover state subtly tints purple.
- [ ] Active preset card border is visibly thicker than inactive.
- [ ] Feature-state ON/OFF colors readable on dark + light themes.
- [ ] No console errors in the browser devtools when opening / closing / switching.

## Sovereignty self-check (any browser session)

- [ ] `python -m one_link audit` (CLI) prints `External telemetry: NO`.
- [ ] If `just_works` is active and the daemon has been up <6h with no UI tabs open: outbound log shows 1 entry (the post-warmup update-check probe).
- [ ] On `quiet` (set + restart daemon for cleanest state): outbound log empty + Privacy panel shows the green "● No outbound calls since this device booted." block.

---

If any item above fails, capture (1) the exact step, (2) what you
saw vs expected, (3) browser devtools console output, and either
file an issue or hand it back to the dev loop.

Python-side regression baseline:
- `tests/test_sovereignty.py` — 34 tests (preset definitions,
  resolver, API endpoints, version gossip, HTML markers).
- `tests/test_doctrine_of_invisibility.py` — 10 tests pass.
- Full suite (last verified): 5091+ pass / 0 real failures.
