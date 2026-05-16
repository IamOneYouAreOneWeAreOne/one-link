# Red-team UX/UI Audit — May 16 2026

One Link desktop SPA, `src/one_link/web/index.html` (~17,500 lines).

Audited by walking every flow as a first-time non-technical user.
Findings grouped by severity. Each lists the file:line, what the
user experiences, and the proposed fix.

Severity:
- **P0** — breaks core UX or locks out a class of users. Ship now.
- **P1** — significant friction normal users hit. Ship this session.
- **P2** — polish / inconsistency. Ship soon.
- **P3** — nit / aspirational.

---

## P0 — Ship now

### P0-1. Three modals have no way to close (no ×, no Esc, no click-outside)

| Modal | Line | What user experiences |
|---|---|---|
| `#palette-backdrop` (Ctrl+K command bar) | [index.html:5870](src/one_link/web/index.html#L5870) | Opens, user can't dismiss without knowing Esc works (it doesn't — no handler) |
| `#rdz-help-backdrop` ("What's a rendezvous?" help) | [index.html:5974](src/one_link/web/index.html#L5974) | Same trap: no × button, no Esc, no click-outside |
| `#debug-backdrop` (debug panel) | [index.html:5912](src/one_link/web/index.html#L5912) | Same trap |

**Fix:** Add × close button + bind Esc + bind backdrop-click on all three (event delegation, like the Privacy panel I just shipped).

### P0-2. 15 modals don't close on Escape

Only `discover-overlay` and the new `privacy-panel-overlay` honor Esc. The other 15 (pairing, settings, device drawer, all call surfaces, onboarding, group, voice-record, shortcuts, forward, media-gallery, conflicts, palette, rdz-help, debug) trap users on Esc.

**Fix:** One global Esc handler that closes the topmost `.modal-backdrop.show` (or any `.show` overlay). ~15 lines of JS.

### P0-3. Dead button — "Hard revoke selected device"

[index.html:4514](src/one_link/web/index.html#L4514) `#btn-self-mesh-revoke` has no click handler. Clicking does nothing.

**Fix:** Wire to existing revoke API, or remove the button if the feature isn't ready.

### P0-4. Pairing modal has no timeout / error state

[index.html:4637–4700](src/one_link/web/index.html#L4637) — if the other device never confirms the SAS, user sees the same screen forever. No "timed out, try again" message.

**Fix:** 60s timeout → show "The other device didn't confirm. Try again or pair in person."

### P0-5. Onboarding name input has no label

[index.html:5817](src/one_link/web/index.html#L5817) `<input id="onboarding-name">` has only a placeholder. Screen-reader users hear nothing; the input is the second screen of the very first launch flow.

**Fix:** Add `aria-label="Your name on this device"` (placeholder is not an accessible label).

### P0-6. Search palette input has no label

[index.html:5873](src/one_link/web/index.html#L5873) `<input id="palette-input">` — same issue. Ctrl+K opens an unlabeled input.

**Fix:** `aria-label="Search messages, people, and files"`.

---

## P1 — Ship this session

### P1-1. "Failed to..." pattern in 119 error messages

Examples:
- [index.html:8068](src/one_link/web/index.html#L8068) `"Root setup failed"`
- [index.html:8244](src/one_link/web/index.html#L8244) `"Request failed: ${error}"`
- [index.html:9858](src/one_link/web/index.html#L9858) `"Failed to load group"`

Reads like a programmer wrote it. Plain-English voice: "Couldn't set up your devices", "That didn't work — please try again", "Couldn't open that group".

**Fix:** Bulk-rewrite the most common patterns (`Failed to X` → `Couldn't X`, `X failed` → `Couldn't X`, `Request failed: …` → `Something went wrong. Try again.`).

### P1-2. Jargon throughout the UI (top offenders)

| Term | Where (count) | Plain replacement |
|---|---|---|
| **rendezvous** | 15+ places in help/buttons | "relay server" |
| **SAS** | 40+ places in pair flow | "security code" or "pair code" |
| **fingerprint** | 25+ places (peer detail, key-change banner) | "device ID" |
| **chunk** | 30+ places (sync UI) | "file part" |
| **cert** / **certificate** | 15+ places (device mesh) | "credential" or "invite code" |
| **key change** | 12+ places (security banner) | "security update" |
| **schema** | settings about pane | "data format version" |
| **outbound** / **inbound** | Privacy panel (already fixed) | "outgoing" / "incoming" |
| **manifest** | folder sync | "file list" (already used elsewhere) |

**Fix:** Surface-by-surface replacement. Highest-impact: rename "SAS" → "pair code" everywhere in the pairing flow (40+ instances, but mechanical).

### P1-3. Messages pane is blank with no peer selected

[index.html:4323](src/one_link/web/index.html#L4323) `<div id="messages">` renders empty white space on cold start (no peer selected yet).

**Fix:** Show the same "Pick a device to start" empty-state copy that's already used elsewhere, so the user knows the next step.

### P1-4. Files "Sent" tab uses plain `.empty`, the "Received" tab uses `.empty.rich`

Inconsistent — Sent looks plain text, Received has a glyph + nicer copy.

[index.html:9726](src/one_link/web/index.html#L9726)

**Fix:** Use `.empty.rich` with glyph + same tone as Received: "Files you send appear here. Drag any file onto a peer's chat to send it."

### P1-5. 12 modals missing `role="dialog"` + `aria-modal="true"`

Pair modal, settings shell, device drawer, create-group, group-settings, media-gallery, forward, palette, conflicts, shortcuts, rdz-help, debug.

Screen-reader users don't get announced "dialog opened"; focus isn't trapped.

**Fix:** Add the attributes per modal. Mechanical change.

### P1-6. Em-dash in placeholder text

[index.html:4780](src/one_link/web/index.html#L4780) `placeholder="Short status — what's up?"`

**Fix:** `placeholder="Short status (what's up?)"`.

### P1-7. Device drawer has no click-outside-to-close

[index.html:5514](src/one_link/web/index.html#L5514) `#device-drawer` — × button works, but clicking backdrop doesn't close.

**Fix:** Backdrop click handler.

### P1-8. Focus ring removed globally without `:focus-visible` fallback on 3 inputs

[index.html:612, 771, 1227](src/one_link/web/index.html#L612) — search input, chat composer, palette input.

Tab navigation reaches them but there's no visual indication. Keyboard users lose their place.

**Fix:** Add `:focus-visible { outline: 2px solid var(--accent); }` to each.

### P1-9. 7 modals don't close on click-outside

`#device-backdrop`, `#create-group-backdrop`, `#group-settings-backdrop`, `#shortcuts-backdrop`, `#voice-overlay`, `#onboarding-backdrop`, plus the three P0-1 modals.

**Fix:** Single delegated `document.addEventListener("click", ...)` that closes any visible `.modal-backdrop` when the click target IS the backdrop (not its children). One handler for all.

---

## P2 — Polish

### P2-1. Five icon-only buttons missing `aria-label`

[index.html:4276, 4177, 5609, 5610, 5684](src/one_link/web/index.html#L4276) — search-toggle, settings gear, SAS speak, SAS art, trust-history toggle. All have `title` (mouse hover) but not `aria-label` (screen-reader).

**Fix:** Add `aria-label` to each.

### P2-2. Search input has no Enter-to-submit

[index.html:4274](src/one_link/web/index.html#L4274) `#search-input` only fires on `input` event. Pressing Enter does nothing.

**Fix:** Bind `keydown` Enter → run search, lose focus.

### P2-3. Settings nav uses `.active` class without `aria-current="page"`

Screen-reader users can't tell which settings section is selected.

**Fix:** Add `aria-current="page"` alongside the class.

### P2-4. Blocked-devices empty state is cute but not helpful

[index.html:4909](src/one_link/web/index.html#L4909) "Nobody on the list. Yet." — doesn't explain how to block someone.

**Fix:** "No blocked devices. Block someone from their device card (gear icon) to add them here."

### P2-5. Privacy panel error state is generic

Just shipped; reports "Couldn't load. (network error)". Should hint at cause.

**Fix:** "Couldn't load. The One Link service may be restarting — try again in a moment."

### P2-6. Folders sync has no per-folder progress indicator

[index.html:10432](src/one_link/web/index.html#L10432) — folder rows don't show "syncing…" while in flight.

**Fix:** Add a small "syncing…" badge when the daemon reports an active sync for that folder.

---

## P3 — Nits

- Activity feed empty state could say "Make a call or send a file — it'll show up here" instead of just "show up here as they happen".
- Settings save success has no toast — silent. Should confirm "Saved" briefly.
- "Verify in person" badge on a peer card (top header) doesn't explain why — tooltip should say "Confirm you're really talking to this person. Tap to learn how."

---

## What I propose to ship in THIS session

Most user impact for the least diff:

1. **P0-1, P0-2** — single document-level Esc handler + close × on the three orphaned modals. ~30 lines, eliminates 18 dead-end traps at once.
2. **P0-3** — wire the dead Hard-revoke button (or remove it cleanly).
3. **P0-4** — pair-modal timeout with retry CTA.
4. **P0-5, P0-6** — `aria-label` on onboarding-name and palette-input.
5. **P1-1** — bulk-rewrite top error messages from "Failed to X" to "Couldn't X".
6. **P1-2 (partial)** — rename "SAS" to "pair code" in the pairing flow (the highest-impact jargon swap).
7. **P1-3, P1-4** — messages-pane + Files-Sent empty states.
8. **P1-6** — the one em-dash.
9. **P1-8** — `:focus-visible` outlines on three inputs.
10. **P1-9** — backdrop-click-to-close across the remaining 7 modals.

Defer to follow-up:
- P1-2 (jargon) for terms other than "SAS" (fingerprint / cert / chunk are bigger surfaces).
- P1-5 (role=dialog on 12 modals) — mechanical, but each one needs a labeled heading. Half-day.
- All of P2 + P3.

That brings the SPA from "many silent dead-ends" to "every flow has an obvious next step, every modal has a way out, every error explains itself in plain English."
