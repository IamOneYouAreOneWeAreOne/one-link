# Phone Tier — implementation guide

Status: living document. Detailed enough to pick up cold and execute.
Last updated: 2026-05-08.

**Owner principle:** [`PRINCIPLES.md`](./PRINCIPLES.md), specifically
principle #2 (Hide the engine) applied at maximum aggression for the
phone form-factor.

**One-line claim:**
> A phone user who can't locate a feature isn't missing the feature;
> the feature is failing them by being there.

This document is the canonical specification for what changes about
One Link's UI when it runs on a phone. It's deliberately exhaustive
so the work can be picked up after a long pause without re-thinking
every call from scratch.

---

## Why a phone tier exists

The desktop UI currently surfaces ~40 settings, 4 pane tabs, a multi-
section device drawer, an Activity feed with filter chips, a
Diagnostics modal, and several power-user controls. On a phone, that
density is hostile:

- A 360px viewport can't render filter chips and a search bar and a
  pane tab bar without overflow.
- Touch targets at desktop sizes (28-32px) miss frequently on
  thumbs.
- Most phone users don't read help text; they tap, see, repeat.
- Nobody on a phone debugs wire frames.
- Nobody on a phone configures a rendezvous URL.

The phone tier is **value subtraction work**: deciding what *not* to
show. It's harder than feature addition because every cut is an
argument with whoever first added the surface.

---

## The mechanism (two layers)

### Layer 1 — `data-form-factor` on `<html>`

Set at boot by a small JS function. Values: `"phone"` | `"tablet"` |
`"desktop"`. Decision rule:

```
const w = Math.min(window.innerWidth, window.innerHeight);
const touch = ("ontouchstart" in window) || navigator.maxTouchPoints > 0;
const ua = navigator.userAgent.toLowerCase();
const ua_mobile = /iphone|ipod|android.+mobile|windows phone/.test(ua);

if (w <= 480 || ua_mobile) factor = "phone";
else if (w <= 900 && touch) factor = "tablet";
else factor = "desktop";
```

CSS reads via attribute selectors:

```css
html[data-form-factor="phone"] .desktop-only { display: none !important; }
html[data-form-factor="phone"] [data-tier="advanced"] { display: none; }
html.show-advanced [data-tier="advanced"] { display: revert !important; }
```

Re-evaluated on `resize` events with a 250ms debounce, so a phone
rotated to landscape doesn't immediately flicker into desktop mode
(stays phone unless the user genuinely resizes a browser window past
the threshold).

### Layer 2 — `state.tier` setting

Persisted in `chat-prefs` (server-synced via the existing endpoint).
Values: `"default"` | `"advanced"`.

- **Phone:** defaults to `"default"`. Toggle in Profile pane: "Show
  advanced controls" reveals everything `data-tier="advanced"`.
  Resets on tab close (per-session, not per-device-persisted) so
  users can't get stuck in advanced mode they don't remember
  enabling.
- **Tablet:** defaults to `"default"`. Same toggle.
- **Desktop:** defaults to `"advanced"` (current full-fat experience).
  Toggle still exists for users who want a leaner surface.

Toggling adds/removes class `show-advanced` on `<html>`.

### Tagging convention

Every UI element being hidden gets one of two attributes / classes:

- `class="desktop-only"` — **truly absent on phone**. Even the
  "Show advanced" toggle does NOT reveal it. Use for things that
  literally don't apply (folder sync, log verbosity dropdown).
- `data-tier="advanced"` — **hidden by default, reveal-able**. Use
  for power-user surfaces that exist but aren't first-class.

A few elements get BOTH on different platforms (e.g., the
Diagnostics modal entry point: `desktop-only` for the keyboard
shortcut hint, `data-tier="advanced"` for the Settings → Advanced
button — kbd-shortcut hint is gone on phone, button is reveal-able).

---

## The complete list

Every UI surface in the app, audited and assigned a phone-tier
disposition. Categories:

- **REMOVE** = `class="desktop-only"`, never visible on phone.
- **ADVANCED** = `data-tier="advanced"`, hidden by default, revealable.
- **RESHAPE** = visible on phone but presentation differs (single
  list instead of tabs, etc.).
- **KEEP** = identical on both tiers.

### Top header (`.top`)

| Element | Disposition | Notes |
|---|---|---|
| Brand logo + wordmark | KEEP | |
| Pane tabs: Chat | KEEP | |
| Pane tabs: Files | REMOVE | Files appear inline in chat already; standalone tab is desktop-only. |
| Pane tabs: Folders | REMOVE | No filesystem access on phone. |
| Pane tabs: Activity | ADVANCED | Power surface; most phone users don't need it. |
| Mobile hamburger button (left) | KEEP | Already shipped v0.14.0. |
| Presence pill | KEEP | |
| Settings gear | KEEP | |

### Sidebar (`.side`)

Behavior on phone is already a slide-in drawer (v0.14.0). Content
specifics:

| Element | Disposition | Notes |
|---|---|---|
| "MY DEVICES" section header | KEEP | |
| Pair-a-new-device button | KEEP | |
| Peer rows | RESHAPE | Tap target ≥ 56px; gear icon ≥ 44px (already shipped). |
| Peer row's "kind icon" (laptop/phone glyph) | KEEP | Useful at-a-glance signal. |
| Peer row latency dot | ADVANCED | The colored dot meaning "RTT < 50ms" is engineer-bait. |
| Peer row reach label ("on Wi-Fi" etc.) | KEEP | Plain language, useful. |
| "GROUPS" section + rows | KEEP | |
| "Archived" expand toggle | KEEP | |

### Conversation header (`.convo-h`)

| Element | Disposition | Notes |
|---|---|---|
| Hamburger icon (left) | KEEP | |
| Peer/group name | KEEP | |
| Verification pill (✓ verified / Verify in person) | KEEP | |
| Disappearing-msg pill (🔥) | KEEP | |
| Search box (always-visible input) | RESHAPE | Becomes a tap-to-expand icon on phone. Already partially responsive. |
| Transfer-pill ("sending N files…") | KEEP but compact | One-line on phone. |
| Group settings text button | KEEP | |
| Attach button (paperclip) | KEEP | |
| Convo-who click → device drawer | KEEP | |

### Conversation pane

| Element | Disposition | Notes |
|---|---|---|
| Message list | KEEP | |
| Message bubbles (text, files, voice, replies, reactions) | KEEP | |
| Day separators | KEEP | |
| Read-receipt ✓✓ | KEEP | Honors privacy toggle. |
| Typing banner | KEEP | |
| Inline previews (PDF/markdown/code) | RESHAPE | Collapsed-by-default on phone; user expands per-bubble. |
| Multi-select bar | KEEP | Long-press triggers it on phone. |
| Pinned messages strip | KEEP | |

### Composer

| Element | Disposition | Notes |
|---|---|---|
| Attach button | KEEP | |
| Screenshot button (camera icon) | REMOVE | iOS/Android share sheet covers this; the in-browser screenshot path is desktop-only. |
| Voice record button | KEEP | Works natively on phone. |
| Textarea | KEEP | 16px font already (prevents iOS zoom). |
| Send button | KEEP | |
| Reply-to indicator above composer | KEEP | |
| Drag-drop overlay | DESKTOP-ONLY | Phones don't have drag-drop. |

### Empty states

| Element | Disposition | Notes |
|---|---|---|
| convo-empty pane | KEEP | |
| Inbox / Sent files empty states | DESKTOP-ONLY | Whole Files pane is REMOVED on phone. |
| Folders empty state | DESKTOP-ONLY | |
| Activity empty state | ADVANCED | |

### Pairing flow / Discovery

| Element | Disposition | Notes |
|---|---|---|
| Discovery overlay (LAN device list) | KEEP | |
| Five-word transcript-bound SAS | KEEP | Authoritative verification path; compare every word and its order. |
| Numeric compatibility value | DE-EMPHASIZE | Show only for a mixed-version peer that cannot render the word protocol. |
| SAS art (visual) | KEEP | Supplementary recognition aid, never a replacement for the words. |
| Speak SAS words aloud button | KEEP | Read in order for accessibility. |
| First-pair "say hi" nudge | KEEP | |

### Settings shell

The 11-pane nav-rail collapses to a horizontal scroll bar on phone
(already shipped v0.11.0). Per-pane phone-tier behavior:

| Pane | Disposition | Notes |
|---|---|---|
| **Profile** | KEEP | Simplest, most relevant pane. Display name + bio + avatar color + identity readonly. |
| **Privacy** | RESHAPE | Keep: Trust-new-pairings toggle, Read receipts (send + display), Typing (send + display), Blocked devices list. Move passphrase row to ADVANCED (env-var driven; user can't actually edit in-app). |
| **Notifications** | RESHAPE | Keep: desktop-notif enable, sound on/off + Test, DND quiet hours. ADVANCED: notification preview toggle, notify-on-reactions toggle. |
| **Appearance** | KEEP | Just theme. Add the "Show advanced controls" toggle at the bottom. |
| **Chats** | RESHAPE | Reduce to one row: auto-pair-on-LAN toggle. The reference to "settings live on the gear" stays as a help paragraph. |
| **Network** | REMOVE | Rendezvous becomes default-on with curated list (own track item). User-edit textarea is ADVANCED on desktop, gone on phone. |
| **Storage** | RESHAPE | Keep: storage-by-chat table (read-only), default disappearing TTL select, "Save data on cellular" toggle (replaces granular bandwidth dropdown). REMOVE: download-folder text input, auto-accept extension allowlist. ADVANCED: auto-accept max size MB. |
| **Devices** | KEEP | Just the explanatory paragraph; no controls live here. |
| **Shortcuts** | REMOVE | No keyboard on phone. |
| **Advanced** | REMOVE on phone | Surface is gone entirely; the items inside are scattered into other panes' ADVANCED tiers. |
| **About** | KEEP | |

Phone settings = 7 visible panes (Profile / Privacy / Notifications /
Appearance / Chats / Storage / Devices / About) instead of 11.

### Per-device drawer

The drawer has ~8 sections currently. On phone, default surface is
~4 sections; rest behind "Show advanced" disclosure within the
drawer.

| Section | Disposition | Notes |
|---|---|---|
| Display (custom name + mute toggle) | KEEP | |
| Mute-with-duration picker | KEEP | |
| Chat wallpaper picker | KEEP | |
| Chat tools (export / clear / media gallery) | KEEP | |
| Disappearing messages | KEEP | |
| Capability toggle grid (chat/files/folders/groups granular) | RESHAPE | Collapse to a single "Allow everything" toggle with a "Customize" expander that reveals the grid. |
| Reachability rows: Connection, Latency, Last seen, Address | ADVANCED | Engineer info; collapse under "Connection details" disclosure. |
| Identity & trust (fingerprint, SAS, SAS art, speaker icon) | KEEP | Critical for verification. |
| Verified in person section | KEEP | |
| Trust history timeline | ADVANCED | |
| Key-change banner (when present) | KEEP | Critical security signal; never hidden. |
| Trust actions (Unpair, Block) | KEEP | |

### Group settings drawer

| Section | Disposition | Notes |
|---|---|---|
| Name (rename) | KEEP | |
| Avatar color | KEEP | |
| Members list + role pickers | KEEP | |
| Add someone | KEEP | |
| Mute group | KEEP | |
| Invite link | KEEP | |
| Chat tools (export / clear) | KEEP | |
| Archive | KEEP | |
| Leave group | KEEP | |

(Group surface is already pretty trimmed; no phone-specific cuts.)

### Diagnostics modal

| Element | Disposition |
|---|---|
| Whole modal | ADVANCED on phone |
| Run health check button | ADVANCED |
| Clear log button | ADVANCED |
| Severity filter dropdown | ADVANCED |
| Error log list | ADVANCED |

Phone access path: long-press the version number in About →
diagnostics opens. (Easter-egg style.) NOT in any visible button
chain on phone default tier.

### Activity feed pane

| Element | Disposition |
|---|---|
| Whole pane | ADVANCED on phone |
| Mesh summary tiles (4 clickable counters) | ADVANCED |
| Filter chips row | DESKTOP-ONLY (entire row, not just on phone) — phone Activity is unfiltered chronological |
| Event list | KEEP (but only when the pane is opened via Advanced reveal) |

### Modals (general behavior)

All modals on phone:
- Width: `100vw` (or `96vw` for narrow ones)
- Height: `100vh` for shell-style modals (Settings, Diagnostics)
- Border-radius: 0 for shell modals (true full-screen feel)
- Border-radius: 14px for transient modals (Confirm dialogs)
- Padding: tighter (16px instead of 32px)

Already partially shipped in v0.14.0. The `.modal.settings-shell`
overrides cover settings; need to extend to other deep modals
(group-settings-backdrop, device-backdrop, debug-backdrop).

---

## Surface count summary

|   | Desktop | Phone (default) | Phone (advanced revealed) |
|---|---|---|---|
| Pane tabs | 4 | 1 | 2 |
| Visible settings panes | 11 | 7 | 11 |
| Visible settings rows | ~40 | ~18 | ~40 |
| Device drawer sections | ~8 | ~4 | ~8 |

The default phone surface is roughly 50% of the desktop surface.
The "Show advanced" path remains, but is a deliberate choice the
user makes, not the default.

---

## "Show advanced" reveal UX

A single toggle at the bottom of the **Profile** pane:

```
┌──────────────────────────────────────┐
│ Show advanced controls         [ ○ ] │
│ Reveals power-user surfaces across   │
│ all settings panes + drawers. Off    │
│ by default; resets when you close    │
│ the app.                             │
└──────────────────────────────────────┘
```

Toggle behavior:
- Adds `show-advanced` class to `<html>` (CSS reveals all
  `[data-tier="advanced"]` items).
- NOT persisted across tab close (per-session) so phone users don't
  end up with a sprawl they didn't actively choose.
- On desktop, the toggle defaults to ON and persists. Same toggle,
  different default + persistence, configured in init() based on
  form-factor.

Each pane that has hidden items gets a subtle hint at the bottom in
the default tier:

```
3 advanced controls hidden. [Show]
```

Tapping the hint flips the toggle. Single-source-of-truth: there's
ONE toggle; the per-pane hints are just shortcuts to it.

---

## Pair flow — phone-specific simplification

The current pair flow shows 6 SAS digits prominently. On phone, the
visual SAS art (already shipped) becomes the primary; digits sit
under it as accessibility fallback.

The "Verify in person" step:

**Desktop today:**
> Compare the SAS above with the same value on the other device.
> Face-to-face, on a call, or by reading it aloud.

**Phone phrasing:**
> Both screens should show the same row of icons. Match? [Yes] [No]

The icon row is the existing SAS art. Yes → mark verified + close.
No → "Try again later. Don't pair until you can confirm in person."

This implements the "Hide the engine" principle: the user verifies
*the same thing*, expressed in human-readable form. Hexadecimal
digits are still there for accessibility / power-user / phone-call
audio confirmation.

---

## Adaptive typography + spacing

Beyond visibility, on phone:

- Base font-size 16px (prevents iOS zoom-on-focus on inputs).
- Line-height 1.5 minimum for body copy.
- Touch target minimum 44x44px on every actionable element.
- Composer sticky-bottom, never above the keyboard (use
  `env(safe-area-inset-bottom)` for notched phones).
- Scroll-restore on pane-switch (when a phone user re-opens the
  app, the conversation is at its last scroll position, not at
  the bottom).

---

## Tests that pin the phone tier

Every disposition above gets a regression test in
`tests/test_phone_tier_v0142.py`:

```python
def test_files_pane_tab_marked_desktop_only(index_html):
    """Files tab in pane-tabs must carry desktop-only so it
    disappears on phone form-factor."""
    idx = index_html.find('data-pane="files"')
    snippet = index_html[idx:idx + 200]
    assert "desktop-only" in snippet

def test_log_verbosity_marked_desktop_only(index_html):
    """Log level dropdown is engineer-bait on phone; pin
    desktop-only so a refactor can't accidentally show it."""
    idx = index_html.find('id="set-log-level"')
    # walk up to the closest container, assert desktop-only
    ...

def test_diagnostics_modal_marked_advanced(index_html):
    ...

def test_show_advanced_toggle_in_profile(index_html):
    ...

def test_form_factor_set_at_boot(index_html):
    """JS must set data-form-factor on <html> at script-load."""
    assert "data-form-factor" in index_html
    assert "function _detectFormFactor" in index_html

def test_advanced_toggle_resets_on_tab_close(index_html):
    """The toggle is per-session on phone; pin the absence of
    persistence calls in the toggle handler."""
    ...
```

A separate test file because phone-tier work is large enough to
warrant its own regression suite + so the file name signals
"this is the phone-tier contract" to future contributors.

---

## Ship sequence

The phone tier work is not a single ship; it's a progression. The
order matters because earlier ships add the mechanism, later ships
populate it.

### v0.14.2 — Phone tier foundation (immediate next ship)

**Mechanism only.** Adds the layer-1 + layer-2 plumbing without
touching the visibility of any specific element yet.

- `_detectFormFactor()` JS function + `data-form-factor` attribute
  on `<html>` set at boot, re-evaluated on debounced resize.
- CSS rules:
  - `html[data-form-factor="phone"] .desktop-only { display: none !important; }`
  - `html[data-form-factor="phone"] [data-tier="advanced"] { display: none; }`
  - `html.show-advanced [data-tier="advanced"] { display: revert !important; }`
- `state.tier` field; "Show advanced controls" toggle in Profile
  pane that flips it.
- Per-pane "N advanced controls hidden. [Show]" hint helper.
- Tests pin: form-factor detection, the three CSS rules, the
  Profile toggle, the per-session reset behavior.

After this ship, the phone form-factor is detectable + the reveal
mechanism exists, but no element is yet tagged. **The desktop
experience is unchanged.** Phone users see the same surface as
before (identical to v0.14.1).

### v0.14.3 — Cut Files / Folders / Activity tabs on phone

Add `class="desktop-only"` to:
- `[data-pane="files"]` button + the entire `#files-panel` aside.
- `[data-pane="folders"]` button + the entire `#folders-panel` aside.
- `[data-pane="mesh"]` button gets `data-tier="advanced"` (phone
  users with Show Advanced on can still reach Activity).

Tests pin every removed element. Visual regression: the pane-tab
bar on phone shows just "Chat."

### v0.14.4 — Cut power-user settings rows on phone

Tag with `data-tier="advanced"` or `class="desktop-only"`:
- Network pane (whole pane is desktop-only).
- Shortcuts pane (whole pane is desktop-only).
- Advanced pane (whole pane is desktop-only).
- Storage pane: log-level dropdown wasn't there but the
  download-folder input goes desktop-only, the granular
  bandwidth dropdown becomes "Save data on cellular" toggle,
  auto-accept extensions input goes desktop-only.
- Privacy pane: passphrase row → advanced.
- Notifications pane: notification-preview toggle + notify-on-
  reactions toggle → advanced.

Tests pin which specific input IDs are tagged what.

### v0.14.5 — Trim per-device drawer on phone

- Reachability rows wrapped in a "Connection details" disclosure
  that collapses by default; expand-toggle is keep but the rows
  inside are advanced.
- Capability toggle grid wrapped in "Customize" disclosure;
  default is the single "Allow everything" toggle.
- Trust history toggle: keep, but rows inside marked advanced.

### v0.14.6 — Composer + drag-drop trim

- Drag-drop overlay → desktop-only.
- Screenshot button → desktop-only.
- Composer respects `safe-area-inset-bottom` on phones.
- Scroll-restore on pane-switch.

### v0.14.7 — Phone-friendly pair flow

- Promote SAS art above SAS digits on phone form-factor.
- "Match? [Yes] [No]" framing on phone.
- "Verify in person" hint copy adjusted per form-factor.

### v0.14.8 — Phone diagnostics escape hatch

- Long-press the version number in About → diagnostics opens.
- "Diagnostics" button in Advanced settings (when user reveals).
- The Ctrl+Shift+D global shortcut stays desktop-only (no Ctrl on
  phone anyway).

After v0.14.8 the phone tier is feature-complete. Subsequent ships
are normal feature work that respect the established patterns.

---

## Edge cases + open questions

These are deferred, documented here so they don't get re-raised.

1. **Tablet form factor.** Currently treats tablet as `default`
   tier (same as phone). iPad-in-landscape with a hardware
   keyboard might want desktop tier. Open question: do we offer a
   form-factor override, or detect keyboard presence? Defer until
   we have actual tablet user reports.

2. **Multi-window phone (foldables).** Unknown. Probably treats
   the smaller half as phone. The CSS doesn't break; the question
   is whether we want different behavior. Defer.

3. **The Activity tab disposition.** I marked it ADVANCED. An
   argument exists that it should be REMOVE entirely on phone
   (most phone users will never want a chronological timeline of
   trust events + transfers + key changes). Compromise: ADVANCED
   for v0.14.3, but if no user opens it via Show Advanced after
   3 months in production telemetry... wait, we don't do telemetry.
   So we'll just ask in user interviews.

4. **The hamburger button on phone.** When no peer is selected,
   it's in the top header. When a peer IS selected, it's in the
   convo header. On a folded phone (very narrow), is one of them
   redundant? Defer.

5. **Per-tier defaults that conflict.** A user on desktop with
   advanced ON, who opens the same identity on a phone (after
   v1.0.0 multi-device-per-identity), inherits the chat-prefs.
   Should the phone start in default tier despite the persisted
   `tier="advanced"` from desktop? **Yes.** Form-factor wins over
   persisted preference. The toggle on phone reflects current
   session state, not the synced state. On desktop, the toggle
   reflects synced state. Document this in code; pin in tests.

6. **The "Show advanced" toggle's discoverability.** On phone, it
   lives at the bottom of Profile. Users who don't scroll Profile
   will never see it. The per-pane "N advanced controls hidden.
   [Show]" hints are the discoverability path. Verify in
   first-run usability that users actually find them.

7. **Accessibility regression risk.** Hiding an element at the
   visual layer (`display: none`) also hides it from screen
   readers. This is correct for our use case (a screen-reader
   user on phone shouldn't have to skip past 40 controls they
   can't reach), but document so we don't make a different
   accessibility choice later.

8. **The CSS `!important` on `.desktop-only`.** Necessary because
   inline `style=""` overrides without it. The whole project
   minimizes `!important` usage; this one is justified.

---

## Definition of "done" for the phone tier

The phone tier is complete (v0.14.8 ships) when:

1. Every UI element above is dispositioned + tagged.
2. Every disposition has a regression test in
   `tests/test_phone_tier_v01_*.py`.
3. A phone user (~360px wide, touch-only) can complete the
   following journey without seeing a single piece of jargon or
   advanced control:
   - Install (PWA add-to-home from v0.15.0+; until then, browse
     the URL).
   - Pair with another device (visual SAS confirmation).
   - Send + receive messages.
   - Send + receive a file.
   - Set a disappearing-msg TTL on a conversation.
   - Mute a conversation.
   - Set a profile name + avatar color.
   - Block a peer.
   - Leave a group.
   - Verify a peer in person.
4. The same user, after toggling "Show advanced controls,"
   can reach every feature available on desktop.
5. On rotation / browser resize, the form-factor re-detects
   without UI flicker beyond a single 250ms debounce window.

---

## Audit reminder

Per `PRINCIPLES.md`, every quarter:

1. Re-read this document. Anything that drifted?
2. Pick one element marked ADVANCED. Has anyone needed it on
   phone? If yes, promote to default. If no, consider promoting
   to REMOVE.
3. Look for new desktop features added since last audit. Are
   they tagged correctly? File a debt ticket if not.

The phone tier is a contract with phone users that the surface
they see is the surface they need. That contract erodes silently
unless someone actively maintains it.
