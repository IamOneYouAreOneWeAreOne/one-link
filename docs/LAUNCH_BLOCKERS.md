# Launch blockers — items that need YOU

This is the honest list of what's left before launch that I (the
codebase) can't fix on my own. Some need money. Some need accounts.
Some need a human on a fresh machine. None are surprises — they're
the things you'd hit on day one of public launch and wish you'd
done first.

## Hard blockers (loss of first-time-user trust)

### 1. Windows code-signing certificate

**Why this matters:** Every Windows first-time user sees a
SmartScreen warning ("Windows protected your PC") on the unsigned
`.exe`. A normal user reads that as "this might be malware" and
closes the dialog. You lose ~30% of installs at this gate.

**The website's SmartScreen guidance already exists** (good!), but
it's a workaround, not a fix. Real fix: sign the binary so the
warning never appears.

**What you need:**
- An EV code-signing certificate ($300–$700/year from
  DigiCert / Sectigo / Comodo). Standard OV certs ($200/year)
  reduce but don't eliminate the warning.
- `signtool.exe` in the release workflow (`.github/workflows/
  reproducible_release.yml`).
- The cert's private key stored as a GitHub Actions secret
  (`WINDOWS_CODE_SIGN_PFX` + passphrase).

**Workflow change needed in `reproducible_release.yml`:** after
the `build_windows_binary` step, add a `signtool sign /f
$WINDOWS_PFX /p $WINDOWS_PFX_PASS /tr http://timestamp.digicert.com
/td sha256 /fd sha256 dist/one-link.exe` step.

---

### 2. macOS notarization

**Why this matters:** Every macOS first-time user sees Gatekeeper
("cannot be opened because the developer cannot be verified"). The
right-click-Open workaround exists on the website but the
unverified-developer line still reads as "malware" to non-technical
users.

**What you need:**
- Apple Developer Program membership ($99/year).
- A Developer ID Application certificate exported as `.p12`.
- Notarytool credentials (Apple ID + app-specific password).
- The `.dmg` build path in `release.yml` extended with
  `codesign --deep --sign "Developer ID Application: ..." --options
  runtime` + `xcrun notarytool submit ... --wait` + `xcrun stapler
  staple`.

---

### 3. Android testing — `⚠️ untested` everywhere

**Why this matters:** The ROADMAP capability table marks
Android `⚠️ untested` for literally every feature. We don't
actually know if it works. Could be 100% functional, could be
totally broken. Shipping with "untested on Android" in the
capability table is shipping on Hope.

**What you need:**
- An Android device or emulator (Android Studio + AVD).
- 30 minutes to walk: install → pair with a desktop daemon → send
  a message → send a photo → voice call attempt.
- Update the ROADMAP table with the actual `✅` / `⚠️` /
  `❌` per cell based on what you saw.
- Likely outcome: some subset works, some doesn't. Document
  what works in the website's download page so users have
  honest expectations.

---

### 4. Website: meta-description vs reality mismatch (P0)

**Why this matters:** The homepage's meta description claims
"Works on Windows, macOS, Linux, Android, iOS" but the
download page (correctly) says "Windows + Linux ship today."
A user finding One Link via search engines sees the meta
description first and tries to download for their Mac, then
hits the honest "in flight" status. First-impression damage.

**Where:** `weareone-link.org` repo, paths approximately:
- `content/weareone-link.org/index.cl` — homepage meta + hero
- `content/weareone-link.org/download/index.cl` — download page
- `content/weareone-link.org/features/index.cl` — features list

**What to change (audit findings from 2026-05-25):**

  | File:Line | Current | Suggested |
  |---|---|---|
  | `/index.html` (meta description) | "Works on Windows, macOS, Linux, Android, iOS" | "Works on Windows and Linux today. macOS, Android, iOS coming soon." |
  | `/features/index.html:93–95` | "Voice and video calls" unqualified | Add "(Desktop only today)" |
  | `/features/index.html:98–99` | "Shared folders" unqualified | Add "(Desktop only today)" |
  | `/download/index.html:56` | "Detecting your device..." placeholder visible on load | Pre-detect or show a minimal spinner |
  | `/download/index.html:177, 241` | "ML-DSA-65 pending (lands v0.22)" | "Coming in next release" (no version pin in user copy) |
  | `/features/index.html:167` | "What lands in v0.22" header | "What lands next" (no version pin) |
  | `/features/index.html:186` | "Last reviewed 2026-05-19" visible mid-page | Move to footer, or drop |
  | `/index.html:54` | Schema.org `operatingSystem: "Windows, macOS, Linux, Android, iOS"` | `"Windows, Linux"` (matches reality) |
  | `/roadmap/index.html:250–280` | "Will not build" section uses negative framing | Reframe as "What One Link stays focused on" |

These are website-repo edits, not daemon-repo. Tackle in a
separate session against `C:\Users\Josh\Projects\One_link_Website\`.

---

### 5. Real human cold-install walk on each OS

**Why this matters:** I (the codebase) measure cold-install
stopwatch at 8 seconds on a dev box. I don't know what a real
non-technical user sees on a fresh Windows machine that's
never had One Link installed:
- Does the download from GitHub actually land where they
  expect?
- Does SmartScreen scare them off, or do they read the
  guidance?
- Does the daemon start cleanly, or does the antivirus
  quarantine it?
- Does the system tray icon appear, or get hidden in the
  overflow tray?
- Does the browser tab open automatically, or do they have
  to find the URL?
- Does pairing actually work via QR, or is the QR too small
  / too dim / cropped?

**What you need:**
- A clean Windows VM or borrowed laptop.
- 30 minutes to walk through with a stopwatch.
- A clean macOS device or VM (if you want to test Mac before
  fix #2 lands).
- Notes on every place you had to think, wait, or guess.

---

## Soft blockers (launchable without, but better with)

### 6. Production telemetry / crash reporting

Right now, you find out about field failures only when users
explicitly click "Copy error report" + paste it into a GitHub
issue. That's a high-friction reporting path; most users won't
do it. A small opt-in crash beacon (anonymized hash of the
exception + version + OS) would surface 10x more bugs.

**Options:**
- Self-host (POST to a daemon endpoint you control) — preserves
  sovereignty, requires running infra.
- Sentry (paid past small free tier) — fastest to set up, adds
  a third-party dependency for error data.

### 7. Localization

ROADMAP says English-only. The codebase has zero i18n
infrastructure (no `i18next`, no message catalogs, no
`{{translate}}` patterns). For an international launch, even a
"Spanish + Portuguese + Mandarin" pass would 10x the addressable
audience.

### 8. Accessibility full sweep

Some ARIA labels exist, some don't. No screen-reader walk has
been done. No keyboard-only navigation test. No high-contrast
mode validation. This is a category of work I can do part of
(I'll do a quick pass in this session) but a real a11y audit
needs human review.

### 9. Group invite acceptance on phone

Last Phase B gap per ROADMAP. Phone can see groups, send/edit/
react/delete in groups, manage members, copy invites, leave —
but cannot ACCEPT an invite link directly on the phone. Workaround:
accept on desktop first. Phone-side acceptance closes Phase B.

---

## Recommendation: soft launch first

Items 1, 2, 4, 5 are real blockers that will damage first
impressions. Item 3 is unknown territory. Items 6–9 are
nice-to-have.

The lowest-risk path to a real launch:

1. **Fix #4 (website mismatch)** — 1-2 hours in the website repo.
2. **Do #5 (cold-install walk)** on Windows + your own Mac — 1-2 hours.
3. **Soft launch** to 10-20 friends/family. Tell them it's early
   access. Watch what breaks. Fix it. Re-launch broader after a
   week with confidence in the install path.
4. **Pursue #1 + #2 in parallel** — code-signing has a long lead
   time (cert validation can take a week+), notarization has a
   shorter one (Apple is same-day once you have the account).
5. **#3 (Android)** can wait until #1 + #2 are done — there's no
   point announcing Android support if you have to walk users
   through Chrome's cert workaround anyway.

The point of this list is to make the unfixable-by-me visible.
None of it is a surprise. All of it is actionable.
