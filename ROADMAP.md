# One Link — The Road to Flawless

**Last updated:** 2026-05-24

> The engineering-deep roadmap lives at [`docs/ROADMAP.md`](docs/ROADMAP.md).
> This document is the user-facing one: what "done" looks like, how we
> know when we've gotten there, and what's standing between us and that.

## The vision

One Link is **for the people**. That means:

- **It just works.** A normal human installs it, pairs their phone and
  laptop, and starts sending messages and files. No terminal, no setup
  wizard with 12 steps, no "first install the cert profile then trust it
  in Settings then…" Just works.

- **It works on every device they have.** Windows, Mac, Linux, iPhone,
  Android. Same identity. Same conversations. Same files. Everything
  syncs without a thought.

- **Nobody can take it away from them.** No company that can be sold,
  shut down, subpoenaed, or pressured. No account that can be banned.
  No cloud server holding their stuff. It works as long as they own
  the devices it runs on.

- **It's accessible to actual humans.** Not just engineers. Not just
  English speakers. Not just sighted people. Not just people on fast
  reliable internet.

## The "we got there" test

We are done when **a non-technical friend of yours** can:

1. Open the One Link website on their phone or laptop
2. Download the app for their device
3. Open it, see a QR code
4. Open it on their second device, scan
5. Type a message, hit send, see it arrive
6. Send a photo, see it arrive

…and the **total time is under 5 minutes**, they don't need to ask
anyone for help, and 6 months later it still works without any
maintenance.

If that test passes for any device combination on any reasonable
network in any language, we're done.

---

## Where we are right now (2026-05-24)

| Capability | Desktop | iOS Safari | Android | Notes |
|---|---|---|---|---|
| Install + run | ✅ Win/Mac/Linux binaries | ✅ via Safari + cert profile | ⚠️ via Chrome + cert workaround | Native iOS/Android apps not built |
| Pair devices | ✅ | ✅ | ⚠️ untested | Tonight: fixed cert chain, ALPN, single-pane UI, cert relogin |
| Auto-reconnect after restart | ✅ | ✅ | ⚠️ should work, untested | Cert-authed relogin |
| Text chat (send + receive) | ✅ | ✅ | ⚠️ untested | Phone has compose |
| Edit / delete / react | ✅ | ✅ | ❌ | Phone direct-chat edit/delete/react shipped |
| Reply / threads | ✅ | ✅ | ❌ | Phone direct-chat reply shipped |
| Search messages | ✅ | ✅ | ⚠️ untested | Phone direct-chat, group, and global search shipped; Android untested |
| Groups | ✅ | partial | ❌ | Phone can see groups, send messages, react/edit/delete own messages, copy invites, add/remove members, and leave; accepting invite links on phone still missing |
| File send | ✅ | ✅ | ⚠️ untested | Tonight: chunked 16 KiB, backpressure |
| File receive (inline render) | ✅ | ✅ | ⚠️ untested | Phone renders inbound attachments inline with download |
| Big files (>100MB, resume) | ✅ | ⚠️ chunked but untested at scale | ⚠️ untested | |
| Folders (bidirectional sync) | ✅ | ❌ | ❌ | |
| Voice calls | ✅ | ❌ | ❌ | Living Presence on desktop only |
| Video calls | ✅ | ❌ | ❌ | |
| Peer roster mgmt (rename/mute) | ✅ | ✅ | ⚠️ untested | Desktop now surfaces paired phone in the identity sidebar; stale generic phone rows are deduped in UI |
| Settings + sign out | ✅ | ✅ | ⚠️ untested | |
| Notifications | ✅ | ❌ Safari can't do background | ⚠️ depends on browser | Need native app for true notifications |
| Recovery from lost devices | partial | ❌ | ❌ | 24-word recovery phrase exists in CLI + first-launch desktop UX; restore UX is CLI-only |
| Packaged artifact parity | partial | n/a | n/a | Source has the fixes; every public tarball/installer must be rebuilt from current source and smoke-tested |
| i18n (non-English) | ❌ | ❌ | ❌ | English only |
| Screen reader support | partial | partial | partial | Audited tonight; need full sweep |
| Works on captive portal Wi-Fi | partial | partial | untested | |
| Works on cell data | depends | depends | untested | LAN-only default |
| Works through symmetric NAT | partial | partial | untested | TURN relay not always reliable |
| Works in censorship-heavy regions | ⚠️ obfs transport code exists, not wired | ❌ | ❌ | |

Bottom line: **desktop is largely there. Phone is ~70%. Network resilience
and accessibility need work. Recovery story is missing.**

---

## The phases

Each phase has a concrete "done when" gate. Not "implement feature X" —
"a user can do Y end-to-end."

### Phase A — Foundation rock-solid

**Goal:** the pair-and-chat-and-send-a-file path works first time, every
time, with no UX cliffs.

**Done when:**
- [ ] A cold install on Windows → opens UI → pairs a phone → sends a
  message → sends a file → all under 60 seconds, repeated 10 times in
  a row, zero errors.
- [ ] Same flow on Mac. Same on Linux.
- [ ] Daemon restart does not require any user action on the phone
  (cert relogin restores the link automatically). ✅ shipped tonight.
- [ ] All cards single-pane (no stacking). ✅ shipped tonight.
- [ ] Browser cache never serves stale UI (ETag + must-revalidate).
  ✅ shipped tonight.
- [ ] File send completes for any file under 100 MB without killing
  the DataChannel. ✅ shipped tonight (needs user retest).
- [ ] File **receive** on the phone renders inline with a download
  button. ✅ shipped tonight.
- [ ] The packaged artifact is provably built from current source,
  includes every dynamic module and data file, and passes the same
  pairing/chat/file smoke tests as source-run daemon.

### Phase B — Phone is a real first-class device

**Goal:** every text-chat thing the desktop can do, the phone can do
too. Phone is not a thin read-only window.

**Done when:**
- [ ] Phone can edit, delete, react to messages. ✅ direct-chat
  surfaces shipped.
- [ ] Phone can reply / quote / start threads. ✅ direct-chat reply
  shipped.
- [ ] Phone can search the chat history. ✅ direct-chat, group, and
  global cross-app search shipped.
- [ ] Phone can join + see group chats. partial: roster, message
  read/send, reactions, own-message edit/delete, invite copy,
  add/remove members, and leave shipped; accepting group invite links
  on phone still missing.
- [ ] Phone can render inbound file attachments (image preview, video
  preview, file icon + name + download for everything else).
- [ ] Phone can manage folders (see shared folders, sync state).
- [ ] Phone receive notifications when a message arrives (browser
  notification API where available; needs native app for true
  background).

### Phase C — Voice and video calls everywhere

**Goal:** the Living Presence call from the README is real on every
device.

**Done when:**
- [ ] Desktop ↔ desktop voice call: rings, connects, audio flows,
  hangs up cleanly. Works on flaky Wi-Fi (graceful degrade to voice
  note + resume).
- [ ] Desktop ↔ phone voice call.
- [ ] Phone ↔ phone voice call.
- [ ] Same matrix for video.
- [ ] Tier ζ semantic codec wired in for low-bandwidth scenarios.

### Phase D — Identity sovereignty for normal humans

**Goal:** if your devices burn down, you don't lose your identity. If
your key is compromised, you can rotate. If you don't know what a
private key is, you still don't lose anything.

**Done when:**
- [ ] First-launch UX shows a recovery phrase, with clear "write this
  down, we cannot recover it for you" copy. ✅ desktop now shows the
  local 24-word BIP-39 phrase during recovery setup.
- [ ] "Recover from phrase" flow exists on every install path.
- [ ] Key rotation: a user can declare "my old key is compromised,
  here is my new one" and existing trust relationships migrate.
- [ ] Multi-root: a user can run separate identities (work / personal)
  on the same device.
- [ ] Plain-English docs explain how this works without crypto jargon.

### Phase E — Network resilience (works anywhere on Earth)

**Goal:** the "anyone anywhere" claim is real. Doesn't matter if
they're on hotel Wi-Fi behind a captive portal, on a mobile network
with carrier-grade NAT, or in a country that throttles VPNs.

**Done when:**
- [ ] Captive portal detection + clear guidance to the user.
- [ ] Symmetric NAT traversal works via federated TURN relays.
- [ ] IPv6-only networks work.
- [ ] Switching from Wi-Fi to cell data and back keeps sessions alive.
- [ ] Long offline periods: messages and files queue, deliver when
  recipient comes back online.
- [ ] Obfs transport wired into the transport selector so One Link
  traffic doesn't look like One Link on hostile networks.
- [ ] Tor support as an optional transport.

### Phase F — Real installers + native phone apps

**Goal:** the README's "double-click `one-link`" should mean *actually*
double-click. No terminal. No "Right-click → Open to bypass Gatekeeper."
On phone, an app icon you tap, not a Safari bookmark.

**Done when:**
- [ ] Release pipeline rebuilds from a clean checkout and refuses to
  publish if the packaged binary is missing source modules, data
  files, or the current `ROADMAP.md`/version identity.
- [ ] Windows: code-signed `.exe` installer, no SmartScreen warning.
- [ ] macOS: notarized `.dmg`, opens cleanly.
- [ ] Linux: `.AppImage`, `.deb`, `.rpm`, and Flathub package.
- [ ] Android: app on F-Droid (sovereign). Play Store secondary.
- [ ] iOS: TestFlight build for sideloaders; AltStore-friendly. App
  Store as a separate question — Apple's gatekeeping is in tension
  with the project's sovereignty stance.
- [ ] All installers verifiable in 30 seconds (Sigstore + SLSA already
  in place; just needs one-line copy-paste verify command in the
  docs).

### Phase G — Accessibility + internationalization

**Goal:** "for the people" includes people who don't read English, who
use screen readers, who navigate with the keyboard, who are color blind,
who need larger text.

**Done when:**
- [ ] Every action reachable via keyboard alone.
- [ ] Every input + control has an accessible label (audited tonight
  for the new phone controls; need to sweep the rest).
- [ ] Screen reader smoke-test passes (VoiceOver on macOS/iOS,
  NVDA on Windows, TalkBack on Android).
- [ ] High-contrast and reduced-motion modes respected.
- [ ] Font scaling doesn't break layouts.
- [ ] Color-blind safe palettes (no information conveyed by color
  alone).
- [ ] String externalization (i18n).
- [ ] Top 10 languages translated (community-driven).
- [ ] RTL layout support for Arabic / Hebrew / etc.

### Phase H — Documentation for humans

**Goal:** a curious non-engineer can read 3 pages and understand what
One Link is, what it does, what's safe about it, and how to use it.

**Done when:**
- [ ] One-page "What is One Link" explainer (plain English, no jargon).
- [ ] One-page "How your data moves" diagram (what travels where, what
  the rendezvous nodes see vs. don't, what's encrypted to whom).
- [ ] One-page "Verify this install is real" guide (copy-paste a
  command, see a green check).
- [ ] One-page "I lost my devices" recovery guide.
- [ ] A "Why should I trust this?" page that doesn't say "trust us" —
  shows the verifiable evidence (signed releases, audit trail, open
  source, no central server).
- [ ] All translated.

### Phase I — Permanence (cannot be captured)

**Goal:** One Link survives if the original maintainer disappears,
gets pressured, gets bought (refused, but the offer alone is leverage),
or just stops caring. Like Bitcoin survived Satoshi vanishing.

**Done when:**
- [ ] Multiple rendezvous nodes operated by independent people, with
  no default that's run by the original maintainer alone.
- [ ] Release mirrors beyond GitHub (IPFS, Tor mirror, multiple Git
  remotes).
- [ ] Reproducible builds verifiable by anyone with no special
  toolchain.
- [ ] Multi-maintainer signing threshold for releases (already
  documented in [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md); needs to
  actually have multiple maintainers).
- [ ] Documented succession plan: what happens if the lead maintainer
  goes away.
- [ ] License + trademark structure that prevents acquisition or
  rebranding (AGPLv3 + non-profit-only trademark already in place).
- [ ] Active community / contributor pipeline so the project isn't
  one-person-deep.

---

## Right-now priorities (next session or two)

In order:

1. ✅ **Confirm tonight's file-send fix actually delivers** on a real
   phone → laptop test. Source fix shipped: 16 KiB chunks,
   backpressure, and DataChannel auto-reconnect. Still worth one
   human retest on the actual iPhone before closing the Phase A gate.
2. ✅ **Phone file RECEIVE.** Inline rendering of inbound file
   attachments + download button shipped.
3. ✅ **Clean up the identity/device surface.** Paired phone now appears
   in the desktop sidebar, stale generic browser duplicates are deduped,
   and non-local stale rows can be pruned from the sidebar or full
   device list.
4. **Walk the cold-install pair flow with a stopwatch.** Find every
   second between "user opens the app" and "first message arrives."
   Fix every speed bump. (Phase A gate.)
5. **Packaged artifact parity gate.** Rebuild from current source,
   inspect the generated bundle manifest, then run packaged binary
   smoke tests for version, recovery routes, `/peer` ETag/cache
   headers, TLS cert chain, ALPN, pair, phone send, and phone file
   transfer. This is the fix for the stale tarball class of bug:
   source green is not enough for public release. Static + optional
   live validator now exists at `scripts/validate_packaged_artifact.py`;
   static parity passes against a rebuilt Windows onedir binary, and
   live packaged-daemon probes now pass for `/peer`, recovery routes,
   TLS two-cert chain, and ALPN `http/1.1`. Remaining work is packaged
   end-to-end pair, phone send, and phone file-transfer probes.
6. **Phone group invite acceptance.** Phone can now see group
   roster/messages, send group messages, react, edit/delete its own
   group messages, copy invites, add/remove members, and leave.
   Remaining Phase B group work is accepting/importing a group invite
   link directly on the phone.
   Direct-chat, group, and global search plus reactions, edit, delete,
   and reply shipped in source.
7. ✅ **Recovery phrase at first launch.** Desktop setup now displays
   the local 24-word recovery phrase and requires explicit confirmation.
   Remaining Phase D work is restore UX outside the CLI, key rotation,
   and multi-root.
8. **Phase C calls** — substantial standalone work. Probably the
   single most user-visible feature still missing on the phone.

---

## How we'll know we got there

We're done when:

- Anyone — your grandmother, your friend in a country with bad
  internet, your friend who's blind, your friend who speaks no English
  — can install One Link on their phone and laptop in under 5 minutes
  and have it work.
- All the rows in the capability table above are ✅ on every column.
- Three people who aren't you have read the docs and can explain to
  someone else what One Link is.
- The project survives a year of you not touching it.
- It's been adopted by groups who need it (journalists, activists,
  families, small teams) and they've been using it without complaint.

That's the finish line. The rest of the road is in the phases above.

---

## Living document

This is meant to be edited. When something ships, check it off. When a
new gap surfaces, add it. When a phase completes, archive its
"done when" list as evidence. The point is to know where we are,
without rose-tinted glasses.
