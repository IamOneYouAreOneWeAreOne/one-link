# One Link Roadmap

Status: living document. Updated as releases ship.
Last updated: 2026-05-08.

This roadmap is gated by [`PRINCIPLES.md`](./PRINCIPLES.md). Every
unfinished ship below has been (or will be) restated against the
ship-gate checklist before code lands. Items that don't pass all
four principles aren't on this list.

Companion docs (the project's plan-of-record at every layer):

- [`PRINCIPLES.md`](./PRINCIPLES.md) — the **five** operating
  principles + ship-gate checklist (Reach / Hide / Async / Depth
  / Defang). The gate every ship passes.
- [`PHONE_TIER.md`](./PHONE_TIER.md) — exhaustive phone-tier
  implementation guide. Every UI surface dispositioned, full ship
  sequence v0.14.2 → v0.14.8.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — implementation-grade
  architectural specification for the v0.15.0 → v1.0.0 PWA pivot.
  Each ship gets frontier, primitive, wire-format additions, state
  migration, test contract, defang cross-reference, and
  Coherence-stdlib reuse callouts.
- [`SOVEREIGNTY.md`](./SOVEREIGNTY.md) — corporate-substrate
  defang specification. Full mapping of every layer (browser,
  DNS, CDN, push, keychain, RNG, etc.) → mitigation. Three
  paranoia tiers (Default / Hardened / Air-gap) with exact
  behavioral matrix.
- [`SECURITY.md`](./SECURITY.md) — threat model + hardening
  contract. Nine adversary classes with countermeasures.
  Cryptographic correctness (constant-time, nonce uniqueness,
  forward secrecy, post-compromise, post-quantum hybrid).
  Runtime hardening (CSP, Trusted Types, worker isolation,
  sensitive material lifecycle).
- [`GOVERNANCE.md`](./GOVERNANCE.md) — license (AGPLv3),
  trademark (non-profit only), release signing (multi-maintainer
  threshold), refuse-acquisition charter, warrant canary,
  funding posture. Project structure as security primitive.

Read order for someone joining cold:
1. `PRINCIPLES.md` — what gates ships.
2. `ROADMAP.md` (this file) — what ships in what order.
3. `ARCHITECTURE.md` — how the PWA pivot is built.
4. `SOVEREIGNTY.md` + `SECURITY.md` — the defenses, paired.
5. `GOVERNANCE.md` — the structural commitments.
6. `PHONE_TIER.md` — the phone-specific surface contract.

The reorganization from earlier roadmaps groups remaining work
under three tracks instead of tiers. Tiers were "what the protocol
needs"; tracks are "what the user gets." North stars steer the
tracks; the four principles gate every ship.

---

## What's already shipped (post-Tier audit, 2026-05-08)

The original Tier 1–3 plan from the v0.7.2 audit is essentially
complete. Tier 4 is barely started.

**Tier 1 — chat fundamentals: ✅ COMPLETE**
- v0.7.3 per-device drawer + settings split
- v0.7.4 transfer resume-on-reconnect
- v0.7.5 reply / quote + reactions
- v0.7.6 edit / delete + read receipts
- v0.12.3 typing indicators (with privacy controls)

**Tier 2 — security UX: ✅ COMPLETE**
- v0.7.7 verified-in-person checkmark
- v0.7.8 key-change warnings
- v0.7.9 multi-modal SAS (digits + audio + visual art)
- v0.8.0 group UI

**Tier 3 — P2P/file features: 4 of 6**
- ✅ v0.8.1 live transfer progress
- ✅ v0.8.2 folder sync conflict UI
- ❌ v0.8.3 multi-path send (still open)
- ✅ v0.8.4 voice messages
- ✅ v0.8.5 inline previews
- ❌ v0.8.6 large file streaming (still open)

**Cross-cutting: all done**
- ✅ Onboarding wizard (v0.9.4)
- ✅ Global search / command palette (v0.9.3)
- ✅ Activity feed (v0.9.1)

**Tier 4 — platform reach: barely started**
- ❌ v0.9.0 mobile-responsive web UI — was the planned target;
  v0.9.x ship slots got spent on settings polish + activity feed
  + voice + onboarding instead. Documenting honestly: this slot
  did not get spent on mobile.
- 🟡 System tray (✅ shipped in v0.10.5) but global hotkey ❌.
- ❌ Multi-device-per-identity (originally v1.0.0)
- ❌ Native iOS/Android apps
- ❌ Voice/video calls

**Beyond the original roadmap (v0.10.x – v0.13.x):**
A parallel UX track shipped Settings overhaul (v0.11.0 – v0.11.6),
disappearing messages, presence, multi-select+forward, native
folder picker, group sidebar polish, per-chat tools, storage
controls, bandwidth cap enforcement, auto-accept filter, server-
synced chat preferences, read-receipt + typing privacy controls,
and the v0.13.x voice pass. Plus a parallel transfer-engine track
from collaborator commits: transfer doctor, transfer brain, fast
lanes, pipelined stream, binary lane.

The honest take from the project audit: **architecturally One
Link lives the mission, but its reach (who can actually use it
right now) doesn't match the name.** That's what the three tracks
below are for.

---

## The three tracks ahead

Every remaining roadmap item maps onto one of these. Each track
gets steered by a different principle.

### Track A — Reach

> Principle 1 (Reach over polish): who can use One Link this week
> who couldn't last week?

The track that turns "We Are One" from aspiration to fact. Every
ship in this track expands the user base meaningfully.

Ordered by leverage:

1. **Mobile-responsive web UI.** ✅ Shipped v0.14.0 (layout +
   Markov prefetch + SW outbox) and v0.14.1 (last-conversation
   restore on boot). The desktop UI now collapses cleanly at
   720px and below.

2. **Phone tier surface trim — full sequence v0.14.2 → v0.14.8.**
   Detailed in [`PHONE_TIER.md`](./PHONE_TIER.md). Removes /
   hides power-user surfaces on phone form-factor so the default
   surface is roughly 50% of the desktop one. Each ship in the
   sequence:

   - **v0.14.2 — Phone tier foundation.** `data-form-factor`
     attribute on `<html>` set at boot, `state.tier` setting,
     CSS rules for `.desktop-only` + `[data-tier="advanced"]` +
     `html.show-advanced` reveal. "Show advanced controls"
     toggle in Profile pane. Per-pane "N advanced controls
     hidden. [Show]" hint helper. Mechanism only — no element
     yet tagged; desktop unchanged.

   - **v0.14.3 — Cut Files / Folders / Activity tabs on phone.**
     Files + Folders panes go `desktop-only` (no addressable
     filesystem on phone). Activity tab goes `data-tier="advanced"`.
     Phone pane-tab bar shows just "Chat."

   - **v0.14.4 — Cut power-user settings rows on phone.** Network,
     Shortcuts, and Advanced panes go desktop-only. Storage
     pane: download-folder input desktop-only, granular bandwidth
     dropdown becomes a "Save data on cellular" toggle, auto-
     accept extensions input desktop-only. Privacy pane:
     passphrase row → advanced. Notifications: notification-
     preview + notify-on-reactions → advanced. Phone settings =
     7 visible panes instead of 11.

   - **v0.14.5 — Trim per-device drawer on phone.** Reachability
     rows wrapped in "Connection details" disclosure (collapsed
     by default). Capability toggle grid wrapped in "Customize"
     disclosure with a single "Allow everything" default.
     Trust history rows marked advanced.

   - **v0.14.6 — Composer + drag-drop trim.** Drag-drop overlay
     desktop-only. Screenshot button desktop-only. Composer
     respects `safe-area-inset-bottom` on phones. Scroll-restore
     on pane-switch.

   - **v0.14.7 — Phone-friendly pair flow.** Promote SAS art
     above SAS digits on phone. "Match? [Yes] [No]" framing.
     "Verify in person" hint copy adjusted per form-factor.

   - **v0.14.8 — Phone diagnostics escape hatch.** Long-press the
     version number in About → diagnostics opens. Diagnostics
     button in Advanced settings (when revealed). Ctrl+Shift+D
     stays desktop-only.

3. **Plain-language pass on every remaining surface.** ✅ Shipped
   v0.13.0 + v0.13.1. Continued vigilance via the principle 2
   audit cadence.

4. **First-run experience that presumes zero technical knowledge.**
   Replace the existing onboarding wizard with one that pairs
   the user's first device for them via a QR-style hand-off and
   doesn't say the words "fingerprint," "rendezvous," or "SAS"
   before the user is paired and chatting. Targeted: post-
   v0.14.8 (the phone tier work informs what the new wizard
   doesn't say).

5. **PWA pivot — the "no computer required" track.** Multi-ship
   sequence v0.15.0 → v1.0.0 to make One Link a pure-browser P2P
   chat that runs entirely on a phone with no daemon required.
   Architecture: WebRTC DataChannel transport, Web Crypto
   identity, OPFS storage, Passkey-aware unlock, Service Worker
   background, PWA install. Detailed sequence:

   - v0.15.0 — PWA shell + manifest + Web Crypto identity foundation
   - v0.16.0 — OPFS storage layer + at-rest encryption
   - v0.17.0 — Passkey / WebAuthn integration for identity unlock
   - v0.18.0 — WebRTC DataChannel transport
   - v0.19.0 — WebTransport bulk path + adaptive transport selector
   - v0.20.0 — BLE proximity pairing on Android, ultrasonic on iOS fallback
   - v0.21.0 — MLS group ratchet
   - v0.22.0 — Sealed sender + cover traffic
   - v0.23.0 — Yjs/Automerge CRDT layer
   - v0.24.0 — WebGPU + on-device model for semantic search
   - v0.25.0 — Federated learning across the user's devices
   - **v1.0.0 — One Link Web** (the phone-only milestone)

6. **Defang ladder.** Per-ship corporate-substrate mitigations
   shipped alongside the PWA pivot:

   - Multi-org STUN endpoints + LAN-only mode (defangs single-
     STUN observation)
   - IPFS distribution + `.onion` mirror (defangs DNS / CDN)
   - OPFS-stored identity, never OS keychain (defangs iCloud /
     Google Password Manager)
   - Optional encrypted Web Push, off by default (defangs
     APNS/FCM message-graph leakage)
   - Hybrid logical clocks (defangs OS clock dependency)
   - Multi-source entropy mixing (defangs RNG dependency)
   - Capacitor sideload build for Android (defangs Play Store
     gatekeeping)
   - Signed updates verified by Service Worker (defangs CDN
     compromise)

7. **Native iOS and Android apps (v1.1+).** Capacitor wrappers
   around the PWA. Same code; gain push notifications, home-
   screen install via app stores for users who want App-Store
   discovery, and EU alternative-app-store distribution
   (sideload friendly).

### Track B — Connection

> Principle 3 (Async by default): does this work when one side is
> offline, asleep, on a plane, or on the move?

The track that turns "Everything is connected" from "if both
sides are online" into "always." Every ship in this track
removes a presence-required precondition.

Ordered by leverage:

1. **Multi-device-per-identity (the v1.0.0 target).** Your phone,
   laptop, and desktop are ONE identity to your friends, not
   three contacts. Frontier: predictive cache so your phone has
   tomorrow's reply pre-decoded before you wake up; learned
   model of which device you'll open next; CRDT merge with
   proofs of commutativity under partition + clock skew + edit
   storms. Surface: peers see one of you. Your devices feel
   instantly synchronized.

2. **Async-first delivery enhancements.** Outbox stops being a
   fallback and becomes the default path; the synchronous path
   is the optimization. Frontier: a learned reachability model
   per peer (when do they typically come online?) so messages
   prefer paths that are about to be available. Surface: send a
   message, it's delivered when it's possible to deliver. The
   user never sees "still trying."

3. **Multi-path send** (the orphaned Tier-3 v0.8.3). Send chunks
   over LAN + internet + relay in parallel; fastest path wins
   per chunk. Frontier: the path-allocator is a learned
   bandit, not a heuristic; CDC dedup makes mistakes nearly free
   so the bandit can be aggressive. Surface: large files
   transfer faster than physics says they should.

4. **Large file streaming** (the orphaned Tier-3 v0.8.6). Don't
   materialize the full file before playback; stream chunks to a
   media element as they arrive. Frontier: predictive chunk
   prefetch driven by playback position + recent throughput;
   adaptive bitrate when bandwidth degrades. Surface: voice
   messages and forwarded video play instantly even on a slow
   peer.

5. **Rendezvous default-on, not advanced setting.** Currently
   rendezvous is a "for power users" knob in Network settings.
   Move it to default-configured-on-install (with a curated
   public rendezvous list shipped in `paths.py`). Frontier: a
   pluggable rendezvous discovery that uses DNS, LAN multicast,
   and a fallback DHT in priority order; the user sees nothing.

### Track C — Engine-hiding

> Principle 2 (Hide the engine): what word, button, or knob
> disappears with this ship?

The track that turns "It just works" from "if you understand
P2P" into "for everyone." Every ship in this track removes a
technical concept from the user's surface.

Ordered by leverage:

1. **Channel-level Double Ratchet activation.** The primitive
   shipped in v0.7.2 and has been sitting unused since. Detect
   mutual `double_ratchet_v1` capability and switch the channel.
   Frontier: forward secrecy + post-compromise security, in
   bytes per message <2× the existing X25519+ChaCha20-Poly1305
   path; auditable transcript binding. Surface: zero. Invisible
   safety upgrade.

2. **Pair flow simplification.** Hide the SAS by default for
   casual pairings (auto-accept on LAN with a deny-by-default
   capability set + a "verify in person?" pill that the user
   can engage when they want). Frontier: a calibrated risk model
   that decides whether to surface the SAS based on context
   (LAN vs. internet, hostname-pubkey history, prior pairings
   from the same network). Surface: most pairings just work; the
   SAS appears only when it actually changes the trust decision.

3. **Progressive disclosure for advanced settings.** Mark settings
   as "everyone / power user / engineer" tiers in the settings
   table; default to "everyone." A long-press / shortcut reveals
   the rest. Frontier: settings that auto-tier based on the
   user's interaction history (we know which ones they touch).
   Surface: 80% of users never see 80% of the settings.

4. **Group sender-key rotation cadence.** Currently never rotates;
   add periodic rotation tied to group event log advancement.
   Frontier: rotation is automatic + driven by entropy/usage
   thresholds; the user never knows. Surface: zero new buttons.

5. **Tighter supply-chain gates.** pip-audit / bandit currently
   report-only; promote to fail-the-build after triage. Frontier:
   reproducible builds verified in CI; SBOM auto-published.
   Surface: zero. The kind of safety the user shouldn't think
   about.

---

## Suggested next ship

**v0.14.2 — Phone tier foundation.** Smallest first step in the
phone-tier sequence detailed in [`PHONE_TIER.md`](./PHONE_TIER.md).
Adds the form-factor detection + the `state.tier` setting + the
"Show advanced controls" toggle, without touching any specific
element's visibility yet. After it lands, every subsequent ship
in the v0.14.x sequence is a simple "tag elements with this
attribute" diff.

Pairs with continued v0.15.0+ planning for the PWA pivot. The
phone-tier work and the PWA work are independent — phone-tier
improves the existing daemon-served experience for phone users;
PWA pivot makes One Link runnable without a daemon at all.

Ship-spec for every merge is evaluated against the checklist in
[`PRINCIPLES.md`](./PRINCIPLES.md).

---

## Sequencing rules (unchanged from prior roadmaps)

- Each version ships independently. Don't bundle.
- Wire-format additions stay backward-compatible: older peers
  ignore unknown fields / message kinds.
- Every cap that affects what a peer can request gets:
  1. capability advertised in CAPS
  2. deny-by-default policy entry
  3. UI grant prompt on first request from a peer
- Any new key-trust pathway gets surfaced in the trust UI before
  the wire feature ships.

---

## Audit cadence

Per `PRINCIPLES.md`, the principles need quarterly audit. Add a
companion exercise: every quarter, also audit this roadmap. Move
items between tracks if their dominant gating principle has
shifted; retire items that have shipped; promote items that
should now be next based on what users actually hit.
