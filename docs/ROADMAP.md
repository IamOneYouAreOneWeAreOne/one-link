# One Link Roadmap

Status: living document. Updated as releases ship.
Last updated: 2026-05-23.

> **File engine v2 status (2026-05-11)**: All four phases of
> [`FILE_ENGINE_V2_PLAN.md`](./FILE_ENGINE_V2_PLAN.md) are structurally
> complete. 16 Rust crates ship in `native/`; ADRs 0001–0033 record
> every architectural decision. Native chunk-store transport is
> default-on for capable peers; Phase D primitives (tau-field
> routing, active inference prefetch, persistent homology durability,
> grammar compression, plausibly deniable storage, formal
> verification, Coherence ↔ Rust codegen) all shipped + tested +
> Python-callable. Production wiring of Phase D crates lands per-item
> as surrounding daemon paths mature (multi-relay graph, chunk-store
> warm-cache hooks, operator diagnostics endpoints). See ADR-0033
> for the wiring matrix.

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
- [`FILE_ENGINE_V2_PLAN.md`](./FILE_ENGINE_V2_PLAN.md) — multi-phase
  architectural rebuild for the next-generation file-delivery
  engine. 10-layer stack (substrate → chunk store → crypto →
  capability → transport → information layer → routing →
  adaptation → shared state → filesystem surface → operability).
  Phase A1 → A2 → B/C → D ordered by dependency, not calendar.
  Harvests OneField Mesh `transport/`, `mesh/`, `bridge/`,
  `privacy/` primitives; built on Coherence Language stdlib
  `std.{capability, crdt, codec.canon, distributed}`. New
  parallel track to the v0.14.x phone tier and v0.15.x → v0.25.x
  PWA pivot. Phase A1 first ship is the chunk-store rewrite
  (line-rate CDC, content-addressed LSM with bloom front,
  crash-only WAL, AEAD pipeline, manifest WAL, stripe-layout-
  ready, both-address capable).
- [`UNIVERSAL_COMMS_FABRIC.md`](./UNIVERSAL_COMMS_FABRIC.md) -
  implementation-grade doctrine for making every device use every
  communication surface it has. Covers LAN, Wi-Fi Direct, private
  hotspot, Bluetooth/BLE, USB, Ethernet, WebRTC, QR, audio,
  offline courier, OneField/LoRa/SDR, future hardware adapters,
  hardware inventory, adapter contracts, route scoring,
  activation safety policy, multi-source pull, store-carry-forward,
  safety budgets, and phased ship gates. Phase 1 now has code:
  inventory, route scoring, activation governor, daemon/API fabric
  truth, transfer metadata, and Activity-panel truth surfacing.

Read order for someone joining cold:
1. `PRINCIPLES.md` — what gates ships.
2. `ROADMAP.md` (this file) — what ships in what order.
3. `ARCHITECTURE.md` — how the PWA pivot is built.
4. `SOVEREIGNTY.md` + `SECURITY.md` — the defenses, paired.
5. `GOVERNANCE.md` — the structural commitments.
6. `UNIVERSAL_COMMS_FABRIC.md` - how One Link reaches people
   when ordinary networks are missing, weak, or fragmented.
7. `PHONE_TIER.md` — the phone-specific surface contract.

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

   **v1.0.0 acceptance gate — "open a URL, decrypt in your tab, no install."**
   The recipient of a share link is a brand-new visitor who has
   never heard of One Link. They click the URL in any browser, the
   PWA loads in-tab, the file decrypts client-side, the download
   completes. No daemon, no app install, no account. Two modes
   share this acceptance gate:

   - **Live-sender mode (preferred when sender is online).**
     Sender stays in their tab; recipient's tab opens a WebRTC
     DataChannel directly to the sender; chunks stream peer-to-peer
     with per-chunk AEAD. No R2 hop, no cap. Sender closes tab,
     transfer pauses; reopen resumes. Uses the same `ol_transfer`
     fountain-coded pipeline that ships today, just bridged
     through the PWA instead of the daemon.

   - **Buffered mode (when sender wants fire-and-forget).** The
     existing `/share/` flow extended from 25 MB to 5 GB via
     streaming PUT to the `RELEASES` R2 bucket with chunked
     transfer encoding (Worker streams body straight to R2 multi-
     part upload, never buffers full payload). TTL raised from 24h
     to 7 days when sender opts in (default stays 24h). Key in URL
     fragment never leaves the two browsers; first GET deletes
     the R2 object (one-shot semantics preserved).

   Both modes terminate E2EE. The acceptance gate is binary: the
   recipient is a non-installed stranger who completes a 1 GB
   transfer without leaving their browser. This is the
   WeTransfer-parity criterion that flips the "one-shot to a
   stranger" use case from "fall back to WeTransfer" to "always
   use One Link."

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

8. **Threshold recovery user-flow ("guardians").** The
   primitive shipped: `native/ol_threshold_recovery` (Shamir
   k-of-n share split + BN multi-sig with per-signer R values)
   is wired into `src/one_link/social_recovery.py` per
   `one_link_phase_f_partial_rows_finished.md`. The
   end-user-facing flow is not. Without it, losing your only
   paired device equals losing your identity, which is the
   adoption ceiling for any user who doesn't keep two devices.
   Frontier: a hide-the-engine surface where the user picks
   3-5 already-paired contacts ("guardians"), and the daemon
   shards the identity-unlock key (k-of-n, default 2-of-3) to
   those guardians via a new `RECOVERY_SHARD_V1` capability.
   Each shard is encrypted to the guardian's pubkey before
   send; guardians store shards in a sandboxed inbox
   (`~/.one-link/recovery_inbox/<sender-fp>.shard`) that the
   daemon refuses to surface in any other UI and that no
   capability except `RECOVERY_REQUEST_V1` can read. Restore
   flow: new install on a fresh device, user enters their old
   peer-fingerprint hash + a `RECOVERY_REQUEST_V1` is broadcast
   to the registered guardian set, each guardian sees a "X is
   requesting account recovery, approve?" prompt with a 5-word
   verbal-confirmation challenge to authenticate the requester
   out-of-band; on k approvals the daemon reconstructs the
   identity key locally. Wire format: three new message kinds,
   all capability-gated and audit-logged:
   `RECOVERY_SHARD_V1` (issue),
   `RECOVERY_REQUEST_V1` (restore broadcast),
   `RECOVERY_APPROVAL_V1` (guardian consent).
   Where: new orchestration module at
   `src/one_link/recovery.py`; UI panel at Settings → Identity →
   Recovery (introduces guardians, shows their status, allows
   replace/remove with proper re-shard); TLA+ spec at
   `docs/formal/recovery.tla` (liveness: any k cooperating
   guardians always succeed; safety: any k-1 colluding
   guardians cannot reconstruct + cannot impersonate the
   requester). Surface: the words "shard", "Shamir",
   "threshold" never appear; principle-2 audit gates the ship.
   Acceptance gate: a non-technical user completes the split
   in under 60 seconds; restore from 2 of 3 guardians completes
   in under 2 minutes; failure modes (guardian denies, times
   out, has lost their own device) each surface a clear next
   step; replace-guardian flow preserves access without
   re-pairing every device.

9. **Group voice + group video + large groups (50-100+).**
   Today group chat works (v0.8.0 group UI shipped); group
   voice and group video do not. For mainstream adoption
   (Signal / WhatsApp / Discord parity) the "30-person voice
   call" use case is not optional. Foundation: MLS group
   ratchet already sequenced into the PWA pivot at v0.21.0.
   New crate: `native/ol_sfu` (Selective Forwarding Unit)
   handling RTP forwarding + simulcast layer selection +
   active-speaker detection + per-participant bandwidth
   governance. Pattern: LiveKit-style SFU but with One Link
   auth (the SFU is itself a One Link peer; calls are E2EE to
   the participant set via MLS group ratchet; the SFU sees
   only encrypted SRTP). Active SFU election: lowest-latency
   volunteer relay carrying the `SFU_V1` capability, or
   member-elected dedicated host. Sender-key rotation per MLS
   epoch ensures post-compromise security per call.
   Wire format: `CALL_INVITE_V1`, `CALL_ANSWER_V1`,
   `CALL_HANGUP_V1`, `CALL_SFU_OFFER_V1`,
   `CALL_SFU_ANSWER_V1`, plus an `SFU_V1` capability advertised
   by qualifying relays. Where: new crate at `native/ol_sfu/`
   (Rust, async-std, srtp + rtp-rs); existing
   `src/one_link/peer_rtc.py` extended for multi-party offer
   exchange; new `src/one_link/group_call.py` orchestrating
   the SFU election + invite fanout; UI extension to the
   existing group sidebar adds a "Call" button when the group
   has `VOICE_GROUP_V1` or `VIDEO_GROUP_V1` advertised by all
   members. Acceptance gate: 50-person voice call sustained
   30 minutes at 64 kbps per participant on a single Hetzner
   CX21 SFU; 8-person video call sustained 15 minutes at
   720p / 8 fps with simulcast; active-speaker switching
   under 200 ms; SFU operator (even a malicious one) cannot
   read AV bytes (verified via a constant-time
   plaintext-presence check + TLA+ spec at
   `docs/formal/sfu.tla` proving the SFU operates only on
   ciphertext + RTP headers, never plaintext samples).

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

6. **Daemon corruption self-healing.** Production messengers
   eat the cost of partial-sync / ratchet-out-of-sync / DB-wipe /
   restored-from-backup scenarios. Today any of these drops the
   user back to "reinstall + lose history," which is the
   single worst recoverable-failure UX in the daemon and an
   adoption ceiling for users who back up their phone or rotate
   devices. Frontier: per-channel sequence-number gap detection
   (if we expect message #N+1 from peer P and receive #N+5,
   suspect corruption); a new `RESYNC_V1` capability that probes
   the peer for "your last-sent index + your current ratchet
   epoch," diffs against local state, and replays the missing
   range from a bounded 30-day outbox cache (already exists
   for `RELAY_OUTBOX_V1` from v0.7.1; extended retention +
   at-rest encryption layer using the channel root key).
   Restore-from-backup detection: backward time-jumps in
   ratchet state at boot (Lamport-clock based check, not
   wall-clock) trigger a key-change warning and a
   re-pair-without-loss flow that preserves the visible message
   history while rotating the long-term keys with peer consent.
   Wire format: `RESYNC_PROBE_V1` (state-snapshot request),
   `RESYNC_RESPONSE_V1` (state-snapshot answer with sealed
   sequence-number summary), `RESYNC_REPLAY_V1` (chunked
   ciphertext replay over the existing channel), all
   capability-gated and ratchet-bound (the probe is itself
   a ratcheted message, so an attacker cannot replay it to
   force re-sync). Where: new crate `native/ol_resync` for
   the state-diff + sequence-number logic + wire-format
   encoding; new orchestration module
   `src/one_link/resync.py`; extension of the existing
   `src/one_link/outbox_store.py` to add a 30-day retention
   window with at-rest encryption keyed off the channel root.
   Surface: a thin "X messages caught up" toast when
   reconciliation succeeds, nothing else. Any unrecoverable
   message gets a single "this message could not be recovered"
   placeholder so silent loss is structurally impossible.
   Acceptance gate: corruption detected within 1 message
   exchange; reconciliation completes under 5 seconds for a
   gap under 100 messages; TLA+ spec at
   `docs/formal/resync.tla` proves monotonicity (no ratchet
   rewind ever; the rebuild path strictly forward-rolls keys)
   + completeness (every message either delivers, is replayed,
   or is explicitly flagged as lost — never silent).

---

### Track D — Coherence Mesh (sovereign network + multi-device identity)

> Principle: all five. This track is the apex of the engine work —
> turns One Link from "best-in-class file + chat engine" into
> "a global communications layer that no company, government, ISP,
> or attacker can lock out, surveil, censor, or destroy — and that
> any person can use without understanding any of that."

Canonical plan: [`COHERENCE_MESH_PLAN.md`](./COHERENCE_MESH_PLAN.md)

**The load-bearing insight:** three trust tiers, three default
privacy modes. Self-traffic (your own devices talking to each
other) is direct + fast because there's no metadata to hide.
Friend-traffic is 1-hop-onion + sealed-sender by default.
Paranoid mode is 3-hop-onion + Loopix-class cover traffic for
users in hostile environments. The user never picks; pair-by-QR
puts your devices in self-mesh, friends in pinned-contact, and
paranoid is an explicit opt-in.

Phase F ships in 8 sub-phases (F1–F8); see the plan for
acceptance gates per phase. Ordered by leverage:

1. **F1 — Harvest the easy wins.** Port `OneField/onefield/privacy/sharding.cl`
   (Shamir threshold recovery, Tier 15 production) and
   `OneField/onefield/bridge/discovery.cl` (peer-cache TTL/announce
   logic) and `OneField/onefield/mesh/bootstrap.cl` (channel-
   reciprocity pair-trust). All three are pre-built in OneField
   Mesh and harvest directly into Rust crates.

2. **F2 — Pair-by-QR.** Ed25519 + Dilithium handshake + optional
   channel-reciprocity Factor-2. Replaces the `--lan` token URL
   entirely. Eliminates remote-pair vulnerabilities.

3. **F3 — Onion circuits.** 1-hop default for pinned-contact friend
   traffic; 3-hop for paranoid mode. Path selection via Phase E
   coherence-field routing (already shipped).

4. **F4 — Sealed sender + cover traffic.** Loopix-style constant-
   rate background between pinned contacts. Defeats timing analysis.

5. **F5 — Personal Device Mesh.** Master identity + per-device
   subkeys + device-presence CRDT + remote-instruct command channel.
   Your phone, laptop, tablet, desktop are ONE identity to friends
   AND separately addressable to you. Phone in TX grabs file from
   laptop in CA at full network speed (self-traffic skips onion).

6. **F6 — DPI-evading transport.** Cloak/Obfs4-style pluggable
   transport. Bytes on the wire look like generic HTTPS;
   censorship-resistant by default.

7. **F7 — PQ signatures.** Ed25519 + Dilithium hybrid. Survives
   quantum computers. Defense-in-depth: either scheme alone
   authenticates.

8. **F8 — Confidential-compute daemon.** Per-platform: Apple Secure
   Memory / Intel SGX / AMD SEV-SNP / Windows TPM. Local malware
   with root cannot extract identity keys.

9. **F9 — Relay-operator onramp (frictionless "run a relay"
   funnel).** Sovereignty + censorship resistance require a
   relay set that is diverse, geographically distributed, and
   not operated by the One Link contributors. Today: relays
   are word-of-mouth + anyone-can-but-few-do. The mesh-as-
   sovereign-network story is only as strong as the diversity
   + uptime of the non-contributor-operated relay set, and the
   funnel for becoming an operator has to be at "10 minutes,
   no developer skills" for that set to grow past the
   enthusiast tier. Frontier:
   - Published OCI image at
     `oci.weareone-link.org/one-link-relay:latest` that runs
     the relay daemon stand-alone (no chat client, no UI,
     just the relay + operator-attestation endpoint).
   - One-liner: `docker run -d --restart unless-stopped
     -p 4040:4040 -v one-link-relay:/data
     oci.weareone-link.org/one-link-relay`.
   - Tested Raspberry Pi 4/5 image flash guide
     (curl-pipe-bash installer + dd of a prebuilt SD image).
   - Cloud-init recipes for DigitalOcean / Hetzner / Vultr /
     Linode one-click deploys (one YAML per provider, signed).
   - Public directory at `https://weareone-link.org/relays/`:
     opt-in, signed self-attestation carrying operator name,
     jurisdiction, uptime URL, capacity claim, donation method
     (if any). Sortable by uptime / bandwidth / longevity.
   - Hall-of-Relays page ranks the top operators by 90-day
     uptime + bytes-forwarded; reciprocity badge for relays
     that have stayed up through a censorship event.
   - "Donate compute" affordance on each relay's directory
     entry: route a portion of your own outbound through this
     relay to credit its bandwidth budget without standing up
     your own.
   New crate: `native/ol_relay_operator` exposing a signed
   `/api/operator` endpoint (capacity, uptime, bandwidth
   stats, jurisdiction declaration, contact). Daemon-side:
   each relay opts in via config; the endpoint signs its
   response with the relay's release key so the directory
   cannot lie about a relay's claims. Worker addition: new
   `/relays/` route on the website + new `OPERATORS` Durable
   Object that polls every registered relay's `/api/operator`
   hourly and aggregates into the directory page. New repo
   `IamOneYouAreOneWeAreOne/one-link-relay-deploy` carrying
   the Docker compose file, Pi image build script,
   cloud-init templates, and provider-specific one-click
   deploy buttons. Defang contribution: a healthy
   non-One-Link-operated relay set directly defangs
   single-point takedown of the contributor-run relays;
   listed in the Defang ladder at Track A item 6 as the
   relay-diversity row. End-user surface: a tiny "via relay
   X" hint when a message takes the relay path, clickable
   for the relay's public attestation page (no PII; just
   "operator-claimed jurisdiction + uptime + bandwidth").
   Acceptance gate: a non-developer stands up a working
   relay in under 10 minutes on Hetzner CX21 (verified by
   recording the flow end to end); the directory page is
   live with 10+ verified independent relays at first ship;
   relay churn metrics published (mean uptime, percent
   active in 7-day window); donate-compute path tested with
   real traffic credit to a recipient relay.

**End state**: capabilities no other consumer messenger ships
(see comparison table in [`COHERENCE_MESH_PLAN.md`](./COHERENCE_MESH_PLAN.md)).
The "everyone on any device, super easily" promise becomes
literally what the architecture delivers.

---

## Track E — External assurance

The internal red-team batches (May 9 / May 14 / May 21 sweeps)
closed every finding raised in-tree. For the architectural
claims to stand up under a hostile audience (journalists, NGOs,
dissidents, regulators, supply-chain reviewers), at least one
published third-party report has to exist. This is the one
track the principles ladder does not gate at the code level
(items here are contractor engagements + funding decisions,
not code merges), but the roadmap owes them a slot because
they are the only thing that converts "audit-ready" into
"audited."

1. **First external pentest** (Trail of Bits / NCC Group /
   Cure53 / Quarkslab class). Scope: the protocol crates
   (`ol_pair_qr`, `ol_ratchet`, `ol_onion`, `ol_capability`,
   `ol_threshold_recovery`, `ol_pqsig`, `ol_pqkem`,
   `ol_confidential`, `ol_resync`, `ol_sfu`, `ol_relay_operator`),
   the Python daemon (pair flow, WebRTC, outbox, social
   recovery, resync orchestration), the Worker code, the
   website's signed-manifest verification pipeline, and a
   sampled review of the WASM verifier path in the browser.
   Funding: per `GOVERNANCE.md` (no acquisition-class capital;
   community + grants are the funding lane); budget estimate
   $50K to $300K depending on firm + depth. Output: published
   report at
   `https://weareone-link.org/audits/external/<firm>-<date>.pdf`
   with a summary tile on the `/audits/` page; signed by the
   release-key holder so the report is integrity-checkable
   independently. Acceptance gate: report published, every
   P0 and P1 finding closed, retest pass committed to git
   history, summary tile live on `/audits/` page. Cadence:
   re-engage annually or on every major version bump,
   whichever is sooner.

2. **Bug bounty live, funded.** Today the bounty intent is
   on `/security/` ("we intend to pay"); the actual purse is
   not funded. Land a real purse (community-funded line
   item, donations + grants pool) with severity tiers
   matching the published policy
   (CRITICAL / HIGH / MEDIUM / LOW from `.well-known/security.txt`).
   Lift the bounty intent on `/security/` from "intent" to
   "active, funded, paying out." Per-finding payout published
   in the report so the program's credibility scales with
   each report. Where: new `/bounty/` page on website
   (with the program rules), new line item on the
   `GOVERNANCE.md` funding posture, optional Open Collective
   or similar transparent treasury. Acceptance gate: at
   least one CRITICAL or HIGH report paid out and published
   (with the reporter's consent) within 6 months of going
   live.

3. **Reproducible-build verification (independent).** A
   non-contributor builds every release from the public
   source and publishes signed attestations that the bytes
   match the release-key-signed binary. Pairs with the
   Track-C item 5 reproducible-build CI; the external
   attestation is the independent eyes on the same property
   (the official CI is necessary but not sufficient — an
   attacker who compromises the CI can pass that gate). Where:
   a `/reproducible/` page on the website listing the
   independent verifiers + their signed attestations per
   release. Acceptance gate: at least three independent
   verifiers (one per major release channel: Windows / Linux /
   source-archive) reproducing bytes within 24h of each
   tagged release; attestation chain published on the page.

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

---

## Scope decisions (the explicit "not in scope" list)

Without this section, the same questions keep arriving. Each
entry is a "no" with the reason it stays a no, so the answer
is durable. If you find yourself proposing one of these,
the burden is to overturn the reason, not just propose
the feature.

- **Contacts / address-book sync.** NOT in scope. Device
  contacts are a third-party metadata surface (your full
  social graph) that directly contradicts the architecture's
  "no user database anywhere." If two users want a shared
  address book, they can send each other a contacts file
  via a normal One Link channel; building it as a primitive
  would create the very database the architecture refuses
  to hold.

- **Calendar sync.** NOT in scope. Same reasoning as
  contacts; calendar entries are a high-value metadata
  surface (who you meet, when, where) and the right answer
  is to use a local calendar app and send invitations as
  files when needed.

- **Email gateway / IMAP bridge.** NOT in scope. Email is
  a clearnet protocol with persistent metadata trails at
  every hop; bolting One Link onto SMTP would inherit the
  worst properties of both. The right answer is "do not
  use email for the things that belong on One Link."

- **Payments / wallets / token rails.** NOT in scope. Money
  systems are a different trust regime (regulatory, custody,
  AML / KYC) and entangling them with the comms layer
  creates surfaces (transaction graphs, regulatory data
  requests, sanctions screening) that the comms layer is
  architected to refuse. If you want a payment rail next
  to your One Link chat, run a separate payment app.

- **Hosted "One Link for Business" SaaS.** NOT in scope. A
  managed-service offering inherits all the surfaces ("our
  servers store your data," "our employees can access X,"
  "we comply with subpoena Y") that the protocol exists to
  eliminate. The federation answer is: each org runs its
  own relay (see Track D F9, relay-operator onramp); the
  trust posture stays "no operator can read what they
  carry."

- **Server-side AI features (auto-summarize, reply-suggest,
  content moderation, semantic search across other users).**
  NOT in scope at the daemon or relay level. If a user wants
  those, they run them locally against their own message
  store (the on-device model path in Track A item 5,
  v0.24.0). The daemon refuses to ship features that need
  to read plaintext server-side; doing so would undo the
  entire architecture.

- **Telemetry of any kind from the daemon or website.**
  NOT in scope. This is the load-bearing privacy claim and
  the architecture is designed so the claim is structural,
  not policy. The only counters that exist are local + opt-
  in (the operator-attestation endpoint on relays publishes
  uptime + bandwidth, but only because the relay operator
  chose to register).

- **Mandatory account recovery via email or SMS.** NOT in
  scope. Both create a fallback identity in a custodial
  system (the email provider, the cell carrier) that
  defeats the purpose of holding the identity locally.
  Threshold recovery via guardians (Track A item 8) is the
  one supported recovery path; users who want a custodial
  fallback can designate themselves on a separate device as
  one of their own guardians.
