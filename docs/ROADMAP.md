# One Link Roadmap

Status: living document. Updated as releases ship.
Last updated: 2026-05-08.

This roadmap is gated by [`PRINCIPLES.md`](./PRINCIPLES.md). Every
unfinished ship below has been (or will be) restated against the
ship-gate checklist before code lands. Items that don't pass all
four principles aren't on this list.

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

1. **Mobile-responsive web UI** (the v0.9.0 that never landed).
   Frontier engine: sub-100ms input latency on a 5-year-old
   phone, frame-budget regression tests, predictive prefetch of
   the next likely conversation, layout that adapts to thumb
   reach. Surface: phone tab Just Works.

2. **Plain-language pass on every remaining surface.**
   Continuation of v0.13.x. Audit every modal, error, tooltip,
   help string. Frontier: zero jargon left for any non-technical
   first-time user; confirmed via a literal "show this to a
   non-technical person" test before merge.

3. **First-run experience that presumes zero technical knowledge.**
   Replace the existing onboarding wizard with one that pairs
   the user's first device for them via a QR-style hand-off and
   doesn't say the words "fingerprint," "rendezvous," or "SAS"
   before the user is paired and chatting.

4. **Native iOS and Android apps.** After mobile-web. Use mobile-
   web as a forcing function; the mobile UI is the iOS UI's
   layout spec. Background-service constraints on mobile are the
   real frontier here.

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

**Mobile-responsive web UI** is Track A, item 1, and the single
biggest unlock toward "We Are One." It's also a forcing function
for everything that follows: every later ship will have to render
at 360px before it merges, which itself drives Engine-hiding
debt down (you can't hide forty advanced settings on a phone
screen, so progressive disclosure becomes mandatory).

Ship-spec for the next merge will be evaluated against the
checklist in [`PRINCIPLES.md`](./PRINCIPLES.md).

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
