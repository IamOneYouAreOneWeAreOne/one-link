# Living Presence — One Link Voice + Video Architecture

> **Status:** partial implementation plus future design specification. The
> alpha source has 1:1 voice/video call lifecycle, signed browser signaling,
> consent controls, real Chromium media/identity tests, Firefox direct
> transport/identity/ICE tests, and network-degradation harnesses. It is not a
> verified production release. WebKit/iOS, a physical multi-machine NAT/TURN
> matrix, long calls, and the semantic/provenance/ambient engines below remain
> open. Native daemon channels can use ML-KEM-768, but call/browser identity is
> still Ed25519 and no post-quantum browser-call or onion-anonymity claim is
> made.

> **Audience:** Any engineer joining the project. This document is
> exhaustive on purpose. Read Part 0 first; everything else is
> navigable from there.

> **The design laws (load-bearing, never optional):**
> 1. **For the people.** Free, universal, on any device, any network.
>    No tiering of humans.
> 2. **Just works.** One button. Zero settings. No error codes.
>    The discipline of invisibility is half the build.
> 3. **We are one.** The user, their devices, their conversations,
>    and the substrate move as one living system.

---

## Part 0 — Reader's Guide

### What this document is

A complete architectural specification for the Voice + Video surface
of One Link. The product is not "calls." The product is **Living
Presence between trusted people**, with intensity as the variable. A
call is one position on the dial.

The 9 engines specified in Parts 4.1–4.9 are *internal mechanism*.
The user never sees one of them.

### What this document is not

- A roadmap with dates. Use tier ordering (Part 10) and dependency
  graphs. There are no calendar dates anywhere in this document on
  purpose; acceptance gates ship work, not calendars.
- A sales pitch. The numbers quoted are measured or derived;
  research-grade claims are flagged explicitly.
- A finished product. Many components are sketches; this document is
  the substrate from which they get built.

### How to navigate

| If you are... | Start at |
|---|---|
| New to the project | Part 1 (Vision), then Part 3 (Architecture Overview) |
| About to write code | Part 9 (Substrate Map), Part 10 (Tier Order) |
| Reviewing a PR | Part 2 (Doctrine of Invisibility), Part 7 (Trust Surface) |
| Designing a new engine | Part 4 (any engine), Part 5 (Shared State) |
| Testing | Part 11 (Test Strategy) |
| Auditing | Part 7, Part 14 |
| Asking "why this way" | Part 1, Part 14 |

### Companion documents

- [PRINCIPLES.md](PRINCIPLES.md) — the project-wide engineering principles
- [SECURITY.md](SECURITY.md) — current security posture + open findings
- [COHERENCE_MESH_PLAN.md](COHERENCE_MESH_PLAN.md) — the 10-row mesh stack
  this product builds on
- [FILE_ENGINE_V2_PLAN.md](FILE_ENGINE_V2_PLAN.md) — the file engine that
  shares native crates with this surface
- [ONE_LINK_VALIDATION_GATES.md](ONE_LINK_VALIDATION_GATES.md) — the
  acceptance ladder this product must climb
- [ARCHITECTURE.md](ARCHITECTURE.md) — the existing daemon architecture
- [CAPSULE_DURABILITY.md](CAPSULE_DURABILITY.md) — implemented encrypted
  async-capsule persistence, replay, retry, and durable-receipt contract
- [../../../OneField Mesh/docs/VOICE_VIDEO_ALIEN_TECH.md](../../../OneField%20Mesh/docs/VOICE_VIDEO_ALIEN_TECH.md)
  — the OneField voice/video math + capabilities

---

## Part 1 — The Vision

### What we are building

Living Presence is a **continuous, variable-intensity channel between
trusted people**, expressed through whatever surfaces are appropriate
at any given moment.

- At low intensity: ambient awareness. Mom is at home; her presence
  is faintly felt without any active session.
- At medium intensity: passive contact. A photo arrives, a thought
  is shared, a voice note plays through a speaker as she walks past.
- At high intensity: full conversation. Face, voice, gaze, gesture,
  through whichever surfaces are present.
- At decay: the conversation goes back to ambient, leaves an async
  trace if conditions require, resumes when both parties return.

The user experiences this as: **one button labelled "Call Mom",
which always works.**

The button does not pick a codec. It does not pick a device. It does
not show an error. It does not buffer. It does not ring busy. It
does not say "reconnecting." If conditions are bad, the call gently
changes form. If both parties are not present, it leaves a capsule.
If conditions recover, it resumes.

This is the only surface.

### Why this is different from every call product

| Product | Breaks which law |
|---|---|
| Zoom / Teams / Meet / WebEx | *Just works* (error toasts, quality bars, "reconnecting..." overlays, cloud-SFU dependency) |
| FaceTime | *We are one* (per-device opt-in via Continuity, walled garden, cloud-relay) |
| Signal / WhatsApp / Telegram | *For the people* (works for the tech-comfortable; grandma on a flaky network gets dropped calls) |
| Discord | *We are one* (separate identity per device, no organic body) |
| Push-to-talk (Voxer / Zello) | *For the people* (async-only is a different product, not a fallback) |

The composition we are designing — **all three laws holding
simultaneously, on a sovereign P2P substrate, with cryptographic
frame-level provenance, across an arbitrary intensity dial** — has
no shipping counterpart.

### Why now

The repository contains substantial substrate, with different activation
boundaries:

- One Link v0.21.0-alpha: native primitives plus live WebRTC and conditional
  identity-bound QUIC paths, ML-KEM-768 daemon-session establishment,
  capability and CRDT state, and personal-device-mesh functions. Hardware
  attestation, post-quantum identity signatures, onion message routing, and
  linked-mesh call handoff are not universal live product capabilities.
- OneField: voice.cl (1616 LOC) and video.cl (1107 LOC) define the
  math, wire format, predicates, and tests for the alien-tier
  semantic channel.
- Coherence Lang: the compiler, the four numerical rails, the
  property fuzzer at 850M trials/sec, the native CUDA path.
- ACE: the relational memory substrate that conversations can
  optionally live inside.

No other team has all of these. The substrate alone is years of
work. The application that exercises all of it is the wedge.

---

## Part 2 — The Doctrine of Invisibility

The single most leverage-y artifact in the project. Every PR is
reviewed against it. Adding to this list is engineering work that
must be paid for somewhere else (in the engines) to remove a surface
from the user.

### What we refuse to ship

- **No advanced settings.** Anywhere. There is no "advanced" tier.
  Every option is a doctrine failure to be paid down.
- **No codec picker.** The Compiler chooses. The user never knows
  the word "codec."
- **No device picker mid-call.** The Body Engine moves between
  surfaces. The user does not pick "use my phone's mic."
- **No relay picker.** The Route Brain chooses. No "use TURN"
  toggle.
- **No "your connection is unstable" toast.** Replace with: the
  Compiler descends a rung; the picture softens; nothing pops up.
- **No "reconnecting..." overlay.** Replace with: the Immune System
  prewarms a backup route invisibly. If the call drops, the Compiler
  goes to async capsule with no UI event.
- **No quality bars.** No bitrate readout. No latency display.
- **No error codes.** Ever. Including for engineers — the daemon
  logs codes locally but the UI never surfaces them.
- **No "call failed."** Calls do not fail. They convert to async.
- **No busy signal.** Replace with: capsule offer.
- **No "user not registered."** Replace with: invite flow that
  gives the recipient an invitation across whatever side channels
  exist (SMS, email, QR, NFC).
- **No "verify your phone number."** Replace with: QR pairing
  (`ol_pair_qr`, Row 2).
- **No CAPTCHA.** Ever. The substrate uses macaroon capabilities
  and rate-limiting at the protocol layer.
- **No "click to allow microphone access."** Ask once at install,
  in plain language, with rationale.
- **No "this app needs an update to call."** Updates are
  background, signed, gated by the Service Worker pubkey pinning
  (C2 fix).
- **No analytics consent banner.** We do not collect telemetry
  about users. We collect *call vitals* locally for the Immune
  System to learn from; they never leave the device.
- **No "subscribe for HD."** Quality is determined by network and
  engines, not by tier.
- **No paywall.** Calls are free for the people. Federated relay
  funds itself; see Part 13.
- **No "your call is being recorded for quality."** No silent
  recording. Ever.
- **No "missed call" badge with a number.** Replace with: the
  capsule itself in the chat surface. There are no "missed
  events"; there are only conversation states.

### What the engines must produce instead

- **State-of-network must be sensed, not surfaced.** The Immune
  System reads `_pair_health`, fragility scores, relay EWMA. It
  acts. It does not tell the user.
- **Transitions must be smooth.** Frame-level crossfade (200ms)
  between device handoff. Codec changes happen at I-frame boundaries
  with no visible artifact.
- **Failures must convert.** Every failure mode the Compiler is
  aware of maps to a rung on the ladder. The lowest rung is
  async-capsule, which is always achievable (it requires only the
  existing courier-bundle infrastructure to deliver).
- **Trust must be visible without being noisy.** A single calm
  provenance dot on the call surface. Tap to reveal: who, what,
  where, how, recording state. Never a popup, never a banner.
- **Identity must be felt, not entered.** First-call SAS
  verification reuses the `ol_pair_qr` 5-word SAS — visible briefly
  ("you and Alex share: amber river canyon meadow stone"), tap to
  confirm, never appears again unless keys rotate.

### The review rule

Every PR introducing user-visible string, setting, toggle, banner,
or status indicator must reference this section in the description
with a justification *for* the surface being a doctrine exception.
Default answer is no.

---

## Part 3 — Architecture Overview

### The mental model

```
                    ┌──────────────────────────┐
                    │      ONE BUTTON          │
                    │      "Call Mom"          │
                    └───────────┬──────────────┘
                                │
                ┌───────────────▼───────────────┐
                │     INTENSITY DIAL (Part 5)   │
                │   {ambient · low · med · high}│
                │   CRDT-backed shared state    │
                └───────────────┬───────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │           NINE HIDDEN ENGINES (Part 4)        │
        │                                               │
        │  Immune ──> Compiler ──> Body ──> Route       │
        │     │           │           │        │        │
        │     └───────────┴───────────┴────────┘        │
        │                  │                            │
        │  Reality ──> Priority ──> Predictive          │
        │                  │                            │
        │            Semantic ──> OneField R&D          │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────┐
        │            EXISTING SUBSTRATE (Part 9)        │
        │  WebRTC | QUIC | TCP | onion | linked-mesh    │
        │  PQ identity | macaroons | confidential       │
        │  duress | CRDT | ChunkRatchet | hwkey         │
        │  39 native Rust crates                        │
        └───────────────────────────────────────────────┘
```

### How a call flows (high-level)

1. User taps "Call Mom" on any device they own.
2. The Body Engine writes to the shared `CallSession` CRDT: "user
   intends to reach `mom_master_vk` at intensity HIGH."
3. The Compiler picks the highest viable rung based on negotiated
   capability intersection + last-known network conditions.
4. The Route Brain prewarms one or more paths.
5. The signaling layer emits CALL_INVITE messages to all of Mom's
   active devices.
6. Mom's Body Engine listens on all devices. The device most likely
   to be where Mom is (based on prior LWW state) renders the ring
   first; others fan out after 3 seconds.
7. Mom accepts on whichever surface she's at. The CRDT updates;
   other devices stop ringing.
8. Media negotiation completes. The Immune System starts its tick
   loop. The Reality Engine signs every frame from the moment
   capture begins.
9. The call runs at whatever rung is sustainable. The Compiler
   moves up or down as conditions change. Every transition is
   crossfaded.
10. End conditions: user-initiated hangup, mutual hangup, or
    Immune-System-converted-to-async. All three are graceful.
11. If async: the in-flight buffer becomes a voice note + chat
    record; live-resumable flag set for 10 minutes.
12. If conditions recover within the window: resume offer appears.

The user sees: the button → a face → a face for as long as
conditions allow → either a clean hangup or a calm capsule offer.

### Layered architecture diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                       PRESENTATION LAYER                        │
│         "Call Mom" button + face surface + capsule offer        │
│        (web/index.html + desktop wrapper + mobile shell)        │
└─────────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────┐
│                       CALL STATE LAYER                          │
│              CallSession (CRDT) — Part 5                        │
│   intensity | participants | active_surfaces | health | trust   │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────┐
│                       ENGINE LAYER                              │
│    9 controllers reading CallSession, writing requests          │
│    Immune | Compiler | Body | Route | Reality | Priority |      │
│    Predictive | Semantic | OneField                             │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────┐
│                       MEDIA LAYER                               │
│   RTP/SRTP audio/video tracks | semantic-delta channel          │
│   jitter buffer | AEC | AGC | crossfade | frame provenance      │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────────┐
│                       TRANSPORT LAYER (EXISTING)                │
│      WebRTC DTLS-SRTP | QUIC | TCP peer | onion | mesh radio    │
└─────────────────────────────────────────────────────────────────┘
```

### Engine responsibility map

| Engine | Reads | Writes | Tick rate |
|---|---|---|---|
| Immune | CallSession, _pair_health, _relay_metrics, homology, attestation | ImmuneDecision events | 100 ms |
| Compiler | CallSession, ImmuneDecision, capability intersection | Rung change requests | Event-driven |
| Body | CallSession, device states (linked-mesh), ISAC presence | Surface role updates (CRDT writes) | 500 ms |
| Route | _relay_metrics, ol_routing scores, fragility | Path prewarm + switch | 200 ms |
| Reality | Every emitted media frame | FrameProvenance tag | Per-frame |
| Priority | Compiler rung, available bandwidth | QoS class per stream | On rung change |
| Predictive | Received frames, model confidence | Locally-rendered ahead frames | Per-frame |
| Semantic | Negotiated caps, model-pack hash | Encoded delta stream | Per-frame |
| OneField R&D | Experimental cap flag | PINN waveform spec | Per-symbol |

---

## Part 4 — The Nine Engines

Each engine specified below has: purpose, data structures, state
machine, integration points (what it reads, what it writes), graduation
mode at launch, thresholds, soak-test pattern.

---

### 4.1 Call Immune System

**Purpose:** Watches the call's vital signs. Requests representation
changes when the user is being or about to be harmed.

**Architectural firewall:** Never touches media directly. Emits
*requests* to downstream engines (Compiler, Route, Body) each of which
has refusal authority.

#### Data structures

```python
# src/one_link/call_immune.py — NEW MODULE

from dataclasses import dataclass
from enum import Enum
from typing import Optional

class PathClass(Enum):
    LOCAL  = 0     # same device (multi-device body internal)
    LAN    = 1     # local network
    DIRECT = 2     # P2P direct via WAN
    RELAY  = 3     # via federated relay
    ONION  = 4     # via onion circuit
    MESH   = 5     # OneField radio mesh (future)

class DeviceRole(Enum):
    MIC      = 0
    CAM      = 1
    DISPLAY  = 2
    SPEAKER  = 3
    RELAY    = 4
    HELPER   = 5
    INACTIVE = 6

class ThermalState(Enum):
    NOMINAL  = 0
    WARM     = 1
    HOT      = 2
    CRITICAL = 3

@dataclass(frozen=True)
class CapabilitySnapshot:
    semantic_media_v1: bool
    predictive_continuity_v1: bool
    onefield_radio_v1: bool
    confidential_tier: int      # 0 = software, 1 = TPM, 2 = SGX/SEV, 3 = SE
    model_pack_hash: Optional[str]

@dataclass(frozen=True)
class CallVitals:
    """Snapshot of all health signals at a single 100ms tick.
       Pure read; no I/O. Composes from existing daemon state.
       Hashable for soak-replay determinism."""
    call_id: str
    peer_fp: str
    tick: int                          # monotonic, 100ms per

    # Transport health (from _PairHealth + _relay_metrics)
    rtt_ewma_ms: float
    loss_rate_ewma: float              # 0.0..1.0
    jitter_ms: float                   # frame-arrival std-dev
    bandwidth_estimate_kbps: float

    # Path topology (from ol_routing + ol_homology)
    path_class: PathClass
    path_fragility_score: float        # 0=robust 1=critical
    backup_routes_warm: int

    # Device state (from linked-mesh)
    own_device_role: DeviceRole
    own_battery_pct: Optional[float]
    own_thermal_state: ThermalState
    peer_device_present: bool

    # Media health (from in-call instrumentation)
    audio_frames_received: int
    audio_frames_dropped: int
    video_frames_received: int
    video_frames_predicted: int
    confirm_ratio_voice: float
    confirm_ratio_video: float

    # Trust state (from attestation)
    path_attested: bool
    capability_state: CapabilitySnapshot

    def vitals_hash(self) -> str:
        """BLAKE3 over canonical encoding. Used by ImmuneDecision."""
        import hashlib
        return hashlib.blake2b(repr(self).encode(), digest_size=16).hexdigest()


class ImmuneAction(Enum):
    HOLD                   = 0
    PREWARM_BACKUP_ROUTE   = 1
    SWITCH_ROUTE           = 2
    REQUEST_LOWER_FIDELITY = 3
    REQUEST_VOICE_ONLY     = 4
    SUGGEST_DEVICE_HANDOFF = 5
    CONVERT_TO_ASYNC       = 6
    EMERGENCY_REKEY        = 7

@dataclass(frozen=True)
class ImmuneDecision:
    action: ImmuneAction
    reason_code: str              # "loss_above_p90", "fragility_critical", etc.
    triggered_by: list[str]       # field names that crossed threshold
    confidence: float             # 0..1 for SHADOW-mode learning
    tick: int
    vitals_hash: str
```

#### State machine

```
                       ┌─────────────────────────┐
                       │  TickLoop @ 100ms       │
                       │  (call lifecycle scope) │
                       └────────────┬────────────┘
                                    │
                       ┌────────────▼────────────┐
                       │  Sense: build CallVitals│
                       └────────────┬────────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
        ┌─────────▼────────┐ ┌──────▼──────┐ ┌────────▼─────────┐
        │ Transport Health │ │ Path Brain  │ │ Device Wellness  │
        │ Controller       │ │ Controller  │ │ Controller       │
        └─────────┬────────┘ └──────┬──────┘ └────────┬─────────┘
                  │                 │                 │
                  └─────────────────┼─────────────────┘
                                    │
                       ┌────────────▼────────────┐
                       │ Arbitrator              │
                       │ (highest-severity wins) │
                       └────────────┬────────────┘
                                    │
                       ┌────────────▼────────────┐
                       │ ImmuneDecision          │
                       │ → Presence Compiler     │
                       │ → Route Brain           │
                       │ → Multi-Device Body     │
                       │ → audit_log.append()    │
                       └─────────────────────────┘
```

Three sub-controllers run in parallel each tick. The Arbitrator
selects the highest-severity action.

**Severity ordering** (highest first):
```
EMERGENCY_REKEY > CONVERT_TO_ASYNC > SWITCH_ROUTE >
REQUEST_VOICE_ONLY > REQUEST_LOWER_FIDELITY >
SUGGEST_DEVICE_HANDOFF > PREWARM_BACKUP_ROUTE > HOLD
```

#### Thresholds with hysteresis

```python
class TransportHealthController:
    # Two thresholds per signal: trigger + recover.
    # Recover < trigger / 2 enforces hysteresis.

    RTT_PREWARM_TRIGGER_MS = 400.0   # prewarm backup
    RTT_PREWARM_RECOVER_MS = 180.0
    RTT_SWITCH_TRIGGER_MS  = 800.0   # switch active
    RTT_SWITCH_RECOVER_MS  = 350.0

    LOSS_DEGRADE_TRIGGER   = 0.05    # 5% loss
    LOSS_DEGRADE_RECOVER   = 0.02
    LOSS_VOICE_TRIGGER     = 0.15
    LOSS_VOICE_RECOVER     = 0.05
    LOSS_ASYNC_TRIGGER     = 0.35
    LOSS_ASYNC_RECOVER     = 0.10

    JITTER_DEGRADE_MS      = 80.0

    def decide(self, v: CallVitals, last: Optional[ImmuneDecision]) -> ImmuneDecision:
        ...
```

**How thresholds are tuned:** Defaults are *initial* values. After 1k
call-minutes of dogfooding (Tier γ SHADOW mode), pull the actual
distribution of `_pair_health.latency_ewma_ms` and `loss_rate_ewma`
from the audit log. Set `PREWARM = p90`, `SWITCH = p99`. This is the
same methodology that tuned the relay-bandit thresholds in v0.21.
Reuse the existing audit-log infrastructure.

#### Integration points

| Subscribes (existing) | Where |
|---|---|
| `Daemon._pair_health[peer_fp]` | every tick |
| `Daemon._relay_metrics[relay_id]` | every tick |
| `routing_native.homology_score(path)` | every tick |
| `confidential_native.current_tier()` | on capability event |
| `Daemon._linked_devices()` | on device-state event |
| `MediaPipeline.frame_stats()` | every tick (NEW) |

| Publishes (new) | Where |
|---|---|
| `PresenceCompiler.request(action)` | each tick if action != HOLD |
| `RouteBrain.request(action)` | each tick if action ∈ {PREWARM, SWITCH} |
| `MultiDeviceBody.suggest(action)` | each tick if action == HANDOFF |
| `audit_log.append(decision)` | every tick, including HOLD |

#### Graduation modes

- **SHADOW (Tier γ):** controller landed, decisions written to audit
  log, no actions emitted. Run for 1k call-minutes of dogfooding.
- **ASSIST (Tier δ):** controller can emit `REQUEST_LOWER_FIDELITY`,
  `PREWARM_BACKUP_ROUTE` only. Cannot switch or convert to async
  without user-equivalent confirmation.
- **AUTOPILOT (Tier η):** all actions enabled. Soak gate ≥95%
  survival on 50k random network scenarios.

#### Three non-obvious invariants

1. **The Arbitrator must be pure.** Given the same `CallVitals` it
   must always emit the same `ImmuneDecision`. The `vitals_hash` in
   each decision allows soak-replay to verify this.
2. **Every decision is logged, even HOLDs.** This is the dataset for
   graduating SHADOW → ASSIST → AUTOPILOT.
3. **The system can refuse to act.** If `confirm_ratio_voice > 0.98`
   and `loss_rate_ewma < 0.02`, it returns HOLD even if RTT crosses
   the prewarm threshold. The threshold is necessary but not
   sufficient. The Immune System reasons about whether the user is
   *currently* being harmed.

#### Soak harness

```python
# tests/test_call_immune_soak.py — NEW

@pytest.mark.parametrize("iters", [int(os.getenv("ONE_LINK_SOAK_ITERS", "2000"))])
def test_immune_system_survives_random_degradation(iters):
    """For N random call-degradation scenarios:
       1) Call ends in {alive, graceful_async, user_terminated}.
          NEVER dead_unrecoverable.
       2) No decision oscillates >3 times in any 1-second window.
       3) Median decision latency < 50ms.
       4) When fragility_score > 0.8, action ∈ {prewarm, switch, async} ≥ 95%.
       5) Reality Engine provenance never drops in a transition."""
    ...
```

Acceptance gate: ≥95% call survival, <1% oscillation, <50ms decision
latency. Run 2k by default, 50k nightly via `ONE_LINK_SOAK_ITERS`.

---

### 4.2 Presence Compiler

**Purpose:** Compiles "this user wants to be present to that user at
intensity X" into a concrete media representation that is sustainable
on the current path with the current devices.

**Surface to user:** invisible. The user sees a face, hears a voice,
or sees the capsule. They never see "you are now on rung 4."

#### Data structures

```python
# src/one_link/presence_compiler.py — NEW MODULE

from dataclasses import dataclass
from enum import Enum

class Rung(Enum):
    """Representation rungs, ordered by fidelity (0 = highest)."""
    RAW_AV             = 0   # full WebRTC video + audio
    OPUS_VIDEO         = 1   # adaptive bitrate Opus + VP9
    SEMANTIC_DELTA_AV  = 2   # neural codec voice + face deltas (Tier ζ+)
    FACE_STILL_MOTION  = 3   # face still + lip-sync from audio
    AUDIO_ONLY         = 4   # Opus audio, video off
    PUSH_TO_TALK       = 5   # discrete utterances
    CONCEPT_TEXT       = 6   # ConceptFrame semantic transmission
    ASYNC_CAPSULE      = 7   # call → voice note + chat
    AMBIENT_PRESENCE   = 8   # below "call" — presence dot only

@dataclass(frozen=True)
class RungSpec:
    rung: Rung
    name: str
    min_kbps: float
    min_confirm_ratio: float | None       # None = doesn't need predictive
    requires_caps: list[str]
    audio_codec: str | None
    video_codec: str | None
    semantic_channel: bool

LADDER: list[RungSpec] = [
    RungSpec(Rung.RAW_AV,            "raw_av",            1000.0, None, ["WEBRTC_AV_V1"],            "opus", "vp9",  False),
    RungSpec(Rung.OPUS_VIDEO,        "opus_video",         300.0, None, ["WEBRTC_AV_V1"],            "opus", "vp9",  False),
    RungSpec(Rung.SEMANTIC_DELTA_AV, "semantic_delta_av",   30.0, 0.95, ["SEMANTIC_MEDIA_V1"],       None,   None,   True),
    RungSpec(Rung.FACE_STILL_MOTION, "face_still_motion",   10.0, 0.90, ["SEMANTIC_MEDIA_V1"],       "opus", None,   True),
    RungSpec(Rung.AUDIO_ONLY,        "audio_only",          16.0, None, ["WEBRTC_AV_V1"],            "opus", None,   False),
    RungSpec(Rung.PUSH_TO_TALK,       "push_to_talk",         3.0, None, ["WEBRTC_AV_V1"],            "opus", None,   False),
    RungSpec(Rung.CONCEPT_TEXT,       "concept_text",         0.1, None, ["SEMANTIC_MEDIA_V1"],       None,   None,   True),
    RungSpec(Rung.ASYNC_CAPSULE,      "async_capsule",        0.0, None, [],                           None,   None,   False),
    RungSpec(Rung.AMBIENT_PRESENCE,   "ambient_presence",     0.0, None, [],                           None,   None,   False),
]
```

#### Compiler logic

```python
class PresenceCompiler:
    def __init__(self, session: CallSession, audit_log: AuditLog):
        self.session = session
        self.audit_log = audit_log
        self.current_rung: Rung = Rung.RAW_AV
        self.last_ascent_tick: int = 0
        ASCENT_HYSTERESIS_TICKS = 100   # 10 seconds at 100ms tick

    def viable_rungs(self) -> list[RungSpec]:
        """Apply capability-intersection mask + bandwidth filter."""
        peer_caps = self.session.peer_capabilities
        bw = self.session.last_vitals.bandwidth_estimate_kbps
        return [
            r for r in LADDER
            if all(c in peer_caps for c in r.requires_caps)
            and r.min_kbps <= bw
        ]

    def request(self, action: ImmuneAction) -> None:
        """Receive request from Immune System or user."""
        target = self._action_to_rung(action)
        self._transition_to(target)

    def _transition_to(self, target: Rung) -> None:
        """Descend aggressively, ascend slowly."""
        if target.value > self.current_rung.value:
            # Descend immediately
            self._do_transition(target)
        elif target.value < self.current_rung.value:
            # Ascend only after hysteresis window
            if self.session.tick - self.last_ascent_tick < ASCENT_HYSTERESIS_TICKS:
                return
            self._do_transition(target)
            self.last_ascent_tick = self.session.tick

    def _do_transition(self, target: Rung) -> None:
        # Emit transition event with 200ms crossfade for media-track changes
        ...
```

#### Two invariants

1. **Monotone-descent / slow-ascent.** Drops happen instantly; rises
   require 10 seconds of stable conditions. Prevents oscillation
   that the user would feel as flicker.
2. **Capability mask is enforced first.** Rung 2 (semantic) is
   invisible to the Compiler unless both peers advertise
   `SEMANTIC_MEDIA_V1` AND model-pack hashes match.

#### Rung 7 → conversation continuity

When the Compiler descends to `ASYNC_CAPSULE`, it does *not* end
the call. It does:

1. Emit `CallSession.convert_to_async()` event.
2. Persist the in-flight buffer as a voice note via the existing
   v0.9.2 voice-message infrastructure
   ([tests/test_voice_messages_v092.py](../tests/test_voice_messages_v092.py)).
3. Hand the conversation context to the chat layer
   ([src/one_link/state.py](../src/one_link/state.py)).
4. Set `live_resumable_until = now + 10 minutes`.
5. Both parties' chat surfaces show a calm "voice note in progress"
   indicator until the buffer flushes; then a "tap to resume" affordance
   appears.

If conditions recover inside the window, the resume affordance
triggers a new call invite with `resume_of = <prior_call_id>` so the
ACE memory substrate (if present) can stitch them into one
conversation object.

#### Integration points

| Reads | Source |
|---|---|
| `CallSession.intensity` | the dial |
| `CallSession.peer_capabilities` | via CAP negotiation |
| `ImmuneDecision` requests | from Immune System |
| `CallVitals.bandwidth_estimate_kbps` | from media pipeline |

| Writes | Target |
|---|---|
| `CallSession.current_rung` | CRDT (LWW) |
| MediaPipeline rung-change events | RTP/SRTP track reconfigure |
| `audit_log` | per transition |

---

### 4.3 Multi-Device Body Engine

**Purpose:** Makes "your devices are organs" architecturally real. The
user is one entity; their devices are surfaces that present them.

**The hardest engine to build right.** Cross-device, cross-network
state convergence with sub-200ms handoff atomicity.

#### Shared state (CRDT)

```python
# src/one_link/body_engine.py — NEW MODULE

from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class SurfaceCapability:
    has_mic: bool
    has_cam: bool
    has_display: bool
    has_speaker: bool
    can_relay: bool
    mic_quality_score: float       # 0..1, learned from prior calls
    cam_quality_score: float
    display_size_px: tuple[int, int] | None
    is_battery_powered: bool
    is_charging: Optional[bool]

@dataclass(frozen=True)
class DeviceCallState:
    device_id: str               # HKDF-derived subkey id
    capability: SurfaceCapability
    role: DeviceRole             # MIC | CAM | DISPLAY | SPEAKER | RELAY | HELPER | INACTIVE
    alive_at_ms: int             # monotonic clock from device
    battery_pct: Optional[float]
    thermal_state: ThermalState
    network_class: PathClass     # what does this device see?

@dataclass
class ParticipantState:
    """CRDT-merged state for one participant in a call."""
    master_vk: bytes
    active_devices: dict[str, DeviceCallState]  # OR-set keyed by device_id
    primary_mic: 'LWWRegister[str]'             # device_id
    primary_cam: 'LWWRegister[str]'
    primary_display: 'LWWRegister[str]'
    primary_speaker: 'LWWRegister[str]'
    preferred_relay: 'LWWRegister[str]'
    last_seen_location: 'LWWRegister[str]'      # opaque token from ISAC or app context

@dataclass
class CallSession:
    """Top-level CRDT for the call. Each device publishes its own
       fragment; merge converges."""
    call_id: str
    intensity: 'LWWRegister[Intensity]'         # AMBIENT | LOW | MED | HIGH
    participants: dict[bytes, ParticipantState] # keyed by master_vk
    current_rung: 'LWWRegister[Rung]'
    started_at_ms: int
    ended_at_ms: Optional[int]
    resume_of: Optional[str]                    # prior call_id if resuming
    conversation_id: Optional[str]              # ACE conversation object
    audit_path: 'LWWSet[FrameProvenance]'       # frame attestations
```

All structures use the existing `ol_crdt` lattice machinery:
[src/one_link/crdt.py](../src/one_link/crdt.py) + native crate.

#### Surface arbitration algorithm

When multiple devices could play a role (e.g., both phone and laptop
have a mic), the Body Engine picks by score:

```
score(device, role=MIC) =
    role_quality_score(device, MIC)               * 0.40
  + (1 - thermal_penalty(device.thermal_state))   * 0.20
  + battery_penalty(device)                       * 0.15
  + network_class_score(device.network_class)     * 0.15
  + recency_score(device.alive_at_ms)             * 0.10
```

Each device computes the score locally and writes its preference into
the CRDT LWW register. The lattice converges; both devices observe the
same winner; ties go to lexicographic device_id (deterministic).

#### Crossfade protocol (the genuinely hard part)

Mic moves phone → laptop. Both are on different networks. Without
care, the receiver hears a glottal seam.

```
        Phone mic         Laptop mic        Receiver buffer
        ─────────         ──────────        ───────────────
T=0     producing →                          fading_in phone
T=1     producing →                          phone (steady)
                          (request to take over emitted)
                          (200ms crossfade window starts)
T=2     producing →       producing →        jitter buffer picks
                                              best frame per slot
T=2.2   stopped           producing →        laptop (steady)
                                              fade-in phone
                                              complete
```

Protocol:

1. Old surface (phone) receives `surface_handoff_request(MIC, target=laptop, fade_ms=200)`.
2. Both devices emit RTP packets *simultaneously* for 200 ms.
3. Receiver's jitter buffer, per output slot, selects the higher-
   confidence frame (each frame carries a `produce_confidence` field
   in the FrameProvenance header).
4. After 200 ms, old surface stops. New surface continues.
5. Reality Engine badge updates: `cam: desktop · mic: phone → laptop`.

No "switching device..." indicator. The user experiences continuous
audio with a millisecond-level seam at worst, indistinguishable from
the codec's normal frame-boundary artifacts.

#### Integration points

| Reads | Source |
|---|---|
| `linked_mesh.devices()` | row 8 substrate |
| `ISAC.presence_probe()` | for "user is in this room" hints |
| device hardware events (charging, thermal) | OS APIs |

| Writes | Target |
|---|---|
| `CallSession.participants[me].primary_*` | CRDT LWW |
| Surface-handoff RTP frames | media pipeline |

#### Graduation modes

- **OFF (Tier α-δ):** single-device per participant. The substrate
  is in place; the algorithm is dormant.
- **ASSIST (Tier ε):** the Body Engine *suggests* a handoff
  ("your laptop has a better mic, switch?"); user confirms.
- **AUTOPILOT (Tier θ):** automatic, crossfaded, invisible.

---

### 4.4 Route Consciousness Engine

**Purpose:** Predicts the future of every available path. Prewarms
backups before primaries die. Switches before the user feels pain.

**Substrate-heavy:** most signals exist already.

#### Data structures

```python
# src/one_link/route_brain.py — NEW MODULE

@dataclass
class RouteCandidate:
    path_id: str
    path_class: PathClass
    rtt_ewma_ms: float
    loss_rate_ewma: float
    bandwidth_kbps: float
    fragility_score: float            # ol_homology
    tau_c_score: float                # ol_routing
    attested: bool
    warm: bool                        # connection already established
    last_used_ms: Optional[int]
    cost_score: float                 # composite

@dataclass
class RouteState:
    active: RouteCandidate
    warm_backups: list[RouteCandidate]    # sorted by cost_score
    cold_alternatives: list[RouteCandidate]
```

#### Decision algorithm

```python
class RouteBrain:
    def __init__(self, session: CallSession):
        self.session = session
        self.state: RouteState = ...

    def on_immune_request(self, action: ImmuneAction) -> None:
        if action == ImmuneAction.PREWARM_BACKUP_ROUTE:
            self._prewarm_top_alternative()
        elif action == ImmuneAction.SWITCH_ROUTE:
            self._switch_to_warmest_backup()

    def _prewarm_top_alternative(self) -> None:
        # Compute cost_score for all cold alternatives
        # Establish full handshake on top-1
        # Move it into warm_backups
        ...

    def _switch_to_warmest_backup(self) -> None:
        # Issue media-redirect to peer's signaling channel
        # Receive ACK
        # Crossfade media to new path (using same 200ms protocol as Body)
        ...
```

#### Composite cost score

```
cost(path) =
    rtt_score(path.rtt_ewma_ms)               * 0.25
  + loss_score(path.loss_rate_ewma)           * 0.30
  + (1 - path.fragility_score)                * 0.20
  + path.tau_c_score                          * 0.10
  + attestation_score(path.attested)          * 0.10
  + warmth_score(path.warm)                   * 0.05
```

Same scoring style as `_pick_best_relay()` (existing). Reused with
call-specific weights.

#### Integration points

| Reads | Source |
|---|---|
| `Daemon._relay_metrics` | existing |
| `routing_native.candidate_paths(peer_fp)` | existing (Row 4) |
| `ol_homology.fragility_score(path)` | existing |
| `ol_prefetch` predicted-load | existing (Row 4D) |

| Writes | Target |
|---|---|
| Path-switch signaling messages | new wire type `MEDIA_REDIRECT` |
| Warmth state per candidate | local to engine |
| `audit_log` per decision | shared |

---

### 4.5 Cryptographic Reality Engine

**Purpose:** Every media segment carries a verifiable provenance tag.
The receiver always knows: who made this frame, on what device, by what
method (real / repaired / predicted / reconstructed), over what path,
with recording in what state.

**The single most important safety system.** Makes advanced media safe
instead of creepy.

#### Frame provenance schema

```python
# src/one_link/frame_provenance.py — NEW MODULE

from enum import Enum

class FrameKind(Enum):
    REAL          = 0   # captured live from physical sensor
    REPAIRED      = 1   # missing samples filled by PLC
    PREDICTED     = 2   # rendered ahead by Predictive Continuity
    RECONSTRUCTED = 3   # rendered from semantic delta + model
    BLANK         = 4   # placeholder (camera off, etc.)

class RecordingState(Enum):
    NOT_RECORDING       = 0
    RECORDING_LOCAL     = 1   # only this device's side
    RECORDING_REMOTE    = 2   # peer is recording (consent required)
    RECORDING_MUTUAL    = 3   # both sides agreed

@dataclass(frozen=True)
class FrameProvenance:
    """32-byte HMAC tag attached to every media segment.
       Verifiable by the receiver against the sender's macaroon chain."""
    schema_version: int               # 1
    segment_hash: bytes               # BLAKE3-256 of segment content
    device_id: str                    # which sender device produced it
    frame_kind: FrameKind
    path_class: PathClass             # local / lan / direct / relay / onion
    recording_state: RecordingState
    timestamp_us: int
    produce_confidence: float         # for Body crossfade selection
    capability_chain_id: bytes        # which macaroon chain attests this
    hmac: bytes                       # over canonical(self) using chain key
```

#### Wire format

The provenance tag is **inline** with every media frame. It piggybacks
on the per-chunk header in the existing `ol_aead` AEAD pipeline. No
new framing.

```
┌─────────────────────────────────────────────────────────────┐
│ Outer transport (DTLS-SRTP or QUIC)                          │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Media frame (RTP packet or QUIC datagram)               │ │
│ │ ┌────────────────────┬────────────────────────────────┐ │ │
│ │ │ FrameProvenance(32B)│ AEAD(content)                  │ │ │
│ │ └────────────────────┴────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

#### Verification flow

1. Sender's device holds a per-call macaroon chain rooted in the
   device subkey (`ol_capability` chain).
2. For each frame: compute `hmac = HMAC-SHA256(chain_key,
   canonical(provenance_minus_hmac))`.
3. Embed in frame header.
4. Receiver caches the chain root on call setup.
5. For each frame: recompute, compare.
6. Mismatch → drop the frame, log, increment counter; if 3 mismatches
   within a 1-second window → `ImmuneAction.EMERGENCY_REKEY`.

The cost is one HMAC per frame. At 50 audio fps + 30 video fps = 80
HMACs/sec per direction. On any modern CPU this is <0.1% CPU. SIMD
HMAC-SHA256 in `ol_aead` makes it negligible.

#### UI surface (the only visible piece)

```
┌──────────────────────────────────────────┐
│  📞  Mom                                  │
│                                           │
│  ┌─────────────────────────┐              │
│  │                         │   • Mom      │
│  │                         │              │
│  │      [face video]       │              │
│  │                         │              │
│  │                         │              │
│  └─────────────────────────┘              │
│                                           │
│  🟢                                        │
└──────────────────────────────────────────┘

Tap the green dot →

┌──────────────────────────────────────────┐
│   Trust                                   │
│                                           │
│   Real                                    │
│   Local network                           │
│   Not recording                           │
│   You verified Mom on Mar 4                │
│                                           │
└──────────────────────────────────────────┘
```

When the Compiler descends to `FACE_STILL_MOTION` (rung 3, semantic),
the dot changes color and the detail shows "Reconstructed from model
(same Mom you verified)". When the Route Brain switches from LAN to
relay, "Local network" → "Via relay". The user is never lied to.

#### Integration points

| Reads | Source |
|---|---|
| Capability chain for this call | `ol_capability` |
| Frame data | media pipeline |
| Recording state | session |
| Path class | Route Brain current state |

| Writes | Target |
|---|---|
| Provenance tag inline in every frame | media pipeline |
| UI badge state | presentation layer |
| Mismatch counter | audit log |

#### Graduation modes

**AUTOPILOT day one.** This is a safety system. It is never opt-in,
never opt-out (you cannot disable it without disabling the call).

---

### 4.6 Human Signal Priority Engine

**Purpose:** Under bandwidth pressure, the human survives. Voice
beats video; intelligibility beats fidelity; faces beat backgrounds;
files cede to media.

**Architecture:** transport-layer detail, not a feature. Ships
AUTOPILOT day one.

#### QoS class hierarchy

```python
class QoSClass(Enum):
    P0_VOICE                  = 0   # intelligibility-critical
    P1_TIMING                 = 1   # turn-taking signals, ack pings
    P2_FACE_PRIMARY           = 2   # primary face region (semantic)
    P3_GESTURE                = 3   # hands, body pose
    P4_FILE_INFLIGHT          = 4   # files in transit
    P5_VIDEO_BACKGROUND       = 5   # background pixels
    P6_AMBIENT                = 6   # background environmental data
```

#### Stream mapping

Each QoS class gets its own QUIC stream (or RTP SSRC for WebRTC paths).
Loss in one class never blocks another.

```
QUIC connection
├── stream 0: control / signaling
├── stream 1: P0_VOICE  ← priority 1 (highest weight)
├── stream 2: P1_TIMING ← priority 2
├── stream 3: P2_FACE
├── stream 4: P3_GESTURE
├── stream 5: P4_FILE
├── stream 6: P5_BACKGROUND
└── stream 7: P6_AMBIENT
```

QUIC's existing priority/weight mechanism (`ol_quic`) carries the
weighting to the wire. When bandwidth drops, P5 and P6 cede first.

#### Integration points

| Reads | Source |
|---|---|
| Current rung | Compiler |
| Active streams | media pipeline |

| Writes | Target |
|---|---|
| Per-stream priority | QUIC stack |

---

### 4.7 Predictive Continuity Engine

**Purpose:** When a frame doesn't arrive, the receiver renders an
educated guess. When the real frame arrives, the system corrects.
Prediction repairs continuity; it never lies about reality (the
Reality Engine flags every predicted frame).

#### Substrate

OneField's `voice.cl` and `video.cl` already define:
- `PredictiveState`
- `should_render_predictively(state, ...)`
- `step_predictive_render(state)`
- `on_delta_arrival(state, novelty) → confirmed | corrected`
- `confirm_ratio()` — the dashboard metric

Lookahead cap: 4 voice frames, 8 video frames (per `voice.cl` /
`video.cl` spec).

#### Algorithm sketch

```python
# src/one_link/predictive_continuity.py — NEW MODULE

@dataclass
class PredictiveState:
    last_real_frame: MediaFrame
    last_real_frame_at_us: int
    predicted_count_since_real: int
    confirm_count: int
    correct_count: int
    model_confidence: float

class PredictiveContinuity:
    MAX_LOOKAHEAD_AUDIO_FRAMES = 4
    MAX_LOOKAHEAD_VIDEO_FRAMES = 8

    def on_frame_due(self, state: PredictiveState) -> MediaFrame:
        if state.predicted_count_since_real >= self.MAX_LOOKAHEAD_AUDIO_FRAMES:
            # We've predicted past our budget. Render silence/freeze + flag.
            return BlankFrame(kind=FrameKind.BLANK)
        predicted = self._extrapolate(state)
        state.predicted_count_since_real += 1
        # Tag with FrameKind.PREDICTED — Reality Engine signs it as such
        return predicted

    def on_real_frame_arrives(self, state: PredictiveState, real: MediaFrame) -> None:
        novelty = self._compute_novelty(state.last_real_frame, real)
        if novelty < CONFIRM_THRESHOLD:
            state.confirm_count += 1
        else:
            state.correct_count += 1
            self._emit_correction(real)
        state.last_real_frame = real
        state.predicted_count_since_real = 0
```

`confirm_ratio = confirm_count / (confirm_count + correct_count)`. When
this exceeds 0.98, the receiver is effectively rendering ahead of the
sender. This remains a research graduation target until real browser samples
are synthesized, inserted into playout, and physically qualified end to end.

#### Integration with Reality Engine

Every predicted frame's `FrameProvenance.frame_kind = PREDICTED`. The
Reality badge changes from "Real" to "Reconstructed (predicted)" until
real frames resume. No silent fakery.

#### Graduation modes

- **OFF (Tier α-δ):** standard codec PLC only.
- **ASSIST (Tier η):** voice predictive only. A/B against Opus PLC.
- **AUTOPILOT (Tier η+):** voice + video predictive.

---

### 4.8 Semantic Video / Voice Engine

**Purpose:** The alien tier. Transmit *intent* and *meaning*, not
pixels and samples. The receiver reconstructs presence from a shared
model + a tiny delta on the wire.

**Research-grade.** The math + protocol ship in OneField source today
([voice.cl](../../../OneField%20Mesh/onefield/app/builtin/voice.cl),
[video.cl](../../../OneField%20Mesh/onefield/app/builtin/video.cl)).
Trained model weights do not exist yet; producing them is
research-grade GPU work on curated datasets.

#### Wire format

Voice: `ArticulatoryFrame` (state) + `VoiceDelta` (change).

```
VoiceDelta:
  schema:  u16 (1)
  seq:     u32
  speaker: u8   (which speaker model)
  bits:    [0..60]  delta bits packed; rest = silence
```

At 50 fps: max 3 kbps, typical 0.5-1.5 kbps. Compare Opus 16k = 16 kbps.

Video: `Scene` (graph) + `VideoDelta` (graph mutation).

```
VideoDelta:
  schema:    u16 (1)
  seq:       u32
  scene_id:  u32
  face_pose: [6 floats] (head pose 6DoF)
  expr:      [16 floats] (FACS-coded expression)
  gaze:      [2 floats]
  mouth:     [22 floats] (visemes)
  hands:     optional [n × pose]
  scene_cuts: optional bool
```

Typical: ~24 bytes/frame stable talking-head. ~1 KB keyframe.

#### Capability negotiation

```
CAP: SEMANTIC_MEDIA_V1
  model_pack_hash: "blake3:abc..."   # both peers must match
  model_pack_version: "voice-1.0,video-1.0"
  model_pack_entropy_bits: 512        # for quantum-resistance claim
```

If hashes don't match: Compiler masks rungs 2, 3, 6 from the ladder.
The user never knows the option existed. The call uses Opus/VP9.

#### Model pack distribution

Out-of-band over the existing file transfer pipeline. Model packs:
- Are signed by a trusted model-pack issuer (initial: project root).
- Are content-addressed by BLAKE3 hash.
- Have versioned schemas; backward-compatible model loaders.
- Are sized ~10-50 MB voice, ~50-200 MB video.
- Are cached locally per-device.
- Refuse to load if the issuer signature fails.

#### Integration with Reality Engine

Semantic-reconstructed frames get `FrameKind.RECONSTRUCTED`. The
provenance tag carries the `model_pack_hash` so the receiver can prove
which model produced the reconstruction. If a sender swaps models
mid-call, the chain breaks; the Immune System rekeys.

#### Honest research dependencies

| What | Status |
|---|---|
| Math, Python codec substrate, predicates, tests | Present; research-only |
| Trained predictor checkpoints (voice + scene) | Vendored ONNX/PT research checkpoints |
| Browser capture -> semantic wire -> receiver playout | Not implemented |
| Encoder/decoder ported to Rust crate | Not started |
| Model-pack identity in negotiated CAPS | Not implemented |
| Model-pack signing infrastructure | Not started |
| Human intelligibility/MOS and physical two-device qualification | Not completed |

The predictor/codec research substrate is not the user feature. Tier ζ+
cannot be advertised until browser capture, negotiated wire transport,
receiver reconstruction/playout, model-pack identity/signing, and physical
two-device quality gates all close. The stable capability registry therefore
keeps ζ/η/θ in `PREVIEW_CAPABILITIES`, outside `LOCAL_CAPABILITIES`.
Stable release artifacts also exclude the model/runtime payload. An explicit
`build_binary.py --include-preview-ml` engineering build packages the validated
research substrate without enabling or advertising those capabilities.

#### Graduation modes

- **OFF (Tier α-ε):** capability not advertised.
- **EXPERIMENTAL (Tier ζ):** voice-only, capability-gated, A/B
  against Opus 32k on 20-call corpus. Measure intelligibility MOS.
  Do not promise quality.
- **OPT-IN (Tier θ):** voice + video, both peers must have model
  packs. Compiler will pick semantic rungs when network can't
  sustain Opus/VP9.

---

### 4.9 OneField R&D Engine

**Purpose:** Bridge to OneField. When OneField hardware is present
(HackRF mesh, future PINN waveform synth), the call can route over
the physics-level substrate. Today: stub; later: full mesh radio.

**Future surface.** Listed here for architectural completeness; no
active build target until OneField hardware is operational.

#### What it would enable

- Calls with no internet at all (mesh-radio peer-to-peer).
- Frequency-agnostic operation (VLF for through-water, mmWave for
  clear-air bursts).
- Negative-SNR reception with shared model prior (~–25 dB SNR
  feasibility per OneField proof).
- Bounded-latency conversations across arbitrary RTT (intent-as-
  channel + Predictive Continuity scaled to seconds-of-prediction).

#### Capability gate

```
CAP: ONEFIELD_RADIO_V1
  hardware_class: enum {HACKRF_PRO, FUTURE_NATIVE_RF}
  band_set: bitfield (which bands the device can transmit/receive)
  compliance_region: enum (FCC, ETSI, ...)  // for safety rails
```

Same capability-gating, opt-in model as Semantic Engine. Never default.

#### Honest status

The HackRF Pro has not yet arrived in the OneField project. The
field-test harness exists; the radio does not. Tier θ+ depends on
this hardware. Do not block earlier tiers on it.

---

## Part 5 — Shared State (CRDT)

### Why CRDT and not state machine

Both ends of a call have their own opinion of {who, what, where, how,
health, fallback}. They sync via vector clock + LWW + OR-set — the
same machinery that ships in [src/one_link/crdt.py](../src/one_link/crdt.py)
today. Each device writes its local view; the lattice converges.

**This matters because:**

- Multi-device Body Engine needs both ends to agree on which device
  is mic vs cam. If one peer's phone goes to sleep, the device-role
  state must converge to "mic moved to laptop" without a synchronous
  round-trip.
- Async-capsule conversion needs both sides to agree the call ended
  in async and what the final state was. CRDT merge handles network
  partition gracefully.
- Resume after capsule needs the next call to inherit the prior
  conversation's state (intensity history, last verified identity,
  preferred surfaces).

### CallSession schema (canonical)

```python
@dataclass
class CallSession:
    # Identity
    call_id: str                                   # ULID
    conversation_id: Optional[str]                 # ACE conversation, if any
    resume_of: Optional[str]                       # prior call_id
    started_at_ms: int

    # Intensity dial — the primary surface
    intensity: 'LWWRegister[Intensity]'            # AMBIENT < LOW < MED < HIGH
    target_intensity: 'LWWRegister[Intensity]'     # what user requested
    current_rung: 'LWWRegister[Rung]'

    # Participants (CRDT-merged from each device's view)
    participants: dict[bytes, ParticipantState]    # keyed by master_vk

    # Routing
    active_path: 'LWWRegister[str]'                # path_id
    warm_backups: 'ORSet[str]'

    # Capability intersection (frozen at call setup)
    negotiated_capabilities: frozenset[str]
    model_pack_hash: Optional[str]

    # Lifecycle
    ended_at_ms: 'LWWRegister[Optional[int]]'
    end_reason: 'LWWRegister[Optional[EndReason]]'
    live_resumable_until_ms: 'LWWRegister[Optional[int]]'

    # Trust + audit
    identity_verified: 'LWWRegister[VerificationState]'
    recording_state: 'LWWRegister[RecordingState]'
    audit_path: 'ORSet[FrameProvenance]'           # (bounded — rotating)

    # Vitals — local, never synced
    # (kept separately per-device; used by Immune System)
```

### Convergence properties

- **`intensity`** uses LWW with timestamp tiebreak by `master_vk`. If
  both sides bump intensity simultaneously, the higher-priority side
  (the originator) wins, then propagates.
- **`participants[*].active_devices`** is an OR-set: devices join and
  leave; the set converges add-wins.
- **`primary_mic`** etc. are LWW; ties go to lex device_id.
- **`audit_path`** is bounded OR-set — keeps last N frame provenance
  tags for end-of-call attestation; older entries decay.

### Sync mechanism

Reuses the existing CRDT message types:
- `CALL_STATE_DELTA` — wire type added to [src/one_link/wire.py](../src/one_link/wire.py).
- Carries vector-clock-stamped delta over the CallSession fields.
- Sent over the existing CONTROL stream, not media stream.

---

## Part 6 — Call Lifecycle Flows

### 6.1 Initiation

```
User taps "Call Mom" on Phone
  │
  ▼
Phone Body Engine writes CallSession with:
  - intensity = HIGH
  - participants[josh_vk].active_devices[phone] = state
  - participants[mom_vk] = {} (not yet known)
  │
  ▼
Phone signaling emits CALL_INVITE to:
  - Mom's rendezvous endpoints (Row 3, ol_discovery)
  - All paired devices Mom has advertised
  │
  ▼
Mom's devices receive CALL_INVITE on their daemon control channel
  │
  ▼
Body Engine on Mom's side:
  - Reads last-known location LWW
  - Identifies which surface(s) Mom is most likely at
  - Renders the ring on those surfaces FIRST
  - After 3s, fans out to all remaining devices
```

### 6.2 Identity verification

**First-ever call** between two parties:

1. Each side derives a 5-word SAS from a transcript hash of
   `(josh_master_vk, mom_master_vk, call_id, dh_shared_secret)` using
   the `ol_pair_qr` SAS primitive.
2. Both sides display the SAS briefly in the calm-trust pane:
   ```
   You and Mom share:
   amber  river  canyon  meadow  stone
   ```
3. If they read the same five words aloud (and they match), tap
   "Yes." This writes `identity_verified = TRUSTED` to CallSession.
4. The verification persists in the local trust store; future calls
   skip this step.

**Subsequent calls:**
- If `master_vk` unchanged: skip entirely.
- If `master_vk` rotated AND new signature chains to the old key:
  badge says "Mom updated her keys"; allow with a re-verify offer.
- If `master_vk` rotated AND chain broken: call refuses. UI says
  "This may not be Mom. Verify in person before continuing." This
  is the C2 fix on the call surface.

### 6.3 Accept / decline

- **Accept**: tap or speak. CallSession transitions to active. Other
  devices' rings stop within 200ms via CRDT propagation.
- **Decline**: tap or speak. CallSession transitions to declined.
  Alex's side: gracefully converts to async capsule offer.
- **Ignore (timeout)**: 30s. Same as decline → async capsule.
- **Mom is offline entirely (no devices respond)**: Alex's side
  instantly transitions to "Leave a voice note for Mom" — no
  "couldn't reach Mom" error.

### 6.4 Active call

Once accepted, the engine layer takes over. The user sees:
- Face / voice / ambient indicator
- A calm provenance dot
- Nothing else

Behind the scenes:
- Immune System tick @ 100ms
- Body Engine tick @ 500ms
- Route Brain tick @ 200ms
- Reality Engine signs every frame
- Predictive Continuity active per cap
- Compiler responds to Immune requests

### 6.5 Degradation transitions

When the Compiler descends, the visible change is:
- Rung 0 → 1: imperceptible (bitrate change at I-frame boundary)
- Rung 1 → 4 (audio only): video softly fades to a still-of-the-face
  with the caption "audio only" appearing for 2 seconds and then
  fading. No toast, no overlay.
- Rung 4 → 7 (async capsule): a single calm message replaces the
  call surface:
  ```
  Mom seems to have lost connection.
  Recording your message for her.
  Tap to finish.
  ```

### 6.6 End

Three end paths, all graceful:

1. **User hangup**: tap end. CallSession.ended_at_ms set. Other side
   sees calm "Mom ended the call" for 2 seconds, fades. Conversation
   record preserved.
2. **Mutual hangup**: both press end. Same flow.
3. **Network-induced async**: Immune System emits
   `CONVERT_TO_ASYNC`. Compiler descends to rung 7. Voice note
   created. Both sides see resume affordance for 10 minutes.

### 6.7 Resume from capsule

Within 10-minute window, network recovers. Either side taps "Resume":
- New CALL_INVITE issued with `resume_of = <prior_call_id>`.
- ACE memory (if present) stitches the two calls into one
  conversation object.
- CallSession inherits prior intensity, prior identity verification,
  prior preferred surfaces.

---

## Part 7 — Trust Surface

### 7.1 Identity at call layer

**Historical prerequisites and current source status:**

- **Audit finding C1** — unsigned browser SDP was a historical blocker.
  Current browser signaling envelopes are signed and identity-bound, with live
  Chromium/Firefox direct probes. Physical route/browser qualification remains
  separate evidence.
- **Audit finding C2** — silent key replacement was a historical blocker.
  Current source has pinned identity-possession, revocation, key-change, and
  transactional rotation controls; an immutable-release and physical
  cross-device re-verification audit is still required.
- **Audit finding C5** ([SECURITY.md](SECURITY.md):225) — At-rest
  encryption for chat bodies and group chain keys. Tier A
  (browser PWA) shipping; Tier B (daemon) required before any
  recording feature.

The baseline Tier α source path exists, but no tier is production-qualified
until these controls pass the immutable release and physical-device gates.

### 7.2 Recording consent

**The most felt privacy moment.** Treated as doctrine, not feature.

- Both sides must explicitly tap a recording-start affordance.
- Recording surface badge is **visible**, not subtle. It uses the
  Reality Engine pane's `recording_state` field.
- Toggling off by either side stops recording immediately. The
  recorded artifact ends at that exact frame.
- Recorded artifacts are cryptographically signed (each frame
  carrying its FrameProvenance) so they are authenticatable later
  and undeepfakeable.
- Recordings are encrypted at rest using a per-recording key derived
  from the call's macaroon chain. Sharing a recording requires
  granting a derived capability.
- **No silent recording.** No "for quality" recording. One Link has no central
  recording service; optional rendezvous/relay infrastructure may still carry
  encrypted traffic and observe connection metadata.

### 7.3 Conversation-as-object capabilities

Conversations are first-class objects. They carry capabilities that
participants can grant or refuse:

```python
class ConversationCap(Enum):
    SUMMARIZE          = "summarize"           # AI can read+summarize
    PERSIST_LOCALLY    = "persist_local"       # save to disk
    PERSIST_TO_ACE     = "persist_to_ace"      # add to relational memory
    SHARE_EXCERPT      = "share_excerpt"       # forward a snippet
    INDEX_FOR_SEARCH   = "index_search"        # searchable later
    AUTO_TRANSCRIBE    = "auto_transcribe"     # local captions
    AUTO_TRANSLATE     = "auto_translate"
    RECORD             = "record"

@dataclass
class ConversationCapState:
    """One row per (conversation, participant, cap).
       Macaroon-attenuated; revocable via existing _cap_store."""
    conversation_id: str
    participant_master_vk: bytes
    cap: ConversationCap
    granted_by: bytes                # whose authority
    granted_at_ms: int
    expires_at_ms: Optional[int]
    macaroon_token: bytes
```

Default state: caps are *not granted*. Each requires an explicit
in-call confirmation. The conversation "can refuse" by simply having
no granting record for a cap.

---

## Part 8 — Wire Format Additions

All new wire types compose into [src/one_link/wire.py](../src/one_link/wire.py)
following the existing length-prefixed JSON envelope.

### 8.1 New message types

| Type | Direction | Body fields |
|---|---|---|
| `CALL_INVITE` | initiator → recipient | `call_id, conversation_id?, resume_of?, intensity, caps_advertised[], offer_sdp_signed, ttl_ms` |
| `CALL_RING` | recipient device → recipient devices | `call_id, ring_surface` (CRDT-converged) |
| `CALL_ACCEPT` | recipient → initiator | `call_id, accepting_device_id, answer_sdp_signed, caps_advertised[]` |
| `CALL_DECLINE` | recipient → initiator | `call_id, reason: enum {busy, ignore, refuse}` |
| `CALL_END` | either → other | `call_id, reason: enum {user_hangup, network_async, error}` |
| `CALL_STATE_DELTA` | either → other | `call_id, vector_clock, fields_changed[]` |
| `MEDIA_REDIRECT` | either → other | `call_id, new_path_id, crossfade_ms` |
| `RESUME_OFFER` | either → other | `call_id, prior_call_id, capsule_blob_hash, ttl_ms` |
| `RECORDING_REQUEST` | either → other | `call_id, scope: enum {audio, video, both}` |
| `RECORDING_GRANT` | recipient → requester | `call_id, granted: bool, conditions[]` |
| `IDENTITY_CHALLENGE` | either → other (first call) | `call_id, sas_transcript_hash` |
| `IDENTITY_CONFIRM` | either → other | `call_id, sas_confirmation_hash` |

### 8.2 SDP audio / video offers

Currently [src/one_link/peer_rtc.py](../src/one_link/peer_rtc.py)
emits only `m=application` DataChannel offers. The migration:

```sdp
v=0
o=- 1234567 1 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 AB:CD:EF:...
a=group:BUNDLE 0 1 2

m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=mid:0
a=sctp-port:5000

m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=mid:1
a=rtpmap:111 opus/48000/2
a=fmtp:111 useinbandfec=1; usedtx=1; minptime=10
a=rtcp-fb:111 nack
a=rtcp-fb:111 transport-cc
a=ssrc:12345 cname:josh-mic
a=extmap:1 http://onelink.dev/frame-provenance

m=video 9 UDP/TLS/RTP/SAVPF 100
c=IN IP4 0.0.0.0
a=mid:2
a=rtpmap:100 VP9/90000
a=fmtp:100 profile-id=0
a=rtcp-fb:100 nack
a=rtcp-fb:100 nack pli
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 transport-cc
a=ssrc:67890 cname:josh-cam
a=extmap:1 http://onelink.dev/frame-provenance
```

The `extmap:1` header is the FrameProvenance carrier (RFC 8285 RTP
header extension). 32 bytes per frame.

### 8.3 Semantic delta wire format

When semantic capability is active, a third media stream is
established (over the same QUIC connection or as an additional WebRTC
DataChannel labeled `semantic-v1`). Format:

```
SemanticFrame:
  schema_version: u16
  call_id_short:  u32     // truncated for compactness
  seq:            u32
  kind:           u8      // 0 = voice delta, 1 = video delta, 2 = concept
  payload_len:    u16
  payload:        bytes   // VoiceDelta | VideoDelta | ConceptFrame
  provenance:     [32]u8  // inline FrameProvenance HMAC
```

### 8.4 Capability schema

New caps to add to [src/one_link/capabilities.py](../src/one_link/capabilities.py):

```python
class Capability(Enum):
    # ... existing ...
    WEBRTC_AV_V1                = "webrtc_av_v1"          # baseline AV
    FRAME_PROVENANCE_V1         = "frame_provenance_v1"   # Reality Engine
    PREDICTIVE_CONTINUITY_V1    = "predictive_continuity_v1"
    SEMANTIC_MEDIA_V1           = "semantic_media_v1"
    MULTIDEVICE_BODY_V1         = "multidevice_body_v1"
    ROUTE_BRAIN_V1              = "route_brain_v1"
    ONEFIELD_RADIO_V1           = "onefield_radio_v1"
    CONVERSATION_OBJECT_V1      = "conversation_object_v1"
```

Capability advertisement happens at the existing
`CAPABILITY_ADVERTISE` handshake. Intersection is the working set for
the call.

---

## Part 9 — Substrate Integration Map

### 9.1 What plugs into what

| Engine | Existing substrate it consumes |
|---|---|
| Immune | `Daemon._pair_health`, `Daemon._relay_metrics`, `routing_native.homology_score`, `confidential_native.current_tier()` |
| Compiler | Capability negotiation, media pipeline (new), audit log |
| Body | `ol_device_mesh` (Row 8), `ol_crdt`, `ol_hwkey` for device subkeys |
| Route | `ol_routing` (Row 4), `ol_prefetch` (Row 4D), `_pick_best_relay` |
| Reality | `ol_capability` macaroon chain, `ol_aead` per-frame, `ol_pqsig` for issuer roots |
| Priority | `ol_quic` priority/weight, RTP SSRC |
| Predictive | OneField voice.cl/video.cl scaffold |
| Semantic | OneField voice.cl/video.cl + new `ol_semantic` crate (codegen-derived) |
| OneField | `ol_routing` (τ_c path scores), future `ol_radio` |

### 9.2 New modules to create

```
src/one_link/
├── call_immune.py              ← Part 4.1
├── presence_compiler.py        ← Part 4.2
├── body_engine.py              ← Part 4.3
├── route_brain.py              ← Part 4.4
├── frame_provenance.py         ← Part 4.5
├── priority_engine.py          ← Part 4.6
├── predictive_continuity.py    ← Part 4.7
├── semantic_pipeline.py        ← Part 4.8 (gated)
├── onefield_bridge.py          ← Part 4.9 (stub)
├── call_session.py             ← Part 5 (CRDT root)
├── call_signaling.py           ← Part 6 (new wire types)
├── identity_sas.py             ← Part 6.2 (reuse ol_pair_qr SAS)
├── recording_consent.py        ← Part 7.2
└── conversation_object.py      ← Part 7.3

native/
├── ol_semantic/                ← NEW crate (codegen from voice.cl/video.cl)
└── ol_provenance/              ← NEW crate (HMAC-SHA256 SIMD per frame)
```

### 9.3 Modifications to existing files

| File | Change |
|---|---|
| [src/one_link/peer_rtc.py](../src/one_link/peer_rtc.py) | Add `m=audio` / `m=video` to SDP offer. Add `extmap:1` for FrameProvenance RTP header extension. Sign SDP envelope (closes C1). |
| [src/one_link/daemon.py](../src/one_link/daemon.py) | Wire CallSession lifecycle. Subscribe Immune System tick loop to existing tick budget. Add CALL_* handler routes. |
| [src/one_link/wire.py](../src/one_link/wire.py) | Add 12 new message types (Part 8.1). |
| [src/one_link/capabilities.py](../src/one_link/capabilities.py) | Add 8 new caps. Wire to existing deny-by-default policy. |
| [src/one_link/crdt.py](../src/one_link/crdt.py) | Add CallSession + ParticipantState merge logic. |
| [src/one_link/state.py](../src/one_link/state.py) | Add call history persistence; voice-note conversion. |
| [src/one_link/courier_bundle.py](../src/one_link/courier_bundle.py) | Add async-capsule format. |
| [src/one_link/web/index.html](../src/one_link/web/index.html) | Add Call surface, Reality dot, intensity dial, identity SAS pane. |
| [native/one_link_native/](../native/one_link_native/) | Canonical inline PEP 561 stubs for every exported `one_link_native` runtime submodule. |

### 9.4 Test surface additions

```
tests/
├── test_call_immune_soak.py
├── test_presence_compiler_ladder.py
├── test_body_engine_crdt_convergence.py
├── test_route_brain_prewarm_hysteresis.py
├── test_frame_provenance_hmac.py
├── test_priority_engine_voice_survives.py
├── test_predictive_continuity_confirm_ratio.py
├── test_semantic_pipeline_capability_gating.py
├── test_call_lifecycle_e2e.py
├── test_identity_sas_first_call.py
├── test_recording_consent_doctrine.py
├── test_doctrine_of_invisibility.py    ← lints the UI string table
├── test_audit_c1_sdp_signing.py
├── test_audit_c2_master_vk_rotation.py
└── property/
    ├── test_call_session_crdt_lattice_laws.py
    └── test_frame_provenance_no_forgery.py
```

---

## Part 10 — Build Tier Order

No calendar dates. Acceptance gates ship work.

### Tier α-pre — Prerequisites

**α-pre-A: Doctrine of Invisibility document.** Live in
[docs/DOCTRINE_OF_INVISIBILITY.md](DOCTRINE_OF_INVISIBILITY.md).
Every subsequent PR reviewed against it.

**α-pre-B: Close audit findings C1, C2, C5.** Voice/video over a
partially-attested trust surface is a doctrine violation.

- C1: SDP envelope signing + identity cross-check in
  [peer_rtc.py](../src/one_link/peer_rtc.py).
- C2: Master VK rotation must chain to prior key or trigger
  re-verification SAS.
- C5: At-rest encryption for chat bodies in daemon (Tier B). Required
  before any call recording feature.

**α-pre-C: Frame provenance HMAC over existing voice messages.**
Demos the Reality Engine before any WebRTC bring-up. Voice messages
v0.9.2 get FrameProvenance tags; UI badge shows them. Validates the
end-to-end design before betting on it for live calls.

**Acceptance**: doctrine document landed; C1 + C2 closed and regression-
tested; voice messages show calm Reality badge.

### Tier α — Baseline WebRTC voice + video

- `m=audio` + `m=video` in SDP (signed, per C1).
- Opus 48k + VP9.
- Browser `getUserMedia`.
- Call accept / decline / end UI.
- Identity SAS on first call (reuses `ol_pair_qr`).
- Two-laptop voice + video call works on home LAN.

**Acceptance**: 30-minute call, both directions, no errors, no toasts.

### Tier β — Reality + Priority

- FrameProvenance HMAC on every audio + video frame.
- UI provenance badge (calm dot, tap to reveal).
- Separate QUIC stream per QoS class (P0 voice, P1 timing, P2 face, ...).
- Bandwidth-cap test: voice survives when total bandwidth = 30 kbps;
  video degrades gracefully.

**Acceptance**: 1000 frames, 100% provenance verified, 0% forgeries
in property test. Voice intelligible at 30 kbps bandwidth cap.

### Tier γ — Immune System SHADOW

- Full Immune controller landed.
- Subscribes to all existing signals.
- Writes every decision (including HOLD) to audit log.
- Emits zero downstream actions.
- 1k call-minutes of dogfooding to tune thresholds against measured
  EWMA distributions.

**Acceptance**: 1k call-minutes logged. p50 / p90 / p99 of `_pair_health`
EWMA measured. Thresholds set to measured p90 / p99.

### Tier δ — Compiler 3-rung + Immune ASSIST

- Compiler with rungs {0: raw_av, 4: audio_only, 7: async_capsule}.
- Immune System can emit `REQUEST_LOWER_FIDELITY`, `REQUEST_VOICE_ONLY`,
  `CONVERT_TO_ASYNC`.
- The headline demo: **"call survives the WiFi router being unplugged
  mid-call by becoming a voice-note + resuming when WiFi returns."**

**Acceptance**: The 90-second demo. Record it. This is the whole pitch.

### Tier ε — Route Brain ASSIST + Multi-Device Body ASSIST

- Route Brain prewarms backup paths on hysteresis trigger.
- Multi-Device Body suggests handoff ("your phone has a better mic,
  switch?"); user confirms.
- 200ms crossfade protocol shipped for both route and surface
  handoffs.

**Acceptance**: 100 simulated path-failure scenarios; all converge
without media gap > 250 ms.

### Tier ζ — Semantic Engine voice-only EXPERIMENTAL

- Train articulatory voice model (research-grade GPU work).
- Port voice.cl to `ol_semantic` crate via `ol_codegen` (1M-iter
  byte-equivalence gate).
- Capability-gated as `SEMANTIC_MEDIA_V1`.
- A/B test 20 calls against Opus 32k.
- Measure intelligibility MOS.

**Acceptance**: A/B MOS measurement complete. Do not promise
quality publicly until measured.

### Tier η — Predictive Continuity + Compiler full ladder + Immune AUTOPILOT

- Predictive Continuity for voice (PLC replacement).
- Compiler exposes all 8 rungs (per capability intersection).
- Immune System AUTOPILOT.
- 50k random network scenarios soak test.

**Acceptance**: ≥95% call survival, <1% oscillation, <50ms decision
latency. The full survival guarantee.

### Tier θ — Semantic video + Multi-Device Body AUTOPILOT + OneField stub

- Semantic video model trained + ported.
- Body Engine AUTOPILOT (cross-device handoff without confirmation).
- OneField bridge module stubbed for future hardware.
- The "alien tech" demo: 3 kbps voice + 20 kbps video, multi-device,
  switching paths under loss, with cryptographic provenance, on one
  button.

**Acceptance**: a single user demo where every engine acts at least
once and nothing in the doctrine list ever surfaces.

### Beyond — Continuous Intensity Dial

After Tier θ, the leap to true Living Presence:
- Intensity below "call" — ambient awareness surface.
- Surfaces (not devices) as routing destinations.
- Conversation-as-first-class-object with rights and decay.
- ACE-stitched memory across calls.
- Bounded-latency conversations (semantic-delta scaled to
  seconds-of-prediction).
- Trans-internet substrate (OneField mesh).

These are research tiers. The substrate exists; the application
patterns do not. Tier-θ ships the *call*; the Beyond tier ships
Living Presence in full.

---

## Part 11 — Test Strategy

### 11.1 Test pyramid

```
                       ┌─────────────────────┐
                       │  E2E Field Tests    │   <100 scenarios
                       │  (real network)     │
                       └─────────────────────┘
                  ┌──────────────────────────────┐
                  │  Soak Harness                │   2k-50k iters
                  │  (simulated network)         │
                  └──────────────────────────────┘
            ┌──────────────────────────────────────┐
            │  Property Tests (CUDA fuzzer)        │   millions of trials
            │  (lattice laws, HMAC non-forgery)    │
            └──────────────────────────────────────┘
      ┌──────────────────────────────────────────────┐
      │  Unit Tests                                   │   thousands
      │  (Arbitrator purity, rung transitions, ...)  │
      └──────────────────────────────────────────────┘
```

### 11.2 Soak harness pattern (per engine)

Lifts from [tests/test_native_pipeline_soak.py](../tests/test_native_pipeline_soak.py):

```python
@pytest.mark.parametrize("iters", [int(os.getenv("ONE_LINK_SOAK_ITERS", "2000"))])
def test_<engine>_soak(iters):
    failures = []
    for i in range(iters):
        scenario = random_scenario(seed=i)
        result = run_simulated(scenario)
        if not result.passes_acceptance():
            failures.append((i, result))
    assert len(failures) < iters * 0.05, f"survival budget: {len(failures)}/{iters}"
```

Default 2k iters. Nightly 50k via `ONE_LINK_SOAK_ITERS=50000`.
Acceptance budget: <5% failures per soak (varies per engine).

### 11.3 Property tests (lattice + crypto)

Reuse the existing CUDA property fuzzer pattern from OneField:

- `CallSession` CRDT merge satisfies lattice laws (associativity,
  commutativity, idempotency) ∀ deltas.
- `FrameProvenance` HMAC is non-forgeable ∀ random keys + tampered
  payloads.
- Compiler rung transitions are monotone-descent + slow-ascent ∀
  vital sequences.
- Identity SAS matches ∀ shared transcripts; differs ∀ different
  transcripts.

Target: ≥1M trials per property in CI; ≥100M nightly.

### 11.4 Real network field tests

A small corpus of network traces from real conditions:

- Home WiFi normal
- Home WiFi with microwave on (2.4 GHz interference)
- Cell 4G good
- Cell 4G congested (rush hour)
- Cell 5G mmWave
- Airplane WiFi
- Hotel WiFi
- Walking out of WiFi range into cell
- Two devices on same LAN
- VPN over poor link

Replay each through the simulated network harness against the full
stack. Acceptance: call survives in every scenario.

### 11.5 Doctrine of Invisibility lint

A CI gate that scans the UI source for forbidden strings:

```python
# tests/test_doctrine_of_invisibility.py

FORBIDDEN = [
    r"reconnecting\.\.\.",
    r"connection unstable",
    r"call failed",
    r"could not reach",
    r"please try again",
    r"network error",
    r"\bsettings\b.*advanced",
    r"upgrade.*HD",
    # etc.
]

def test_no_doctrine_violations():
    for path in glob("src/one_link/web/**/*.{html,js,ts,jsx,tsx}"):
        content = open(path).read()
        for pattern in FORBIDDEN:
            assert not re.search(pattern, content, re.I), \
                f"Doctrine violation in {path}: pattern '{pattern}'"
```

Every PR runs this. Adding a new forbidden string requires the
Doctrine document to be updated first.

---

## Part 12 — Accessibility

**For the people** means every person. Built in Tier α, not deferred.

### 12.1 Live captions

- On-device transcription only. Never cloud.
- Whisper-small or comparable model running locally.
- Captions are a UI overlay; FrameProvenance signs them too
  (`FrameKind.RECONSTRUCTED` from `audio` source).
- Toggle via accessibility settings, not call settings.
- Both sides see captions if requested; sender of audio can disable
  caption generation for their own audio (privacy of speech text).

### 12.2 Screen-reader navigability

- Every UI element labeled for ARIA / VoiceOver / TalkBack.
- Call accept/decline/end accessible via keyboard alone.
- Intensity dial controllable via single-axis input (rocker, gesture).
- Identity SAS spoken aloud by screen reader.

### 12.3 Voice-only mode

- A first-class mode, not a degraded fallback.
- For users without sight, video adds no value; system can default
  to audio-only and use the saved bandwidth for higher voice
  fidelity (rung 4 with Opus 64k instead of rung 0 with 16k voice).
- Predictive Continuity especially valuable here (face context lost,
  audio context maximal).

### 12.4 Hearing accessibility

- Visual ring (flash, color cue) optional alongside ringtone.
- Caption-first mode: video shown, captions always on, audio optional.
- Tactile ring on wearables.

---

## Part 13 — For the People

### 13.1 Free tier

Calls are free. Forever. No paywall.

**Who pays:**
- Direct P2P calls cost nothing (no relay needed).
- Relay-assisted calls use the existing federated-relay model
  ([SOVEREIGN_NETWORK_BLUEPRINT.md](SOVEREIGN_NETWORK_BLUEPRINT.md)).
- Volunteers run relay nodes; bandwidth costs are amortized by the
  volunteer pool (similar to Tor).
- Heavy users may choose to volunteer relay capacity.
- No company runs cloud SFU infrastructure. No bill.

### 13.2 Zero-account onboarding

First device, first call, first peer — no account creation.

```
User downloads One Link.
  │
  ▼
App opens. Single screen:
  ┌──────────────────────────────┐
  │  Welcome to One Link.        │
  │  Share this code with someone │
  │  you trust.                   │
  │                                │
  │     [QR code]                  │
  │                                │
  │  Or scan theirs:               │
  │     [Scan button]              │
  └──────────────────────────────┘
  │
  ▼
QR pair completes (ol_pair_qr, Row 2).
SAS confirmation flow.
  │
  ▼
Main screen: contacts (just the one).
Tap to call.
```

90 seconds from install to first call. No email, no phone number,
no password, no profile.

### 13.3 Identity sovereignty

The user's identity (master_vk) is theirs. Not the platform's.

- Generated on first install.
- Sealed in hardware (`ol_hwkey`) where available.
- Backed up via Shamir threshold across the user's own devices
  (`ol_threshold_recovery`, Row 9).
- If a device is lost, recovery quorum from remaining devices.
- If all devices are lost, the identity is gone — by design. No
  centralized recovery, no support email, no "verify with passport"
  flow.
- The trade-off (no recovery on total loss) is acknowledged plainly
  in the onboarding doctrine.

### 13.4 Internationalization

- The Doctrine of Invisibility minimizes UI strings, which makes i18n
  cheap.
- Every visible string must have translations for at least: English,
  Spanish, Mandarin, Hindi, Arabic, Portuguese, French. Day-one ship.
- No region-locked features.
- No "this feature is unavailable in your country."

### 13.5 Low-end devices

- The Compiler ladder degrades to handle low-end hardware naturally
  (a 2GB-RAM Android phone defaults to audio-only).
- Graduated Semantic Engine model packs should eventually use size tiers
  (for example 10 MB voice, 50 MB voice, 200 MB video), with the device
  selecting the largest signed pack that fits. Those tiers do not exist yet.
- OneField R&D path is the long-term answer to bandwidth poverty:
  3 kbps voice on a $20 mesh-radio module reaches every village.

---

## Part 14 — Honest Limits & Dependencies

### 14.1 Open audit findings (BLOCKERS for ship)

| Finding | Severity | Status | Blocks |
|---|---|---|---|
| C1 — Browser SDP attestation unsigned | CRITICAL | Source mitigation landed: signed identity-bound signaling + browser tests; physical/release proof open | Tier α release qualification |
| C2 — Master VK silent rotation post-TOFU | CRITICAL | Source pin/revoke/rotation controls landed; physical cross-device re-verification audit open | Tier α release qualification |
| C5 — At-rest chat/group encryption | CRITICAL | Desktop SQLCipher/LockBox controls partial; browser/blob/runtime coverage open | Tier β recording feature |
| H7-H15 | HIGH | Open per May-14 audit | Various, not call-blocking |

Voice/video remains alpha source functionality, not a production-qualified
claim, until the remaining release and physical gates above are archived.

### 14.2 Research-grade dependencies

| Dependency | Status | Tier blocked |
|---|---|---|
| Articulatory voice predictor weights | Vendored research ONNX/PT checkpoint; unsigned and not media-wired | ζ |
| Scene-feature predictor weights | Vendored research ONNX/PT checkpoint; unsigned and not media-wired | θ |
| PINN waveform synth weights | Does not exist | OneField R&D |
| HackRF Pro hardware | Not yet acquired | OneField R&D |

None of these block Tier α-η. The product is shippable without any
of them; the alien tier requires them.

### 14.3 Platform constraints

- **iOS**: Background audio capture restricted. Native Swift wrapper
  required for full functionality; PWA path has limited capability.
  Plan: ship Mac + Android + PWA first; iOS native last.
- **Android**: Generally permissive but battery management aggressive
  in low-end OEM skins. Plan: foreground service for active calls.
- **Browser**: WebRTC stack varies; Chrome / Edge / Firefox tested
  baseline. Safari may need polyfills.

### 14.4 Network constraints

- **NAT traversal**: direct ICE works only where gathered routes permit.
  Symmetric/restrictive NAT may require operator-configured TURN; no success
  percentage or universal fallback is claimed without the physical matrix.
- **Firewalls**: QUIC over UDP/443 is the most-portable transport.
  Fallback to TLS-over-TCP/443 for restrictive networks.

### 14.5 Patent landscape

Neural codec IP is contested:
- Google: Lyra family patents
- Meta: Encodec / SoundStream patents
- NVIDIA: Maxine face-reenactment patents

OneField's S_ONE → coherence-prior derivation provides an
independent-invention foundation, but a defensive patent pool
(extending [PATENTS.md](../../../OneField%20Mesh/PATENTS.md)) and
careful publication-first strategy is essential before the Semantic
Engine ships externally.

### 14.6 Honest non-claims

- "Quantum-resistant info-theoretic privacy" claim from
  [VOICE_VIDEO_ALIEN_TECH.md](../../../OneField%20Mesh/docs/VOICE_VIDEO_ALIEN_TECH.md)
  needs rewriting. It is a large symmetric pre-shared key, not a new
  quantum-immune primitive. Defensible technically, but the framing
  must be tightened before any external pitch.
- "1000× better than Zoom" — true for specific metrics (bandwidth per
  intelligible call-minute under bad networks; call survival under
  network failure), not uniformly. Pitch the experience, not the
  number.

---

## Part 15 — Glossary

| Term | Meaning |
|---|---|
| **Ambient presence** | The lowest-intensity rung; faint awareness without active session. |
| **AEAD** | Authenticated Encryption with Associated Data; one-shot encrypt-and-sign primitive. |
| **Body Engine** | Multi-Device Body Engine; arbitrates surface roles across user's devices. |
| **Call Immune System** | The 100ms-tick controller that watches vitals and requests representation changes. |
| **Capability (cap)** | Macaroon-attenuable token granting a specific right (file send, semantic media, recording). |
| **CallSession** | The top-level CRDT object representing one call. |
| **CallVitals** | Per-tick read-only snapshot of all health signals. |
| **Compiler** | Presence Compiler; picks the active rung. |
| **Confirm ratio** | Predictive Continuity metric: fraction of predicted frames that match real arrivals. |
| **Crossfade protocol** | 200ms overlap window during route or surface handoff. |
| **CRDT** | Conflict-Free Replicated Data Type; lattice-based eventual consistency. |
| **Doctrine of Invisibility** | The list of surfaces we refuse to ship, and what engines must do instead. |
| **EWMA** | Exponentially Weighted Moving Average; smoothing of streaming statistics. |
| **FrameProvenance** | 32-byte per-frame HMAC tag attesting kind / device / path / recording state. |
| **Hysteresis** | Two-threshold trigger preventing oscillation between two states. |
| **Intensity dial** | The continuous variable of presence; "call" is one position. |
| **Linked mesh** | Row 8: user's own devices act as one identity to outsiders, separately addressable to user. |
| **LWW Register** | Last-Writer-Wins CRDT; tie-broken by (timestamp, master_vk). |
| **Master VK** | Master Verification Key; the long-lived identity public key. |
| **Macaroon** | Attenuable HMAC-chained capability token (`ol_capability`). |
| **OR-set** | Observed-Remove set; CRDT add-wins lattice. |
| **Provenance dot** | The calm UI indicator that opens the trust pane. |
| **Reality Engine** | Cryptographic Reality Engine; signs every frame. |
| **Rung** | One of 9 representations on the Compiler ladder (raw_av down to ambient_presence). |
| **SAS** | Short Authentication String; 5-word verification on first call. |
| **Semantic delta** | Wire format that carries change-in-meaning, not change-in-pixels. |
| **Surface** | An ephemeral output (a TV, a speaker, a watch) — distinct from a *device*. |
| **τ_c** | Coherence time field; the unifying physics primitive in OneField. |
| **TOFU** | Trust-On-First-Use; pinning identity on first contact. |
| **Vector clock** | Per-node logical clock used for CRDT happens-before. |

---

## Part 16 — Reference Map

### 16.1 Existing files referenced

| File | Role |
|---|---|
| [src/one_link/peer_rtc.py](../src/one_link/peer_rtc.py) | WebRTC browser-peer signaling and DataChannel lifecycle; owner-call media also uses the signed call API/UI path. |
| [src/one_link/peer_transport.py](../src/one_link/peer_transport.py) | Transport selection (WebRTC vs QUIC). |
| [src/one_link/daemon.py](../src/one_link/daemon.py) | Main daemon with baseline call lifecycle plus the future engine integration points specified here. |
| [src/one_link/wire.py](../src/one_link/wire.py) | Wire message types. |
| [src/one_link/capabilities.py](../src/one_link/capabilities.py) | Capability set. |
| [src/one_link/crdt.py](../src/one_link/crdt.py) | Vector clock + LWW + OR-set. |
| [src/one_link/state.py](../src/one_link/state.py) | Chat history persistence. |
| [src/one_link/courier_bundle.py](../src/one_link/courier_bundle.py) | Async delivery; will host capsules. |
| [src/one_link/native_transfer.py](../src/one_link/native_transfer.py) | Native chunk-store transport. |
| [src/one_link/chunk_ratchet.py](../src/one_link/chunk_ratchet.py) | Per-chunk forward-secret ratchet. |
| [src/one_link/web/index.html](../src/one_link/web/index.html) | Web UI; voice messages v0.9.2 live here. |
| [tests/test_voice_messages_v092.py](../tests/test_voice_messages_v092.py) | Existing voice-message tests; provenance v1 layered on top. |
| [tests/test_native_pipeline_soak.py](../tests/test_native_pipeline_soak.py) | Soak harness pattern to mirror. |
| [docs/SECURITY.md](SECURITY.md) | Open findings ledger. |
| [docs/COHERENCE_MESH_PLAN.md](COHERENCE_MESH_PLAN.md) | 10-row mesh stack we build on. |
| [docs/PRINCIPLES.md](PRINCIPLES.md) | Project-wide engineering principles. |

### 16.2 Native crates referenced

| Crate | Role in this product |
|---|---|
| `ol_aead` | Per-frame AEAD; carries FrameProvenance inline. |
| `ol_capability` | Macaroon chain rooting FrameProvenance HMAC. |
| `ol_crdt` | Vector clock + LWW + OR-set for CallSession. |
| `ol_routing` | τ_c path scoring; Route Brain. |
| `ol_homology` | Fragility score; Route Brain. |
| `ol_prefetch` | Active inference; route prewarming priors. |
| `ol_pair_qr` | First-call SAS verification. |
| `ol_pqsig` | Ed25519 + ML-DSA-65 hybrid signatures for SDP. |
| `ol_pqkem` | ML-KEM-768 + X25519 for key agreement. |
| `ol_confidential` | Hardware attestation tier. |
| `ol_device_mesh` | Row 8; underpins Body Engine. |
| `ol_threshold_recovery` | Shamir recovery for identity sovereignty. |
| `ol_quic` | QUIC transport with per-stream priority. |
| `ol_hwkey` | Hardware-bound device subkeys. |
| `ol_onion` | Optional onion routing per intensity. |
| **`ol_semantic`** | **NEW** — codegen from voice.cl/video.cl. |
| **`ol_provenance`** | **NEW** — SIMD HMAC-SHA256 per frame. |

### 16.3 OneField source referenced

| File | Role |
|---|---|
| [voice.cl](../../../OneField%20Mesh/onefield/app/builtin/voice.cl) | Semantic voice math + wire format (1616 LOC). |
| [video.cl](../../../OneField%20Mesh/onefield/app/builtin/video.cl) | Semantic video math + wire format (1107 LOC). |
| [VOICE_VIDEO_ALIEN_TECH.md](../../../OneField%20Mesh/docs/VOICE_VIDEO_ALIEN_TECH.md) | Math + capabilities reference. |
| [coherence_engine.cl](../../../OneField%20Mesh/onefield/sim/coherence_engine.cl) | OCDM eigenmode channel basis. |
| [tau_c_field_sim.cl](../../../OneField%20Mesh/onefield/sim/tau_c_field_sim.cl) | τ_c PDE field math. |

### 16.4 Audit references

| Source | Findings relevant to this product |
|---|---|
| [SECURITY.md](SECURITY.md) | C1, C2, C5 (blockers) |
| [SECURITY_AUDIT_v0.7.0.md](SECURITY_AUDIT_v0.7.0.md) | A, B, C (scope gaps still partially open) |
| May 14 2026 four-agent red-team | 6 findings closed `6f5fd10`, 50 open |

---

## Closing — The Bar

When this is shipped end-to-end, an advanced engineer reading the
codebase + this document should encounter:

- A sovereign P2P transport stack with hardware attestation,
  post-quantum identity, capability-based trust, threshold recovery
  for identity sovereignty.
- Frame-level cryptographic provenance attesting kind / device /
  path / recording state on every media segment, verifiable in
  hardware-rooted macaroon chains.
- A CRDT-based shared call session that survives network partition,
  cross-device, cross-network, with 200ms crossfade atomicity for
  surface handoff.
- A 9-engine internal mechanism — Immune watching vitals at 100ms,
  Compiler arbitrating a 9-rung representation ladder, Body Engine
  treating devices as organs, Route Brain prewarming paths,
  Predictive Continuity rendering ahead of the wire, Semantic
  Engine carrying intent at 3 kbps with model-pack capability
  gating, Priority Engine protecting the human signal at the
  transport layer, OneField R&D bridging to physics-layer mesh
  radio.
- A continuous intensity dial below "call" reaching toward ambient
  presence, conversation-as-first-class-object, ACE-stitched
  relational memory across calls.
- Compile-time verified numerical safety on the radio path (CFL,
  Nyquist, Maxwell-Courant, PML rails).
- A Doctrine of Invisibility enforcing that not one of these surfaces
  to the user.

The user sees: one button labelled "Call Mom." It always works.

That is the bar.
