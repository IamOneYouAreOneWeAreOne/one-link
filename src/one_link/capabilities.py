"""Per-peer capability model.

Capabilities are intentionally plain strings on the wire. That keeps the
protocol auditable and lets older peers ignore features they do not know yet.
"""

from __future__ import annotations


CHAT = "chat"
FILES = "files"
FILE_CDC = "file_cdc"
FILE_RESUMABLE = "file_resumable"
FILE_SWARM = "file_swarm"
FILE_COMPRESSION = "file_compression"
FILE_BINARY_FRAME = "file_binary_frame"
FILE_CDC_BINARY_FRAME = "file_cdc_binary_frame"
FILE_ACK_BATCH = "file_ack_batch"
# Wave 2b: multiple FILE_OFFERs bundled in a single
# FILE_OFFER_BATCH frame so a "send 100 photos" workflow pays
# one round-trip instead of N. Receiver answers with one
# FILE_WANTS_BATCH covering every offer; sender then streams
# chunks for all of them through the existing per-file
# pipeline. Both peers must advertise this cap; falls back to
# one-FILE_OFFER-at-a-time when either side lacks it.
FILE_OFFER_BATCH_V1 = "file_offer_batch_v1"
FOLDER_SYNC = "folder_sync"
MERKLE_SYNC = "merkle_sync"
FUTURE_TRANSPORTS = "future_transports"
SELF_MESH_MANIFEST = "self_mesh_manifest"
SELF_MESH_SEND = "self_mesh_send"
# v0.7.2: capability advertisement for the Signal-style Double Ratchet.
# When BOTH peers advertise this in CAPS, post-handshake traffic
# upgrades to forward-secret + post-compromise-secure encryption.
# The library lives in one_link.double_ratchet; channel-level
# activation lands in v0.7.3 (this release ships the negotiation
# capability + audited library only, so deployments can interop
# without yet flipping the wire format).
DOUBLE_RATCHET_V1 = "double_ratchet_v1"
# Phase C-3 (ADR-0025, ADR-0026): capability advertisement for the
# native chunk-store transport pipeline. When both peers advertise
# this AND the sender opts in via ONE_LINK_NATIVE_TRANSFER=1, file
# chunks travel as FILE_NATIVE_CHUNK messages encrypted by the
# ring-backed AEAD pipeline (ADR-0002) keyed off the channel's
# native-transfer-derived session secret (ADR-0025). Legacy peers
# (no NATIVE_TRANSFER_V1 in caps) keep using FILE_CHUNK /
# FILE_BIN_CHUNK transparently.
NATIVE_TRANSFER_V1 = "native_transfer_v1"
# Phase B Bloom-init handshake (ADR-pending): when both peers advertise
# this, the receiver sends a Bloom filter of its locally-held chunk_ids
# at transfer-offer time; the sender XORs it against the manifest and
# sends only the missing chunks. Reduces bytes-on-wire by 75-93% in the
# steady-state resume regime. Falls back transparently to the legacy
# manifest-then-chunks flow when either peer lacks this cap.
BLOOM_INIT_V1 = "bloom_init_v1"
# Phase A2 QUIC transport (PHASE_A2_QUIC_CUTOVER_PLAN.md): when both
# peers advertise this, daemon↔daemon traffic flows over QUIC instead
# of WebRTC/DTLS-SRTP. Browser-as-peer paths stay on WebRTC; v0.20.x
# daemons interop on WebRTC because they don't advertise this cap.
QUIC_TRANSPORT_V1 = "quic_transport_v1"
# Living Presence Tier α-pre (LIVING_PRESENCE_ARCHITECTURE.md §4.5):
# when both peers advertise this, the sender attaches a signed
# FrameProvenance tag to every file (and later, every media frame).
# The receiver verifies against the sender's pinned master_vk and
# surfaces the Reality dot in the UI. Older peers ignore the unknown
# FILE_PROVENANCE wire type (graceful degradation per wire.py:18).
# The wiring module lives in one_link.provenance_wiring; the
# cryptography in one_link.frame_provenance.
FRAME_PROVENANCE_V1 = "frame_provenance_v1"

# Living Presence Tier ζ — semantic voice codec. Peers advertising
# this feature can negotiate the SEMANTIC_DELTA_AV rung on the
# Presence Compiler ladder. The model_pack_hash field on CAPS
# pins the exact trained checkpoint; mismatched packs fall back
# to the AUDIO_ONLY rung (Opus 16 kbps).
SEMANTIC_VOICE_V1 = "semantic_voice_v1"

# Living Presence Tier η — neural predictive extrapolator. Peers
# advertising this run a trained next-frame predictor on the
# receive path so missing audio frames are filled by a model-
# generated continuation rather than a hold-last placeholder.
# Tier η AUTOPILOT prerequisite per LIVING_PRESENCE_ARCHITECTURE
# §4.7.
PREDICTIVE_CONTINUITY_V1 = "predictive_continuity_v1"

# Living Presence Tier θ — semantic scene codec. Peers advertising
# this can negotiate scene-feature compression at ~1.5 kbps for
# the video plane. Receiver renders the scene representation as
# moving boxes / face stand-ins / icons per doctrine §3.6.c.
SEMANTIC_SCENE_V1 = "semantic_scene_v1"

# May 15 2026 — base user-facing call capabilities. Distinct from the
# advanced presence tiers (SEMANTIC_VOICE_V1 / SEMANTIC_SCENE_V1 /
# PREDICTIVE_CONTINUITY_V1) which are *codec/tier* negotiations;
# these two are the plain-English permissions a user grants:
#   - VOICE_CALL: "this peer may initiate / accept an audio call with me"
#   - VIDEO_CALL: "this peer may initiate / accept a video call with me"
# The UI renders them as distinct buttons (phone + video) and as
# separate Permissions pills (Voice + Video) so a user can grant one
# without the other (e.g., a colleague allowed audio but not video,
# or a family member with both).
VOICE_CALL = "voice_call"
VIDEO_CALL = "video_call"

# D18 — Bidirectional folder sync. When both peers advertise this, a
# single MANIFEST_PUSH carrying ``request_reverse=True`` triggers the
# receiver to push their own manifest back on the same channel, so
# both sides exchange manifests + wants in one cycle instead of two.
# Old peers ignore the unknown flag and behave as v0.20.x asymmetric
# sync — graceful interop.
FOLDER_SYNC_BIDI_V1 = "folder_sync_bidi_v1"

LOCAL_CAPABILITIES = (
    CHAT,
    FILES,
    FILE_CDC,
    FILE_RESUMABLE,
    FILE_SWARM,
    FILE_COMPRESSION,
    FILE_BINARY_FRAME,
    FILE_CDC_BINARY_FRAME,
    FILE_ACK_BATCH,
    FILE_OFFER_BATCH_V1,
    FOLDER_SYNC,
    FOLDER_SYNC_BIDI_V1,
    MERKLE_SYNC,
    FUTURE_TRANSPORTS,
    SELF_MESH_MANIFEST,
    SELF_MESH_SEND,
    DOUBLE_RATCHET_V1,
    NATIVE_TRANSFER_V1,
    BLOOM_INIT_V1,
    QUIC_TRANSPORT_V1,
    FRAME_PROVENANCE_V1,
    SEMANTIC_VOICE_V1,
    PREDICTIVE_CONTINUITY_V1,
    SEMANTIC_SCENE_V1,
    VOICE_CALL,
    VIDEO_CALL,
)

# v0.7.1 deny-by-default capability split. The audit doc
# (docs/SECURITY_AUDIT_v0.7.0.md, finding A) prescribes:
#   - chat: allowed-after-pairing — automatic on SAS confirm
#   - files / folder / group / future_transports: prompt/allowlist —
#     user must explicitly grant
# These tuples are the policy-layer enforcement points.
DEFAULT_ALLOW_AFTER_PAIRING = (CHAT,)
PROMPT_REQUIRED = (
    FILES,
    FOLDER_SYNC,
    MERKLE_SYNC,
    FUTURE_TRANSPORTS,
    SELF_MESH_MANIFEST,
    SELF_MESH_SEND,
    # Advanced presence/media capabilities are user-facing powers.
    # They may use model packs, predictive continuity, or semantic
    # rendering, so they stay deny-by-default until the user grants
    # them to a trusted peer.
    SEMANTIC_VOICE_V1,
    PREDICTIVE_CONTINUITY_V1,
    SEMANTIC_SCENE_V1,
    # Voice + Video calls are user-facing powers — each peer must be
    # explicitly granted each one. Granting Voice doesn't imply Video
    # and vice versa.
    VOICE_CALL,
    VIDEO_CALL,
)
# DOUBLE_RATCHET_V1 is a transport-layer capability negotiated
# between channels; it isn't a user-facing prompt-required cap.
# Therefore it appears in neither tuple — and the deny-by-default
# tests check that union(DEFAULT_ALLOW_AFTER_PAIRING, PROMPT_REQUIRED)
# excludes transport-layer caps. Update accordingly.
TRANSPORT_LAYER_CAPS = (
    FILE_CDC,
    FILE_RESUMABLE,
    FILE_SWARM,
    FILE_COMPRESSION,
    FILE_BINARY_FRAME,
    FILE_CDC_BINARY_FRAME,
    FILE_ACK_BATCH,
    FILE_OFFER_BATCH_V1,
    DOUBLE_RATCHET_V1,
    NATIVE_TRANSFER_V1,
    BLOOM_INIT_V1,
    QUIC_TRANSPORT_V1,
    # FRAME_PROVENANCE_V1 is automatic safety metadata. It does not
    # grant a peer any new access; it attaches verifiable provenance
    # to what's already being sent. No user prompt; always on when
    # both peers support it.
    FRAME_PROVENANCE_V1,
    # FOLDER_SYNC_BIDI_V1 is a protocol extension of FOLDER_SYNC. It
    # doesn't grant any new permission; it just changes how an
    # already-permitted folder sync proceeds (both sides exchange in
    # one cycle instead of two). The underlying user-facing power
    # (granting the peer access to the folder) is still gated by
    # FOLDER_SYNC + the per-folder share-list.
    FOLDER_SYNC_BIDI_V1,
)


def normalize_caps(values) -> tuple[str, ...]:
    out = []
    seen = set()
    for v in values or []:
        if v is None:
            continue
        s = str(v).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return tuple(sorted(out))
