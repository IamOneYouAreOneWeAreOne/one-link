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
# Exact end-to-end file commit receipt.  Chunk ACKs only prove that a peer
# accepted a frame; they do not prove that the destination was fsynced and its
# complete BLAKE3 matched the offered blob.  Peers advertising this capability
# send an encrypted, offer-correlated FILE_COMMIT after that durable boundary.
FILE_COMMIT_RECEIPT_V1 = "file_commit_receipt_v1"
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
# Authenticated, deadlock-free cutover extension for DOUBLE_RATCHET_V1. Peers
# advertising this exchange a ratchet-encrypted commit containing both exact
# final-legacy sequence boundaries. Older v1 peers omit it and remain safely
# interoperable: the responder waits for the initiator's first application DR
# frame rather than emitting post-activation legacy ciphertext.
DOUBLE_RATCHET_CUTOVER_V2 = "double_ratchet_cutover_v2"
# The exact pre-channel wire suite implemented by channel.py: signed suite
# offer/selection, independent X25519 plus native ML-KEM-768/X25519 KEM,
# transcript-bound extraction, and mutual key confirmation.  It is removed
# from runtime CAPS unless the native KEM passes its process self-test.
PQ_HYBRID_HANDSHAKE_V1 = "pq_hybrid_x25519_mlkem768_v1"
# Phase C-3 (ADR-0025, ADR-0026): capability advertisement for the
# native chunk-store transport pipeline. When both peers advertise
# this (plus NATIVE_TRANSFER_INDEXED_V1) and has not explicitly disabled
# native transfer via ONE_LINK_NATIVE_TRANSFER=0, file chunks travel as
# FILE_NATIVE_CHUNK messages encrypted by the
# ring-backed AEAD pipeline (ADR-0002) keyed off the channel's
# native-transfer-derived session secret (ADR-0025). Legacy peers
# (no NATIVE_TRANSFER_V1 in caps) keep using FILE_CHUNK /
# FILE_BIN_CHUNK transparently.
NATIVE_TRANSFER_V1 = "native_transfer_v1"
# Native transfer wire fix: FILE_NATIVE_CHUNK now carries the session's
# native chunk_index separately from per-file seq. Peers must advertise
# this cap before the sender uses FILE_NATIVE_CHUNK; legacy
# native_transfer_v1 peers receive FILE_BIN_CHUNK instead so repeated
# file sends cannot drift AEAD nonce/index state.
NATIVE_TRANSFER_INDEXED_V1 = "native_transfer_indexed_v1"
# Phase B Bloom-init handshake (ADR-pending): the v1 capability permits a
# receiver-inventory Bloom advisory. It does not promise that the advisory is
# an exact replacement for FILE_WANTS, because a legacy Bloom has false
# positives and older peers do not bind it to one ordered manifest.
BLOOM_INIT_V1 = "bloom_init_v1"
# Lossless Bloom cutover. A v2 receiver binds the filter to the exact ordered
# CDC manifest and includes every false-positive missing index as a correction.
# This makes Bloom + corrections exactly equivalent to FILE_WANTS. The new
# capability is deliberately separate: silently changing v1 response semantics
# would make a new default-on receiver deadlock with an older v1 sender.
BLOOM_INIT_EXACT_V2 = "bloom_init_exact_v2"
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
# Durable async-capsule transport: bounded offer/chunk/complete exchange plus
# an exact receiver commit receipt.  This is a protocol extension, not a new
# user permission; the underlying voice/video-call capability still governs
# who may create the conversation artifact.
ASYNC_CAPSULE_V1 = "async_capsule_v1"

# Living Presence Tier ζ research capability. The repository contains a
# deterministic codec substrate and trained predictor checkpoint, but the
# browser media plane does not yet carry semantic audio end to end. Therefore
# this string is known for forward compatibility but MUST NOT appear in
# LOCAL_CAPABILITIES until capture -> wire -> reconstruction -> playout and
# model-pack binding all pass the physical two-device release gate.
SEMANTIC_VOICE_V1 = "semantic_voice_v1"

# Living Presence Tier η research capability. Current runtime adapters track
# prediction metadata and deterministic decisions; they do not synthesize and
# insert real browser media samples. Keep it non-advertised until that playout
# boundary is implemented and qualified.
PREDICTIVE_CONTINUITY_V1 = "predictive_continuity_v1"

# Living Presence Tier θ research capability. Codec and model tests exist, but
# scene extraction, negotiated DataChannel transport, and receiver rendering
# are not yet wired into calls, so stable builds do not advertise it.
SEMANTIC_SCENE_V1 = "semantic_scene_v1"

# Features that exist as tested research substrates but are not complete wire
# promises. Keeping this explicit prevents a future marketing/build change
# from accidentally turning module presence into an advertised capability.
PREVIEW_CAPABILITIES = (
    SEMANTIC_VOICE_V1,
    PREDICTIVE_CONTINUITY_V1,
    SEMANTIC_SCENE_V1,
)

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

# Exact folder reconciliation receipt. Chunk writes alone do not prove that a
# manifest was accepted, every requested CAS object was durably indexed, or the
# winning paths were materialized. Peers advertising this extension finish a
# sync with an ID-bound FOLDER_SYNC_VERIFY / FOLDER_SYNC_COMMIT exchange.
FOLDER_SYNC_COMMIT_V1 = "folder_sync_commit_v1"

# Crash/disconnect-resumable folder CAS reception. A receiver advertises an
# fsynced prefix offset and BLAKE3 digest inside the authenticated,
# manifest-correlated MANIFEST_WANTS response. The sender validates that exact
# prefix against its verified CAS object and binds every resumed offer/chunk to
# absolute byte offsets. This changes transport efficiency only; FOLDER_SYNC
# and the per-folder share policy remain the authorization boundary.
FOLDER_BLOB_RESUME_V1 = "folder_blob_resume_v1"

# D17 (wire-up) — Receiver-initiated blob fetch. When both peers
# advertise this, the daemon can send BLOB_REQUEST{blob=hash} and the
# peer (if it has the blob and the requester is paired) responds with
# BLOB_OFFER + BLOB_CHUNKs in the same channel. Lets the dedupe-site
# index actually accelerate fetches by pulling from any paired peer
# that has the blob cached, not just the original sender.
BLOB_REQUEST_V1 = "blob_request_v1"

# D05 wire-up — Cover-traffic dispatch. When both peers advertise this,
# the cover-traffic emitter can send COVER_PACKET frames to mask
# real-traffic timing patterns. The frame carries opaque random bytes
# that the receiver drops silently — it exists purely so an on-path
# observer sees a steady stream of indistinguishable packets rather
# than the bursty pattern of real messages. Old peers ignore the
# unknown frame type (graceful interop with v0.20.x daemons).
COVER_TRAFFIC_V1 = "cover_traffic_v1"

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
    FILE_COMMIT_RECEIPT_V1,
    FILE_OFFER_BATCH_V1,
    FOLDER_SYNC,
    FOLDER_SYNC_BIDI_V1,
    FOLDER_SYNC_COMMIT_V1,
    FOLDER_BLOB_RESUME_V1,
    BLOB_REQUEST_V1,
    COVER_TRAFFIC_V1,
    MERKLE_SYNC,
    FUTURE_TRANSPORTS,
    SELF_MESH_MANIFEST,
    SELF_MESH_SEND,
    DOUBLE_RATCHET_V1,
    DOUBLE_RATCHET_CUTOVER_V2,
    PQ_HYBRID_HANDSHAKE_V1,
    NATIVE_TRANSFER_INDEXED_V1,
    BLOOM_INIT_V1,
    BLOOM_INIT_EXACT_V2,
    QUIC_TRANSPORT_V1,
    FRAME_PROVENANCE_V1,
    ASYNC_CAPSULE_V1,
    VOICE_CALL,
    VIDEO_CALL,
)


def advertised_capabilities() -> tuple[str, ...]:
    """Return capabilities this *running build* can actually execute.

    ``LOCAL_CAPABILITIES`` is the complete protocol vocabulary compiled into
    Python. Native-backed promises are narrower: advertising them when their
    authenticated ABI is absent makes negotiation claim a data path that will
    inevitably fall back. Runtime CAPS therefore removes only those promises
    whose required native implementation is unavailable.
    """

    available = list(LOCAL_CAPABILITIES)
    native_checks = (
        (BLOOM_INIT_V1, "bloom_init"),
        (BLOOM_INIT_EXACT_V2, "bloom_init"),
        (QUIC_TRANSPORT_V1, "peer_quic"),
        (NATIVE_TRANSFER_INDEXED_V1, "native_transfer"),
        (PQ_HYBRID_HANDSHAKE_V1, "pqkem_native"),
    )
    for capability, module_name in native_checks:
        try:
            module = __import__(
                f"one_link.{module_name}",
                fromlist=[module_name],
            )
            probe = getattr(module, "runtime_is_usable", None)
            usable = (
                bool(probe())
                if callable(probe)
                else bool(getattr(module, "HAS_NATIVE", False))
            )
        except (ImportError, OSError, RuntimeError):
            usable = False
        if not usable and capability in available:
            available.remove(capability)
    return tuple(available)

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
    FILE_COMMIT_RECEIPT_V1,
    FILE_OFFER_BATCH_V1,
    DOUBLE_RATCHET_V1,
    DOUBLE_RATCHET_CUTOVER_V2,
    PQ_HYBRID_HANDSHAKE_V1,
    NATIVE_TRANSFER_INDEXED_V1,
    BLOOM_INIT_V1,
    BLOOM_INIT_EXACT_V2,
    QUIC_TRANSPORT_V1,
    # FRAME_PROVENANCE_V1 is automatic safety metadata. It does not
    # grant a peer any new access; it attaches verifiable provenance
    # to what's already being sent. No user prompt; always on when
    # both peers support it.
    FRAME_PROVENANCE_V1,
    ASYNC_CAPSULE_V1,
    # FOLDER_SYNC_BIDI_V1 is a protocol extension of FOLDER_SYNC. It
    # doesn't grant any new permission; it just changes how an
    # already-permitted folder sync proceeds (both sides exchange in
    # one cycle instead of two). The underlying user-facing power
    # (granting the peer access to the folder) is still gated by
    # FOLDER_SYNC + the per-folder share-list.
    FOLDER_SYNC_BIDI_V1,
    FOLDER_SYNC_COMMIT_V1,
    FOLDER_BLOB_RESUME_V1,
    # BLOB_REQUEST_V1 is a protocol extension of FOLDER_SYNC for
    # receiver-pulled blob fetches. It doesn't grant any new permission;
    # the BLOB_REQUEST handler still gates on the same pinned-peer +
    # folder-share + capability checks as the existing BLOB_OFFER path.
    BLOB_REQUEST_V1,
    # COVER_TRAFFIC_V1 is a privacy primitive — opaque random bytes
    # the receiver drops silently. Adds no user-facing power; it
    # only obscures traffic patterns. Sender + receiver gate on
    # pairing (cover packets only flow between paired peers).
    COVER_TRAFFIC_V1,
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
