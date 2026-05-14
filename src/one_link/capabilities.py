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
    FOLDER_SYNC,
    MERKLE_SYNC,
    FUTURE_TRANSPORTS,
    SELF_MESH_MANIFEST,
    SELF_MESH_SEND,
    DOUBLE_RATCHET_V1,
    NATIVE_TRANSFER_V1,
    BLOOM_INIT_V1,
    QUIC_TRANSPORT_V1,
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
    DOUBLE_RATCHET_V1,
    NATIVE_TRANSFER_V1,
    BLOOM_INIT_V1,
    QUIC_TRANSPORT_V1,
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
