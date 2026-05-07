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
FOLDER_SYNC = "folder_sync"
MERKLE_SYNC = "merkle_sync"
FUTURE_TRANSPORTS = "future_transports"
# v0.7.2: capability advertisement for the Signal-style Double Ratchet.
# When BOTH peers advertise this in CAPS, post-handshake traffic
# upgrades to forward-secret + post-compromise-secure encryption.
# The library lives in one_link.double_ratchet; channel-level
# activation lands in v0.7.3 (this release ships the negotiation
# capability + audited library only, so deployments can interop
# without yet flipping the wire format).
DOUBLE_RATCHET_V1 = "double_ratchet_v1"

LOCAL_CAPABILITIES = (
    CHAT,
    FILES,
    FILE_CDC,
    FILE_RESUMABLE,
    FILE_SWARM,
    FILE_COMPRESSION,
    FOLDER_SYNC,
    MERKLE_SYNC,
    FUTURE_TRANSPORTS,
    DOUBLE_RATCHET_V1,
)

# v0.7.1 deny-by-default capability split. The audit doc
# (docs/SECURITY_AUDIT_v0.7.0.md, finding A) prescribes:
#   - chat: allowed-after-pairing — automatic on SAS confirm
#   - files / folder / group / future_transports: prompt/allowlist —
#     user must explicitly grant
# These tuples are the policy-layer enforcement points.
DEFAULT_ALLOW_AFTER_PAIRING = (CHAT,)
PROMPT_REQUIRED = (FILES, FOLDER_SYNC, MERKLE_SYNC, FUTURE_TRANSPORTS)
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
    DOUBLE_RATCHET_V1,
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
