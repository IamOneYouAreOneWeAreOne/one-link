"""Per-peer capability model.

Capabilities are intentionally plain strings on the wire. That keeps the
protocol auditable and lets older peers ignore features they do not know yet.
"""

from __future__ import annotations


CHAT = "chat"
FILES = "files"
FILE_CDC = "file_cdc"
FOLDER_SYNC = "folder_sync"
MERKLE_SYNC = "merkle_sync"
FUTURE_TRANSPORTS = "future_transports"

LOCAL_CAPABILITIES = (
    CHAT,
    FILES,
    FILE_CDC,
    FOLDER_SYNC,
    MERKLE_SYNC,
    FUTURE_TRANSPORTS,
)

# v0.7.1 deny-by-default capability split. The audit doc
# (docs/SECURITY_AUDIT_v0.7.0.md, finding A) prescribes:
#   - chat: allowed-after-pairing — automatic on SAS confirm
#   - files / folder / group / future_transports: prompt/allowlist —
#     user must explicitly grant
# These tuples are the policy-layer enforcement points.
DEFAULT_ALLOW_AFTER_PAIRING = (CHAT,)
PROMPT_REQUIRED = (FILES, FILE_CDC, FOLDER_SYNC, MERKLE_SYNC, FUTURE_TRANSPORTS)


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
