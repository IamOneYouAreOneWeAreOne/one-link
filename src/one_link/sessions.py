"""Explicit peer session protocol definitions.

This is a lightweight runtime mirror of the coherence_lang session-protocol
idea: every peer conversation has a named, ordered shape that audit tools and
tests can inspect.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Step:
    direction: str
    message: str
    note: str = ""


@dataclass(frozen=True)
class Protocol:
    name: str
    steps: tuple[Step, ...]

    def to_dict(self) -> dict:
        return {"name": self.name, "steps": [asdict(s) for s in self.steps]}


PROTOCOLS = (
    Protocol(
        "chat_text",
        (
            Step("send", "CAPS", "advertise capabilities"),
            Step("send", "TEXT", "deliver one chat message"),
            Step("recv", "ACK", "receiver persisted message"),
        ),
    ),
    Protocol(
        "file_cdc_transfer",
        (
            Step("send", "CAPS"),
            Step("send", "FILE_OFFER", "includes whole-file hash and CDC chunk index"),
            Step("recv", "FILE_WANTS", "receiver names missing chunk indexes"),
            Step("send", "FILE_CDC_CHUNK", "only missing chunks cross the wire"),
            Step("recv", "ACK", "per chunk integrity/sequence acknowledgment"),
        ),
    ),
    Protocol(
        "folder_merkle_sync",
        (
            Step("send", "CAPS"),
            Step("send", "MANIFEST_PUSH", "includes Merkle root and manifest rows"),
            Step("recv", "MANIFEST_WANTS", "empty when Merkle roots already match"),
            Step("send", "BLOB_OFFER"),
            Step("send", "BLOB_CHUNK"),
        ),
    ),
    Protocol(
        "pairing",
        (
            Step("send", "PAIR_REQUEST"),
            Step("recv", "ACK"),
            Step("send", "PAIR_CONFIRM"),
            Step("recv", "ACK"),
        ),
    ),
)


def protocol_catalog() -> list[dict]:
    return [p.to_dict() for p in PROTOCOLS]
