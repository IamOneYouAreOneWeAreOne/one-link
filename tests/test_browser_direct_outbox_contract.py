"""Static guardrails for peer.html's executable direct-chat outbox.

The browser E2E companion proves these paths against real IndexedDB/Web Locks;
these fast checks ensure the full contract remains in the default test gate.
"""

from pathlib import Path


PEER = Path("src/one_link/web/peer.html")


def _between(source: str, start: str, end: str) -> str:
    left = source.index(start)
    right = source.index(end, left + len(start))
    return source[left:right]


def test_direct_outbox_schema_is_bounded_and_identity_indexed() -> None:
    source = PEER.read_text(encoding="utf-8")
    schema = _between(source, "const MSG_PROTOCOL_VERSION", "function _newMessageId")
    open_db = _between(source, "function _openMessagesDb", "function _validStoredMessageId")
    assert 'MSG_OUTBOX_STORE_NAME = "outbox.v1"' in schema
    assert 'MSG_QUARANTINE_STORE_NAME = "outbox-quarantine.v1"' in schema
    assert "MSG_DB_VERSION = 3" in schema
    assert "MSG_OUTBOX_MAX_ROWS_PER_PEER = 512" in schema
    assert "MSG_OUTBOX_MAX_TOTAL_ROWS = 2000" in schema
    assert '"by_owner_peer", ["owner_fp", "peer_fp"]' in open_db
    assert '"by_owner_peer_id", ["owner_fp", "peer_fp", "id"]' in open_db
    assert "unique: true" in open_db


def test_outbound_history_and_outbox_admit_in_one_transaction() -> None:
    source = PEER.read_text(encoding="utf-8")
    persist = _between(
        source,
        "async function persistOutboundMessage",
        "function _sameRawChatOutboxRow",
    )
    assert "[MSG_STORE_NAME, MSG_OUTBOX_STORE_NAME]" in persist
    assert '"readwrite"' in persist
    assert "_sameStoredMessage" in persist
    assert "_sameChatOutboxPayload" in persist
    assert "message id was reused for different content" in persist
    assert "chat outbox id was reused for different content" in persist
    assert "MSG_OUTBOX_MAX_ROWS_PER_PEER" in persist
    assert "MSG_OUTBOX_MAX_TOTAL_ROWS" in persist
    assert persist.index("messages.add(message)") < persist.index("await done")
    assert persist.index("queue.add(outbox)") < persist.index("await done")


def test_session_binding_freezes_both_local_and_remote_authorities() -> None:
    source = PEER.read_text(encoding="utf-8")
    pairing = _between(source, "function _newPairing", "function _abortPairing")
    binding = _between(source, "function _activeChatBinding", "function _chatWireJson")
    assert "local_identity_fingerprint" in pairing
    assert "local_identity_pubkey_b64u" in pairing
    assert "p.local_identity_fingerprint !== ownerFp" in binding
    assert "p.local_identity_pubkey_b64u !== state.rec.public_key_b64u" in binding
    assert "remote_signal_signer_fingerprint !== peerFp" in binding
    assert "remote_signal_signer_pubkey_b64u !== p.remote_hello.pubkey" in binding
    assert "chat_session_id" in binding


def test_replay_reserves_before_exact_wire_send_and_is_mutexed() -> None:
    source = PEER.read_text(encoding="utf-8")
    reserve = _between(
        source,
        "async function _reserveChatOutboxAttempt",
        "async function _drainChatOutboxOnce",
    )
    drain = _between(
        source,
        "async function _drainChatOutboxOnce",
        "async function acknowledgeOutboundMessage",
    )
    assert "current.last_session_id === sessionId" in reserve
    assert "last_session_id: sessionId" in reserve
    assert "attempt_count: current.attempt_count + 1" in reserve
    reserve_call = drain.index("await _reserveChatOutboxAttempt")
    wire_send = drain.index("control.send(reserved.wire_json)")
    assert reserve_call < wire_send
    assert "_chatOutboxDrainTail" in drain
    assert "navigator.locks.request" in drain
    assert "MSG_OUTBOX_LOCK_NAME" in drain


def test_ack_marks_history_and_deletes_exact_outbox_atomically() -> None:
    source = PEER.read_text(encoding="utf-8")
    ack = _between(
        source,
        "async function acknowledgeOutboundMessage",
        "// ── chat send + receive",
    )
    assert "[MSG_STORE_NAME, MSG_OUTBOX_STORE_NAME]" in ack
    assert "queued.body !== message.body" in ack
    assert "queued.ts !== message.ts" in ack
    assert "message.ack_ms = ackMs" in ack
    assert "queue.delete(outboxKey)" in ack
    assert ack.index("message.ack_ms = ackMs") < ack.index("await done")
    assert ack.index("queue.delete(outboxKey)") < ack.index("await done")


def test_malformed_rows_are_removed_with_body_free_bounded_diagnostics() -> None:
    source = PEER.read_text(encoding="utf-8")
    quarantine = _between(
        source,
        "function _chatOutboxQuarantineSummary",
        "async function listChatOutbox",
    )
    drain = _between(
        source,
        "async function _drainChatOutboxOnce",
        "let _chatOutboxDrainTail",
    )
    assert "body_code_units" in quarantine
    assert "body:" not in quarantine
    assert "MSG_OUTBOX_QUARANTINE_MAX_ROWS" in quarantine
    assert "store.delete(candidate.row.key)" in quarantine
    assert "quarantineChatOutboxRows" in drain
    assert "Promise.all(invalidRows.map" in quarantine
    assert "MSG_OUTBOX_MAX_BATCHES_PER_DRAIN" in drain
    assert "removedInvalid" in drain


def test_revocation_paths_purge_queued_authority() -> None:
    source = PEER.read_text(encoding="utf-8")
    delete_identity = _between(
        source, "async function deleteIdentity", "// Narrow raw authority hooks"
    )
    delete_peer = _between(source, "async function deletePeer", "// SAS derivation:")
    assert "clearChatOutboxForOwner(ownerFp)" in delete_identity
    assert "clearChatOutboxForPeer(canonical)" in delete_peer
