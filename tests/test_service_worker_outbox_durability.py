"""Service-worker outbox transaction and concurrency contracts."""

from pathlib import Path


SW = Path("src/one_link/web/sw.js")
INDEX = Path("src/one_link/web/index.html")


def _between(source: str, start: str, end: str) -> str:
    left = source.index(start)
    right = source.index(end, left + len(start))
    return source[left:right]


def test_network_fetch_is_outside_indexeddb_transaction() -> None:
    source = SW.read_text(encoding="utf-8")
    drain = _between(source, "async function _drainOutboxOnce", "function drainOutbox")
    assert "await idbTransactionDone(snapshotTx)" in drain
    assert drain.index("await idbTransactionDone(snapshotTx)") < drain.index("await fetch(")
    assert "_deleteDeliveredOutboxItem" in drain
    delete = _between(
        source,
        "async function _deleteDeliveredOutboxItem",
        "async function _drainOutboxOnce",
    )
    assert 'db.transaction(IDB_STORE, "readwrite")' in delete
    assert "await fetch(" not in delete


def test_outbox_has_in_process_mutex_and_cross_worker_lease() -> None:
    source = SW.read_text(encoding="utf-8")
    assert "let outboxDrainTail = Promise.resolve()" in source
    assert "outboxDrainTail.then(_drainOutboxOnce" in source
    assert "_acquireOutboxLease" in source
    assert "_renewOutboxLease" in source
    assert "_releaseOutboxLease" in source
    assert "OUTBOX_LEASE_TTL_MS" in source


def test_outbox_delete_is_bound_to_exact_dispatched_payload() -> None:
    source = SW.read_text(encoding="utf-8")
    helper = _between(
        source,
        "function _sameQueuedDispatch",
        "async function _drainOutboxOnce",
    )
    for field in ("dedupe_key", "url", "method", "body"):
        assert field in helper
    assert "outbox row changed while delivery was in flight" in helper


def test_page_queue_uses_unique_client_message_id_and_exact_replay() -> None:
    source = INDEX.read_text(encoding="utf-8")
    validator = _between(source, "function _validatedOutboxSend", "async function _outboxQueue")
    queue = _between(source, "async function _outboxQueue", "async function _outboxRequestSync")
    assert 'index("dedupe_key")' in queue
    assert "client_msg_id" in validator
    assert "existing.body !== queuedItem.body" in queue
    assert "tx.abort()" in queue
    assert "_OUTBOX_MAX_ROWS" in queue
    assert "OUTBOX_CONFLICT" in queue
    assert "OUTBOX_QUOTA" in queue
    assert 'indexedDB.open("one-link-outbox-v1", 3)' in source
    assert "indexedDB.open(IDB_NAME, IDB_VERSION)" in SW.read_text(encoding="utf-8")


def test_service_worker_outbox_is_not_generic_replay_engine() -> None:
    source = SW.read_text(encoding="utf-8")
    validator = _between(source, "function _validQueuedSend", "async function _deleteDeliveredOutboxItem")
    drain = _between(source, "async function _drainOutboxOnce", "function drainOutbox")
    assert 'item.url !== "/api/send"' in validator
    assert 'item.method !== "POST"' in validator
    assert "OUTBOX_MAX_BODY_BYTES" in validator
    assert "OUTBOX_MAX_ROWS" in source
    assert "acknowledgement.ok !== true" in drain
    assert "AbortController" in drain


def test_v1_queue_upgrade_backfills_dedupe_keys_without_stalling() -> None:
    for source in (SW.read_text(encoding="utf-8"), INDEX.read_text(encoding="utf-8")):
        assert "event.oldVersion < 2" in source
        assert "openCursor()" in source
        assert "client_msg_id" in source
        assert "legacy-conflict:" in source
        assert "cursor.delete()" in source


def test_poison_rows_are_removed_and_diagnosed_without_copying_body() -> None:
    source = SW.read_text(encoding="utf-8")
    helper = _between(
        source,
        "function _outboxQuarantineSummary",
        "async function _deleteDeliveredOutboxItem",
    )
    drain = _between(source, "async function _drainOutboxOnce", "function drainOutbox")
    assert 'IDB_QUARANTINE_STORE = "quarantine"' in source
    assert "OUTBOX_QUARANTINE_MAX_ROWS" in helper
    assert "body_code_units" in helper
    assert "body:" not in helper
    assert "_quarantineInvalidOutboxItems" in drain
    assert "invalidItems" in drain


def test_full_poison_snapshot_cannot_starve_later_valid_rows() -> None:
    source = SW.read_text(encoding="utf-8")
    drain = _between(source, "async function _drainOutboxOnce", "function drainOutbox")
    assert "OUTBOX_MAX_BATCHES_PER_DRAIN" in drain
    assert "for (let batch = 0;" in drain
    assert "lastBatchWasFull" in drain
    assert "if (!lastBatchWasFull) break" in drain
    assert 'sync.register("ol-outbox")' in drain
