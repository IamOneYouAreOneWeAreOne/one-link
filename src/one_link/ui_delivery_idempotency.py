"""Power-loss-durable idempotency for authenticated UI file sends.

The browser-to-daemon HTTP hop is not the delivery authority.  A response can
be lost after the daemon has already emitted a ``FILE_OFFER``; blindly handling
the retried multipart request as a new upload would therefore create a second
wire delivery.  This module binds a browser-minted idempotency key to the exact
send contract *before* the daemon is allowed to offer bytes.

The store deliberately lives beside, rather than inside, ``state.db``.  It is a
small security boundary with ``synchronous=FULL`` on every mutation, while the
high-volume activity ledger can retain its independently tuned durability
policy.  Contract mismatches fail closed and an ambiguous post-dispatch row is
never reclaimed automatically after a process restart.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time
from typing import Any, Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from one_link.fault_observability import report_best_effort_failure

log = logging.getLogger(__name__)


_CLIENT_DELIVERY_RE = re.compile(r"^[0-9a-f]{32}$")
_BLOB_RE = re.compile(r"^[0-9a-f]{64}$")
_TRANSFER_RE = re.compile(r"^out:[0-9a-f]{64}:[0-9a-f]{12,64}$")
_DELIVERY_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_SCOPE_BYTES = 256
_MAX_NAME_BYTES = 1024
_MAX_REL_PATH_BYTES = 8192
_MAX_RESPONSE_BYTES = 64 * 1024
_DEFAULT_MAX_RECORDS = 250_000
_WAL_AUTOCHECKPOINT_PAGES = 256
_WAL_RETAINED_BYTES = 16 * 1024 * 1024
_SCHEMA_VERSION = 4
_CONTRACT_DIGEST_DOMAIN = b"OL/ui-file-contract/v3\0"
_PRINCIPAL_DIGEST_DOMAIN = b"OL/ui-principal/v3\0"
_IDENTITY_KEY_DOMAIN = b"OL/ui-transfer-identity-key/v3\0"
_IDENTITY_AAD_DOMAIN = b"OL/ui-transfer-identity/v3\0"
_RESPONSE_KEY_DOMAIN = b"OL/ui-response-key/v3\0"
_RESPONSE_AAD_DOMAIN = b"OL/ui-response/v3\0"
_KEY_VERIFIER_DOMAIN = b"OL/ui-store-key-verifier/v3\0"
_LEGACY_V2_KEY_VERIFIER_DOMAIN = b"OL/ui-store-key-verifier/v2\0"
_EXTERNAL_CLIENT_ID_DOMAIN = b"OL/external-client-delivery-id/v3\0"


def _is_link_or_reparse(path: Path, value: os.stat_result) -> bool:
    """Recognize Unix symlinks and Windows junction/reparse-point entries."""

    if stat.S_ISLNK(value.st_mode):
        return True
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if int(getattr(value, "st_file_attributes", 0)) & reparse_flag:
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            return bool(is_junction())
        except OSError:
            return True
    return False


class UIDeliveryIdempotencyError(RuntimeError):
    """Base class for fail-closed UI delivery accounting errors."""


class UIDeliveryContractConflict(UIDeliveryIdempotencyError):
    """An idempotency key was reused for a different send contract."""


class UIDeliveryStoreUnavailable(UIDeliveryIdempotencyError):
    """Durable accounting could not be established or updated."""


class _UIDeliveryIntegrityFailure(UIDeliveryStoreUnavailable):
    """Internal marker for authenticated state that can no longer be trusted."""


@dataclass(frozen=True)
class UIDeliveryContract:
    """Every user-visible and wire-relevant field bound to one UI intent."""

    peer_fp: str
    blob_hash: str
    size: int
    display_name: str
    rel_path: str
    chat_inline: bool

    def validate(self) -> None:
        if not _BLOB_RE.fullmatch(self.peer_fp):
            raise ValueError("peer fingerprint must be canonical lowercase hex")
        if not _BLOB_RE.fullmatch(self.blob_hash):
            raise ValueError("content hash must be canonical lowercase hex")
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or self.size < 0
        ):
            raise ValueError("file size must be a non-negative integer")
        if not self.display_name or len(self.display_name.encode("utf-8")) > _MAX_NAME_BYTES:
            raise ValueError("display name is empty or too large")
        if len(self.rel_path.encode("utf-8")) > _MAX_REL_PATH_BYTES:
            raise ValueError("relative path is too large")
        if not isinstance(self.chat_inline, bool):
            raise ValueError("chat_inline must be boolean")


@dataclass(frozen=True)
class UIDeliveryBinding:
    principal_scope: str
    client_delivery_id: str
    contract: UIDeliveryContract
    transfer_id: str
    delivery_id: str | None
    phase: str
    owns_attempt: bool
    reclaimable_before_dispatch: bool
    recoverable_after_restart: bool
    response_status: int | None
    response_body: dict[str, Any] | None

    @property
    def is_replay(self) -> bool:
        return self.response_status is not None and self.response_body is not None

    @property
    def is_outcome_ambiguous(self) -> bool:
        return self.phase == "dispatching" and not self.is_replay


class UIDeliveryIdempotencyStore:
    """SQLite-backed exact-once admission map for local UI file sends.

    One ``UIServer`` instance owns a random epoch.  Rows still owned by the
    same epoch are concurrent duplicate HTTP requests and never dispatch.
    Rows left by an older epoch may be reclaimed only before ``dispatching``;
    once dispatch begins, absence of a response is an outcome-unknown state
    that must be reconciled by the transfer/receipt ledger, never guessed.
    """

    def __init__(
        self,
        path: Path,
        *,
        contract_key: bytes,
        owner_epoch: str | None = None,
        max_records: int = _DEFAULT_MAX_RECORDS,
    ) -> None:
        self.path = Path(path)
        if not isinstance(contract_key, bytes) or len(contract_key) < 32:
            raise ValueError("contract_key must contain at least 256 secret bits")
        self._contract_key = bytes(contract_key)
        self._identity_key = hmac.new(
            self._contract_key,
            _IDENTITY_KEY_DOMAIN,
            hashlib.sha256,
        ).digest()
        self._identity_aead = AESGCM(self._identity_key)
        self._response_key = hmac.new(
            self._contract_key,
            _RESPONSE_KEY_DOMAIN,
            hashlib.sha256,
        ).digest()
        self._response_aead = AESGCM(self._response_key)
        self.owner_epoch = owner_epoch or secrets.token_hex(16)
        if not _CLIENT_DELIVERY_RE.fullmatch(self.owner_epoch):
            raise ValueError("owner_epoch must be 32 lowercase hex characters")
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records < 1
        ):
            raise ValueError("max_records must be a positive integer")
        self._max_records = max_records
        self._lock = threading.RLock()
        self._closed = False
        self._poisoned = False
        self._prepare_path()
        try:
            self._conn = sqlite3.connect(
                str(self.path),
                timeout=30.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._configure()
            self._migrate()
            self._harden_and_sync_paths()
        except Exception as exc:
            with getattr(self, "_lock", threading.RLock()):
                conn = getattr(self, "_conn", None)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception as close_exc:
                        report_best_effort_failure(
                            log,
                            "ui_delivery_store_failed_open_close",
                            close_exc,
                            level=logging.DEBUG,
                        )
            raise UIDeliveryStoreUnavailable(
                f"cannot open durable UI delivery accounting: {exc}"
            ) from exc

    def _prepare_path(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        parent_stat = os.lstat(self.path.parent)
        if _is_link_or_reparse(self.path.parent, parent_stat) or not stat.S_ISDIR(
            parent_stat.st_mode
        ):
            raise UIDeliveryStoreUnavailable(
                "UI delivery database parent is not a private directory"
            )
        for candidate in (
            self.path,
            self.path.with_name(self.path.name + "-wal"),
            self.path.with_name(self.path.name + "-shm"),
        ):
            try:
                candidate_stat = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if _is_link_or_reparse(candidate, candidate_stat):
                raise UIDeliveryStoreUnavailable(
                    f"UI delivery SQLite path cannot be a link: {candidate.name}"
                )
            if not stat.S_ISREG(candidate_stat.st_mode):
                raise UIDeliveryStoreUnavailable(
                    f"UI delivery SQLite path is not a file: {candidate.name}"
                )
        if os.name != "nt":
            try:
                os.chmod(self.path.parent, 0o700)
                if not self.path.exists():
                    fd = os.open(
                        str(self.path),
                        os.O_CREAT | os.O_EXCL | os.O_RDWR,
                        0o600,
                    )
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                os.chmod(self.path, 0o600)
                directory_fd = os.open(str(self.path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as exc:
                raise UIDeliveryStoreUnavailable(
                    f"cannot create private durable accounting path: {exc}"
                ) from exc

    def _configure(self) -> None:
        self._conn.execute("PRAGMA busy_timeout = 30000")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA trusted_schema = OFF")
        self._conn.execute("PRAGMA secure_delete = ON")
        mode_row = self._conn.execute("PRAGMA journal_mode = WAL").fetchone()
        mode = str(mode_row[0]).lower() if mode_row else ""
        if mode != "wal":
            raise UIDeliveryStoreUnavailable(
                f"UI delivery database refused WAL mode ({mode or 'unknown'})"
            )
        self._conn.execute("PRAGMA synchronous = FULL")
        sync_row = self._conn.execute("PRAGMA synchronous").fetchone()
        if not sync_row or int(sync_row[0]) < 2:
            raise UIDeliveryStoreUnavailable("UI delivery database refused FULL sync")
        # Result rows are deliberately retained indefinitely: deleting a
        # completed idempotency key would turn a sufficiently late replay into
        # a second wire delivery.  Bound row count plus bounded field/response
        # sizes therefore provides the safe storage ceiling; once full, new
        # admissions fail closed while every old key remains replayable.
        self._conn.execute(
            f"PRAGMA wal_autocheckpoint = {_WAL_AUTOCHECKPOINT_PAGES}"
        )
        self._conn.execute(f"PRAGMA journal_size_limit = {_WAL_RETAINED_BYTES}")

    def _harden_and_sync_paths(self) -> None:
        """Make initial DB/WAL directory entries private and durable.

        SQLite ``synchronous=FULL`` protects transaction contents, but the first
        creation of the DB/WAL names is a separate filesystem metadata event.
        POSIX therefore verifies 0600 on every SQLite sidecar and fsyncs the
        containing directory before the store can authorize a wire send.
        Response/content metadata is AEAD/HMAC protected on every platform.
        """

        paths = (
            self.path,
            self.path.with_name(self.path.name + "-wal"),
            self.path.with_name(self.path.name + "-shm"),
        )
        for candidate in paths:
            try:
                candidate_stat = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if _is_link_or_reparse(candidate, candidate_stat) or not stat.S_ISREG(
                candidate_stat.st_mode
            ):
                raise UIDeliveryStoreUnavailable(
                    f"unsafe SQLite accounting path: {candidate.name}"
                )
            if os.name != "nt":
                try:
                    os.chmod(candidate, 0o600)
                    mode = candidate.stat().st_mode & 0o777
                except OSError as exc:
                    raise UIDeliveryStoreUnavailable(
                        f"cannot restrict {candidate.name}: {exc}"
                    ) from exc
                if mode & 0o077:
                    raise UIDeliveryStoreUnavailable(
                        f"SQLite accounting path is not private: {candidate.name}"
                    )
        if os.name != "nt":
            try:
                directory_fd = os.open(str(self.path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as exc:
                raise UIDeliveryStoreUnavailable(
                    f"cannot durably sync UI delivery directory: {exc}"
                ) from exc

    def _migrate(self) -> None:
        with self._lock:
            version_row = self._conn.execute("PRAGMA user_version").fetchone()
            version = int(version_row[0]) if version_row else 0
            if version not in (0, 1, 2, 3, _SCHEMA_VERSION):
                raise UIDeliveryStoreUnavailable(
                    f"unsupported UI delivery schema version {version}"
                )
            table_names = {
                str(row[0])
                for row in self._conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            legacy = version in (1, 2) or (
                version == 0 and "ui_file_deliveries" in table_names
            )
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if version == 2 and "ui_delivery_meta" in table_names:
                    legacy_verifier = self._conn.execute(
                        "SELECT key_verifier FROM ui_delivery_meta WHERE singleton = 1"
                    ).fetchone()
                    expected_legacy = hmac.new(
                        self._contract_key,
                        _LEGACY_V2_KEY_VERIFIER_DOMAIN,
                        hashlib.sha256,
                    ).digest()
                    if legacy_verifier is not None and not hmac.compare_digest(
                        bytes(legacy_verifier["key_verifier"]),
                        expected_legacy,
                    ):
                        raise UIDeliveryStoreUnavailable(
                            "UI delivery accounting key does not match this database"
                        )
                if legacy:
                    # v1/v2 existed only during this pre-release audit. v1 had
                    # plaintext contract strings; v2 still leaked blob hashes
                    # through transfer_id. Securely retire both layouts.
                    self._conn.execute("DROP TABLE IF EXISTS ui_file_deliveries")
                    self._conn.execute("DROP TABLE IF EXISTS ui_delivery_meta")
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ui_delivery_meta (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        key_verifier BLOB NOT NULL CHECK(length(key_verifier) = 32)
                    ) STRICT
                    """
                )
                key_verifier = hmac.new(
                    self._contract_key,
                    _KEY_VERIFIER_DOMAIN,
                    hashlib.sha256,
                ).digest()
                verifier_row = self._conn.execute(
                    "SELECT key_verifier FROM ui_delivery_meta WHERE singleton = 1"
                ).fetchone()
                if verifier_row is None:
                    self._conn.execute(
                        "INSERT INTO ui_delivery_meta(singleton, key_verifier) VALUES(1, ?)",
                        (key_verifier,),
                    )
                elif not hmac.compare_digest(
                    bytes(verifier_row["key_verifier"]),
                    key_verifier,
                ):
                    raise UIDeliveryStoreUnavailable(
                        "UI delivery accounting key does not match this database"
                    )
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ui_file_deliveries (
                        record_id BLOB NOT NULL UNIQUE CHECK(length(record_id) = 32),
                        principal_digest BLOB NOT NULL CHECK(length(principal_digest) = 32),
                        client_delivery_id TEXT NOT NULL,
                        contract_digest BLOB NOT NULL CHECK(length(contract_digest) = 32),
                        identity_nonce BLOB NOT NULL CHECK(length(identity_nonce) = 12),
                        identity_ciphertext BLOB NOT NULL CHECK(length(identity_ciphertext) >= 16),
                        phase TEXT NOT NULL CHECK(
                            phase IN ('bound', 'queued', 'dispatching', 'result')
                        ),
                        owner_epoch TEXT NOT NULL,
                        response_status INTEGER,
                        response_nonce BLOB,
                        response_ciphertext BLOB,
                        created_ms INTEGER NOT NULL,
                        updated_ms INTEGER NOT NULL,
                        PRIMARY KEY(principal_digest, client_delivery_id),
                        CHECK(
                            (
                                response_status IS NULL
                                AND response_nonce IS NULL
                                AND response_ciphertext IS NULL
                            )
                            OR
                            (
                                response_status BETWEEN 100 AND 599
                                AND length(response_nonce) = 12
                                AND length(response_ciphertext) >= 16
                            )
                        )
                    ) STRICT
                    """
                )
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ui_file_deliveries_updated "
                    "ON ui_file_deliveries(updated_ms)"
                )
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ui_file_deliveries_client_id "
                    "ON ui_file_deliveries(client_delivery_id)"
                )
                if version == 3:
                    self._upgrade_v3_authenticated_state()
                self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                self._conn.execute("COMMIT")
            except Exception:
                with contextlib.suppress(Exception):
                    self._conn.execute("ROLLBACK")
                raise
            if legacy:
                # secure_delete clears freed cells; VACUUM and a truncated WAL
                # ensure retired plaintext/fingerprint columns cannot survive in
                # unallocated pages or a sidecar after the migration.
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.execute("VACUUM")
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def _upgrade_v3_authenticated_state(self) -> None:
        """Bind mutable phase/owner columns into each encrypted row envelope.

        Schema v3 authenticated contracts, transfer identities, and responses,
        but its plaintext ``phase``/``owner_epoch`` columns were still delivery
        authority. A valid SQLite edit could therefore turn ``dispatching``
        back into reclaimable ``queued`` state. Re-encrypt both the identity and
        any response atomically so every state-machine decision is fail-closed.
        """

        last_record_id: bytes | None = None
        while True:
            if last_record_id is None:
                rows = self._conn.execute(
                    "SELECT * FROM ui_file_deliveries "
                    "ORDER BY record_id LIMIT 256"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM ui_file_deliveries WHERE record_id > ? "
                    "ORDER BY record_id LIMIT 256",
                    (last_record_id,),
                ).fetchall()
            if not rows:
                break
            for row in rows:
                record_id = bytes(row["record_id"])
                transfer_id, delivery_id, contract = self._decode_identity_payload(
                    row,
                    require_authenticated_state=False,
                )
                if contract is None:
                    raise _UIDeliveryIntegrityFailure(
                        "v3 delivery row has no authenticated contract"
                    )
                response_status, response_body = self._decode_response(row)
                identity_nonce, identity_ciphertext = self._encode_identity(
                    row,
                    transfer_id=transfer_id,
                    delivery_id=delivery_id,
                    contract=contract,
                    phase=str(row["phase"]),
                    owner_epoch=str(row["owner_epoch"]),
                )
                self._conn.execute(
                    "UPDATE ui_file_deliveries SET identity_nonce = ?, "
                    "identity_ciphertext = ? WHERE record_id = ?",
                    (identity_nonce, identity_ciphertext, record_id),
                )
                if response_body is not None:
                    assert response_status is not None
                    updated = self._conn.execute(
                        "SELECT * FROM ui_file_deliveries WHERE record_id = ?",
                        (record_id,),
                    ).fetchone()
                    if updated is None:
                        raise _UIDeliveryIntegrityFailure(
                            "v3 delivery row disappeared during migration"
                        )
                    encoded = json.dumps(
                        response_body,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                    response_nonce = secrets.token_bytes(12)
                    response_ciphertext = self._response_aead.encrypt(
                        response_nonce,
                        encoded,
                        self._response_aad(updated, status=response_status),
                    )
                    self._conn.execute(
                        "UPDATE ui_file_deliveries SET response_nonce = ?, "
                        "response_ciphertext = ? WHERE record_id = ?",
                        (response_nonce, response_ciphertext, record_id),
                    )
                last_record_id = record_id
    @staticmethod
    def _validate_key(principal_scope: str, client_delivery_id: str) -> None:
        if not principal_scope or len(principal_scope.encode("utf-8")) > _MAX_SCOPE_BYTES:
            raise ValueError("principal scope is empty or too large")
        if not _CLIENT_DELIVERY_RE.fullmatch(client_delivery_id):
            raise ValueError("client_delivery_id must be 32 lowercase hex characters")

    @staticmethod
    def _transfer_id(blob_hash: str) -> str:
        return f"out:{blob_hash}:{secrets.token_hex(16)}"

    def derive_client_delivery_id(self, *, namespace: str, value: str) -> str:
        """Map another authenticated UI protocol's stable ID into this store.

        The keyed mapping avoids persisting low-entropy or user-correlatable
        phone message IDs while retaining a canonical 128-bit idempotency key.
        """

        if (
            not isinstance(namespace, str)
            or not namespace
            or len(namespace.encode("utf-8")) > 128
            or not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 512
        ):
            raise ValueError("external client delivery identity is invalid")
        payload = (
            _EXTERNAL_CLIENT_ID_DOMAIN
            + len(namespace.encode("utf-8")).to_bytes(2, "big")
            + namespace.encode("utf-8")
            + value.encode("utf-8")
        )
        return hmac.new(self._contract_key, payload, hashlib.sha256).hexdigest()[:32]

    def _principal_digest(self, principal_scope: str) -> bytes:
        return hmac.new(
            self._contract_key,
            _PRINCIPAL_DIGEST_DOMAIN + principal_scope.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _canonical_contract(contract: UIDeliveryContract) -> bytes:
        return json.dumps(
            {
                "blob_hash": contract.blob_hash,
                "chat_inline": contract.chat_inline,
                "display_name": contract.display_name,
                "peer_fp": contract.peer_fp,
                "rel_path": contract.rel_path,
                "size": contract.size,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def _contract_digest(self, contract: UIDeliveryContract) -> bytes:
        return hmac.new(
            self._contract_key,
            _CONTRACT_DIGEST_DOMAIN + self._canonical_contract(contract),
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _identity_aad(row: sqlite3.Row) -> bytes:
        fields = (
            bytes(row["record_id"]),
            bytes(row["principal_digest"]),
            str(row["client_delivery_id"]).encode("ascii"),
            bytes(row["contract_digest"]),
        )
        return _IDENTITY_AAD_DOMAIN + b"\0".join(fields)

    @staticmethod
    def _identity_aad_values(
        *,
        record_id: bytes,
        principal_digest: bytes,
        client_delivery_id: str,
        contract_digest: bytes,
    ) -> bytes:
        return _IDENTITY_AAD_DOMAIN + b"\0".join(
            (
                record_id,
                principal_digest,
                client_delivery_id.encode("ascii"),
                contract_digest,
            )
        )

    def _decode_identity_payload(
        self,
        row: sqlite3.Row,
        *,
        require_authenticated_state: bool = True,
    ) -> tuple[str, str | None, UIDeliveryContract | None]:
        try:
            plaintext = self._identity_aead.decrypt(
                bytes(row["identity_nonce"]),
                bytes(row["identity_ciphertext"]),
                self._identity_aad(row),
            )
            decoded = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise _UIDeliveryIntegrityFailure(
                "durable transfer identity authentication failed"
            ) from exc
        if not isinstance(decoded, dict):
            raise _UIDeliveryIntegrityFailure(
                "durable transfer identity is not an object"
            )
        transfer_id = decoded.get("transfer_id")
        delivery_id = decoded.get("delivery_id")
        if not isinstance(transfer_id, str) or not _TRANSFER_RE.fullmatch(transfer_id):
            raise _UIDeliveryIntegrityFailure("corrupt durable transfer id")
        if delivery_id is not None and (
            not isinstance(delivery_id, str)
            or not _DELIVERY_RE.fullmatch(delivery_id)
        ):
            raise _UIDeliveryIntegrityFailure("corrupt durable wire delivery id")
        stored_phase = decoded.get("phase")
        stored_owner = decoded.get("owner_epoch")
        if stored_phase is not None or stored_owner is not None:
            if stored_phase not in {"bound", "queued", "dispatching", "result"}:
                raise _UIDeliveryIntegrityFailure("corrupt durable delivery phase")
            if not isinstance(stored_owner, str) or (
                stored_owner != "" and not _CLIENT_DELIVERY_RE.fullmatch(stored_owner)
            ):
                raise _UIDeliveryIntegrityFailure("corrupt durable delivery owner")
            if stored_phase != str(row["phase"]):
                raise _UIDeliveryIntegrityFailure("durable delivery phase changed")
            if stored_owner != str(row["owner_epoch"]):
                raise _UIDeliveryIntegrityFailure("durable delivery owner changed")
        elif require_authenticated_state:
            raise _UIDeliveryIntegrityFailure(
                "durable delivery state authentication is missing"
            )
        contract_raw = decoded.get("contract")
        stored_contract: UIDeliveryContract | None = None
        if contract_raw is not None:
            if not isinstance(contract_raw, dict):
                raise _UIDeliveryIntegrityFailure(
                    "durable transfer contract is not an object"
                )
            try:
                stored_contract = UIDeliveryContract(
                    peer_fp=contract_raw["peer_fp"],
                    blob_hash=contract_raw["blob_hash"],
                    size=contract_raw["size"],
                    display_name=contract_raw["display_name"],
                    rel_path=contract_raw["rel_path"],
                    chat_inline=contract_raw["chat_inline"],
                )
                stored_contract.validate()
            except (KeyError, TypeError, ValueError) as exc:
                raise _UIDeliveryIntegrityFailure(
                    "durable transfer contract is corrupt"
                ) from exc
            if not hmac.compare_digest(
                bytes(row["contract_digest"]),
                self._contract_digest(stored_contract),
            ):
                raise _UIDeliveryIntegrityFailure(
                    "durable transfer contract authentication failed"
                )
        return transfer_id, delivery_id, stored_contract

    def _decode_identity(self, row: sqlite3.Row) -> tuple[str, str | None]:
        transfer_id, delivery_id, _contract = self._decode_identity_payload(row)
        return transfer_id, delivery_id

    def _encode_identity(
        self,
        row: sqlite3.Row,
        *,
        transfer_id: str,
        delivery_id: str | None,
        contract: UIDeliveryContract,
        phase: str | None = None,
        owner_epoch: str | None = None,
    ) -> tuple[bytes, bytes]:
        authenticated_phase = str(row["phase"]) if phase is None else phase
        authenticated_owner = (
            str(row["owner_epoch"]) if owner_epoch is None else owner_epoch
        )
        if authenticated_phase not in {"bound", "queued", "dispatching", "result"}:
            raise ValueError("delivery phase cannot be authenticated")
        if authenticated_owner != "" and not _CLIENT_DELIVERY_RE.fullmatch(
            authenticated_owner
        ):
            raise ValueError("delivery owner cannot be authenticated")
        contract_body = json.loads(self._canonical_contract(contract).decode("utf-8"))
        encoded = json.dumps(
            {
                "contract": contract_body,
                "delivery_id": delivery_id,
                "owner_epoch": authenticated_owner,
                "phase": authenticated_phase,
                "transfer_id": transfer_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        nonce = secrets.token_bytes(12)
        return nonce, self._identity_aead.encrypt(
            nonce,
            encoded,
            self._identity_aad(row),
        )

    @staticmethod
    def _response_aad(row: sqlite3.Row, *, status: int | None = None) -> bytes:
        """Authenticate every unencrypted field needed to interpret a result."""

        effective_status = row["response_status"] if status is None else status
        if effective_status is None:
            raise _UIDeliveryIntegrityFailure(
                "durable UI response status is missing"
            )
        fields = (
            bytes(row["record_id"]),
            bytes(row["principal_digest"]),
            str(row["client_delivery_id"]).encode("ascii"),
            bytes(row["contract_digest"]),
            hashlib.sha256(
                bytes(row["identity_nonce"])
                + bytes(row["identity_ciphertext"])
            ).digest(),
            str(int(effective_status)).encode("ascii"),
        )
        return _RESPONSE_AAD_DOMAIN + b"\0".join(fields)

    def _decode_response(self, row: sqlite3.Row) -> tuple[int | None, dict[str, Any] | None]:
        status_raw = row["response_status"]
        nonce_raw = row["response_nonce"]
        ciphertext_raw = row["response_ciphertext"]
        if status_raw is None and nonce_raw is None and ciphertext_raw is None:
            return None, None
        if status_raw is None or nonce_raw is None or ciphertext_raw is None:
            raise _UIDeliveryIntegrityFailure(
                "incomplete durable UI response record"
            )
        try:
            plaintext = self._response_aead.decrypt(
                bytes(nonce_raw),
                bytes(ciphertext_raw),
                self._response_aad(row),
            )
            decoded = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise _UIDeliveryIntegrityFailure(
                "durable UI response authentication failed"
            ) from exc
        if not isinstance(decoded, dict):
            raise _UIDeliveryIntegrityFailure(
                "durable UI response is not an object"
            )
        return int(status_raw), decoded

    def _binding(
        self,
        row: sqlite3.Row,
        *,
        principal_scope: str,
        contract: UIDeliveryContract,
        owns_attempt: bool,
    ) -> UIDeliveryBinding:
        self._assert_contract(row, contract)
        response_status, response_body = self._decode_response(row)
        transfer_id, delivery_id = self._decode_identity(row)
        return UIDeliveryBinding(
            principal_scope=principal_scope,
            client_delivery_id=str(row["client_delivery_id"]),
            contract=contract,
            transfer_id=transfer_id,
            delivery_id=delivery_id,
            phase=str(row["phase"]),
            owns_attempt=owns_attempt,
            reclaimable_before_dispatch=(
                str(row["phase"]) in {"bound", "queued"}
                and response_body is None
                and str(row["owner_epoch"]) != self.owner_epoch
            ),
            recoverable_after_restart=(
                str(row["phase"]) == "dispatching"
                and response_body is None
                and str(row["owner_epoch"]) != self.owner_epoch
            ),
            response_status=response_status,
            response_body=response_body,
        )

    def _assert_contract(
        self,
        row: sqlite3.Row,
        expected: UIDeliveryContract,
    ) -> None:
        actual = bytes(row["contract_digest"])
        wanted = self._contract_digest(expected)
        if not hmac.compare_digest(actual, wanted):
            raise UIDeliveryContractConflict(
                "client_delivery_id is already bound to a different file send"
            )

    def bind(
        self,
        *,
        principal_scope: str,
        client_delivery_id: str,
        contract: UIDeliveryContract,
    ) -> UIDeliveryBinding:
        """Create or replay an exact contract under a FULL-sync transaction."""

        self._validate_key(principal_scope, client_delivery_id)
        contract.validate()
        principal_digest = self._principal_digest(principal_scope)
        contract_digest = self._contract_digest(contract)
        now_ms = int(time.time() * 1000)
        with self._transaction():
            row = self._conn.execute(
                "SELECT * FROM ui_file_deliveries "
                "WHERE principal_digest = ? AND client_delivery_id = ?",
                (principal_digest, client_delivery_id),
            ).fetchone()
            if row is None:
                # Client IDs are 128-bit browser-minted delivery identities,
                # not per-session sequence numbers. Refuse reuse across auth
                # namespaces: a session revocation/token rotation during a
                # retry must fail closed instead of creating a second transfer
                # under the fallback principal. BEGIN IMMEDIATE + the store
                # lock make this check/insert atomic across server instances.
                other_principal = self._conn.execute(
                    "SELECT 1 FROM ui_file_deliveries "
                    "WHERE client_delivery_id = ? LIMIT 1",
                    (client_delivery_id,),
                ).fetchone()
                if other_principal is not None:
                    raise UIDeliveryContractConflict(
                        "client_delivery_id belongs to another authenticated principal"
                    )
                row_count = self._conn.execute(
                    "SELECT count(*) FROM ui_file_deliveries"
                ).fetchone()
                if row_count is None:
                    raise _UIDeliveryIntegrityFailure(
                        "durable UI delivery capacity query returned no result"
                    )
                if int(row_count[0]) >= self._max_records:
                    raise UIDeliveryStoreUnavailable(
                        "UI delivery idempotency capacity is exhausted; "
                        "old keys were retained to prevent unsafe replay"
                    )
                transfer_id = self._transfer_id(contract.blob_hash)
                record_id = secrets.token_bytes(32)
                identity_nonce = secrets.token_bytes(12)
                contract_body = json.loads(
                    self._canonical_contract(contract).decode("utf-8")
                )
                identity_plaintext = json.dumps(
                    {
                        "contract": contract_body,
                        "delivery_id": None,
                        "owner_epoch": self.owner_epoch,
                        "phase": "bound",
                        "transfer_id": transfer_id,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                identity_ciphertext = self._identity_aead.encrypt(
                    identity_nonce,
                    identity_plaintext,
                    self._identity_aad_values(
                        record_id=record_id,
                        principal_digest=principal_digest,
                        client_delivery_id=client_delivery_id,
                        contract_digest=contract_digest,
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO ui_file_deliveries(
                        record_id, principal_digest, client_delivery_id, contract_digest,
                        identity_nonce, identity_ciphertext, phase, owner_epoch, response_status,
                        response_nonce, response_ciphertext, created_ms, updated_ms
                    ) VALUES(?, ?, ?, ?, ?, ?, 'bound', ?, NULL, NULL, NULL, ?, ?)
                    """,
                    (
                        record_id,
                        principal_digest,
                        client_delivery_id,
                        contract_digest,
                        identity_nonce,
                        identity_ciphertext,
                        self.owner_epoch,
                        now_ms,
                        now_ms,
                    ),
                )
                row = self._conn.execute(
                    "SELECT * FROM ui_file_deliveries "
                    "WHERE principal_digest = ? AND client_delivery_id = ?",
                    (principal_digest, client_delivery_id),
                ).fetchone()
                if row is None:  # pragma: no cover - SQLite invariant
                    raise _UIDeliveryIntegrityFailure(
                        "durable binding insert vanished"
                    )
                return self._binding(
                    row,
                    principal_scope=principal_scope,
                    contract=contract,
                    owns_attempt=True,
                )

            self._assert_contract(row, contract)
            existing = self._binding(
                row,
                principal_scope=principal_scope,
                contract=contract,
                owns_attempt=False,
            )
            if existing.is_replay or existing.phase == "dispatching":
                return existing
            if str(row["owner_epoch"]) == self.owner_epoch:
                # A concurrent request in this server already owns admission.
                return existing
            identity_nonce, identity_ciphertext = self._encode_identity(
                row,
                transfer_id=existing.transfer_id,
                delivery_id=existing.delivery_id,
                contract=contract,
                phase=existing.phase,
                owner_epoch=self.owner_epoch,
            )
            self._conn.execute(
                "UPDATE ui_file_deliveries SET owner_epoch = ?, "
                "identity_nonce = ?, identity_ciphertext = ?, updated_ms = ? "
                "WHERE principal_digest = ? AND client_delivery_id = ?",
                (
                    self.owner_epoch,
                    identity_nonce,
                    identity_ciphertext,
                    now_ms,
                    principal_digest,
                    client_delivery_id,
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM ui_file_deliveries "
                "WHERE principal_digest = ? AND client_delivery_id = ?",
                (principal_digest, client_delivery_id),
            ).fetchone()
            if row is None:  # pragma: no cover - SQLite invariant
                raise _UIDeliveryIntegrityFailure("durable binding disappeared")
            return self._binding(
                row,
                principal_scope=principal_scope,
                contract=contract,
                owns_attempt=True,
            )

    def mark_queued(
        self,
        binding: UIDeliveryBinding,
        *,
        delivery_id: str,
    ) -> UIDeliveryBinding:
        if not _DELIVERY_RE.fullmatch(delivery_id):
            raise ValueError("wire delivery_id must be 32 lowercase hex characters")
        return self._advance(binding, phase="queued", delivery_id=delivery_id)

    def probe(
        self,
        *,
        principal_scope: str,
        client_delivery_id: str,
    ) -> UIDeliveryBinding | None:
        """Read an existing exact intent without claiming or mutating it.

        New rows carry their full contract inside the authenticated encrypted
        identity envelope.  That lets the HTTP multipart parser prove a replay
        from the small metadata prefix and stop before reading a multi-gigabyte
        file part.  Pre-upgrade rows intentionally return ``None`` so callers
        fall back to hashing the body and the normal exact ``bind`` path.
        """

        self._validate_key(principal_scope, client_delivery_id)
        principal_digest = self._principal_digest(principal_scope)
        with self._transaction(write=False):
            row = self._conn.execute(
                "SELECT * FROM ui_file_deliveries "
                "WHERE principal_digest = ? AND client_delivery_id = ?",
                (principal_digest, client_delivery_id),
            ).fetchone()
            if row is None:
                return None
            _transfer_id, _delivery_id, contract = self._decode_identity_payload(row)
            if contract is None:
                return None
            return self._binding(
                row,
                principal_scope=principal_scope,
                contract=contract,
                owns_attempt=False,
            )

    def mark_dispatching(self, binding: UIDeliveryBinding) -> UIDeliveryBinding:
        """Persist the point after which replay must assume wire ambiguity."""

        return self._advance(binding, phase="dispatching")

    def release_before_dispatch(self, binding: UIDeliveryBinding) -> UIDeliveryBinding:
        """Allow a later request to reclaim a failure proven pre-wire."""

        now_ms = int(time.time() * 1000)
        with self._transaction():
            row = self._require_owned_row(binding)
            if str(row["phase"]) == "dispatching":
                raise UIDeliveryStoreUnavailable(
                    "cannot release an outcome-unknown delivery"
                )
            transfer_id, delivery_id = self._decode_identity(row)
            identity_nonce, identity_ciphertext = self._encode_identity(
                row,
                transfer_id=transfer_id,
                delivery_id=delivery_id,
                contract=binding.contract,
                owner_epoch="",
            )
            self._conn.execute(
                "UPDATE ui_file_deliveries SET owner_epoch = '', "
                "identity_nonce = ?, identity_ciphertext = ?, updated_ms = ? "
                "WHERE principal_digest = ? AND client_delivery_id = ?",
                (
                    identity_nonce,
                    identity_ciphertext,
                    now_ms,
                    self._principal_digest(binding.principal_scope),
                    binding.client_delivery_id,
                ),
            )
            return self._read_binding(binding, owns_attempt=False)

    def record_response(
        self,
        binding: UIDeliveryBinding,
        *,
        status: int,
        body: dict[str, Any],
    ) -> UIDeliveryBinding:
        return self._record_response(
            binding,
            status=status,
            body=body,
            reconciled_after_restart=False,
        )

    def record_reconciled_response(
        self,
        binding: UIDeliveryBinding,
        *,
        status: int,
        body: dict[str, Any],
    ) -> UIDeliveryBinding:
        """Persist a result proven by the durable transfer/receipt ledger.

        This is deliberately distinct from :meth:`record_response`: only a
        reconstructed server may close an old ``dispatching`` owner epoch, and
        its caller must first prove the exact transfer/delivery contract from
        the authoritative ledger.
        """

        return self._record_response(
            binding,
            status=status,
            body=body,
            reconciled_after_restart=True,
        )

    def _record_response(
        self,
        binding: UIDeliveryBinding,
        *,
        status: int,
        body: dict[str, Any],
        reconciled_after_restart: bool,
    ) -> UIDeliveryBinding:
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise ValueError("HTTP response status is outside 100..599")
        if not isinstance(body, dict):
            raise ValueError("HTTP response must be a JSON object")
        try:
            encoded = json.dumps(
                body,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("HTTP response is not canonical JSON") from exc
        if len(encoded) > _MAX_RESPONSE_BYTES:
            raise ValueError("HTTP response is too large for idempotency accounting")
        now_ms = int(time.time() * 1000)
        with self._transaction():
            row = self._row_for(binding)
            self._assert_binding_row(row, binding)
            response_status, response_body = self._decode_response(row)
            if response_body is not None:
                if response_status != status or response_body != body:
                    raise UIDeliveryStoreUnavailable("durable response is immutable")
                return self._binding(
                    row,
                    principal_scope=binding.principal_scope,
                    contract=binding.contract,
                    owns_attempt=False,
                )

            owner_epoch = str(row["owner_epoch"])
            if reconciled_after_restart:
                if str(row["phase"]) != "dispatching":
                    raise UIDeliveryStoreUnavailable(
                        "only a dispatching delivery may be ledger-reconciled"
                    )
                if owner_epoch == self.owner_epoch:
                    raise UIDeliveryStoreUnavailable(
                        "current server delivery cannot use restart reconciliation"
                    )
            elif owner_epoch != self.owner_epoch:
                raise UIDeliveryStoreUnavailable(
                    "UI delivery attempt is not owned by this server"
                )

            transfer_id, delivery_id = self._decode_identity(row)
            identity_nonce, identity_ciphertext = self._encode_identity(
                row,
                transfer_id=transfer_id,
                delivery_id=delivery_id,
                contract=binding.contract,
                phase="result",
                owner_epoch=self.owner_epoch,
            )
            self._conn.execute(
                """
                UPDATE ui_file_deliveries
                SET phase = 'result', owner_epoch = ?, identity_nonce = ?,
                    identity_ciphertext = ?, updated_ms = ?
                WHERE principal_digest = ? AND client_delivery_id = ?
                """,
                (
                    self.owner_epoch,
                    identity_nonce,
                    identity_ciphertext,
                    now_ms,
                    self._principal_digest(binding.principal_scope),
                    binding.client_delivery_id,
                ),
            )
            updated_row = self._row_for(binding)
            nonce = secrets.token_bytes(12)
            ciphertext = self._response_aead.encrypt(
                nonce,
                encoded,
                self._response_aad(updated_row, status=status),
            )
            self._conn.execute(
                """
                UPDATE ui_file_deliveries
                SET response_status = ?, response_nonce = ?,
                    response_ciphertext = ?
                WHERE principal_digest = ? AND client_delivery_id = ?
                """,
                (
                    status,
                    nonce,
                    ciphertext,
                    self._principal_digest(binding.principal_scope),
                    binding.client_delivery_id,
                ),
            )
            return self._read_binding(binding, owns_attempt=False)

    def reclaim_dispatching_before_wire(
        self,
        binding: UIDeliveryBinding,
    ) -> UIDeliveryBinding:
        """Reclaim an old dispatch boundary after authoritative no-wire proof.

        The store cannot itself know whether ``FILE_OFFER`` escaped.  The UI
        server may call this only after matching the exact transfer row and
        proving it is still the pristine, zero-attempt pre-offer queue record.
        """

        now_ms = int(time.time() * 1000)
        with self._transaction():
            row = self._row_for(binding)
            self._assert_binding_row(row, binding)
            if row["response_ciphertext"] is not None:
                raise UIDeliveryStoreUnavailable("UI delivery already has a response")
            if str(row["phase"]) != "dispatching":
                raise UIDeliveryStoreUnavailable(
                    "only a dispatching delivery may be reclaimed"
                )
            if str(row["owner_epoch"]) == self.owner_epoch:
                raise UIDeliveryStoreUnavailable(
                    "current server delivery cannot be restart-reclaimed"
                )
            transfer_id, decoded_delivery_id = self._decode_identity(row)
            delivery_id = str(decoded_delivery_id or "")
            if not _DELIVERY_RE.fullmatch(delivery_id):
                raise UIDeliveryStoreUnavailable(
                    "dispatching delivery has no durable wire identity"
                )
            identity_nonce, identity_ciphertext = self._encode_identity(
                row,
                transfer_id=transfer_id,
                delivery_id=delivery_id,
                contract=binding.contract,
                phase="queued",
                owner_epoch=self.owner_epoch,
            )
            self._conn.execute(
                """
                UPDATE ui_file_deliveries
                SET phase = 'queued', owner_epoch = ?, identity_nonce = ?,
                    identity_ciphertext = ?, updated_ms = ?
                WHERE principal_digest = ? AND client_delivery_id = ?
                """,
                (
                    self.owner_epoch,
                    identity_nonce,
                    identity_ciphertext,
                    now_ms,
                    self._principal_digest(binding.principal_scope),
                    binding.client_delivery_id,
                ),
            )
            return self._read_binding(binding, owns_attempt=True)

    def _advance(
        self,
        binding: UIDeliveryBinding,
        *,
        phase: Literal["queued", "dispatching"],
        delivery_id: str | None = None,
    ) -> UIDeliveryBinding:
        now_ms = int(time.time() * 1000)
        with self._transaction():
            row = self._require_owned_row(binding)
            current_phase = str(row["phase"])
            allowed = {
                "queued": {"bound", "queued"},
                "dispatching": {"queued", "dispatching"},
            }
            if current_phase not in allowed[phase]:
                raise UIDeliveryStoreUnavailable(
                    f"invalid UI delivery phase transition {current_phase!r} -> {phase!r}"
                )
            transfer_id, current_delivery = self._decode_identity(row)
            if delivery_id is not None and current_delivery not in (None, delivery_id):
                raise UIDeliveryStoreUnavailable("wire delivery id changed for bound intent")
            next_delivery = delivery_id if delivery_id is not None else current_delivery
            if phase == "dispatching" and next_delivery is None:
                raise UIDeliveryStoreUnavailable(
                    "dispatching requires a durable wire delivery identity"
                )
            identity_nonce, identity_ciphertext = self._encode_identity(
                row,
                transfer_id=transfer_id,
                delivery_id=next_delivery,
                contract=binding.contract,
                phase=phase,
                owner_epoch=self.owner_epoch,
            )
            self._conn.execute(
                """
                UPDATE ui_file_deliveries
                SET phase = ?, identity_nonce = ?, identity_ciphertext = ?, updated_ms = ?
                WHERE principal_digest = ? AND client_delivery_id = ?
                """,
                (
                    phase,
                    identity_nonce,
                    identity_ciphertext,
                    now_ms,
                    self._principal_digest(binding.principal_scope),
                    binding.client_delivery_id,
                ),
            )
            return self._read_binding(binding, owns_attempt=True)

    def _require_owned_row(
        self,
        binding: UIDeliveryBinding,
    ) -> sqlite3.Row:
        row = self._row_for(binding)
        self._assert_binding_row(row, binding)
        if str(row["owner_epoch"]) != self.owner_epoch:
            raise UIDeliveryStoreUnavailable("UI delivery attempt is not owned by this server")
        if row["response_ciphertext"] is not None:
            raise UIDeliveryStoreUnavailable("UI delivery already has a durable response")
        return row

    def _row_for(self, binding: UIDeliveryBinding) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM ui_file_deliveries "
            "WHERE principal_digest = ? AND client_delivery_id = ?",
            (
                self._principal_digest(binding.principal_scope),
                binding.client_delivery_id,
            ),
        ).fetchone()
        if row is None:
            raise _UIDeliveryIntegrityFailure(
                "durable UI delivery row is missing"
            )
        return row

    def _assert_binding_row(
        self,
        row: sqlite3.Row,
        binding: UIDeliveryBinding,
    ) -> None:
        expected_principal = self._principal_digest(binding.principal_scope)
        if not hmac.compare_digest(bytes(row["principal_digest"]), expected_principal):
            raise _UIDeliveryIntegrityFailure("durable UI principal changed")
        if str(row["client_delivery_id"]) != binding.client_delivery_id:
            raise _UIDeliveryIntegrityFailure(
                "durable client delivery id changed"
            )
        self._assert_contract(row, binding.contract)
        transfer_id, actual_delivery = self._decode_identity(row)
        if transfer_id != binding.transfer_id:
            raise _UIDeliveryIntegrityFailure("durable transfer id changed")
        if not transfer_id.startswith(f"out:{binding.contract.blob_hash}:"):
            raise _UIDeliveryIntegrityFailure(
                "durable transfer id is bound to another blob"
            )
        if (
            binding.delivery_id is not None
            and actual_delivery != binding.delivery_id
        ):
            raise _UIDeliveryIntegrityFailure(
                "durable wire delivery id changed"
            )

    def _read_binding(
        self,
        binding: UIDeliveryBinding,
        *,
        owns_attempt: bool,
    ) -> UIDeliveryBinding:
        row = self._row_for(binding)
        self._assert_binding_row(row, binding)
        return self._binding(
            row,
            principal_scope=binding.principal_scope,
            contract=binding.contract,
            owns_attempt=owns_attempt,
        )

    class _Transaction:
        def __init__(
            self,
            store: "UIDeliveryIdempotencyStore",
            *,
            write: bool,
        ) -> None:
            self.store = store
            self.write = write

        def __enter__(self) -> None:
            self.store._lock.acquire()
            if self.store._closed or self.store._poisoned:
                self.store._lock.release()
                state = "closed" if self.store._closed else "fail-closed"
                raise UIDeliveryStoreUnavailable(f"UI delivery store is {state}")
            try:
                self.store._conn.execute(
                    "BEGIN IMMEDIATE" if self.write else "BEGIN"
                )
            except Exception as exc:
                self.store._lock.release()
                raise UIDeliveryStoreUnavailable(
                    f"cannot begin durable UI delivery transaction: {exc}"
                ) from exc

        def __exit__(self, exc_type, exc, tb) -> Literal[False]:
            try:
                if exc_type:
                    try:
                        self.store._conn.execute("ROLLBACK")
                    except Exception as rollback_exc:
                        self.store._poisoned = True
                        raise UIDeliveryStoreUnavailable(
                            "durable UI delivery rollback failed; store is fail-closed"
                        ) from rollback_exc
                    if isinstance(exc, _UIDeliveryIntegrityFailure):
                        self.store._poisoned = True
                        raise UIDeliveryStoreUnavailable(
                            "durable UI delivery integrity failed; store is fail-closed"
                        ) from exc
                    if isinstance(exc, UIDeliveryIdempotencyError):
                        # Contract conflicts and explicit state-machine refusals
                        # are already normalized domain outcomes.  The rollback
                        # above leaves the connection safe for other keys.
                        return False
                    if isinstance(exc, Exception):
                        # sqlite3/AEAD/codec/path faults raised by transaction
                        # bodies must never leak through the HTTP boundary as an
                        # arbitrary 500.  Their effect on authenticated state is
                        # uncertain, so retire this connection after rollback.
                        self.store._poisoned = True
                        raise UIDeliveryStoreUnavailable(
                            "durable UI delivery operation failed; store is fail-closed"
                        ) from exc
                else:
                    try:
                        self.store._conn.execute("COMMIT")
                    except Exception as commit_exc:
                        with contextlib.suppress(Exception):
                            self.store._conn.execute("ROLLBACK")
                        self.store._poisoned = True
                        raise UIDeliveryStoreUnavailable(
                            "durable UI delivery commit failed; store is fail-closed"
                        ) from commit_exc
                    if self.write:
                        try:
                            self.store._harden_and_sync_paths()
                        except Exception as durability_exc:
                            self.store._poisoned = True
                            raise UIDeliveryStoreUnavailable(
                                "durable UI delivery path sync failed; "
                                "store is fail-closed"
                            ) from durability_exc
            finally:
                self.store._lock.release()
            return False

    def _transaction(
        self,
        *,
        write: bool = True,
    ) -> "UIDeliveryIdempotencyStore._Transaction":
        return self._Transaction(self, write=write)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._conn.close()


__all__ = [
    "UIDeliveryBinding",
    "UIDeliveryContract",
    "UIDeliveryContractConflict",
    "UIDeliveryIdempotencyError",
    "UIDeliveryIdempotencyStore",
    "UIDeliveryStoreUnavailable",
]
