"""External, authenticated replacement helper for frozen One Link installs.

The running onedir application never renames itself.  It validates and copies
the separately frozen one-file helper into private update state, captures the
exact parent process instance, writes a MAC-authenticated one-use handoff, and
passes the authority key over a private stdin pipe.  The helper independently
authenticates the exact release, stages the A/B transaction, waits for that
captured parent instance to exit, activates the candidate, launches only the
signed executable path, and commits only after authenticated daemon and UI
readiness from that exact candidate tree.

No install root, executable, relaunch command, hash, tag, or authority key is
accepted from a browser request or command line.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import threading
import time
from typing import Callable, IO, Mapping

from packaging.version import InvalidVersion, Version

from one_link import control_ipc
from one_link.key_material import KeyMaterialError, read_bytes_if_exists
from one_link.process_security import (
    hidden_creationflags,
    resolve_explicit_executable,
    trusted_process_env,
)
from one_link.standalone_updater import (
    PreparedStandaloneUpdate,
    StandaloneInstallPlan,
    build_standalone_install_plan,
    prepare_authenticated_standalone_update,
)
from one_link.update_metadata import PLATFORM_CONTRACTS
from one_link.update_transaction import (
    AuthenticatedUpdateState,
    ProcessGuard,
    UpdateJournal,
    UpdateProcessStillRunning,
    UpdateTransactionError,
    abort_update_transaction,
    activate_prepared_update,
    capture_process_guard,
    mark_update_healthy,
    prepare_update_transaction,
    read_process_identity,
    recover_update_transaction,
    require_guarded_process_exit,
    validate_installed_bundle,
)
from one_link.updater import remove_staged_file


HELPER_HANDOFF_SCHEMA = "one-link-external-update-handoff/v1"
HELPER_ACCEPTANCE_SCHEMA = "one-link-external-update-acceptance/v1"
HELPER_HANDOFF_KIND = "external-helper-handoff"
HELPER_HANDOFF_FILENAME = "update-helper-handoff.auth.json"
HELPER_STATE_DIRECTORY = "updates"
MAX_HANDOFF_FRAME_BYTES = 64 * 1024
MAX_ACCEPTANCE_FRAME_BYTES = 4096
MAX_HELPER_BYTES = 512 * 1024 * 1024
DEFAULT_HANDOFF_LIFETIME = timedelta(minutes=15)
MAX_HANDOFF_LIFETIME = timedelta(minutes=30)
DEFAULT_HEALTH_POLL_SECONDS = 0.15
DEFAULT_ACCEPTANCE_TIMEOUT_SECONDS = 15.0

_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_STABLE_TAG = re.compile(
    r"^v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)$"
)
_PHASES = frozenset(
    {
        "staged",
        "accepted",
        "release_authenticated",
        "candidate_prepared",
        "candidate_active",
        "candidate_relaunched",
        "committed",
        "rolled_back",
        "failed_closed",
    }
)
_PHASE_TRANSITIONS = {
    "staged": frozenset({"accepted", "failed_closed"}),
    "accepted": frozenset({"release_authenticated", "failed_closed"}),
    "release_authenticated": frozenset({"candidate_prepared", "failed_closed"}),
    "candidate_prepared": frozenset(
        {"candidate_active", "rolled_back", "failed_closed"}
    ),
    "candidate_active": frozenset(
        {"candidate_relaunched", "committed", "rolled_back", "failed_closed"}
    ),
    "candidate_relaunched": frozenset(
        {"committed", "rolled_back", "failed_closed"}
    ),
    "committed": frozenset(),
    "rolled_back": frozenset(),
    "failed_closed": frozenset(),
}


class ExternalUpdateHelperError(RuntimeError):
    """The external replacement ceremony failed closed."""


@dataclass(frozen=True)
class ExternalUpdateCapability:
    """Locally proven ability to perform a transactional frozen-app update."""

    available: bool
    reason: str
    platform: str | None = None
    install_root: Path | None = None
    data_root: Path | None = None
    home_override: Path | None = None
    expected_executable: str | None = None
    helper_path: Path | None = None
    helper_sha256: str | None = None

    def to_public_dict(self) -> dict[str, object]:
        """Return capability truth without disclosing private filesystem paths."""

        result: dict[str, object] = {
            "available": self.available,
            "reason": self.reason,
        }
        if self.platform is not None:
            result["platform"] = self.platform
        return result


@dataclass(frozen=True)
class ExternalUpdateHandoff:
    phase: str
    handoff_id: str
    nonce: str
    issued_at: str
    expires_at: str
    expected_tag: str
    expected_release_id: int
    current_version: str
    platform: str
    install_root: str
    state_root: str
    data_root: str
    home_override: str | None
    helper_path: str
    helper_sha256: str
    parent_pid: int
    parent_instance_token: str
    parent_executable: str
    transaction_id: str | None = None
    result_code: str | None = None

    @property
    def process_guard(self) -> ProcessGuard:
        return ProcessGuard(
            pid=self.parent_pid,
            instance_token=self.parent_instance_token,
            executable=self.parent_executable,
        )


@dataclass(frozen=True)
class ExternalHelperLaunch:
    executable: Path
    frame: bytes
    handoff: ExternalUpdateHandoff


@dataclass(frozen=True)
class CandidateHealthProof:
    pid: int
    process_guard: ProcessGuard
    control_port: int
    ui_port: int
    source_fingerprint: str


PlanBuilder = Callable[..., StandaloneInstallPlan]
AuthenticatedPreparer = Callable[..., PreparedStandaloneUpdate]
TransactionPreparer = Callable[..., UpdateJournal]
Activator = Callable[..., UpdateJournal]
HealthMarker = Callable[..., UpdateJournal]
CandidateLauncher = Callable[[UpdateJournal, ExternalUpdateHandoff], subprocess.Popen[bytes]]
CandidateProbe = Callable[[UpdateJournal, ExternalUpdateHandoff], CandidateHealthProof | None]
AcceptanceCallback = Callable[[ExternalUpdateHandoff, bytes], None]
FailureRestarter = Callable[[ExternalUpdateHandoff], None]


def _canonical_json(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ExternalUpdateHelperError("update helper state is not canonical JSON") from exc


def _format_utc(value: datetime) -> str:
    observed = value.astimezone(UTC).replace(microsecond=0)
    return observed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: str, *, label: str) -> datetime:
    if not isinstance(value, str) or len(value) != 20:
        raise ExternalUpdateHelperError(f"{label} timestamp is malformed")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ExternalUpdateHelperError(f"{label} timestamp is malformed") from exc
    return parsed


def _absolute_lexical(path: Path, *, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        raise ExternalUpdateHelperError(f"{label} must be an absolute traversal-free path")
    normalized = Path(os.path.abspath(candidate))
    if normalized != candidate:
        raise ExternalUpdateHelperError(f"{label} is not lexically canonical")
    return normalized


def _same_or_below(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def update_helper_relative_path(platform_key: str) -> PurePosixPath:
    if platform_key.startswith("windows-"):
        return PurePosixPath("one-link-update-helper.exe")
    if platform_key.startswith("linux-"):
        return PurePosixPath("one-link-update-helper")
    if platform_key == "macos-arm64":
        return PurePosixPath("Contents/MacOS/one-link-update-helper")
    raise ExternalUpdateHelperError("unsupported update-helper platform")


def inspect_external_update_capability(
    *,
    _executable: Path | None = None,
    _platform_key: str | None = None,
    _data_root: Path | None = None,
    _frozen: bool | None = None,
) -> ExternalUpdateCapability:
    """Prove that this exact process belongs to a complete managed bundle.

    Source trees, ordinary Python installs, unsupported architectures, a
    missing helper, a changed member, and overlapping application/data roots
    all fail closed.  The optional underscored arguments exist only for
    deterministic tests; production callers use the running process and the
    canonical One Link data root.
    """

    frozen = getattr(sys, "frozen", False) is True if _frozen is None else _frozen is True
    if not frozen:
        return ExternalUpdateCapability(False, "not_frozen_standalone_bundle")
    try:
        from one_link.paths import _home_override, data_dir
        from one_link.update_metadata import host_platform_key

        platform_key = _platform_key or host_platform_key()
        contract = PLATFORM_CONTRACTS[platform_key]
    except Exception:
        return ExternalUpdateCapability(False, "unsupported_host")
    try:
        running = Path(_executable or sys.executable).resolve(strict=True)
        relative_executable = PurePosixPath(contract.executable)
        install = running
        for _part in relative_executable.parts:
            install = install.parent
        install = install.resolve(strict=True)
        expected = install.joinpath(*relative_executable.parts).resolve(strict=True)
        if expected != running:
            return ExternalUpdateCapability(
                False,
                "running_executable_outside_managed_layout",
                platform=platform_key,
            )

        data = Path(_data_root if _data_root is not None else data_dir()).resolve(strict=True)
        if _same_or_below(data, install) or _same_or_below(install, data):
            return ExternalUpdateCapability(
                False,
                "application_and_data_roots_overlap",
                platform=platform_key,
            )
        home: Path | None = None
        if _data_root is None:
            configured_home = _home_override()
            if configured_home is not None:
                home = Path(configured_home).resolve(strict=True)
                if data != home / "data":
                    return ExternalUpdateCapability(
                        False,
                        "home_override_does_not_own_data_root",
                        platform=platform_key,
                    )

        validate_installed_bundle(
            install,
            expected_executable=contract.executable,
        )
        helper = install.joinpath(*update_helper_relative_path(platform_key).parts)
        helper_digest, _helper_size = _stable_file_sha256(helper)
        return ExternalUpdateCapability(
            True,
            "available",
            platform=platform_key,
            install_root=install,
            data_root=data,
            home_override=home,
            expected_executable=contract.executable,
            helper_path=helper,
            helper_sha256=helper_digest,
        )
    except Exception:
        return ExternalUpdateCapability(
            False,
            "managed_bundle_validation_failed",
            platform=platform_key,
        )


def _handoff_payload(handoff: ExternalUpdateHandoff) -> dict[str, object]:
    return asdict(handoff)


def _validate_handoff(handoff: ExternalUpdateHandoff) -> None:
    if handoff.phase not in _PHASES:
        raise ExternalUpdateHelperError("update helper phase is invalid")
    if not _HEX_32.fullmatch(handoff.handoff_id) or not _HEX_64.fullmatch(handoff.nonce):
        raise ExternalUpdateHelperError("update helper id/nonce is invalid")
    if not _STABLE_TAG.fullmatch(handoff.expected_tag):
        raise ExternalUpdateHelperError("update helper tag is not canonical stable")
    if type(handoff.expected_release_id) is not int or handoff.expected_release_id <= 0:
        raise ExternalUpdateHelperError("update helper release id is invalid")
    try:
        Version(handoff.current_version)
    except InvalidVersion as exc:
        raise ExternalUpdateHelperError("update helper source version is invalid") from exc
    if handoff.platform not in PLATFORM_CONTRACTS:
        raise ExternalUpdateHelperError("update helper platform is unsupported")
    install = _absolute_lexical(Path(handoff.install_root), label="install_root")
    state = _absolute_lexical(Path(handoff.state_root), label="state_root")
    data = _absolute_lexical(Path(handoff.data_root), label="data_root")
    helper = _absolute_lexical(Path(handoff.helper_path), label="helper_path")
    if state != data / HELPER_STATE_DIRECTORY:
        raise ExternalUpdateHelperError("update state root is not derived from data root")
    if _same_or_below(state, install) or _same_or_below(install, state):
        raise ExternalUpdateHelperError("install and update-state roots overlap")
    if not _same_or_below(helper, state / "helper-bin"):
        raise ExternalUpdateHelperError("staged helper escaped its private state directory")
    if handoff.home_override is not None:
        home = _absolute_lexical(Path(handoff.home_override), label="home_override")
        if data != home / "data":
            raise ExternalUpdateHelperError("home override does not own data root")
    if not _HEX_64.fullmatch(handoff.helper_sha256):
        raise ExternalUpdateHelperError("update helper digest is invalid")
    if (
        type(handoff.parent_pid) is not int
        or handoff.parent_pid <= 0
        or not _HEX_64.fullmatch(handoff.parent_instance_token)
        or not handoff.parent_executable
    ):
        raise ExternalUpdateHelperError("parent process guard is invalid")
    issued = _parse_utc(handoff.issued_at, label="issued_at")
    expires = _parse_utc(handoff.expires_at, label="expires_at")
    if not issued < expires or expires - issued > MAX_HANDOFF_LIFETIME:
        raise ExternalUpdateHelperError("update helper lifetime is invalid")
    if handoff.transaction_id is not None and not _HEX_32.fullmatch(handoff.transaction_id):
        raise ExternalUpdateHelperError("update helper transaction id is invalid")
    if handoff.result_code is not None and (
        not 1 <= len(handoff.result_code) <= 64
        or not handoff.result_code.replace("_", "").isalnum()
    ):
        raise ExternalUpdateHelperError("update helper result code is invalid")


def _handoff_from_payload(payload: Mapping[str, object]) -> ExternalUpdateHandoff:
    expected = {field for field in ExternalUpdateHandoff.__dataclass_fields__}
    if set(payload) != expected:
        raise ExternalUpdateHelperError("update helper handoff fields differ from schema")
    try:
        handoff = ExternalUpdateHandoff(**dict(payload))  # type: ignore[arg-type]
    except TypeError as exc:
        raise ExternalUpdateHelperError("update helper handoff types are malformed") from exc
    _validate_handoff(handoff)
    return handoff


def encode_handoff_frame(handoff: ExternalUpdateHandoff, authority_key: bytes) -> bytes:
    _validate_handoff(handoff)
    if not isinstance(authority_key, bytes) or len(authority_key) != 32:
        raise ValueError("update authority key must be exactly 32 bytes")
    payload = _handoff_payload(handoff)
    body = {"schema": HELPER_HANDOFF_SCHEMA, "handoff": payload}
    body_bytes = _canonical_json(body)
    mac = hmac.new(authority_key, b"one-link-update-helper\0" + body_bytes, hashlib.sha256)
    frame = _canonical_json(
        {
            **body,
            "authority_key": base64.urlsafe_b64encode(authority_key).decode("ascii").rstrip("="),
            "mac": mac.hexdigest(),
        }
    )
    if len(frame) > MAX_HANDOFF_FRAME_BYTES:
        raise ExternalUpdateHelperError("update helper handoff frame is oversized")
    return frame


def decode_handoff_frame(frame: bytes) -> tuple[ExternalUpdateHandoff, bytes]:
    if not isinstance(frame, bytes) or not frame or len(frame) > MAX_HANDOFF_FRAME_BYTES:
        raise ExternalUpdateHelperError("update helper handoff frame is empty or oversized")
    try:
        value = json.loads(frame.decode("ascii", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ExternalUpdateHelperError("update helper handoff frame is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "handoff",
        "authority_key",
        "mac",
    }:
        raise ExternalUpdateHelperError("update helper handoff envelope is malformed")
    if value["schema"] != HELPER_HANDOFF_SCHEMA or not isinstance(value["handoff"], dict):
        raise ExternalUpdateHelperError("update helper handoff schema is unsupported")
    encoded_key = value["authority_key"]
    supplied_mac = value["mac"]
    if not isinstance(encoded_key, str) or not isinstance(supplied_mac, str):
        raise ExternalUpdateHelperError("update helper handoff authority is malformed")
    try:
        authority_key = base64.urlsafe_b64decode(encoded_key + "=" * (-len(encoded_key) % 4))
    except (ValueError, TypeError) as exc:
        raise ExternalUpdateHelperError("update helper authority key is malformed") from exc
    if len(authority_key) != 32 or not _HEX_64.fullmatch(supplied_mac):
        raise ExternalUpdateHelperError("update helper authority key/MAC is malformed")
    body = {"schema": HELPER_HANDOFF_SCHEMA, "handoff": value["handoff"]}
    expected = hmac.new(
        authority_key,
        b"one-link-update-helper\0" + _canonical_json(body),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied_mac, expected):
        raise ExternalUpdateHelperError("update helper handoff MAC verification failed")
    handoff = _handoff_from_payload(value["handoff"])
    if frame != encode_handoff_frame(handoff, authority_key):
        raise ExternalUpdateHelperError("update helper handoff is not canonical")
    return handoff, authority_key


def encode_helper_acceptance(
    handoff: ExternalUpdateHandoff,
    authority_key: bytes,
    *,
    pid: int | None = None,
) -> bytes:
    """Authenticate the exact helper process that consumed one handoff."""

    if handoff.phase != "accepted":
        raise ExternalUpdateHelperError("helper acceptance has the wrong phase")
    if not isinstance(authority_key, bytes) or len(authority_key) != 32:
        raise ValueError("update authority key must be exactly 32 bytes")
    helper_pid = os.getpid() if pid is None else pid
    if type(helper_pid) is not int or helper_pid <= 0:
        raise ExternalUpdateHelperError("helper acceptance pid is invalid")
    body: dict[str, object] = {
        "schema": HELPER_ACCEPTANCE_SCHEMA,
        "phase": "accepted",
        "handoff_id": handoff.handoff_id,
        "nonce": handoff.nonce,
        "helper_sha256": handoff.helper_sha256,
        "pid": helper_pid,
    }
    mac = hmac.new(
        authority_key,
        b"one-link-update-helper-acceptance\0" + _canonical_json(body),
        hashlib.sha256,
    ).hexdigest()
    encoded = _canonical_json({**body, "mac": mac})
    if len(encoded) > MAX_ACCEPTANCE_FRAME_BYTES:
        raise ExternalUpdateHelperError("helper acceptance frame is oversized")
    return encoded


def verify_helper_acceptance(
    frame: bytes,
    handoff: ExternalUpdateHandoff,
    authority_key: bytes,
    *,
    expected_pid: int,
) -> None:
    """Verify a canonical acceptance receipt from the spawned helper."""

    if not isinstance(frame, bytes) or not frame or len(frame) > MAX_ACCEPTANCE_FRAME_BYTES:
        raise ExternalUpdateHelperError("helper acceptance frame is empty or oversized")
    try:
        value = json.loads(frame.decode("ascii", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ExternalUpdateHelperError("helper acceptance frame is not strict JSON") from exc
    expected_fields = {
        "schema",
        "phase",
        "handoff_id",
        "nonce",
        "helper_sha256",
        "pid",
        "mac",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ExternalUpdateHelperError("helper acceptance fields differ from schema")
    if (
        value.get("schema") != HELPER_ACCEPTANCE_SCHEMA
        or value.get("phase") != "accepted"
        or value.get("handoff_id") != handoff.handoff_id
        or value.get("nonce") != handoff.nonce
        or value.get("helper_sha256") != handoff.helper_sha256
        or type(value.get("pid")) is not int
        or value.get("pid") != expected_pid
        or not isinstance(value.get("mac"), str)
        or not _HEX_64.fullmatch(str(value.get("mac")))
    ):
        raise ExternalUpdateHelperError("helper acceptance authority differs")
    body = {key: value[key] for key in expected_fields if key != "mac"}
    expected_mac = hmac.new(
        authority_key,
        b"one-link-update-helper-acceptance\0" + _canonical_json(body),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(value["mac"]), expected_mac):
        raise ExternalUpdateHelperError("helper acceptance MAC verification failed")
    accepted = replace(handoff, phase="accepted")
    if frame != encode_helper_acceptance(
        accepted,
        authority_key,
        pid=expected_pid,
    ):
        raise ExternalUpdateHelperError("helper acceptance is not canonical")


def _write_handoff(store: AuthenticatedUpdateState, handoff: ExternalUpdateHandoff) -> None:
    _validate_handoff(handoff)
    # AuthenticatedUpdateState deliberately owns the canonical MAC envelope,
    # atomic replacement, fsync, no-follow readback, and shared process lock.
    store._write(  # noqa: SLF001 - same trust-domain extension record
        HELPER_HANDOFF_FILENAME,
        kind=HELPER_HANDOFF_KIND,
        payload=_handoff_payload(handoff),
    )


def _read_handoff(store: AuthenticatedUpdateState) -> ExternalUpdateHandoff | None:
    payload = store._read(  # noqa: SLF001 - same trust-domain extension record
        HELPER_HANDOFF_FILENAME,
        kind=HELPER_HANDOFF_KIND,
    )
    return None if payload is None else _handoff_from_payload(payload)


def _stable_file_sha256(path: Path, *, maximum: int = MAX_HELPER_BYTES) -> tuple[str, int]:
    candidate = Path(path)
    try:
        before = os.lstat(candidate)
    except OSError as exc:
        raise ExternalUpdateHelperError("update helper executable is unreadable") from exc
    attributes = int(getattr(before, "st_file_attributes", 0) or 0)
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if (
        stat.S_ISLNK(before.st_mode)
        or bool(attributes & reparse)
        or not stat.S_ISREG(before.st_mode)
        or not (0 < before.st_size <= maximum)
    ):
        raise ExternalUpdateHelperError("update helper is not a bounded regular file")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            count += len(block)
            if count > maximum:
                raise ExternalUpdateHelperError("update helper exceeds its byte budget")
            digest.update(block)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = os.lstat(candidate)
    identity = {
        (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns)
        for v in (before, opened, opened_after, after)
    }
    if len(identity) != 1 or count != before.st_size:
        raise ExternalUpdateHelperError("update helper changed while hashing")
    return digest.hexdigest(), count


def _stage_helper(source: Path, state_root: Path, digest: str, size: int) -> Path:
    suffix = ".exe" if source.suffix.casefold() == ".exe" else ""
    directory = state_root / "helper-bin" / digest
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        directory.chmod(0o700)
    destination = directory / f"one-link-update-helper{suffix}"
    if destination.exists():
        existing_digest, existing_size = _stable_file_sha256(destination)
        if existing_digest != digest or existing_size != size:
            raise ExternalUpdateHelperError("existing staged helper differs from authority")
        return destination
    temporary = directory / f".{destination.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(temporary, flags, 0o700)
    source_descriptor = -1
    try:
        try:
            before = os.lstat(source)
        except OSError as exc:
            raise ExternalUpdateHelperError("update helper vanished before staging") from exc
        attributes = int(getattr(before, "st_file_attributes", 0) or 0)
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if (
            stat.S_ISLNK(before.st_mode)
            or bool(attributes & reparse)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size != size
        ):
            raise ExternalUpdateHelperError("update helper changed before staging")
        read_flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        read_flags |= int(getattr(os, "O_CLOEXEC", 0))
        read_flags |= int(getattr(os, "O_NOFOLLOW", 0))
        source_descriptor = os.open(source, read_flags)
        opened = os.fstat(source_descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise ExternalUpdateHelperError("update helper changed while opening for staging")
        copied = 0
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            while True:
                block = os.read(source_descriptor, 1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > size:
                    raise ExternalUpdateHelperError("update helper grew while staging")
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        opened_after = os.fstat(source_descriptor)
        after = os.lstat(source)
        identity = {
            (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
            for value in (before, opened, opened_after, after)
        }
        if len(identity) != 1 or copied != size:
            raise ExternalUpdateHelperError("update helper changed while staging")
        copied_digest, copied_size = _stable_file_sha256(temporary)
        if copied_digest != digest or copied_size != size:
            raise ExternalUpdateHelperError("staged helper failed digest readback")
        os.replace(temporary, destination)
        final_digest, final_size = _stable_file_sha256(destination)
        if final_digest != digest or final_size != size:
            raise ExternalUpdateHelperError("published helper failed digest readback")
        return destination
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass


def prepare_external_helper_launch(
    *,
    install_root: Path,
    data_root: Path,
    authority_key: bytes,
    current_version: str,
    expected_tag: str,
    expected_release_id: int,
    platform_key: str,
    parent_pid: int | None = None,
    home_override: Path | None = None,
    now: datetime | None = None,
    lifetime: timedelta = DEFAULT_HANDOFF_LIFETIME,
    process_reader=read_process_identity,
) -> ExternalHelperLaunch:
    """Validate, copy, and authorize the external helper before parent exit."""

    observed = (now or datetime.now(tz=UTC)).astimezone(UTC)
    if not timedelta(minutes=1) <= lifetime <= MAX_HANDOFF_LIFETIME:
        raise ValueError("helper handoff lifetime must be between 1 and 30 minutes")
    if platform_key not in PLATFORM_CONTRACTS:
        raise ExternalUpdateHelperError("unsupported helper platform")
    install = _absolute_lexical(Path(install_root), label="install_root")
    data = _absolute_lexical(Path(data_root), label="data_root")
    state = data / HELPER_STATE_DIRECTORY
    if home_override is not None:
        home = _absolute_lexical(Path(home_override), label="home_override")
        if data != home / "data":
            raise ExternalUpdateHelperError("home override does not own data root")
    contract = PLATFORM_CONTRACTS[platform_key]
    validate_installed_bundle(install, expected_executable=contract.executable)
    source_helper = install.joinpath(*update_helper_relative_path(platform_key).parts)
    digest, size = _stable_file_sha256(source_helper)
    store = AuthenticatedUpdateState(state, authority_key)
    staged = _stage_helper(source_helper, state, digest, size)
    guard = capture_process_guard(parent_pid or os.getpid(), reader=process_reader)
    expected_parent = install.joinpath(*PurePosixPath(contract.executable).parts)
    if Path(guard.executable).resolve(strict=False) != expected_parent.resolve(strict=False):
        raise ExternalUpdateHelperError("update parent is not the managed executable")
    handoff = ExternalUpdateHandoff(
        phase="staged",
        handoff_id=os.urandom(16).hex(),
        nonce=os.urandom(32).hex(),
        issued_at=_format_utc(observed),
        expires_at=_format_utc(observed + lifetime),
        expected_tag=expected_tag,
        expected_release_id=expected_release_id,
        current_version=current_version,
        platform=platform_key,
        install_root=str(install),
        state_root=str(state),
        data_root=str(data),
        home_override=str(home_override) if home_override is not None else None,
        helper_path=str(staged),
        helper_sha256=digest,
        parent_pid=guard.pid,
        parent_instance_token=guard.instance_token,
        parent_executable=guard.executable,
    )
    _validate_handoff(handoff)
    with store.lock():
        existing = _read_handoff(store)
        if existing is not None and existing.phase not in {
            "committed",
            "rolled_back",
            "failed_closed",
        }:
            raise ExternalUpdateHelperError("another external update handoff is unfinished")
        _write_handoff(store, handoff)
    return ExternalHelperLaunch(
        executable=staged,
        frame=encode_handoff_frame(handoff, authority_key),
        handoff=handoff,
    )


def cancel_external_helper_launch(
    launch: ExternalHelperLaunch,
    authority_key: bytes,
    *,
    result_code: str = "parent_cancelled_before_spawn",
) -> ExternalUpdateHandoff:
    """Terminally revoke a staged handoff that never obtained acceptance."""

    framed, framed_key = decode_handoff_frame(launch.frame)
    if framed != launch.handoff or not hmac.compare_digest(framed_key, authority_key):
        raise ExternalUpdateHelperError("cancel authority differs from staged handoff")
    store = AuthenticatedUpdateState(Path(framed.state_root), authority_key)
    with store.lock():
        current = _read_handoff(store)
    accepted = replace(framed, phase="accepted")
    if current not in {framed, accepted}:
        raise ExternalUpdateHelperError(
            "helper advanced beyond a safely cancellable launch phase"
        )
    return _transition(
        store,
        current,
        "failed_closed",
        result_code=result_code,
    )


def _terminate_spawned_helper(process: subprocess.Popen[bytes]) -> None:
    """Boundedly reap a helper whose authenticated startup was not proven."""

    with contextlib.suppress(OSError, subprocess.SubprocessError):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5.0)


def _read_acceptance_line(
    stream: IO[bytes],
    *,
    timeout: float,
    process: subprocess.Popen[bytes],
) -> bytes:
    """Read one bounded pipe receipt without an unbounded Windows wait."""

    result: dict[str, object] = {}

    def _reader() -> None:
        try:
            result["line"] = stream.readline(MAX_ACCEPTANCE_FRAME_BYTES + 2)
        except BaseException as exc:  # delivered to the owning thread below
            result["error"] = exc

    reader = threading.Thread(
        target=_reader,
        name="one-link-update-helper-acceptance",
        daemon=True,
    )
    reader.start()
    reader.join(timeout)
    if reader.is_alive():
        _terminate_spawned_helper(process)
        with contextlib.suppress(OSError):
            stream.close()
        reader.join(1.0)
        raise ExternalUpdateHelperError("external helper acceptance timed out")
    error = result.get("error")
    if isinstance(error, BaseException):
        raise ExternalUpdateHelperError("external helper acceptance pipe failed") from error
    line = result.get("line")
    if not isinstance(line, bytes) or not line.endswith(b"\n"):
        raise ExternalUpdateHelperError("external helper acceptance is incomplete")
    if len(line) > MAX_ACCEPTANCE_FRAME_BYTES + 1:
        raise ExternalUpdateHelperError("external helper acceptance is oversized")
    return line[:-1]


def spawn_external_update_helper(
    launch: ExternalHelperLaunch,
    *,
    acceptance_timeout: float = DEFAULT_ACCEPTANCE_TIMEOUT_SECONDS,
) -> int:
    """Spawn the helper and require its authenticated one-use acceptance."""

    if not 1.0 <= acceptance_timeout <= 60.0:
        raise ValueError("helper acceptance timeout must be between 1 and 60 seconds")

    executable = resolve_explicit_executable(str(launch.executable.resolve(strict=True)))
    if _stable_file_sha256(Path(executable))[0] != launch.handoff.helper_sha256:
        raise ExternalUpdateHelperError("staged helper changed before spawn")
    framed_handoff, authority_key = decode_handoff_frame(launch.frame)
    if framed_handoff != launch.handoff:
        raise ExternalUpdateHelperError("launch frame differs from staged helper authority")
    environment = trusted_process_env()
    process = subprocess.Popen(  # noqa: S603 - authenticated absolute helper path
        [executable, "--execute-stdin"],
        shell=False,
        cwd=str(Path(launch.handoff.state_root)),
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=hidden_creationflags(detached=True),
        start_new_session=(os.name != "nt"),
    )
    if process.stdin is None or process.stdout is None:
        _terminate_spawned_helper(process)
        raise ExternalUpdateHelperError("external helper private pipes were not created")
    try:
        process.stdin.write(launch.frame + b"\n")
        process.stdin.flush()
    except OSError as exc:
        _terminate_spawned_helper(process)
        raise ExternalUpdateHelperError("external helper rejected its private handoff") from exc
    finally:
        process.stdin.close()
    try:
        receipt = _read_acceptance_line(
            process.stdout,
            timeout=acceptance_timeout,
            process=process,
        )
        verify_helper_acceptance(
            receipt,
            launch.handoff,
            authority_key,
            expected_pid=process.pid,
        )
    except BaseException:
        _terminate_spawned_helper(process)
        raise
    finally:
        with contextlib.suppress(OSError):
            process.stdout.close()
    return process.pid


def _read_control_port(data_root: Path) -> int:
    try:
        raw = read_bytes_if_exists(
            data_root / "control.port",
            label="candidate control port",
            max_bytes=32,
        )
    except KeyMaterialError as exc:
        raise ExternalUpdateHelperError("candidate control port is unsafe") from exc
    if raw is None:
        raise ExternalUpdateHelperError("candidate control port is absent")
    try:
        value = int(raw.decode("ascii", "strict").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ExternalUpdateHelperError("candidate control port is malformed") from exc
    if not 1 <= value <= 65535:
        raise ExternalUpdateHelperError("candidate control port is out of range")
    return value


def _prove_ui_instance(status: Mapping[str, object], secret: str, *, timeout: float) -> int:
    port = status.get("ui_server_port")
    pid = status.get("pid")
    instance = status.get("daemon_instance_id")
    source = status.get("source_fingerprint")
    if (
        type(port) is not int
        or not 1 <= port <= 65535
        or type(pid) is not int
        or pid <= 0
        or not isinstance(instance, str)
        or not instance
        or not isinstance(source, str)
        or not _HEX_64.fullmatch(source)
    ):
        raise ExternalUpdateHelperError("candidate control status is incomplete")
    challenge = control_ipc.make_ui_instance_challenge()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(
            "GET",
            f"/api/local-instance-proof?challenge={challenge}",
            headers={"Accept": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        raw = response.read(16 * 1024 + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise ExternalUpdateHelperError("candidate UI readiness proof failed") from exc
    finally:
        connection.close()
    if response.status != 200 or len(raw) > 16 * 1024:
        raise ExternalUpdateHelperError("candidate UI readiness proof was rejected")
    try:
        body = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExternalUpdateHelperError("candidate UI readiness proof is malformed") from exc
    if not isinstance(body, dict) or (
        body.get("ok") is not True
        or body.get("daemon_instance_id") != instance
        or body.get("source_fingerprint") != source
        or body.get("pid") != pid
        or body.get("ui_server_port") != port
        or not control_ipc.verify_ui_instance_proof(
            str(body.get("proof") or ""),
            secret,
            challenge=challenge,
            instance_id=instance,
            pid=pid,
            port=port,
            source_fingerprint=source,
        )
    ):
        raise ExternalUpdateHelperError("candidate UI readiness identity differs")
    return port


def probe_candidate_health(
    journal: UpdateJournal,
    handoff: ExternalUpdateHandoff,
    *,
    timeout: float = 1.5,
) -> CandidateHealthProof | None:
    """Return proof only for the exact activated daemon and UI instance."""

    try:
        data_root = Path(handoff.data_root)
        port = _read_control_port(data_root)
        secret = control_ipc.read_control_secret(data_root)
        status = control_ipc.request_control(
            port,
            {"cmd": "status"},
            timeout=timeout,
            secret=secret,
        )
        if (
            status.get("ok") is not True
            or status.get("app_version") != journal.version
            or not status.get("protocol_version")
            or type(status.get("schema_version")) is not int
            or int(status["schema_version"]) <= 0
        ):
            return None
        pid = status.get("pid")
        if type(pid) is not int or pid <= 0:
            return None
        identity = read_process_identity(pid)
        expected_executable = Path(journal.install_root).joinpath(
            *PurePosixPath(journal.expected_executable).parts
        )
        if identity is None or Path(identity.executable).resolve(strict=False) != (
            expected_executable.resolve(strict=False)
        ):
            return None
        ui_port = _prove_ui_instance(status, secret, timeout=timeout)
        source = str(status.get("source_fingerprint") or "")
        return CandidateHealthProof(
            pid=pid,
            process_guard=ProcessGuard(pid, identity.instance_token, identity.executable),
            control_port=port,
            ui_port=ui_port,
            source_fingerprint=source,
        )
    except Exception:
        return None


def _launch_candidate(
    journal: UpdateJournal,
    handoff: ExternalUpdateHandoff,
) -> subprocess.Popen[bytes]:
    executable = Path(journal.install_root).joinpath(
        *PurePosixPath(journal.expected_executable).parts
    )
    resolved = resolve_explicit_executable(str(executable.resolve(strict=True)))
    environment = trusted_process_env()
    if handoff.home_override is not None:
        environment["ONE_LINK_HOME"] = handoff.home_override
    return subprocess.Popen(  # noqa: S603 - signed path from authenticated journal
        [resolved],
        shell=False,
        cwd=str(Path(journal.install_root)),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=hidden_creationflags(detached=True),
        start_new_session=(os.name != "nt"),
    )


def _matching_managed_application_is_running(
    handoff: ExternalUpdateHandoff,
    expected_executable: Path,
) -> bool:
    """Use authenticated control status plus process identity to avoid duplicates."""

    try:
        data_root = Path(handoff.data_root)
        port = _read_control_port(data_root)
        secret = control_ipc.read_control_secret(data_root)
        status = control_ipc.request_control(
            port,
            {"cmd": "status"},
            timeout=1.5,
            secret=secret,
        )
        pid = status.get("pid")
        identity = read_process_identity(pid) if type(pid) is int and pid > 0 else None
        return bool(
            status.get("ok") is True
            and identity is not None
            and Path(identity.executable).resolve(strict=False)
            == expected_executable.resolve(strict=False)
        )
    except Exception:
        return False


def _ensure_active_application_after_failure(
    handoff: ExternalUpdateHandoff,
) -> None:
    """Keep a failed update from leaving a previously healthy app offline."""

    contract = PLATFORM_CONTRACTS[handoff.platform]
    install = Path(handoff.install_root)
    executable = install.joinpath(*PurePosixPath(contract.executable).parts)
    try:
        require_guarded_process_exit(handoff.process_guard, timeout=60.0)
    except UpdateProcessStillRunning:
        # The API never completed its shutdown handoff. The original exact
        # process remains the safest application instance to leave running.
        return
    if _matching_managed_application_is_running(handoff, executable):
        return
    validate_installed_bundle(install, expected_executable=contract.executable)
    resolved = resolve_explicit_executable(str(executable.resolve(strict=True)))
    environment = trusted_process_env()
    if handoff.home_override is not None:
        environment["ONE_LINK_HOME"] = handoff.home_override
    subprocess.Popen(  # noqa: S603 - validated managed application path
        [resolved],
        shell=False,
        cwd=str(install),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=hidden_creationflags(detached=True),
        start_new_session=(os.name != "nt"),
    )


def _stop_candidate_for_recovery(
    journal: UpdateJournal,
    handoff: ExternalUpdateHandoff,
    launched_process: subprocess.Popen[bytes] | None,
) -> None:
    """Best-effort exact-instance shutdown before directory rollback.

    The authenticated control path handles launchers that hand off to a daemon
    child. The retained ``Popen`` handle handles a still-running direct child.
    Neither path trusts a bare PID, and failure remains fail-closed in the
    transaction recovery layer.
    """

    expected_executable = Path(journal.install_root).joinpath(
        *PurePosixPath(journal.expected_executable).parts
    )
    try:
        data_root = Path(handoff.data_root)
        port = _read_control_port(data_root)
        secret = control_ipc.read_control_secret(data_root)
        status = control_ipc.request_control(
            port,
            {"cmd": "status"},
            timeout=1.5,
            secret=secret,
        )
        pid = status.get("pid")
        identity = read_process_identity(pid) if type(pid) is int and pid > 0 else None
        if (
            status.get("ok") is True
            and status.get("app_version") == journal.version
            and identity is not None
            and Path(identity.executable).resolve(strict=False)
            == expected_executable.resolve(strict=False)
        ):
            guard = ProcessGuard(identity.pid, identity.instance_token, identity.executable)
            response = control_ipc.request_control(
                port,
                {"cmd": "shutdown"},
                timeout=3.0,
                secret=secret,
            )
            if response.get("ok") is True:
                try:
                    require_guarded_process_exit(guard, timeout=10.0)
                except UpdateTransactionError:
                    pass
    except Exception:
        pass

    if launched_process is None:
        return
    poll = getattr(launched_process, "poll", None)
    terminate = getattr(launched_process, "terminate", None)
    wait = getattr(launched_process, "wait", None)
    if not callable(poll) or not callable(terminate) or not callable(wait):
        return
    try:
        if poll() is not None:
            return
        terminate()
        try:
            wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            kill = getattr(launched_process, "kill", None)
            if callable(kill):
                kill()
                wait(timeout=5.0)
    except (OSError, subprocess.SubprocessError):
        pass


def _transition(
    store: AuthenticatedUpdateState,
    handoff: ExternalUpdateHandoff,
    phase: str,
    *,
    transaction_id: str | None = None,
    result_code: str | None = None,
) -> ExternalUpdateHandoff:
    allowed = _PHASE_TRANSITIONS.get(handoff.phase, frozenset())
    if phase not in allowed:
        raise ExternalUpdateHelperError(
            f"invalid external update transition: {handoff.phase} -> {phase}"
        )
    changed = replace(
        handoff,
        phase=phase,
        transaction_id=transaction_id if transaction_id is not None else handoff.transaction_id,
        result_code=result_code,
    )
    with store.lock():
        current = _read_handoff(store)
        if current != handoff:
            raise ExternalUpdateHelperError("update helper handoff authority changed")
        _write_handoff(store, changed)
    return changed


def execute_external_update_handoff(
    frame: bytes,
    *,
    self_executable: Path | None = None,
    now: datetime | None = None,
    plan_builder: PlanBuilder = build_standalone_install_plan,
    authenticated_preparer: AuthenticatedPreparer = prepare_authenticated_standalone_update,
    transaction_preparer: TransactionPreparer = prepare_update_transaction,
    activator: Activator = activate_prepared_update,
    health_marker: HealthMarker = mark_update_healthy,
    candidate_launcher: CandidateLauncher = _launch_candidate,
    candidate_probe: CandidateProbe = probe_candidate_health,
    accepted_callback: AcceptanceCallback | None = None,
    failure_restarter: FailureRestarter = _ensure_active_application_after_failure,
    sleep: Callable[[float], None] = time.sleep,
) -> UpdateJournal:
    """Execute one authenticated handoff from discovery through health commit."""

    handoff, authority_key = decode_handoff_frame(frame)
    observed = (now or datetime.now(tz=UTC)).astimezone(UTC)
    if observed > _parse_utc(handoff.expires_at, label="expires_at"):
        raise ExternalUpdateHelperError("update helper handoff expired before acceptance")
    running_helper = Path(self_executable or sys.executable).resolve(strict=True)
    if running_helper != Path(handoff.helper_path).resolve(strict=True):
        raise ExternalUpdateHelperError("running helper path differs from handoff authority")
    if _stable_file_sha256(running_helper)[0] != handoff.helper_sha256:
        raise ExternalUpdateHelperError("running helper digest differs from handoff authority")
    store = AuthenticatedUpdateState(Path(handoff.state_root), authority_key)
    with store.lock():
        persisted = _read_handoff(store)
        if persisted != handoff or persisted.phase != "staged":
            raise ExternalUpdateHelperError("update helper handoff was replayed or replaced")
    handoff = _transition(store, handoff, "accepted")
    prepared: PreparedStandaloneUpdate | None = None
    journal: UpdateJournal | None = None
    candidate_process: subprocess.Popen[bytes] | None = None
    try:
        if accepted_callback is not None:
            accepted_callback(handoff, authority_key)
        recovery = recover_update_transaction(
            state_root=Path(handoff.state_root),
            authority_key=authority_key,
            now=observed,
        )
        if recovery.status not in {"none", "committed", "rolled_back"}:
            raise ExternalUpdateHelperError("an earlier update transaction is unfinished")
        plan = plan_builder(
            current_version=handoff.current_version,
            expected_tag=handoff.expected_tag,
            expected_release_id=handoff.expected_release_id,
            platform_key=handoff.platform,
        )
        if plan.status != "ready_for_authentication":
            raise ExternalUpdateHelperError("pinned release is not ready for authentication")
        from one_link.sigstore_verify import verify_sigstore_identity

        prepared = authenticated_preparer(
            plan,
            now=observed,
            verify_identity=verify_sigstore_identity,
        )
        if prepared.manifest.tag != handoff.expected_tag:
            raise ExternalUpdateHelperError("authenticated release differs from pinned tag")
        handoff = _transition(store, handoff, "release_authenticated")
        journal = transaction_preparer(
            manifest=prepared.manifest,
            platform_key=handoff.platform,
            archive_path=prepared.artifact_path,
            install_root=Path(handoff.install_root),
            state_root=Path(handoff.state_root),
            authority_key=authority_key,
            current_version=handoff.current_version,
            now=observed,
        )
        remove_staged_file(prepared.artifact_path)
        prepared = None
        handoff = _transition(
            store,
            handoff,
            "candidate_prepared",
            transaction_id=journal.txid,
        )
        journal = activator(
            state_root=Path(handoff.state_root),
            authority_key=authority_key,
            process_guard=handoff.process_guard,
        )
        handoff = _transition(store, handoff, "candidate_active")
        candidate_process = candidate_launcher(journal, handoff)
        handoff = _transition(store, handoff, "candidate_relaunched")
        deadline = _parse_utc(journal.health_deadline, label="health_deadline")
        monotonic_deadline = time.monotonic() + max(
            0.0,
            (deadline - datetime.now(tz=UTC)).total_seconds(),
        )
        proof: CandidateHealthProof | None = candidate_probe(journal, handoff)
        while (
            proof is None
            and datetime.now(tz=UTC) <= deadline
            and time.monotonic() <= monotonic_deadline
        ):
            sleep(DEFAULT_HEALTH_POLL_SECONDS)
            proof = candidate_probe(journal, handoff)
        if proof is None:
            raise ExternalUpdateHelperError("candidate missed authenticated readiness")
        expected_executable = Path(journal.install_root).joinpath(
            *PurePosixPath(journal.expected_executable).parts
        )
        journal = health_marker(
            state_root=Path(handoff.state_root),
            authority_key=authority_key,
            running_executable=expected_executable,
            observed_version=journal.version,
            health_probe=lambda _path: candidate_probe(journal, handoff) is not None,
        )
        handoff = _transition(
            store,
            handoff,
            "committed",
            result_code="health_committed",
        )
        return journal
    except BaseException:
        if prepared is not None:
            remove_staged_file(prepared.artifact_path)
        result = "failed_before_prepare"
        terminal_phase: str | None = None
        if journal is not None:
            try:
                # Reconcile first so a health commit completed by a concurrent
                # recovery owner is never followed by stopping that now-
                # authoritative candidate. Nonterminal health-pending state is
                # then stopped and explicitly aborted; ordinary crash recovery
                # would otherwise wait until the deadline despite this helper
                # having observed a concrete failure.
                recovery = recover_update_transaction(
                    state_root=Path(handoff.state_root),
                    authority_key=authority_key,
                )
                if recovery.status not in {"committed", "rolled_back"}:
                    _stop_candidate_for_recovery(
                        journal,
                        handoff,
                        candidate_process,
                    )
                    recovery = abort_update_transaction(
                        state_root=Path(handoff.state_root),
                        authority_key=authority_key,
                        detail="external_helper_failure",
                    )
                if recovery.status == "rolled_back":
                    terminal_phase = "rolled_back"
                    result = "transaction_rolled_back"
                elif recovery.status == "committed":
                    terminal_phase = "committed"
                    result = "recovery_committed"
                else:
                    result = f"recovery_{recovery.status}"
            except UpdateTransactionError:
                result = "recovery_failed_closed"
        if terminal_phase != "committed":
            try:
                failure_restarter(handoff)
            except Exception:
                result = f"relaunch_failed_{result}"[:64]
        try:
            _transition(
                store,
                handoff,
                terminal_phase or "failed_closed",
                result_code=result,
            )
        except Exception:
            pass
        raise


def read_handoff_frame_from_stdin() -> bytes:
    stream = sys.stdin.buffer
    frame = stream.readline(MAX_HANDOFF_FRAME_BYTES + 2)
    if not frame.endswith(b"\n") or len(frame) > MAX_HANDOFF_FRAME_BYTES + 1:
        raise ExternalUpdateHelperError("private helper handoff is incomplete or oversized")
    if stream.read(1):
        raise ExternalUpdateHelperError("private helper pipe contains trailing data")
    return frame[:-1]


def helper_main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--self-test"]:
        previous_logging_disable = logging.root.manager.disable
        try:
            # Sigstore's offline production root load emits an informational
            # warning. Keep the self-test streams exact while still surfacing
            # any real exception explicitly below.
            logging.disable(logging.CRITICAL)
            from one_link.sigstore_verify import _load_sigstore_api

            _hashed, _bundle, _identity, verifier_api = _load_sigstore_api()
            verifier_type, _hash_algorithm = verifier_api
            # Prove the frozen package contains a parseable production trust
            # root, not merely importable Python names. Offline construction
            # never contacts the network and catches missing PyInstaller data.
            verifier_type.production(offline=True)
        except Exception as exc:
            print(
                f"one-link-update-helper self-test failed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return 70
        finally:
            logging.disable(previous_logging_disable)
        print("one-link-update-helper self-test ok")
        return 0
    if arguments != ["--execute-stdin"]:
        return 64
    try:
        frame = read_handoff_frame_from_stdin()

        def _announce_acceptance(
            handoff: ExternalUpdateHandoff,
            authority_key: bytes,
        ) -> None:
            stream = sys.stdout.buffer
            stream.write(
                encode_helper_acceptance(handoff, authority_key) + b"\n"
            )
            stream.flush()

        execute_external_update_handoff(
            frame,
            accepted_callback=_announce_acceptance,
        )
        return 0
    except Exception:
        return 70


__all__ = [
    "CandidateHealthProof",
    "ExternalHelperLaunch",
    "ExternalUpdateCapability",
    "ExternalUpdateHandoff",
    "ExternalUpdateHelperError",
    "cancel_external_helper_launch",
    "decode_handoff_frame",
    "encode_helper_acceptance",
    "encode_handoff_frame",
    "execute_external_update_handoff",
    "helper_main",
    "inspect_external_update_capability",
    "prepare_external_helper_launch",
    "probe_candidate_health",
    "spawn_external_update_helper",
    "update_helper_relative_path",
    "verify_helper_acceptance",
]
