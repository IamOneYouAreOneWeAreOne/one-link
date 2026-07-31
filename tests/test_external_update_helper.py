"""Adversarial and transactional proof for the external frozen updater."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import zipfile

import pytest

import one_link.update_helper as update_helper
from one_link import control_ipc
from one_link.sigstore_verify import verify_sigstore_identity
from one_link.standalone_updater import PreparedStandaloneUpdate, StandaloneInstallPlan
from one_link.update_helper import (
    CandidateHealthProof,
    ExternalUpdateHelperError,
    decode_handoff_frame,
    encode_helper_acceptance,
    encode_handoff_frame,
    execute_external_update_handoff,
    helper_main,
    inspect_external_update_capability,
    prepare_external_helper_launch,
    spawn_external_update_helper,
    update_helper_relative_path,
    verify_helper_acceptance,
)
from one_link.update_metadata import (
    PLATFORM_CONTRACTS,
    StandaloneArtifact,
    canonical_update_metadata_bytes,
    parse_authenticated_update_manifest,
    rollback_index_for_version,
)
from one_link.update_transaction import (
    AuthenticatedUpdateState,
    ProcessGuard,
    ProcessIdentity,
    TransactionPhase,
    UpdateTransactionError,
    activate_prepared_update,
    mark_update_healthy,
    prepare_update_transaction,
    validate_installed_bundle,
)


NOW = datetime(2026, 7, 23, 12, 0, 0, tzinfo=UTC)
KEY = bytes.fromhex("41" * 32)
PLATFORM = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
CONTRACT = PLATFORM_CONTRACTS[PLATFORM]
HELPER = update_helper_relative_path(PLATFORM).as_posix()


def _member_manifest(files: dict[str, tuple[bytes, int]]) -> bytes:
    rows = ["# sha256\tkind\tbytes\tpath\ttarget"]
    for relative, (payload, _mode) in sorted(files.items()):
        rows.append(
            "\t".join(
                (
                    hashlib.sha256(payload).hexdigest(),
                    "FILE",
                    str(len(payload)),
                    f"one-link/{relative}",
                    "",
                )
            )
        )
    return ("\n".join(rows) + "\n").encode()


def _bundle_files(marker: bytes) -> dict[str, tuple[bytes, int]]:
    return {
        CONTRACT.executable: (b"application:" + marker, 0o755),
        HELPER: (b"frozen-helper:" + marker, 0o755),
        "_internal/runtime.bin": (b"runtime:" + marker, 0o644),
    }


def _write_bundle(root: Path, marker: bytes) -> Path:
    files = _bundle_files(marker)
    root.mkdir(parents=True)
    for relative, (payload, mode) in files.items():
        path = root.joinpath(*Path(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        if os.name != "nt":
            path.chmod(mode)
    manifest = root / "BUNDLE_SHA256SUMS"
    manifest.write_bytes(_member_manifest(files))
    if os.name != "nt":
        manifest.chmod(0o644)
    return root


def _write_archive(path: Path, marker: bytes) -> Path:
    files = _bundle_files(marker)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, (payload, mode) in sorted(files.items()):
            info = zipfile.ZipInfo(f"one-link/{relative}")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
        info = zipfile.ZipInfo("one-link/BUNDLE_SHA256SUMS")
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, _member_manifest(files))
    return path


def _manifest(archive: Path):
    artifact = StandaloneArtifact(
        platform=PLATFORM,
        filename=CONTRACT.filename,
        size=archive.stat().st_size,
        sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        bundle_root="one-link",
        executable=CONTRACT.executable,
        kind="standalone-zip-v1",
    )
    artifacts = []
    for platform_key, contract in PLATFORM_CONTRACTS.items():
        selected = artifact if platform_key == PLATFORM else None
        artifacts.append(
            {
                "platform": platform_key,
                "filename": contract.filename,
                "size": selected.size if selected else 123,
                "sha256": (
                    selected.sha256
                    if selected
                    else hashlib.sha256(platform_key.encode()).hexdigest()
                ),
                "bundle_root": "one-link",
                "executable": contract.executable,
                "kind": "standalone-zip-v1",
            }
        )
    document = {
        "schema": "one-link-update-manifest/v1",
        "tag": "v0.22.0",
        "version": "0.22.0",
        "rollback_index": rollback_index_for_version("0.22.0"),
        "minimum_source_version": "0.20.0",
        "created_at": "2026-07-01T00:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z",
        "source": {
            "repository": "coherence-energy-labs/one-link",
            "workflow": ".github/workflows/release.yml",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "commit_sha": "a" * 40,
            "ref": "refs/tags/v0.22.0",
        },
        "sbom": {
            "filename": "sbom.cdx.json",
            "size": 4,
            "sha256": hashlib.sha256(b"sbom").hexdigest(),
        },
        "artifacts": artifacts,
    }
    return parse_authenticated_update_manifest(
        canonical_update_metadata_bytes(document),
        verified_tag="v0.22.0",
        now=NOW,
    )


def _launch(tmp_path: Path, *, now: datetime = NOW):
    install = _write_bundle(tmp_path / "installed", b"old")
    data = tmp_path / "home" / "data"
    executable = install.joinpath(*Path(CONTRACT.executable).parts)
    identity = ProcessIdentity(4321, "b" * 64, str(executable.resolve()))
    launch = prepare_external_helper_launch(
        install_root=install.resolve(),
        data_root=data.resolve(),
        authority_key=KEY,
        current_version="0.21.0",
        expected_tag="v0.22.0",
        expected_release_id=987,
        platform_key=PLATFORM,
        parent_pid=4321,
        now=now,
        process_reader=lambda pid: identity if pid == 4321 else None,
    )
    return install, data, launch


def test_handoff_is_canonical_authenticated_and_pipe_keyed(tmp_path: Path):
    _install, _data, launch = _launch(tmp_path)
    handoff, recovered_key = decode_handoff_frame(launch.frame)
    assert handoff == launch.handoff
    assert recovered_key == KEY
    assert handoff.helper_sha256 == hashlib.sha256(launch.executable.read_bytes()).hexdigest()
    assert str(tmp_path) not in launch.frame.decode().split('"authority_key":')[1].split(",")[0]
    assert encode_handoff_frame(handoff, recovered_key) == launch.frame

    tampered = json.loads(launch.frame)
    tampered["handoff"]["expected_release_id"] += 1
    with pytest.raises(ExternalUpdateHelperError, match="MAC"):
        decode_handoff_frame(
            json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()
        )


def test_dynamic_capability_requires_frozen_complete_managed_bundle(tmp_path: Path):
    install = _write_bundle(tmp_path / "installed", b"old")
    executable = install.joinpath(*Path(CONTRACT.executable).parts)
    data = tmp_path / "home" / "data"
    data.mkdir(parents=True)

    source = inspect_external_update_capability(
        _executable=executable,
        _platform_key=PLATFORM,
        _data_root=data,
        _frozen=False,
    )
    available = inspect_external_update_capability(
        _executable=executable,
        _platform_key=PLATFORM,
        _data_root=data,
        _frozen=True,
    )

    assert source.available is False
    assert source.reason == "not_frozen_standalone_bundle"
    assert available.available is True
    assert available.install_root == install.resolve()
    assert available.helper_path == install.joinpath(*Path(HELPER).parts)
    assert available.helper_sha256 == hashlib.sha256(
        available.helper_path.read_bytes()
    ).hexdigest()

    available.helper_path.unlink()
    missing = inspect_external_update_capability(
        _executable=executable,
        _platform_key=PLATFORM,
        _data_root=data,
        _frozen=True,
    )
    assert missing.available is False
    assert missing.reason == "managed_bundle_validation_failed"


def test_helper_acceptance_receipt_binds_pid_handoff_and_mac(tmp_path: Path):
    _install, _data, launch = _launch(tmp_path)
    accepted = replace(launch.handoff, phase="accepted")
    receipt = encode_helper_acceptance(accepted, KEY, pid=8080)

    verify_helper_acceptance(
        receipt,
        launch.handoff,
        KEY,
        expected_pid=8080,
    )
    tampered = json.loads(receipt)
    tampered["pid"] = 8081
    with pytest.raises(ExternalUpdateHelperError, match="MAC|authority|canonical"):
        verify_helper_acceptance(
            json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode(),
            launch.handoff,
            KEY,
            expected_pid=8081,
        )


def test_spawn_requires_authenticated_helper_acceptance(monkeypatch, tmp_path: Path):
    _install, _data, launch = _launch(tmp_path)
    accepted = replace(launch.handoff, phase="accepted")
    receipt = encode_helper_acceptance(accepted, KEY, pid=9191) + b"\n"
    processes = []

    class Sink:
        def __init__(self):
            self.payload = bytearray()

        def write(self, value):
            self.payload.extend(value)
            return len(value)

        def flush(self):
            return None

        def close(self):
            return None

    class Process:
        def __init__(self, *_args, **_kwargs):
            self.pid = 9191
            self.stdin = Sink()
            self.stdout = io.BytesIO(receipt)
            self.killed = False
            processes.append(self)

        def poll(self):
            return None

        def kill(self):
            self.killed = True

        def wait(self, *, timeout):
            assert timeout == 5.0
            return 0

    monkeypatch.setattr(update_helper.subprocess, "Popen", Process)

    assert spawn_external_update_helper(launch) == 9191
    assert bytes(processes[0].stdin.payload) == launch.frame + b"\n"
    assert processes[0].killed is False

    bad_receipt = receipt.replace(b'"pid":9191', b'"pid":9192')

    class BadProcess(Process):
        def __init__(self, *_args, **_kwargs):
            super().__init__()
            self.stdout = io.BytesIO(bad_receipt)

    monkeypatch.setattr(update_helper.subprocess, "Popen", BadProcess)
    with pytest.raises(ExternalUpdateHelperError, match="authority|MAC|canonical"):
        spawn_external_update_helper(launch)
    assert processes[-1].killed is True


def test_handoff_transition_is_atomic_exactly_once(tmp_path: Path):
    _install, data, launch = _launch(tmp_path)
    store = AuthenticatedUpdateState(data / "updates", KEY)

    accepted = update_helper._transition(  # noqa: SLF001 - state-machine proof
        store,
        launch.handoff,
        "accepted",
    )
    with pytest.raises(ExternalUpdateHelperError, match="authority changed"):
        update_helper._transition(  # noqa: SLF001 - stale replay proof
            store,
            launch.handoff,
            "accepted",
        )
    with pytest.raises(ExternalUpdateHelperError, match="invalid external update transition"):
        update_helper._transition(  # noqa: SLF001 - transition graph proof
            store,
            accepted,
            "candidate_active",
        )


def test_prepare_helper_rejects_parent_outside_managed_install(tmp_path: Path):
    install = _write_bundle(tmp_path / "installed", b"old")
    outside = tmp_path / ("outside.exe" if os.name == "nt" else "outside")
    outside.write_bytes(b"outside")
    if os.name != "nt":
        outside.chmod(0o700)
    identity = ProcessIdentity(44, "c" * 64, str(outside.resolve()))
    with pytest.raises(ExternalUpdateHelperError, match="parent"):
        prepare_external_helper_launch(
            install_root=install.resolve(),
            data_root=(tmp_path / "home" / "data").resolve(),
            authority_key=KEY,
            current_version="0.21.0",
            expected_tag="v0.22.0",
            expected_release_id=1,
            platform_key=PLATFORM,
            parent_pid=44,
            now=NOW,
            process_reader=lambda _pid: identity,
        )


def test_prepare_helper_rejects_unmanifested_or_changed_helper(tmp_path: Path):
    install, _data, _launch_value = _launch(tmp_path)
    install.joinpath(*Path(HELPER).parts).write_bytes(b"changed")
    executable = install.joinpath(*Path(CONTRACT.executable).parts)
    identity = ProcessIdentity(45, "d" * 64, str(executable.resolve()))
    with pytest.raises(Exception, match="manifest|differs"):
        prepare_external_helper_launch(
            install_root=install.resolve(),
            data_root=(tmp_path / "different" / "data").resolve(),
            authority_key=KEY,
            current_version="0.21.0",
            expected_tag="v0.22.0",
            expected_release_id=2,
            platform_key=PLATFORM,
            parent_pid=45,
            now=NOW,
            process_reader=lambda _pid: identity,
        )


def test_external_helper_runs_real_transaction_to_health_commit(tmp_path: Path):
    install, data, launch = _launch(tmp_path)
    archive = _write_archive(tmp_path / "candidate.zip", b"new")
    manifest = _manifest(archive)

    def authenticate(_plan, **_kwargs):
        return PreparedStandaloneUpdate(
            artifact_path=archive,
            manifest=manifest,
            authenticated_artifact_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        )

    def activate(**kwargs):
        return activate_prepared_update(
            **kwargs,
            identity_reader=lambda _pid: None,
            process_timeout=0,
            now=NOW + timedelta(seconds=10),
        )

    def mark(**kwargs):
        return mark_update_healthy(**kwargs, now=NOW + timedelta(seconds=20))

    proof = CandidateHealthProof(
        pid=777,
        process_guard=ProcessGuard(777, "e" * 64, str(install / CONTRACT.executable)),
        control_port=7117,
        ui_port=7118,
        source_fingerprint="f" * 64,
    )
    result = execute_external_update_handoff(
        launch.frame,
        self_executable=launch.executable,
        now=NOW,
        plan_builder=lambda **_kwargs: StandaloneInstallPlan(
            status="ready_for_authentication",
            tag="v0.22.0",
            release_id=987,
            platform=PLATFORM,
        ),
        authenticated_preparer=authenticate,
        activator=activate,
        health_marker=mark,
        candidate_launcher=lambda _journal, _handoff: SimpleNamespace(pid=777),
        candidate_probe=lambda _journal, _handoff: proof,
    )
    assert result.phase == TransactionPhase.COMMITTED.value
    assert validate_installed_bundle(
        install,
        expected_executable=CONTRACT.executable,
    ).manifest_sha256 == result.candidate_manifest_sha256
    persisted = json.loads((data / "updates" / "update-helper-handoff.auth.json").read_text())
    assert persisted["payload"]["phase"] == "committed"
    assert persisted["payload"]["result_code"] == "health_committed"
    assert not archive.exists()

    with pytest.raises(ExternalUpdateHelperError, match="replayed|replaced"):
        execute_external_update_handoff(
            launch.frame,
            self_executable=launch.executable,
            now=NOW,
        )


def test_transaction_error_after_activation_persists_rolled_back_terminal_state(
    tmp_path: Path,
):
    # Keep the candidate inside its health window. Generic crash recovery would
    # leave it awaiting health here; an explicit helper failure must roll back
    # immediately.
    launch_now = datetime.now(tz=UTC)
    install, data, launch = _launch(tmp_path, now=launch_now)
    archive = _write_archive(tmp_path / "candidate.zip", b"new")
    manifest = _manifest(archive)

    def authenticate(_plan, **_kwargs):
        return PreparedStandaloneUpdate(
            artifact_path=archive,
            manifest=manifest,
            authenticated_artifact_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        )

    def prepare(**kwargs):
        return prepare_update_transaction(
            **kwargs,
            health_window=timedelta(seconds=30),
        )

    def activate(**kwargs):
        return activate_prepared_update(
            **kwargs,
            identity_reader=lambda _pid: None,
            process_timeout=0,
            now=launch_now + timedelta(seconds=5),
        )

    def fail_launch(_journal, _handoff):
        raise UpdateTransactionError("synthetic candidate launch failure")

    with pytest.raises(UpdateTransactionError, match="synthetic candidate launch failure"):
        execute_external_update_handoff(
            launch.frame,
            self_executable=launch.executable,
            now=launch_now,
            plan_builder=lambda **_kwargs: StandaloneInstallPlan(
                status="ready_for_authentication",
                tag="v0.22.0",
                release_id=987,
                platform=PLATFORM,
            ),
            authenticated_preparer=authenticate,
            transaction_preparer=prepare,
            activator=activate,
            candidate_launcher=fail_launch,
            failure_restarter=lambda _handoff: None,
        )

    persisted = json.loads((data / "updates" / "update-helper-handoff.auth.json").read_text())
    assert persisted["payload"]["phase"] == "rolled_back"
    assert persisted["payload"]["result_code"] == "transaction_rolled_back"
    assert install.joinpath(*Path(CONTRACT.executable).parts).read_bytes() == b"application:old"


def test_recovery_shutdown_authenticates_daemon_and_stops_retained_child(
    monkeypatch,
    tmp_path: Path,
):
    install, _data, launch = _launch(tmp_path)
    executable = install.joinpath(*Path(CONTRACT.executable).parts).resolve()
    identity = ProcessIdentity(7001, "9" * 64, str(executable))
    commands: list[str] = []
    waited: list[ProcessGuard] = []

    monkeypatch.setattr(update_helper, "_read_control_port", lambda _root: 7123)
    monkeypatch.setattr(control_ipc, "read_control_secret", lambda _root: "secret")

    def request_control(_port, request, **_kwargs):
        commands.append(request["cmd"])
        if request["cmd"] == "status":
            return {"ok": True, "app_version": "0.22.0", "pid": identity.pid}
        return {"ok": True, "stopping": True}

    monkeypatch.setattr(control_ipc, "request_control", request_control)
    monkeypatch.setattr(update_helper, "read_process_identity", lambda _pid: identity)
    monkeypatch.setattr(
        update_helper,
        "require_guarded_process_exit",
        lambda guard, **_kwargs: waited.append(guard),
    )

    class RetainedChild:
        def __init__(self):
            self.terminated = False
            self.waited = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, *, timeout):
            assert timeout == 10.0
            self.waited = True
            return 0

    child = RetainedChild()
    journal = SimpleNamespace(
        install_root=str(install),
        expected_executable=CONTRACT.executable,
        version="0.22.0",
    )
    update_helper._stop_candidate_for_recovery(  # noqa: SLF001 - recovery proof
        journal,
        launch.handoff,
        child,
    )

    assert commands == ["status", "shutdown"]
    assert waited == [ProcessGuard(identity.pid, identity.instance_token, identity.executable)]
    assert child.terminated is True
    assert child.waited is True


def test_sigstore_verifier_uses_prehashed_public_api_and_exact_identity(tmp_path: Path):
    artifact = tmp_path / "artifact.zip"
    bundle = tmp_path / "artifact.zip.sigstore"
    artifact.write_bytes(b"artifact-bytes")
    bundle.write_bytes(b"{}")
    observed: dict[str, object] = {}

    class HashAlgorithm:
        SHA2_256 = "sha2-256"

    class Hashed:
        def __init__(self, *, digest, algorithm):
            observed["digest"] = digest
            observed["algorithm"] = algorithm

    class Bundle:
        @classmethod
        def from_json(cls, raw):
            observed["bundle"] = raw
            return cls()

    class Identity:
        def __init__(self, *, identity, issuer):
            observed["identity"] = identity
            observed["issuer"] = issuer

    class Verifier:
        @classmethod
        def production(cls, *, offline):
            observed["offline"] = offline
            return cls()

        def verify_artifact(self, hashed, signed_bundle, policy):
            observed["verified"] = (hashed, signed_bundle, policy)

    verify_sigstore_identity(
        artifact=artifact,
        bundle=bundle,
        tag="v0.22.0",
        _loader=lambda: (Hashed, Bundle, Identity, (Verifier, HashAlgorithm)),
    )
    assert observed["digest"] == hashlib.sha256(b"artifact-bytes").digest()
    assert observed["algorithm"] == "sha2-256"
    assert observed["bundle"] == b"{}"
    assert observed["offline"] is False
    assert observed["issuer"] == "https://token.actions.githubusercontent.com"
    assert observed["identity"] == (
        "https://github.com/coherence-energy-labs/one-link/"
        ".github/workflows/release.yml@refs/tags/v0.22.0"
    )


def test_release_build_includes_one_file_helper_before_bundle_manifest():
    builder = Path("scripts/build_binary.py").read_text(encoding="utf-8")
    helper_builder = Path("scripts/build_update_helper.py").read_text(encoding="utf-8")
    package_builder = Path("scripts/package_standalone_bundle.py").read_text(encoding="utf-8")
    assert "build_update_helper.py" in builder
    assert "one-link-update-helper" in builder
    assert builder.index("build_update_helper.py") < builder.index("smoke test: one-link --version")
    assert '"--onefile"' in helper_builder
    assert '"--collect-data"' in helper_builder
    assert '"--collect-all"' not in helper_builder
    assert '"--exclude-module"' in helper_builder
    for excluded in ("hypothesis", "numpy", "PIL", "sigstore.sign", "sigstore._cli"):
        assert f'"{excluded}"' in helper_builder
    assert "sigstore.verify.verifier" in helper_builder
    assert "BUNDLE_SHA256SUMS" in package_builder


def test_helper_builder_refuses_ambiguous_or_unowned_disposable_paths(tmp_path: Path):
    script = Path("scripts/build_update_helper.py").resolve()
    spec = importlib.util.spec_from_file_location("build_update_helper_test", script)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    with pytest.raises(builder.UpdateHelperBuildError, match="absolute"):
        builder._canonical_absolute(Path("relative-work"), label="test work")

    unowned = (tmp_path / "unowned-work").resolve()
    unowned.mkdir()
    sentinel = unowned / "dist"
    sentinel.mkdir()
    (sentinel / "user-data.bin").write_bytes(b"must survive")
    with pytest.raises(builder.UpdateHelperBuildError, match="ownership marker"):
        builder._initialize_work_root(unowned)
    assert (sentinel / "user-data.bin").read_bytes() == b"must survive"

    owned = (tmp_path / "owned-work").resolve()
    builder._initialize_work_root(owned)
    builder._initialize_work_root(owned)
    unsafe_derived = owned / "dist"
    unsafe_derived.write_bytes(b"not a disposable directory")
    with pytest.raises(builder.UpdateHelperBuildError, match="real directory"):
        builder._reset_derived_directory(unsafe_derived, work=owned)
    assert unsafe_derived.read_bytes() == b"not a disposable directory"


def test_helper_self_test_proves_trust_root_with_exact_stream_contract(
    monkeypatch,
    capsys,
):
    import one_link.sigstore_verify as sigstore_verify

    class Verifier:
        @classmethod
        def production(cls, *, offline):
            assert offline is True
            logging.warning("benign offline trust-root status")
            return cls()

    monkeypatch.setattr(
        sigstore_verify,
        "_load_sigstore_api",
        lambda: (object(), object(), object(), (Verifier, object())),
    )

    assert helper_main(["--self-test"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "one-link-update-helper self-test ok\n"
    assert captured.err == ""
