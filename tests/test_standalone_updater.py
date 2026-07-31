"""Fail-closed standalone release discovery/authentication tests."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import urllib.parse

import pytest

from one_link.standalone_updater import (
    StandaloneUpdateError,
    build_standalone_install_plan,
    prepare_authenticated_standalone_update,
)
from one_link.update_metadata import (
    PLATFORM_CONTRACTS,
    canonical_update_metadata_bytes,
    parse_authenticated_update_manifest,
    rollback_index_for_version,
)


NOW = datetime(2026, 7, 23, 12, 0, 0, tzinfo=UTC)
TAG = "v0.22.0"
PLATFORM = "linux-x86_64"
REPOSITORY = "coherence-energy-labs/one-link"


def _url(name: str, *, tag: str = TAG) -> str:
    return (
        f"https://github.com/{REPOSITORY}/releases/download/"
        f"{urllib.parse.quote(tag, safe='')}/{urllib.parse.quote(name, safe='')}"
    )


def _asset(name: str, payload: bytes) -> dict[str, object]:
    return {"name": name, "browser_download_url": _url(name), "size": len(payload)}


def _metadata(artifact_payload: bytes, sbom_payload: bytes) -> bytes:
    artifacts = []
    for key, contract in PLATFORM_CONTRACTS.items():
        payload = artifact_payload if key == PLATFORM else f"artifact:{key}".encode()
        artifacts.append(
            {
                "platform": key,
                "filename": contract.filename,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bundle_root": "one-link",
                "executable": contract.executable,
                "kind": "standalone-zip-v1",
            }
        )
    return canonical_update_metadata_bytes(
        {
            "schema": "one-link-update-manifest/v1",
            "tag": TAG,
            "version": "0.22.0",
            "rollback_index": rollback_index_for_version("0.22.0"),
            "minimum_source_version": "0.20.0",
            "created_at": "2026-07-01T00:00:00Z",
            "expires_at": "2026-12-01T00:00:00Z",
            "source": {
                "repository": REPOSITORY,
                "workflow": ".github/workflows/release.yml",
                "oidc_issuer": "https://token.actions.githubusercontent.com",
                "commit_sha": "a" * 40,
                "ref": f"refs/tags/{TAG}",
            },
            "sbom": {
                "filename": "sbom.cdx.json",
                "size": len(sbom_payload),
                "sha256": hashlib.sha256(sbom_payload).hexdigest(),
            },
            "artifacts": artifacts,
        }
    )


def _release_fixture():
    artifact_name = PLATFORM_CONTRACTS[PLATFORM].filename
    artifact_payload = b"authenticated standalone zip bytes"
    sbom_payload = b'{"bomFormat":"CycloneDX"}\n'
    metadata_payload = _metadata(artifact_payload, sbom_payload)
    checksum_payload = (
        f"{hashlib.sha256(artifact_payload).hexdigest()}  {artifact_name}\n"
    ).encode()
    payloads = {
        artifact_name: artifact_payload,
        f"{artifact_name}.sigstore": b"artifact signature",
        "UPDATE_MANIFEST.json": metadata_payload,
        "UPDATE_MANIFEST.json.sigstore": b"metadata signature",
        "SHA256SUMS": checksum_payload,
        "SHA256SUMS.sigstore": b"checksum signature",
        "sbom.cdx.json": sbom_payload,
        "sbom.cdx.json.sigstore": b"sbom signature",
    }
    payload = {
        "id": 220,
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "assets": [_asset(name, body) for name, body in payloads.items()],
    }
    return payload, payloads


def test_build_standalone_plan_requires_complete_stable_release():
    payload, _payloads = _release_fixture()
    plan = build_standalone_install_plan(
        current_version="0.21.0",
        platform_key=PLATFORM,
        fetch_json=lambda _url, _timeout: payload,
    )
    assert plan.status == "ready_for_authentication"
    assert plan.release_id == 220
    assert plan.tag == TAG
    assert plan.platform == PLATFORM
    assert plan.artifact is not None
    assert plan.artifact.name == PLATFORM_CONTRACTS[PLATFORM].filename
    assert plan.to_dict()["artifact"]["authentication"] == "pending_exact_tag_sigstore"


@pytest.mark.parametrize(
    ("mutation", "status"),
    [
        (lambda p: p.update(id="220"), "unverified"),
        (lambda p: p.update(tag_name="auto-latest"), "unverified"),
        (lambda p: p.update(tag_name="v0.22.0rc1"), "unverified"),
        (lambda p: p.update(draft=True), "unverified"),
        (lambda p: p.update(prerelease=True), "unverified"),
        (lambda p: p["assets"].pop(), "unverified"),
        (lambda p: p["assets"].append(dict(p["assets"][0])), "unverified"),
        (
            lambda p: p["assets"][0].update(browser_download_url="https://evil.test/file"),
            "unverified",
        ),
    ],
)
def test_build_standalone_plan_rejects_untrusted_discovery_mutations(mutation, status: str):
    payload, _payloads = _release_fixture()
    mutation(payload)
    plan = build_standalone_install_plan(
        current_version="0.21.0",
        platform_key=PLATFORM,
        fetch_json=lambda _url, _timeout: payload,
    )
    assert plan.status == status


def test_build_standalone_plan_binds_presented_tag_and_release_id():
    payload, _payloads = _release_fixture()
    assert build_standalone_install_plan(
        current_version="0.21.0",
        expected_tag="v0.21.9",
        platform_key=PLATFORM,
        fetch_json=lambda _url, _timeout: payload,
    ).status == "release_changed"
    assert build_standalone_install_plan(
        current_version="0.21.0",
        expected_release_id=219,
        platform_key=PLATFORM,
        fetch_json=lambda _url, _timeout: payload,
    ).status == "release_changed"


def test_build_standalone_plan_rejects_non_newer_and_unsupported_host():
    payload, _payloads = _release_fixture()
    assert build_standalone_install_plan(
        current_version="0.22.0",
        platform_key=PLATFORM,
        fetch_json=lambda _url, _timeout: payload,
    ).status == "not_newer"
    assert build_standalone_install_plan(
        current_version="0.21.0",
        platform_key="macos-x86_64",
        fetch_json=lambda _url, _timeout: payload,
    ).status == "unsupported_host"


def _fake_downloader(tmp_path: Path, payloads: dict[str, bytes]):
    download_root = tmp_path / "downloads"
    download_root.mkdir()

    def download(
        url: str,
        *,
        expected_size: int,
        timeout: float,
        artifact_filename: str,
    ) -> Path:
        assert timeout > 0
        assert urllib.parse.unquote(url.rsplit("/", 1)[-1]) == artifact_filename
        body = payloads[artifact_filename]
        if len(body) != expected_size:
            raise ValueError("fake exact-size contract failed")
        path = download_root / artifact_filename
        path.write_bytes(body)
        return path

    return download


def _ready_plan(payload):
    plan = build_standalone_install_plan(
        current_version="0.21.0",
        platform_key=PLATFORM,
        fetch_json=lambda _url, _timeout: payload,
    )
    assert plan.status == "ready_for_authentication"
    return plan


def test_prepare_authenticates_metadata_checksums_sbom_and_artifact(tmp_path: Path):
    payload, payloads = _release_fixture()
    plan = _ready_plan(payload)
    verifications: list[tuple[str, str, str]] = []

    def verify(*, artifact: Path, bundle: Path, tag: str) -> None:
        verifications.append((artifact.name, bundle.name, tag))

    prepared = prepare_authenticated_standalone_update(
        plan,
        now=NOW,
        download=_fake_downloader(tmp_path, payloads),
        verify_identity=verify,
    )
    assert prepared.artifact_path.name == PLATFORM_CONTRACTS[PLATFORM].filename
    assert prepared.artifact_path.exists()
    assert prepared.authenticated_artifact_sha256 == hashlib.sha256(
        payloads[prepared.artifact_path.name]
    ).hexdigest()
    assert prepared.manifest.tag == TAG
    assert verifications == [
        ("UPDATE_MANIFEST.json", "UPDATE_MANIFEST.json.sigstore", TAG),
        ("SHA256SUMS", "SHA256SUMS.sigstore", TAG),
        ("sbom.cdx.json", "sbom.cdx.json.sigstore", TAG),
        (
            PLATFORM_CONTRACTS[PLATFORM].filename,
            f"{PLATFORM_CONTRACTS[PLATFORM].filename}.sigstore",
            TAG,
        ),
    ]
    leftovers = sorted(path.name for path in prepared.artifact_path.parent.iterdir())
    assert leftovers == [prepared.artifact_path.name]


def test_prepare_rejects_failed_exact_tag_signature_and_cleans_all(tmp_path: Path):
    payload, payloads = _release_fixture()
    plan = _ready_plan(payload)

    def verify(*, artifact: Path, bundle: Path, tag: str) -> None:
        _ = bundle, tag
        if artifact.name == "UPDATE_MANIFEST.json":
            raise RuntimeError("signature invalid")

    with pytest.raises(RuntimeError, match="signature invalid"):
        prepare_authenticated_standalone_update(
            plan,
            now=NOW,
            download=_fake_downloader(tmp_path, payloads),
            verify_identity=verify,
        )
    assert list((tmp_path / "downloads").iterdir()) == []


def test_prepare_rejects_checksum_disagreement(tmp_path: Path):
    payload, payloads = _release_fixture()
    wrong = f"{'0' * 64}  {PLATFORM_CONTRACTS[PLATFORM].filename}\n".encode()
    payloads["SHA256SUMS"] = wrong
    checksum_asset = next(a for a in payload["assets"] if a["name"] == "SHA256SUMS")
    checksum_asset["size"] = len(wrong)
    plan = _ready_plan(payload)
    with pytest.raises(StandaloneUpdateError, match="checksum manifest differs"):
        prepare_authenticated_standalone_update(
            plan,
            now=NOW,
            download=_fake_downloader(tmp_path, payloads),
            verify_identity=lambda **_kwargs: None,
        )


def test_prepare_rejects_signed_metadata_vs_discovery_size_disagreement(tmp_path: Path):
    payload, payloads = _release_fixture()
    artifact_name = PLATFORM_CONTRACTS[PLATFORM].filename
    artifact_asset = next(a for a in payload["assets"] if a["name"] == artifact_name)
    artifact_asset["size"] += 1
    plan = _ready_plan(payload)
    with pytest.raises(StandaloneUpdateError, match="discovery artifact differs"):
        prepare_authenticated_standalone_update(
            plan,
            now=NOW,
            download=_fake_downloader(tmp_path, payloads),
            verify_identity=lambda **_kwargs: None,
        )


def test_prepare_rejects_expired_signed_metadata(tmp_path: Path):
    payload, payloads = _release_fixture()
    plan = _ready_plan(payload)
    with pytest.raises(Exception, match="expired"):
        prepare_authenticated_standalone_update(
            plan,
            now=datetime(2027, 1, 1, tzinfo=UTC),
            download=_fake_downloader(tmp_path, payloads),
            verify_identity=lambda **_kwargs: None,
        )


# ── deterministic release metadata producer ─────────────────────────


def _load_generator():
    script = Path(__file__).resolve().parents[1] / "scripts" / "generate_update_manifest.py"
    spec = importlib.util.spec_from_file_location("generate_update_manifest", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _release_dist(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    for key, contract in PLATFORM_CONTRACTS.items():
        (dist / contract.filename).write_bytes(f"standalone:{key}".encode())
    (dist / "sbom.cdx.json").write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")
    return dist


def test_generator_emits_metadata_accepted_by_runtime_parser(tmp_path: Path):
    generator = _load_generator()
    dist = _release_dist(tmp_path)
    epoch = int(datetime(2026, 7, 1, tzinfo=UTC).timestamp())
    document = generator.build_update_document(
        dist_dir=dist,
        tag=TAG,
        commit_sha="a" * 40,
        source_date_epoch=epoch,
        minimum_source_version="0.20.0",
    )
    output = generator.write_update_manifest(dist / "UPDATE_MANIFEST.json", document)
    parsed = parse_authenticated_update_manifest(
        output.read_bytes(), verified_tag=TAG, now=NOW
    )
    assert parsed.commit_sha == "a" * 40
    assert set(parsed.artifacts) == set(PLATFORM_CONTRACTS)
    assert parsed.sbom.sha256 == hashlib.sha256((dist / "sbom.cdx.json").read_bytes()).hexdigest()


def test_generator_is_deterministic_and_refuses_different_replacement(tmp_path: Path):
    generator = _load_generator()
    dist = _release_dist(tmp_path)
    document = generator.build_update_document(
        dist_dir=dist,
        tag=TAG,
        commit_sha="a" * 40,
        source_date_epoch=int(datetime(2026, 7, 1, tzinfo=UTC).timestamp()),
        minimum_source_version="0.20.0",
    )
    output = dist / "UPDATE_MANIFEST.json"
    generator.write_update_manifest(output, document)
    first = output.read_bytes()
    generator.write_update_manifest(output, document)
    assert output.read_bytes() == first
    changed = json.loads(first)
    changed["source"]["commit_sha"] = "b" * 40
    with pytest.raises(generator.ManifestGenerationError, match="differs"):
        generator.write_update_manifest(output, changed)


def test_generator_rejects_missing_linked_and_prerelease_inputs(tmp_path: Path):
    generator = _load_generator()
    dist = _release_dist(tmp_path)
    epoch = int(datetime(2026, 7, 1, tzinfo=UTC).timestamp())
    missing = dist / PLATFORM_CONTRACTS[PLATFORM].filename
    missing.unlink()
    with pytest.raises(generator.ManifestGenerationError, match="absent"):
        generator.build_update_document(
            dist_dir=dist,
            tag=TAG,
            commit_sha="a" * 40,
            source_date_epoch=epoch,
            minimum_source_version="0.20.0",
        )
    missing.write_bytes(b"restored")
    with pytest.raises(generator.ManifestGenerationError, match="canonical stable"):
        generator.build_update_document(
            dist_dir=dist,
            tag="v0.22.0rc1",
            commit_sha="a" * 40,
            source_date_epoch=epoch,
            minimum_source_version="0.20.0",
        )


def test_generator_requires_canonical_output_name(tmp_path: Path):
    generator = _load_generator()
    with pytest.raises(generator.ManifestGenerationError, match="must be named"):
        generator.write_update_manifest(tmp_path / "metadata.json", {})
