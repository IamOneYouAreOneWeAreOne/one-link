"""Exact-tag discovery and authentication for standalone application ZIPs.

Release API responses only locate bytes.  Installation authority comes from
three independent, exact-tag Sigstore checks: the canonical update metadata,
``SHA256SUMS``, and the selected standalone ZIP.  The signed SBOM is also
downloaded, identity-verified, and matched to the digest bound by the update
metadata before the artifact is returned to the transaction layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
from typing import Callable
import urllib.parse

from packaging.version import InvalidVersion, Version

from one_link.update_metadata import (
    AuthenticatedUpdateManifest,
    MAX_UPDATE_METADATA_BYTES,
    PLATFORM_CONTRACTS,
    UPDATE_METADATA_BUNDLE_FILENAME,
    UPDATE_METADATA_FILENAME,
    UPDATE_REPOSITORY,
    UpdateMetadataError,
    host_platform_key,
    parse_authenticated_update_manifest,
)
from one_link.updater import (
    MAX_UPDATE_ARTIFACT_BYTES,
    _exact_manifest_hash,
    _run_sigstore_identity_verify,
    download_to_temp,
    remove_staged_file,
    sha256_file,
)
from one_link.update_check import _build_url, _default_fetch


_STABLE_TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
MAX_RELEASE_ASSETS = 5000


class StandaloneUpdateError(RuntimeError):
    """Standalone update discovery/authentication failed closed."""


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    url: str
    size: int


@dataclass(frozen=True)
class StandaloneInstallPlan:
    status: str
    tag: str | None = None
    release_id: int | None = None
    platform: str | None = None
    artifact: ReleaseAsset | None = None
    artifact_bundle: ReleaseAsset | None = None
    metadata: ReleaseAsset | None = None
    metadata_bundle: ReleaseAsset | None = None
    checksum_manifest: ReleaseAsset | None = None
    checksum_bundle: ReleaseAsset | None = None
    sbom: ReleaseAsset | None = None
    sbom_bundle: ReleaseAsset | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"status": self.status}
        for key in ("tag", "release_id", "platform", "error"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        if self.artifact is not None:
            result["artifact"] = {
                "filename": self.artifact.name,
                "size": self.artifact.size,
                "authentication": "pending_exact_tag_sigstore",
            }
        return result


@dataclass(frozen=True)
class PreparedStandaloneUpdate:
    artifact_path: Path
    manifest: AuthenticatedUpdateManifest
    authenticated_artifact_sha256: str


DownloadFn = Callable[..., Path]


def _canonical_release_url(*, tag: str, name: str) -> str:
    encoded_tag = urllib.parse.quote(tag, safe="")
    encoded_name = urllib.parse.quote(name, safe="")
    return f"https://github.com/{UPDATE_REPOSITORY}/releases/download/{encoded_tag}/{encoded_name}"


def _asset_from_payload(asset: object, *, tag: str) -> ReleaseAsset | None:
    if not isinstance(asset, dict) or set(asset) < {"name", "browser_download_url", "size"}:
        return None
    name = asset.get("name")
    url = asset.get("browser_download_url")
    size = asset.get("size")
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 255
        or Path(name).name != name
        or "/" in name
        or "\\" in name
        or not isinstance(url, str)
        or url != _canonical_release_url(tag=tag, name=name)
        or type(size) is not int
        or not (0 < size <= MAX_UPDATE_ARTIFACT_BYTES)
    ):
        return None
    return ReleaseAsset(name=name, url=url, size=size)


def _plan_failure(status: str, error: str, *, tag: str | None = None) -> StandaloneInstallPlan:
    return StandaloneInstallPlan(status=status, tag=tag, error=error)


def build_standalone_install_plan(
    *,
    current_version: str,
    expected_tag: str | None = None,
    expected_release_id: int | None = None,
    platform_key: str | None = None,
    timeout: float = 6.0,
    fetch_json: Callable[[str, float], dict] | None = None,
) -> StandaloneInstallPlan:
    """Discover a complete stable release without treating it as trusted."""

    fetch = fetch_json or _default_fetch
    try:
        payload = fetch(_build_url("coherence-energy-labs", "one-link"), timeout)
    except Exception as exc:
        return _plan_failure("no_release", f"release discovery failed: {exc}")
    if not isinstance(payload, dict):
        return _plan_failure("unverified", "release payload is not an object")
    tag_value = payload.get("tag_name")
    tag = tag_value.strip() if isinstance(tag_value, str) else ""
    if not _STABLE_TAG.fullmatch(tag):
        return _plan_failure("unverified", "release tag is not canonical stable")
    release_id = payload.get("id")
    if type(release_id) is not int or release_id <= 0:
        return _plan_failure("unverified", "release id is missing or invalid", tag=tag)
    if expected_tag is not None and tag != expected_tag:
        return _plan_failure("release_changed", "release tag changed after presentation", tag=tag)
    if expected_release_id is not None and release_id != expected_release_id:
        return _plan_failure("release_changed", "release id changed after presentation", tag=tag)
    if payload.get("draft") is not False or payload.get("prerelease") is not False:
        return _plan_failure("unverified", "standalone updates require a public stable release", tag=tag)
    try:
        candidate = Version(tag.removeprefix("v"))
        installed = Version(current_version)
    except InvalidVersion as exc:
        return _plan_failure("unverified", f"version boundary is invalid: {exc}", tag=tag)
    if candidate <= installed:
        return _plan_failure("not_newer", "release is not newer than this installation", tag=tag)
    try:
        target_platform = platform_key or host_platform_key()
        contract = PLATFORM_CONTRACTS[target_platform]
    except (KeyError, UpdateMetadataError) as exc:
        return _plan_failure("unsupported_host", str(exc), tag=tag)
    assets_value = payload.get("assets")
    if not isinstance(assets_value, list) or not (1 <= len(assets_value) <= MAX_RELEASE_ASSETS):
        return _plan_failure("unverified", "release asset list is malformed or excessive", tag=tag)
    parsed_assets: dict[str, ReleaseAsset] = {}
    for raw_asset in assets_value:
        parsed = _asset_from_payload(raw_asset, tag=tag)
        if parsed is None or parsed.name in parsed_assets:
            return _plan_failure("unverified", "release contains invalid or duplicate assets", tag=tag)
        parsed_assets[parsed.name] = parsed
    required = {
        "artifact": contract.filename,
        "artifact_bundle": f"{contract.filename}.sigstore",
        "metadata": UPDATE_METADATA_FILENAME,
        "metadata_bundle": UPDATE_METADATA_BUNDLE_FILENAME,
        "checksum_manifest": "SHA256SUMS",
        "checksum_bundle": "SHA256SUMS.sigstore",
        "sbom": "sbom.cdx.json",
        "sbom_bundle": "sbom.cdx.json.sigstore",
    }
    if any(name not in parsed_assets for name in required.values()):
        return _plan_failure(
            "unverified",
            "release lacks the complete standalone signature/evidence contract",
            tag=tag,
        )
    metadata_names = (
        required["artifact_bundle"],
        required["metadata"],
        required["metadata_bundle"],
        required["checksum_manifest"],
        required["checksum_bundle"],
        required["sbom"],
        required["sbom_bundle"],
    )
    if any(parsed_assets[name].size > MAX_UPDATE_METADATA_BYTES for name in metadata_names):
        return _plan_failure("unverified", "release evidence asset exceeds metadata budget", tag=tag)
    return StandaloneInstallPlan(
        status="ready_for_authentication",
        tag=tag,
        release_id=release_id,
        platform=target_platform,
        artifact=parsed_assets[required["artifact"]],
        artifact_bundle=parsed_assets[required["artifact_bundle"]],
        metadata=parsed_assets[required["metadata"]],
        metadata_bundle=parsed_assets[required["metadata_bundle"]],
        checksum_manifest=parsed_assets[required["checksum_manifest"]],
        checksum_bundle=parsed_assets[required["checksum_bundle"]],
        sbom=parsed_assets[required["sbom"]],
        sbom_bundle=parsed_assets[required["sbom_bundle"]],
    )


def _download_asset(asset: ReleaseAsset, *, timeout: float, download: DownloadFn) -> Path:
    return download(
        asset.url,
        expected_size=asset.size,
        timeout=timeout,
        artifact_filename=asset.name,
    )


def prepare_authenticated_standalone_update(
    plan: StandaloneInstallPlan,
    *,
    now: datetime | None = None,
    timeout: float = 60.0,
    download: DownloadFn = download_to_temp,
    verify_identity: Callable[..., None] = _run_sigstore_identity_verify,
) -> PreparedStandaloneUpdate:
    """Download and authenticate all release authority needed for a swap."""

    if plan.status != "ready_for_authentication" or not plan.tag or not plan.platform:
        raise StandaloneUpdateError("standalone install plan is not ready for authentication")
    required_assets = (
        plan.artifact,
        plan.artifact_bundle,
        plan.metadata,
        plan.metadata_bundle,
        plan.checksum_manifest,
        plan.checksum_bundle,
        plan.sbom,
        plan.sbom_bundle,
    )
    if any(asset is None for asset in required_assets):
        raise StandaloneUpdateError("standalone install plan lost a required evidence asset")
    assert plan.artifact is not None
    assert plan.artifact_bundle is not None
    assert plan.metadata is not None
    assert plan.metadata_bundle is not None
    assert plan.checksum_manifest is not None
    assert plan.checksum_bundle is not None
    assert plan.sbom is not None
    assert plan.sbom_bundle is not None
    downloaded: list[Path] = []
    artifact_path: Path | None = None
    success = False
    try:
        metadata_path = _download_asset(plan.metadata, timeout=timeout, download=download)
        downloaded.append(metadata_path)
        metadata_bundle = _download_asset(plan.metadata_bundle, timeout=timeout, download=download)
        downloaded.append(metadata_bundle)
        verify_identity(artifact=metadata_path, bundle=metadata_bundle, tag=plan.tag)
        manifest = parse_authenticated_update_manifest(
            metadata_path.read_bytes(),
            verified_tag=plan.tag,
            now=now,
        )
        signed_artifact = manifest.artifact_for(plan.platform)
        if (
            signed_artifact.filename != plan.artifact.name
            or signed_artifact.size != plan.artifact.size
        ):
            raise StandaloneUpdateError(
                "release discovery artifact differs from signed update metadata"
            )

        checksum_path = _download_asset(
            plan.checksum_manifest,
            timeout=timeout,
            download=download,
        )
        downloaded.append(checksum_path)
        checksum_bundle = _download_asset(
            plan.checksum_bundle,
            timeout=timeout,
            download=download,
        )
        downloaded.append(checksum_bundle)
        verify_identity(artifact=checksum_path, bundle=checksum_bundle, tag=plan.tag)
        try:
            checksum_text = checksum_path.read_bytes().decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise StandaloneUpdateError("signed checksum manifest is not strict UTF-8") from exc
        signed_checksum = _exact_manifest_hash(checksum_text, plan.artifact.name)
        if signed_checksum is None or not hmac_compare(signed_checksum, signed_artifact.sha256):
            raise StandaloneUpdateError(
                "signed checksum manifest differs from signed update metadata"
            )

        sbom_path = _download_asset(plan.sbom, timeout=timeout, download=download)
        downloaded.append(sbom_path)
        sbom_bundle = _download_asset(plan.sbom_bundle, timeout=timeout, download=download)
        downloaded.append(sbom_bundle)
        verify_identity(artifact=sbom_path, bundle=sbom_bundle, tag=plan.tag)
        if (
            plan.sbom.name != manifest.sbom.filename
            or plan.sbom.size != manifest.sbom.size
            or not hmac_compare(sha256_file(sbom_path), manifest.sbom.sha256)
        ):
            raise StandaloneUpdateError("signed SBOM differs from signed update metadata")

        artifact_path = _download_asset(plan.artifact, timeout=timeout, download=download)
        downloaded.append(artifact_path)
        artifact_bundle = _download_asset(
            plan.artifact_bundle,
            timeout=timeout,
            download=download,
        )
        downloaded.append(artifact_bundle)
        artifact_digest = sha256_file(artifact_path)
        if not hmac_compare(artifact_digest, signed_artifact.sha256):
            raise StandaloneUpdateError("standalone ZIP differs from signed authority")
        verify_identity(artifact=artifact_path, bundle=artifact_bundle, tag=plan.tag)
        success = True
        return PreparedStandaloneUpdate(
            artifact_path=artifact_path,
            manifest=manifest,
            authenticated_artifact_sha256=artifact_digest,
        )
    finally:
        for path in downloaded:
            if success and artifact_path is not None and path == artifact_path:
                continue
            remove_staged_file(path)


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time comparison for canonical public digests."""

    import hmac

    return hmac.compare_digest(left, right)


__all__ = [
    "PreparedStandaloneUpdate",
    "ReleaseAsset",
    "StandaloneInstallPlan",
    "StandaloneUpdateError",
    "build_standalone_install_plan",
    "prepare_authenticated_standalone_update",
]
