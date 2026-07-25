#!/usr/bin/env python3
"""Run every committed TLA+ model and emit release-bindable evidence.

The manifest is deliberately authoritative: validation fails when a ``.tla``
or ``.cfg`` file exists outside it, when names differ only by case, when the
tool digest drifts, or when TLC does not report exhaustive success.  That turns
the formal directory from design documentation into a reproducible CI gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


MODEL_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MODULE_HEADER_RE = re.compile(
    r"^-+\s+MODULE\s+([A-Za-z_][A-Za-z0-9_]*)\s+-+\s*$", re.MULTILINE
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TLC_SUCCESS_MARKER = "Model checking completed. No error has been found."
MANIFEST_KEYS = frozenset({"schema", "tool", "models"})
TOOL_KEYS = frozenset({"name", "version", "sha256", "url"})
MODEL_KEYS = frozenset({"id", "spec", "config", "timeout_seconds"})
UNTRUSTED_JAVA_ENV = frozenset({
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
})


class FormalGateError(RuntimeError):
    """A manifest, tool, model, or evidence invariant failed."""


@dataclass(frozen=True)
class ToolAuthority:
    name: str
    version: str
    sha256: str
    url: str


@dataclass(frozen=True)
class Model:
    model_id: str
    spec: Path
    config: Path
    timeout_seconds: int


@dataclass(frozen=True)
class Manifest:
    path: Path
    formal_dir: Path
    tool: ToolAuthority
    models: tuple[Model, ...]


def _plain_object(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise FormalGateError(f"{label} must be a JSON object with string keys")
    return value


def _exact_keys(value: dict[str, Any], expected: frozenset[str], *, label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise FormalGateError(
            f"{label} fields do not match schema; missing={missing}, unknown={unknown}"
        )


def _relative_model_path(formal_dir: Path, value: Any, *, suffix: str, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise FormalGateError(f"{label} must be non-empty text")
    pure = PurePosixPath(value)
    if pure.is_absolute() or len(pure.parts) != 1 or pure.name in {".", ".."}:
        raise FormalGateError(f"{label} must be a direct child of docs/formal")
    if pure.suffix != suffix:
        raise FormalGateError(f"{label} must end in {suffix}")
    path = formal_dir / pure.name
    if not path.is_file() or path.is_symlink():
        raise FormalGateError(f"{label} is missing, not a file, or a symlink: {pure.name}")
    if path.resolve().parent != formal_dir.resolve():
        raise FormalGateError(f"{label} escapes docs/formal: {pure.name}")
    return path


def _require_unique_casefold(values: Sequence[str], *, label: str) -> None:
    by_folded: dict[str, str] = {}
    for value in values:
        folded = value.casefold()
        previous = by_folded.get(folded)
        if previous is not None:
            raise FormalGateError(
                f"{label} collision is unsafe on case-insensitive filesystems: "
                f"{previous!r} and {value!r}"
            )
        by_folded[folded] = value


def _validate_module_identity(spec: Path, config: Path, *, model_id: str) -> None:
    """Bind TLC's declared module, spec filename, and config filename exactly."""
    try:
        source = spec.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise FormalGateError(f"cannot read model {model_id} spec: {exc}") from exc
    matches = MODULE_HEADER_RE.findall(source)
    if len(matches) != 1:
        raise FormalGateError(
            f"model {model_id} must contain exactly one canonical MODULE declaration"
        )
    declared = matches[0]
    if declared != spec.stem:
        raise FormalGateError(
            f"model {model_id} module/filename mismatch: "
            f"declared={declared!r}, filename={spec.name!r}"
        )
    if config.stem != spec.stem:
        raise FormalGateError(
            f"model {model_id} config/spec mismatch: "
            f"config={config.name!r}, spec={spec.name!r}"
        )


def load_manifest(path: Path) -> Manifest:
    path = path.resolve()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FormalGateError(f"cannot read formal manifest {path}: {exc}") from exc
    root = _plain_object(payload, label="manifest")
    _exact_keys(root, MANIFEST_KEYS, label="manifest")
    if root["schema"] != 1:
        raise FormalGateError("unsupported formal manifest schema")

    tool_raw = _plain_object(root["tool"], label="manifest.tool")
    _exact_keys(tool_raw, TOOL_KEYS, label="manifest.tool")
    if tool_raw["name"] != "tla2tools":
        raise FormalGateError("manifest.tool.name must be tla2tools")
    for field in ("version", "url"):
        if not isinstance(tool_raw[field], str) or not tool_raw[field]:
            raise FormalGateError(f"manifest.tool.{field} must be non-empty text")
    digest = tool_raw["sha256"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise FormalGateError("manifest.tool.sha256 must be canonical lowercase SHA-256")
    expected_url = (
        "https://github.com/tlaplus/tlaplus/releases/download/"
        f"v{tool_raw['version']}/tla2tools.jar"
    )
    if tool_raw["url"] != expected_url:
        raise FormalGateError("manifest tool URL is not bound to its exact release version")
    tool = ToolAuthority(
        name=tool_raw["name"],
        version=tool_raw["version"],
        sha256=digest,
        url=tool_raw["url"],
    )

    models_raw = root["models"]
    if not isinstance(models_raw, list) or not models_raw:
        raise FormalGateError("manifest.models must be a non-empty array")
    formal_dir = path.parent
    models: list[Model] = []
    ids: list[str] = []
    spec_names: list[str] = []
    config_names: list[str] = []
    for index, raw in enumerate(models_raw):
        row = _plain_object(raw, label=f"manifest.models[{index}]")
        _exact_keys(row, MODEL_KEYS, label=f"manifest.models[{index}]")
        model_id = row["id"]
        if not isinstance(model_id, str) or not MODEL_ID_RE.fullmatch(model_id):
            raise FormalGateError(f"model {index} has a non-canonical id")
        timeout_seconds = row["timeout_seconds"]
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or not 1 <= timeout_seconds <= 3_600
        ):
            raise FormalGateError(f"model {model_id} timeout must be 1..3600 seconds")
        spec = _relative_model_path(
            formal_dir, row["spec"], suffix=".tla", label=f"model {model_id} spec"
        )
        config = _relative_model_path(
            formal_dir, row["config"], suffix=".cfg", label=f"model {model_id} config"
        )
        _validate_module_identity(spec, config, model_id=model_id)
        ids.append(model_id)
        spec_names.append(spec.name)
        config_names.append(config.name)
        models.append(Model(model_id, spec, config, timeout_seconds))

    _require_unique_casefold(ids, label="model id")
    _require_unique_casefold(spec_names, label="spec filename")
    _require_unique_casefold(config_names, label="config filename")
    if len(set(ids)) != len(ids):
        raise FormalGateError("duplicate model id")

    discovered_specs = {entry.name for entry in formal_dir.glob("*.tla")}
    discovered_configs = {entry.name for entry in formal_dir.glob("*.cfg")}
    if set(spec_names) != discovered_specs or set(config_names) != discovered_configs:
        raise FormalGateError(
            "formal manifest must cover every .tla/.cfg exactly; "
            f"unlisted_specs={sorted(discovered_specs - set(spec_names))}, "
            f"missing_specs={sorted(set(spec_names) - discovered_specs)}, "
            f"unlisted_configs={sorted(discovered_configs - set(config_names))}, "
            f"missing_configs={sorted(set(config_names) - discovered_configs)}"
        )
    return Manifest(path, formal_dir, tool, tuple(models))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_tool(manifest: Manifest, jar: Path) -> str:
    jar = jar.resolve()
    if not jar.is_file() or jar.is_symlink():
        raise FormalGateError(f"TLC jar is missing, not a file, or a symlink: {jar}")
    actual = sha256_file(jar)
    if actual != manifest.tool.sha256:
        raise FormalGateError(
            f"TLC jar digest mismatch: expected {manifest.tool.sha256}, got {actual}"
        )
    return actual


def _safe_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in UNTRUSTED_JAVA_ENV
    }


def _java_runtime(java: str, *, environment: dict[str, str]) -> dict[str, str]:
    """Return authenticated-run evidence for the Java executable used by TLC."""
    try:
        completed = subprocess.run(  # noqa: S603 - argv only; no shell
            [java, "-version"],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FormalGateError(f"cannot identify Java runtime {java!r}: {exc}") from exc
    version_output = (completed.stdout + completed.stderr).strip()
    if completed.returncode != 0 or not version_output:
        raise FormalGateError(
            f"Java runtime identification failed for {java!r}: "
            f"returncode={completed.returncode}"
        )
    return {
        "command": java,
        "version": version_output,
        "version_sha256": hashlib.sha256(version_output.encode("utf-8")).hexdigest(),
    }


def _git_commit(repo_root: Path) -> str | None:
    environment_value = os.environ.get("GITHUB_SHA", "").strip().lower()
    if environment_value and not re.fullmatch(r"[0-9a-f]{40,64}", environment_value):
        raise FormalGateError("GITHUB_SHA is not a canonical Git object id")
    try:
        completed = subprocess.run(  # noqa: S603,S607 - fixed command, no shell
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return environment_value or None
    value = completed.stdout.strip().lower()
    git_value = (
        value
        if completed.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value)
        else None
    )
    if git_value and environment_value and git_value != environment_value:
        raise FormalGateError(
            f"checked-out commit {git_value} does not match GITHUB_SHA {environment_value}"
        )
    return git_value or environment_value or None


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(encoded, encoding="utf-8", newline="\n")
    temporary.replace(path)


def run_models(
    manifest: Manifest,
    *,
    jar: Path,
    java: str,
    output_dir: Path,
    workers: int,
    repo_root: Path,
) -> dict[str, Any]:
    if not 1 <= workers <= 64:
        raise FormalGateError("workers must be between 1 and 64")
    jar_digest = verify_tool(manifest, jar)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = output_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    environment = _safe_environment()
    java_runtime = _java_runtime(java, environment=environment)
    started_ms = int(time.time() * 1000)
    results: list[dict[str, Any]] = []

    for model in manifest.models:
        model_started = time.monotonic()
        timed_out = False
        with tempfile.TemporaryDirectory(prefix=f"one-link-tlc-{model.model_id}-") as metadata:
            command = [
                java,
                "-XX:+UseParallelGC",
                "-jar",
                str(jar.resolve()),
                "-workers",
                str(workers),
                "-cleanup",
                "-metadir",
                metadata,
                "-config",
                model.config.name,
                model.spec.name,
            ]
            try:
                completed = subprocess.run(  # noqa: S603 - argv only; no shell
                    command,
                    cwd=manifest.formal_dir,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=model.timeout_seconds,
                )
                returncode: int | None = completed.returncode
                output = completed.stdout + completed.stderr
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                returncode = None
                stdout = (
                    exc.stdout.decode("utf-8", "replace")
                    if isinstance(exc.stdout, bytes)
                    else (exc.stdout or "")
                )
                stderr = (
                    exc.stderr.decode("utf-8", "replace")
                    if isinstance(exc.stderr, bytes)
                    else (exc.stderr or "")
                )
                output = stdout + stderr + (
                    f"\nFORMAL_GATE_TIMEOUT={model.timeout_seconds}s\n"
                )
            except OSError as exc:
                returncode = None
                output = f"FORMAL_GATE_EXEC_ERROR={exc}\n"

        duration_ms = round((time.monotonic() - model_started) * 1000)
        success = (
            not timed_out
            and returncode == 0
            and TLC_SUCCESS_MARKER in output
        )
        log_path = logs_dir / f"{model.model_id}.log"
        log_path.write_text(output, encoding="utf-8", errors="replace", newline="\n")
        results.append({
            "id": model.model_id,
            "spec": model.spec.name,
            "spec_sha256": sha256_file(model.spec),
            "config": model.config.name,
            "config_sha256": sha256_file(model.config),
            "timeout_seconds": model.timeout_seconds,
            "duration_ms": duration_ms,
            "returncode": returncode,
            "timed_out": timed_out,
            "success_marker": TLC_SUCCESS_MARKER in output,
            "status": "passed" if success else "failed",
            "log": log_path.relative_to(output_dir).as_posix(),
            "log_sha256": sha256_file(log_path),
        })

    finished_ms = int(time.time() * 1000)
    passed = all(row["status"] == "passed" for row in results)
    summary: dict[str, Any] = {
        "schema": 1,
        "status": "passed" if passed else "failed",
        "commit": _git_commit(repo_root),
        "started_ms": started_ms,
        "finished_ms": finished_ms,
        "duration_ms": max(0, finished_ms - started_ms),
        "workers": workers,
        "java": java_runtime,
        "tool": {
            "name": manifest.tool.name,
            "version": manifest.tool.version,
            "url": manifest.tool.url,
            "sha256": jar_digest,
        },
        "manifest": manifest.path.relative_to(repo_root).as_posix(),
        "manifest_sha256": sha256_file(manifest.path),
        "models": results,
    }
    _atomic_json(output_dir / "summary.json", summary)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("docs/formal/models.json"),
        help="authoritative model/tool manifest",
    )
    parser.add_argument("--jar", type=Path, help="verified tla2tools.jar")
    parser.add_argument("--java", default="java", help="Java executable")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".formal-results"),
        help="evidence output directory",
    )
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate exhaustive manifest coverage without executing TLC",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        if args.validate_only:
            print(f"formal manifest valid: {len(manifest.models)} models")
            return 0
        if args.jar is None:
            raise FormalGateError("--jar is required unless --validate-only is used")
        repo_root = Path(__file__).resolve().parents[1]
        summary = run_models(
            manifest,
            jar=args.jar,
            java=args.java,
            output_dir=args.output_dir,
            workers=args.workers,
            repo_root=repo_root,
        )
    except FormalGateError as exc:
        print(f"formal gate rejected: {exc}", file=sys.stderr)
        return 2
    passed = sum(row["status"] == "passed" for row in summary["models"])
    print(
        f"formal gate {summary['status']}: {passed}/{len(summary['models'])} models; "
        f"evidence={args.output_dir / 'summary.json'}"
    )
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
