"""Validate that a packaged One Link artifact matches current source.

This is the release-side guard for the stale-tarball class of bug:
source may be green while the public binary is old or missing dynamic
imports/package data. The validator is intentionally split into cheap
static checks and optional live probes so CI can run the static gate on
every build, while a release operator can point it at a launched packaged
daemon for the network-facing checks.

Examples:

    python scripts/validate_packaged_artifact.py \
      --artifact dist/one-link \
      --spec build/one-link.spec

    python scripts/validate_packaged_artifact.py \
      --artifact dist/one-link \
      --spec build/one-link.spec \
      --base-url https://192.168.1.142:7118 \
      --cacert "%LOCALAPPDATA%/One_link/data/peer_https/root_ca.pem"
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import contextlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import types
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from typing import Any


REQUIRED_HIDDEN_IMPORTS = (
    "one_link.sessions",
    "one_link.recovery_api",
)
REQUIRED_DATA_FRAGMENTS = (
    "one_link/web",
    "one_link/data",
    "one_link/_build",
    # The build-identity stamp (build_info.STAMP_FILENAME). Without it an
    # installed artifact cannot tell it is older than the published build,
    # so a stampless spec is a distribution-contract failure, not a warning.
    "one_link",
)
REQUIRED_STABLE_SUBMODULE_COLLECTORS = (
    "aiohttp",
    "cryptography",
    "one_link_native",
    "zeroconf",
)
STABLE_PREVIEW_MARKER = "ONE_LINK_PREVIEW_ML = False"
FORBIDDEN_STABLE_PREVIEW_FRAGMENTS = ("assets/models",)
REQUIRED_STABLE_EXCLUDES = (
    "aiohttp.pytest_plugin",
    "aiohttp.test_utils",
    "aiohttp.worker",
    "ast_serialize",
    "cffi._shimmed_dist_utils",
    "cffi.ffiplatform",
    "cffi.recompiler",
    "cffi.setuptools_ext",
    "cffi.verifier",
    "cffi.vengine_cpy",
    "cffi.vengine_gen",
    "hypothesis",
    "lxml",
    "mypy",
    "mypy_extensions",
    "annotated_types",
    "certifi",
    "charset_normalizer",
    "email_validator",
    "id",
    "jwt",
    "markdown_it",
    "mdurl",
    "numpy",
    "numpy.f2py",
    "numpy.testing",
    "onnxruntime",
    "one_link.ml",
    "one_link.neural_extrapolator",
    "one_link.semantic_scene_codec",
    "one_link.semantic_voice_codec",
    "pydantic.mypy",
    "pydantic.v1._hypothesis_plugin",
    "pydantic.v1.mypy",
    "pydantic",
    "pydantic_core",
    "pyasn1",
    "pygments",
    "rekor_types",
    "requests",
    "rfc3161_client",
    "rfc8785",
    "rich",
    "scipy",
    "securesystemslib",
    "setuptools",
    "sigstore",
    "sigstore_models",
    "tuf",
    "typing_inspection",
    "urllib3",
    "wheel",
)
FORBIDDEN_STABLE_BUNDLE_PATH_FRAGMENTS = (
    "/assets/models/",
    "/onnxruntime/",
    "/onnxruntime_providers_",
)
FORBIDDEN_STABLE_PHYSICAL_NAMESPACE_ROOTS = (
    "annotated_types",
    "ast_serialize",
    "certifi",
    "charset_normalizer",
    "email_validator",
    "hypothesis",
    "id",
    "jwt",
    "lxml",
    "markdown_it",
    "mdurl",
    "mypy",
    "mypy_extensions",
    "numpy",
    "pydantic",
    "pydantic_core",
    "pyasn1",
    "pygments",
    "rekor_types",
    "requests",
    "rfc3161_client",
    "rfc8785",
    "rich",
    "securesystemslib",
    "setuptools",
    "sigstore",
    "sigstore_models",
    "tuf",
    "typing_inspection",
    "urllib3",
    "wheel",
)
FORBIDDEN_STABLE_METADATA_FILENAMES = (
    "direct_url.json",
    "uv_build.json",
    "uv_cache.json",
)
FORBIDDEN_STABLE_EMBEDDED_MODULE_PREFIXES = (
    "aiohttp.pytest_plugin",
    "aiohttp.test_utils",
    "aiohttp.worker",
    "ast_serialize",
    "cffi._shimmed_dist_utils",
    "cffi.ffiplatform",
    "cffi.recompiler",
    "cffi.setuptools_ext",
    "cffi.verifier",
    "cffi.vengine_cpy",
    "cffi.vengine_gen",
    "hypothesis",
    "lxml",
    "mypy",
    "mypy_extensions",
    "annotated_types",
    "certifi",
    "charset_normalizer",
    "email_validator",
    "id",
    "jwt",
    "markdown_it",
    "mdurl",
    "numpy",
    "pydantic.mypy",
    "pydantic.v1._hypothesis_plugin",
    "pydantic.v1.mypy",
    "pydantic",
    "pydantic_core",
    "pyasn1",
    "pygments",
    "rekor_types",
    "requests",
    "rfc3161_client",
    "rfc8785",
    "rich",
    "scipy",
    "securesystemslib",
    "setuptools",
    "sigstore",
    "sigstore_models",
    "tuf",
    "typing_inspection",
    "urllib3",
    "wheel",
)

# Consume the same fail-closed namespace contract as the builder.  The legacy
# constants above remain source-readable rationale, but cannot drift into the
# executable release decision.
from one_link.build_identity import (  # noqa: E402
    STABLE_FROZEN_ALLOWED_THIRD_PARTY_ROOTS,
    STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES,
    STABLE_FROZEN_FORBIDDEN_PHYSICAL_ROOTS,
    STABLE_FROZEN_LEGACY_STDLIB_ROOTS,
    STABLE_FROZEN_MAX_BUNDLE_BYTES,
    STABLE_FROZEN_MAX_DIRECTORIES,
    STABLE_FROZEN_MAX_ENTRIES,
    STABLE_FROZEN_MAX_FILES,
    STABLE_FROZEN_MAX_PYZ_MODULES,
    STABLE_FROZEN_MAX_ZIP_MEMBERS,
    STABLE_FROZEN_MAX_ZIP_UNCOMPRESSED_BYTES,
)

REQUIRED_STABLE_EXCLUDES = STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES
FORBIDDEN_STABLE_EMBEDDED_MODULE_PREFIXES = STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES
FORBIDDEN_STABLE_PHYSICAL_NAMESPACE_ROOTS = tuple(
    sorted(
        set(FORBIDDEN_STABLE_PHYSICAL_NAMESPACE_ROOTS)
        | set(STABLE_FROZEN_FORBIDDEN_PHYSICAL_ROOTS)
    )
)
RUNTIME_FEATURE_EXPECTED_STATUSES = {
    "aiortc_datachannel": "OK",
    "keyring_backend": "OK",
    "native_cdc_scan": "OK",
    "packaging_updater": "OK",
    "pillow_tray_icon": "OK",
    "psutil_process": "OK",
    "pyav_primitives": "OK",
    "pystray_backend": "OK",
    "qrcode_svg_stdlib": "OK",
    "sigstore_frozen_update_boundary": "NOT_APPLICABLE_FROZEN_UPDATES_DISABLED",
    "sqlcipher_roundtrip": "OK",
    "watchdog_observer": "OK",
}
# Environment-conditional statuses a feature may honestly report in addition
# to its expected packaging status. pystray's X11 backend resolves DISPLAY at
# import time, so a headless host (CI runners) cannot exercise it regardless
# of bundle correctness -- the module bytes stay covered by the inventory and
# import gates. First release binaries to reach the feature smoke failed on
# exactly this, on every Linux leg.
RUNTIME_FEATURE_ALLOWED_ENVIRONMENT_STATUSES: dict[str, set[str]] = {
    "pystray_backend": {"NOT_APPLICABLE_HEADLESS_NO_DISPLAY"},
    # pyproject excludes aiortc (and its PyAV dependency) on Windows ARM64 by
    # environment marker -- upstream ships no cp3*-win_arm64 wheels -- and the
    # browser-datachannel path documents itself as unsupported on that binary.
    # Demanding OK there made this gate contradict the dependency contract.
    "aiortc_datachannel": {"NOT_APPLICABLE_NO_UPSTREAM_WIN_ARM64_WHEELS"},
    "pyav_primitives": {"NOT_APPLICABLE_NO_UPSTREAM_WIN_ARM64_WHEELS"},
}
REQUIRED_PEER_HEADERS = {
    "cache-control": ("no-cache", "must-revalidate"),
    "etag": ('"',),
}
DEFAULT_VERSION_TIMEOUT = 15.0
DEFAULT_INVENTORY_TIMEOUT = 120.0
DEFAULT_RUNTIME_IMPORT_TIMEOUT = 180.0
DEFAULT_RUNTIME_FEATURE_TIMEOUT = 120.0

_ARTIFACT_ENV_PASSTHROUGH = frozenset(
    {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TZ",
        "WINDIR",
    }
)


class GateFailure(RuntimeError):
    pass


def _artifact_subprocess_environment(isolated_root: Path) -> dict[str, str]:
    """Return a minimal environment that cannot import from the checkout.

    Release probes must exercise only bytes inside the frozen artifact.  They
    run from a disposable home/cwd and intentionally discard PYTHONPATH,
    PYTHONHOME, virtual-environment markers, loader overrides, and One Link
    developer/test switches inherited from the release shell.
    """
    env = {
        key: value for key, value in os.environ.items() if key.upper() in _ARTIFACT_ENV_PASSTHROUGH
    }
    root = isolated_root.resolve()
    temp_dir = root / "tmp"
    config_dir = root / "config"
    cache_dir = root / "cache"
    data_dir = root / "data"
    for directory in (temp_dir, config_dir, cache_dir, data_dir):
        directory.mkdir(parents=True, exist_ok=True)
    env.update(
        {
            "APPDATA": str(config_dir),
            "HOME": str(root),
            "LOCALAPPDATA": str(data_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TEMP": str(temp_dir),
            "TMP": str(temp_dir),
            "TMPDIR": str(temp_dir),
            "USERPROFILE": str(root),
            "XDG_CACHE_HOME": str(cache_dir),
            "XDG_CONFIG_HOME": str(config_dir),
            "XDG_DATA_HOME": str(data_dir),
            # The absolute launcher path and bundled loader closure require no
            # executable search.  An empty PATH proves probes did not import or
            # spawn helper programs from the checkout, venv, or user profile.
            "PATH": "",
        }
    )
    return env


def _run_artifact_command(
    executable: Path,
    arguments: list[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    executable = executable.resolve()
    with tempfile.TemporaryDirectory(prefix="one-link-artifact-gate-") as raw_root:
        isolated_root = Path(raw_root)
        return subprocess.run(
            [str(executable), *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=isolated_root,
            env=_artifact_subprocess_environment(isolated_root),
        )


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_source_version(repo: Path) -> str:
    init_py = repo / "src" / "one_link" / "__init__.py"
    try:
        module = ast.parse(init_py.read_text(encoding="utf-8"), filename=str(init_py))
    except (OSError, SyntaxError) as exc:
        raise GateFailure(f"could not parse {init_py}: {exc}") from exc
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            version = node.value.value.strip()
            if version:
                return version
    raise GateFailure(f"could not read literal __version__ from {init_py}")


def _expected_runtime_source_manifest(repo: Path) -> dict[str, Any]:
    """Compile and hash the current stable source without importing modules."""
    from one_link.build_identity import (
        EXPECTED_STABLE_RUNTIME_MODULES,
        EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        normalized_code_sha256,
        stable_module_source_path,
    )

    package_root = (repo.resolve() / "src" / "one_link").resolve()
    modules: dict[str, dict[str, str]] = {}
    for module in EXPECTED_STABLE_RUNTIME_MODULES:
        source_path = stable_module_source_path(package_root, module)
        try:
            metadata = source_path.lstat()
        except OSError as exc:
            raise GateFailure(f"stable source is missing: {source_path}: {exc}") from exc
        if _is_link_like(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise GateFailure(f"stable source is not a physical regular file: {source_path}")
        try:
            source = source_path.read_bytes()
            after = source_path.lstat()
        except OSError as exc:
            raise GateFailure(f"stable source cannot be read: {source_path}: {exc}") from exc
        before_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if before_identity != after_identity:
            raise GateFailure(f"stable source changed while hashing: {source_path}")
        try:
            code = compile(
                source,
                str(source_path),
                "exec",
                dont_inherit=True,
                optimize=sys.flags.optimize,
            )
        except (SyntaxError, ValueError) as exc:
            raise GateFailure(f"stable source cannot compile: {source_path}: {exc}") from exc
        modules[module] = {
            "source_path": source_path.relative_to(package_root).as_posix(),
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "normalized_code_sha256": normalized_code_sha256(code),
        }
    return {
        "schema": "one-link-runtime-source-manifest-v1",
        "python_cache_tag": sys.implementation.cache_tag,
        "python_optimization": sys.flags.optimize,
        "runtime_module_manifest_sha256": EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        "modules": modules,
    }


def _canonical_manifest_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _normalize_text(text: str) -> str:
    return text.replace("\\", "/")


def _stable_preview_contract_failures(text: str) -> list[str]:
    failures: list[str] = []
    try:
        tree = ast.parse(text, filename="one-link.spec")
    except SyntaxError:
        return ["parseable PyInstaller spec"]

    preview_values: list[object] = []
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if not any(
            isinstance(target, ast.Name) and target.id == "ONE_LINK_PREVIEW_ML"
            for target in targets
        ):
            continue
        try:
            if statement.value is None:
                raise ValueError("annotation has no value")
            preview_values.append(ast.literal_eval(statement.value))
        except (TypeError, ValueError):
            preview_values.append(object())
    if not (
        len(preview_values) == 1 and type(preview_values[0]) is bool and preview_values[0] is False
    ):
        failures.append("literal stable preview gate ONE_LINK_PREVIEW_ML = False")

    analysis_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name)
            and node.func.id == "Analysis"
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == "Analysis"
        )
    ]
    excludes: object = None
    if len(analysis_calls) == 1:
        keyword = next(
            (item for item in analysis_calls[0].keywords if item.arg == "excludes"),
            None,
        )
        if keyword is not None:
            try:
                excludes = ast.literal_eval(keyword.value)
            except (TypeError, ValueError):
                excludes = None
    if not isinstance(excludes, (list, tuple, set)) or not all(
        isinstance(item, str) for item in excludes
    ):
        failures.append("one literal Analysis(..., excludes=[...]) contract")
    else:
        missing_excludes = sorted(set(REQUIRED_STABLE_EXCLUDES) - set(excludes))
        if missing_excludes:
            failures.append("stable Analysis exclusions missing: " + ", ".join(missing_excludes))

    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.Call):
            continue
        function_name = (
            candidate.func.id
            if isinstance(candidate.func, ast.Name)
            else candidate.func.attr
            if isinstance(candidate.func, ast.Attribute)
            else ""
        )
        if function_name != "collect_all" or not candidate.args:
            continue
        try:
            collected = ast.literal_eval(candidate.args[0])
        except (TypeError, ValueError):
            continue
        if collected == "onnxruntime":
            failures.append("stable preview spec must not collect_all('onnxruntime')")
            break
    found = [fragment for fragment in FORBIDDEN_STABLE_PREVIEW_FRAGMENTS if fragment in text]
    if found:
        failures.append("preview payload present in stable artifact: " + ", ".join(found))
    return failures


def _stable_spec_structure_failures(text: str) -> list[str]:
    """Validate security-relevant spec fields from AST, never substrings."""
    from one_link.build_identity import EXPECTED_STABLE_RUNTIME_MODULES

    try:
        tree = ast.parse(text, filename="one-link.spec")
    except SyntaxError:
        return ["parseable PyInstaller spec"]

    literal_assignments: dict[str, list[object]] = {
        "binaries": [],
        "datas": [],
        "hiddenimports": [],
    }
    analysis_calls: list[ast.Call] = []
    top_level_collectors: list[str] = []
    executable_collector_calls: set[int] = set()
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            names = [target.id for target in statement.targets if isinstance(target, ast.Name)]
            for name in literal_assignments.keys() & names:
                try:
                    value = ast.literal_eval(statement.value)
                except (TypeError, ValueError):
                    value = None
                literal_assignments[name].append(value)
            if (
                len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == "a"
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Name)
                and statement.value.func.id == "Analysis"
            ):
                analysis_calls.append(statement.value)
        if not isinstance(statement, ast.AugAssign):
            continue
        if not isinstance(statement.target, ast.Name) or statement.target.id != "hiddenimports":
            continue
        call = statement.value
        if (
            not isinstance(statement.op, ast.Add)
            or not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Name)
            or call.func.id != "collect_submodules"
            or len(call.args) != 1
            or call.keywords
        ):
            continue
        try:
            collected = ast.literal_eval(call.args[0])
        except (TypeError, ValueError):
            continue
        executable_collector_calls.add(id(call))
        if isinstance(collected, str):
            top_level_collectors.append(collected)

    failures: list[str] = []
    hidden_values = literal_assignments["hiddenimports"]
    if (
        len(hidden_values) != 1
        or not isinstance(hidden_values[0], list)
        or not all(isinstance(item, str) for item in hidden_values[0])
    ):
        failures.append("one literal hiddenimports production manifest")
    else:
        hidden = set(hidden_values[0])
        expected = set(EXPECTED_STABLE_RUNTIME_MODULES)
        omitted = sorted(expected - hidden)
        unexpected = sorted(hidden - expected)
        if omitted or unexpected:
            failures.append(
                "hiddenimports differ from stable runtime manifest: "
                f"omitted={omitted!r}, unexpected={unexpected!r}"
            )

    data_values = literal_assignments["datas"]
    if len(data_values) != 1 or not isinstance(data_values[0], list):
        failures.append("one literal datas package-data manifest")
    else:
        from one_link.native_cdc import (
            native_library_name,
            native_platform_tag,
        )

        data_rows = [
            (
                item[0].replace("\\", "/"),
                item[1].replace("\\", "/").rstrip("/"),
            )
            for item in data_values[0]
            if isinstance(item, (list, tuple))
            and len(item) == 2
            and all(isinstance(value, str) for value in item)
        ]
        native_destination = f"one_link/native/{native_platform_tag()}"
        expected_destinations = {*REQUIRED_DATA_FRAGMENTS, native_destination}
        destinations = [destination for _source, destination in data_rows]
        from one_link.build_info import STAMP_FILENAME

        expected_source_suffixes = {
            "one_link/web": "/src/one_link/web",
            "one_link/data": "/src/one_link/data",
            "one_link/_build": "/build/release-contract/runtime-source-manifest.json",
            # PyInstaller keeps the source basename, and build_info reads
            # only STAMP_FILENAME, so the exact name is part of the contract.
            "one_link": "/build/release-contract/" + STAMP_FILENAME,
            native_destination: "/" + native_library_name() + ".sha256",
        }
        def _source_matches(source: str, suffix: str) -> bool:
            return source == suffix.removeprefix("/") or source.endswith(suffix)

        malformed_rows = len(data_rows) != len(data_values[0])
        missing_destinations = sorted(expected_destinations - set(destinations))
        unexpected_destinations = sorted(set(destinations) - expected_destinations)
        duplicate_destinations = sorted(
            destination for destination in set(destinations) if destinations.count(destination) > 1
        )
        bad_sources = sorted(
            source
            for source, destination in data_rows
            if destination not in expected_source_suffixes
            or not _source_matches(source, expected_source_suffixes[destination])
        )
        if (
            malformed_rows
            or len(data_rows) != len(expected_destinations)
            or missing_destinations
            or unexpected_destinations
            or duplicate_destinations
            or bad_sources
        ):
            failures.append(
                "exact stable package-data and native-CDC sidecar manifest: "
                f"malformed={malformed_rows!r}, missing={missing_destinations!r}, "
                f"unexpected={unexpected_destinations!r}, "
                f"duplicate={duplicate_destinations!r}, bad_sources={bad_sources!r}"
            )

    binary_values = literal_assignments["binaries"]
    from one_link.native_cdc import native_library_name, native_platform_tag

    native_destination = f"one_link/native/{native_platform_tag()}"
    if (
        len(binary_values) != 1
        or not isinstance(binary_values[0], list)
        or len(binary_values[0]) != 1
        or not isinstance(binary_values[0][0], (list, tuple))
        or len(binary_values[0][0]) != 2
        or (
            str(binary_values[0][0][0]).replace("\\", "/")
            != native_library_name()
            and not str(binary_values[0][0][0]).replace("\\", "/").endswith(
                "/" + native_library_name()
            )
        )
        or str(binary_values[0][0][1]).replace("\\", "/").rstrip("/")
        != native_destination
    ):
        failures.append("one literal mandatory native-CDC binary manifest")

    if len(analysis_calls) != 1:
        failures.append("one top-level a = Analysis(...) production graph")
    else:
        analysis = analysis_calls[0]
        expected_names = {
            "binaries": "binaries",
            "datas": "datas",
            "hiddenimports": "hiddenimports",
        }
        for keyword_name, variable_name in expected_names.items():
            values = [item.value for item in analysis.keywords if item.arg == keyword_name]
            if not (
                len(values) == 1
                and isinstance(values[0], ast.Name)
                and values[0].id == variable_name
            ):
                failures.append(
                    f"Analysis(..., {keyword_name}={variable_name}) production binding"
                )

        exclude_values = [item.value for item in analysis.keywords if item.arg == "excludes"]
        try:
            analysis_excludes = ast.literal_eval(exclude_values[0]) if len(exclude_values) == 1 else None
        except (TypeError, ValueError):
            analysis_excludes = None
        if not isinstance(analysis_excludes, (list, tuple)) or not all(
            isinstance(item, str) for item in analysis_excludes
        ):
            failures.append("literal Analysis(..., excludes=[...]) production binding")
        else:
            missing_excludes = sorted(set(REQUIRED_STABLE_EXCLUDES) - set(analysis_excludes))
            if missing_excludes:
                failures.append("stable Analysis exclusions missing: " + ", ".join(missing_excludes))

    all_submodule_calls: list[tuple[int, object]] = []
    collect_all_calls = 0
    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.Call):
            continue
        function_name = (
            candidate.func.id
            if isinstance(candidate.func, ast.Name)
            else candidate.func.attr
            if isinstance(candidate.func, ast.Attribute)
            else ""
        )
        if function_name not in {"collect_all", "collect_submodules"}:
            continue
        if function_name == "collect_all":
            collect_all_calls += 1
            continue
        if len(candidate.args) != 1 or candidate.keywords:
            all_submodule_calls.append((id(candidate), None))
            continue
        try:
            collected = ast.literal_eval(candidate.args[0])
        except (TypeError, ValueError):
            collected = None
        all_submodule_calls.append((id(candidate), collected))
    if collect_all_calls:
        failures.append("no collect_all(...) metadata collection in a stable spec")
    if (
        sorted(top_level_collectors) != list(REQUIRED_STABLE_SUBMODULE_COLLECTORS)
        or sorted(value for _identity, value in all_submodule_calls if isinstance(value, str))
        != list(REQUIRED_STABLE_SUBMODULE_COLLECTORS)
        or any(not isinstance(value, str) for _identity, value in all_submodule_calls)
    ):
        failures.append(
            "exact live top-level collect_submodules manifest: "
            + ", ".join(REQUIRED_STABLE_SUBMODULE_COLLECTORS)
        )
    # A collector hidden in ``if False``, a function body, lambda, or unused
    # literal must never satisfy the spec contract.  Every native collector in
    # the AST must be the direct value of the reviewed top-level augmentation.
    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.Call) or not candidate.args:
            continue
        if not isinstance(candidate.func, ast.Name) or candidate.func.id != "collect_submodules":
            continue
        try:
            collected = ast.literal_eval(candidate.args[0])
        except (TypeError, ValueError):
            continue
        if id(candidate) not in executable_collector_calls:
            failures.append("no dead or indirectly consumed submodule collector")
            break
    return failures


def validate_spec(spec_path: Path) -> list[str]:
    if not spec_path.is_file():
        raise GateFailure(f"spec file not found: {spec_path}")
    text = _normalize_text(spec_path.read_text(encoding="utf-8"))
    missing = _stable_preview_contract_failures(text)
    missing += _stable_spec_structure_failures(text)
    if missing:
        raise GateFailure("generated PyInstaller spec is missing: " + ", ".join(missing))
    return [
        "spec includes dynamic imports: " + ", ".join(REQUIRED_HIDDEN_IMPORTS),
        "spec includes package data: " + ", ".join(REQUIRED_DATA_FRAGMENTS),
        "stable artifact excludes preview ML models/runtime",
    ]


def _module_matches_prefix(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def _forbidden_embedded_modules(modules: set[str] | tuple[str, ...]) -> list[str]:
    """Return exact namespace matches, without substring false positives."""
    return sorted(
        module
        for module in modules
        if any(
            _module_matches_prefix(module, prefix)
            for prefix in FORBIDDEN_STABLE_EMBEDDED_MODULE_PREFIXES
        )
    )


def _embedded_python_archive(
    executable: Path,
) -> tuple[tuple[str, ...], dict[str, str]]:
    """Read PYZ names and independently hash every stable code object.

    Candidate-emitted JSON proves that its importer can resolve modules, but it
    is not independent evidence of the bytes in the candidate: compromised or
    stale code can simply print the expected digests.  This reader unmarshals
    the nested PYZ directly from the executable and applies the source-owned
    canonical code serializer to all 194 stable modules.
    """
    from one_link.build_identity import (
        EXPECTED_STABLE_RUNTIME_MODULES,
        normalized_code_sha256,
    )

    try:
        from PyInstaller.archive.readers import CArchiveReader
    except ImportError as exc:
        raise GateFailure(
            "PyInstaller archive reader is required for the stable nested-PYZ gate"
        ) from exc

    try:
        archive = CArchiveReader(str(executable.resolve(strict=True)))
        pyz_entries = [
            name
            for name, entry in archive.toc.items()
            if isinstance(name, str)
            and isinstance(entry, tuple)
            and entry
            and entry[-1] == "z"
        ]
    except Exception as exc:
        # PyInstaller exposes version-specific archive exception classes; this
        # parser consumes an untrusted release candidate and must normalize all
        # malformed-archive failures into the gate's stable error taxonomy.
        raise GateFailure(f"could not parse frozen executable archive: {exc}") from exc
    if len(pyz_entries) != 1:
        raise GateFailure(
            "frozen executable must contain exactly one inspectable PYZ archive; "
            f"found {pyz_entries!r}"
        )
    try:
        pyz = archive.open_embedded_archive(pyz_entries[0])
        toc = pyz.toc
    except Exception as exc:
        # See above: nested archive corruption must fail closed without leaking
        # a PyInstaller implementation exception through the release command.
        raise GateFailure(f"could not parse nested PYZ archive: {exc}") from exc
    if not isinstance(toc, dict) or not toc or not all(isinstance(name, str) for name in toc):
        raise GateFailure("nested PYZ archive has an invalid or empty module table")
    modules = tuple(sorted(toc))
    if len(modules) > STABLE_FROZEN_MAX_PYZ_MODULES:
        raise GateFailure(
            f"nested PYZ module budget exceeded: {len(modules)} > "
            f"{STABLE_FROZEN_MAX_PYZ_MODULES}"
        )
    stable_digests: dict[str, str] = {}
    for module in EXPECTED_STABLE_RUNTIME_MODULES:
        if module not in toc:
            continue
        try:
            code = pyz.extract(module)
        except Exception as exc:
            raise GateFailure(f"could not extract stable PYZ module {module}: {exc}") from exc
        if not isinstance(code, types.CodeType):
            raise GateFailure(f"stable PYZ entry is not executable code: {module}")
        try:
            stable_digests[module] = normalized_code_sha256(code)
        except (TypeError, ValueError) as exc:
            raise GateFailure(f"could not normalize stable PYZ code {module}: {exc}") from exc
    return modules, stable_digests


def _embedded_python_module_names(executable: Path) -> tuple[str, ...]:
    """Compatibility wrapper for tests and callers that need only PYZ names."""
    return _embedded_python_archive(executable)[0]


def _unexpected_python_roots(modules: tuple[str, ...] | set[str]) -> list[str]:
    allowed = (
        set(sys.stdlib_module_names)
        | set(STABLE_FROZEN_LEGACY_STDLIB_ROOTS)
        | set(STABLE_FROZEN_ALLOWED_THIRD_PARTY_ROOTS)
        | {"one_link"}
    )
    return sorted(
        root
        for root in {module.split(".", 1)[0] for module in modules}
        if root not in allowed
        # CPython generates its build-configuration module with a
        # platform-specific name (_sysconfigdata__linux_x86_64-linux-gnu,
        # aarch64 and darwin variants...) that is stdlib but absent from
        # sys.stdlib_module_names -- it refused the first Linux release
        # bundle ever gated. It is stdlib by construction, not a leak.
        and not root.startswith("_sysconfigdata_")
    )


def _zip_python_modules(path: Path) -> tuple[str, ...]:
    """Inspect one physical Python ZIP with traversal/duplicate/bomb limits."""
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > STABLE_FROZEN_MAX_ZIP_MEMBERS:
                raise GateFailure(f"Python ZIP member budget exceeded in {path}: {len(infos)}")
            total = sum(info.file_size for info in infos)
            if total > STABLE_FROZEN_MAX_ZIP_UNCOMPRESSED_BYTES:
                raise GateFailure(
                    f"Python ZIP uncompressed budget exceeded in {path}: {total}"
                )
            names = [info.filename for info in infos]
            folded = [
                unicodedata.normalize("NFC", name.replace("\\", "/")).casefold()
                for name in names
            ]
            if len(names) != len(set(names)) or len(folded) != len(set(folded)):
                raise GateFailure(f"Python ZIP has duplicate/colliding members: {path}")
            modules: set[str] = set()
            for name in names:
                normalized = name.replace("\\", "/")
                parts = normalized.split("/")
                posix_path = PurePosixPath(normalized)
                windows_path = PureWindowsPath(name)
                if (
                    normalized.startswith("/")
                    or "\\" in name
                    or ".." in parts
                    or any(not part for part in parts)
                    or posix_path.as_posix() != normalized
                    or windows_path.drive
                    or windows_path.root
                    or any(ord(character) < 32 or ord(character) == 127 for character in name)
                ):
                    raise GateFailure(f"Python ZIP has unsafe member {name!r}: {path}")
                if not normalized.endswith((".py", ".pyc")):
                    continue
                without_suffix = normalized.rsplit(".", 1)[0]
                module_parts = without_suffix.split("/")
                if "__pycache__" in module_parts:
                    cache_index = module_parts.index("__pycache__")
                    cached = module_parts[cache_index + 1].split(".", 1)[0]
                    module_parts = module_parts[:cache_index] + [cached]
                if module_parts[-1] == "__init__":
                    module_parts.pop()
                if module_parts:
                    modules.add(".".join(module_parts))
            # Reading every member makes CRC validation real and bounded by the
            # budget above; metadata-only testzip checks can miss size-policy
            # regressions and do not bind our module parsing to readable bytes.
            for info in infos:
                with archive.open(info, "r") as stream:
                    while stream.read(1024 * 1024):
                        pass
            return tuple(sorted(modules))
    except GateFailure:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise GateFailure(f"could not inspect physical Python ZIP {path}: {exc}") from exc


def _inspect_physical_python_archives(artifact: Path) -> tuple[int, int]:
    if not artifact.is_dir():
        return 0, 0
    executable = _find_artifact_executable(artifact)
    inventory_root, _runtime_root, _data_root, _layout = _artifact_layout(
        artifact, executable
    )
    archive_count = 0
    module_count = 0
    for label in _independent_bundle_hashes(artifact):
        relative = label.removeprefix("bundle/")
        if not relative.lower().endswith(".zip"):
            continue
        path = inventory_root / Path(relative)
        modules = _zip_python_modules(path)
        archive_count += 1
        module_count += len(modules)
        forbidden = _forbidden_embedded_modules(modules)
        if forbidden:
            raise GateFailure(
                f"physical Python ZIP contains forbidden modules ({relative}): "
                + ", ".join(forbidden[:20])
            )
        unexpected_roots = _unexpected_python_roots(set(modules))
        if unexpected_roots:
            raise GateFailure(
                f"physical Python ZIP contains unreviewed roots ({relative}): "
                + ", ".join(unexpected_roots[:20])
            )
        unexpected_one_link = sorted(
            module for module in modules if _module_matches_prefix(module, "one_link")
        )
        if unexpected_one_link:
            raise GateFailure(
                "One Link application code must live only in the signed PYZ, not a physical ZIP: "
                + ", ".join(unexpected_one_link[:20])
            )
    return archive_count, module_count


_MODULE_ARTIFACT_SUFFIXES = (".py", ".pyc", ".pyd", ".so", ".dylib", ".dll")


def _path_contains_forbidden_namespace(relative: str) -> bool:
    components = tuple(
        component.lower()
        for component in relative.replace("\\", "/").strip("/").split("/")
        if component
    )
    if not components:
        return False
    # Namespace roots describe PACKAGES, which manifest as directories
    # (numpy/..., wheel-0.47.dist-info/...) or as importable module files
    # (id.cpython-312.pyd). Applying the directory rules to terminal
    # FILENAMES flagged innocent data that merely shares a name -- every
    # dist-info/WHEEL metadata file matched the `wheel` package, Tcl's
    # Indonesian locale id.msg matched sigstore's `id`, and ttk's
    # notebook.tcl matched `notebook` -- which refused the first release
    # binaries ever built. Terminal files count only as module artifacts.
    *directories, terminal = components
    for namespace in FORBIDDEN_STABLE_PHYSICAL_NAMESPACE_ROOTS:
        distribution = namespace.replace("_", "-")
        for component in directories:
            if component == namespace or component.startswith(namespace + "."):
                return True
            if component.startswith(namespace + "_") or component.startswith(
                distribution + "-"
            ):
                return True
            if component.endswith((".dist-info", ".egg-info", ".data")) and (
                component.startswith(namespace + "-")
                or component.startswith(distribution + "-")
            ):
                return True
        if terminal.startswith((namespace + ".", namespace + "_")) and terminal.endswith(
            _MODULE_ARTIFACT_SUFFIXES
        ):
            return True
    return False


def validate_stable_bundle_contents(artifact: Path) -> str:
    """Reject preview, dev/test/tooling, and local-build bytes independently."""
    if not artifact.is_file() and not artifact.is_dir():
        raise GateFailure(f"artifact path not found: {artifact}")

    forbidden_paths: list[str] = []
    if artifact.is_dir():
        inventory = _independent_bundle_hashes(artifact)
        for label in inventory:
            relative = label.removeprefix("bundle/")
            normalized = "/" + relative.replace("\\", "/").lower()
            filename = Path(relative).name.lower()
            if (
                any(fragment in normalized for fragment in FORBIDDEN_STABLE_BUNDLE_PATH_FRAGMENTS)
                or filename.startswith("checkpoint.onnx")
                or filename in FORBIDDEN_STABLE_METADATA_FILENAMES
                or filename.endswith((".py", ".pyc"))
                or _path_contains_forbidden_namespace(relative)
            ):
                forbidden_paths.append(relative)
                if len(forbidden_paths) >= 12:
                    break
    if forbidden_paths:
        raise GateFailure(
            "stable artifact contains forbidden preview/dev/tooling/local-build payload: "
            + ", ".join(forbidden_paths)
        )

    executable = _find_artifact_executable(artifact)
    embedded_modules, _stable_digests = _embedded_python_archive(executable)
    forbidden_modules = _forbidden_embedded_modules(embedded_modules)
    if forbidden_modules:
        raise GateFailure(
            "stable artifact nested PYZ contains forbidden preview/dev/tooling modules: "
            + ", ".join(forbidden_modules[:20])
        )
    from one_link.build_identity import EXPECTED_STABLE_RUNTIME_MODULES

    embedded_one_link = {
        module for module in embedded_modules if _module_matches_prefix(module, "one_link")
    }
    expected_one_link = set(EXPECTED_STABLE_RUNTIME_MODULES)
    if embedded_one_link != expected_one_link:
        raise GateFailure(
            "stable artifact One Link namespace is not exact: "
            f"missing={sorted(expected_one_link - embedded_one_link)!r}, "
            f"unexpected={sorted(embedded_one_link - expected_one_link)!r}"
        )
    unexpected_roots = _unexpected_python_roots(set(embedded_modules))
    if unexpected_roots:
        raise GateFailure(
            "stable artifact nested PYZ contains unreviewed Python roots: "
            + ", ".join(unexpected_roots[:20])
        )
    archive_count, archive_module_count = _inspect_physical_python_archives(artifact)
    return (
        "stable artifact contains no forbidden preview/dev/tooling/local-build payload; "
        f"nested PYZ inspected {len(embedded_modules)} allowlisted modules with exact "
        f"One Link namespace; inspected {archive_count} physical Python ZIP(s) "
        f"containing {archive_module_count} modules"
    )


def _find_artifact_executable(artifact: Path) -> Path:
    try:
        artifact_metadata = artifact.lstat()
    except OSError as exc:
        raise GateFailure(f"artifact path not found or unreadable: {artifact}") from exc
    if _is_link_like(artifact_metadata):
        raise GateFailure(f"artifact root is a link/reparse point: {artifact}")
    if stat.S_ISREG(artifact_metadata.st_mode):
        metadata = artifact_metadata
        if _is_link_like(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise GateFailure(f"One Link launcher is a link/reparse/special entry: {artifact}")
        return artifact.resolve(strict=True)
    if not stat.S_ISDIR(artifact_metadata.st_mode):
        raise GateFailure(f"artifact root is not a regular file or directory: {artifact}")
    candidates = [
        artifact / "one-link.exe",
        artifact / "one-link",
        artifact / "One Link.exe",
        artifact / "Contents" / "MacOS" / "one-link",
        artifact / "one-link.app" / "Contents" / "MacOS" / "one-link",
    ]
    reviewed_matches: list[Path] = []
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if _is_link_like(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise GateFailure(f"One Link launcher is a link/reparse/special entry: {candidate}")
        reviewed_matches.append(candidate)
    # Reject copied/backup launchers anywhere in the bundle, including paths a
    # permissive first-match resolver would otherwise ignore.
    discovered_matches: list[Path] = []
    try:
        for directory, directory_names, file_names in os.walk(artifact, followlinks=False):
            directory_names.sort()
            file_names.sort()
            parent = Path(directory)
            for directory_name in list(directory_names):
                child = parent / directory_name
                try:
                    metadata = child.lstat()
                except OSError as exc:
                    raise GateFailure(f"could not inspect artifact directory: {child}") from exc
                if _is_link_like(metadata):
                    # Never search through aliases for an executable. The
                    # complete inventory gate subsequently rejects them in
                    # onedir layouts and validates contained macOS framework
                    # links without following them.
                    directory_names.remove(directory_name)
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    raise GateFailure(f"artifact directory entry is not a directory: {child}")
            for filename in file_names:
                if filename.casefold() not in {"one-link", "one-link.exe", "one link.exe"}:
                    continue
                candidate = parent / filename
                try:
                    metadata = candidate.lstat()
                except OSError as exc:
                    raise GateFailure(f"could not inspect One Link launcher: {candidate}") from exc
                if _is_link_like(metadata) or not stat.S_ISREG(metadata.st_mode):
                    raise GateFailure(
                        f"One Link launcher is a link/reparse/special entry: {candidate}"
                    )
                discovered_matches.append(candidate)
    except OSError as exc:
        raise GateFailure(f"could not enumerate artifact launchers: {exc}") from exc
    reviewed = {candidate.resolve(strict=True) for candidate in reviewed_matches}
    discovered = {candidate.resolve(strict=True) for candidate in discovered_matches}
    if len(reviewed) != 1 or discovered != reviewed:
        raise GateFailure(
            "stable onedir must contain exactly one reviewed One Link launcher; "
            f"reviewed={[str(path) for path in sorted(reviewed)]!r}, "
            f"discovered={[str(path) for path in sorted(discovered)]!r}"
        )
    return next(iter(reviewed))


def _artifact_layout(
    artifact: Path,
    executable: Path,
) -> tuple[Path, Path, Path, str]:
    """Return inventory root, runtime root, data root, and layout contract."""
    executable = executable.resolve()
    # An app bundle is recognized by its STRUCTURE, not by the folder's name.
    # The release ZIP archives every platform under the root member
    # "one-link", so the extracted macOS copy is
    # <tmp>/one-link/Contents/MacOS/one-link -- structurally an .app, but
    # without the suffix. Requiring the suffix made the extracted copy fall
    # through to the onedir contract, which forbids the Frameworks/Resources
    # mirror links Apple's layout requires, and the final packaging gate
    # rejected the very bundle its own artifact-level pass had accepted.
    # Info.plist beside Contents/MacOS is the load-bearing marker.
    contents_root = executable.parent.parent
    if (
        executable.parent.name == "MacOS"
        and contents_root.name == "Contents"
        and (
            contents_root.parent.suffix.lower() == ".app"
            or (contents_root / "Info.plist").is_file()
        )
    ):
        app_root = executable.parent.parent.parent.resolve()
        return (
            app_root,
            app_root / "Contents" / "Frameworks",
            app_root / "Contents" / "Resources",
            "frozen_macos_app_bundle",
        )
    root = (artifact if artifact.is_dir() else executable.parent).resolve()
    runtime_root = root / "_internal"
    return root, runtime_root, runtime_root, "frozen_onedir_bundle"


def _is_link_like(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _stable_file_sha256(path: Path) -> str:
    """Hash one regular file while detecting link swaps and concurrent writes."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise GateFailure(f"could not inspect bundle entry {path}: {exc}") from exc
    if _is_link_like(before):
        raise GateFailure(f"bundle entry is a link or reparse point: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise GateFailure(f"bundle entry is not a regular file: {path}")
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            identity_opened = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            )
            if identity_opened != identity_before:
                raise GateFailure(f"bundle entry changed before hashing: {path}")
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            after_open = os.fstat(handle.fileno())
        after_path = path.lstat()
    except OSError as exc:
        raise GateFailure(f"could not hash bundle entry {path}: {exc}") from exc
    identities_after = (
        (
            after_open.st_dev,
            after_open.st_ino,
            after_open.st_size,
            after_open.st_mtime_ns,
        ),
        (
            after_path.st_dev,
            after_path.st_ino,
            after_path.st_size,
            after_path.st_mtime_ns,
        ),
    )
    if any(identity != identity_opened for identity in identities_after):
        raise GateFailure(f"bundle entry changed while hashing: {path}")
    return digest.hexdigest()


def _safe_relative_link_sha256(
    root: Path,
    path: Path,
    *,
    link_target: str | None = None,
) -> str:
    """Hash one contained relative symlink without following it as a file."""
    try:
        target = os.readlink(path) if link_target is None else link_target
    except OSError as exc:
        raise GateFailure(f"could not read bundle symlink {path}: {exc}") from exc
    target_path = Path(target)
    if target_path.is_absolute():
        raise GateFailure(f"bundle symlink target is absolute: {path} -> {target}")
    try:
        resolved_root = root.resolve(strict=True)
        resolved_target = (path.parent / target_path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GateFailure(f"bundle symlink target is broken or cyclic: {path} -> {target}") from exc
    if resolved_target != resolved_root and resolved_root not in resolved_target.parents:
        raise GateFailure(f"bundle symlink escapes artifact: {path} -> {target}")
    encoded = target.encode("utf-8", "surrogatepass")
    digest = hashlib.sha256(b"ONE-LINK-BUNDLE-SYMLINK-V1\x00")
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return digest.hexdigest()


def _independent_bundle_hashes(artifact: Path) -> dict[str, str]:
    """Walk an onedir bundle independently of its executable's self-report."""
    if not artifact.is_dir():
        raise GateFailure("complete runtime inventory requires an inspectable onedir artifact")
    executable = _find_artifact_executable(artifact)
    root, _runtime_root, _data_root, layout = _artifact_layout(artifact, executable)
    allow_contained_links = layout == "frozen_macos_app_bundle"
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise GateFailure(f"could not inspect artifact root {root}: {exc}") from exc
    if _is_link_like(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise GateFailure(f"artifact root is not a safe physical directory: {root}")

    hashes: dict[str, str] = {}
    total_bytes = 0
    directory_count = 0
    entry_count = 0

    def _walk_error(error: OSError) -> None:
        raise error

    try:
        for directory, directory_names, file_names in os.walk(
            root,
            followlinks=False,
            onerror=_walk_error,
        ):
            directory_names.sort()
            file_names.sort()
            directory_count += 1
            entry_count += len(directory_names) + len(file_names)
            if directory_count > STABLE_FROZEN_MAX_DIRECTORIES:
                raise GateFailure(
                    "stable bundle directory budget exceeded: "
                    f"{directory_count} > {STABLE_FROZEN_MAX_DIRECTORIES}"
                )
            if entry_count > STABLE_FROZEN_MAX_ENTRIES:
                raise GateFailure(
                    "stable bundle entry budget exceeded: "
                    f"{entry_count} > {STABLE_FROZEN_MAX_ENTRIES}"
                )
            parent = Path(directory)
            for name in list(directory_names):
                child = parent / name
                metadata = child.lstat()
                if _is_link_like(metadata):
                    if not allow_contained_links:
                        raise GateFailure(f"bundle directory is unsafe or non-directory: {child}")
                    relative = child.relative_to(root).as_posix()
                    hashes[f"bundle/{relative}"] = _safe_relative_link_sha256(
                        root,
                        child,
                    )
                    if len(hashes) > STABLE_FROZEN_MAX_FILES:
                        raise GateFailure(
                            "stable bundle file budget exceeded: "
                            f"{len(hashes)} > {STABLE_FROZEN_MAX_FILES}"
                        )
                    directory_names.remove(name)
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    raise GateFailure(f"bundle directory is unsafe or non-directory: {child}")
            for name in file_names:
                path = parent / name
                relative = path.relative_to(root).as_posix()
                metadata = path.lstat()
                if _is_link_like(metadata):
                    if not allow_contained_links:
                        raise GateFailure(f"bundle entry is a link: {path}")
                    hashes[f"bundle/{relative}"] = _safe_relative_link_sha256(
                        root,
                        path,
                    )
                else:
                    total_bytes += int(metadata.st_size)
                    if total_bytes > STABLE_FROZEN_MAX_BUNDLE_BYTES:
                        raise GateFailure(
                            "stable bundle byte budget exceeded: "
                            f"{total_bytes} > {STABLE_FROZEN_MAX_BUNDLE_BYTES}"
                        )
                    hashes[f"bundle/{relative}"] = _stable_file_sha256(path)
                if len(hashes) > STABLE_FROZEN_MAX_FILES:
                    raise GateFailure(
                        "stable bundle file budget exceeded: "
                        f"{len(hashes)} > {STABLE_FROZEN_MAX_FILES}"
                    )
    except OSError as exc:
        raise GateFailure(f"could not enumerate complete bundle {root}: {exc}") from exc
    return hashes


def _expected_package_data_hashes(
    repo: Path,
    *,
    bundle_package_root: str = "bundle/_internal/one_link",
) -> dict[str, str]:
    """Bind every source web/data asset into the frozen-bundle release gate."""
    from one_link.build_identity import EXPECTED_STABLE_PACKAGE_DATA

    package = repo.resolve() / "src" / "one_link"
    expected: dict[str, str] = {}
    discovered: set[str] = set()
    for subtree in ("web", "data"):
        source_root = package / subtree
        if not source_root.is_dir():
            raise GateFailure(f"required package-data directory is absent: {source_root}")
        for path in sorted(source_root.rglob("*")):
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise GateFailure(f"could not inspect package data {path}: {exc}") from exc
            if _is_link_like(metadata):
                raise GateFailure(f"source package data contains a link: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise GateFailure(f"source package data is not regular: {path}")
            relative = path.relative_to(package).as_posix()
            discovered.add(relative)
            expected[f"{bundle_package_root}/{relative}"] = _stable_file_sha256(path)
    contract = set(EXPECTED_STABLE_PACKAGE_DATA)
    if discovered != contract:
        raise GateFailure(
            "source package-data tree differs from explicit stable contract: "
            f"missing={sorted(contract - discovered)!r}, "
            f"unexpected={sorted(discovered - contract)!r}"
        )
    if not expected:
        raise GateFailure("source package-data manifest is empty")
    return expected


def validate_native_cdc_payload(artifact: Path) -> str:
    """Bind, load, and behavior-test the mandatory frozen CDC library."""
    from one_link.native_cdc import (
        native_library_name,
        native_platform_tag,
        validate_native_cdc_library,
    )

    executable = _find_artifact_executable(artifact)
    root, runtime_root, data_root, _layout = _artifact_layout(artifact, executable)
    relative = Path("one_link") / "native" / native_platform_tag()
    library = runtime_root / relative / native_library_name()
    sidecar = data_root / relative / (native_library_name() + ".sha256")
    inventory = _independent_bundle_hashes(artifact)

    library_suffix = "/" + native_library_name().casefold()
    sidecar_suffix = library_suffix + ".sha256"
    library_labels = sorted(
        label
        for label in inventory
        if label.casefold().endswith(library_suffix)
        and not label.casefold().endswith(sidecar_suffix)
    )
    sidecar_labels = sorted(
        label for label in inventory if label.casefold().endswith(sidecar_suffix)
    )
    expected_library_label = "bundle/" + library.relative_to(root).as_posix()
    expected_sidecar_label = "bundle/" + sidecar.relative_to(root).as_posix()
    # PyInstaller's .app layout maintains a MIRRORED dual tree: every member
    # under Contents/Frameworks is also reachable under Contents/Resources
    # (one side real, the other its safe-link twin), so the CDC library and
    # sidecar legitimately inventory at BOTH paths on macOS. The canonical
    # locations stay mandatory; only the exact mirror twin is additionally
    # tolerated. Onedir bundles have no mirror and keep the exact-set rule.
    def _mirror_label(label: str) -> str:
        if label.startswith("bundle/Contents/Frameworks/"):
            return label.replace("bundle/Contents/Frameworks/", "bundle/Contents/Resources/", 1)
        if label.startswith("bundle/Contents/Resources/"):
            return label.replace("bundle/Contents/Resources/", "bundle/Contents/Frameworks/", 1)
        return label

    allowed_library_labels = {expected_library_label, _mirror_label(expected_library_label)}
    allowed_sidecar_labels = {expected_sidecar_label, _mirror_label(expected_sidecar_label)}
    libraries_ok = (
        expected_library_label in library_labels
        and set(library_labels) <= allowed_library_labels
    )
    sidecars_ok = (
        expected_sidecar_label in sidecar_labels
        and set(sidecar_labels) <= allowed_sidecar_labels
    )
    if not (libraries_ok and sidecars_ok):
        raise GateFailure(
            "frozen native CDC payload must contain one library and one sidecar at "
            "the platform layout: "
            f"libraries={library_labels!r}, sidecars={sidecar_labels!r}, "
            f"expected={[expected_library_label, expected_sidecar_label]!r}"
        )
    try:
        line = sidecar.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise GateFailure(f"native CDC sidecar cannot be read: {sidecar}: {exc}") from exc
    digest = _stable_file_sha256(library)
    if line != f"{digest}  {library.name}\n":
        raise GateFailure("native CDC sidecar does not exactly bind the bundled library")
    if inventory[expected_library_label] != digest:
        raise GateFailure("bundle inventory does not bind the native CDC library digest")
    if inventory[expected_sidecar_label] != hashlib.sha256(line.encode("ascii")).hexdigest():
        raise GateFailure("bundle inventory does not bind the native CDC sidecar digest")
    try:
        validate_native_cdc_library(library)
    except Exception as exc:
        raise GateFailure(f"native CDC CDLL/ABI known-vector validation failed: {exc}") from exc
    return f"native CDC library hash and ABI known vector passed ({digest})"


def validate_version(artifact: Path, expected_version: str) -> str:
    exe = _find_artifact_executable(artifact)
    try:
        proc = _run_artifact_command(
            exe,
            ["--version"],
            timeout=DEFAULT_VERSION_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GateFailure(f"could not run {exe} --version: {e}") from e
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    out = stdout + ("\n" + stderr if stderr else "")
    if proc.returncode != 0:
        raise GateFailure(f"{exe} --version exited {proc.returncode}: {out.strip()}")
    expected_output = f"one-link, version {expected_version}"
    if stdout != expected_output or stderr:
        raise GateFailure(
            f"packaged version mismatch: expected {expected_output!r}, got {out.strip()!r}"
        )
    return f"artifact --version reports {expected_version}"


def validate_install_inventory(
    artifact: Path,
    expected_version: str,
    repo: Path | None = None,
) -> str:
    """Run the frozen bundle's complete, non-authenticating inventory gate."""
    from one_link.build_identity import (
        EXPECTED_STABLE_RUNTIME_MODULES,
        EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        STABLE_RUNTIME_FORBIDDEN_MODULES,
        STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256,
    )

    exe = _find_artifact_executable(artifact)
    independent_files = _independent_bundle_hashes(artifact)
    expected_root, _runtime_root, data_root, expected_inventory_mode = _artifact_layout(
        artifact, exe
    )
    try:
        proc = _run_artifact_command(
            exe,
            ["verify-this-install", "--inventory-only", "--json"],
            timeout=DEFAULT_INVENTORY_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateFailure(f"could not inventory packaged bundle {exe}: {exc}") from exc
    output = (proc.stdout or "").strip()
    diagnostic = ((proc.stderr or "") + "\n" + output[:500]).strip()
    if proc.returncode != 0:
        raise GateFailure(f"packaged install inventory exited {proc.returncode}: {diagnostic}")
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise GateFailure(f"packaged install inventory returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise GateFailure("packaged install inventory must return a JSON object")

    expected_root = expected_root.resolve()
    try:
        reported_root = Path(str(payload["inventory_root"])).resolve()
    except (KeyError, OSError) as exc:
        raise GateFailure("packaged install inventory omitted a valid inventory_root") from exc
    if reported_root != expected_root:
        raise GateFailure(f"packaged inventory root mismatch: {reported_root} != {expected_root}")
    if payload.get("inventory_mode") != expected_inventory_mode:
        raise GateFailure(
            "packaged inventory mode mismatch: "
            f"{payload.get('inventory_mode')!r} != {expected_inventory_mode!r}"
        )
    if payload.get("version") != expected_version:
        raise GateFailure(f"packaged inventory version mismatch: {payload.get('version')!r}")
    if payload.get("verification_status") != "inventory_only":
        raise GateFailure(
            f"packaged inventory did not complete: {payload.get('verification_status')!r}"
        )
    if payload.get("authenticity_verified") is not False:
        raise GateFailure("local packaged inventory must not claim authenticated provenance")
    if payload.get("missing") != [] or payload.get("unsafe_entries") != []:
        raise GateFailure(
            "packaged inventory reports missing or unsafe entries: "
            f"missing={payload.get('missing')!r}, "
            f"unsafe={payload.get('unsafe_entries')!r}"
        )

    runtime_modules = payload.get("runtime_modules")
    runtime_module_count = payload.get("runtime_module_count")
    runtime_manifest_digest = payload.get("runtime_module_manifest_sha256")
    missing_runtime_modules = payload.get("missing_runtime_modules")
    expected_runtime_modules = set(EXPECTED_STABLE_RUNTIME_MODULES)
    if not isinstance(runtime_modules, dict):
        raise GateFailure("packaged inventory omitted its runtime-module map")
    if runtime_module_count != len(EXPECTED_STABLE_RUNTIME_MODULES):
        raise GateFailure(
            "packaged runtime-module count mismatch: "
            f"{runtime_module_count!r} != {len(EXPECTED_STABLE_RUNTIME_MODULES)}"
        )
    if runtime_manifest_digest != EXPECTED_STABLE_RUNTIME_MODULES_SHA256:
        raise GateFailure("packaged runtime-module manifest digest does not match source contract")
    if set(runtime_modules) != expected_runtime_modules:
        omitted = sorted(expected_runtime_modules - set(runtime_modules))
        unexpected = sorted(set(runtime_modules) - expected_runtime_modules)
        raise GateFailure(
            "packaged runtime-module inventory keys differ from source contract: "
            f"omitted={omitted!r}, unexpected={unexpected!r}"
        )
    invalid_runtime_modules = sorted(
        module for module, status in runtime_modules.items() if status != "PRESENT"
    )
    if missing_runtime_modules != [] or invalid_runtime_modules:
        raise GateFailure(
            "packaged runtime modules are incomplete or externally shadowed: "
            f"reported={missing_runtime_modules!r}, invalid={invalid_runtime_modules!r}"
        )

    forbidden_runtime_modules = payload.get("forbidden_runtime_modules")
    forbidden_runtime_module_count = payload.get("forbidden_runtime_module_count")
    forbidden_manifest_digest = payload.get("forbidden_runtime_module_manifest_sha256")
    present_forbidden = payload.get("present_forbidden_runtime_modules")
    expected_forbidden_modules = set(STABLE_RUNTIME_FORBIDDEN_MODULES)
    if not isinstance(forbidden_runtime_modules, dict):
        raise GateFailure("packaged inventory omitted its forbidden-module map")
    if forbidden_runtime_module_count != len(STABLE_RUNTIME_FORBIDDEN_MODULES):
        raise GateFailure(
            "packaged forbidden-module count mismatch: "
            f"{forbidden_runtime_module_count!r} != "
            f"{len(STABLE_RUNTIME_FORBIDDEN_MODULES)}"
        )
    if forbidden_manifest_digest != STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256:
        raise GateFailure(
            "packaged forbidden-module manifest digest does not match source contract"
        )
    if set(forbidden_runtime_modules) != expected_forbidden_modules:
        raise GateFailure("packaged forbidden-module inventory keys differ from source contract")
    resolved_forbidden = sorted(
        module for module, status in forbidden_runtime_modules.items() if status != "ABSENT"
    )
    if present_forbidden != [] or resolved_forbidden:
        raise GateFailure(
            "packaged stable bundle resolves preview-only modules: "
            f"reported={present_forbidden!r}, resolved={resolved_forbidden!r}"
        )

    files = payload.get("files")
    file_count = payload.get("file_count")
    if not isinstance(files, dict) or not isinstance(file_count, int):
        raise GateFailure("packaged inventory omitted its file map or count")
    if file_count != len(files) or file_count <= 0:
        raise GateFailure(
            f"packaged inventory count is inconsistent: {file_count!r} vs {len(files)}"
        )
    if files != independent_files:
        reported_keys = set(files)
        independent_keys = set(independent_files)
        omitted = sorted(independent_keys - reported_keys)[:12]
        unexpected = sorted(reported_keys - independent_keys)[:12]
        mismatched = sorted(
            key for key in reported_keys & independent_keys if files[key] != independent_files[key]
        )[:12]
        raise GateFailure(
            "packaged executable's inventory differs from independent artifact walk: "
            f"omitted={omitted!r}, unexpected={unexpected!r}, "
            f"digest_mismatch={mismatched!r}"
        )
    source_repo = repo or _repo_root()
    bundle_package_root = "bundle/" + (data_root / "one_link").relative_to(expected_root).as_posix()
    source_data = _expected_package_data_hashes(
        source_repo,
        bundle_package_root=bundle_package_root,
    )
    actual_data_labels = {
        label
        for label in independent_files
        if label.startswith(f"{bundle_package_root}/web/")
        or label.startswith(f"{bundle_package_root}/data/")
    }
    missing_data = sorted(set(source_data) - set(independent_files))
    unexpected_data = sorted(actual_data_labels - set(source_data))
    stale_data = sorted(
        label
        for label, digest in source_data.items()
        if independent_files.get(label) not in {None, digest}
    )
    if missing_data or unexpected_data or stale_data:
        raise GateFailure(
            "packaged web/data payload differs from current source: "
            f"missing={missing_data!r}, unexpected={unexpected_data!r}, "
            f"stale={stale_data!r}"
        )
    expected_source_manifest = _expected_runtime_source_manifest(source_repo)
    expected_source_manifest_bytes = _canonical_manifest_bytes(expected_source_manifest)
    source_manifest_label = f"{bundle_package_root}/_build/runtime-source-manifest.json"
    source_manifest_path = expected_root / source_manifest_label.removeprefix("bundle/")
    try:
        packaged_source_manifest_bytes = source_manifest_path.read_bytes()
    except OSError as exc:
        raise GateFailure(
            f"packaged runtime source manifest is absent or unreadable: {exc}"
        ) from exc
    if packaged_source_manifest_bytes != expected_source_manifest_bytes:
        raise GateFailure("packaged runtime source manifest differs from current source contract")
    expected_source_manifest_digest = hashlib.sha256(expected_source_manifest_bytes).hexdigest()
    if independent_files.get(source_manifest_label) != expected_source_manifest_digest:
        raise GateFailure("independent bundle inventory did not bind the runtime source manifest")
    exe_label = f"bundle/{exe.resolve().relative_to(expected_root).as_posix()}"
    exe_digest = independent_files.get(exe_label)
    if exe_digest is None:
        raise GateFailure("independent bundle walk did not find packaged executable")
    if files.get(exe_label) != exe_digest:
        raise GateFailure("packaged executable is absent or duplicated in bundle inventory")
    if payload.get("frozen_binary_sha256") != exe_digest:
        raise GateFailure("packaged frozen-binary digest does not match executable bytes")
    rollup = payload.get("rollup_sha256")
    if (
        not isinstance(rollup, str)
        or len(rollup) != 64
        or any(character not in "0123456789abcdef" for character in rollup)
    ):
        raise GateFailure("packaged inventory returned an invalid rollup")
    return (
        f"complete frozen bundle inventory covers {file_count} files and "
        f"{runtime_module_count} stable runtime modules; independent walk and "
        f"{len(source_data)} source package-data files plus exact Python source "
        "manifest match"
    )


def validate_runtime_imports(artifact: Path, repo: Path | None = None) -> str:
    """Execute the frozen import gate for all stable and forbidden modules."""
    from one_link.build_identity import (
        EXPECTED_NATIVE_RUNTIME_SUBMODULES,
        EXPECTED_NATIVE_RUNTIME_SUBMODULES_SHA256,
        EXPECTED_STABLE_RUNTIME_MODULES,
        EXPECTED_STABLE_RUNTIME_MODULES_SHA256,
        STABLE_RUNTIME_FORBIDDEN_MODULES,
        STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256,
    )

    exe = _find_artifact_executable(artifact)
    _embedded_modules, embedded_code_digests = _embedded_python_archive(exe)
    expected_source_manifest = _expected_runtime_source_manifest(repo or _repo_root())
    expected_code_digests = {
        module: entry["normalized_code_sha256"]
        for module, entry in expected_source_manifest["modules"].items()
    }
    if embedded_code_digests != expected_code_digests:
        omitted = sorted(set(expected_code_digests) - set(embedded_code_digests))[:12]
        unexpected = sorted(set(embedded_code_digests) - set(expected_code_digests))[:12]
        mismatched = sorted(
            module
            for module in set(embedded_code_digests) & set(expected_code_digests)
            if embedded_code_digests[module] != expected_code_digests[module]
        )[:12]
        raise GateFailure(
            "direct nested-PYZ bytecode differs from current stable source: "
            f"omitted={omitted!r}, unexpected={unexpected!r}, "
            f"digest_mismatch={mismatched!r}"
        )
    try:
        proc = _run_artifact_command(
            exe,
            ["runtime-import-smoke", "--json"],
            timeout=DEFAULT_RUNTIME_IMPORT_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateFailure(f"could not run frozen runtime import smoke: {exc}") from exc
    output = (proc.stdout or "").strip()
    diagnostic = ((proc.stderr or "") + "\n" + output[:500]).strip()
    if proc.returncode != 0:
        raise GateFailure(f"frozen runtime import smoke exited {proc.returncode}: {diagnostic}")
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise GateFailure(f"frozen runtime import smoke returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise GateFailure("frozen runtime import smoke must return a JSON object")
    imports = payload.get("runtime_modules")
    forbidden = payload.get("forbidden_runtime_modules")
    if not isinstance(imports, dict) or set(imports) != set(EXPECTED_STABLE_RUNTIME_MODULES):
        raise GateFailure("frozen import-smoke runtime-module keys are incomplete")
    failed_imports = sorted(module for module, status in imports.items() if status != "IMPORTED")
    if payload.get("runtime_module_count") != len(EXPECTED_STABLE_RUNTIME_MODULES):
        raise GateFailure("frozen import-smoke runtime-module count mismatch")
    if payload.get("runtime_module_manifest_sha256") != EXPECTED_STABLE_RUNTIME_MODULES_SHA256:
        raise GateFailure("frozen import-smoke runtime-module digest mismatch")
    runtime_code_digests = payload.get("runtime_code_sha256")
    if runtime_code_digests != expected_code_digests:
        if isinstance(runtime_code_digests, dict):
            omitted = sorted(set(expected_code_digests) - set(runtime_code_digests))[:12]
            unexpected = sorted(set(runtime_code_digests) - set(expected_code_digests))[:12]
            mismatched = sorted(
                module
                for module in set(runtime_code_digests) & set(expected_code_digests)
                if runtime_code_digests[module] != expected_code_digests[module]
            )[:12]
        else:
            omitted = list(expected_code_digests)[:12]
            unexpected = []
            mismatched = []
        raise GateFailure(
            "frozen runtime bytecode differs from current source: "
            f"omitted={omitted!r}, unexpected={unexpected!r}, "
            f"digest_mismatch={mismatched!r}"
        )
    expected_source_manifest_sha256 = hashlib.sha256(
        _canonical_manifest_bytes(expected_source_manifest)
    ).hexdigest()
    if (
        payload.get("runtime_source_manifest_status") != "PRESENT"
        or payload.get("runtime_source_manifest_sha256") != expected_source_manifest_sha256
    ):
        raise GateFailure("frozen runtime source manifest is absent, invalid, or stale")
    if not isinstance(forbidden, dict) or set(forbidden) != set(STABLE_RUNTIME_FORBIDDEN_MODULES):
        raise GateFailure("frozen import-smoke forbidden-module keys are incomplete")
    present_forbidden = sorted(module for module, status in forbidden.items() if status != "ABSENT")
    if payload.get("forbidden_runtime_module_count") != len(STABLE_RUNTIME_FORBIDDEN_MODULES):
        raise GateFailure("frozen import-smoke forbidden-module count mismatch")
    if (
        payload.get("forbidden_runtime_module_manifest_sha256")
        != STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256
    ):
        raise GateFailure("frozen import-smoke forbidden-module digest mismatch")
    if (
        payload.get("verification_status") != "runtime_imports_ok"
        or payload.get("invalid_runtime_modules") != []
        or payload.get("present_forbidden_runtime_modules") != []
        or failed_imports
        or present_forbidden
    ):
        raise GateFailure(
            "frozen runtime imports are incomplete or preview modules resolved: "
            f"failed={failed_imports!r}, forbidden={present_forbidden!r}"
        )

    native_modules = payload.get("native_runtime_modules")
    if not isinstance(native_modules, dict) or set(native_modules) != set(
        EXPECTED_NATIVE_RUNTIME_SUBMODULES
    ):
        raise GateFailure("frozen native ABI module keys are incomplete")
    invalid_native = sorted(
        module for module, status in native_modules.items() if status != "IMPORTED"
    )
    if payload.get("native_runtime_module_count") != len(EXPECTED_NATIVE_RUNTIME_SUBMODULES):
        raise GateFailure("frozen native ABI module count mismatch")
    if (
        payload.get("native_runtime_module_manifest_sha256")
        != EXPECTED_NATIVE_RUNTIME_SUBMODULES_SHA256
    ):
        raise GateFailure("frozen native ABI module digest mismatch")
    expected_version = _load_source_version(repo or _repo_root())
    if payload.get("native_version") not in {
        expected_version,
        f"{expected_version}.0",
    }:
        raise GateFailure("frozen native extension version differs from core version")
    if (
        payload.get("native_package_status") != "IMPORTED"
        or payload.get("invalid_native_runtime_modules") != []
        or invalid_native
    ):
        raise GateFailure(f"frozen native extension ABI import failed: {invalid_native!r}")
    return (
        f"directly extracted and normalized {len(embedded_code_digests)} PYZ code objects; "
        f"frozen process imported {len(imports)} stable modules and proved "
        f"{len(forbidden)} preview modules absent; imported "
        f"{len(native_modules)} native ABI modules with independently proven source parity"
    )


def validate_runtime_features(artifact: Path) -> str:
    """Execute representative, side-effect-free operations in the frozen app."""
    exe = _find_artifact_executable(artifact)
    try:
        proc = _run_artifact_command(
            exe,
            ["runtime-feature-smoke", "--json"],
            timeout=DEFAULT_RUNTIME_FEATURE_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateFailure(f"could not run frozen runtime feature smoke: {exc}") from exc
    output = (proc.stdout or "").strip()
    diagnostic = ((proc.stderr or "") + "\n" + output[:500]).strip()
    if proc.returncode != 0:
        raise GateFailure(f"frozen runtime feature smoke exited {proc.returncode}: {diagnostic}")
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise GateFailure(f"frozen runtime feature smoke returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise GateFailure("frozen runtime feature smoke must return a JSON object")
    features = payload.get("features")
    if (
        not isinstance(features, dict)
        or set(features) != set(RUNTIME_FEATURE_EXPECTED_STATUSES)
        or any(
            features[name]
            not in (
                {RUNTIME_FEATURE_EXPECTED_STATUSES[name]}
                | RUNTIME_FEATURE_ALLOWED_ENVIRONMENT_STATUSES.get(name, set())
            )
            for name in RUNTIME_FEATURE_EXPECTED_STATUSES
        )
    ):
        raise GateFailure(
            "frozen runtime feature statuses differ from the independent release contract: "
            f"{features!r}"
        )
    if payload.get("feature_count") != len(RUNTIME_FEATURE_EXPECTED_STATUSES):
        raise GateFailure("frozen runtime feature count mismatch")
    if payload.get("feature_errors") != {}:
        raise GateFailure("frozen runtime feature smoke reported errors")
    if payload.get("numpy_status") != "ABSENT":
        raise GateFailure("stable frozen runtime resolved forbidden NumPy payload")
    if payload.get("verification_status") != "runtime_features_ok":
        raise GateFailure("frozen runtime feature verification did not pass")
    if payload.get("side_effect_policy") != (
        "no_external_network_no_ui_no_keychain_access_isolated_temporary_io_only"
    ):
        raise GateFailure("frozen runtime feature smoke side-effect policy mismatch")
    return (
        f"frozen process completed {len(features)} representative dependency operations "
        "with no external network/UI/keychain access and temporary I/O only; NumPy absent"
    )


def validate_frozen_e2e(artifact: Path) -> str:
    """Boot two frozen daemons and prove authenticated exactly-once transfer."""
    from one_link import control_ipc

    executable = _find_artifact_executable(artifact).resolve()

    # First launch of a FRESHLY EXTRACTED bundle is the slowest start this
    # binary will ever do: macOS verifies the signature of every Mach-O in the
    # tree on first execution (hundreds of dylibs, cold page cache, temp
    # volume), and Windows Defender scans the same way. The daemon in the
    # failing run had already logged its launch and established its seed --
    # it simply had not reached port publication inside 30s. The contract is
    # THAT IT STARTS, not how fast a cold shared runner gets there.
    def _wait_file(path: Path, *, timeout: float = 180.0) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = path.read_text(encoding="utf-8").strip()
            except OSError:
                value = ""
            if value:
                return value
            time.sleep(0.05)
        raise GateFailure(f"frozen daemon did not create {path.name} within {timeout}s")

    def _wait_control_secret(data_root: Path, *, timeout: float = 60.0) -> str:
        """Return the daemon's published control secret once it is readable."""
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                value = control_ipc.read_control_secret(data_root)
            except Exception as exc:  # not yet written / mid-write
                last_error = exc
                value = None
            if isinstance(value, str) and value.strip():
                return value
            time.sleep(0.1)
        raise GateFailure(
            f"frozen daemon never published a readable control secret: {last_error}"
        )

    def _control(port: int, secret: str, **request: Any) -> dict[str, Any]:
        last_error: Exception | None = None
        for delay in (0.0, 0.1, 0.4, 1.0):
            if delay:
                time.sleep(delay)
            try:
                result = control_ipc.request_control(
                    port,
                    request,
                    timeout=180.0 if request.get("cmd") == "send_file" else 15.0,
                    secret=secret,
                )
                if not isinstance(result, dict):
                    raise RuntimeError("control response is not an object")
                return result
            except (OSError, RuntimeError) as exc:
                last_error = exc
        raise GateFailure(f"authenticated control request failed: {last_error}")

    def _http_json(
        port: int,
        path: str,
        *,
        token: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        status, _headers, raw = _request(
            f"http://127.0.0.1:{port}{path}",
            token=token,
            method="POST" if body is not None else "GET",
            body=body,
        )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateFailure(f"frozen daemon {path} returned invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise GateFailure(f"frozen daemon {path} did not return an object")
        return status, payload

    with tempfile.TemporaryDirectory(prefix="one-link-frozen-e2e-") as raw_root:
        root = Path(raw_root)
        cohort = f"_olp{uuid.uuid4().hex[:8]}._tcp.local."
        processes: list[tuple[subprocess.Popen[bytes], Any, Path, int | None, str | None]] = []
        handles: list[dict[str, Any]] = []
        failure: Exception | None = None
        try:
            for label in ("A", "B"):
                home = root / label
                home.mkdir()
                env = _artifact_subprocess_environment(home / "environment")
                env.update(
                    {
                        "ONE_LINK_ALLOW_SAME_HOST_PEERS": "1",
                        "ONE_LINK_BIND_HOST": "127.0.0.1",
                        "ONE_LINK_DISABLE_REVEAL": "1",
                        "ONE_LINK_HOME": str(home),
                        "ONE_LINK_MDNS_SERVICE_TYPE": cohort,
                        "ONE_LINK_REQUIRE_FILE_ACCEPT": "0",
                    }
                )
                log_path = root / f"{label}.log"
                log_handle = log_path.open("wb")
                process = subprocess.Popen(
                    [str(executable), "daemon", "--no-tray", "--no-open"],
                    cwd=home,
                    env=env,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    creationflags=(
                        subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                    ),
                )
                processes.append((process, log_handle, log_path, None, None))
                control_port = int(_wait_file(home / "data" / "control.port"))
                server_port = int(_wait_file(home / "data" / "server.port"))
                token = _wait_file(home / "data" / "ui.token")
                # Read the control secret LAST, and only after the daemon has
                # published its full runtime set. It used to be read the
                # instant control.port appeared -- but the port is published
                # early in startup, and this ONE value is reused for every
                # later request. On a host where startup pauses after that
                # point (macOS spends its keychain deadline there), the read
                # landed before the secret was final and every authenticated
                # control request then timed out against a healthy daemon.
                secret = _wait_control_secret(home / "data")
                info = _control(control_port, secret, cmd="peers")
                if not info.get("ok") or not isinstance(info.get("me"), dict):
                    raise GateFailure(f"frozen daemon {label} control plane is unhealthy: {info!r}")
                processes[-1] = (process, log_handle, log_path, control_port, secret)
                handles.append(
                    {
                        "home": home,
                        "control_port": control_port,
                        "secret": secret,
                        "server_port": server_port,
                        "token": token,
                        "me": info["me"],
                    }
                )

            for handle in handles:
                server_port = int(handle["server_port"])
                status, health = _http_json(server_port, "/api/debug/health")
                if status != 200 or not isinstance(health.get("checks"), list):
                    raise GateFailure(f"frozen daemon health surface failed: {status}, {health!r}")
                required_health = {"state_db", "discovery", "peer_server"}
                rows = {
                    row.get("name"): row
                    for row in health["checks"]
                    if isinstance(row, dict) and isinstance(row.get("name"), str)
                }
                failed_health = sorted(
                    name for name in required_health if not rows.get(name, {}).get("ok")
                )
                if failed_health:
                    raise GateFailure(f"frozen daemon core health checks failed: {failed_health!r}")
                unauthorized, _ = _http_json(server_port, "/api/peers")
                if unauthorized not in {401, 403}:
                    raise GateFailure("frozen daemon /api/peers is not auth-gated")
                authorized, peers_payload = _http_json(
                    server_port, "/api/peers", token=str(handle["token"])
                )
                if authorized != 200 or not isinstance(peers_payload.get("peers"), list):
                    raise GateFailure("authenticated frozen daemon /api/peers failed")
                status, _headers, ui = _request(f"http://127.0.0.1:{server_port}/")
                if (
                    status != 200
                    or b"<title>One Link</title>" not in ui
                    or b'<div class="app">' not in ui
                ):
                    raise GateFailure("frozen daemon did not serve the current desktop UI")

            a, b = handles
            deadline = time.monotonic() + 35.0
            while time.monotonic() < deadline:
                a_peers = _control(a["control_port"], a["secret"], cmd="peers")
                b_peers = _control(b["control_port"], b["secret"], cmd="peers")
                a_sees_b = any(
                    peer.get("short_id") == b["me"]["short_id"]
                    for peer in a_peers.get("peers", [])
                )
                b_sees_a = any(
                    peer.get("short_id") == a["me"]["short_id"]
                    for peer in b_peers.get("peers", [])
                )
                if a_sees_b and b_sees_a:
                    break
                time.sleep(0.2)
            else:
                raise GateFailure("two frozen daemons did not converge through private mDNS")

            for source, peer in ((a, b), (b, a)):
                status, pinned = _http_json(
                    source["server_port"],
                    f"/api/peers/{peer['me']['fingerprint']}/trust",
                    token=source["token"],
                    body={"trust": "pinned"},
                )
                if status != 200 or not pinned.get("ok"):
                    raise GateFailure(f"authenticated peer pin failed: {status}, {pinned!r}")

            sample = root / "multichunk-release-probe.bin"
            expected_size = 5 * 1024 * 1024 + 137
            digest = hashlib.sha256()
            pattern = bytes(range(256)) * 4096
            remaining = expected_size
            with sample.open("wb") as stream:
                while remaining:
                    block = pattern[: min(len(pattern), remaining)]
                    stream.write(block)
                    digest.update(block)
                    remaining -= len(block)
            expected_digest = digest.hexdigest()
            sent = _control(
                a["control_port"],
                a["secret"],
                cmd="send_file",
                peer=b["me"]["short_id"],
                path=str(sample),
            )
            result = sent.get("result") if sent.get("ok") else None
            if not isinstance(result, dict) or int(result.get("chunks") or 0) < 2:
                raise GateFailure(f"frozen multichunk send failed: {sent!r}")
            blob = str(result.get("blob") or "")
            if not blob:
                raise GateFailure("frozen multichunk send omitted its blob identity")

            inbox = b["home"] / "data" / "inbox"
            deadline = time.monotonic() + 120.0
            matching: list[Path] = []
            while time.monotonic() < deadline:
                matching = []
                if inbox.is_dir():
                    for candidate in inbox.iterdir():
                        if not candidate.is_file() or candidate.stat().st_size != expected_size:
                            continue
                        if _stable_file_sha256(candidate) == expected_digest:
                            matching.append(candidate)
                if len(matching) == 1:
                    status, transfers = _http_json(
                        b["server_port"], "/api/transfers?limit=100", token=b["token"]
                    )
                    rows = transfers.get("transfers") if status == 200 else None
                    ledger_matches = [
                        row
                        for row in rows or []
                        if isinstance(row, dict)
                        and row.get("direction") == "in"
                        and row.get("blob_hash") == blob
                        and row.get("status") == "complete"
                    ]
                    if len(ledger_matches) == 1:
                        break
                time.sleep(0.1)
            else:
                raise GateFailure(
                    "frozen transfer did not commit exactly one digest-matching file and ledger row"
                )
            if len(matching) != 1:
                raise GateFailure(f"frozen transfer materialized duplicate inbox files: {matching!r}")
            # Require a short quiescent interval after the first successful
            # observation.  A duplicate materialization/ledger append racing
            # just behind the original must not make an exactly-once gate pass.
            time.sleep(1.0)
            settled_matching = [
                candidate
                for candidate in inbox.iterdir()
                if candidate.is_file()
                and candidate.stat().st_size == expected_size
                and _stable_file_sha256(candidate) == expected_digest
            ]
            settled_status, settled_transfers = _http_json(
                b["server_port"], "/api/transfers?limit=100", token=b["token"]
            )
            settled_rows = (
                settled_transfers.get("transfers") if settled_status == 200 else None
            )
            settled_ledger_matches = [
                row
                for row in settled_rows or []
                if isinstance(row, dict)
                and row.get("direction") == "in"
                and row.get("blob_hash") == blob
                and row.get("status") == "complete"
            ]
            if len(settled_matching) != 1 or len(settled_ledger_matches) != 1:
                raise GateFailure(
                    "frozen transfer was not exactly-once after quiescence: "
                    f"files={settled_matching!r}, ledger={settled_ledger_matches!r}"
                )

            # The authenticated shutdown command must let both daemons flush
            # state and unregister discovery without a kill signal.
            # Ask BOTH daemons to stop BEFORE waiting on either. Stopping one
            # at a time left the survivor actively dialing the daemon that was
            # tearing down -- the CI logs show the reconnect churn (connected /
            # connection reset / disconnected, repeatedly) -- so the first
            # daemon kept servicing new peer work instead of finishing its
            # exit. Quiescing the swarm first is what the shutdown contract
            # actually means for a peer-to-peer pair.
            for _process, _log, _path, port, secret in processes:
                assert port is not None and secret is not None
                response = _control(port, secret, cmd="shutdown")
                if response != {"ok": True, "stopping": True}:
                    raise GateFailure(f"frozen daemon rejected graceful shutdown: {response!r}")
            for process, _log, _path, port, secret in processes:
                try:
                    # A frozen daemon that has just completed a real transfer
                    # unwinds a large graph on exit -- cover-traffic
                    # scheduler, discovery unregistration, WAL flush, index
                    # persistence -- and the CI logs show it doing exactly
                    # that at the old 20-second mark on shared runners. The
                    # contract is CLEAN EXIT WITHOUT A KILL SIGNAL, not
                    # exit speed; give the orderly path room.
                    return_code = process.wait(timeout=90.0)
                except subprocess.TimeoutExpired as exc:
                    raise GateFailure("frozen daemon did not exit after authenticated shutdown") from exc
                if return_code != 0:
                    raise GateFailure(f"frozen daemon graceful exit returned {return_code}")
        except Exception as exc:
            failure = exc
        finally:
            for process, log_handle, _log_path, port, secret in processes:
                try:
                    if process.poll() is None:
                        if port is not None and secret is not None:
                            try:
                                _control(port, secret, cmd="shutdown")
                                process.wait(timeout=8.0)
                            except Exception:
                                pass
                        if process.poll() is None:
                            try:
                                process.terminate()
                                process.wait(timeout=5.0)
                            except (OSError, subprocess.TimeoutExpired):
                                if process.poll() is None:
                                    process.kill()
                                    process.wait(timeout=5.0)
                finally:
                    log_handle.close()
        if failure is not None:
            # Emit the tails LINE BY LINE. Embedding them in the exception
            # produced one enormous log line, and CI truncates a single line
            # at ~500 characters -- so the daemon's last words, which are the
            # entire diagnostic value, were unreachable exactly when a
            # platform failed for an unknown reason.
            # Preserve the COMPLETE logs as a job artifact. Tails answer
            # "which line was last"; they cannot answer "what happened during
            # the 62 seconds after startup finished", which is exactly the
            # question a silent daemon poses. The copy lands in the workspace
            # so the workflow can upload it on failure.
            preserved = Path.cwd() / "frozen-e2e-logs"
            with contextlib.suppress(OSError):
                preserved.mkdir(parents=True, exist_ok=True)
            for index, (_process, _handle, log_path, _port, _secret) in enumerate(processes):
                with contextlib.suppress(OSError):
                    shutil.copy2(log_path, preserved / f"daemon-{index}-{log_path.name}")
                print(f"--- frozen daemon {index} log tail: {log_path}", flush=True)
                try:
                    tail = log_path.read_text(encoding="utf-8", errors="replace")[-8000:]
                except OSError:
                    print("    <missing log>", flush=True)
                    continue
                for line in tail.splitlines()[-80:]:
                    print(f"    {line}", flush=True)
            raise GateFailure(
                f"frozen two-daemon E2E failed: {failure} "
                "(per-daemon log tails printed above)"
            ) from failure
        for index, (_process, _handle, log_path, _port, _secret) in enumerate(processes):
            text = log_path.read_text(encoding="utf-8", errors="replace")
            if "Traceback (most recent call last)" not in text and " CRITICAL " not in text:
                continue
            # This check lives AFTER the E2E's own failure handling, so it
            # used to raise with a path and nothing else -- and the path
            # points inside a temp dir that dies with the job. A gate that
            # says "something logged a traceback" without saying WHICH one
            # costs a whole release cycle to re-provoke, so preserve the
            # logs and quote the offending block here.
            preserved = Path.cwd() / "frozen-e2e-logs"
            with contextlib.suppress(OSError):
                preserved.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                shutil.copy2(log_path, preserved / f"daemon-{index}-{log_path.name}")
            lines = text.splitlines()
            excerpt: list[str] = []
            for n, line in enumerate(lines):
                if "Traceback (most recent call last)" in line or " CRITICAL " in line:
                    # The line BEFORE a traceback names what failed; the
                    # lines after are the frames.
                    excerpt = lines[max(0, n - 1):n + 12]
                    break
            print(f"--- frozen daemon {index} logged a traceback: {log_path}", flush=True)
            for line in excerpt:
                print(f"    {line}", flush=True)
            first = excerpt[0].strip() if excerpt else "<unavailable>"
            raise GateFailure(
                "frozen daemon logged a traceback/critical failure: "
                f"{log_path} -- first offending record: {first[:300]} "
                "(full block printed above; complete logs preserved)"
            )
    return (
        "two isolated frozen daemons passed authenticated health/UI, mutual pinning, "
        "real multichunk digest/exactly-once transfer, and graceful shutdown"
    )


def validate_release_archive(
    release_archive: Path,
    source_artifact: Path,
    *,
    repo: Path,
    expected_version: str,
    run_frozen_e2e: bool,
) -> str:
    """Revalidate, safely extract, and execute the final downloadable ZIP."""
    packager_path = Path(__file__).resolve().with_name("package_standalone_bundle.py")
    spec = importlib.util.spec_from_file_location(
        "_one_link_release_bundle_validator", packager_path
    )
    if spec is None or spec.loader is None:
        raise GateFailure("could not load standalone bundle manifest validator")
    packager = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = packager
    try:
        spec.loader.exec_module(packager)
    except Exception as exc:
        raise GateFailure(f"could not load standalone bundle manifest validator: {exc}") from exc

    source_executable = _find_artifact_executable(source_artifact)
    source_root, _runtime, _data, _layout = _artifact_layout(
        source_artifact, source_executable
    )
    try:
        executable_relative = source_executable.relative_to(source_root).as_posix()
    except ValueError as exc:
        raise GateFailure("source artifact executable is outside its inventory root") from exc
    # The archive root mirrors the source bundle: a macOS .app ships as
    # "one-link.app/..." so the extracted download IS an application (its
    # bootloader recognizes a bundle by that path shape); every other
    # platform ships "one-link/...".
    archive_root = "one-link.app" if source_root.name.lower().endswith(".app") else "one-link"
    expected_member = f"{archive_root}/{executable_relative}"
    # Extracted members carry their archived permission bits, and a DLL
    # extracted read-only cannot be deleted on Windows -- TemporaryDirectory's
    # cleanup then raises PermissionError(WinError 5) AFTER every validation
    # has already passed, failing the release on housekeeping. Restore write
    # permission on the way out, then remove.
    def _force_writable(func, path, _exc):
        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            func(path)

    raw_root = tempfile.mkdtemp(prefix="one-link-release-zip-")
    try:
        extraction = Path(raw_root)
        snapshot = extraction / "candidate.snapshot.zip"
        # Snapshot the untrusted release input once while binding the opened
        # descriptor to both pre/post path identities. All subsequent manifest
        # validation and extraction use this private immutable copy, closing the
        # path-swap window between two ZipFile opens.
        try:
            before = release_archive.lstat()
            if _is_link_like(before) or not stat.S_ISREG(before.st_mode):
                raise GateFailure("release ZIP must be a physical regular file")
            before_identity = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            snapshot_digest = hashlib.sha256()
            with release_archive.open("rb") as source, snapshot.open("xb") as output:
                opened = os.fstat(source.fileno())
                opened_identity = (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                )
                if opened_identity != before_identity:
                    raise GateFailure("release ZIP changed before snapshotting")
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    snapshot_digest.update(block)
                    output.write(block)
                after_open = os.fstat(source.fileno())
            after_path = release_archive.lstat()
            after_identities = (
                (
                    after_open.st_dev,
                    after_open.st_ino,
                    after_open.st_size,
                    after_open.st_mtime_ns,
                ),
                (
                    after_path.st_dev,
                    after_path.st_ino,
                    after_path.st_size,
                    after_path.st_mtime_ns,
                ),
            )
            if any(identity != before_identity for identity in after_identities):
                raise GateFailure("release ZIP changed while snapshotting")
            if os.name != "nt":
                snapshot.chmod(stat.S_IREAD)
        except GateFailure:
            raise
        except OSError as exc:
            raise GateFailure(f"release ZIP could not be snapshotted safely: {exc}") from exc

        try:
            packager.validate_bundle_archive(
                snapshot,
                expected_executable=expected_member,
            )
        except Exception as exc:
            raise GateFailure(f"release ZIP manifest/hash validation failed: {exc}") from exc
        try:
            with zipfile.ZipFile(snapshot, "r") as archive:
                infos = archive.infolist()
                symlink_names = {
                    info.filename.rstrip("/")
                    for info in infos
                    if stat.S_ISLNK(info.external_attr >> 16)
                }
                all_names = {info.filename.rstrip("/") for info in infos}
                # Link targets for chain resolution, read from the archive the
                # manifest verification above already bound digest-for-digest.
                symlink_targets: dict[str, str] = {}
                for info in infos:
                    if not stat.S_ISLNK(info.external_attr >> 16):
                        continue
                    try:
                        symlink_targets[info.filename.rstrip("/")] = archive.read(
                            info
                        ).decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise GateFailure(
                            f"release ZIP symlink is not UTF-8: {info.filename!r}"
                        ) from exc
                for name in all_names:
                    parts = PurePosixPath(name).parts
                    prefixes = {"/".join(parts[:index]) for index in range(1, len(parts))}
                    if prefixes & symlink_names:
                        raise GateFailure(
                            f"release ZIP member is nested under a symlink: {name!r}"
                        )

                for info in infos:
                    name = info.filename
                    try:
                        packager._validate_portable_archive_path(name, archive_root)
                    except Exception as exc:
                        raise GateFailure(
                            f"release ZIP member path is unsafe: {name!r}: {exc}"
                        ) from exc
                    if info.is_dir():
                        raise GateFailure(
                            f"release ZIP contains an explicit directory member: {name!r}"
                        )
                    destination = extraction.joinpath(*PurePosixPath(name).parts)
                    try:
                        destination.resolve(strict=False).relative_to(extraction.resolve(strict=True))
                    except (OSError, ValueError) as exc:
                        raise GateFailure(
                            f"release ZIP extraction destination escapes: {name!r}"
                        ) from exc
                    # Containment and portable-name validation above happen
                    # before the first mutating mkdir for this member.
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    mode = info.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raw_target = archive.read(info)
                        try:
                            target = raw_target.decode("utf-8")
                        except UnicodeDecodeError as exc:
                            raise GateFailure(f"release ZIP symlink is not UTF-8: {name!r}") from exc
                        target_path = PurePosixPath(target.replace("\\", "/"))
                        windows_target = PureWindowsPath(target)
                        if (
                            target_path.is_absolute()
                            or windows_target.is_absolute()
                            or windows_target.drive
                            or windows_target.root
                        ):
                            raise GateFailure(f"release ZIP symlink target is absolute: {name!r}")
                        # Resolve through the PACKAGER's chain resolver, not a
                        # local copy: this extraction path had its own one-hop
                        # implementation, so teaching the packager about
                        # Apple's framework layout (Python ->
                        # Versions/Current/Python, Versions/Current ->
                        # Versions/3.x) fixed one gate and left this one
                        # refusing the same real bundle. One resolver, both
                        # callers -- escapes, cycles and absent targets stay
                        # refused exactly as before.
                        try:
                            relocated_name = packager._resolve_archive_link(
                                PurePosixPath(name).parent,
                                target_path,
                                symlink_targets,
                                member=name,
                                archive_root=archive_root,
                            )
                        except packager.BundleError as exc:
                            raise GateFailure(
                                f"release ZIP symlink escapes bundle: {name!r}: {exc}"
                            ) from exc
                        if not (
                            relocated_name in all_names
                            or any(member.startswith(relocated_name + "/") for member in all_names)
                        ):
                            raise GateFailure(f"release ZIP symlink target is absent: {name!r}")
                        destination.symlink_to(target)
                        continue
                    with archive.open(info, "r") as source, destination.open("xb") as output:
                        for block in iter(lambda: source.read(1024 * 1024), b""):
                            output.write(block)
                    if os.name != "nt":
                        destination.chmod(mode & 0o777)
        except GateFailure:
            raise
        except (OSError, zipfile.BadZipFile) as exc:
            raise GateFailure(f"release ZIP safe extraction failed: {exc}") from exc
        if _stable_file_sha256(snapshot) != snapshot_digest.hexdigest():
            raise GateFailure("private release ZIP snapshot changed during validation/extraction")

        extracted_artifact = extraction / archive_root
        original_hashes = _independent_bundle_hashes(source_artifact)
        extracted_hashes = _independent_bundle_hashes(extracted_artifact)
        extracted_hashes.pop("bundle/BUNDLE_SHA256SUMS", None)
        if extracted_hashes != original_hashes:
            raise GateFailure("safely extracted release ZIP differs from the validated bundle")

        # Execute all artifact gates from the extracted download, not merely
        # the pre-archive build tree.  This catches lost execute bits, malformed
        # symlinks, path/case transformations, and a stale ZIP input.
        validate_stable_bundle_contents(extracted_artifact)
        validate_native_cdc_payload(extracted_artifact)
        validate_version(extracted_artifact, expected_version)
        validate_install_inventory(extracted_artifact, expected_version, repo=repo)
        validate_runtime_imports(extracted_artifact, repo)
        validate_runtime_features(extracted_artifact)
        if run_frozen_e2e:
            validate_frozen_e2e(extracted_artifact)
    finally:
        shutil.rmtree(raw_root, onerror=_force_writable)
    return (
        "final release ZIP manifest and every member digest revalidated; safely extracted "
        + ("and completed frozen two-daemon E2E" if run_frozen_e2e else "and executed")
    )


def _request(
    url: str,
    *,
    token: str | None = None,
    cacert: Path | None = None,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise GateFailure(f"live probe URL must use http or https: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise GateFailure("live probe URL must not contain userinfo")
    if token and parsed.scheme == "http":
        hostname = parsed.hostname.rstrip(".").lower()
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname == "localhost"
        if not loopback:
            raise GateFailure("owner tokens may only use loopback HTTP or authenticated HTTPS")
    data = None
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    ctx = None
    if parsed.scheme == "https":
        # A release gate must never turn an owner-token probe into a TLS
        # downgrade.  Public endpoints use the platform trust store; local or
        # private-CA packaged daemons must provide their exact CA explicitly.
        # Refusing an unknown certificate is actionable evidence, while
        # CERT_NONE would make a successful probe meaningless and could expose
        # the bearer to a machine-in-the-middle.
        ctx = ssl.create_default_context(
            cafile=str(cacert) if cacert is not None else None,
        )
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        # Scheme/authority/userinfo are validated immediately above.
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:  # nosec B310
            return (
                int(resp.status),
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read(),
            )
    except urllib.error.HTTPError as e:
        return (
            int(e.code),
            {k.lower(): v for k, v in e.headers.items()},
            e.read(),
        )


def validate_peer_headers(base_url: str, cacert: Path | None) -> str:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "peer")
    status, headers, body = _request(url, cacert=cacert)
    if status != 200:
        raise GateFailure(f"GET /peer returned HTTP {status}: {body[:120]!r}")
    for name, needles in REQUIRED_PEER_HEADERS.items():
        value = headers.get(name, "")
        if not all(n in value for n in needles):
            raise GateFailure(f"/peer header {name!r} invalid: {value!r}")
    peer_markers = (
        b"<title>One Link",
        b"daemon-global-search-input",
        b"setup_device_invite",
        b"cert-authed reconnect",
    )
    missing = [m.decode("ascii", "ignore") for m in peer_markers if m not in body]
    if missing:
        raise GateFailure(
            "/peer response does not look like current peer.html; "
            "missing markers: " + ", ".join(missing)
        )
    return "/peer has ETag and no-cache/must-revalidate headers"


def validate_recovery_routes(base_url: str, token: str | None, cacert: Path | None) -> str:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "api/v1/recovery/status")
    status, _headers, body = _request(url, token=token, cacert=cacert)
    if not token and status in (401, 403):
        return "recovery route exists and is auth-gated"
    if status != 200:
        raise GateFailure(f"recovery status returned HTTP {status}: {body[:160]!r}")
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as e:
        raise GateFailure(f"recovery status returned invalid JSON: {e}") from e
    for key in ("phrase", "social", "backup", "any_ready"):
        if key not in payload:
            raise GateFailure(f"recovery status missing key {key!r}")
    return "recovery status route returns all recovery tracks"


def validate_alpn(base_url: str, cacert: Path | None) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "https":
        return "ALPN probe skipped for non-HTTPS base URL"
    host = parsed.hostname
    if not host:
        raise GateFailure(f"invalid HTTPS base URL: {base_url!r}")
    port = parsed.port or 443
    ctx = ssl.create_default_context(
        cafile=str(cacert) if cacert is not None else None,
    )
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            selected = ssock.selected_alpn_protocol()
    if selected != "http/1.1":
        raise GateFailure(f"expected ALPN http/1.1, got {selected!r}")
    return "HTTPS ALPN selects http/1.1"


def validate_cert_chain_with_openssl(base_url: str, cacert: Path | None) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "https":
        return "cert-chain probe skipped for non-HTTPS base URL"
    host = parsed.hostname
    if not host:
        raise GateFailure(f"invalid HTTPS base URL: {base_url!r}")
    port = parsed.port or 443
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-showcerts",
        "-alpn",
        "h2,http/1.1",
    ]
    if cacert is not None:
        cmd.extend(["-CAfile", str(cacert)])
    try:
        proc = subprocess.run(
            cmd,
            input="",
            capture_output=True,
            text=True,
            timeout=12,
        )
    except FileNotFoundError:
        return _validate_cert_chain_with_python_ssl(host, port, cacert)
    except subprocess.TimeoutExpired as e:
        raise GateFailure("openssl s_client timed out") from e
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    cert_count = out.count("-----BEGIN CERTIFICATE-----")
    if cert_count < 2:
        raise GateFailure(f"expected 2+ certs in TLS chain, got {cert_count}")
    if "ALPN protocol: http/1.1" not in out and "ALPN protocol: h2" in out:
        raise GateFailure("openssl negotiated h2; Safari will hang")
    return f"TLS serves a chain with {cert_count} certificates"


def _validate_cert_chain_with_python_ssl(
    host: str,
    port: int,
    cacert: Path | None,
) -> str:
    ctx = ssl.create_default_context(
        cafile=str(cacert) if cacert is not None else None,
    )
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            selected = ssock.selected_alpn_protocol()
            chain_fn = getattr(ssock, "get_verified_chain", None) or getattr(
                ssock, "get_unverified_chain", None
            )
            chain = chain_fn() if chain_fn is not None else []
    if selected == "h2":
        raise GateFailure("Python ssl negotiated h2; Safari will hang")
    if len(chain) < 2:
        raise GateFailure(f"expected 2+ certs in TLS chain, got {len(chain)}")
    return f"TLS serves a chain with {len(chain)} certificates"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Validate a packaged One Link artifact against current source.",
    )
    p.add_argument(
        "--artifact",
        type=Path,
        required=True,
        help="complete packaged onedir or macOS .app bundle",
    )
    p.add_argument(
        "--release-archive",
        type=Path,
        default=None,
        help="final standalone ZIP to manifest-verify, safely extract, and execute",
    )
    p.add_argument(
        "--frozen-e2e",
        action="store_true",
        help="boot two isolated frozen daemons and require a real multichunk transfer",
    )
    p.add_argument(
        "--spec",
        type=Path,
        default=Path("build/one-link.spec"),
        help="generated PyInstaller spec to inspect",
    )
    p.add_argument(
        "--repo", type=Path, default=_repo_root(), help="repo root containing src/one_link"
    )
    p.add_argument("--skip-version", action="store_true", help="skip running artifact --version")
    p.add_argument(
        "--skip-runtime-inventory",
        action="store_true",
        help="skip executing the packaged complete-inventory smoke (static tests only)",
    )
    p.add_argument(
        "--allow-native-missing",
        action="store_true",
        help="always rejected: complete native runtime is mandatory for stable standalone artifacts.",
    )
    p.add_argument(
        "--base-url", default="", help="optional live packaged daemon URL, e.g. https://LAN:7118"
    )
    p.add_argument(
        "--token",
        default=os.environ.get("ONE_LINK_UI_TOKEN", ""),
        help="optional UI bearer token for guarded live routes",
    )
    p.add_argument(
        "--cacert", type=Path, default=None, help="optional root CA for live HTTPS probes"
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    checks: list[str] = []
    try:
        if args.allow_native_missing:
            raise GateFailure(
                "stable standalone validation cannot waive the mandatory native runtime"
            )
        source_version = _load_source_version(args.repo)
        checks.extend(validate_spec(args.spec))
        checks.append(validate_stable_bundle_contents(args.artifact))
        checks.append(validate_native_cdc_payload(args.artifact))
        if not args.skip_version:
            checks.append(validate_version(args.artifact, source_version))
        if not args.skip_runtime_inventory:
            checks.append(
                validate_install_inventory(
                    args.artifact,
                    source_version,
                    repo=args.repo,
                )
            )
            checks.append(validate_runtime_imports(args.artifact, args.repo))
            checks.append(validate_runtime_features(args.artifact))
        if args.release_archive is not None:
            checks.append(
                validate_release_archive(
                    args.release_archive,
                    args.artifact,
                    repo=args.repo,
                    expected_version=source_version,
                    run_frozen_e2e=args.frozen_e2e,
                )
            )
        elif args.frozen_e2e:
            checks.append(validate_frozen_e2e(args.artifact))
        if args.base_url:
            cacert = args.cacert if args.cacert and args.cacert.exists() else None
            checks.append(validate_peer_headers(args.base_url, cacert))
            checks.append(validate_recovery_routes(args.base_url, args.token or None, cacert))
            checks.append(validate_alpn(args.base_url, cacert))
            checks.append(validate_cert_chain_with_openssl(args.base_url, cacert))
    except GateFailure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print("PACKAGED ARTIFACT PARITY: PASS")
    for c in checks:
        print(f"  - {c}")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
