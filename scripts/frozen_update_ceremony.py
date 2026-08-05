#!/usr/bin/env python3
"""Execute the update transaction against a REAL frozen bundle, on real hardware.

The audit's one remaining condition. `tests/test_update_metadata_transaction.py`
drives every step of this ceremony, and `tests/test_update_preserves_user_data_e2e.py`
proves the user's database survives it -- both against a synthetic three-file
bundle. What had never happened anywhere is the same ceremony against an actual
PyInstaller onedir tree: ~1200 files, 220 MB, a 54 MB helper, real Windows file
locking, and a process guard captured from a process that really ran.

That distinction matters because the defects this repo keeps finding are of
exactly this shape -- a mechanism proven against a model of the thing rather
than the thing. The macOS self-install bug was invisible for the same reason:
the validator was tested on bundles the packager did not produce.

What this runs, in order:

    1.  stage a copy of the frozen bundle as the INSTALLED (old) tree
    2.  write its BUNDLE_SHA256SUMS with the single canonical writer
    3.  validate it through the product's own validate_installed_bundle
    4.  build a CANDIDATE archive from the same tree, version marker bumped
    5.  launch the real frozen executable, capture its process guard, stop it,
        and require_guarded_process_exit against the real PID
    6.  prepare -> activate -> validate the activated tree -> mark healthy
    7.  and separately: prepare -> activate -> FORCED FAILURE -> rollback,
        verifying the previous tree comes back byte-for-byte

Every step asserts. A step that cannot run says so and fails; nothing here
reports success for work it skipped.

Usage:
    python scripts/frozen_update_ceremony.py --bundle dist/one-link
    python scripts/frozen_update_ceremony.py --bundle dist/one-link --keep
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from one_link.update_metadata import (  # noqa: E402
    PLATFORM_CONTRACTS,
    host_platform_key,
    rollback_index_for_version,
)
from one_link.update_transaction import (  # noqa: E402
    TransactionPhase,
    UpdateTransactionError,
    activate_prepared_update,
    capture_process_guard,
    mark_update_healthy,
    prepare_update_transaction,
    recover_update_transaction,
    require_guarded_process_exit,
    validate_installed_bundle,
)

AUTHORITY_KEY = b"\x5c" * 32
STEP = 0


def step(message: str) -> None:
    global STEP
    STEP += 1
    print(f"\n[{STEP:02d}] {message}", flush=True)


def ok(message: str) -> None:
    print(f"     OK  {message}", flush=True)


def fail(message: str) -> None:
    raise SystemExit(f"     FAIL {message}")


# ── building a faithful candidate from the real tree ──────────────────


def write_manifest(bundle: Path, root_name: str, executable: str) -> Path:
    """Use the SINGLE canonical writer, not a reimplementation here.

    Writing our own would be the exact defect this script exists to catch: a
    verifier that validates a shape the product never produces.

    --verify re-reads the file it just wrote through validate_installed_bundle,
    which needs to know which member is the launcher; it takes that from
    ONE_LINK_BUNDLE_EXECUTABLE.
    """
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "write_bundle_manifest.py"),
         "--bundle", str(bundle), "--root-name", root_name, "--verify"],
        capture_output=True, text=True, cwd=str(REPO),
        env={**os.environ, "ONE_LINK_BUNDLE_EXECUTABLE": executable},
    )
    if result.returncode != 0:
        fail(f"manifest writer failed:\n{result.stdout}\n{result.stderr}")
    return bundle / "BUNDLE_SHA256SUMS"


def build_candidate_archive(
    tree: Path, out: Path, root_name: str, marker: bytes, executable: str
) -> Path:
    """Zip the real tree as a candidate, with one file changed.

    The changed file is what proves activation actually swapped trees. Without
    it, "the new bundle is installed" would be indistinguishable from "nothing
    happened".
    """
    stamp = tree / "_internal" / "one_link" / "_build" / "CEREMONY_MARKER"
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_bytes(marker)
    write_manifest(tree, root_name, executable)

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=1) as archive:
        for path in sorted(tree.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(tree).as_posix()
            info = zipfile.ZipInfo(f"{root_name}/{relative}")
            info.create_system = 3
            mode = 0o755 if path.suffix.lower() in (".exe", ".dll", ".so") else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    return out


def authenticated_manifest(archive: Path, platform_key: str, version: str):
    from one_link.update_metadata import (
        canonical_update_metadata_bytes,
        parse_authenticated_update_manifest,
    )

    contract = PLATFORM_CONTRACTS[platform_key]
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    size = archive.stat().st_size
    entries = []
    for key, other in PLATFORM_CONTRACTS.items():
        chosen = key == platform_key
        entries.append({
            "platform": key,
            "filename": other.filename,
            "size": size if chosen else 123,
            "sha256": digest if chosen else hashlib.sha256(key.encode()).hexdigest(),
            "bundle_root": "one-link",
            "executable": other.executable,
            "kind": "standalone-zip-v1",
        })
    now = datetime.now(UTC).replace(microsecond=0)
    document = {
        "schema": "one-link-update-manifest/v1",
        "tag": f"v{version}",
        "version": version,
        "rollback_index": rollback_index_for_version(version),
        "minimum_source_version": "0.20.0",
        "created_at": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "repository": "coherence-energy-labs/one-link",
            "workflow": ".github/workflows/release.yml",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "commit_sha": "c" * 40,
            "ref": f"refs/tags/v{version}",
        },
        "sbom": {
            "filename": "sbom.cdx.json",
            "size": 321,
            "sha256": hashlib.sha256(b"sbom").hexdigest(),
        },
        "artifacts": entries,
    }
    # verified_tag is an EXPLICIT input from the signature ceremony -- the
    # parser refuses to take it from inside the document, which is the right
    # design and worth honouring here rather than working around.
    manifest = parse_authenticated_update_manifest(
        canonical_update_metadata_bytes(document),
        verified_tag=f"v{version}",
    )
    return manifest, contract


# ── the real process ──────────────────────────────────────────────────


def stop_process_tree(process: subprocess.Popen) -> None:
    """Stop the launcher AND its supervised child.

    One Link is a two-process application on Windows: the launcher spawns a
    supervised child (see ONE_LINK_SUPERVISED in docs/ENVIRONMENT.md).
    Popen.terminate() kills only the launcher, and the surviving child keeps a
    handle open inside the install directory -- so the activation rename fails
    with WinError 32, "the process cannot access the file because it is being
    used by another process".

    That is not a product defect, and discovering it here is the reason to say
    so explicitly: the real updater does NOT kill the application. It requests
    a clean shutdown over the control IPC first (see update_helper.py), which
    stops both processes. A harness that killed only the parent would be
    testing a shutdown path the product never takes, and would have reported a
    failure that says nothing about the shipped behaviour.

    taskkill /T is the closest approximation available without a running
    control channel: stop the tree, then confirm nothing survived, because an
    orphan holding the directory would make the next step fail for a reason
    that has nothing to do with the transaction.
    """
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True, text=True, timeout=60,
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=60)


def assert_no_survivors(root: Path) -> None:
    """Nothing may still be running out of `root` before we rename it."""
    if os.name != "nt":
        return
    for _ in range(30):
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Process | Where-Object { $_.Path -like '"
             + str(root).replace("'", "''") + "*' }).Count"],
            capture_output=True, text=True, timeout=60,
        )
        count = (result.stdout or "").strip() or "0"
        if count in ("0", ""):
            return
        time.sleep(1.0)
    fail(f"a process is still running out of {root}; the rename would fail "
         f"for a reason unrelated to the transaction")


def real_process_guard(executable: Path, home: Path):
    """Launch the ACTUAL frozen binary, capture its guard, then stop it.

    This is the part no test could do. capture_process_guard binds a PID to an
    instance token read from the live OS process, and require_guarded_process_exit
    refuses to proceed while that exact instance is alive. Both were only ever
    exercised against synthetic identities.
    """
    home.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["ONE_LINK_HOME"] = str(home)
    environment["ONE_LINK_UPDATE_CHECK"] = "0"

    process = subprocess.Popen(
        [str(executable)],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(executable.parent),
    )
    try:
        time.sleep(4.0)  # let it get past import and actually be a live process
        if process.poll() is not None:
            fail(
                f"the frozen executable exited immediately with code "
                f"{process.returncode} -- it cannot be updated if it cannot run"
            )
        guard = capture_process_guard(process.pid)
        ok(f"captured a live process guard: pid={guard.pid} "
           f"token={guard.instance_token[:12]}...")

        # It must REFUSE while the process is alive. If this does not raise,
        # the guard is not guarding anything.
        try:
            require_guarded_process_exit(guard, timeout=1.0)
        except UpdateTransactionError:
            ok("refused to proceed while the guarded process was still running")
        else:
            fail("require_guarded_process_exit accepted a LIVE process")
    finally:
        stop_process_tree(process)

    require_guarded_process_exit(guard, timeout=60.0)
    ok("accepted the exit of that exact instance")
    return guard


# ── the ceremony ──────────────────────────────────────────────────────


def run(bundle: Path, workspace: Path) -> None:
    platform_key = host_platform_key()
    if platform_key is None:
        fail("this host is not a published target platform")
    contract = PLATFORM_CONTRACTS[platform_key]
    executable_name = contract.executable
    root_name = "one-link"

    step(f"Staging the real frozen bundle ({platform_key})")
    installed = workspace / "installed" / root_name
    installed.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundle, installed)
    count = sum(1 for p in installed.rglob("*") if p.is_file())
    size = sum(p.stat().st_size for p in installed.rglob("*") if p.is_file())
    ok(f"{count} files, {size:,} bytes")
    if not (installed / executable_name).is_file():
        fail(f"{executable_name} is not in the bundle; wrong --bundle?")

    step("Writing BUNDLE_SHA256SUMS with the single canonical writer")
    write_manifest(installed, root_name, executable_name)
    ok("written and re-read through validate_installed_bundle (--verify)")

    step("Validating the installed tree the way the updater does")
    previous = validate_installed_bundle(installed, expected_executable=executable_name)
    ok(f"validated {previous.file_count} members, "
       f"{previous.payload_bytes:,} payload bytes, "
       f"manifest_sha256={previous.manifest_sha256[:16]}...")

    step("Building a CANDIDATE archive from the same real tree")
    candidate_tree = workspace / "candidate" / root_name
    candidate_tree.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(installed, candidate_tree)
    (candidate_tree / "BUNDLE_SHA256SUMS").unlink(missing_ok=True)
    archive = workspace / contract.filename
    build_candidate_archive(
        candidate_tree, archive, root_name, b"ceremony-new-0.22.1", executable_name
    )
    ok(f"{archive.name}: {archive.stat().st_size:,} bytes")

    manifest, _ = authenticated_manifest(archive, platform_key, "0.22.1")
    ok("authenticated update manifest parsed")

    step("Launching the REAL frozen executable and capturing its process guard")
    guard = real_process_guard(installed / executable_name, workspace / "home")

    # ── scenario 1: commit ────────────────────────────────────────────
    state_root = workspace / "update-state"
    step("SCENARIO 1 -- prepare")
    prepared = prepare_update_transaction(
        manifest=manifest,
        platform_key=platform_key,
        archive_path=archive,
        install_root=installed,
        state_root=state_root,
        authority_key=AUTHORITY_KEY,
        current_version="0.22.0",
        health_window=timedelta(minutes=10),
    )
    ok(f"phase={prepared.phase}, candidate staged from a 220 MB archive")
    if validate_installed_bundle(
        installed, expected_executable=executable_name
    ).manifest_sha256 != previous.manifest_sha256:
        fail("prepare MUTATED the installed tree; it must be non-destructive")
    ok("the installed tree is untouched after prepare")

    step("SCENARIO 1 -- activate (the real rename dance on a real tree)")
    assert_no_survivors(installed)
    started = time.monotonic()
    active = activate_prepared_update(
        state_root=state_root,
        authority_key=AUTHORITY_KEY,
        process_guard=guard,
        process_timeout=60.0,
    )
    elapsed = time.monotonic() - started
    if active.phase != TransactionPhase.CANDIDATE_ACTIVE.value:
        fail(f"expected candidate_active, got {active.phase}")
    ok(f"phase={active.phase} in {elapsed:.1f}s")

    step("SCENARIO 1 -- the installed tree is now the CANDIDATE")
    now_installed = validate_installed_bundle(
        installed, expected_executable=executable_name
    )
    if now_installed.manifest_sha256 != prepared.candidate_manifest_sha256:
        fail("the activated tree does not match the prepared candidate")
    marker = installed / "_internal" / "one_link" / "_build" / "CEREMONY_MARKER"
    if not marker.is_file() or marker.read_bytes() != b"ceremony-new-0.22.1":
        fail("the candidate marker is absent -- the trees were not swapped")
    ok("manifest matches the candidate AND the new marker file is present")

    step("SCENARIO 1 -- the activated binary RUNS")
    activated = installed / executable_name
    probe = subprocess.Popen(
        [str(activated)],
        env={**os.environ, "ONE_LINK_HOME": str(workspace / "home2"),
             "ONE_LINK_UPDATE_CHECK": "0"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=str(activated.parent),
    )
    try:
        time.sleep(5.0)
        alive = probe.poll() is None
    finally:
        stop_process_tree(probe)
    if not alive:
        fail("the ACTIVATED executable does not start -- an update that "
             "installs a build which cannot run is worse than no update")
    ok("the activated frozen executable started and stayed up")

    step("SCENARIO 1 -- health probe and COMMIT")
    committed = mark_update_healthy(
        state_root=state_root,
        authority_key=AUTHORITY_KEY,
        running_executable=activated,
        observed_version="0.22.1",
        health_probe=lambda path: path.is_file() and alive,
    )
    if committed.phase != TransactionPhase.COMMITTED.value:
        fail(f"expected committed, got {committed.phase}")
    if Path(committed.backup_root).exists():
        fail("the backup tree survived a commit")
    ok(f"phase={committed.phase}; backup and staging removed")

    # ── scenario 2: forced failure -> rollback ────────────────────────
    step("SCENARIO 2 -- staging a second real install to roll back")
    installed2 = workspace / "installed2" / root_name
    installed2.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundle, installed2)
    write_manifest(installed2, root_name, executable_name)
    baseline = validate_installed_bundle(
        installed2, expected_executable=executable_name
    )
    ok(f"baseline manifest_sha256={baseline.manifest_sha256[:16]}...")

    state_root2 = workspace / "update-state-2"
    prepared2 = prepare_update_transaction(
        manifest=manifest,
        platform_key=platform_key,
        archive_path=archive,
        install_root=installed2,
        state_root=state_root2,
        authority_key=AUTHORITY_KEY,
        current_version="0.22.0",
        # 30s is the product's own MINIMUM -- it rejects anything shorter,
        # which is correct: a health window measured in milliseconds would
        # roll back healthy updates. So the harness waits it out rather
        # than asking for a window the product refuses to grant.
        health_window=timedelta(seconds=30),
    )
    assert_no_survivors(installed2)
    activate_prepared_update(
        state_root=state_root2,
        authority_key=AUTHORITY_KEY,
        process_guard=guard,
        process_timeout=60.0,
    )
    swapped = validate_installed_bundle(installed2, expected_executable=executable_name)
    if swapped.manifest_sha256 != prepared2.candidate_manifest_sha256:
        fail("scenario 2 did not activate; the rollback below would prove nothing")
    ok("candidate activated -- there is now something to roll back")

    assert_no_survivors(installed2)
    step("SCENARIO 2 -- FORCED FAILURE: the new build never reports healthy")
    print("     ... waiting out the 30s health window, as a dead build would",
          flush=True)
    time.sleep(34.0)
    result = recover_update_transaction(
        state_root=state_root2,
        authority_key=AUTHORITY_KEY,
    )
    if result.status != "rolled_back":
        fail(f"expected rolled_back, got {result.status!r}")
    ok("recovery rolled the transaction back")

    step("SCENARIO 2 -- the PREVIOUS build is back, byte for byte")
    restored = validate_installed_bundle(installed2, expected_executable=executable_name)
    if restored.manifest_sha256 != baseline.manifest_sha256:
        fail("the restored tree does not match the pre-update baseline")
    if (installed2 / "_internal" / "one_link" / "_build" / "CEREMONY_MARKER").exists():
        fail("the candidate's marker survived the rollback")
    ok(f"restored {restored.file_count} members "
       f"({restored.payload_bytes:,} bytes) to the exact prior manifest")

    step("SCENARIO 2 -- the ROLLED-BACK binary runs")
    rolled = subprocess.Popen(
        [str(installed2 / executable_name)],
        env={**os.environ, "ONE_LINK_HOME": str(workspace / "home3"),
             "ONE_LINK_UPDATE_CHECK": "0"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=str(installed2),
    )
    try:
        time.sleep(5.0)
        rolled_alive = rolled.poll() is None
    finally:
        stop_process_tree(rolled)
    if not rolled_alive:
        fail("the rolled-back executable does not start -- rollback restored "
             "a tree that cannot run, which is the worst outcome of all")
    ok("the rolled-back frozen executable started and stayed up")

    print("\n" + "=" * 68)
    print("CEREMONY COMPLETE -- commit AND forced-failure rollback both")
    print(f"executed against a real {size // (1024 * 1024)} MB frozen bundle")
    print("=" * 68)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path,
                        help="a real frozen onedir bundle, e.g. dist/one-link")
    parser.add_argument("--keep", action="store_true",
                        help="keep the workspace for inspection")
    args = parser.parse_args()

    bundle = args.bundle.resolve()
    if not bundle.is_dir():
        raise SystemExit(f"not a directory: {bundle}")

    workspace = Path(tempfile.mkdtemp(prefix="one-link-ceremony-"))
    print(f"workspace: {workspace}")
    try:
        run(bundle, workspace)
    finally:
        if args.keep:
            print(f"\nworkspace kept at {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
