# Transactional standalone updater contract

One Link's historical wheel updater is retired. It downloaded `latest`, checked
only `SHA256SUMS`, ran `pip --force-reinstall`, and restarted even when the
install failed. That path is not a safe basis for a frozen onedir application.

The replacement core is split into four explicit trust boundaries:

1. `scripts/generate_update_manifest.py` inventories the five supported
   standalone ZIPs and SBOM at the tagged commit. It emits canonical
   `UPDATE_MANIFEST.json`, binding tag, full commit SHA, workflow/OIDC identity,
   validity window, monotonic rollback index, compatible source-version floor,
   platform layout, exact size, and SHA-256.
2. `one_link.standalone_updater` treats GitHub release JSON as discovery only.
   It requires exact canonical download URLs and independently verifies the
   Sigstore bundles for `UPDATE_MANIFEST.json`, `SHA256SUMS`, the SBOM, and the
   selected standalone ZIP under the exact immutable tag identity.
3. `one_link.update_transaction` hashes and safely extracts the authenticated
   ZIP, then revalidates every member against its internal
   `BUNDLE_SHA256SUMS`. Archive hashing and extraction use the same open file
   identity. Portable-name collisions, links on Windows, escaping links on
   POSIX, special files, unexpected members, archive bombs, and path/reparse
   aliases fail closed.
4. The same module performs a journaled current -> backup, candidate -> current
   exchange only after the captured process instance exits. The restarted
   candidate must report the signed version, run from the exact activated
   executable, re-hash its complete tree, and pass an explicit application
   health probe before the rollback high-water mark advances and the backup is
   retired.

## Durable state machine

The transaction state and rollback ledger are MAC-authenticated with a stable,
random authority key wrapped by One Link's LockBox. Existing corrupt or
undecryptable authority never triggers replacement-key generation.

The durable phases are:

```text
prepared
  -> backup_intent -> backup_created
  -> activate_intent -> candidate_active
  -> health_accepted -> high_water_committed -> committed

any pre-health failure
  -> rollback_intent -> rolled_back
```

Each filesystem rename is preceded by intent and followed by a durable phase.
Recovery handles a crash on either side of every boundary. A candidate without
an authenticated health marker remains active only until its signed journal
deadline; expiry restores the byte-validated previous bundle. After health is
accepted, recovery finishes the commit and will not downgrade to older code.

The high-water ledger permanently binds each observed tag to version, rollback
index, source commit, artifact digest, and signed-metadata digest. A moved or
reissued tag, same/lower rollback index, same/lower version, corrupt ledger, or
missing history fails closed.

## Required release wiring

The tagged release authority must generate `UPDATE_MANIFEST.json` after the
complete SBOM and all standalone ZIPs exist, but before `SHA256SUMS` and the
all-file Sigstore loop. A representative invocation is:

```text
python scripts/generate_update_manifest.py \
  --dist-dir dist \
  --tag v<stable-major.minor.patch> \
  --commit-sha <exact-40-hex-tag-commit> \
  --source-date-epoch <tag-commit-epoch> \
  --minimum-source-version <reviewed-compatible-floor>
```

Publication must include the metadata in `SHA256SUMS`, per-file Sigstore
signing, build-provenance subjects, and release assets. Stable public tags are
append-never/replace-never authority: a workflow rerun may accept an existing
draft asset only when its remote digest and size exactly match; it must not use
`--clobber` to mutate a published release.

## Packaged activation helper and product wiring

The standalone build now creates a separate one-file
`one-link-update-helper` executable and places it inside the onedir before
`BUNDLE_SHA256SUMS` is generated. The helper therefore crosses the same signed
release boundary as the rest of the bundle. Before exit, the running process
validates the installed manifest, copies the exact helper bytes to private
update state, captures its process-instance guard, persists a one-use
MAC-authenticated handoff, and passes the authority only through a private
stdin pipe. The external process independently verifies the exact-tag Sigstore
identity in-process, performs the journaled replacement after the guarded
parent exits, launches only the signed candidate executable, and accepts health
only from authenticated daemon/control and UI proofs for that exact candidate.

The owner-authenticated UI now exposes an explicit one-shot installation only
when the running process proves that it is the exact executable inside a
complete, locally validated standalone bundle and the fixed helper hashes to
the value in that bundle. Source, pip, incomplete, moved, or modified installs
fail closed and expose no installation action.

The daemon and HTTP boundary:

- obtain the stable update-state authority from the existing LockBox;
- defer while calls, transfers, state migrations, recovery, or identity
  rotation are active, treating guard-inspection errors as a deferral;
- independently discover the stable tagged release; no tag, digest, path, or
  command is accepted from the browser;
- capture the parent process instance token, spawn the external helper, flush
  durable application state, require a MAC-authenticated helper acceptance
  receipt bound to the exact helper process, and exit normally;
- have the restarted candidate run full startup/self-health before calling the
  health-commit API; and
- surface rollback/commit evidence without exposing raw journal paths.

The daemon refuses the handoff while calls, active transfers, uploads,
deliveries, recovery, or another update are in flight. It then drains new work,
holds the cross-process recovery authority, persists the authenticated handoff,
and shuts down cleanly only after helper acceptance. If authentication,
activation, or candidate health fails after shutdown, the helper restores and
relaunches the validated prior bundle.

This is user-confirmed, one-click installation—not unattended/background
auto-installation. The Automatic installation setting intentionally remains
unavailable. A platform is install-capable only when its release package
contains the helper and signed standalone artifact required by this contract.
