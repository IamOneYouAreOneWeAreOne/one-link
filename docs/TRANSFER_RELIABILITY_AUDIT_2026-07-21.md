# One Link transfer reliability audit — 2026-07-21

## Status

`partial`

The local implementation and isolated end-to-end paths are substantially
hardened, but this tree is **not** represented as flawless or release-ready.
Closure is intentionally not called complete until the repaired build is
exercised between physical devices over the reported 596 ms route, forced
crashes and power loss are tested on the supported filesystems, signed packaged
builds pass on every supported OS, repaired GitHub jobs pass after publication,
and recoverable quarantines age through their retention windows.

## 2026-07-22 revalidation boundary

This revalidation covers the current local source tree and the evidence named
below. It does not turn an uncommitted working tree into a released artifact,
does not authenticate a future installer, and does not substitute focused
reruns for a clean full-suite run. There is no current signed production tag or
published build proving that these local repairs are what users are running.

The strongest current result is therefore a hardened, explicitly fail-closed
implementation with several strong local gates. The whole product remains
`partial`: the last broad Python run was not green, packaged/runtime matrices
and physical fault campaigns remain open, and several website/history/manual
surfaces are source-maintained rather than independently generated evidence.

## Root causes

1. The desktop upload HTTP request stayed open for the entire remote transfer.
   A browser timeout/retry minted a new delivery and could create repeated
   offers/cards for one user action.
2. Sender success was not bound to an authenticated, durable receiver commit,
   so a lost final response left an ambiguous outcome that was unsafe to guess.
3. A stream plan expressed as four 1 MiB chunks was copied as four much smaller
   CDC cadence chunks. At 596 ms RTT, the 385 MiB case required about 404 ACK
   flights before alignment and 101 even after the initial count-only fix.
4. The 30-second folder reconciliation loop created a full transfer/activity
   row for equality probes. The production database accumulated 20,054
   historical `paper` rows.
5. Relay payloads and browser DataChannel dispatch tasks were bounded per
   operation but not across the process/lifecycle, permitting memory and
   shutdown races under fan-out.
6. Interrupted tests and historical lifecycle gaps left unreferenced inbox,
   chunk, resume, and CAS files in the production profile.
7. Folder synchronization had no authenticated durable suffix-resume contract.
   Reconnects could restart content, and a manifest could be accepted without a
   crash-recoverable, generation-bound materialization transaction.
8. The experimental updater mixed release discovery with installation policy.
   Its artifact identity, staging, archive validation, and concurrent installer
   ownership were not strict enough for an authenticated update boundary.
9. Session revocation accepted an ambiguous bare-decimal reference. An
   eight-character numeric display prefix could be interpreted as a database
   row identifier instead of a session fingerprint prefix.
10. A loopback document navigation was treated as owner identity and could
    mint owner/persistent cookies without an independent credential. Valid
    bootstrap responses could also be answered with `304 Not Modified`, which
    risks skipping credential minting, and the long-lived owner bearer was
    copied into script-readable `localStorage`.

## Implemented

- Stable browser/phone delivery keys, request coalescing, atomic same-key
  claims, and durable replay records.
- Local admission ends at a FULL-synced durable queue record and returns
  `202 Accepted`; remote transfer continues in the background.
- Completed phone retries are re-staged and content-hashed before replay.
  Equal filename/size with different bytes now conflicts instead of replaying
  an unrelated success.
- Exact authenticated `FILE_COMMIT` receipts, delivery-nonce deduplication,
  restart reconciliation, and explicit legacy `sent_unconfirmed` handling.
- Strong staged-file identity, one-pass indexing, resume ownership locks,
  exact chunk-receipt replay, and collision-safe inbound ledger identities.
- Byte-budgeted adaptive scheduling with live RTT observations, conservative
  warm start, additive growth, multiplicative backoff, and an immutable
  24 MiB window ceiling. Small CDC chunks may use a larger chunk count without
  increasing the byte cap.
- A 512 MiB process-wide relay payload budget plus a protected 4 MiB
  control/teardown reserve; exact lease accounting and fail-closed overload.
- Bounded/tracked browser DataChannel dispatch and shutdown draining.
- Phone upload reconnect/resume, strict failure handling, periodic orphan
  sweep, bounded AIMD upload window, and cancellation/finalization ownership.
- Explicit `folder_blob_resume_v1` negotiation with peer/hash/size-bound
  partials, exact offset plus BLAKE3 prefix proof, crash-tail truncation,
  corruption discard, suffix-only reconnect transfer, final BLAKE3 CAS commit,
  bounded partial storage, cleanup, and garbage-collection accounting. Legacy
  peers safely restart at byte zero.
- Schema v30 durable `folder_pending_applies` journal. Manifest generation and
  journal records commit atomically with SQLite `FULL` synchronization; staged,
  moved, published, and delete phases recover after restart. Exact preimage and
  target hashes, durable CAS roots, no-replace publication, indexed blob
  arrival, and symlink/race checks prevent silent overwrite and false success.
- Folder equality probes now update one durable checkpoint and create no
  transfer/activity row unless the receiver requests content.
- Content-addressed storage graph audit, reference-safe cleanup, recoverable
  quarantine/rollback, and a separate 30-day-grace purge operation.
- Windows Edge E2E startup uses an explicit loopback debugging port, bounded
  fresh-profile retry, process-tree cleanup, and cleanup-error-safe temp dirs.
- The benchmark harness now declares its `psutil` dependency, enables its live
  lane explicitly, isolates/pins both peers, and grants the required file
  capability.
- Pytest installs an isolated `ONE_LINK_HOME` before importing product code,
  preventing future test artifacts from entering the real profile.
- Fuzz parser allocation counts are checked before allocation and all derived
  lengths use checked arithmetic with exact trailing-body rejection.
- Capability caveat decoding now validates nested counts and remaining body
  bytes before allocation. The historical 0x540000000-byte nightly-fuzz
  allocation has an exact 105-byte regression vector.
- The July 21 implementation made executable handoff unconditionally
  unavailable. That historical boundary was superseded on July 24: an explicit
  owner-confirmed endpoint may now hand authority to the fixed external A/B
  helper, but only after a complete local frozen standalone bundle validates.
  Source/pip/development, incomplete, moved, or modified installs fail closed;
  background polling remains notification-only and unattended/background
  automatic installation remains unavailable. Release planning and the helper
  enforce exact Sigstore workflow/tag identity, manifest/SHA-256/SBOM/artifact
  contracts, private bounded staging, fsync, archive validation,
  downgrade/equivocation guards, daemon/UI health checks, and rollback.
- Session revocation uses an unambiguous `id-<positive-int64>` reference. Bare
  decimal/display prefixes fail closed; exact legacy 64-hex bearer tokens remain
  supported.
- Unbound legacy v1 channel `HELLO` is rejected by default on both initiation
  and response. `ONE_LINK_ALLOW_V1_HELLO=1` is an explicit, temporary
  migration-only override for upgrading both endpoints; normal operation uses
  the responder-bound v2 transcript and must not silently fall back.
- Loopback routing no longer authorizes or mints owner/session credentials.
  Invalid or stale bootstrap tokens return `401` unless an independent owner or
  persistent-session credential is already valid. Authenticated bootstrap is a
  full `no-store` response even when an ETag matches, captures the owner bearer
  into tab-scoped `sessionStorage` before URL scrubbing, and never persists that
  bearer in `localStorage`.
- Packaged-artifact probes no longer disable TLS certificate verification.
  Public HTTPS uses the platform trust store; private/local CAs must be supplied
  explicitly before any owner bearer is transmitted.
- Windows namespace publication and replacement now use documented
  `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` semantics. Replace and no-replace
  paths preserve their distinct collision behavior, and the helper is wired
  into final file/folder publication, fail-stop markers, resume sidecars, and
  pending-apply materialization/recovery. POSIX paths retain parent-directory
  synchronization after namespace changes.
- `one-link verify-this-install` now inventories every stable file recursively
  under the managed Python package and separately installed native package,
  rejecting link-like/unsafe or unreadable entries and recording missing
  required entries. Only runtime bytecode/cache debris and OS metadata are
  excluded. The default fails closed without an independently authenticated
  64-hex SHA-256 rollup; `--inventory-only` is explicitly diagnostic and is not
  authenticity or provenance evidence. Released artifacts still require exact
  tag-bound Sigstore identity verification without wildcards.
- Mount capability reporting now reflects implementation truth. Linux is ready
  only when the feature-gated libfuse binding exposes the complete mount ABI;
  macOS FSKit and Windows WinFsp/Dokan adapters report `backend=none` and
  `reason=adapter_unimplemented` rather than inferring support from a general
  native extension.
- Channel-reciprocity Factor-2 remains fail closed. QR pairing can mix and
  explicitly confirm externally supplied candidates, but the former high-level
  secret derivation API raises `Factor2UnavailableError` because probe
  acquisition, interactive reconciliation, entropy/leakage proof, daemon
  wiring, and adversarial hardware evidence do not exist yet.
- The release SBOM generator now creates deterministic CycloneDX 1.6 inventory
  over the frozen Python dependency graph, complete Cargo lock/workspace graph,
  and exact release artifact sizes and SHA-256 hashes. Release workflow ordering
  generates it before checksums/signatures and then re-verifies SBOM contents,
  final artifact bytes, and `SHA256SUMS` as identical views before signing and
  provenance attestation.
- AppImage input handling now uses immutable GitHub asset IDs with exact byte
  lengths and SHA-256 pins, TLS-only download, bounded temporary staging, and
  refusal to overwrite an output. The rendezvous container uses digest-pinned
  build/runtime bases, an exact hash-locked dependency subset, a minimal module
  allowlist, non-root execution, read-only/resource-cap defaults, and no
  registry image fallback in Compose. These are build-source controls, not
  proof that an AppImage or OCI image was built, signed, published, or exercised
  in an external runtime.
- Ruff correctness debt was closed across the Python tree, including a test
  silently shadowed by a duplicate function definition.

## Website and public-claim alignment

- The companion `One_link_Website` r96 working tree uses bounded streaming
  uploads, strict `Content-Length`, a Durable Object single-consumer claim,
  delete-before-return retrieval, durable expiry/retry, and privacy-minimized
  rate keys.
- Public copy in all six locales and the capability-gap matrix now separates
  demonstrated behavior, platform limitations, and roadmap requirements. The
  bar was not lowered by presenting roadmap work as shipped capability.
- This is not yet a production claim: live remains r95, and the historical
  Ed25519 manifest signature covers the old manifest. Only 86 of 155 current
  assets match that signed inventory; 69 are mismatches. r96 remains blocked
  until an offline key holder
  rehashes and signs the exact audited tree and the resulting release is
  deployed and re-audited.

## Production profile remediation

- Preserved and re-verified the one valid received archive:
  `08cad99a_ACE.zip`, 403,387,968 bytes, 127 ZIP entries, BLAKE3
  `08cad99a1e4d341a52c0612d26054632591e9f22c846cf708597d0bec7fe8ebc`,
  with no corrupt ZIP member.
- The encrypted transfer ledger now has exactly one `ACE.zip` row: inbound,
  `complete`, 403,387,968 / 403,387,968 bytes. It has no queued, offered,
  active, or paused transfer rows.
- Content-verified CAS audit found 108,265 unreferenced objects totaling
  107,942,293,459 bytes and zero corrupt objects. They were moved into 11
  pinned, journaled, rollback-capable quarantine batches. The live CAS now has
  367 objects / 43,446,188 bytes and zero candidates or audit errors.
- Quarantined 771 independently manifested pytest artifacts totaling
  30,649,635 bytes. Every destination hash verified, every source is absent,
  and no deletion occurred.
- Removed the obsolete 195,268,608-byte plaintext migration backup by secure
  overwrite/delete. SQLCipher and SQLite integrity checks are clean.
- The live inbox now contains 242 preserved files and no resume sidecars.
- Historical terminal transfer/activity rows were retained to avoid silently
  deleting user history. The repaired 30-second equality cycle produced zero
  new activity and zero new `paper` rows during observation.

The 107.9 GB CAS quarantine is deliberately not purged. Its default recovery
grace makes the first batches eligible around 2026-08-20; disk space is not
reclaimed until an explicit, separately verified purge.

## Verification

- The most recent broad Python run ended at 8,157 passed / 21 failed. A later
  root-focused repair set is 119 / 119 passed. That focused result is not a
  substitute for the broad run: a final complete Python rerun is still pending,
  and the repository is not green until it exits cleanly.
- Focused UI idempotency: 62 passed. Storage lifecycle: 31 passed, 3 skipped.
  Transfer/receipt/cache/resume/mesh/relay focused set: 278 passed.
- Full folder suite: 467 passed, 14 skipped. Live two-daemon folder suite:
  6 passed. Focused resume/storage/journal/bidirectional suite: 92 passed,
  6 skipped. Pending-apply adversarial journal suite: 20 passed.
- Updater/update-policy focused suite: 98 passed. Supply-chain focused suite:
  85 passed.
- Ruff: clean. Mypy: clean across 209 source files. Compileall and
  `uv lock --check`: clean. `git diff --check`: clean apart from line-ending
  notices.
- JavaScript Acorn gates: `index.html` and `peer.html` clean. npm audit: zero
  vulnerabilities.
- Playwright Chromium: 42 passed.
- Real local two-daemon Edge call gate: pass in 18.851 s; caller and receiver
  connected, each received 45 audio packets, received 23/24 video packets and
  9/10 frames, and all privacy-failure flags remained false.
- Edge media soak: pass; 509 audio packets, 272 frames, 2,108 ms setup, zero
  maximum frozen milliseconds, with ICE restart and renegotiation observed.
- Isolated 385 MiB cold transfer: 15.467 s, 24.9 MiB/s. This is a local
  end-to-end result, not a WAN throughput claim.
- 385 MiB ingest: CDC indexing 2.08 GiB/s; durable ingest 0.29 GiB/s.
- Current Rust formatting and static-analysis evidence is clean:
  `cargo fmt --all -- --check` passed, and
  `cargo clippy --locked --workspace --all-targets --all-features --keep-going
  -- -D warnings` passed. The formatter baseline touched 697 native files; that
  broad mechanical normalization is not behavioral or runtime proof. No clean
  full workspace test claim is inferred from fmt/Clippy.
- Frozen dependency audit: zero known vulnerabilities. Bandit: 0 medium/high.
  Gitleaks 8.30.1: no resulting-tree secrets. Zizmor strict: no findings.
- The production-readiness script now reports only
  `file_engine_v2_wiring_ready`; even a scoped pass keeps
  `production_ready=false` with an explicit whole-product limitation. A skipped
  pre-release gate does not become release evidence (`release_gated=false`).
- State migration and encryption suites pass with schema 30. No claim is made
  here that an installed/running production daemon is loaded from this dirty
  source tree.
- Companion website r96 gates: Node 42/42; strict Wrangler 4.113 dry-runs for
  both Workers; HTMLHint 127/127; Pa11y WCAG 2 AA on 20 routes; live r95 audit
  34/34 desktop/mobile views; static LCP 244 ms, TTFB 6 ms, CLS 0. These tests
  do not substitute for signing or deployment of r96.

## Remaining

- Run the 385 MiB archive between two upgraded physical devices on the actual
  596 ms path, including lost-response and restart/resume fault injection, and
  prove one receiver path plus one sender delivery nonce.
- Exercise folder suffix resume and pending-apply recovery with physical
  process kills and power interruption on NTFS, ext4, and APFS. Windows now uses
  a write-through namespace operation at the critical publication boundaries,
  but only real power-cut tests can characterize filesystem, volume-cache, and
  storage-controller behavior.
- Current folder resume is a sequential suffix protocol with 8 MiB
  checkpoints and O(prefix) reconnect rehashing, not sparse/out-of-order,
  multipath resume or serialized BLAKE3 state. Its 16 TiB ceiling is
  policy-tested, not hardware-tested; destination-volume headroom still needs
  a complete materialization budget.
- Partial metadata checksums protect accidental corruption, not a keyed local
  disk attacker, and partial locking is single-instance rather than
  cross-process. Conflict-UI materializations are outside the pending-apply
  journal, and publication is fail-closed but not fully descriptor-relative
  no-follow on every platform.
- Produce and verify signed packaged builds on every supported OS. Current
  GitHub CI cannot attest to this uncommitted local tree, and no packaged
  `dist/one-link` artifact from this repaired source is available for an
  installed-application E2E verdict.
- Run the digest-pinned rendezvous build in a real Docker/OCI engine, exercise
  health, restart, read-only filesystem, resource exhaustion, relay-disabled
  defaults, and network isolation, then publish and verify a signed image by
  digest. Source-contract tests do not supply this external runtime evidence.
- Build the pinned AppImage with the actual downloaded tool, verify its
  resulting signature/checksum, and execute it across the supported Linux
  distro/glibc/FUSE matrix. Asset pins and shell-contract tests alone do not
  prove that the produced AppImage launches or updates safely.
- Publish the browser-startup and capability-parser root fixes, then rerun the
  currently failing remote browser and fuzz jobs. Local success is not remote
  CI evidence.
- Keep unattended/background automatic installation unavailable. The
  owner-confirmed external handoff must remain limited to a completely
  validated frozen standalone bundle, and must not be promoted as a production
  updater until signed immutable stable releases, packaged-application E2E,
  rollback/recovery, post-restart health, and cross-platform installer
  ownership are proven. The GitHub `auto-latest` prerelease is not a stable
  update channel.
- Keep QUIC chunk cutover disabled until the physical-device proof is green.
- Keep reciprocity Factor-2 unavailable until independent physical probes,
  authenticated interactive reconciliation, measured min-entropy/leakage,
  explicit daemon use, bidirectional confirmation, and adversarial relay/replay
  hardware trials are complete.
- The loopback bootstrap/session repair removes navigation-as-auth and
  `localStorage` persistence, but the HTTP owner bearer remains host-wide and
  port-agnostic. Origin-bound HTTPS or a stronger OS-mediated owner channel is
  still required before claiming resistance to every local-process/browser
  origin threat.
- Retain or explicitly archive/prune the 23,006 historical terminal ledger
  rows; no automatic destructive choice was made.
- After retention, explicitly approve or roll back each quarantine before any
  permanent purge.
- Repository-wide production-readiness advisories remain: facade migration is
  8 / 145 channel call sites, Bloom-honor cutover is disabled pending telemetry,
  macOS/Windows filesystem mount bridges remain unimplemented, and packaged
  Linux `/dev/fuse` qualification plus the real 24-hour mount/kill/restart gate
  are not complete.
- Website r96 needs offline rehash/signing, deployment, Cloudflare preview
  Durable Object/R2 E2E, provider-retention verification, physical large-file
  fault campaigns, authenticated capability advertisements, real two-device
  pairing, and an independent security assessment.
- Apple Intel support, hardware-key-backed identity closure, complete signed
  discovery surfaces, branch-protection evidence, and a full external red-team
  audit remain release gates. Passing repository tests is not proof that every
  feature or adversarial environment has been exhausted.
- Dated `ROADMAP.md`/`ARCHITECTURE.md` passages still need historical labeling
  and a complete manual claim sweep. The hand-maintained Truth Matrix and
  `/api/audit` vocabulary are useful source snapshots, not signed, generated,
  or independently observed capability evidence.

## History and dependency comparison

Local sibling repositories and available Git/GitHub history were searched for
newer transfer, receipt, resume, scheduling, and storage-lifecycle work. No
more complete implementation was found to transplant. Historical GitHub fuzz
and browser-call failures were traced to the allocation-count and Edge startup
issues described above and fixed at their sources. All compatible direct
and development/tooling dependency updates accepted by the resolver are in the
lock and were validated by the stated local gates. Twenty-four incompatible
major-version candidates were deliberately not force-migrated across ecosystem
constraints; they require explicit migrations and regression campaigns. This
is a compatibility-grounded lock result, not a claim that every package is on
the numerically newest upstream major.
