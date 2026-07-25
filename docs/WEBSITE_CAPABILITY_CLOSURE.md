# Website capability closure

Status: `in_progress`

Checked: 2026-07-24

This is the promotion contract between One Link's public website and the
reviewed product runtime. It is intentionally stricter than a source inventory.
A claim is complete only when all four layers are true:

1. `primitive`: the cryptographic/system primitive exists and passes its native
   or language-level adversarial tests;
2. `runtime`: the daemon negotiates and uses it on the real application path;
3. `surface`: every relevant UI/API exposes the real state without simulating
   or silently falling back;
4. `qualification`: packaged builds pass the stated physical, fault, platform,
   and release-evidence gate at one immutable commit.

Code that is present but dormant is not a product capability. Simulation is not
physical evidence. A mutable rolling artifact is not a release. Provider
metadata is not "nothing collected." These rules raise implementation to the
claim; they are not permission to weaken the claim.

## Whole-repository reuse inventory

The audit covered `src/`, `native/`, `tests/`, `scripts/`, `packaging/`,
`deploy/`, `.github/`, documentation, current Git history, all repository
branches, the public site, public APIs, and the current GitHub release. No newer
unmerged One Link implementation exists on another branch; all extra branches
are ancestors of `master`.

| Capability | Existing work to integrate (do not duplicate) |
|---|---|
| Five-word pairing | `native/ol_pair_qr`, `pair_qr_native.py`, `pairing.py`, `identity_sas.py`, daemon pairing, direct-browser pairing, One Setup enrollment |
| Hybrid ML-KEM | `native/ol_pqkem`, `one_link_native.pqkem`, `pqkem_native.py`, `pq_hybrid.py`, `channel.py` |
| Onion/Sphinx | `native/ol_onion`, `onion_native.py`, `sphinx_native.py`, cover-traffic wiring in `daemon.py` |
| Blinded relay routing | `sealed_sender.py`, `sealed_relay.py`, `relay_routing.py`, v2 `relay_client.py`/`relay_proto.py`, and daemon listen/dial/first-flight sealing |
| Durable transfer | `daemon.py`, CDC/chunk store, exact Bloom v2, commit receipts, resume journals, native transfer crates |
| Recovery | `recovery_api.py`, `backup_bundle.py`, `social_recovery.py`, transactional rotation journal and recovery tests |
| Updates/releases | `updater.py`, `update_check.py`, packaging scripts, release/reproducibility workflows, SBOM generator |
| Hardware/duress | `native/ol_hwkey`, `native/ol_device_mesh` duress primitives, formal models; product wiring remains incomplete |

## Claim closure matrix

| Public claim family | Current status | Runtime truth | Promotion gate |
|---|---|---|---|
| 1:1 chat and durable delivery | `in_progress` | Daemon/desktop persistence, idempotency, ACK ordering and bounded outboxes are implemented. Direct-browser chat now persists an identity/session-bound outbox, replays exact ciphertext idempotently after reconnect, verifies ACKs, quarantines poison rows, and survives Service Worker restart; browser durability and real two-page transport gates pass. | Two packaged physical devices; disconnect/crash/replay/duplicate/corrupt-outbox matrix; zero lost or duplicated accepted messages. |
| Group chat | `in_progress` | Signed group-event membership, sender-chain encryption, bounded out-of-order receive, durable per-recipient fan-out, reactions/edits/deletes, and ephemeral privacy-gated group typing are wired through daemon, API, and UI. A real two-daemon encrypted typing round trip proves current-member-only fan-out without persisting composition metadata. This does not claim multiparty voice/video. | Three or more packaged physical devices; concurrent send, membership churn, removal/key-rotation, long offline replay, malicious-member, duplicate/reorder and crash matrix with zero post-removal delivery. |
| File transfer, resume, and no duplicate offers | `partial` | Durable intents, exact commit receipts, bounded resume, exact Bloom corrections, CDC and native paths exist. | Physical 385 MiB and 10-50 GiB runs on every supported platform under 596 ms RTT, loss, duplication, reorder, process kill, sleep, disk-full and corruption. Publish raw artifacts. |
| "10 GB verified" | `partial` | Current 10 GiB evidence is synthetic manifest/state-machine execution, not physical byte transfer. | Hash-verified physical transfer with captured versions, routes, timings, resource peaks and fault schedule. |
| Voice/video calls | `partial` | 1:1 call lifecycle and media paths are wired; group calling is not shipped. Firefox mDNS-only ICE now receives a LAN-scoped numeric companion candidate from a bounded local STUN responder on both peer-chat and call-media paths; real Firefox and Chromium gates pass. | Multi-hour packaged two-device browser/desktop soak across route changes, sleep/resume, AP isolation, diverse NAT/TURN and media loss; physical macOS/iOS WebKit, consent and teardown proofs. |
| Shared folders | `partial` | Real two-daemon full-duplex byte sync exists. Linux release wheels now expose a read-only, callback-backed `fuser` mount with strict manifest/CAS validation, bounded reads, owned-session unmount and a real Linux round-trip gate. Windows WinFsp/Dokan and macOS FSKit adapters remain explicitly unsupported; BLE remains inventory/bootstrap rather than bulk transport. | Physical multi-platform bidirectional fault matrix; Linux packaged `/dev/fuse` qualification; conflicts, rename storms, disk-full, restart and large trees; implement and qualify native Windows/macOS mounts before advertising them. |
| Five-word pairing | `in_progress` | Active daemon, direct-browser, and One Setup ceremonies use one curated five-word vocabulary. Both One Setup devices independently derive the phrase from the one-use invite secret and both public keys; the browser rejects version/key/phrase/vector mismatches and does not persist the bearer token. First-contact calls now fail closed if a transcript-bound phrase cannot be derived. | Real camera/QR and manual pairing on two physical devices, MITM/replay/key-swap tests, accessibility/read-aloud checks, measured completion distribution. |
| Recovery and identity rotation | `partial` | Phrase, bundle, threshold/social recovery and crash-safe transactional rotation are implemented locally. | Offline multi-device guardian enrollment/revocation/refresh drills plus packaged crash/tamper/power-loss matrix on every platform. |
| Post-quantum sessions | `in_progress` | The live v3 daemon channel now signs hybrid-suite negotiation, combines independent X25519 and FIPS-203 ML-KEM-768 secrets, binds the transcript, mutually confirms the derived key, rejects replay and refuses classical/legacy downgrade by default. Runtime advertisement is conditional on a native ABI self-test. | Expose the negotiated suite per live chat; packaged native availability on every platform; cross-version migration matrix and long physical-network qualification; no classical session may be advertised as PQ. |
| Three-hop Sphinx routing | `partial` | Fixed-size Sphinx/onion primitives and real local cover-packet round trips exist. Application messages/files do not yet traverse three independently operated hops. | Authenticated rotating relay directory, replay/padding/cover/failure recovery, real payload routing, independent operators and multi-vantage packet-capture metadata analysis. |
| Sealed sender / hidden participants | `partial` | The default daemon relay path now uses authenticated rotating pairwise tags and seals both identity-bearing channel first flights. A real two-daemon relay capture proves neither Ed25519 public key appears in v2 URLs, control state, route tables, logs, or forwarded DATA; legacy identity routing is an explicit opt-in downgrade. This is recipient-identifier blinding, not sender anonymity: the relay still observes socket IPs, timing, sizes, duration, route-set linkage and approximate peer count. | Independent multi-vantage captures, abuse controls and operational retention proof; traffic-analysis resistance and independently operated multi-hop payload routing before claiming anonymity or hidden participants. |
| Automatic authenticated updates | `in_progress` | Explicit owner-confirmed installation is implemented only for a locally proven frozen standalone bundle. A fixed external helper independently authenticates exact-tag release metadata and artifacts, coordinates recovery/update authority, waits for quiescence, performs A/B activation, requires daemon/UI health, and rolls back on failure. Source, pip, incomplete, moved, or modified installs fail closed. Update polling remains notification-only and unattended/background installation remains disabled. | Publish an immutable signed release, exercise the frozen helper on every packaged platform, retain crash injection and rollback evidence for every transaction boundary, and prove restart/health behavior on physical machines. |
| Signed reproducible releases | `partial` | Only mutable prerelease `auto-latest` exists; it is not production authority and lacks complete Sigstore/SBOM/provenance evidence. | Clean immutable `v*` tag, every gate green, platform signatures, signed checksums, SBOM, artifact-bound provenance, independent rebuild and post-download verification. |
| Platform availability | `partial` | Rolling desktop artifacts cover several architectures; macOS Intel and mobile artifacts are not currently authoritative releases. | Build, sign, install, launch, update, rollback and uninstall on every listed OS/architecture; download routing must match artifact architecture exactly. |
| No central message store | `partial` | Normal daemon communication is direct-first with optional encrypted relay; browser temporary sharing intentionally stores ciphertext in provider storage. | Scope every surface, prove deletion/retry/expiry behavior, publish provider/backup limits, and avoid applying daemon claims to browser sharing. |
| "Collect nothing" / no metadata | `partial` | Product analytics are absent, but network providers and optional infrastructure process ordinary IP/timing/size data; website rate limits and presence maintain bounded state. | Minimize, document and enforce fields/retention; privacy review and deletion proofs. Absolute zero-processing language requires an architecture that actually makes it true. |
| Live mesh/topology | `partial` | Local personal-device mesh exists. Public website-presence dots are not authenticated routing nodes, and public topology currently has no provisioned node/relay authority. | Signed expiring node attestations, Sybil controls, authenticated aggregate topology, real relays, freshness and failure proofs. |
| Hardware-backed keys | `partial` | Hardware TOFU/native primitives exist; persistent production platform backends are incomplete. | TPM/Secure Enclave/Keychain-backed non-exportable key lifecycle, migration/recovery and packaged hardware matrix. |
| Duress mode | `partial` | Native/formal/test primitives exist; complete daemon/UI policy wiring is not proven. | End-to-end activation, false-positive resistance, revocation/recovery, audit/privacy behavior and physical-device drills. |
| Formal verification on every change | `in_progress` | All 14 committed models now parse and exhaustively pass their documented finite instances under SHA-256-pinned TLC 1.7.4; the complete local manifest gate passed 14/14 in 113.74 s. CI blocks every push/PR and tagged release, rejects inventory/module/config drift, records Java/model/config/log hashes, and binds hosted evidence to `GITHUB_SHA`. These proofs cover only their named abstractions; for example self-routing does not yet prove max-min search or pruning, and adversarial fan-out safety does not imply liveness under unlimited loss. | Obtain a green hosted run for an immutable release and retain its artifacts; add executable max-min/prune and fair-delivery models before making those narrower claims; keep every public statement scoped to the finite state machines rather than the implementation or whole product. |
| Fuzzing and security audit counts | `partial` | Extensive fuzz/property/adversarial tests exist, but public numeric claims are not generated from versioned job artifacts; no external product audit has occurred. | Machine-generated counts/results at the release commit, retained corpora/crashes/sanitizer logs, and independent audit with remediations. |
| Performance/scale claims | `partial` | Recorded solver and transfer microbenchmarks are not equivalent to live routing-network scale. | Versioned scenario, hardware, build, dataset and raw results; distinguish primitive microbenchmarks from end-to-end network throughput. |
| Cryptographically verified website | `partial` | The deployed manifest is signed but stale; deployed Service Worker paths can serve/cache unverified network bytes. | Verify every byte before serve/cache, fail closed without trusted fresh metadata, sign final bundle, and post-deploy hash every route/asset. |

## Release-wide blocking gate

No website capability may be marked complete until a single immutable commit has:

- a clean worktree and reproducible dependency lock;
- all Python, Rust, browser, native, packaging, formal, fuzz, security and
  end-to-end gates green;
- packaged physical-device results for every advertised platform and route;
- signed artifacts, checksums, SBOM and provenance bound to that commit;
- independent rebuild and download verification evidence;
- a generated signed capability attestation consumed by the website;
- a post-deploy asset/route integrity audit;
- an external security review for any wording that says externally audited.

Until then the product status is `partial`, regardless of primitive depth.
