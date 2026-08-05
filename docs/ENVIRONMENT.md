# Environment variables

Every `ONE_LINK_*` variable the shipped source reads, what it does, and what
happens if you set it wrong.

**One Link needs none of these.** The shipped defaults are the supported
configuration. This file exists because a switch nobody can read about is a
switch nobody can audit — an earlier version of the codebase read
`ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE`, which disables post-quantum key
agreement, with zero tests and zero documentation, while the product's own
refusal message told operators to set it.

`tests/test_no_dark_env_switches.py` compares the switches the source reads
against this file, the tests, the workflows and the shipped web assets, and
fails if a new one appears that none of them mention. So this list cannot
silently fall behind the code.

---

## Read this first: the switches that weaken security

These turn a protection **off**. None should be set on a machine you care
about. Each is listed with what protection it removes.

| Variable | Default | What setting it gives up |
|---|---|---|
| `ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE` | off | Drops ML-KEM-768 from the handshake, leaving X25519 alone. Removes protection against **harvest-now-decrypt-later**: traffic recorded today stays decryptable by a future quantum adversary. Requires exactly `1`. |
| `ONE_LINK_ALLOW_V1_HELLO` | off | Accepts a v1 hello with no expected responder key, so the channel is not bound to a specific peer identity. Same consequence class as above. Requires exactly `1`. |
| `ONE_LINK_ALLOW_LEGACY_RELAY_IDENTITY_ROUTE` | off | Re-enables a superseded relay identity route for mixed-version migration. Accepts `1`, `true`, `yes`, `on`, and can also be enabled by a stored setting. |
| `ONE_LINK_ALLOW_SAME_HOST_PEERS` | off | Lets the discovery layer treat processes on the same host as remote peers. Intended for multi-instance testing; it weakens an assumption the peer model relies on. |
| `ONE_LINK_ENABLE_TEST_API` | off | Exposes the test-only HTTP API. Never set this on a machine reachable by anyone else. Requires exactly `1`. |
| `ONE_LINK_DEV_HOOKS` | off | Enables developer hooks inside the daemon. Requires exactly `1`. |
| `ONE_LINK_ALLOW_FIXED_COURIER_TARGETS` | off | Offers **fixed** drives as courier targets, not just removable ones. The code comment is explicit that production must not spray courier files onto `C:`. Requires exactly `1`. |
| `ONE_LINK_ALLOW_NATIVE_PATH_CREATE` | off | Permits the native path-creation route that is otherwise refused. Requires exactly `1`. |

Two of these — `ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE` and `ONE_LINK_ALLOW_V1_HELLO`
— are the same switch pair in the same function. They must be considered
together: covering one and not the other is how the gap arose in the first
place.

### Switches that make security *stricter*

Safe to set. They only ever refuse more.

| Variable | Default | Effect |
|---|---|---|
| `ONE_LINK_REQUIRE_ATTESTED_PEERS` | off | Refuse peers that cannot present attestation. |
| `ONE_LINK_REQUIRE_BROWSER_IDENTITY_POSSESSION` | off | Require the browser to prove possession of the identity key. |
| `ONE_LINK_REQUIRE_FILE_ACCEPT` | stored setting | Force explicit acceptance of every inbound file, overriding the stored preference. |

---

## Paths and process

| Variable | Default | Effect |
|---|---|---|
| `ONE_LINK_HOME` | platform data dir | Root of the data directory: database, identity, blobs. Point it at a different directory to run an isolated instance. **This is where your data lives** — see [Backup and restore](#backup-and-restore). |
| `ONE_LINK_BIND_HOST` | loopback | Host the UI and control server bind to. Set by the app itself; overriding it can expose the local UI beyond loopback. |
| `ONE_LINK_AUTO_OPEN` | off | Open a browser on start even when the CLI was told not to. Requires exactly `1`. |
| `ONE_LINK_SUPERVISED` | off | Marks the process as supervised by a parent, changing restart behaviour. Requires exactly `1`. |
| `ONE_LINK_UPDATE_CHECK` | stored policy | Overrides whether the daemon may make update-check network calls. Sovereignty policy still applies. |

## Discovery, transport and relays

| Variable | Default | Effect |
|---|---|---|
| `ONE_LINK_QUIC_TRANSPORT` | `1` (on) | Set to exactly `0` to disable QUIC and force fallback transports. Read at three sites in `daemon.py`. |
| `ONE_LINK_NATIVE_TRANSFER` | `1` (on) | Set to `0` to use the Python transfer path instead of the native one. Slower; useful when isolating a native-extension fault. |
| `ONE_LINK_MDNS_SERVICE_TYPE` | product default | Overrides the mDNS service type. Peers only find each other if they agree, so changing it on one machine hides it from every other. |
| `ONE_LINK_STUN_SERVERS` | built-in list | Comma-separated STUN URLs for WebRTC. |
| `ONE_LINK_TURN_SERVERS` | none | Comma-separated TURN URLs. |
| `ONE_LINK_TURN_USERNAME` | stored setting | TURN username, used when no stored setting exists. |
| `ONE_LINK_TURN_CREDENTIAL` | stored setting | TURN credential. A relay credential taken from the process environment is visible to anything that can read the environment — prefer the stored setting. |
| `ONE_LINK_TURN_SHARED_SECRET` | stored setting | Shared secret for time-limited TURN credentials. |
| `ONE_LINK_TURN_TTL_SECONDS` | `3600` | Lifetime of a minted TURN credential. Clamped to `[300, 86400]`. |
| `ONE_LINK_RELAY_PROBE_TIMEOUT_SECONDS` | `1.5` | Relay reachability probe timeout. Clamped to `[0.3, 5.0]`; the low end makes a healthy relay on a slow link look unreachable. |
| `ONE_LINK_RDZ_DEFAULTS` | none | Default rendezvous servers. |

## Peer and resource bounds

| Variable | Default | Effect |
|---|---|---|
| `ONE_LINK_MAX_PEERS` | `256` | Global cap on concurrent peer connections; the bound against a coordinated fan-in. Clamped to `[1, 65536]` — a ceiling of `0` would accept nobody, which reads as a network fault rather than a configuration one. |
| `ONE_LINK_MAX_PEERS_PER_FP` | `4` | Per-fingerprint connection cap, so one key cannot wedge the global cap. Clamped to `[1, 4096]`. |
| `ONE_LINK_FOREGROUND_ACK_DEADLINE_S` | `2.0` | Deadline for a foreground chat/control acknowledgement before the session is dropped and retried. Clamped to `[0.1, 60.0]`. |
| `ONE_LINK_QUIC_FRAME_DEADLINE_S` | `2.0` | Bounds one-off QUIC frame probes so a dead cached path cannot block the user-facing fast path. Clamped to `[0.1, 60.0]`. |
| `ONE_LINK_UI_UPLOAD_IDLE_TIMEOUT_SECONDS` | `30` | Idle timeout for a UI upload. Clamped to `[1, 300]`; the low end aborts legitimate slow uploads. |

> **Malformed values never crash the daemon.** All five parse through
> `one_link.env_bounds`, which falls back to the shipped default and logs a
> warning naming the variable. Before 2026-08-05 these were bare
> `int(os.environ.get(...))` calls at module scope, so `ONE_LINK_MAX_PEERS=abc`
> raised at import — the process could not start, and the traceback was the only
> thing that said why. `ONE_LINK_MAX_PEERS=0` was accepted silently.

## Sync and folder behaviour

| Variable | Default | Effect |
|---|---|---|
| `ONE_LINK_FOLDER_CRDT_NATIVE` | `0` | Use the native CRDT implementation for folder sync. |
| `ONE_LINK_RECONCILE_DISAGREEMENTS_ACKED` | internal | Number of disagreements acknowledged per reconciliation pass. Changes convergence behaviour on conflict. |
| `ONE_LINK_BLOOM_FP_RATE` | internal | False-positive rate for the availability Bloom filter. Higher means more wasted requests; lower means more memory. |
| `ONE_LINK_BLOOM_HONOR` | internal | Whether a peer's advertised Bloom filter is honoured. |
| `ONE_LINK_COURIER_MEDIA_ROOTS` | none | Extra directories offered as courier targets, in addition to detected removable drives. |

## Selection, research and diagnostics

Off by default. Enabling them changes behaviour without changing any security
property.

| Variable | Default | Effect |
|---|---|---|
| `ONE_LINK_SELECTOR_KIND` | `smart_rules` | Which transport selector to use. |
| `ONE_LINK_SMART_SELECTOR` | internal | Smart-selector toggle. |
| `ONE_LINK_SMART_SELECTOR_ENFORCE` | `0` | Turns the selector from **advisory** into **enforcing**, so it can refuse a transport the user asked for. |
| `ONE_LINK_BANDIT_ROUTE_PICKER` | `1` (on) | Set to `0` to disable the bandit route picker and use fixed route preference. |
| `ONE_LINK_COVER_TRAFFIC` | `0` | Generate cover traffic. Changes what an observer sees on the wire, and costs bandwidth. |
| `ONE_LINK_WAVE_FORECAST` | `0` | Research feature, shipped disabled. Starts a periodic forecast tick on the daemon event loop. |
| `ONE_LINK_WAVE_FORECAST_DT` | `0.5` | Forecast tick cadence in seconds. Clamped to `[0.05, 3600]`; a tiny value starves other event-loop work. |
| `ONE_LINK_CASCADE_THRESHOLD` | `0.5` | Threshold at which mesh-stress cascade warnings fire. Deliberately **not** clamped at the top, because a large value is a legitimate way to mute the warning. |
| `ONE_LINK_RADIO_BATCHER` | `0` | Enable the radio batcher. |
| `ONE_LINK_CALL_RESUME` | off | Call-resume behaviour. |
| `ONE_LINK_FIELD_PREFETCH_DISABLE` | off | Disable field prefetch. |
| `ONE_LINK_FIELD_HOMOLOGY_DISABLE` | off | Disable field homology computation. |

## Native extension and desktop integration

| Variable | Default | Effect |
|---|---|---|
| `ONE_LINK_DISABLE_NATIVE_CDC` | off | Fall back to the Python content-defined chunker. |
| `ONE_LINK_CC` | `CC`, then platform default | C compiler used when building the native CDC extension. Build-time only. |
| `ONE_LINK_DISABLE_NATIVE_PICKER` | off | Use the in-page file picker instead of the OS dialog. |
| `ONE_LINK_DISABLE_PATH_CREATE_LAUNCH` | off | Disable launching a created path. Requires exactly `1`. |
| `ONE_LINK_DISABLE_NATIVE_PATH_CREATE` | off | Disable native path creation. Requires exactly `1`. |
| `ONE_LINK_DISABLE_REVEAL` | off | Disable "reveal in file manager". Requires exactly `1`. |

---

## How values are parsed

Parsing is **not** uniform, and the differences are deliberate:

- **Security switches require exactly `1`.** `ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE=true`
  does **not** disable post-quantum key agreement. A downgrade should be hard to
  trigger by accident.
- **Operator switches accept a token set** — `1`, `true`, `yes`, `on`, case- and
  whitespace-insensitive — because a human types them.
- **Numeric knobs clamp and warn.** Out of range is pulled to the nearest legal
  bound; unparseable falls back to the default. Both log a warning naming the
  variable. `inf` and `nan` are rejected even though `float()` accepts them: an
  infinite deadline is indistinguishable from a hang, and `nan` makes every
  comparison false, so a timeout set to either stops being a timeout.
- **Empty is treated as unset**, not as a parse error, because
  `export ONE_LINK_MAX_PEERS=` is a common shell accident.

Anything malformed **fails closed**: the protection stays on, the default stays
in force.

---

## Backup and restore

Everything One Link cannot rebuild lives under one directory — the platform data
directory, or `ONE_LINK_HOME` if you set it.

```
$ONE_LINK_HOME/
  state.db          identity, chat history, peer trust, folder manifests
  blobs/            content-addressed file data
```

**To back up:** stop One Link, copy the whole directory. Copying `state.db` while
the daemon is running can capture a torn write — SQLite's WAL means the `.db`
file alone may not be a complete database.

**To restore:** stop One Link, replace the directory, start it. The schema
migrates forward automatically on first boot; a database written by any earlier
release migrates to current without data loss
(`tests/test_migration_from_oldest_schema.py` runs the full 30-step ladder
against a populated v1 database on every CI run).

**Migration is forward-only.** A database opened by a newer build will not
downgrade. If you need to go back to an older release, restore the backup you
took before upgrading — which is the reason to take one.

## Updates and rollback

The in-app updater is transactional. It stages the new build beside the old one,
activates it by rename, and **commits only after the new version starts and
passes a health probe**. If it does not, the previous build is restored
automatically.

- Your data is untouched by both paths. The update replaces the install
  directory only; `tests/test_update_preserves_user_data_e2e.py` asserts the
  database is byte-identical after a commit *and* after a rollback.
- If the machine loses power mid-update, the next start replays the journal and
  either resumes or rolls back — never a half-installed tree.
- To roll back deliberately, install the older release over the current one.
  There is no "undo last update" command; the automatic rollback exists for
  updates that fail, not for updates you regret.
