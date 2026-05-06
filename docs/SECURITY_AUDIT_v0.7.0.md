# One Link Security Audit - v0.7.0

Status: in_progress

This audit reviewed the current `origin/master`/`v0.7.0` codebase after the
Linked Mesh changes, with emphasis on preserving One Link's advanced P2P
features while closing trust-boundary gaps.

## Scope

- Local UI server and browser token access.
- LAN discovery and mDNS rendezvous inheritance.
- Pairing, peer trust state, capability exchange, and endpoint updates.
- Direct encrypted peer channel, relay fallback, rendezvous registration,
  relay listen/connect flow, chat, file transfer, folder sync, CDC cache,
  group event logs, group sender chains, and linked mesh controls.
- Persistence security in SQLite state, upload staging, received files,
  group messages, and audit trails.

## Fixes Landed In This Pass

### 1. Ambient mDNS rendezvous inheritance now requires explicit opt-in

Severity: high

Previous behavior:

- If local rendezvous URLs were empty, any LAN peer advertising an `rdz`
  mDNS TXT value could cause this device to save those rendezvous URLs and
  immediately register there.
- mDNS is ambient and unauthenticated, so a hostile LAN actor could steer a
  fresh device toward attacker-controlled rendezvous infrastructure.

Fix:

- `Daemon._maybe_inherit_rendezvous_from_mdns()` now requires
  `inherit_rendezvous_from_mdns=true`.
- Pinned-peer CAPS rendezvous inheritance remains enabled by default, so the
  easy trusted path is preserved.

Security upgrade:

- Zero-friction inheritance remains available after trust exists.
- Lower-trust LAN bootstrap is still supported, but only as an intentional
  mode.

Regression coverage:

- mDNS inheritance disabled by default.
- mDNS inheritance still works when explicitly opted in.
- Invalid protocols remain filtered.

### 2. Group key offers are bound to current group membership

Severity: high

Previous behavior:

- A pinned peer could send `GROUP_KEY_OFFER` for a group without proving that
  the signed group event log currently includes that peer as a member.
- This let transport trust bleed into group authorization.

Fix:

- Added group-state materialization helpers on the daemon.
- `_handle_group_key_offer()` now rejects key material from pinned peers that
  are not current members of the target group.

Security upgrade:

- Sender-chain material is accepted only when peer trust and group membership
  both agree.

Regression coverage:

- Pinned non-member key offer returns `ACK rejected=group_not_member`.
- No inbound sender chain is persisted.

### 3. Group messages are checked against current membership at receive time

Severity: high

Previous behavior:

- If an inbound sender chain existed, a pinned peer could keep sending group
  messages even if it was not in the current reduced group state.

Fix:

- `_handle_group_msg()` now rejects messages from pinned peers that are not
  current group members before chain lookup/decrypt/persist.

Security upgrade:

- Stale or injected sender chains cannot keep a removed/non-member sender
  alive.

Regression coverage:

- Pinned non-member group message returns `ACK rejected=group_not_member`.
- No message is inserted and the chain counter is not advanced.

### 4. Rendezvous server no longer trusts X-Forwarded-For by default

Severity: medium-high

Previous behavior:

- A directly exposed rendezvous server trusted `X-Forwarded-For`.
- A client could spoof source IP identity and weaken per-IP rate limiting and
  observed-endpoint accuracy.

Fix:

- Added `ServerConfig.trust_proxy_headers=False`.
- Added CLI flag `--trust-proxy-headers` for controlled reverse-proxy
  deployments.
- `_client_ip()` now uses socket peer IP unless proxy trust is explicitly
  enabled.

Regression coverage:

- Registering with spoofed `X-Forwarded-For` still reports `127.0.0.1` in the
  default server configuration.

### 5. Relay listener auth has nonce replay defense

Severity: medium-high

Previous behavior:

- Relay listen auth was signed and timestamp-bound, but the rendezvous server
  did not remember used nonces.
- A captured listen auth blob could be replayed inside the timestamp window
  to try to reclaim a listener slot.

Fix:

- Added per-pubkey relay listen nonce cache.
- Replayed listen nonce is rejected before replacing an existing listener.
- Nonce cache is swept on the existing server maintenance loop.

Regression coverage:

- Replaying the same `ListenAuth` over a second WebSocket is closed with
  relay auth rejection and does not replace the active listener.

### 6. Endpoint updates now use verified candidate promotion

Severity: high

Previous behavior:

- A pinned peer can advertise endpoint updates that are saved as direct dial
  targets. The encrypted peer handshake prevents impersonation, but the app
  may still be steered into unwanted connection attempts or stale route churn.

Fix:

- Endpoint updates are queued as route candidates.
- The daemon opens a bounded connection to each candidate and runs the normal
  encrypted peer handshake.
- The route is promoted into `peers.last_address/last_port` only if the
  endpoint proves the expected fingerprint.

Security upgrade:

- Pinned peers can still act as one and share fresh route intelligence, but
  route persistence now requires possession of the peer key at the announced
  address.

Regression coverage:

- Endpoint update queues verification without immediate route overwrite.
- Verified handshake promotes the route.
- Flooded endpoint updates remain capped.

### 7. Browser UI query token is now one-time page bootstrap only

Severity: medium-high

Previous behavior:

- The local UI accepts `?t=` query tokens. Query tokens can leak through
  browser history, screenshots, local logs, or referrers if a future external
  link is added.

Fix:

- Plain `GET /` no longer hands out the UI auth cookie.
- `?t=` is accepted only on `GET /` and only to set the HttpOnly/SameSite
  cookie.
- The returned page injects `history.replaceState` to scrub the token from the
  address bar.
- API and WebSocket routes reject query tokens; they require cookie or
  Authorization header auth.
- Bootstrap responses are `Cache-Control: no-store` and `Referrer-Policy:
  no-referrer`.

Regression coverage:

- Query token bootstraps index and sets cookie.
- Query token does not authorize `/api/me`.
- WebSocket tests now authenticate by header instead of query string.

### 8. Upload staging cleanup now covers multipart read failures

Severity: medium

Previous behavior:

- File upload staging is cleaned after normal send attempts, but multipart
  read failures can leave partial staging files.

Fix:

- Multipart read/write is wrapped so partial staging files are deleted on
  exception before send.
- Staged upload filenames include random entropy, not only timestamp and
  original name.

Next upgrade:

- Add startup prune for old staging files.
- Add per-transfer disk budget and backpressure reporting in the Activity UI.

### 9. Rendezvous register/revoke exact replay cache

Severity: medium

Previous behavior:

- Register/revoke requests were signed and timestamp-bound, but an exact
  captured request could be replayed inside the timestamp window.

Fix:

- Added a bounded signed-message replay cache keyed by request kind and
  pubkey.
- Exact duplicate register/revoke signatures are rejected inside the replay
  window.
- The cache is swept by the existing server maintenance loop.

Security upgrade:

- Existing clients remain wire-compatible, while the server closes the
  practical unmodified replay path.

Regression coverage:

- Exact signed register replay returns `409`.
- Exact signed revoke replay returns `409`.

### 10. Channel transcript binding in keys, AEAD, and CAPS

Severity: high

Previous behavior:

- The channel authenticated peer identity and encrypted frames, but higher
  layers had no explicit transcript binding to inspect.

Fix:

- The handshake transcript hash is computed as `SHA256(HELLO || REPLY)`.
- HKDF key derivation includes the transcript hash.
- AEAD associated data includes the transcript hash.
- CAPS now carries an encrypted `channel_bind` claim with self fingerprint,
  peer fingerprint, transcript hash, and feature list.
- Receivers verify CAPS channel binding before accepting peer capabilities.

Security upgrade:

- Session keys and first encrypted control metadata are bound to the exact
  handshake transcript, reducing protocol-confusion and channel-splicing risk.

Regression coverage:

- Both sides compute the same transcript hash.
- Fresh handshakes produce different transcript hashes.
- Existing channel, relay, and linked mesh tests pass.

### 11. Folder sync has per-peer root capability modes

Severity: high

Previous behavior:

- `shared_with` meant a peer had folder-sync access, but it did not describe
  directionality.

Fix:

- Each shared folder peer now has an explicit mode:
  - `push`: this device may send this folder to the peer.
  - `pull`: this device may accept remote changes from the peer.
  - `rw`: both directions, preserving the existing paired-device experience.
- Inbound `MANIFEST_PUSH` requires `pull`.
- Outbound folder push and `MANIFEST_WANTS` blob service require `push`.
- The folder API accepts `mode` on share and exposes `peer_permissions`.

Security upgrade:

- Folder roots become scoped capabilities instead of an all-or-nothing shared
  list. Users can keep devices acting as one with `rw`, or lock a peer to
  one-way backup/mirror behavior.

Regression coverage:

- State tests cover default `rw`, one-way `push`, and permission cleanup on
  unshare.
- Folder sync/server suites pass with compatibility defaults.

## Remaining Findings And Advanced Fix Plan

### A. Capability policy should become deny-by-default per sensitive surface

Severity: medium

Risk:

- Capabilities exist, but user intent should be clearer for files, folders,
  group sync, relay, endpoint update, and future transports.

Solution:

- Split capability policy into `advertised`, `peer_requested`,
  `user_allowed`, and `session_negotiated`.
- Default chat to allowed after pairing; default files/folders/group mutation
  to prompt/allowlist.
- Add signed capability-policy audit events so devices can explain why an
  action was allowed.

### B. Folder sync needs path capability sandboxes

Severity: medium

Risk:

- Folder sync is powerful. Every local path should have a durable scoped
  capability, never a raw implicit permission.

Solution:

- Model each sync root as a capability object with `root_id`, canonical path,
  direction, peer allowlist, max file size, ignored patterns, and conflict
  policy.
- Require explicit user approval for a peer to write into a root.
- Keep Merkle/CDC efficiency, but bind every remote write to a root
  capability and append-only audit event.

### C. Release/package security should add supply-chain gates

Severity: medium

Risk:

- The project is intended for broad public use. Build outputs need repeatable
  provenance as the app grows.

Solution:

- Add pinned lockfiles for release builds.
- Generate SBOM.
- Sign release artifacts.
- Add CI checks for `pip-audit`, `bandit` targeted rules, test suite, and
  reproducible PyInstaller build metadata.

## Verification

Targeted security tests:

```powershell
python -m pytest tests/test_groups_wire.py tests/test_rendezvous_inherit.py tests/test_rendezvous_server.py tests/test_relay_e2e.py tests/test_server.py tests/test_linked_mesh_v070.py -q
```

Result:

```text
105 passed in 63.88s
```

Full regression suite:

```powershell
python -m pytest -q
```

Result:

```text
557 passed in 239.75s
```
