# We Are One: One Link Master Plan

Status: in_progress
Last updated: 2026-05-07

This document captures the long-term doctrine for One Link so the vision does not get diluted into "another chat app." One Link is meant to become a free, open, user-owned mesh layer where people can communicate, move files, preserve data, sync devices, and eventually share compute without being dependent on corporate accounts, corporate clouds, or platform gatekeepers.

The short version:

> Send anything. Keep everything. Trust your people. Own the network.

The deeper version:

> Your devices and trusted people act as One: one identity fabric, one private network, one encrypted memory, one storage layer, one resilient transfer engine, and one local-first foundation for future apps.

---

## 1. Mission

One Link exists to remove corporate leverage from ordinary digital life.

Today, most useful digital relationships depend on someone else's server:

- A phone number or email account controlled by a provider.
- A cloud drive subscription.
- A centralized chat platform.
- A corporate identity provider.
- A CDN or app store.
- A server-side data model that the user cannot inspect, export, fork, or replace.

One Link should replace that assumption with a people-owned substrate:

- No required account.
- No required cloud storage.
- No required company server.
- No required app-store gatekeeper.
- No artificial size limit.
- No forced platform lock-in.
- No central data harvest.
- No single point of failure.

One Link should make the advanced thing feel simple:

> Pick a trusted person or one of your devices. Send anything. If the network breaks, it keeps trying. If a device sleeps, it waits. If another trusted device has the chunks, it helps. If versions differ, it falls back. If the internet disappears, the local mesh still works.

---

## 2. Product Promise

The first public promise must be narrow enough to prove, but powerful enough to matter:

> One Link sends huge files, messages, and folders between your devices and trusted people without cloud storage, and it resumes automatically until the data arrives.

That promise expands into:

- Send any file type.
- Send very large files.
- Resume after disconnects.
- Resume after process restart.
- Resume after device sleep.
- Verify every byte.
- Skip chunks the receiver already has.
- Work across compatible versions.
- Work locally without internet.
- Use optional blind relays only when direct paths fail.
- Let people self-host any assistive infrastructure.

The user should not have to understand "chunks," "capabilities," "Merkle trees," "replay windows," or "rendezvous." Those are internal powers. The user experience is simple: it gets there.

---

## 3. Non-Negotiable Principles

### 3.1 User-Owned Identity

Identity must belong to the user and their devices, not to an account provider.

Requirements:

- Device identity is cryptographic.
- User identity can span multiple devices.
- Adding a device should be local, human-verifiable, and account-free.
- Losing a device should not destroy the identity.
- Key changes must be visible and hard to spoof.
- Identity should be exportable, recoverable, and portable.

### 3.2 Local-First Operation

One Link should use the internet when helpful, but not depend on it for the core relationship.

Requirements:

- LAN discovery and transfer work without a central server.
- Local history lives locally.
- Local files remain usable without remote availability.
- Groups and device state are represented as signed local events.
- The app should degrade gracefully when offline.

### 3.3 P2P First, Blind Relay When Needed

Direct peer paths should be preferred. Relays are only path helpers.

Requirements:

- Relays never see plaintext.
- Relays should not need user accounts.
- Relays should be self-hostable.
- Relay use must be replaceable and optional.
- Rendezvous and relay protocols must be documented and open.

### 3.4 Content-Addressed Everything

Every durable object should be identified by what it is, not where it happens to live.

Requirements:

- File chunks are addressed by cryptographic hash.
- Whole files have verifiable manifests.
- Folders have Merkle roots.
- Attachments can be deduplicated across chats, groups, and folders.
- Renames should not force retransmission.
- Duplicate files should be detected without uploading them anywhere.

### 3.5 Resumable Forever

Transfers should be durable promises, not fragile socket events.

Requirements:

- Every transfer has a ledger.
- Completed chunks survive restart.
- Missing chunks are requested again.
- Corrupt chunks are rejected and retried.
- The UI shows the truth without making the user babysit the transfer.
- Failure should mean "paused, waiting for a path" whenever recovery is possible.

### 3.6 Compatible By Design

Version mismatch should not break baseline communication.

Requirements:

- Peers negotiate capabilities.
- Unknown optional features are ignored safely.
- Old peers can still receive baseline chat and file transfer.
- New peers use advanced features when both sides support them.
- Hard failure is reserved for true cryptographic or protocol impossibility.

### 3.7 Security That Does Not Punish Normal People

Security should be strong by default and understandable when action is needed.

Requirements:

- End-to-end encryption for all peer data.
- Signed identity and group events.
- Replay protection.
- Safety number or equivalent human verification.
- Key-change warnings.
- Per-peer and per-group permissions.
- Least authority for relays and local APIs.
- No scary jargon as the default UI.

### 3.8 Open Protocol, Open Implementation

The protocol matters more than one UI.

Requirements:

- Protocol documentation lives in the repo.
- Wire compatibility tests are treated as release gates.
- Third-party clients should be possible.
- Self-hosted infrastructure should be first-class.
- Data export must be possible.

---

## 4. The Core Thesis

One Link should not become a Discord clone, Signal clone, AirDrop clone, Syncthing clone, or Dropbox clone.

It should become a user-owned mesh substrate:

- Like Signal for trust and cryptography.
- Like Syncthing for local-first sync.
- Like AirDrop for ease.
- Like BitTorrent for swarm transfer.
- Like IPFS for content-addressed objects.
- Like a personal cloud, but owned by the person.
- Like a distributed operating layer for trusted devices.

The strongest thesis:

> One Link replaces the assumption that modern digital life requires company-owned servers in the middle.

---

## 5. System Model

One Link is built from seven major layers.

### 5.1 One Identity

Purpose:

Represent a person and their devices without a corporate account.

Core objects:

- Device keypair.
- Device fingerprint.
- User identity root.
- Device cluster membership.
- Recovery material.
- Verified-person trust edges.
- Revocation events.

Required behavior:

- Pair a device locally.
- Promote multiple devices into one identity cluster.
- Revoke a lost device.
- Detect unexpected key replacement.
- Export identity backup.
- Import identity backup with human confirmation.

Advanced behavior:

- Threshold recovery from trusted devices.
- Hardware-backed local key storage when available.
- Post-quantum hybrid identity upgrade path.
- Device roles: phone, laptop, desktop, storage node, relay node, emergency node.

### 5.2 One Trust

Purpose:

Represent who and what the user trusts, with explicit scope.

Core objects:

- Trust edge.
- Capability grant.
- Verification record.
- Key-change event.
- Block/revoke event.
- Trust score.
- Behavioral history.

Required behavior:

- Trust is not the same as reachability.
- Paired devices remain trusted across networks.
- Permissions can be granted by feature: chat, files, folders, groups, relay, storage, compute.
- Trust can decay when a peer behaves strangely.
- Sensitive actions require stronger trust.

Advanced behavior:

- Trust gravity: owned devices are strongest, verified friends next, unverified peers inert.
- Local anomaly detection based on link behavior, key changes, replay attempts, and impossible state transitions.
- Capability tokens with expiration.
- Delegated trust for group admins.

### 5.3 One Memory

Purpose:

Represent messages, files, folder changes, group events, and device state as one encrypted event graph.

Core objects:

- Signed event.
- Event ID.
- Causal parent set.
- Vector clock or equivalent causal marker.
- Conversation log.
- Group log.
- File manifest event.
- Folder drift event.
- Trust event.

Required behavior:

- Events are append-only.
- Edits and deletes are new signed events.
- Events are encrypted according to conversation or group policy.
- Conflict handling is deterministic.
- Local history survives restart.

Advanced behavior:

- Shared encrypted event logs across a user's own devices.
- Offline group events that merge later.
- Portable export/import.
- Event provenance and audit view.
- Local-only search over decrypted owned data.

### 5.4 One Storage

Purpose:

Store and retrieve objects by content, not by platform.

Core objects:

- Blob.
- Chunk.
- Manifest.
- Merkle tree.
- Erasure-coded shard.
- Chunk availability record.
- Local cache index.
- Repair record.

Required behavior:

- Chunk writes are atomic.
- Hash verification is mandatory.
- Partial writes never appear complete.
- Missing chunks are visible to the transfer planner.
- Duplicate chunks are stored once.
- Cache integrity can be audited.

Advanced behavior:

- Erasure coding so data survives missing devices.
- Encrypted storage on untrusted helper devices.
- Local storage quotas and eviction policy.
- "Keep alive" policy for important files.
- "Repair this file" from trusted devices.
- "This file is safe on 3 devices" safety status.

### 5.5 One Transfer Engine

Purpose:

Move data reliably across unstable networks and mismatched capabilities.

Core objects:

- Transfer intent.
- Transfer ledger.
- Chunk plan.
- Wants list.
- Capability negotiation result.
- Route candidate.
- Transport session.
- Integrity proof.

Required behavior:

- Send baseline files to old compatible peers.
- Use CDC when supported.
- Resume missing chunks.
- Retry with backoff.
- Verify final file hash.
- Show progress, pause, resume, and completion truthfully.

Advanced behavior:

- Swarm transfer from multiple trusted devices.
- Multi-path transfer over LAN plus relay or other routes.
- Predictive pre-chunking for likely sends.
- Opportunistic prefetch for owned devices.
- Adaptive timeout using observed RTT, jitter, and file size.
- FEC/parity for lossy links.
- Streaming playback while file arrives.

### 5.6 One Mesh

Purpose:

Find peers, route data, and survive network change.

Core objects:

- Peer registry.
- Endpoint advertisement.
- Link health.
- Route candidate.
- Rendezvous registration.
- Relay envelope.
- Delay-tolerant courier bundle.

Required behavior:

- LAN discovery.
- Stable peer identity despite changing IP/port.
- Ghost/self peer suppression.
- Stale peer expiration.
- Structured reachability status.
- Optional rendezvous for internet reachability.
- Optional blind relay fallback.

Advanced behavior:

- Delay-tolerant encrypted courier mode.
- Self-healing route selection.
- Route quality scoring.
- Peer-assisted relay among trusted devices.
- Local community mesh mode.
- Emergency offline network mode.

### 5.7 One Experience

Purpose:

Hide distributed-systems complexity behind a simple human interface.

Required behavior:

- No jargon-first UI.
- No protocol panic banners.
- No manual cleanup buttons for normal state.
- Clear selected conversation identity.
- Clear group management.
- Clear send/receive state.
- Clear trust warnings only when action matters.

Advanced behavior:

- Intent-based actions: "send this," "keep this safe," "share with this group."
- Local planner explains what is happening in plain language.
- Smart defaults based on device role and trust.
- User-facing language centers people and devices, not protocols.

---

## 6. Mind-Blowing Capabilities

These are the capabilities that can make One Link feel meaningfully different from big-tech products.

### 6.1 Swarm File Transfer

Instead of a file belonging to one sender, a file becomes a verified object that any trusted holder can help deliver.

Scenario:

1. Alex sends a 20 GB file to Computer 2.
2. Computer 2 gets 40 percent.
3. Alex's laptop sleeps.
4. Alex's desktop already has 30 percent of the same chunks from an earlier transfer.
5. Computer 2 automatically pulls the missing chunks from the desktop.
6. When the laptop wakes, all peers reconcile.

Why it matters:

- Transfer can finish even if the original sender disappears.
- Large files become mesh objects.
- Devices help without exposing plaintext to untrusted parties.

Required building blocks:

- Content-addressed chunk store.
- Chunk availability announcements.
- Multi-source wants planner.
- Per-chunk integrity verification.
- Trust-aware source selection.
- Transfer ledger that can bind multiple sources to one file.

### 6.2 Self-Reconstructing Files

Important files should survive device loss using encrypted erasure-coded shards.

Scenario:

1. A user marks a folder "keep alive."
2. One Link splits content into encrypted shards.
3. Shards are placed across trusted devices.
4. Any threshold subset can reconstruct the file.
5. No helper device can read its shard.

Why it matters:

- Personal data availability without cloud storage.
- Recovery even when a device fails.
- User-owned resilience.

Required building blocks:

- Erasure coding.
- Shard manifest.
- Encryption before distribution.
- Shard placement policy.
- Repair jobs.
- Safety indicator: unsafe, partial, safe, overprotected.

### 6.3 Delay-Tolerant Human Internet

Data should eventually arrive even if sender and receiver are never online at the same time.

Scenario:

1. Alice sends Bob a file.
2. Bob is offline.
3. Alice's phone receives encrypted courier bundles.
4. Alice's phone later encounters Bob's laptop or Bob's trusted relay.
5. Bundles are forwarded.
6. Bob decrypts and reconstructs.

Why it matters:

- Works in emergencies, rural areas, schools, events, travel, censorship, and expensive-network situations.
- Turns human movement into network availability.
- No intermediary needs plaintext.

Required building blocks:

- Encrypted courier bundle format.
- Store-and-forward policy.
- Expiration and quota.
- Duplicate suppression.
- Replay protection.
- Delivery receipt when possible.

### 6.4 Personal Data Availability Layer

The user should not care which device currently has which file.

Scenario:

The UI says:

- "Available now."
- "Available when Desktop wakes."
- "Recoverable from 3 devices."
- "Missing 2 chunks."
- "Repairing."

Why it matters:

- Replaces cloud-drive mental model.
- Makes personal devices feel like one storage fabric.

Required building blocks:

- Chunk availability index.
- Device role model.
- Storage quotas.
- Repair planner.
- Folder/object safety scoring.

### 6.5 Mesh Time Machine

Folders and objects should have history, drift detection, repair, and rollback.

Scenario:

1. A synced folder diverges on two devices.
2. One Link detects the Merkle drift.
3. It identifies changed leaves only.
4. The user can inspect changes, accept one, keep both, or roll back.

Why it matters:

- Makes local-first folder sync safer than blind latest-wins.
- Gives users confidence that nothing vanished silently.

Required building blocks:

- Merkle roots.
- Change events.
- Conflict objects.
- Snapshot manifests.
- Rollback operation.
- Human-readable conflict UI.

### 6.6 Adaptive Transport Engine

The system should choose how to send based on reality, not static assumptions.

Route options:

- Direct LAN.
- Direct internet hole-punch.
- Blind relay.
- Multi-path direct plus relay.
- Delay-tolerant courier.
- Future QUIC.
- Future UDP with FEC.
- Future BLE or local radio-like transports.

Decision factors:

- Peer capability.
- Link latency.
- Loss/retry rate.
- File size.
- Chunk overlap.
- Battery state.
- Metered network.
- Trust level.
- User intent.

The UI should say "Sending" or "Waiting for Computer 2" while the engine handles the complexity.

### 6.7 Protocol Shape-Shifting

Peers on different versions should still cooperate at the strongest shared capability.

Examples:

- v0.7 peer: baseline chat and simple file send.
- v0.8 peer: CDC, resume, group actions.
- v0.9 peer: multi-source chunk transfer.
- v1.0 peer: identity cluster and swarm availability.

Unknown fields should be ignored when safe. Unsupported required features should produce clear internal reasons and simple user-facing state.

### 6.8 Local Mesh Planner

One Link should eventually have a local planning layer that turns user intent into mesh actions.

Examples:

- "Get this to Sarah."
- "Keep this project safe."
- "Share this with the group."
- "Move this to my laptop when it wakes."
- "Recover this folder."

The planner decides:

- Which peers can help.
- Which chunks are missing.
- Which path to try.
- Whether to wait, relay, split, repair, or ask the user.

The planner must be local, explainable, and non-invasive.

### 6.9 Personal Compute Swarm

Long term, the same mesh can coordinate trusted compute.

Examples:

- Desktop indexes files for laptop.
- Workstation runs local AI for phone.
- Spare machine repairs folder manifests.
- Home server stores encrypted shards.
- Device cluster shares search indexes.

This must remain permissioned and local-first.

---

## 7. Security Doctrine

Security is not an add-on. It is the structure that makes user-owned infrastructure safe.

### 7.1 Required Security Properties

- Mutual authentication.
- End-to-end encryption.
- Forward secrecy for sessions.
- Replay protection.
- Key-change detection.
- Signed events.
- Per-peer permissions.
- Per-group permissions.
- Local API token isolation.
- Path traversal defense.
- Atomic receive writes.
- Hash verification.
- Corrupt cache detection.
- Rate limiting.
- Safe logging: no private keys, secrets, plaintext message dumps, or sensitive file paths unless intentionally enabled.

### 7.2 Replay Protection

Every authenticated frame class should have a replay policy.

Required tests:

- Same sequence rejected.
- Too-old sequence rejected.
- Bad timestamp rejected.
- Reordered but valid frame accepted.
- Large sequence jump handled safely.

### 7.3 Trust and Key Changes

The app must assume key changes are security-sensitive.

Required behavior:

- Known hostname with new key creates warning.
- Pinned or verified peer key change blocks sensitive send until acknowledged.
- User can inspect key history.
- User can re-verify.
- Key-change warning is clear and not buried.

### 7.4 Group Security

Groups must be event-driven and signed.

Required behavior:

- Membership changes are signed.
- Role changes are signed.
- Leave events are signed.
- Invite links are signed and expiring.
- Group message events identify their sender cryptographically.
- Removed members cannot receive future group keys.

Advanced behavior:

- Sender-key rotation on membership change.
- Group admin threshold options.
- Sealed sender for group messages.
- Optional disappearing messages.

### 7.5 Relay Security

Relays must be blind path helpers.

Required behavior:

- Relay cannot decrypt payload.
- Relay can rate-limit abuse by pubkey or token.
- Relay cannot silently replace peer keys.
- Relay does not become account authority.
- Relay failure does not destroy local operation.

---

## 8. Compatibility Doctrine

One Link must not break the user's trust with "update both devices or nothing works."

### 8.1 Capability Negotiation

Each peer advertises:

- Protocol version.
- Supported frame types.
- Supported transfer modes.
- Supported crypto modes.
- Supported group features.
- Supported storage/chunk features.
- Maximum frame size.
- Resume support.
- Relay support.

### 8.2 Compatibility Rules

- Same major protocol version should preserve baseline features.
- New optional features must be ignorable.
- Required features must be declared explicitly.
- Older peers receive simpler envelopes.
- Newer peers use strongest common mode.
- UI should say "using compatibility mode" only when helpful.

### 8.3 Required Compatibility Tests

- New client sends baseline file to old compatible peer.
- Old client sends baseline file to new client.
- Unknown optional field ignored.
- Unsupported required feature rejected with structured reason.
- Different transfer feature sets fall back to simple chunk transfer.
- Different group feature sets preserve read-only or baseline behavior.

---

## 9. Build Sequence

This is the proposed order for turning the doctrine into reality without collapsing under scope.

### Phase 1: Reliability Bedrock

Goal:

Make the current system hard to break.

Deliverables:

- Transfer fault test suite.
- Protocol compatibility test suite.
- Peer registry stability tests.
- Chunk store atomicity and corruption tests.
- Replay-window primitive and tests.
- Validation gate document.

Exit criteria:

- Disconnect mid-transfer resumes.
- Restart mid-transfer resumes.
- Disk-full or interrupted write does not produce fake completed file.
- Ghost/self devices do not appear in the main device list.
- Compatible version mismatch does not block baseline send.

### Phase 2: Content-Addressed Storage Core

Goal:

Turn files into durable verified objects.

Deliverables:

- Blob/chunk store abstraction.
- Chunk availability index.
- File manifest format.
- Manifest verification.
- Cache audit command.
- Dedup across sends.

Exit criteria:

- Duplicate chunks stored once.
- Re-sending same file transmits almost nothing.
- Renamed same file recognized.
- Corrupt chunk rejected.
- Missing chunk retried.

### Phase 3: Transfer Intent Engine

Goal:

Replace one-shot sends with durable intents.

Deliverables:

- Transfer intent model.
- Durable transfer planner.
- Wants-list protocol.
- Resume scheduler.
- Adaptive retry/backoff.
- User-facing paused/resuming/completed states.

Exit criteria:

- Sending is a durable task.
- User can close/reopen UI without losing progress.
- Peer offline becomes "waiting," not "failed," when recoverable.
- Transfer finishes after peer returns.

### Phase 4: Compatibility and Capability Engine

Goal:

Make different versions cooperate gracefully.

Deliverables:

- Formal capability registry.
- Protocol version matrix.
- Feature fallback map.
- Compatibility-mode send paths.
- Structured unsupported-feature errors.

Exit criteria:

- File send works across compatible minor versions.
- Unsupported advanced features degrade without panic.
- UI does not force update for baseline communication.

### Phase 5: Swarm Transfer

Goal:

Allow trusted devices to help deliver chunks.

Deliverables:

- Chunk availability announcement.
- Multi-source planner.
- Per-source trust gating.
- Multi-source transfer ledger.
- Duplicate source suppression.
- Final manifest verification.

Exit criteria:

- Receiver can fetch missing chunks from more than one trusted peer.
- Transfer can complete after original sender disappears if enough chunks exist elsewhere.
- User sees a simple "helped by Desktop" style activity summary.

### Phase 6: Mesh Availability and Repair

Goal:

Make personal storage resilient.

Deliverables:

- Keep-alive policy.
- Erasure-coded shards.
- Shard placement planner.
- Repair jobs.
- Availability scoring.
- Recovery UI.

Exit criteria:

- User can mark important folder/file as protected.
- One Link reports whether it is recoverable.
- Missing/corrupt chunks can be repaired from trusted devices.

### Phase 7: Delay-Tolerant Courier Mode

Goal:

Let encrypted data move through trusted carriers when sender and receiver are not simultaneously online.

Deliverables:

- Courier bundle format.
- Bundle expiration.
- Bundle quotas.
- Store-and-forward engine.
- Duplicate/replay protection.
- Delivery receipts.

Exit criteria:

- A trusted intermediary can carry unreadable encrypted data.
- Sender and receiver do not need to be online at the same time.
- Intermediary cannot decrypt.

### Phase 8: One Identity, Many Devices

Goal:

Make a person's devices act as one identity cluster.

Deliverables:

- Identity root.
- Device cluster membership.
- Intra-cluster sync.
- Device revocation.
- Cluster safety display.
- Recovery story.

Exit criteria:

- User can add a second owned device to the same identity.
- Messages and transfer state sync across owned devices.
- Revoking a device prevents future access.

### Phase 9: Local-First App Substrate

Goal:

Expose the mesh as a foundation for future local-first apps.

Deliverables:

- Documented local API.
- Permissioned app capabilities.
- Event/object APIs.
- Storage APIs.
- Group APIs.
- Developer test harness.

Exit criteria:

- A small local app can use One Link for identity, encrypted object transfer, and group state without running its own server.

---

## 10. Validation Gates

One Link should not call a release "production ready" unless these gates pass.

### 10.1 File Transfer Gate

Required:

- Zero-byte file.
- One-byte file.
- Small text file.
- Binary file.
- Large file.
- Huge sparse test file where practical.
- Filename with spaces.
- Unicode filename where supported.
- Same file sent twice.
- Renamed duplicate file.
- Interrupted transfer.
- Restarted daemon transfer.
- Receiver disk write failure simulation.
- Corrupt chunk simulation.

### 10.2 Compatibility Gate

Required:

- Current to previous minor.
- Previous minor to current.
- Unknown optional field.
- Unsupported required feature.
- Old file mode fallback.
- Old chat mode fallback.
- Old group mode fallback where possible.

### 10.3 Security Gate

Required:

- Replay frame rejected.
- Bad signature rejected.
- Bad AEAD tag rejected.
- Key-change warning generated.
- Path traversal rejected.
- Local API token required.
- Unauthorized peer cannot send.
- Unauthorized peer cannot request file.
- Blocked peer blocked across reconnect.

### 10.4 Reliability Gate

Required:

- Peer disappears mid-send.
- Peer changes IP.
- Peer returns after delay.
- Connection reset.
- Latency spike.
- Packet/frame truncation.
- Multiple concurrent transfers.
- UI reload during transfer.
- Daemon restart during transfer.

### 10.5 Mesh Gate

Required:

- Stale peer removed automatically.
- Self peer suppressed.
- Duplicate endpoint collapsed.
- Route status structured.
- Relay unavailable fallback shown.
- Chunk availability from multiple peers reconciled.

### 10.6 UX Gate

Required:

- First-run user knows what to do.
- Selected conversation is obvious.
- Group settings are discoverable.
- Leaving group is obvious.
- Sending file has obvious button and drag/drop.
- Advanced warnings are plain language.
- No giant panic banners for recoverable states.
- No manual cleanup for normal background maintenance.

---

## 11. What Big Platforms Cannot Easily Copy

Big platforms can copy buttons and screens. The hard part is copying incentives.

One Link should focus on powers that conflict with centralized business models:

- User-owned identity instead of platform accounts.
- Open protocol instead of private network lock-in.
- Self-hosted rendezvous instead of mandatory company infrastructure.
- Content-addressed personal storage instead of paid cloud storage.
- Device swarm availability instead of subscription sync.
- No telemetry graph.
- No phone-number dependency.
- No forced app store.
- No central moderation authority for private trusted groups.
- No artificial file size ceiling.

The strategic advantage is not just technical. It is moral and architectural:

> The user owns the relationship, the data, the identity, and the path.

---

## 12. User Experience Doctrine

The UI should never expose raw complexity unless the user asks for detail.

Use people-facing language:

- "Waiting for Computer 2."
- "Sending when it comes back online."
- "Already had most of this file."
- "Verified."
- "Safety number changed."
- "Available from 3 devices."
- "Recovering missing pieces."
- "This group has 4 people."
- "Desktop helped finish this transfer."

Avoid default jargon:

- CDC.
- Merkle.
- AEAD.
- Relay envelope.
- Capability negotiation.
- Replay window.
- CRDT.
- NAT traversal.

Advanced details can live in diagnostics, activity, and developer views.

---

## 13. Immediate Next Build

The next work should convert this vision into tests and architecture rails before adding more visible features.

Priority 1:

- `tests/test_protocol_compat.py`
- `tests/test_transfer_faults.py`
- `tests/test_peer_registry_stability.py`
- `tests/test_chunk_store_faults.py`
- `tests/test_replay_window.py`
- `docs/ONE_LINK_VALIDATION_GATES.md`

Priority 2:

- Content-addressed chunk store abstraction.
- Transfer intent model.
- Capability registry.
- Compatibility fallback map.
- UI language cleanup around recoverable states.

Priority 3:

- Multi-source chunk availability.
- Swarm transfer planner.
- Keep-alive storage policy.
- Erasure-coded shard prototype.
- Delay-tolerant courier prototype.

The build rule:

> Every advanced feature must make the app easier for the user, not harder.

---

## 14. Definition of "We Are One"

We are One means:

- Your devices are one.
- Your trusted people are one circle.
- Your files are one memory.
- Your groups are one shared space.
- Your network is one living path.
- Your identity is yours.
- Your data stays yours.
- Your future does not require a company in the middle.

This is the flag:

> One Link is a free, open, sovereign mesh for people. It lets anyone send anything, preserve anything, sync anything, and stay connected through their own devices and trusted people. No gatekeeper. No rent. No artificial limits. We are One.
