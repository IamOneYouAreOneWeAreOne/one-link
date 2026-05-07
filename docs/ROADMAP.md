# One Link Roadmap

Status: living document. Updated as releases ship. Last updated: 2026-05-06.

This is the post-v0.7.2 plan to take One Link from "entry level" to
best-in-class P2P chat + file sync. Driven by the user audit that
followed v0.7.2 (deny-by-default, outbox, sandbox, supply-chain,
Double Ratchet primitive landed). The big picture: protocol is
strong; UX is not yet matching the protocol's strength.

Each version is a single ship-sized chunk: implementation + tests +
docs + tag. Sequence is the proposed order; reorder freely.

---

## Settings architecture (cross-cutting)

The split that drives every UI change in this roadmap:

**App-wide settings** (gear top-right of the chat surface):
things about YOU, the daemon owner.

  - Display name
  - Identity export/import
  - Default permission policy for new pairings
    (deny-by-default vs permissive vs prompt)
  - Rendezvous URLs, auto-accept LAN
  - Desktop notifications (browser-level permission)
  - Theme, language, default download folder
  - Log verbosity, auto-update channel

**Per-device settings** (gear/⋮ next to each device row, OR
a click on the conversation header device card): things about
THAT one paired device.

  - Identity & trust: fingerprint (copyable), SAS code, key change
    history, "verified in person" toggle
  - Permissions: chat / files / folders / groups (moves out of
    app settings entirely)
  - Reachability: live regime (LAN/internet/relay/offline),
    latency (EWMA), last-alive, advertised endpoints list
  - Display: custom name override, color/avatar, custom alert sound
  - Notifications: per-device mute, do-not-disturb hours
  - Activity: messages/files exchanged, audit log, link to history
  - Trust actions: unpair, block, force-rekey

**Per-conversation settings** (becomes meaningful when groups
land): retention policy, member list, custom theme, mute.

---

## Tier 1 — chat fundamentals every modern chat app has

These are non-negotiable for a chat product to feel competent.
Most are backwards-compatible wire additions (new message kinds
or fields older peers ignore).

  - **v0.7.3 — Per-device drawer + settings split.** Move per-
    device controls (Allow toggles, mute, custom name, view SAS,
    unpair) into a dedicated drawer keyed by peer fingerprint.
    Global settings keeps only app-wide concerns. Closes the
    "Allow row clutters the chat header" frustration permanently.

  - **v0.7.4 — Resume-on-reconnect for transfers.** A WinError
    10053 mid-transfer (or any network drop) shouldn't lose work.
    Ledger already tracks chunks_done; add wire-protocol resume
    + UI "paused — will resume" status pill. Auto-resume when
    peer reconnects.

  - **v0.7.5 — Reply / quote + reactions.** Wire: message has
    optional `reply_to: msg_id` field; reactions are a new
    `REACTION` frame `{target_msg_id, emoji, op: add|remove}`.
    UI: right-click → reply, hover → react. Threaded view shows
    inline quote.

  - **v0.7.6 — Edit / delete + read receipts + typing.** Wire:
    new `EDIT_MSG`, `DELETE_MSG`, `READ_MARKER`, `TYPING_START`
    /`TYPING_STOP` frames. UI: edit / delete from message context
    menu (with a 5-min cooldown after which edits are blocked);
    optional read-receipts (per-device toggle); subtle "typing…"
    indicator under conversation name.

---

## Tier 2 — security UX that matches the protocol's strength

We have Double Ratchet, deny-by-default, sandbox, transcript
binding. Users can't see any of it. These changes surface the
crypto so trust decisions are obvious.

  - **v0.7.7 — Verified-in-person checkmark.** ✓ Shipped (released
    as package v0.8.3). Trust state remains `pinned`, but a separate
    `verified_at_ms` / `verified_method` / `verified_note` triple is
    set after the user confirms a side-channel SAS match. UI: green
    ✓ overlay on the sidebar avatar, green "Verified" pill in the
    conversation header, yellow "Verify in person" CTA before that.
    Drawer section captures the audit trail. New endpoints: `POST
    /api/peers/{fp}/verify` + `DELETE /api/peers/{fp}/verify`. Schema
    migration v8.

  - **v0.7.8 — Key-change warning.** ✓ Shipped (released as
    package v0.8.4). state.py tracks every (hostname, ed_pub_hex)
    pair ever observed in `hostname_keys`; whenever a hostname
    rotates pubkeys, an entry is appended to `key_change_events`
    with severity = high (old peer pinned) / medium (pending)
    / low (never persisted). Detection runs inside upsert_peer so
    every code path (handshake, discovery, snapshot) is covered.
    UI: red ⚠ overlay on the sidebar avatar (overrides the green
    ✓), red banner under the conversation header with severity
    pill + Acknowledge action, full audit list in the device
    drawer's "Key change detected" section. Endpoints: GET
    `/api/key-change-events`, POST
    `/api/key-change-events/{id}/ack`, POST
    `/api/peers/{fp}/key-change-events/ack-all`, GET
    `/api/peers/{fp}/key-history`. Schema migration v9.

  - **v0.7.9 — Multi-modal SAS verification.** ✓ Shipped (released
    as package v0.8.5). Audio readback (SpeechSynthesis API spells
    each digit, "zero four three, one nine two") for phone-call
    confirmation. Visual SAS art (deterministic 6-cell emoji + color
    grid derived from the SAS digits) for face-to-face glance
    confirmation, similar in spirit to SSH host-key randomart and
    Threema's emoji codes. Both rendered alongside the canonical 6
    digits in the pair modal AND device drawer; either side can
    derive them locally — no extra wire data. Webcam QR scanning
    is intentionally deferred (heavy vendored library, narrow win
    over multi-modal already covered).

  - **v0.8.0 — Group UI** (depends on v0.7.5/.6 chat features).
    Wire all the existing v0.6.x group protocol into the UI:
    create group, member list, invite-by-link, leave group.
    Group chat reuses the chat fundamentals from .5/.6.

---

## Tier 3 — P2P/file features that beat AirDrop and Syncthing

Pure capability advantages over centralized chat. Each one closes
a specific competitive gap.

  - **v0.8.1 — Live bandwidth + transfer progress in chat.** ✓
    Shipped (released as package v0.8.8). Client-side EWMA
    (alpha=0.4) rate tracker computes bytes/sec from delta
    progress_bytes across `transfer` WS events — no extra wire
    data. Each in-flight FILE_OFFER bubble shows live bytes / total
    + B/s + ETA. Conversation header gains an aggregate
    "Sending N files · 14 MB/s · 47%" pill that ticks once per
    second so a stalled transfer's stale rate fades. Click pill
    → opens Files → Sent. Rate cache resets on terminal status
    so retries start clean; rate decays to 0 after >3s of no
    events so frozen transfers don't show ghost rates.

  - **v0.8.2 — Folder sync conflict UI.** ✓ Shipped (released as
    package v0.8.9). When the manifest CRDT detects a divergent
    edit (concurrent vclocks + different blob_hashes), state.py
    logs both versions to a new `manifest_conflicts` table BEFORE
    the merge tie-breaks. Server endpoints surface the unresolved
    list + a per-conflict resolve handler that supports
    mine | theirs | both. The 'both' choice keeps mine in place
    AND writes the peer's version under
    `<name>.conflict-<peer-shortfp>.<ext>` so nothing is lost.
    UI: yellow Conflicts banner above the Folders list shows the
    count + opens a side-by-side dialog with Auto-applied tag,
    blob/size/mtime/peer per side, and Keep mine / Keep theirs /
    Keep both buttons. Live `folder_conflict_detected` WS event
    broadcasts toast + banner refresh. Schema migration v10.

  - **v0.8.3 — Multi-path send.** When LAN + internet both
    reachable, send chunks in parallel over both, fastest path
    wins per chunk. CDC dedup makes this nearly free.

  - **v0.8.4 — Voice messages.** ✓ Shipped (released as package
    v0.9.2). MediaRecorder captures opus (webm/ogg fallback chain
    by browser support) → uploads via existing /api/send-file
    pipeline → receiver's chat bubble auto-renders an inline
    audio player. Mic button in composer + Ctrl+Shift+M shortcut.
    Recording overlay slides in with live timer + Cancel + Send;
    5-min hard cap, sub-1 KB blobs discarded as misclicks. mic
    stream tracks explicitly stopped on rec.onstop so OS-level
    indicator turns off. No schema, no new endpoint.

  - **v0.8.5 — Inline previews for PDFs / markdown / code.** ✓
    Markdown + code + plain-text shipped (released as package
    v0.9.0). PDFs deferred — vendoring PDF.js (~600 KB) for the
    long tail seemed disproportionate; OS / browser-native PDF
    handlers cover that case via Open. Markdown gets a real
    subset renderer (ATX headings, paragraphs, fenced code,
    blockquotes, ordered + unordered lists, horizontal rules,
    plus inline bold/italic/code/autolinks). Code gets a
    line-numbered monospace block. Plain text wraps in a pre.
    Server endpoint GET /api/files/{name}/preview enforces a
    50-extension whitelist + 256 KB cap with utf-8/latin-1
    fallback decode. Per-bubble Show preview toggle in chat;
    cached on the message so re-opening doesn't re-fetch.

  - **v0.8.6 — Large file streaming.** Don't materialize the
    full file before playback; stream chunks to a video/audio
    element as they arrive. Especially for voice messages and
    forwarded video.

---

## Tier 4 — platform reach

These are major efforts (each its own multi-month project).
Listed in dependency order.

  - **v0.9.0 — Mobile-friendly responsive web UI.** Same daemon,
    new layout that works on iPad/iPhone Safari, Android Chrome.
    Touch-first interactions. Drawer becomes a fullscreen sheet.

  - **v0.9.1 — System tray + global hotkey.** Minimize-to-tray;
    Win+L (or configurable) sends clipboard/selected file to
    last-used device.

  - **v1.0.0 — Multi-device-per-identity.** One identity (one
    keypair shown to peers) but many local devices that all sync
    messages between themselves over the same protocol. Requires
    a new "device cluster" abstraction in state.

  - **v1.1+ — Native iOS/Android apps.** Same daemon ported.
    Background-service constraints on mobile mean significant
    lifecycle work.

  - **v1.2+ — Voice / video calls.** WebRTC over the same
    encrypted channel. Major undertaking; depends on stable
    multi-device-per-identity.

---

## Sequencing rules

  - Each version ships independently. Don't bundle.
  - Wire-format additions stay backward-compatible: older peers
    ignore unknown fields / message kinds.
  - Every cap that affects what a peer can request gets:
    1. capability advertised in CAPS
    2. deny-by-default policy entry
    3. UI grant prompt on first request from a peer
  - Tier 2 security UX must keep up with new wire features —
    don't ship a feature that creates a new key-trust pathway
    without first surfacing it in the trust UI.
  - Resume-on-reconnect (v0.7.4) is a prerequisite for the
    larger file features in Tier 3 — don't build voice-message /
    streaming on a flaky transport layer.

---

## Cross-cutting follow-ups (post-Tier 3 starts)

  - **Activity feed.** ✓ Shipped (released as package v0.9.1).
    Cross-peer chronological view merging capability_audit (verify,
    trust, cap policy) + key_change_events + transfers (terminal
    states only) + manifest_conflicts + peers first_seen into one
    timeline. Filter chips (All / Trust / Keys / Files / Conflicts
    / Peers). Live-updating: every relevant WS event nudges a
    coalesced refresh on the open pane. Lives in the existing
    Activity sidebar tab. Endpoint
    `GET /api/activity?since=&kinds=&peer=&limit=`.

## Cross-cutting tech debt to attend to as we go

  - **Wire-format channel-level Double Ratchet activation.** v0.7.2
    shipped the audited primitive; v0.7.3+ should detect mutual
    `double_ratchet_v1` capability and switch the channel. Aim
    to land this inside v0.7.4 (transfer resume) since both touch
    the channel layer.
  - **pip-audit / bandit findings.** Currently report-only. After
    triage, tighten to fail-the-build in v0.8.x.
  - **Group sender-key rotation cadence.** Currently never rotates;
    add periodic rotation tied to group event log advancement
    when v0.8.0 group UI lands.
  - **Mobile responsive readiness.** Every UI commit from v0.7.3
    forward should be mobile-aware so v0.9.0 isn't a full rewrite.
