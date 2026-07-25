# Fail-open Triage — 2026-05-22

> Historical record. The v1 HELLO opt-in rejection documented here was
> superseded on 2026-07-22: rejection is now the default; only the explicit
> temporary `ONE_LINK_ALLOW_V1_HELLO=1` migration override permits v1.

Hunt: residual fail-open patterns in security-relevant code AFTER the May 21
audit closeout (T1-A through T1-J, Batch P/Q/S/V/Z). Scope per the brief:
daemon.py, channel.py, cap_root_key.py, cap_store.py, caps_grants.py,
state.py, peer_rtc.py, master_seed.py, identity.py, lockbox.py,
peer_https.py, share_link.py, server.py.

Quality bar: a finding only counts if an exception, None value, or missing
field causes the system to GRANT / SKIP / ASSUME-SAFE. Telemetry / logging /
cleanup suppressions are out of scope.

## Genuine fail-opens (need fix)

### FO-1. QUIC `_NoopChannel` re-creates the T1-G empty-fingerprint collision when no WebRTC channel exists for the peer
- File: `src/one_link/daemon.py:21891-21906` (in `_quic_inbound_frame_loop`).
- Pattern: None-fallback to empty bytes.
- Code:
  ```python
  _real_ed_pub = (
      getattr(_real_channel, "peer_ed_pub", b"")
      if _real_channel is not None else b""
  )
  ...
  class _NoopChannel:
      def __init__(self) -> None:
          self.peer_caps = dict(_real_peer_caps)
          self.peer_ed_pub = _real_ed_pub   # ← b"" when no WebRTC channel
          self.peer_short_id = peer_sid
  ```
  Then for `FILE_OFFER` (line 21933-21939) the dispatcher routes through
  `_on_peer_message`, which at line 4412 does
  `peer_fp = fingerprint_of(channel.peer_ed_pub)` — i.e. derives the peer fp
  from `b""` for every QUIC-only peer that doesn't have a coexisting WebRTC
  channel.
- Risk: QUIC-only peers (mobile, fresh inbound, post-WebRTC-teardown) all
  collapse onto the same synthetic fingerprint `fingerprint_of(b"")`, so
  IncomingFile / transfer-ledger / capability-request keying collides
  across distinct rustls-authenticated peers. Cap check itself happens
  against this synthetic fp (deny by default — not paired), but ledger
  state and any code that trusts `channel.peer_ed_pub` downstream sees
  the wrong identity. T1-G acknowledged this risk but only fixed it for
  the case where a real channel already exists; the fallback was left.
- Fix: when `_real_channel is None` but `peer_fp` is known (always true on
  this path — rustls `conn.peer_fingerprint()` bound it at accept), resolve
  the pubkey via `self._peer_pub_for_fp(peer_fp)` and use that instead of
  `b""`. Fall back to refusing the QUIC frame (not synthesizing) if the
  pubkey isn't in the peer registry.

### FO-2. `_inbound_is_rejected` returns False when `state is None`
- File: `src/one_link/daemon.py:11800-11801`.
- Pattern: None default-allow.
- Code:
  ```python
  def _inbound_is_rejected(self, peer_fp: str) -> bool:
      if self.state is None:
          return False           # ← treats every peer as not-rejected
      rec = self.state.get_peer(peer_fp)
      return bool(rec and rec.trust == "rejected")
  ```
- Risk: same class of bug T1-D closed in `_capability_allowed`. A boot race,
  corrupt state DB, or `state` being nulled (tests, recovery path) lets
  EXPLICITLY-REJECTED peers complete inbound handshakes and run the full
  CAPS / channel-message loop. Downstream cap checks (post-T1-D) deny their
  ops, but the channel itself stays alive — wastes resources, leaks
  liveness signals, and contradicts the documented "rejected peers cannot
  connect" property the comment at `_on_peer_message:4421` relies on (the
  H2 rejection-handler check fires AFTER the channel is up).
- Fix: return True (treat as rejected) on `state is None`, with a loud
  audit log + denial counter. Matches the T1-D pattern exactly.

### FO-3. `_check_outbound_trust` allows outbound to rejected peers when state is None
- File: `src/one_link/daemon.py:11829-11839`.
- Pattern: None default-allow.
- Code:
  ```python
  def _check_outbound_trust(self, peer: Peer) -> str | None:
      """Returns None if outbound is allowed; otherwise an error string."""
      if self.state is None:
          return None              # ← allow outbound
      ...
  ```
- Risk: same mechanism, opposite direction — outbound traffic to a peer the
  user previously marked `rejected` slips out during any state-unavailable
  window. Leaks our liveness + signaling to a peer that should be cut off.
- Fix: return a sentinel error string (e.g. `"state unavailable; outbound
  refused"`) when state is None. Loud + fail-closed.

### FO-4. `rotate_cap_root_key` persists the prior cap_root_key in plaintext when DPAPI wrap fails on Windows
- File: `src/one_link/cap_root_key.py:165-171`.
- Pattern: silent fallback to unencrypted persistence.
- Code:
  ```python
  if os.name == "nt":
      from one_link.lockbox import _dpapi_protect
      wrapped = _dpapi_protect(prior)
      if wrapped is not None:
          payload = wrapped
      else:
          payload = prior  # last-resort raw on DPAPI failure
  else:
      payload = prior
  ```
  Then `payload` is written to `cap_root.old.key` for the rotation grace
  window.
- Risk: the cap_root_key is the macaroon HMAC root; an attacker with brief
  FS read access during a rotation in which DPAPI happens to fail walks
  away with the prior root key and can forge macaroons against any in-grace
  capability. The active `store_cap_root_key` path at line 96-100 raises
  when DPAPI wrap fails (correct); rotation's old-key persistence silently
  degrades.
- Fix: raise (or skip the old-key persistence entirely) when DPAPI wrap
  fails during rotation. Better to lose the grace window than write the
  prior root in clear.

## Probably-fine but worth a tracking comment (NOT counted in the budget)

- `daemon.py:8963-8964` (`_sandbox_filter_manifest_entries` returns
  unfiltered entries when `state is None`) — only caller (`_handle_manifest_push`)
  already gates on `state is not None` at line 9147, so the fail-open is
  unreachable today. Add a defensive `return []` for future-proofing.

- `daemon.py:11912` (`_capability_allowed` consults `_cap_store` only when
  `_cap_store is not None and self.state is not None`) — the grant-chain
  walker is correctly skipped on state=None, but the explicit
  `state is None` block immediately below (line 11943) is what closes the
  path, not a guard on the walker itself. Today this is OK.

- `lockbox.py:408-411` (`acquire_or_create_silent_drk` swallows
  `master_seed.load_seed` exceptions and mints a fresh DRK) — this is the
  documented "lost-laptop ⇒ lose access" behaviour, but a transient FS
  hiccup during a legitimate restore-from-mnemonic boot would silently
  mint a fresh DRK and the user would think the restore worked while
  their at-rest data becomes unreadable. Reliability, not security.

## Already-shipped (verified via comment annotations)

| Site | Tag | Note |
|------|-----|------|
| `daemon.py:11843-11904` `_capability_allowed` seed-tamper-detector raising | 2026-05-22 Batch S | Fails closed with reason=`seed_tamper_check_failed` |
| `daemon.py:11944-11959` `_capability_allowed` state=None | 2026-05-21 T1-D | Fails closed + audit log + denial counter |
| `daemon.py:11960-11979` `_capability_allowed` verifier exception | 2026-05-21 T1-D | Fails closed + audit log + denial counter |
| `state.py:1503-1516` `get_peer_capability_policy` JSON decode | 2026-05-21 T3-W | Raises instead of returning `[]` (which was deny-all but asymmetric with `None` allow-all) |
| `daemon.py:21697-21722` QUIC `peer_fp` binding via `conn.peer_fingerprint()` | 2026-05-22 T1-H FULL FIX | Ground-truth fp from rustls cert; legacy FIFO only on fallback |
| `daemon.py:21881-21906` QUIC `_NoopChannel` proxies real `peer_ed_pub` | 2026-05-21 T1-G | (partial — see FO-1) |
| `daemon.py:4561-4577` `CAPABILITY_GRANT` rejected from unpinned peers | 2026-05-21 T1-J | Pin gate before `_cap_store.accept` |
| `daemon.py:4578-4608` per-peer rate limit on `CAPABILITY_GRANT` | 2026-05-22 Batch P | 5 per 60 s |
| `daemon.py:13942-13958` chain walker refuses unpinned intermediates | 2026-05-22 Batch P | Belt-and-suspenders on stale store edges |
| `daemon.py:17523-17535` `send_file` refuses on `peer_fp_for_policy=None` | 2026-05-21 T1-F | No more silent cap bypass |
| `cap_store.py:147-183` revoke_subject / revoke_granter tombstone nonces | 2026-05-22 Batch Z | Replay-defense survives eviction |
| `channel.py:811-812` REPLY signature invalid raises | (pre-audit, hardened) | RuntimeError, no fall-through |
| `channel.py:859-869` HELLO nonce replay window | 2026-05-22 Batch V | Pre-crypto reject |
| `channel.py:879-898` v1 HELLO sig hard-reject under `ONE_LINK_REJECT_V1_HELLO=1` | 2026-05-21 T2-B | UKS-defended path on demand |
| `double_ratchet.py:198-211` small-order pubkey rejection is CT + `!= 0` | 2026-05-22 Batch Q | Length pre-check returns True = REJECT (fail-closed) |
| `identity.py:478-497` `verify` narrows except clause | 2026-05-21 (crypto agent) | Was bare except; now only `InvalidSignature` / `ValueError` |
| `peer_rtc.py:920-929` `verify_doc` failure returns | (pre-audit, hardened) | Fail-closed |
| `peer_rtc.py:891-905` attest_response wrong-DC race | Audit M9 May 2026 | Drop on DC instance mismatch |
| `peer_rtc.py:944-970` per-master-vk fork detection | Audit I6 May 2026 | Refuse + tear down on rollback |
| `peer_rtc.py:976-984` master_vk HWM persisted across restart | External audit 2026-05-18 ES-44 | Survives daemon restart |
| `server.py:1804-1821` `_check_token` constant-time compare | v0.20.7 audit L12 | hmac.compare_digest |
| `server.py:1858-1894` `_csrf_origin_ok` exception → return False | 2026-05-21 T2-O | urlparse raise → deny |
| `route_bootstrap.py:229-286` signed-bootstrap verify is exhaustive | (already hardened) | All exceptions surface as ValueError |
| `share_link.py:312-345` redeem is single-use + expiry-checked | (pre-audit, hardened) | None on miss/expired/consumed |
