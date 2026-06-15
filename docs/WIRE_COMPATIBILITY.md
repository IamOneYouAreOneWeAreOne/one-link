# Wire Compatibility — different versions must always talk

One Link installs update independently. Two paired devices are
routinely on **different builds** — one took the update, one didn't,
or one runs the installer build while the other runs from source. The
product promise is:

> **Any two One Link builds can always at least chat and send a file
> to each other. A version difference may disable a fancy feature, but
> it must never sever the connection.**

This document is the contract that keeps that true. It is enforced by
`tests/test_wire_compat_contract.py` and `tests/test_protocol_compat.py`.
If one of those tests fails, do not "fix" the test — read this first.

---

## The three layers, and which one governs compatibility

| Version | Example | Governs |
|---|---|---|
| **App / marketing version** | `0.21.4`, `1.0.0` | Nothing on the wire. Display + update checks only. |
| **Wire protocol version** | `OL1.2` (`PROTOCOL_VERSION`) | Frame shape. The real compatibility boundary. |
| **Capabilities** | `chat`, `files`, `file_cdc`, `folder_sync_bidi_v1`, … | Which optional features two peers may use together. |

The cardinal rule of the original bug we fixed (2026-06-04): **never
gate compatibility on the app version.** A routine `0.x → 1.0` release
with an unchanged wire must not break interop. `negotiate()` keys its
"major boundary" check off the **wire** version, falling back to the
app semver only for legacy peers that don't advertise a wire version.

## Rules every wire-touching change MUST follow

1. **Never remove or rename a capability string.** A peer that still
   expects the old name silently loses that feature. Add new caps;
   never repurpose old ones. (Pinned: `test_advertised_caps_include_core_features`.)

2. **New behavior is always gated behind a capability.** Before using
   a feature, check the peer advertised it: `if FEATURE in peer_features`.
   Never assume a peer understands a frame just because you sent it.

3. **New fields on an existing message are always OPTIONAL.** The
   receiver must tolerate their absence (old sender) and their presence
   (new sender). Never make an existing message type require a field
   an older build doesn't send.

4. **New message types are safe.** The dispatch loop silently ignores
   unknown message types (there is no terminal `else` that raises), so
   a newer peer sending a frame an older peer doesn't know about is a
   no-op on the old side. Keep it that way.

5. **Version differences DOWNGRADE, never REFUSE.** `negotiate()` may
   only drop the negotiated mode (e.g. to `baseline_cross_major`) on a
   version difference. The single legitimate hard-incompatible is
   *genuinely zero shared user capability* (can't even chat). (Pinned:
   `test_version_difference_alone_never_refuses`,
   `test_no_shared_capability_is_the_only_hard_incompatible`.)

6. **The Double-Ratchet header version is frozen at `v1`.** This is the
   hardest constraint in the whole system: `double_ratchet.Header.decode()`
   raises on any version byte `!= 1`, so a peer that bumps it instantly
   hard-fails every older peer with *"unsupported ratchet header
   version"*. You may **not** just change the number. To evolve the
   ratchet wire format:
   - add a new capability (e.g. `double_ratchet_v2`),
   - only emit v2 frames when BOTH peers advertise it,
   - keep accepting v1 for **at least one full release cycle**,
   - then drop v1 only after telemetry shows ~no v1 peers remain.

   (Pinned: `test_ratchet_header_frozen_at_v1`.)

7. **Bumping `PROTOCOL_VERSION`'s wire major is a breaking change.** It
   forces every mixed-major pair down to `baseline_cross_major` (chat +
   baseline file only). Do it deliberately, document the migration, and
   provide a negotiated path the same way as the ratchet (rule 6).
   (Pinned: `test_protocol_version_is_present_and_parseable`.)

## What "always work" actually delivers across a boundary

- **Same wire major, any app versions** → full feature negotiation.
  A `2.0.0` app and a `0.21.0` app both on `OL1.2` use CDC/swarm/etc.
  normally.
- **Different wire major** (a real, deliberate framing break) →
  `baseline_cross_major`: chat + baseline file transfer keep working;
  advanced framing is disabled until both sides share a wire major.
- **Peer advertises no version** (ancient build) → `legacy_unknown`:
  conservative baseline, still compatible.
- **Zero shared capability** → the only hard `incompatible`. In
  practice unreachable, because every build advertises `chat` + `files`.

## Where this lives in code

- `src/one_link/protocol_compat.py` — `negotiate()`, the decision engine.
- `src/one_link/daemon.py` — `PROTOCOL_VERSION`, `CAPS_FEATURES`, the
  `_build_caps` frame, and the receive-loop dispatch (unknown types
  fall through harmlessly).
- `src/one_link/double_ratchet.py` — `Header` (the v1-frozen header).
- `src/one_link/capabilities.py` — `LOCAL_CAPABILITIES` + the cap strings.
- `tests/test_wire_compat_contract.py` + `tests/test_protocol_compat.py`
  — the enforced contract.
