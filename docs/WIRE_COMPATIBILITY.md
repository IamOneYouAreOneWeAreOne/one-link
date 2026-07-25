# Wire Compatibility — negotiated mixed-version baseline

One Link installs update independently. Two paired devices are
routinely on **different builds** — one took the update, one didn't,
or one runs a packaged build while the other runs from source. The engineering
goal is:

> **Preserve a tested chat/file baseline across supported adjacent versions,
> and negotiate optional behavior explicitly.**

This is a compatibility policy and source-level negotiation contract, not proof
that any two historical or future builds interoperate. Shared capability names
do not prove identical frame semantics. Exact build pairs still need daemon-to-
daemon message/file tests, migration fixtures, and packaged-network evidence.
`tests/test_wire_compat_contract.py` and `tests/test_protocol_compat.py` pin the
bounded negotiation behavior below.

---

## The three layers, and which one governs compatibility

| Version | Example | Governs |
|---|---|---|
| **App / marketing version** | `0.21.4`, `1.0.0` | Display/update checks; legacy fallback only when a peer omits a wire version. |
| **Wire protocol version** | `OL1.2` (`PROTOCOL_VERSION`) | Frame shape. The real compatibility boundary. |
| **Capabilities** | `chat`, `files`, `file_cdc`, `folder_sync_bidi_v1`, … | Which optional features two peers may use together. |

The cardinal rule of the original bug we fixed (2026-06-04): **never
gate compatibility on the app version.** A routine `0.x → 1.0` release
with an unchanged wire must not break interop. `negotiate()` keys its
"major boundary" check off the **wire** version, falling back to the
app semver only for legacy peers that don't advertise a wire version.

## Rules every wire-touching change MUST follow

1. **Do not remove or rename a supported capability string without a staged
   migration.** A peer that still
   expects the old name silently loses that feature. Add new caps;
   never repurpose old ones. (Pinned: `test_advertised_caps_include_core_features`.)

2. **New optional wire behavior must be gated behind a capability.** Before using
   a feature, check the peer advertised it: `if FEATURE in peer_features`.
   Never assume a peer understands a frame just because you sent it.

3. **New fields on an existing message must be OPTIONAL while older supported
   peers remain in the compatibility window.** The
   receiver must tolerate their absence (old sender) and their presence
   (new sender). Never make an existing message type require a field
   an older build doesn't send.

4. **Unknown message types are ignored by the current dispatch loop.** This
   bounded behavior makes an unknown type a no-op; it does not make every
   possible semantic change compatible. The loop silently ignores
   unknown message types (there is no terminal `else` that raises), so
   a newer peer sending a frame an older peer doesn't know about is a
   no-op on the old side. Keep it that way.

5. **The negotiation function does not refuse solely on a version
   difference.** It may drop the selected mode (for example, to
   `baseline_cross_major`). Missing required/shared user capabilities can make
   this decision incompatible, and handshake/frame validation can fail later.
   (Pinned:
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
   - keep accepting v1 through a declared supported compatibility window,
   - remove it only after the exact supported build matrix and migration gates
     establish that doing so is safe. One Link ships no product-analytics
     telemetry that could prove the installed population has upgraded.

   (Pinned: `test_ratchet_header_frozen_at_v1`.)

7. **Bumping `PROTOCOL_VERSION`'s wire major is a breaking change.** It
   forces every mixed-major pair down to `baseline_cross_major` (chat +
   baseline file only). Do it deliberately, document the migration, and
   provide a negotiated path the same way as the ratchet (rule 6).
   (Pinned: `test_protocol_version_is_present_and_parseable`.)

## What negotiation currently selects (not end-to-end proof)

- **Same wire major** → intersect advertised capabilities and select the best
  known mode. Actual interoperation still depends on matching semantics.
- **Different wire major** (a real, deliberate framing break) →
  `baseline_cross_major`: attempt chat + baseline file transfer when both sides
  advertise those capabilities; advanced framing is disabled.
- **A peer omits wire version** → fall back to parseable app-version majors for
  the conservative decision; if those are also unavailable, no cross-major
  downgrade is inferred.
- **Missing required capability or zero shared capability** →
  `incompatible`. Current tested builds advertise `chat` + `files`, but that is
  not a statement about every historical/future or modified build.

## Where this lives in code

- `src/one_link/protocol_compat.py` — `negotiate()`, the decision engine.
- `src/one_link/daemon.py` — `PROTOCOL_VERSION`, `CAPS_FEATURES`, the
  `_build_caps` frame, and the receive-loop dispatch (unknown types
  fall through harmlessly).
- `src/one_link/double_ratchet.py` — `Header` (the v1-frozen header).
- `src/one_link/capabilities.py` — `LOCAL_CAPABILITIES` + the cap strings.
- `tests/test_wire_compat_contract.py` + `tests/test_protocol_compat.py`
  — the enforced contract.
