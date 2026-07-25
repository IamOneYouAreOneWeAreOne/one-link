# Testing One Link

This is the local quick start. [`docs/TESTING.md`](docs/TESTING.md) describes
the test layers and CI contract in detail.

## Reproducible local setup

Use the repository lock instead of resolving an ad-hoc environment:

```bash
uv sync --frozen --extra dev --extra e2e
```

Browser tests also require a browser installed by Playwright:

```bash
uv run --frozen --extra e2e playwright install chromium firefox
```

## Required invocations

Run the main and browser suites separately. Their session-scoped event-loop
fixtures are intentionally isolated:

```bash
# Main unit + integration suite. Mirrors the full-suite workflow exclusions.
uv run --frozen --extra dev python -m pytest tests/ \
  --ignore=tests/e2e \
  --ignore=tests/test_call_reliability_soak.py \
  --deselect tests/test_pairing.py \
  -q --tb=short --maxfail=20

# Browser E2E.
ONE_LINK_RUN_BROWSER_E2E=1 \
  uv run --frozen --extra e2e python -m pytest tests/e2e/ -q --browser chromium

# Cross-engine, no-public-STUN transport authority.
ONE_LINK_RUN_BROWSER_E2E=1 \
  uv run --frozen --extra e2e python -m pytest \
  tests/e2e/test_peer_live_transport.py::test_two_isolated_peer_pages_complete_manual_webrtc_and_exchange_probe \
  tests/e2e/test_browser_identity_possession_live.py::test_required_mode_live_pair_owner_request_and_immediate_revoke \
  tests/e2e/test_call_local_candidate_live.py::test_call_media_local_candidate_augmentation_uses_real_browser_ice \
  -q --browser firefox
```

The browser suite's named screenshots are capture-for-review evidence, not a
pixel-diff regression gate. Normal runs write to the ignored
`test-results/screenshots/` directory, which CI uploads as an artifact. Use
`ONE_LINK_VISUAL_CAPTURE_DIR` for another artifact directory. Updating the
checked-in references under `tests/e2e/screenshots/` requires the deliberate
`ONE_LINK_UPDATE_VISUAL_BASELINES=1` opt-in; unsafe source-tree destinations
are rejected before any screenshot is written.

The repository also has native Rust tests, security gates, deterministic
soaks, platform probes, and performance gates. Follow the commands in the
workflows and [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) for a
release candidate; a passing subset is never a release sign-off.

## Coverage shape

The suite includes, among other areas:

- identity, handshake, channel, framing, replay, and malformed-input tests;
- transfer durability, retry, deduplication, receipts, recovery, and file-size
  boundary tests;
- state, capability, personal-device mesh, rendezvous, relay, and WebRTC tests;
- real subprocess/loopback daemon integration tests;
- browser-driven UI tests and real-OS probes; and
- Rust unit, property, fuzz-replay, and audit gates.

Test counts and runtimes change continuously, so this document deliberately
does not promise a fixed number or duration. Read the pytest summary from the
exact commit and environment being evaluated.

## Evidence limits

- Simulated and loopback tests do not replace physical multi-host,
  cross-network NAT, lossy-WAN, or long-duration soak evidence.
- CI configuration is an intended gate, not proof that the latest run passed.
- A green development suite does not establish production readiness,
  independent security review, whole-product reproducibility, or release
  provenance.
- One Link currently has no verified production release. The mutable
  `auto-latest` prerelease is not a trusted test or distribution baseline.
