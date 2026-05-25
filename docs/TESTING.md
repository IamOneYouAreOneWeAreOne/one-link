# Testing strategy

One Link's testing layers are designed to catch different bug classes.
Knowing which layer catches what helps you write the right test for
the bug you just fixed (and helps reviewers spot when a fix is missing
its regression test).

## The layers

```
                                   what each layer catches
                                   ──────────────────────────────────
   ┌─────────────────────────┐
   │  Real-user clicking     │  Bugs that need a human to see
   │  (manual smoke)         │  ("this looks wrong", "this feels slow")
   └─────────────────────────┘
              ▲
              │ feeds bugs into ↓
   ┌─────────────────────────┐
   │  Browser E2E            │  Pixel overlap, iframe headers, click
   │  (tests/e2e/, chromium) │  handler hijacks, dialog z-order,
   │                         │  multi-state UI combos, security headers
   └─────────────────────────┘
              ▲
              │ if E2E catches it but no unit test does ↓
   ┌─────────────────────────┐
   │  Integration            │  Cross-module behavior, real subprocess
   │  (tests/test_*_v021,    │  daemon interactions, wire protocol
   │   tests/harness.py)     │  round-trips, FTS5 query semantics
   └─────────────────────────┘
              ▲
              │ if integration catches it ↓
   ┌─────────────────────────┐
   │  Unit + source-text     │  Single-function correctness,
   │  (tests/test_*.py)      │  contract pinning, fail-closed shape
   │                         │  invariants, doctrine compliance
   └─────────────────────────┘
              ▲
              │ if any specific platform/OS-only ↓
   ┌─────────────────────────┐
   │  Platform probes        │  Real-Windows COM, real-macOS osascript,
   │  (CI matrix)            │  real-Linux zenity, CLSID registration
   └─────────────────────────┘
```

## CI workflows

| Workflow | Trigger | What it gates |
|---|---|---|
| `tests.yml` | every push + PR | Fast unit subset (~200 tests). Quick feedback. |
| `full_suite_and_e2e.yml` | every push + PR | **Full pytest suite (6400+)** + **Playwright E2E** on Linux + Windows + **real-OS Windows folder-picker probe**. The safety-net gate. |
| `release.yml` | tag push | Reproducible builds, Sigstore signing, artifact upload. |
| `security.yml` | nightly | pip-audit, bandit, SBOM regeneration. |
| `fuzz_nightly.yml` | nightly | proptest fuzzers over Sphinx + onion + crypto primitives. |

The `tests.yml` matrix is intentionally narrow (only ~200 tests) for
fast PR feedback. **`full_suite_and_e2e.yml` is the real gate** —
every UI / platform / wire-protocol regression must show as red here
before merge.

## When to write which test

You fixed a bug. Which layer needs a regression?

**The bug was visible to the user in a browser.** Write a Playwright
test in `tests/e2e/` that exercises the same flow the user did.
Examples: PDF preview iframe blank, search input visual overlap,
Details click also opens the file, no-matches state showing welcome
screen. These bugs are categorically invisible to source reading.

**The bug was in code logic.** Write a unit test in `tests/test_*.py`
that calls the affected function with the inputs that broke. Examples:
`search_messages("k")` returns 0 results, `mint_certificate` produces
the wrong fingerprint, `transition_peer_fingerprint` misses a table.

**The bug was in a multi-module interaction.** Write an integration
test that exercises the whole flow with a real subprocess daemon.
Examples: rotation cert sent from A applies on B, recovery wizard
endpoint round-trips with realistic state.

**The bug was platform-specific.** Add a probe to the Windows /
macOS / Linux job in `full_suite_and_e2e.yml`. Example: the modern
Windows folder picker CLSID being unregistered on certain Win11
builds — invisible to all Linux CI and all mocked unit tests, but
caught by `scripts/ci_probe_modern_folder_picker.py` against a real
Windows runner.

**The bug was a security-header / response-shape regression.** Add
both: a unit test against the handler function, and an E2E test that
hits the live endpoint via `requests` and asserts the headers. The
production middleware can override what the handler sets; only a
live-daemon assertion catches that case.

## Running tests locally

```bash
# Fast: the same subset CI runs first.
pytest tests/test_identity.py tests/test_wire.py tests/test_paths.py \
       tests/test_channel.py tests/test_discovery.py tests/test_cli.py

# Full unit + integration (matches the full_suite job).
pytest tests/ --ignore=tests/e2e

# Browser E2E (one-time: pip install -e .[e2e] && playwright install chromium).
pytest tests/e2e/

# Windows-only: real folder-picker COM probe.
python scripts/ci_probe_modern_folder_picker.py
```

**IMPORTANT — invocation isolation:** `pytest tests/e2e/` and
`pytest tests/` (anything else) MUST run as separate invocations.
pytest-playwright starts a session-scoped event loop that
conflicts with the async fixtures in the integration tests
(`Cannot run the event loop while another loop is running`).
The CI `full_suite_and_e2e.yml` workflow runs them as separate
jobs for this reason. If you see that error locally, you ran
both in one `pytest` command.

## What NOT to do

- **Don't write source-text gates as a replacement for behavioral
  tests.** A regex that asserts `"raise" not in body` catches code
  shape, not runtime behavior. Pair it with an actual call.
- **Don't mock the thing you're trying to test.** The picker test
  fixture sets `ONE_LINK_DISABLE_NATIVE_PICKER=1` so no real dialog
  ever pops in CI — that's the right call for test hygiene, but it
  means the real picker code path has zero unit coverage. The
  Windows CI probe is what fills that gap.
- **Don't skip the test you can't get to pass.** Either delete it
  (with a written reason in the commit message) or fix the underlying
  problem. Skipped tests rot in place + the bug-class they cover
  silently degrades.
