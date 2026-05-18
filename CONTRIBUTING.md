# Contributing to One Link

Thanks for considering a contribution. This document is short and
covers the things that matter most.

## Before you start

- **Read [`NOTICE`](NOTICE)** - the project's "for the people"
  charter and the reasoning behind the AGPLv3 license. By
  contributing, you agree your contribution will be licensed
  under AGPLv3.
- **Read [`docs/SECURITY.md`](docs/SECURITY.md)** - the threat
  model. Anything you ship has to live up to it.
- **Read [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md)** - the
  Reach / Hide / Async / Depth / Defang ship-gate.

## How we review changes

Every change passes these gates:

1. **Tests stay green.** `python -m pytest -q` must pass on a
   fresh checkout before review. CI runs the same gate.
2. **No new dependencies without justification.** Each new
   dependency is supply-chain risk. The bar is "no other path
   exists" or "this is a vetted, audited library with no
   telemetry."
3. **No telemetry, no analytics, no phone-home of any kind.**
   This is non-negotiable. If your change adds an outbound HTTP
   request to an origin the user did not configure, it gets
   reverted at review.
4. **Threat-model alignment.** If the change introduces a new
   surface (a new wire kind, a new endpoint, a new file format),
   the PR description must say which threat tiers (T1-T9) the
   surface affects and how it's defended.
5. **Reproducible.** Build outputs must be deterministic. If
   your change introduces non-determinism (timestamp embedding,
   random padding without a seed, etc.), fix it before merge.

## Security-sensitive changes

Anything touching:

- `src/one_link/channel.py`
- `src/one_link/double_ratchet.py`
- `src/one_link/groups_crypto.py`
- `src/one_link/identity.py`
- `src/one_link/lockbox.py`
- `src/one_link/pairing.py`
- `src/one_link/rendezvous_proto.py` / `rendezvous_server.py`

…is under stricter review. Expect a longer review window and
likely a request for an external cryptographic review before
merge if the change touches a primitive.

If you're not sure whether your change qualifies, err on the side
of asking in the PR description.

## Reporting vulnerabilities

**Do not file public PRs / issues for security bugs.** See
[`SECURITY.md`](SECURITY.md) for the responsible-disclosure
process.

## Style

- Python: PEP 8 with descriptive docstrings on public functions.
  Existing code is the reference.
- JavaScript: same. ES2017+, no transpiler.
- Comments document the **why**, not the **what**. Code reviewers
  read both; future maintainers read the comments.

## License

By submitting a contribution, you certify that you have the right
to license your work under AGPL-3.0-or-later, and you agree your
contribution will be released under that license. (This is the
"DCO-style" agreement; we don't require a CLA.)

## Maintainer

Until the project incorporates as a non-profit foundation,
contributions go to:

- Maintainer: One Link contributors <weareone@oneunity.earth>
- Code: https://github.com/IamOneYouAreOneWeAreOne/one-link
