# Security policy

One Link is a privacy + sovereignty tool that real people rely on. We
take security reports seriously.

This file is the canonical responsible-disclosure entry point. The
in-depth threat model + cryptographic correctness contract lives
separately at [`docs/SECURITY.md`](docs/SECURITY.md).

## Reporting a vulnerability

**Do not file public GitHub issues for security bugs.** Vulnerability
reports go to:

```
weareone@oneunity.earth
```

PGP key (recommended for credible reports): published at
[https://github.com/Jphilbrick10.gpg](https://github.com/Jphilbrick10.gpg)
once we set up the multi-maintainer threshold-signing key. Until
then, reports in plaintext to the address above are accepted and
acknowledged within 72 hours.

Include:

- A clear description of the vulnerability.
- Steps to reproduce, or a proof-of-concept.
- Affected version (`one-link --version` or commit SHA).
- The threat model tier you believe is broken (T1-T9 in
  [`docs/SECURITY.md`](docs/SECURITY.md)).
- Your name / handle for credit (optional).

## What you can expect

- **Acknowledgement within 72 hours.** Even outside business hours;
  the maintainer treats reports as the priority job.
- **Initial assessment within 7 days.** We tell you whether we
  agree the report is a vulnerability + a rough severity rating.
- **Fix targeted within 30 days for critical reports**, 90 days
  for medium / low severity. If we can't hit that window we tell
  you why.
- **Coordinated disclosure.** Default 90-day disclosure window
  from the date of acknowledgement. We'll publish a CVE +
  advisory after the fix ships.
- **Public credit** unless you ask to remain anonymous.

## What we ask from you

- **Don't disclose publicly until the fix has shipped.** 90 days
  is the firm wall (per industry norm — Project Zero / CERT/CC
  alignment).
- **Don't test against production / third-party deployments**
  without explicit permission. The project's own rendezvous server
  is fair game for non-disruptive testing.
- **Don't extract or retain user data** beyond what's needed to
  demonstrate the vulnerability.

## Scope

In scope:

- The Python daemon (`src/one_link/`)
- The browser-as-peer code (`src/one_link/web/`)
- The rendezvous + relay servers (`src/one_link/rendezvous_server.py`,
  `src/one_link/relay_proto.py` and friends)
- Cryptographic primitives (channel handshake, Double Ratchet,
  group sender chains, lockbox, identity)
- Wire protocol (`src/one_link/wire.py`)

Out of scope:

- Vulnerabilities in third-party libraries (`cryptography`,
  `aiohttp`, `aiortc`, etc.) — report those upstream. We're happy
  to coordinate.
- Browser engine / OS / hardware vulnerabilities (Apple, Google,
  Mozilla, Microsoft). Same: upstream first.
- Issues that require the attacker to already have root on the
  user's machine, or full physical possession during an active
  session, are documented as out-of-scope in the threat model
  matrix; report them to us anyway but they may not qualify for
  bounty (when the program funds).

## Safe harbor

Good-faith security research conducted within this scope and
under coordinated disclosure will not be pursued legally. We
follow the [Disclose.io](https://disclose.io) safe-harbor norm.

## Bug bounty (planned)

A formal bug bounty with tiered payouts will be funded by
community donations once the project's foundation infrastructure
is in place. Until then, credit + a "Hall of Thanks" entry is what
we can offer; we appreciate that's not the same as money. If you
need a paid security engagement, reach out and we'll find a
budget — security work is the priority spend in this project.

## Past advisories

Will be listed here as `CVE-YYYY-NNNNN: short title (date)`.
The 2026-05-09 audit (commits `8857bcf` … `fbe066c`) closed 55+
internal findings ahead of any public-disclosure window; the
finding-by-finding record is in
[`docs/SECURITY_AUDIT_v0.7.0.md`](docs/SECURITY_AUDIT_v0.7.0.md)
and the 2026-05-09 audit findings file in the project's memory
notes.
