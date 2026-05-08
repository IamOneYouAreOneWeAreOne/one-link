# Governance — project structure as security primitive

Status: living document. Companion to
[`PRINCIPLES.md`](./PRINCIPLES.md),
[`SOVEREIGNTY.md`](./SOVEREIGNTY.md), and
[`SECURITY.md`](./SECURITY.md).

Last updated: 2026-05-08.

> Engineering alone doesn't keep a project free of corporations;
> structure does. A perfectly-engineered codebase still falls if
> the entity holding the trademark accepts an acquisition, the
> maintainer accepts a NSL gag order alone, or the license permits
> a closed-source corporate fork.

This document is the project-structure complement to the engineering
controls in `SOVEREIGNTY.md`. It specifies the legal, procedural,
and ceremonial commitments that prevent corporate capture by
structure rather than by code.

---

## License — AGPLv3

**License:** GNU Affero General Public License v3 or later.

**Why AGPL specifically (not MIT, not Apache, not GPL):**

- **MIT / Apache permit closed forks.** A corporation can take
  the One Link codebase, add proprietary surveillance, ship as a
  closed-source competitor. We refuse to make that legal.
- **GPL covers binary distribution.** Modern services run as
  hosted SaaS without distributing the binary; GPL leaves a
  loophole.
- **AGPL closes the SaaS loophole.** Anyone who modifies One Link
  and offers it as a network service must publish their modified
  source.

The trade-off: AGPL deters some corporate adoption (which is
fine; we're not optimizing for corporate adoption). It strongly
encourages forks to publish their source, which is what "for the
people" requires.

**Implementation:**
- `LICENSE` file at repo root contains the AGPL-3.0-or-later text.
- Every source file carries a header:
  ```
  // SPDX-License-Identifier: AGPL-3.0-or-later
  // Copyright (c) <year> <Trademark Holder> and contributors.
  ```
- No CLA (Contributor License Agreement) that transfers ownership.
  Contributors retain copyright on their contributions; the
  cumulative work is collectively licensed AGPL.

---

## Trademark holding — non-profit only

**Holder:** a non-profit organization (501(c)(3) in the US, or
equivalent in another jurisdiction). Specifically NOT an
individual maintainer, NOT a company, NOT a foundation that
takes corporate sponsorship with influence.

**Why non-profit:**
- An individual can be coerced, bought, or compromised. A
  non-profit has board oversight and statutory restrictions.
- A for-profit company can be acquired. A 501(c)(3) cannot be
  acquired in the conventional sense; its assets must transfer
  to another non-profit on dissolution.
- A non-profit's books are public (Form 990 filings).

**Until the non-profit exists** (we're pre-incorporation as of
2026-05-08): the trademark is held by the founding maintainer
under a published trust deed that obligates transfer to the
non-profit upon incorporation.

**Use rules** (binding on the holder):
1. The "One Link" mark may be used only for software adhering to
   `PRINCIPLES.md` and this `GOVERNANCE.md`.
2. Forks that violate the principles must not use the name "One
   Link."
3. The mark may not be sold, licensed for-fee, or transferred to
   a for-profit entity. Transfer to another non-profit with
   identical principles is permitted upon dissolution.

---

## Release signing — multi-maintainer threshold

**Scheme:** Ed25519 signatures. Releases require **≥2-of-N**
maintainer signatures to be valid. N starts at 3 (founding
maintainers). Quorum can grow as the project grows; a single
maintainer signing alone is never sufficient.

**Why threshold:**
- Single-maintainer signing means a single key compromise =
  malicious release. Threshold means an attacker needs to
  compromise 2 simultaneously.
- A maintainer under coercion (NSL, blackmail, etc.) cannot ship
  a backdoored release alone. The other maintainers serve as
  attestation that the release wasn't compelled.

**Key custody:**
- Each maintainer's release-signing key lives on a hardware
  security module (YubiKey 5C / similar) that the maintainer
  physically possesses.
- Air-gapped key generation. Public keys published in source
  (`docs/maintainer_keys.md`).
- Rotation: every 2 years, or on suspected compromise. Rotation
  ceremony requires the existing quorum to sign the new keys.

**Service Worker enforcement:**
- The SW (per `SECURITY.md`) verifies every update against the
  pinned multi-key threshold. A release signed by 1-of-N is
  rejected. A release signed by ≥2-of-N proceeds.

---

## Refuse-acquisition charter

**Binding text** (incorporated into the non-profit's charter once
established; binding-by-published-policy until then):

> The One Link project, the entity holding its trademark, and
> the keys signing its releases SHALL NOT be sold, transferred,
> or operationally controlled by any for-profit entity. Offers
> of acquisition shall be declined publicly. The signing keys
> shall not be transferred outside the maintainer pool. The
> trademark shall not be licensed to a for-profit entity. This
> charter may be amended only by unanimous vote of all current
> maintainers AND a public 90-day comment period.

**Practical effect:** even if a corporation offers $1B for One
Link, the answer is "no" by binding charter. Maintainers who
would accept the offer can leave the project (free to fork under
AGPL); they cannot take the trademark, the canonical signing
keys, or the canonical release pipeline with them.

---

## Funding posture

**What we accept:**
- Individual donations (small, recurring, anonymous if desired).
- Crowdfunding (Open Collective, Liberapay, similar).
- Grants from non-profit foundations (with no influence clauses).

**What we refuse:**
- Corporate sponsorship with seat-at-the-table influence.
- Sponsorship that requires logo placement in the app
  (advertising-by-stealth).
- Investment of any kind. We're not a startup.
- Any funding that requires us to deviate from
  `PRINCIPLES.md`.

**Sustainability model:** the project costs are tiny by design (a
$5/mo VPS for the canonical rendezvous; domain registration; CI
minutes). Annual budget target: under $5,000. Funded entirely by
small donations from users.

If we ever need substantially more (paid maintainers, security
audits), the path is:
1. Public budget proposal.
2. Public funding round (donation drive).
3. If raised, books published quarterly.
4. If not raised, scope adjusts to fit available funds.

We never accept money to ship a feature corporate sponsors want.

---

## Maintainer covenant

Every maintainer signs a published covenant (as a Git-committed
text file with a maintainer's signature) before being added to
the threshold quorum. The covenant binds:

1. Custody of one's signing key on personal HSM.
2. Refusal to sign any release the maintainer hasn't reviewed.
3. Refusal to sign under coercion (NSL, gag order, etc.); the
   correct response is to recuse and notify other maintainers,
   who then collectively decide whether to halt the release
   pipeline temporarily.
4. Public disclosure of any conflict of interest (employment by
   relevant corporations, ownership of relevant equity, etc.).
5. Two-week notice on resignation, with secure handoff of public
   responsibilities.

A maintainer who breaches the covenant is removed from the
quorum by the remaining maintainers. Their signing key is
revoked; outstanding releases re-signed.

---

## Warrant canary

**The mechanism:**

A canary statement is published at a known canonical URL
(`/canary.txt` on the project's primary domain, plus mirrored
elsewhere) and updated on a fixed cadence (monthly, on the 1st).
The statement reads, in part:

```
One Link Warrant Canary — <month> <year>

As of <date>, the One Link project maintainers have NOT received:
  - Any National Security Letter, FISA order, or equivalent
    in any jurisdiction
  - Any compelled-access request requiring secrecy
  - Any subpoena targeting user data we do not hold (see note 1)
  - Any takedown order against the canonical release pipeline

Note 1: One Link by design does not hold user message content,
contact graphs, or any per-user identifying information beyond
what's in the public release commit log. We have no user data to
disclose.

Signed by ≥2-of-N maintainers, the keys for which are pinned in
docs/maintainer_keys.md.

  -- Maintainer A: <signature>
  -- Maintainer B: <signature>
```

**The signal:**
- A **fresh canary** signed monthly = no compelled access has been
  received.
- A **stale canary** (more than ~6 weeks old) = something happened.
  We deliberately don't lie ("we received nothing" when we did);
  we just stop signing.
- The absence is the message. Users monitoring the canary URL
  see staleness automatically.

**Limitations (named honestly):**
- Some legal regimes can compel a fake canary. We mitigate by
  threshold-signing: it's harder to compel ≥2 of N maintainers in
  different jurisdictions to lie.
- We commit to maintainers across multiple jurisdictions to avoid
  single-jurisdiction compulsion risk.

---

## Maintainer geographic distribution

The threshold quorum is designed to be **multi-jurisdictional**.
At least 2 of the N maintainers must reside in different
jurisdictions. This makes a single-government compulsion order
insufficient to forge a release or fake the canary.

This is documented in `docs/maintainer_keys.md` as
non-identifying jurisdiction tags (e.g., "EU - non-Schengen,"
"North America - non-US," "South America"). Specific identities
are public; specific addresses are not.

---

## Code of conduct + community governance

The community follows the Contributor Covenant 2.1 (industry
standard, well-tested) with one addition: the principles in
`PRINCIPLES.md` are non-negotiable. Contributors who advocate for
violating them (e.g., proposing telemetry "for the user's own
good") are not breaching the CoC, but their proposals will not
merge.

Decisions on disputed merges go through:
1. Public PR discussion (default).
2. Maintainer rough-consensus.
3. If unresolved: full maintainer vote with quorum.
4. Major architectural changes: 30-day public RFC + comment period.

---

## Project amnesty / sunset clause

If the project becomes structurally compromised (e.g.,
maintainer quorum compromised; canary chain broken; codebase
shipped a backdoor in a release that 2-of-N signed maliciously),
the project's structural commitment is to:

1. **Publicly disclose the compromise** within 7 days of
   discovery, with full forensic detail.
2. **Revoke the canonical signing keys**. No further releases
   from the compromised pipeline.
3. **Recommend users uninstall** until a clean fork is
   established under new keys + new maintainer quorum.
4. **Publish post-mortem** with root-cause analysis and
   structural changes.
5. **Sunset the trademark** rather than transfer it to a
   compromised entity. The mark goes dormant; a clean
   community fork can adopt a new name.

The reputational cost is real and unrecoverable. That's the
point: the cost prevents shortcuts.

---

## Audit cadence

Per `PRINCIPLES.md`, every quarter:

1. **Verify the canary chain.** Each signed canary cross-checks
   against the prior month's; gaps trigger investigation.
2. **Audit financial books.** Public; reviewed by an independent
   non-profit auditor annually.
3. **Re-verify maintainer covenants.** Each maintainer re-signs
   the covenant annually, with an opportunity to declare new
   conflicts of interest.
4. **Threshold key health check.** Each signing key still
   accessible to its maintainer; each HSM still functional.
5. **Re-publish the warrant canary** (per the monthly cadence).

A governance document that doesn't get audited becomes
decoration. The audit cadence is the difference between a
charter and a charter that holds.

---

## What this collectively prevents

| Capture vector | Prevention |
|---|---|
| Maintainer accepts acquisition | Refuse-acquisition charter |
| Maintainer is bought / blackmailed | Threshold-quorum signing (single key insufficient) |
| Maintainer is compelled to ship backdoor (NSL etc.) | Multi-jurisdictional quorum + warrant canary |
| For-profit fork goes proprietary | AGPLv3 license blocks closed-source distribution |
| Trademark sold | Non-profit holding + use-rule restriction |
| CDN compromised | Pinned release key + signed updates |
| CA compromised | Pinned release key (HTTPS not the trust root) |
| OS keychain compelled disclosure | OPFS-stored identity, not OS keychain |
| Single maintainer compromised | Threshold quorum |
| All maintainers compromised | Project amnesty / sunset clause; community fork |

This is what governance buys that engineering cannot.
