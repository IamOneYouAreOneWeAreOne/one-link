# Release sign-off checklist

Every tag push triggers `reproducible_release.yml` which builds +
signs the artifacts. The checklist below is what a human (or a
multi-sig co-signer) MUST verify GREEN before the tag goes out.
Most of these gates already run as CI workflows; the checklist
turns "did CI pass" into a concrete decision a human can make.

## Pre-tag (run on the source you're about to tag)

- [ ] **`tests.yml` green on the target SHA.** The fast subset
      (~200 tests, ~2 min). Quick sanity.

- [ ] **`full_suite_and_e2e.yml` green on the target SHA.** The
      real gate: full pytest suite + Playwright E2E + multi-OS
      native picker probe. Runs on Linux + Windows + macOS.

- [ ] **`security.yml` green on the target SHA.** pip-audit
      against the lockfile + bandit SAST scan + SBOM generation.
      Any HIGH-severity finding blocks release.

- [ ] **`synthetic_monitor.yml` green for the past 7 days.**
      No transient failures in the morning + evening runs - if
      the monitor has been flaky, the symptom is in production
      too.

- [ ] **`fuzz_nightly.yml` green for the past 7 days.** No new
      proptest failures on the crypto / onion / Sphinx primitives.

- [ ] **`one-link verify-this-install` rollup hash recorded in the
      release notes.** Run on a fresh checkout at the tag; paste
      the rollup BLAKE2s-128 value into the release notes under
      a `### Source rollup hash` heading. Auditors compare this
      against their own `verify-this-install` output to confirm
      they have the same source on disk.

## Tag + push

- [ ] **Tag is annotated** (`git tag -a vX.Y.Z -m "..."`), not
      lightweight. Lightweight tags don't carry the signature
      Sigstore needs.

- [ ] **Tag commit message names every breaking change.** A user
      reading `git log v(N-1)..vN` should see what they need to
      do (or what they should re-test) before upgrading.

- [ ] **Tag pushed to origin.** Triggers `reproducible_release.yml`
      automatically.

## Post-tag (after reproducible_release.yml completes)

- [ ] **`reproducible_release.yml` green across all three OS
      runners.** Build + Sigstore sign + attestation upload.

- [ ] **Hash-of-hashes matches across runners.** Each runner's
      build emits a BLAKE3 hash of every artifact; the rollup
      MUST be byte-identical Linux ↔ Windows ↔ macOS. If they
      diverge, the build is non-reproducible + cannot be
      meaningfully signed.

- [ ] **Sigstore bundle attached to the release.** Verify with:

      ```
      cosign verify-blob \
        --certificate-identity-regexp '.*' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        --bundle <artifact>.sigstore \
        <artifact>
      ```

- [ ] **Co-signer signature attached** (if `RELEASE_COSIGNER_ID`
      org secret is set). Per the governance model, two-party
      signing is the production trust gate.

- [ ] **Manual smoke on a fresh device.** Download the release
      artifact, install it on a machine that wasn't part of CI,
      run `one-link verify-this-install`, confirm the rollup
      matches the release notes.

## Rollback

If a release ships and a user-affecting regression surfaces
within 24h:

1. Tag the previous-good commit as `vX.Y.Z+1-rollback` (do NOT
   delete the bad tag — Sigstore transparency log already has it).
2. Update `latest` release pointer to the rollback tag.
3. Write a postmortem in `docs/incidents/<date>.md` describing
   what shipped, what broke, what the new tests are that would
   have caught it.

## Why this checklist exists

A release is a public statement: "this binary is what the source
on the tag says it is, signed by the maintainer, reproducible by
any auditor, tested across every code path we know how to test."
The checklist is the operational form of that statement. Skipping
items breaks the public promise.
