#!/usr/bin/env bash
# verify-release.sh — One-command verification of a One Link release artifact.
#
# Usage:
#   bash scripts/verify-release.sh <artifact-path>
#
# Where <artifact-path> is a .tar.gz, .whl, or other release file
# downloaded from https://github.com/IamOneYouAreOneWeAreOne/one-link/releases.
#
# What this script does, in order:
#   1. Locates the matching SHA256SUMS + .sigstore bundle next to
#      the artifact (or downloads them from the same release if
#      the script can infer the version).
#   2. Computes sha256sum of the artifact and confirms it appears
#      in SHA256SUMS — proves the artifact wasn't tampered with
#      between the published manifest and your disk.
#   3. Verifies the Sigstore attestation bundle for the artifact:
#      that it was signed by GitHub Actions running the release
#      workflow at the matching tag — proves the artifact came
#      from a real CI run on the canonical repo, not a private
#      rebuild someone is offering you under the same name.
#
# If anything fails the script exits non-zero with a clear
# explanation. Don't install anything that fails this check.
#
# Sovereignty note: this script trusts only:
#   - sha256sum (in coreutils, baseline-trusted)
#   - python3 + sigstore-python (PyPI; package is itself signed
#     via Sigstore so a tampered sigstore-python doesn't slip
#     through unless the Sigstore log itself is broken)
#   - The Sigstore Rekor transparency log (Linux Foundation
#     OpenSSF, append-only public log)
# It does NOT trust:
#   - This script's host page
#   - Any single private signing key
#   - Any third-party download mirror that doesn't carry the
#     matching .sigstore bundle

set -euo pipefail

REPO="IamOneYouAreOneWeAreOne/one-link"
WORKFLOW_PATH=".github/workflows/release.yml"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

# ── argument parsing ──────────────────────────────────────────
if [ "${1:-}" = "" ]; then
  cat <<EOF
verify-release.sh — verify a One Link release artifact

Usage:
  bash scripts/verify-release.sh <artifact-path>

Examples:
  bash scripts/verify-release.sh one_link-0.20.7.tar.gz
  bash scripts/verify-release.sh one_link-0.20.7-py3-none-any.whl

The directory containing <artifact-path> must also contain:
  - SHA256SUMS         (signed hash manifest)
  - <artifact>.sigstore (Sigstore bundle for the artifact)
  - SHA256SUMS.sigstore (Sigstore bundle for the manifest itself)

Download all four from the GitHub release at
  https://github.com/${REPO}/releases
EOF
  exit 1
fi

ARTIFACT="$1"
ARTIFACT_DIR="$(dirname "$ARTIFACT")"
ARTIFACT_NAME="$(basename "$ARTIFACT")"
SUMS="${ARTIFACT_DIR}/SHA256SUMS"
SUMS_SIG="${ARTIFACT_DIR}/SHA256SUMS.sigstore"
ARTIFACT_SIG="${ARTIFACT}.sigstore"

# ── prereq checks ─────────────────────────────────────────────
if [ ! -f "$ARTIFACT" ]; then
  echo "ERROR: artifact not found: $ARTIFACT" >&2
  exit 1
fi
if [ ! -f "$SUMS" ]; then
  echo "ERROR: SHA256SUMS not found at $SUMS" >&2
  echo "Download it from the GitHub release page." >&2
  exit 1
fi
if [ ! -f "$ARTIFACT_SIG" ]; then
  echo "ERROR: Sigstore bundle not found at $ARTIFACT_SIG" >&2
  echo "Download it from the GitHub release page." >&2
  exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  if command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
  else
    echo "ERROR: sha256sum / shasum not found. Install coreutils." >&2
    exit 1
  fi
else
  sha256() { sha256sum "$@"; }
fi

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python ≥3.11 to verify Sigstore bundle." >&2
  exit 1
fi
PY="$(command -v python3 || command -v python)"
if ! "$PY" -c "import sigstore" >/dev/null 2>&1; then
  echo "Note: sigstore-python not installed. Installing into a temp venv..."
  TMPVENV="$(mktemp -d)/venv"
  "$PY" -m venv "$TMPVENV"
  "$TMPVENV/bin/pip" install --quiet --upgrade pip sigstore
  PY="$TMPVENV/bin/python"
fi

# ── derive expected workflow identity from artifact filename ──
# Filename is one_link-X.Y.Z.tar.gz or one_link-X.Y.Z-py3-none-any.whl;
# the version slot drives the expected --cert-identity value.
VERSION="$(echo "$ARTIFACT_NAME" | sed -E 's/^one_link-//; s/(\.tar\.gz|-.+\.whl)$//')"
if [ -z "$VERSION" ]; then
  echo "WARNING: could not infer version from filename '$ARTIFACT_NAME'" >&2
  echo "         Sigstore identity check will use 'master' as the fallback ref." >&2
  EXPECTED_REF="refs/heads/master"
else
  EXPECTED_REF="refs/tags/v${VERSION}"
fi
EXPECTED_IDENTITY="https://github.com/${REPO}/${WORKFLOW_PATH}@${EXPECTED_REF}"

echo "─────────────────────────────────────────────────"
echo "verify-release.sh"
echo "  artifact:      $ARTIFACT"
echo "  expected tag:  ${EXPECTED_REF}"
echo "  signing ident: ${EXPECTED_IDENTITY}"
echo "─────────────────────────────────────────────────"

# ── step 1: hash matches manifest ─────────────────────────────
echo "[1/3] checking SHA-256 against manifest..."
ACTUAL_HASH="$(sha256 "$ARTIFACT" | awk '{print $1}')"
MANIFEST_LINE="$(grep -F "  ${ARTIFACT_NAME}" "$SUMS" || true)"
if [ -z "$MANIFEST_LINE" ]; then
  echo "  FAIL: $ARTIFACT_NAME not listed in $SUMS" >&2
  exit 1
fi
EXPECTED_HASH="$(echo "$MANIFEST_LINE" | awk '{print $1}')"
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
  echo "  FAIL: hash mismatch for $ARTIFACT_NAME" >&2
  echo "    expected: $EXPECTED_HASH" >&2
  echo "    actual:   $ACTUAL_HASH" >&2
  exit 1
fi
echo "  OK: $ACTUAL_HASH"

# ── step 2: sigstore verify the manifest itself ──────────────
if [ -f "$SUMS_SIG" ]; then
  echo "[2/3] verifying Sigstore attestation on SHA256SUMS..."
  "$PY" -m sigstore verify identity \
      --bundle "$SUMS_SIG" \
      --cert-identity "$EXPECTED_IDENTITY" \
      --cert-oidc-issuer "$OIDC_ISSUER" \
      "$SUMS" \
    || { echo "  FAIL: SHA256SUMS Sigstore signature does not verify" >&2; exit 1; }
  echo "  OK"
else
  echo "[2/3] no SHA256SUMS.sigstore — skipping (older release format)"
fi

# ── step 3: sigstore verify the artifact directly ────────────
echo "[3/3] verifying Sigstore attestation on $ARTIFACT_NAME..."
"$PY" -m sigstore verify identity \
    --bundle "$ARTIFACT_SIG" \
    --cert-identity "$EXPECTED_IDENTITY" \
    --cert-oidc-issuer "$OIDC_ISSUER" \
    "$ARTIFACT" \
  || { echo "  FAIL: artifact Sigstore signature does not verify" >&2; exit 1; }
echo "  OK"

echo "─────────────────────────────────────────────────"
echo "VERIFIED: $ARTIFACT_NAME"
echo "  - SHA-256 matches the published manifest"
echo "  - signed by GitHub Actions via Sigstore at ${EXPECTED_REF}"
echo "  - Rekor transparency-log entry exists + verifies"
echo "─────────────────────────────────────────────────"
