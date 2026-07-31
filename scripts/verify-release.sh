#!/usr/bin/env bash
# verify-release.sh — One-command verification of a One Link release artifact.
#
# Usage:
#   bash scripts/verify-release.sh <artifact-path> <release-tag>
#
# Where <artifact-path> is a .tar.gz, .whl, or other release file
# downloaded from https://github.com/coherence-energy-labs/one-link/releases.
#
# What this script does, in order:
#   1. Verifies the signed SHA256SUMS manifest next to the artifact.
#   2. Computes sha256sum of the artifact and confirms an exact filename match
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
#   - A caller-provided sigstore-python installation, or the exact
#     hash-locked sigstore environment in this repository's uv.lock
#   - The Sigstore Rekor transparency log (Linux Foundation
#     OpenSSF, append-only public log)
# It does NOT trust:
#   - This script's host page
#   - Any single private signing key
#   - Any third-party download mirror that doesn't carry the
#     matching .sigstore bundle

set -euo pipefail

REPO="coherence-energy-labs/one-link"
WORKFLOW_PATH=".github/workflows/release.yml"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

# ── argument parsing ──────────────────────────────────────────
if [ "$#" -ne 2 ]; then
  cat <<EOF
verify-release.sh — verify a One Link release artifact

Usage:
  bash scripts/verify-release.sh <artifact-path> <release-tag>

Examples:
  bash scripts/verify-release.sh one-link-linux-x86_64.zip v0.21.0
  bash scripts/verify-release.sh one_link-0.21.0-py3-none-any.whl v0.21.0

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
RELEASE_TAG="$2"
ARTIFACT_DIR="$(dirname "$ARTIFACT")"
ARTIFACT_NAME="$(basename "$ARTIFACT")"
SUMS="${ARTIFACT_DIR}/SHA256SUMS"
SUMS_SIG="${ARTIFACT_DIR}/SHA256SUMS.sigstore"
ARTIFACT_SIG="${ARTIFACT}.sigstore"

# Artifact filenames are normalized differently by each packager (for example,
# the project version `0.21.0-alpha` becomes `0.21.0a0` in wheel filenames),
# and standalone binary names contain no version at all. Never guess signing
# identity from a filename: require the release tag the user intended to trust.
if [[ ! "$RELEASE_TAG" =~ ^v[0-9][0-9A-Za-z.+-]*$ ]]; then
  echo "ERROR: invalid release tag '$RELEASE_TAG' (expected v<version>, no slashes)" >&2
  exit 1
fi

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
if [ ! -f "$SUMS_SIG" ]; then
  echo "ERROR: signed-manifest bundle not found at $SUMS_SIG" >&2
  echo "Download SHA256SUMS.sigstore from the same tagged release." >&2
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

# Prefer the repository's reviewed, hash-locked verifier environment. If this
# script was copied out of the repository, accept an already-installed Sigstore
# client but never download or execute an unpinned package automatically.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
if command -v uv >/dev/null 2>&1 \
   && [ -f "$REPO_ROOT/uv.lock" ] \
   && [ -f "$REPO_ROOT/pyproject.toml" ]; then
  SIGSTORE=(uv run --project "$REPO_ROOT" --frozen --only-group release-tools python -m sigstore)
else
  if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "ERROR: Python 3.11+ and sigstore-python 4.4.0 are required." >&2
    exit 1
  fi
  PY="$(command -v python3 || command -v python)"
  if ! "$PY" -c "import sigstore; assert sigstore.__version__ == '4.4.0'" >/dev/null 2>&1; then
    echo "ERROR: sigstore-python 4.4.0 is not installed." >&2
    echo "Use this repository's locked uv environment or provision the verifier explicitly." >&2
    exit 1
  fi
  SIGSTORE=("$PY" -m sigstore)
fi

EXPECTED_REF="refs/tags/${RELEASE_TAG}"
EXPECTED_IDENTITY="https://github.com/${REPO}/${WORKFLOW_PATH}@${EXPECTED_REF}"

echo "─────────────────────────────────────────────────"
echo "verify-release.sh"
echo "  artifact:      $ARTIFACT"
echo "  expected tag:  ${EXPECTED_REF}"
echo "  signing ident: ${EXPECTED_IDENTITY}"
echo "─────────────────────────────────────────────────"

# ── step 1: authenticate the manifest before trusting its hashes ──
echo "[1/3] verifying Sigstore attestation on SHA256SUMS..."
"${SIGSTORE[@]}" verify identity \
    --bundle "$SUMS_SIG" \
    --cert-identity "$EXPECTED_IDENTITY" \
    --cert-oidc-issuer "$OIDC_ISSUER" \
    "$SUMS" \
  || { echo "  FAIL: SHA256SUMS Sigstore signature does not verify" >&2; exit 1; }
echo "  OK"

# ── step 2: hash matches one exact manifest filename ─────────
echo "[2/3] checking SHA-256 against authenticated manifest..."
ACTUAL_HASH="$(sha256 "$ARTIFACT" | awk '{print $1}')"
EXPECTED_HASHES="$(awk -v name="$ARTIFACT_NAME" 'NF == 2 && $2 == name { print $1 }' "$SUMS")"
MATCH_COUNT="$(printf '%s\n' "$EXPECTED_HASHES" | awk 'NF { count++ } END { print count + 0 }')"
if [ "$MATCH_COUNT" -ne 1 ]; then
  echo "  FAIL: expected exactly one manifest entry for $ARTIFACT_NAME, found $MATCH_COUNT" >&2
  exit 1
fi
EXPECTED_HASH="$EXPECTED_HASHES"
if [[ ! "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]]; then
  echo "  FAIL: malformed SHA-256 for $ARTIFACT_NAME in signed manifest" >&2
  exit 1
fi
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
  echo "  FAIL: hash mismatch for $ARTIFACT_NAME" >&2
  echo "    expected: $EXPECTED_HASH" >&2
  echo "    actual:   $ACTUAL_HASH" >&2
  exit 1
fi
echo "  OK: $ACTUAL_HASH"

# ── step 3: sigstore verify the artifact directly ────────────
echo "[3/3] verifying Sigstore attestation on $ARTIFACT_NAME..."
"${SIGSTORE[@]}" verify identity \
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
