"""Path-PII protection for the daemon's at-rest indexes.

Audit M30 (2026-05-09): the desktop daemon stores fully-qualified
filesystem paths in two indexed columns:

  - ``chunk_sources.path`` — used to hydrate cache misses by reading
    bytes from a known location on disk
  - ``file_index_cache.path`` — used to look up a previously-computed
    chunk manifest for the same source file

These paths reveal the user's home-dir layout (e.g.
``/Users/Alex/Documents/Confidential/...``) to a T4 (lost device)
attacker who has unlocked at-rest access. The audit's recommended
fix was to hash the path or store basename + folder-root reference.

The trouble with both naïve fixes:

  - **Hash-only**: kills the path → bytes lookup. We need to actually
    open the file at that path to serve a chunk; an opaque hash
    can't do that.

  - **Basename + root reference**: requires schema redesign, restricts
    every path to be under a known synced folder, breaks the
    ad-hoc-send case where any file on disk can be a chunk source.

Outside-the-box fix: **deterministic authenticated encryption** with
AES-SIV (RFC 5297). Same plaintext path → same ciphertext (so
indexes work + lookup is fast), but the ciphertext is opaque to
anyone without the seed-derived key. Authenticated, so a flipped
byte invalidates the tag.

Why AES-SIV and not AES-GCM?

AES-GCM with a fixed nonce is broken (catastrophic key recovery
after two collisions). AES-GCM with a random nonce is non-
deterministic, which kills our index. AES-SIV is purpose-built for
deterministic AEAD: it derives a synthetic IV from the plaintext +
AAD via a CMAC-like construction, so the same input deterministically
produces the same output, but the IV remains effectively random for
distinct inputs. RFC 5297 + Hoang et al. 2017 prove the security
bound: the only structural attack is "same plaintext under same key
produces same ciphertext" — which is exactly what we want for
indexing.

Wire format
-----------

Encrypted paths are written as ASCII strings prefixed with
``~OL1~`` (tilde-bracketed marker that real filesystem paths never
start with, on either Windows or POSIX). The body is the urlsafe-
base64 of the AES-SIV synthetic-IV-prefixed ciphertext.

Reads detect the marker and decrypt; absent the marker, they treat
the value as legacy cleartext so old rows remain accessible. New
writes always go through encryption when a key is available.

Backward compat — what happens without a master seed?
-----------------------------------------------------

The encryptor is only constructed when the daemon has a seed (the
v0.20.7 master-seed flow). Daemons without a seed (legacy installs
that never ran ``backup init`` or ``backup restore``) keep storing
cleartext paths. The audit threat is T4 + at-rest unlock; for a
seed-less install there's no recoverable secret to derive a key
from anyway, so cleartext is no worse than the prior posture.
"""
from __future__ import annotations

import base64
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PATH_PII_MARKER = "~OL1~"
# AES-SIV with a 64-byte key (two 32-byte AES halves internally).
PATH_PII_KEY_LEN = 64
# HKDF info string for the path-PII key. Distinct from every other
# subkey derived from the master seed so a leak of the path-PII key
# doesn't compromise the DRK / identity / backup keys.
_INFO_PATH_PII = b"OL/master/path-pii-aes-siv|v1"


def derive_path_pii_key(seed: bytes) -> bytes:
    """Derive a 64-byte AES-SIV key from the 32-byte master seed.

    The path-PII key is a separate domain from every other derived
    key. If it's ever compromised, the worst case is "attacker can
    decrypt path columns for this install." It cannot be used to
    decrypt chat content, identity-sign, or unwrap the backup key."""
    if len(seed) != 32:
        raise ValueError("master seed must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=PATH_PII_KEY_LEN,
        salt=None,
        info=_INFO_PATH_PII,
    ).derive(bytes(seed))


class PathPIIEncryptor:
    """Deterministic AEAD wrapper for filesystem-path columns.

    Construct once at daemon startup with the master seed. Pass to
    ``State.set_path_pii_encryptor`` so chunk_sources / file_index_cache
    reads + writes go through ``wrap`` / ``unwrap``.

    Same plaintext + AAD → same ciphertext (the property we need so
    SQLite's PRIMARY KEY + UNIQUE indexes still de-duplicate on the
    canonical path). Different plaintext or different AAD → different
    ciphertext. RFC 5297 Sec 6 proves the security bound.
    """

    def __init__(self, seed: bytes):
        self._key = derive_path_pii_key(seed)
        self._aead = AESSIV(self._key)

    def wrap(self, path: str, *, aad: bytes = b"") -> str:
        """Encrypt a path string; return the marker-prefixed
        urlsafe-base64 ciphertext. Empty input yields empty output
        (callers that want NULL semantics keep storing NULL)."""
        if not path:
            return ""
        plaintext = path.encode("utf-8", errors="strict")
        # AESSIV.encrypt takes a list of associated-data items.
        # We use one: a domain-separation tag bound to the column
        # (caller-supplied) so the same path encrypted under a
        # different AAD produces different ciphertext — keeps
        # chunk_sources rows from accidentally matching
        # file_index_cache rows on the same path string.
        ct = self._aead.encrypt(plaintext, [aad])
        body = base64.urlsafe_b64encode(ct).rstrip(b"=").decode("ascii")
        return PATH_PII_MARKER + body

    def unwrap(self, value: str, *, aad: bytes = b"") -> Optional[str]:
        """Decrypt a wrapped path. Legacy cleartext (no marker) is
        returned unchanged. Returns None if the value is wrapped but
        decryption fails (tamper / wrong key / different install).

        The legacy-cleartext passthrough is the rolling-upgrade hatch:
        rows written before this module was wired in stay readable
        until they're rewritten via the normal write path."""
        if not value:
            return value
        if not value.startswith(PATH_PII_MARKER):
            # Legacy cleartext path — return as-is.
            return value
        body = value[len(PATH_PII_MARKER):]
        try:
            pad = "=" * ((4 - len(body) % 4) % 4)
            ct = base64.urlsafe_b64decode((body + pad).encode("ascii"))
            plaintext = self._aead.decrypt(ct, [aad])
            return plaintext.decode("utf-8", errors="strict")
        except Exception:
            return None


def is_wrapped(value: str) -> bool:
    """True iff ``value`` is a wrapped (marker-prefixed) path."""
    return isinstance(value, str) and value.startswith(PATH_PII_MARKER)
