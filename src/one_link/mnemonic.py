"""BIP-39 mnemonic encoding for the One Link master seed.

What this gives the user
------------------------
A single human-friendly recovery phrase — 24 ordinary English
words — that backs up the entire identity + at-rest encryption
of the daemon. If you lose your laptop, type those 24 words on
your new device and you become "the same user again": peers
recognize you, your at-rest-encrypted chat history decrypts,
group chain keys reload, your stored capability policies stay
intact.

The same model that Bitcoin / Ethereum / hardware-wallet users
rely on, applied to a privacy-first chat tool. No corporate
cloud sync; no email-based password reset; no third-party
recovery service. The user controls the secret on a piece of
paper they keep wherever they keep paper they care about.

Cryptographic posture
---------------------
We use the BIP-39 English wordlist (2048 words, the standard
canonical list from bitcoin/bips) to encode 256 bits of
entropy + 8 bits of checksum into 24 words. The encoding is
deterministic + collision-resistant; any single typo in the
phrase fails the SHA-256 checksum at decode time.

We DO NOT implement BIP-39's PBKDF2 seed-derivation step
(which exists to mix the mnemonic with an optional passphrase
into a 64-byte seed). Instead, the One Link master seed IS
the 256 bits of mnemonic entropy directly. Reasoning:

  1. PBKDF2 in BIP-39 was designed to slow down brute-force on
     a low-entropy passphrase. Our use case has no extra
     passphrase to mix in; the 256 entropy bits are already
     fully random.
  2. Keeping the entropy = master seed = no derivation step
     means the wordlist round-trip is straightforward. Anyone
     can verify the encode/decode against the BIP-39 spec
     without needing to also implement the HMAC-SHA512 PBKDF2.
  3. The application layer derives DOMAIN-SEPARATED subkeys
     (DRK, identity, future) from the seed via HKDF-SHA256
     with explicit info strings (master_seed.py). HKDF gives
     us proper key separation; PBKDF2 wouldn't add anything.

Length choice: 24 words = 256 bits of entropy + 8 bits of
checksum. The shorter 12-word variant (128 bits) is
insufficient for the post-quantum threat model we plan toward
(2028+ Grover-search reduces 128 bits to effective 64 bits;
256 bits stays at effective 128 bits even under Grover).
24 words is the de facto standard for any seed that's expected
to outlive a single decade.
"""
from __future__ import annotations

import hashlib
import secrets
from importlib import resources
from pathlib import Path
from typing import Iterable


# BIP-39 specifies 2048 words. We ship the canonical English list.
_WORDLIST_FILENAME = "bip39-english.txt"
_WORDLIST: list[str] | None = None
_WORD_INDEX: dict[str, int] | None = None


def _load_wordlist() -> tuple[list[str], dict[str, int]]:
    global _WORDLIST, _WORD_INDEX
    if _WORDLIST is not None and _WORD_INDEX is not None:
        return _WORDLIST, _WORD_INDEX
    try:
        text = (
            resources.files("one_link").joinpath(f"data/{_WORDLIST_FILENAME}").read_text(encoding="utf-8")
        )
    except Exception:
        # Filesystem fallback (dev mode without installed package).
        here = Path(__file__).resolve().parent / "data" / _WORDLIST_FILENAME
        text = here.read_text(encoding="utf-8")
    words = [w.strip() for w in text.splitlines() if w.strip()]
    if len(words) != 2048:
        raise RuntimeError(
            f"BIP-39 wordlist must be exactly 2048 words; got {len(words)}"
        )
    if len(set(words)) != 2048:
        raise RuntimeError("BIP-39 wordlist contains duplicates")
    # Each word is at most 8 characters by BIP-39 spec; the first 4
    # of each word are unique within the list (a property the spec
    # guarantees for prefix-typing UX).
    index = {w: i for i, w in enumerate(words)}
    _WORDLIST = words
    _WORD_INDEX = index
    return words, index


# Public API -----------------------------------------------------------------


SEED_LEN_BYTES = 32   # 256 bits
WORD_COUNT = 24       # 256 entropy + 8 checksum = 264 bits = 24 * 11


def generate_seed() -> bytes:
    """CSPRNG-fresh 32-byte master seed. The same value the BIP-39
    mnemonic will encode."""
    return secrets.token_bytes(SEED_LEN_BYTES)


def encode(seed: bytes) -> str:
    """Encode 32 random bytes as a 24-word BIP-39 mnemonic.

    Returns a single space-separated string. Caller should display
    this to the user with paper-backup instructions; the secret
    must NEVER be transmitted off-device.
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) != SEED_LEN_BYTES:
        raise ValueError(f"seed must be {SEED_LEN_BYTES} bytes, got {len(seed)}")
    seed = bytes(seed)
    words, _ = _load_wordlist()

    # 256 entropy bits + 8 checksum bits = 264 bits = 24 * 11
    checksum_byte = hashlib.sha256(seed).digest()[0]
    bits = int.from_bytes(seed, "big") << 8 | checksum_byte
    out = []
    for i in range(WORD_COUNT):
        # Highest 11 bits first.
        shift = (WORD_COUNT - 1 - i) * 11
        idx = (bits >> shift) & 0x7FF
        out.append(words[idx])
    return " ".join(out)


def decode(phrase: str) -> bytes:
    """Decode a 24-word BIP-39 mnemonic back to 32 entropy bytes.

    Raises ValueError on:
      - wrong word count
      - any unknown word
      - checksum mismatch (typo / fabrication)

    Whitespace is normalized; case is normalized to lowercase since
    the BIP-39 wordlist is all-lowercase.
    """
    if not isinstance(phrase, str):
        raise TypeError("phrase must be a string")
    tokens = phrase.strip().lower().split()
    if len(tokens) != WORD_COUNT:
        raise ValueError(
            f"mnemonic must be {WORD_COUNT} words, got {len(tokens)}"
        )
    _, index = _load_wordlist()
    bits = 0
    for tok in tokens:
        idx = index.get(tok)
        if idx is None:
            raise ValueError(f"unknown BIP-39 word: {tok!r}")
        bits = (bits << 11) | idx
    # Split off the trailing 8 checksum bits.
    checksum = bits & 0xFF
    seed_int = bits >> 8
    seed = seed_int.to_bytes(SEED_LEN_BYTES, "big")
    expected = hashlib.sha256(seed).digest()[0]
    if checksum != expected:
        raise ValueError(
            "BIP-39 checksum mismatch — likely a typo. Re-check the "
            "spelling of every word against the printed phrase."
        )
    return seed


def normalize(phrase: str) -> str:
    """Round-trip a phrase through decode→encode to canonicalize
    whitespace + case. Useful for displaying the user's typed
    phrase back to them with the spelling we accepted."""
    return encode(decode(phrase))


# Helpers --------------------------------------------------------------------


def is_valid(phrase: str) -> bool:
    try:
        decode(phrase)
        return True
    except (ValueError, TypeError):
        return False


def words_for_completion(prefix: str) -> Iterable[str]:
    """Return BIP-39 words that begin with ``prefix`` (case-insensitive).
    For UX completion in entry forms — the standard wordlist guarantees
    that the first 4 chars uniquely identify a word."""
    words, _ = _load_wordlist()
    p = prefix.strip().lower()
    if not p:
        return iter(words)
    return (w for w in words if w.startswith(p))
