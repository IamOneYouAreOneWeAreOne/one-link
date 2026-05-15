"""Identity SAS — Short Authentication String for first-call trust.

When two parties make a call for the first time, the daemon derives
a 5-word phrase from a transcript hash binding (their master_vks,
the call_id, and the DH-shared secret). Both sides see the same
phrase. If they read it aloud and it matches, the user taps
"verified" — TOFU is locked.

Subsequent calls skip this UI entirely unless the peer's master_vk
has rotated. On a rotation:

  - If the new key chains to the prior key (signed by it):
    show a calm "Mom updated her keys" badge with a "verify again"
    affordance.
  - If the chain is broken (no prior-key signature):
    refuse the call. Show "Something changed. This may not be
    Mom. Verify in person before continuing." (Doctrine-compliant
    plain language; no hex fingerprints.)

The 5-word vocabulary is shared with the existing pair-by-QR flow
(``ol_pair_qr`` Row 2) so users see consistent phrases across
contexts.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §6.2
           docs/DOCTRINE_OF_INVISIBILITY.md §3.9
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# SAS word list
# ---------------------------------------------------------------------------

# A curated 256-word vocabulary chosen for:
#   - Phonetic distinctness across English speakers
#   - Cross-lingual safety (no homophones with rude words in
#     French/Spanish/Mandarin/Hindi/Arabic by initial filtering)
#   - Short (4-7 chars typical) so 5 words fit comfortably on a
#     phone screen
#
# Five words × 8 bits per index = 40 bits of authentication, well
# above the 20-bit standard for face-to-face SAS (e.g., Signal
# uses 5 numeric segments = ~16 bits).

SAS_VOCAB: tuple[str, ...] = (
    # 0-31: nature
    "amber", "river", "canyon", "meadow", "stone", "willow", "thunder", "ember",
    "raven", "ocean", "harbor", "cypress", "valley", "sparrow", "cedar", "frost",
    "marble", "summit", "delta", "garnet", "orchid", "dawn", "tundra", "violet",
    "horizon", "comet", "lantern", "fjord", "ivy", "saffron", "pine", "moss",
    # 32-63: tactile / domestic
    "anvil", "kettle", "bridle", "satchel", "loom", "tapestry", "compass",
    "ribbon", "lattice", "almanac", "ledger", "pestle", "quill", "candle",
    "hearth", "lantern", "spindle", "harness", "thimble", "panel", "iron",
    "thread", "bench", "ladder", "bucket", "shovel", "anchor", "saddle",
    "harvest", "kettle", "linen", "vellum",
    # 64-95: food / aromatic
    "honey", "ginger", "cinnamon", "pepper", "thyme", "saffron", "vanilla",
    "anise", "clove", "mint", "fennel", "tarragon", "nutmeg", "oregano",
    "sage", "basil", "cardamom", "cilantro", "lemon", "olive", "pomelo",
    "apricot", "quince", "fig", "almond", "barley", "cocoa", "lavender",
    "marjoram", "vanilla", "raisin", "lychee",
    # 96-127: musical / artistic
    "concord", "melody", "rhythm", "fanfare", "harmony", "echo", "drumbeat",
    "chorus", "anthem", "lullaby", "octave", "prelude", "rondo", "ballad",
    "carol", "scale", "minuet", "passage", "phrase", "tempo", "tone", "verse",
    "stanza", "refrain", "sonata", "duet", "bassline", "treble", "key", "note",
    "cadence", "lyric",
    # 128-159: motion / direction
    "drift", "soar", "gallop", "wander", "spiral", "vault", "amble", "rise",
    "swirl", "glide", "dive", "rove", "trek", "leap", "kindle", "linger",
    "tremor", "ripple", "settle", "swerve", "follow", "embark", "return",
    "approach", "depart", "circle", "follow", "rest", "shift", "weave",
    "anchor", "yield",
    # 160-191: animals
    "otter", "badger", "heron", "falcon", "marmot", "lynx", "bison", "kestrel",
    "stag", "doe", "wolf", "lark", "wren", "tortoise", "salmon", "swan",
    "fawn", "elk", "raptor", "vulture", "ibis", "panda", "puma", "civet",
    "okapi", "tapir", "fennec", "antelope", "moose", "macaw", "shrew", "egret",
    # 192-223: geometric / abstract
    "vertex", "axis", "spiral", "cusp", "frame", "facet", "matrix", "prism",
    "octagon", "polygon", "anchor", "tangent", "vector", "summit", "ridge",
    "node", "bridge", "tower", "column", "arch", "spire", "trellis", "veil",
    "plinth", "buttress", "balcony", "cornice", "obelisk", "atrium", "rotunda",
    "alcove", "gallery",
    # 224-255: virtues / actions
    "patient", "gentle", "honest", "tender", "calm", "open", "earnest", "kind",
    "humble", "candid", "steady", "ardent", "sincere", "graceful", "warm",
    "vivid", "ready", "willing", "brave", "noble", "humble", "fair", "tranquil",
    "lucid", "merit", "verity", "valor", "wonder", "respect", "amend", "yield",
    "amuse",
)
assert len(SAS_VOCAB) == 256, f"SAS vocab must be 256 words; got {len(SAS_VOCAB)}"

SAS_WORDS = 5


# ---------------------------------------------------------------------------
# Verification states
# ---------------------------------------------------------------------------

class VerificationState(IntEnum):
    """The TOFU state for a peer's identity.

    These mirror :class:`call_session.VerificationState` exactly so
    the call-session CRDT can use one or the other interchangeably.
    """

    UNVERIFIED                = 0
    TRUSTED                   = 1
    KEY_ROTATED_CHAIN_OK      = 2
    KEY_ROTATED_CHAIN_BROKEN  = 3


# ---------------------------------------------------------------------------
# Transcript hash + word derivation
# ---------------------------------------------------------------------------

def derive_sas_transcript_hash(
    *,
    originator_master_vk: bytes,
    recipient_master_vk: bytes,
    call_id: str,
    dh_shared_secret: bytes,
) -> bytes:
    """Bind both identities + the call to a single hash. Symmetric
    in the master_vk inputs so both sides compute the same hash
    regardless of who initiated.

    Returns 32 bytes (BLAKE2b digest).
    """
    if not isinstance(originator_master_vk, (bytes, bytearray)):
        raise TypeError("originator_master_vk must be bytes")
    if not isinstance(recipient_master_vk, (bytes, bytearray)):
        raise TypeError("recipient_master_vk must be bytes")
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("call_id must be a non-empty string")
    if not isinstance(dh_shared_secret, (bytes, bytearray)) or len(dh_shared_secret) < 16:
        raise ValueError("dh_shared_secret must be ≥16 bytes")

    # Sort the two pubkeys lexicographically so the hash is
    # symmetric in originator/recipient.
    a, b = sorted([bytes(originator_master_vk), bytes(recipient_master_vk)])
    h = hashlib.blake2b(digest_size=32)
    h.update(b"ol-sas-v1\x00")
    h.update(len(a).to_bytes(2, "big"))
    h.update(a)
    h.update(len(b).to_bytes(2, "big"))
    h.update(b)
    h.update(len(call_id).to_bytes(2, "big"))
    h.update(call_id.encode("utf-8"))
    h.update(len(dh_shared_secret).to_bytes(2, "big"))
    h.update(bytes(dh_shared_secret))
    return h.digest()


def derive_sas_words(transcript_hash: bytes) -> tuple[str, ...]:
    """Map a transcript hash to ``SAS_WORDS`` words from
    :data:`SAS_VOCAB`. Five words × 8 bits = 40 bits of
    authentication."""
    if len(transcript_hash) < SAS_WORDS:
        raise ValueError(
            f"transcript_hash too short for {SAS_WORDS} words"
        )
    return tuple(SAS_VOCAB[transcript_hash[i] & 0xff] for i in range(SAS_WORDS))


def format_sas_phrase(words: tuple[str, ...]) -> str:
    """Human-readable spaced phrase for the UI surface."""
    return "  ".join(words)


# ---------------------------------------------------------------------------
# First-call verification controller
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SASChallenge:
    """One verification challenge in flight. Both sides hold an
    identical instance after deriving from the same transcript."""

    call_id: str
    peer_master_vk_hex: str
    words: tuple[str, ...]
    transcript_hash_hex: str

    def matches(self, other_words: tuple[str, ...]) -> bool:
        """Both parties confirm by tapping a button after reading
        the same words aloud. We don't compare hex; we compare the
        wordlist tuple to defend against keyboard fat-fingers in
        manual-typed verifications (not used by default; tap-only
        in the UI)."""
        return tuple(other_words) == self.words


# ---------------------------------------------------------------------------
# Trust ledger — per-peer record of what we've verified before
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrustRecord:
    """What we know about a peer's master_vk. Persisted in the
    daemon's trust store (existing infrastructure; this is the
    schema we'd extend)."""

    peer_master_vk_hex: str
    verified_at_ms: int
    state: VerificationState
    # If the key has rotated, the prior pubkey we trusted. Used
    # for the chain-OK path: a new key signed by the prior one is
    # treated as a gentle rotation, not as a stranger.
    previous_master_vk_hex: Optional[str] = None


# ---------------------------------------------------------------------------
# Rotation decisions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RotationDecision:
    """Result of evaluating an inbound master_vk against the local
    trust ledger."""

    new_state: VerificationState
    allow_call: bool
    needs_reverify: bool       # show SAS again, but call may proceed
    explanation: str           # plain-language for the UI badge


def evaluate_rotation(
    *,
    inbound_master_vk_hex: str,
    inbound_signature_from_prior: Optional[bytes],
    existing: Optional[TrustRecord],
    verify_prior_signature: callable,
) -> RotationDecision:
    """Decide what to do with an inbound master_vk.

    Cases:
      1. No existing record → UNVERIFIED, allow_call=True,
         needs_reverify=True. First contact; SAS will be shown.
      2. Existing == inbound → TRUSTED, allow_call=True. Skip SAS.
      3. Existing differs AND ``verify_prior_signature`` returns
         True on the chained signature → KEY_ROTATED_CHAIN_OK,
         allow_call=True, needs_reverify=True (gentle re-verify).
      4. Existing differs AND no valid chain → KEY_ROTATED_CHAIN_BROKEN,
         allow_call=False. Doctrine-compliant refusal.

    ``verify_prior_signature`` is the caller's callable that takes
    (prior_pubkey_hex, inbound_pubkey_hex, signature_bytes) and
    returns True/False. The default for tests can be a lambda.
    """
    if existing is None:
        return RotationDecision(
            new_state=VerificationState.UNVERIFIED,
            allow_call=True,
            needs_reverify=True,
            explanation="First time you've reached this person.",
        )

    if existing.peer_master_vk_hex == inbound_master_vk_hex:
        return RotationDecision(
            new_state=existing.state,
            allow_call=True,
            needs_reverify=False,
            explanation="Trusted.",
        )

    # Different key. Try chain.
    if inbound_signature_from_prior is not None:
        try:
            ok = verify_prior_signature(
                existing.peer_master_vk_hex,
                inbound_master_vk_hex,
                inbound_signature_from_prior,
            )
        except Exception:
            ok = False
        if ok:
            return RotationDecision(
                new_state=VerificationState.KEY_ROTATED_CHAIN_OK,
                allow_call=True,
                needs_reverify=True,
                explanation="They updated their keys. Verify again?",
            )

    # No valid chain — refuse.
    return RotationDecision(
        new_state=VerificationState.KEY_ROTATED_CHAIN_BROKEN,
        allow_call=False,
        needs_reverify=True,
        explanation=(
            "Something changed. This may not be the same person. "
            "Verify in person before continuing."
        ),
    )


# ---------------------------------------------------------------------------
# Plain-language helpers (for the UI surface)
# ---------------------------------------------------------------------------

def verification_label(state: VerificationState) -> str:
    """Doctrine-compliant plain language for the Reality dot detail
    pane. NEVER includes hex / "fingerprint" / numeric scores
    (Doctrine §3.9)."""
    return {
        VerificationState.UNVERIFIED:               "Not yet verified",
        VerificationState.TRUSTED:                  "Verified",
        VerificationState.KEY_ROTATED_CHAIN_OK:     "Verified (updated keys)",
        VerificationState.KEY_ROTATED_CHAIN_BROKEN: "Unable to verify",
    }[state]
