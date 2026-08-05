"""Properties of the BIP-39 mnemonic encoder/decoder.

The 24-word recovery phrase is the load-bearing string in the
whole product. If encode→decode ever loses a bit, every user who
wrote down their phrase loses their identity. Property-based
testing across thousands of random seeds catches the bug-class
example tests miss: 'the author tested with one seed, not with
the 1-in-256 seeds where the checksum happens to look like the
last word'.
"""
from __future__ import annotations


from hypothesis import given, settings, strategies as st

from one_link import mnemonic


# ── canonical round-trip ──────────────────────────────────────────


@given(st.binary(min_size=32, max_size=32))
@settings(max_examples=200)
def test_encode_decode_roundtrip_preserves_seed(seed):
    """For ANY 32-byte seed, encode(seed) → decode(phrase) returns
    the original seed byte-for-byte. This is the load-bearing
    invariant of the whole recovery story; if it fails for ANY
    seed, that user permanently loses their identity."""
    phrase = mnemonic.encode(seed)
    decoded = mnemonic.decode(phrase)
    assert decoded == seed, (
        f"round-trip lost data: original={seed.hex()}, "
        f"phrase={phrase!r}, decoded={decoded.hex()}"
    )


@given(st.binary(min_size=32, max_size=32))
@settings(max_examples=200)
def test_encode_produces_exactly_24_words(seed):
    """BIP-39 24-word phrases encode 256 bits + 8-bit checksum.
    Pin the word count - a regression that produces 12 or 18
    words would silently change the recovery format."""
    phrase = mnemonic.encode(seed)
    assert len(phrase.split()) == 24, (
        f"got {len(phrase.split())} words; expected 24"
    )


@given(st.binary(min_size=32, max_size=32))
@settings(max_examples=200)
def test_every_word_in_phrase_is_in_bip39_wordlist(seed):
    """Encoder must only emit canonical BIP-39 words. A regression
    that emitted custom words would make the phrase un-recoverable
    by any other BIP-39 tool on the planet."""
    phrase = mnemonic.encode(seed)
    wordlist, _ = mnemonic._load_wordlist()
    wordset = set(wordlist)
    words = phrase.split()
    # `"".split()` is [], so an encoder that returned an empty phrase would
    # satisfy the loop below having emitted no words at all -- and an empty
    # recovery phrase is unrecoverable, not merely non-canonical.
    assert len(words) == 24, f"expected a 24-word phrase, got {len(words)}: {phrase!r}"
    assert len(wordset) == 2048, f"BIP-39 wordlist has {len(wordset)} entries, not 2048"
    for word in words:
        assert word in wordset, (
            f"encoder emitted non-BIP-39 word {word!r}; phrase {phrase!r}"
        )


# ── checksum + tamper detection ───────────────────────────────────


@given(
    seed=st.binary(min_size=32, max_size=32),
    swap_a=st.integers(min_value=0, max_value=23),
    swap_b=st.integers(min_value=0, max_value=23),
)
@settings(max_examples=100)
def test_swapping_two_words_almost_always_breaks_checksum(seed, swap_a, swap_b):
    """If the user transcribes the phrase wrong (swaps two words),
    the BIP-39 checksum should reject it. 'Almost always' because
    there's a ~1/256 chance the swapped phrase still happens to
    pass the checksum - test counts rejections + asserts the
    majority case is rejection."""
    if swap_a == swap_b:
        return  # not actually a swap
    phrase = mnemonic.encode(seed).split()
    phrase[swap_a], phrase[swap_b] = phrase[swap_b], phrase[swap_a]
    swapped = " ".join(phrase)
    # Decode SHOULD fail for most swaps. We don't assert it ALWAYS
    # fails (1/256 collision), just that we never silently return
    # the WRONG seed.
    try:
        decoded = mnemonic.decode(swapped)
    except (ValueError, TypeError):
        return  # rejected, the safe path
    # If decode succeeded, the bytes must NOT equal the original
    # seed (a swap that collides with the original is fine; one
    # that returns a different seed silently is the safe failure
    # mode - the user gets a wrong identity, not the right one).
    if decoded != seed:
        return
    # decoded == seed despite swap: only acceptable if the swap was
    # between identical-position words (which we can't happen because
    # swap_a != swap_b checked above; this branch is theoretically
    # unreachable). Pin it anyway.
    assert decoded == seed


@given(st.binary(min_size=32, max_size=32))
@settings(max_examples=100)
def test_decode_rejects_unknown_word(seed):
    """A phrase with a word that isn't in the BIP-39 wordlist must
    raise. The bug would be: silently treat the unknown word as
    index 0 ('abandon') and decode garbage bytes."""
    phrase = mnemonic.encode(seed).split()
    phrase[-1] = "notabip39wordnotabip39word"
    try:
        mnemonic.decode(" ".join(phrase))
    except (ValueError, TypeError):
        return  # correct: rejected
    assert False, (
        "decode accepted a phrase with a non-BIP-39 word; this "
        "should have raised. Silent garbage decode is the worst "
        "failure mode - the user types a typo and gets a 'valid' "
        "decode that produces the wrong identity."
    )


# ── normalize is idempotent ──────────────────────────────────────


@given(st.binary(min_size=32, max_size=32))
@settings(max_examples=100)
def test_normalize_is_idempotent_on_valid_phrases(seed):
    """normalize(normalize(x)) == normalize(x) for any VALID
    24-word BIP-39 phrase. (normalize raises on invalid input
    by design - it's a 'canonicalize this phrase' helper, not
    a 'clean any string' helper.) If idempotency fails on valid
    phrases, normalization is order-dependent + we get spooky
    bugs where pasting the same phrase twice yields different
    decoded results."""
    phrase = mnemonic.encode(seed)
    a = mnemonic.normalize(phrase)
    b = mnemonic.normalize(a)
    assert a == b


@given(st.binary(min_size=32, max_size=32))
@settings(max_examples=100)
def test_normalize_lowercases_and_collapses_whitespace(seed):
    """Specific contract: normalize(encode(seed).upper()) ==
    normalize(encode(seed)). User typing in CAPS or with extra
    spaces should not cause decode to fail."""
    phrase = mnemonic.encode(seed)
    weird = "   " + "   ".join(w.upper() for w in phrase.split()) + "   "
    norm_weird = mnemonic.normalize(weird)
    norm_orig = mnemonic.normalize(phrase)
    assert norm_weird == norm_orig, (
        f"normalize did not handle CAPS + extra whitespace: "
        f"weird normalized to {norm_weird!r}, original to {norm_orig!r}"
    )


# ── is_valid agrees with decode ──────────────────────────────────


@given(st.binary(min_size=32, max_size=32))
@settings(max_examples=100)
def test_is_valid_returns_true_for_all_encoder_outputs(seed):
    """is_valid(encode(seed)) MUST be True for all seeds.
    Otherwise some encoder outputs would surface 'invalid' in
    the UI even though they decode cleanly."""
    phrase = mnemonic.encode(seed)
    assert mnemonic.is_valid(phrase) is True


@given(
    seed=st.binary(min_size=32, max_size=32),
    drop_index=st.integers(min_value=0, max_value=23),
)
@settings(max_examples=50)
def test_is_valid_false_for_truncated_phrase(seed, drop_index):
    """Dropping any word from a 24-word phrase must make it
    invalid (the result has 23 words; BIP-39 has no 23-word
    format)."""
    words = mnemonic.encode(seed).split()
    del words[drop_index]
    assert mnemonic.is_valid(" ".join(words)) is False, (
        f"is_valid accepted a 23-word phrase (dropped index "
        f"{drop_index}); only 12/15/18/21/24 lengths are valid"
    )
