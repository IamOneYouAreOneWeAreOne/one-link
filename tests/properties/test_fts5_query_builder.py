"""Properties of the FTS5 prefix-match query builder.

The bug we shipped this week ('typing k returns 0 results') had a
specific property nobody had pinned: 'for every message body, every
non-empty alphanumeric prefix of every word in that body should
return that message'. This file pins it + several related
invariants over 100s of generated inputs per run.
"""
from __future__ import annotations

import re
import sqlite3
import string

import pytest
from hypothesis import HealthCheck, example, given, settings, strategies as st

from one_link.state import State, _normalize_user_query_to_fts5_prefix


# ── normalizer-shape invariants (no DB needed) ─────────────────────


_ALNUM = string.ascii_letters + string.digits


@given(st.text())
def test_normalizer_never_raises(raw):
    """The normalizer is called with arbitrary user input from the
    search box. It MUST NOT raise on any input - that would surface
    as a 500 from /api/search and a broken UI."""
    out = _normalize_user_query_to_fts5_prefix(raw)
    assert isinstance(out, str)


@given(st.text(min_size=1))
def test_normalizer_output_is_safe_for_fts5_match(raw):
    """Whatever the normalizer outputs must be valid as the right-
    hand side of `messages_fts MATCH ?`. We don't have a cheap FTS5
    parser here; the practical proxy is: the output contains ONLY
    word chars, '*', spaces, and double-quoted phrases. No raw
    parens / colons / hyphens leak through to FTS5 where they'd
    flip syntax (e.g. `field:` is a field-restricted query)."""
    out = _normalize_user_query_to_fts5_prefix(raw)
    if not out:
        return  # empty is always safe
    # Pass-through case: a fully-quoted phrase. Accept as-is.
    if out.startswith('"') and out.endswith('"'):
        return
    # Tokenized case: quoted tokens separated by spaces, each ending in '*'.
    for tok in out.split():
        assert tok.startswith('"') and tok.endswith('"*')
        bare = tok[1:-2]
        # The quoted token must be alphanumeric / underscore (\w).
        assert re.fullmatch(r"\w+", bare), (
            f"normalizer leaked a non-\\w token: {tok!r} from {raw!r}"
        )


@given(st.text(max_size=256))
# deadline is a WALL-CLOCK assertion inside a correctness property, and
# these run on shared CI. One example of an in-memory FTS5 query took
# 2817ms against a 2000ms deadline on a loaded windows-latest runner and
# hypothesis reported it as FlakyFailure -- the runner stalled, the parser
# did not regress. Raised well past any realistic stall rather than removed:
# a genuinely pathological normalizer (accidentally quadratic on a 256-char
# input) would blow through 30s, so the blowup check survives while the
# false alarm does not.
@settings(max_examples=250, deadline=30000)
@example(raw="hello world")
@example(raw="prefix")
def test_every_normalized_query_is_accepted_by_real_fts5(raw):
    """Parser safety is a runtime property, not just a character whitelist.

    The `@example` cases are load-bearing, not decoration. The body returns
    early when the normalizer yields an empty query, so a normalizer that
    regressed to ALWAYS empty would make all 250 generated cases return
    without touching FTS5 -- 250 green examples proving nothing. Pinning two
    inputs that must normalize to something guarantees the MATCH below is
    executed at least twice per run.
    """

    query = _normalize_user_query_to_fts5_prefix(raw)
    if not query:
        return
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE VIRTUAL TABLE probe USING fts5(body)")
        connection.execute("INSERT INTO probe(body) VALUES (?)", (raw,))
        connection.execute(
            "SELECT rowid FROM probe WHERE probe MATCH ?", (query,)
        ).fetchall()
    finally:
        connection.close()


@given(st.text(alphabet=_ALNUM, min_size=1, max_size=64))
def test_alnum_single_word_becomes_prefix_match(word):
    """For any non-empty alphanumeric word, the normalizer produces
    exactly that word with a trailing '*'. This is the contract
    the prefix-match feature depends on."""
    out = _normalize_user_query_to_fts5_prefix(word)
    assert out == f'"{word}"*'


@given(
    st.lists(
        st.text(alphabet=_ALNUM, min_size=1, max_size=16),
        min_size=2, max_size=5,
    ),
)
def test_multi_word_query_is_implicit_and(words):
    """Each word becomes 'word*'; the joiner is a single space
    (FTS5 implicit-AND). No commas, no quotes, no extra glue."""
    raw = " ".join(words)
    out = _normalize_user_query_to_fts5_prefix(raw)
    expected = " ".join(f'"{word}"*' for word in words)
    assert out == expected


@pytest.mark.parametrize("operator", ["AND", "OR", "NOT", "NEAR"])
def test_reserved_fts5_operators_are_quoted_prefix_terms(operator):
    assert _normalize_user_query_to_fts5_prefix(operator) == f'"{operator}"*'


@given(st.text(alphabet=" \t\n\r", max_size=20))
def test_whitespace_only_returns_empty(blanks):
    """Whitespace-only queries return empty so the API handler can
    skip the DB hit entirely (FTS5 MATCH on '' raises). Pin this
    so a future tokenizer change doesn't accidentally return ' '."""
    assert _normalize_user_query_to_fts5_prefix(blanks) == ""


@given(st.text(alphabet="!@#$%^&()[]{};:'\"\\|/<>?,.", max_size=20))
def test_special_chars_only_returns_empty(garbage):
    """Pure-symbol input has no word chars to extract; output must
    be empty (caller returns [] without hitting FTS5)."""
    assert _normalize_user_query_to_fts5_prefix(garbage) == ""


# ── end-to-end DB-backed invariants ────────────────────────────────


@pytest.fixture
def state(tmp_path):
    s = State(tmp_path / "props.db")
    s.upsert_peer(
        fingerprint="aa" * 32, short_id="alice",
        pubkey=b"\x01" * 32, hostname="alice.test",
    )
    try:
        yield s
    finally:
        s.close()


@given(
    body=st.text(alphabet=_ALNUM + " ", min_size=3, max_size=120)
              .filter(lambda s: any(c.isalnum() for c in s)),
    prefix_len=st.integers(min_value=1, max_value=8),
)
@settings(
    max_examples=100, deadline=30000,
    # State is a function-scoped fixture but hypothesis warns when
    # function-scoped state mutates between examples (we wipe + re-
    # insert each iteration so it's safe).
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_every_prefix_of_every_word_finds_the_message(state, body, prefix_len):
    """THE invariant the picker bug violated: for any message body,
    every prefix of every word in it should match. If a user typed
    the first N letters of a word in any message, they should find
    that message."""
    msg_id = "prop_msg"
    # Wipe + re-insert so each example tests a fresh state.
    with state._write_lock:
        state._conn.execute("DELETE FROM messages")
        state._conn.execute("DELETE FROM messages_fts")
        state._conn.commit()
    state.record_message(
        id=msg_id, ts_ms=1000, direction="in",
        peer_fp="aa" * 32, msg_type="TEXT", body=body,
    )

    words = [w for w in re.findall(r"\w+", body) if len(w) >= prefix_len]
    if not words:
        return  # body had no words long enough; nothing to test

    for word in words:
        prefix = word[:prefix_len]
        results = state.search_messages(prefix, limit=10)
        ids = {m.id for m in results}
        assert msg_id in ids, (
            f"prefix {prefix!r} (from word {word!r}) did not find "
            f"the body {body!r}; results={ids}. This is exactly the "
            "bug the prefix-match feature is supposed to prevent."
        )


@given(
    bodies=st.lists(
        st.text(alphabet=_ALNUM + " ", min_size=3, max_size=80)
              .filter(lambda s: any(c.isalnum() for c in s)),
        min_size=2, max_size=8, unique=True,
    ),
)
@settings(
    max_examples=50, deadline=30000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_disjoint_queries_return_disjoint_results(state, bodies):
    """Plant N distinct messages. For any query that matches one
    message and NOT another (because the matched-word's prefix
    doesn't appear in the unmatched body), the result set must
    contain the first message ID and not the second.

    Catches a class of bug where the prefix normalizer accidentally
    matches too much (e.g. always returns all messages)."""
    with state._write_lock:
        state._conn.execute("DELETE FROM messages")
        state._conn.execute("DELETE FROM messages_fts")
        state._conn.commit()
    for i, body in enumerate(bodies):
        state.record_message(
            id=f"m_{i}", ts_ms=1000 + i, direction="in",
            peer_fp="aa" * 32, msg_type="TEXT", body=body,
        )
    for i, body in enumerate(bodies):
        # Find a word that appears in body i but in NO other body.
        body_words = set(re.findall(r"\w+", body.lower()))
        other_words: set[str] = set()
        for j, other in enumerate(bodies):
            if j == i:
                continue
            other_words |= set(re.findall(r"\w+", other.lower()))
        unique_words = body_words - other_words
        if not unique_words:
            continue
        word = next(iter(unique_words))
        if len(word) < 2:
            continue
        results = state.search_messages(word, limit=20)
        ids = {m.id for m in results}
        assert f"m_{i}" in ids
        # Stronger: results must NOT contain any other body's id
        # IF the word doesn't appear in that body. (Prefix-match
        # may match other bodies' prefixes; constrain via the
        # whole-word check first.)
        for j in range(len(bodies)):
            if j == i:
                continue
            j_words = set(re.findall(r"\w+", bodies[j].lower()))
            j_has_prefix = any(
                w.startswith(word.lower()) for w in j_words
            )
            if not j_has_prefix:
                assert f"m_{j}" not in ids, (
                    f"query {word!r} (unique to body {i}: {body!r}) "
                    f"falsely matched body {j} ({bodies[j]!r}); "
                    f"that body has no word with prefix {word!r}"
                )
