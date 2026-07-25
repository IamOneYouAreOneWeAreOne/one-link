"""v0.21.x search: forgiving prefix-match for plain-user queries.

The raw FTS5 MATCH expression treats user input as exact token
queries, so typing 'k' only matches messages with the standalone
token 'k' - not 'kanye', 'kjg', 'oksana'. Plain users expect
substring-feeling search. Convert each typed token to a
parser-safe prefix-match (`"token"*`) so single-letter searches do something
useful.

Power users can still phrase-search by wrapping their query in
double quotes ('"hello world"') - the normalizer detects that
shape and passes through to FTS5's literal-phrase syntax.
"""
from __future__ import annotations


import pytest

from one_link.state import State, _normalize_user_query_to_fts5_prefix


# ── helper: normalizer behavior ─────────────────────────────────────


@pytest.mark.parametrize("raw,expected", [
    # Single letter: was the original bug ('k' matched nothing).
    ("k", '"k"*'),
    # Multi-letter prefix: still prefix.
    ("kan", '"kan"*'),
    # Multi-token: AND'd prefixes (FTS5 whitespace = implicit AND).
    ("hello world", '"hello"* "world"*'),
    # Mixed case: FTS5's default tokenizer is case-insensitive, so
    # we just pass tokens through verbatim - no extra normalization.
    ("Kanye", '"Kanye"*'),
    # Tokens with internal apostrophes split (\\w+ excludes ').
    ("don't", '"don"* "t"*'),
    # Special chars stripped (the user typed 'C:\\path' or 'foo(bar)').
    ("C:\\path", '"C"* "path"*'),
    ("foo(bar)", '"foo"* "bar"*'),
    # FTS5 grammar words must remain literal searchable terms.
    ("AND", '"AND"*'),
    ("or", '"or"*'),
    # Empty / whitespace-only -> empty (caller returns [] without DB hit).
    ("", ""),
    ("   ", ""),
    # Garbage-only (no \\w chars) -> empty.
    ("!!!", ""),
])
def test_normalizer_produces_expected_fts5_query(raw, expected):
    assert _normalize_user_query_to_fts5_prefix(raw) == expected


def test_normalizer_passes_through_quoted_phrase_for_power_users():
    """A query wrapped in double quotes is the FTS5 phrase-literal
    syntax; pass it through unchanged so a user who knows FTS5 can
    still do exact-phrase searches."""
    assert _normalize_user_query_to_fts5_prefix('"hello world"') == '"hello world"'


def test_quoted_input_cannot_escape_into_fts5_operator_syntax():
    assert _normalize_user_query_to_fts5_prefix(
        '"foo" OR "bar"'
    ) == '"foo"" OR ""bar"'


# ── integration: end-to-end search via State ───────────────────────


@pytest.fixture
def populated_state(tmp_path) -> State:
    s = State(tmp_path / "search.db")
    s.upsert_peer(fingerprint="aa" * 32, short_id="alice", pubkey=b"\x01" * 32)
    s.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="kanye dropped a new album",
    )
    s.record_message(
        id="m2", ts_ms=2000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="kjg is initials I've seen",
    )
    s.record_message(
        id="m3", ts_ms=3000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="oksana sent the docs",
    )
    s.record_message(
        id="m4", ts_ms=4000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="hello world",
    )
    s.record_message(
        id="m5", ts_ms=5000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="goodbye world",
    )
    return s


def test_single_letter_k_finds_all_words_starting_with_k(populated_state):
    """The bug: 'k' returned 0 matches. Now it must find every
    message containing a word that starts with 'k'."""
    out = populated_state.search_messages("k")
    bodies = sorted(m.body for m in out)
    # m1 ('kanye'), m2 ('kjg') - oksana starts with 'o' so it's
    # NOT included (prefix match anchors at token start).
    assert "kanye dropped a new album" in bodies
    assert "kjg is initials I've seen" in bodies
    # Sanity: messages with no k-prefix word are NOT returned.
    assert "hello world" not in bodies
    assert "goodbye world" not in bodies


def test_two_token_query_is_implicit_and(populated_state):
    """'hello world' should find messages containing both prefixes;
    'goodbye world' is missing the 'hello*' term so it's excluded."""
    out = populated_state.search_messages("hello world")
    bodies = [m.body for m in out]
    assert bodies == ["hello world"]


def test_multi_letter_prefix_still_works(populated_state):
    """Prefix matching with more letters narrows results."""
    out = populated_state.search_messages("kan")
    bodies = [m.body for m in out]
    assert bodies == ["kanye dropped a new album"]


@pytest.mark.parametrize("operator", ["AND", "OR", "NOT", "NEAR"])
def test_fts5_operator_words_are_searchable_literals(tmp_path, operator):
    state = State(tmp_path / f"reserved-{operator}.db")
    state.upsert_peer(
        fingerprint="aa" * 32,
        short_id="alice",
        pubkey=b"\x01" * 32,
    )
    state.record_message(
        id=f"reserved-{operator}",
        ts_ms=1000,
        direction="in",
        peer_fp="aa" * 32,
        msg_type="TEXT",
        body=operator,
    )
    try:
        assert [row.id for row in state.search_messages(operator)] == [
            f"reserved-{operator}"
        ]
    finally:
        state.close()


def test_empty_query_returns_empty_list_without_hitting_db(populated_state):
    """An empty query should return [] without raising the FTS5
    'malformed MATCH expression' error."""
    assert populated_state.search_messages("") == []
    assert populated_state.search_messages("   ") == []
    assert populated_state.search_messages("!!!") == []


def test_phrase_quoted_query_does_literal_match(populated_state):
    """'"hello world"' should match the exact phrase, NOT find
    messages with 'hello' OR 'world' alone via prefix expansion."""
    out = populated_state.search_messages('"hello world"')
    bodies = sorted(m.body for m in out)
    assert bodies == ["hello world"]


def test_prefix_match_opt_out_falls_back_to_raw_fts5(populated_state):
    """global_search and other callers that pre-format the query
    can opt out via prefix_match=False. Verify the raw token 'k'
    finds nothing (the original bug behavior) when normalization
    is disabled - this confirms the opt-out is wired through."""
    out = populated_state.search_messages("k", prefix_match=False)
    assert out == [], (
        "prefix_match=False must skip normalization; raw 'k' should "
        "match no messages because none contain the standalone token "
        "'k' (the original bug)"
    )


def test_existing_test_state_search_still_passes(populated_state):
    """Sanity: the existing test_state.py search assertions
    ('quick' finds two messages) still pass under prefix
    normalization. 'quick' -> '"quick"*' still matches 'quick'."""
    s = populated_state
    s.record_message(
        id="m_q1", ts_ms=6000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="the quick brown fox",
    )
    s.record_message(
        id="m_q2", ts_ms=7000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="quick bunny",
    )
    out = s.search_messages("quick")
    bodies = sorted(m.body for m in out)
    assert bodies == ["quick bunny", "the quick brown fox"]


def test_peer_filter_still_applies_under_prefix_match(tmp_path):
    """The peer_fp filter must compose with prefix normalization."""
    s = State(tmp_path / "peer_filter.db")
    s.upsert_peer(fingerprint="aa" * 32, short_id="alice", pubkey=b"\x01" * 32)
    s.upsert_peer(fingerprint="bb" * 32, short_id="bob", pubkey=b"\x02" * 32)
    s.record_message(
        id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="kanye",
    )
    s.record_message(
        id="m2", ts_ms=2, direction="in", peer_fp="bb" * 32,
        msg_type="TEXT", body="kanye",
    )
    out = s.search_messages("k", peer_fp="aa" * 32)
    assert len(out) == 1
    assert out[0].peer_fp == "aa" * 32
