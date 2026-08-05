"""/api/capability-audit reaches a user, and its rendering is EXECUTED.

The second of the two endpoints the route-consumer audit found registered,
authenticated, correct, and called by nothing. The daemon has recorded every
capability change since the first schema version and never showed one to
anybody.

It is the answer to "did I give this device access to my files, and when?" --
a question a user of a privacy product is entitled to ask about their own
machine. It now renders as a permission history in the peer drawer, beside the
toggles that write the entries.

As with test_update_plan_wiring.py, the rendering runs under Node against a
fake DOM rather than being grepped. The interesting behaviour here is not that
the code exists; it is that `null` and `["*"]` both mean "everything" in the
wire format, and a history that showed a user `null` would be worse than no
history at all.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INDEX = REPO / "src" / "one_link" / "web" / "index.html"

_NODE = shutil.which("node")

# Same rule as test_update_plan_wiring.py: skipping locally is fine, skipping
# on CI is how a gate goes dark while the summary line still says "passed".
if _NODE is None and os.environ.get("CI"):
    raise RuntimeError(
        "node is missing on CI, so the capability-history rendering tests "
        "would silently not run."
    )

pytestmark = pytest.mark.skipif(
    _NODE is None,
    reason="node is required to execute the extracted browser functions",
)


def _extract(start: str, end: str) -> str:
    source = INDEX.read_text(encoding="utf-8")
    a = source.index(start)
    b = source.index(end, a + len(start))
    return source[a:b]


def _run_node(script: str):
    result = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, timeout=60,
        cwd=REPO,
        # encoding is explicit: text=True decodes with the Windows
        # locale codepage (cp1252 here), which turned the arrow in the
        # rendered history into mojibake and failed an assertion about
        # text the product renders correctly. The harness was reading
        # different bytes than node wrote.
        encoding="utf-8",
    )
    assert result.returncode == 0, (
        f"node failed ({result.returncode}):\n{result.stderr}\n{result.stdout}"
    )
    assert result.stdout.strip(), f"node produced no output:\n{result.stderr}"
    return json.loads(result.stdout.strip().splitlines()[-1])


# ── the policy label, executed ────────────────────────────────────────


def test_the_policy_label_never_shows_a_user_a_wire_value() -> None:
    """`null` and `["*"]` both mean "everything"; `[]` means "nothing".

    A history that rendered `null` or `*` would be reporting the storage
    format to somebody trying to find out whether they shared their files.
    """
    body = _extract("function _capPolicyLabel", "\n  // Render this peer's")
    cases = [
        None, ["*"], [], ["chat"], ["chat", "files"],
        ["voice_call", "video_call"], ["folder_sync"], ["unknown_future_cap"],
    ]
    script = textwrap.dedent(f"""
        {body}
        console.log(JSON.stringify({json.dumps(cases)}.map(_capPolicyLabel)));
    """)
    got = _run_node(script)
    assert got == [
        "everything", "everything", "nothing", "Chat", "Chat, Files",
        "Voice, Video", "Folders", "unknown_future_cap",
    ], got
    for rendered in got:
        assert "null" not in rendered and "*" not in rendered


# ── the renderer, executed against a fake DOM ─────────────────────────


_HARNESS = r"""
function makeEl(tag) {
  return {
    tag, className: "", _text: "", children: [], hidden: false,
    set textContent(v) { this._text = String(v); this.children = []; },
    get textContent() {
      return this._text + this.children.map(c =>
        typeof c === "string" ? c : c.textContent).join(" ");
    },
    set innerHTML(v) { this._text = ""; this.children = []; },
    get innerHTML() { return this.textContent; },
    appendChild(c) { this.children.push(c); return c; },
    append(...xs) { for (const x of xs) this.children.push(x); },
  };
}
const document = { createElement: makeEl };
const wrap = makeEl("div");
const host = makeEl("div");
const $ = (sel) => (sel === "#dev-cap-history-wrap" ? wrap
                  : sel === "#dev-cap-history" ? host : null);
function _humanRelMs(ms) { return "T" + ms; }
const api = { get: async (url) => { LAST_URL = url; return (API_RESULT); } };
let LAST_URL = null;
"""


def _render(api_result: str, fingerprint: str = "'" + "a" * 64 + "'"):
    body = (
        _extract("function _capPolicyLabel", "\n  // Render this peer's")
        + _extract("async function renderCapabilityHistory",
                   "\n  function syncDrawerCapabilityControls")
    )
    script = (
        _HARNESS.replace("API_RESULT", api_result)
        + body
        + textwrap.dedent(f"""
        renderCapabilityHistory({fingerprint}).then(() => {{
          console.log(JSON.stringify({{
            hidden: wrap.hidden,
            rows: host.children.length,
            text: host.textContent,
            url: LAST_URL,
          }}));
        }}).catch(e => {{ console.error(e); process.exit(3); }});
        """)
    )
    return _run_node(script)


def test_a_real_history_renders_readable_transitions() -> None:
    out = _render(
        "{events:[{ts_ms:1,kind:'set',before_json:['chat'],"
        "after_json:['chat','files'],actor:'user'},"
        "{ts_ms:2,kind:'set',before_json:null,after_json:[],actor:'user'}]}"
    )
    assert out["hidden"] is False
    assert out["rows"] == 2
    assert "Chat → Chat, Files" in out["text"]
    assert "everything → nothing" in out["text"], out["text"]
    assert "user" in out["text"], "the actor is the accountability half"


def test_the_request_is_scoped_to_this_peer_and_bounded() -> None:
    """An unscoped request would show one peer's drawer another peer's history.

    The limit matters too: the handler clamps to [1, 1000], and asking for the
    default 200 rows to populate a drawer panel is wasteful.
    """
    out = _render("{events:[]}", fingerprint="'" + "b" * 64 + "'")
    assert out["url"] == f"/api/capability-audit?fp={'b' * 64}&limit=20"


def test_a_fingerprint_is_url_encoded() -> None:
    """The fingerprint reaches a query string, so it gets encoded.

    Fingerprints are hex today. Encoding is not for today's values; it is so
    that a future identifier containing & or # cannot truncate or extend the
    request.
    """
    out = _render("{events:[]}", fingerprint="'a&b=1'")
    assert out["url"] == "/api/capability-audit?fp=a%26b%3D1&limit=20"


@pytest.mark.parametrize(
    "api_result,label",
    [
        ("null", "null body"),
        ("{events:[]}", "no history for this peer"),
        ("{}", "a response with no events key"),
    ],
)
def test_an_empty_history_shows_nothing_at_all(api_result: str, label: str) -> None:
    """A peer whose permissions never changed has no history, and that is fine.

    Showing an empty panel headed "Permission history" would read as though
    something had been lost.
    """
    out = _render(api_result)
    assert out["hidden"] is True, f"panel was shown for {label}"
    assert out["rows"] == 0


def test_a_failing_request_cannot_break_the_drawer() -> None:
    """The drawer is how a user manages a peer. It must open regardless."""
    body = (
        _extract("function _capPolicyLabel", "\n  // Render this peer's")
        + _extract("async function renderCapabilityHistory",
                   "\n  function syncDrawerCapabilityControls")
    )
    script = (
        _HARNESS.replace(
            "api = { get: async (url) => { LAST_URL = url; return (API_RESULT); } }",
            "api = { get: async () => { throw new Error('offline'); } }",
        )
        + body
        + textwrap.dedent("""
        renderCapabilityHistory("aa").then(() => {
          console.log(JSON.stringify({hidden: wrap.hidden, ok: true}));
        }).catch(() => { console.log(JSON.stringify({ok: false})); });
        """)
    )
    out = _run_node(script)
    assert out["ok"] is True, "a failed fetch propagated out of the renderer"
    assert out["hidden"] is True


def test_a_previous_peers_history_cannot_persist_into_the_next_drawer() -> None:
    """Opening peer B after peer A must not show A's permissions under B.

    This is the sharpest failure available on this panel: it would tell a user
    something false about who has access to their files.
    """
    source = INDEX.read_text(encoding="utf-8")
    start = source.index("async function renderCapabilityHistory")
    prelude = source[start:start + 1200]
    assert "wrap.hidden = true;" in prelude
    assert 'host.innerHTML = "";' in prelude
    # Both resets must precede the await, or a slow request leaves the old
    # peer's rows on screen while the new peer's drawer is open.
    assert prelude.index("wrap.hidden = true;") < prelude.index("await api.get")
    assert prelude.index('host.innerHTML = "";') < prelude.index("await api.get")
