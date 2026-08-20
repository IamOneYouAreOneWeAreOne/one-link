"""One pasted code block must never shove the sidebar off-screen.

Reported from the field on TWO devices at the same moment -- the tell that
nothing local changed and the same chat message simply arrived on both. The app
looked broken: sidebar gone, bubbles cut off, content shifted sideways.

Mechanism, three layers that each default to "refuse to shrink":

  * .main used `grid-template-columns: 280px 1fr 0fr`, and a bare `1fr` track is
    `minmax(auto, 1fr)` -- its MINIMUM is the column's min-content width;
  * .convo is the grid ITEM in that column, and a grid item defaults to
    min-width:auto, so fixing the track alone still lets the item overflow it;
  * .messages is a flex column, so each .msg is a flex item with the same
    min-width:auto default.

A <pre> never wraps, so its min-content is its longest line. Any one of those
three layers is enough to propagate that width all the way out to the window.

This drives the REAL stylesheet against the REAL shell markup at a fixed
viewport, rather than the live app, because in the default e2e state no
conversation is open and .messages has zero width -- a test written against it
passes no matter what the CSS says. That version of this test was vacuous and
was replaced; see the differential note in the commit.
"""
from __future__ import annotations

import re
from pathlib import Path

INDEX = Path(__file__).resolve().parents[2] / "src" / "one_link" / "web" / "index.html"

_LONG_UNWRAPPABLE_LINE = "an_unbreakable_column_of_output_" * 12  # ~384 chars

_SHELL = """
<div class="app">
  <div class="main">
    <aside class="side"></aside>
    <section class="convo">
      <div class="messages">
        <div class="msg in">
          <div class="msg-body">
            <div class="md-chat">
              <p>Everything is in. Here is the full report.</p>
              <pre><code>__LINE__</code></pre>
            </div>
          </div>
        </div>
      </div>
    </section>
    <aside class="filespane"></aside>
  </div>
</div>
"""


def _app_stylesheet() -> str:
    html = INDEX.read_text(encoding="utf-8")
    blocks = re.findall(r"<style[^>]*>(.*?)</style>", html, re.S)
    assert blocks, "no <style> block found in index.html"
    return "\n".join(blocks)


def _measure(page) -> dict:
    page.set_viewport_size({"width": 1400, "height": 900})
    page.set_content(
        "<!doctype html><html><head><meta charset='utf-8'><style>"
        + _app_stylesheet()
        + "</style></head><body>"
        + _SHELL.replace("__LINE__", _LONG_UNWRAPPABLE_LINE)
        + "</body></html>"
    )
    return page.evaluate(
        """() => {
            const main = document.querySelector('.main');
            const convo = document.querySelector('.convo');
            const side = document.querySelector('.side');
            const pre = document.querySelector('.md-chat pre');
            return {
                viewport: document.documentElement.clientWidth,
                mainWidth: main.getBoundingClientRect().width,
                convoWidth: convo.getBoundingClientRect().width,
                sideWidth: side.getBoundingClientRect().width,
                sideRight: side.getBoundingClientRect().right,
                preScrollable: pre.scrollWidth > pre.clientWidth,
                preOverflowX: getComputedStyle(pre).overflowX,
            };
        }"""
    )


def test_a_wide_code_block_cannot_widen_the_chat_pane_past_the_window(page):
    """The field failure, reduced to its cause."""

    m = _measure(page)
    assert m["convoWidth"] <= m["viewport"] - m["sideWidth"] + 1, (
        "a single message containing a fenced code block stretched the chat pane "
        f"past its column, which is what pushes the sidebar off-screen: {m}. "
        "Check minmax(0, 1fr) on .main, min-width:0 on .convo, min-width:0 on .msg."
    )
    assert m["mainWidth"] <= m["viewport"] + 1, f"the app shell exceeded the window: {m}"


def test_the_code_block_still_scrolls_inside_its_bubble(page):
    """Guard against a BAD fix: clipping the text instead of containing it.

    This one passes before and after, deliberately. It exists so a future
    "fix" that hides the overflow (overflow:hidden, or forcing the <pre> to
    wrap) cannot pass the test above by destroying the content.
    """

    m = _measure(page)
    assert m["preOverflowX"] == "auto", (
        "the code block lost its own scroll container, so long lines have nowhere "
        "to go but outward"
    )
    assert m["preScrollable"], (
        "the long line is no longer scrollable inside the bubble, so it was either "
        "clipped or reflowed away instead of contained"
    )
