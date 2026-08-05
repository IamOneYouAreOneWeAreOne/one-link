"""Both doors into the post-quantum downgrade, not just the one that was tested.

`_legacy_handshake_override_enabled` accepts a legacy X25519-only channel --
no ML-KEM, so no harvest-now-decrypt-later protection -- and TWO environment
variables open it:

    ONE_LINK_ALLOW_V1_HELLO             6 test files, 1 doc
    ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE  0 tests, 0 docs

Same function, same call site (channel.py `_respond_or_reject`), same
consequence. The suite covered one of the two doors.

Worse, the product's own refusal message names the UNTESTED one:

    "legacy classical handshake rejected: live channels require the versioned
     X25519+ML-KEM-768 suite (explicit migration override:
     ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE=1)"

So the documented remedy was the door with no coverage. Found by auditing
every ONE_LINK_* variable the source READS against everything that could set,
document or test it: 18 were reachable from nowhere else, and this pair was
the security-relevant one.

These tests pin the secure DEFAULT first -- that is the property that actually
protects users -- then both doors, then the precedence rule.
"""

from __future__ import annotations

import pytest

from one_link.channel import _legacy_handshake_override_enabled

BOTH_DOORS = ("ONE_LINK_ALLOW_V1_HELLO", "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE")


@pytest.fixture(autouse=True)
def _no_ambient_override(monkeypatch: pytest.MonkeyPatch):
    """A developer shell exporting either one must not silently pass these."""
    for name in BOTH_DOORS:
        monkeypatch.delenv(name, raising=False)


def test_the_default_refuses_a_classical_downgrade() -> None:
    """The property that actually protects users: off unless asked for."""
    assert _legacy_handshake_override_enabled(None) is False


@pytest.mark.parametrize("door", BOTH_DOORS)
def test_each_door_opens_the_downgrade(door: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(door, "1")
    assert _legacy_handshake_override_enabled(None) is True, (
        f"{door} did not enable the override; if it was renamed or removed, the "
        "refusal message in channel.py that names it is now wrong"
    )


@pytest.mark.parametrize("door", BOTH_DOORS)
def test_only_the_exact_value_1_opens_a_door(door: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A downgrade must not be openable by an accident of shell truthiness.

    `ONE_LINK_ALLOW_V1_HELLO=0` or `=false` reads to a human as OFF. If any
    non-empty value enabled it, setting it to "0" to turn it off would turn it
    ON -- the worst possible direction for this particular switch.
    """
    for value in ("0", "false", "no", "true", "yes", "", "2"):
        monkeypatch.setenv(door, value)
        assert _legacy_handshake_override_enabled(None) is False, (
            f"{door}={value!r} opened the classical downgrade; only '1' may"
        )


@pytest.mark.parametrize("door", BOTH_DOORS)
def test_an_explicit_argument_overrides_the_environment(
    door: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller passing False must win over an ambient env var.

    `_respond_or_reject(allow_classical_downgrade=False)` is how a caller says
    "never downgrade this channel, whatever the process environment says". If
    the env could override that, a stray export would silently re-enable
    downgrades for callers that explicitly refused them.
    """
    monkeypatch.setenv(door, "1")
    assert _legacy_handshake_override_enabled(False) is False
    assert _legacy_handshake_override_enabled(True) is True


def test_the_refusal_message_names_a_switch_that_actually_works() -> None:
    """The message tells operators what to set. It must not name a dead flag.

    This is the specific defect that made the gap dangerous: the string was
    right, the variable worked, and nothing tested it -- so a rename would have
    left the product printing instructions that do nothing.
    """
    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / "src" / "one_link" / "channel.py"
    text = source.read_text(encoding="utf-8")
    assert "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE=1" in text, (
        "the refusal message no longer names the override"
    )
    # ...and the named switch is one of the doors proven to work above.
    assert "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE" in BOTH_DOORS
