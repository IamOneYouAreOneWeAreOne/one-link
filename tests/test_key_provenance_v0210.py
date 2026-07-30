"""The daemon must report where the state key IS, not what this host HAS.

Taken verbatim from a real macOS release-binary boot log, two lines apart:

    keychain: no functional OS keychain backend on this host; minting the
              state key in the private local key file.
    state.db: AES-256 at-rest encryption ACTIVE (key from macOS Keychain)

Both came from the same process. The second is false: the key was in
state.key. An operator auditing where their encryption key lives -- which is
exactly what that message exists for -- was pointed at the wrong store.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean_provenance():
    from one_link import keychain

    keychain._last_key_source = None
    yield
    keychain._last_key_source = None


def test_local_fallback_is_not_reported_as_the_os_keychain(monkeypatch, tmp_path):
    from one_link import keychain

    monkeypatch.setattr(keychain, "backend_label", lambda: "macOS Keychain")
    monkeypatch.setattr(keychain, "_local_key_path", lambda: tmp_path / "state.key")
    monkeypatch.setattr(
        keychain, "_read_local_key_at", lambda _p: "a-real-key-from-the-file"
    )

    assert keychain._read_local_key() == "a-real-key-from-the-file"

    label = keychain.last_key_source_label()
    assert label is not None
    assert "macOS Keychain" not in label, (
        f"the local key file was reported as the OS keychain: {label!r}"
    )
    assert keychain.LOCAL_KEY_FILENAME in label


def test_an_env_override_names_itself(monkeypatch):
    from one_link import keychain

    monkeypatch.setenv(keychain.ENV_VAR, "operator-supplied")
    assert keychain.get_passphrase() == "operator-supplied"
    label = keychain.last_key_source_label()
    assert label and keychain.ENV_VAR in label


def test_a_real_keychain_hit_still_names_the_backend(monkeypatch):
    from one_link import keychain

    monkeypatch.delenv(keychain.ENV_VAR, raising=False)
    monkeypatch.setattr(keychain, "_disabled", lambda: False)
    monkeypatch.setattr(keychain, "backend_label", lambda: "Windows Credential Manager")
    monkeypatch.setattr(keychain, "_read_local_key", lambda: None)
    monkeypatch.setattr(keychain, "keychain_target", lambda *a, **k: ("svc", "acct"))

    class _FakeKeyring:
        @staticmethod
        def get_password(service, account):
            return "key-that-lives-in-the-os-store"

    monkeypatch.setattr(keychain, "_load_keyring", lambda: _FakeKeyring)

    assert keychain.get_passphrase() == "key-that-lives-in-the-os-store"
    assert keychain.last_key_source_label() == "Windows Credential Manager"


def test_unresolved_provenance_falls_back_rather_than_lying(monkeypatch):
    """Before any resolution the reporters must not invent a source."""
    from one_link import keychain

    assert keychain.last_key_source_label() is None

    from one_link import hardening_checks

    monkeypatch.setattr(keychain, "backend_label", lambda: "Linux Secret Service")
    findings = hardening_checks.check_at_rest_encryption(is_encrypted=True)
    assert any("Linux Secret Service" in f.message for f in findings)


def test_both_reporters_consult_provenance_not_just_the_backend():
    """Twin-copy guard: two call sites make the same claim."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "one_link"
    for name in ("state.py", "hardening_checks.py"):
        text = (root / name).read_text(encoding="utf-8")
        if "backend_label()" not in text:
            continue
        assert "last_key_source_label()" in text, (
            f"{name} reports a key location from backend_label() alone -- that "
            "names the backend INSTALLED here, not the store the key is in"
        )
