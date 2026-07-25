"""v0.21.x recovery-audit CLI commands.

Mirrors the wizard's non-destructive audit triangle as CLI commands
so a user in a CLI-only environment (SSH, headless, browser
broken) can still verify their phrase / backup / shares without
committing to a destructive restore:

  - one-link backup test [WORDS...]
  - one-link backup test-bundle BUNDLE_PATH [WORDS...]
  - one-link recovery test-shares PORTABLE_SHARES...

Exit codes are deliberately rich (0 / 1 / 2) so the commands can be
scripted into periodic-audit cron jobs.
"""
from __future__ import annotations

import os

from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ── backup test (phrase verification) ───────────────────────────────


def test_backup_test_returns_zero_for_matching_phrase(tmp_path, monkeypatch):
    """Happy path: a daemon's own phrase verifies against its own
    seed; CLI exits 0 + prints VERIFIED."""
    from one_link import master_seed, mnemonic, paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    seed = master_seed.load_or_create_seed(tmp_path)[0]
    master_seed.install_seed_derived_authority(
        tmp_path,
        identity_path=paths.key_path(),
        seed=seed,
    )
    phrase = mnemonic.encode(seed)
    result = CliRunner().invoke(cli, ["backup", "test"] + phrase.split())
    assert result.exit_code == 0, result.output
    assert "VERIFIED" in result.output


def test_backup_test_returns_two_for_phrase_against_no_identity(tmp_path, monkeypatch):
    """A daemon with no master.seed yet: any valid phrase exits 2
    (amber: valid but nothing to compare against). Distinct from
    exit 1 (red: invalid phrase) so a scripted audit can branch."""
    from one_link import mnemonic, paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    phrase = mnemonic.encode(mnemonic.generate_seed())
    result = CliRunner().invoke(cli, ["backup", "test"] + phrase.split())
    assert result.exit_code == 2
    assert "no master seed" in result.output.lower()


def test_backup_test_returns_two_for_phrase_against_different_identity(tmp_path, monkeypatch):
    """A valid phrase for a DIFFERENT seed exits 2 (amber) with a
    clear message - distinct from invalid-checksum exit 1 so the
    user / a script can tell the two failure modes apart."""
    from one_link import master_seed, mnemonic, paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    master_seed.load_or_create_seed(tmp_path)
    other_phrase = mnemonic.encode(mnemonic.generate_seed())
    result = CliRunner().invoke(cli, ["backup", "test"] + other_phrase.split())
    assert result.exit_code == 2
    assert "different install" in result.output.lower() or "does not match" in result.output.lower()


def test_backup_test_returns_one_for_invalid_phrase(tmp_path, monkeypatch):
    """An invalid phrase fails the BIP-39 checksum + exits 1 (red).
    Use a guaranteed-not-in-wordlist token (NOT 'zebra' which is a
    real BIP-39 word and would pass the checksum 1/256 times)."""
    from one_link import master_seed, mnemonic, paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    seed = master_seed.load_or_create_seed(tmp_path)[0]
    words = mnemonic.encode(seed).split()
    words[-1] = "notabip39word"
    result = CliRunner().invoke(cli, ["backup", "test"] + words)
    assert result.exit_code == 1
    assert "INVALID PHRASE" in result.output


def test_backup_test_help_text_documents_exit_codes():
    """Pin the exit-code documentation in --help so a user scripting
    the audit knows what each code means."""
    from one_link.cli import cli

    result = CliRunner().invoke(cli, ["backup", "test", "--help"])
    assert result.exit_code == 0
    # Mention 0 / 1 / 2 explicitly so cron scripts can branch.
    assert "0" in result.output
    assert "1" in result.output
    assert "2" in result.output
    assert "green" in result.output.lower()
    assert "amber" in result.output.lower()
    assert "red" in result.output.lower()


# ── backup test-bundle (bundle verification) ────────────────────────


def test_backup_test_bundle_returns_zero_for_matching_phrase_and_bundle(tmp_path, monkeypatch):
    """Happy path: encode a real .olbak from a seed, then verify it
    decrypts cleanly with the corresponding phrase via the CLI."""
    from one_link import backup_bundle, mnemonic, paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    (tmp_path / "state.db").write_bytes(b"SQLite format 3\x00" + os.urandom(512))
    (tmp_path / "master.seed").write_bytes(os.urandom(32))
    seed = (tmp_path / "master.seed").read_bytes()
    phrase = mnemonic.encode(seed)
    bundle = backup_bundle.create_bundle(seed=seed, data_dir=tmp_path)
    bundle_path = tmp_path / "out.olbak"
    bundle_path.write_bytes(bundle)
    result = CliRunner().invoke(
        cli, ["backup", "test-bundle", str(bundle_path)] + phrase.split(),
    )
    assert result.exit_code == 0, result.output
    assert "VERIFIED" in result.output
    assert "file_count" in result.output


def test_backup_test_bundle_returns_one_for_wrong_phrase(tmp_path):
    """Right shape but wrong key: exit 1 + 'DECRYPT FAILED'."""
    from one_link import backup_bundle, mnemonic
    from one_link.cli import cli

    real_seed = os.urandom(32)
    (tmp_path / "state.db").write_bytes(b"data" + os.urandom(256))
    bundle = backup_bundle.create_bundle(seed=real_seed, data_dir=tmp_path)
    bundle_path = tmp_path / "out.olbak"
    bundle_path.write_bytes(bundle)
    wrong_phrase = mnemonic.encode(os.urandom(32))
    result = CliRunner().invoke(
        cli, ["backup", "test-bundle", str(bundle_path)] + wrong_phrase.split(),
    )
    assert result.exit_code == 1
    assert "BUNDLE DECRYPT FAILED" in result.output


def test_backup_test_bundle_returns_one_for_invalid_phrase(tmp_path):
    """Phrase fails the BIP-39 checksum -> exit 1 + INVALID PHRASE
    (the bundle is never even opened)."""
    from one_link import backup_bundle
    from one_link.cli import cli

    (tmp_path / "state.db").write_bytes(b"data" + os.urandom(256))
    bundle = backup_bundle.create_bundle(seed=os.urandom(32), data_dir=tmp_path)
    bundle_path = tmp_path / "out.olbak"
    bundle_path.write_bytes(bundle)
    bad_phrase = ["notabip39word"] * 24
    result = CliRunner().invoke(
        cli, ["backup", "test-bundle", str(bundle_path)] + bad_phrase,
    )
    assert result.exit_code == 1
    assert "INVALID PHRASE" in result.output


def test_backup_test_bundle_rejects_missing_file():
    """Click's exists=True must reject a non-existent path BEFORE the
    handler runs (so the user gets a clear 'no such file' instead of
    a cryptic decrypt error)."""
    from one_link.cli import cli

    result = CliRunner().invoke(
        cli, ["backup", "test-bundle", "/does/not/exist.olbak", "word"] * 1,
    )
    assert result.exit_code == 2  # click usage error


# ── recovery test-shares (share verification) ───────────────────────


def _make_portable_shares(seed: bytes, k: int, n: int) -> tuple[list[str], list[Ed25519PrivateKey]]:
    """Helper: split a seed into n shares, unwrap k of them, return
    the portable base64 form `recovery unwrap` emits. Mirrors the
    real CLI flow byte-for-byte."""
    import base64

    from one_link import social_recovery

    guardians = [Ed25519PrivateKey.generate() for _ in range(n)]
    wrapped = social_recovery.split_and_wrap(
        seed=seed,
        contact_ed_pubs=[g.public_key().public_bytes_raw() for g in guardians],
        threshold_k=k, total_n=n,
    )
    portables: list[str] = []
    for i in range(k):
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=wrapped[i].encoded,
            my_ed_priv_seed=guardians[i].private_bytes_raw(),
        )
        payload = bytes([idx]) + share_bytes
        portables.append(
            base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
        )
    return portables, guardians


def test_recovery_test_shares_returns_zero_for_matching_quorum(tmp_path, monkeypatch):
    """Happy path: split the daemon's own seed into a 2-of-3, unwrap
    2 portable shares, verify the CLI exits 0 + prints VERIFIED."""
    from one_link import master_seed, paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    seed = master_seed.load_or_create_seed(tmp_path)[0]
    master_seed.install_seed_derived_authority(
        tmp_path,
        identity_path=paths.key_path(),
        seed=seed,
    )
    portables, _ = _make_portable_shares(seed, k=2, n=3)
    result = CliRunner().invoke(cli, ["recovery", "test-shares"] + portables)
    assert result.exit_code == 0, result.output
    assert "VERIFIED" in result.output
    assert "2 shares" in result.output


def test_recovery_test_shares_returns_two_for_different_identity_quorum(tmp_path, monkeypatch):
    """Valid quorum that reconstructs a DIFFERENT seed -> exit 2
    (amber) with the 'someone else's recovery setup' message. The
    user has the K shares but they're for the wrong identity."""
    from one_link import master_seed, paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    master_seed.load_or_create_seed(tmp_path)
    other_seed = os.urandom(32)
    portables, _ = _make_portable_shares(other_seed, k=2, n=3)
    result = CliRunner().invoke(cli, ["recovery", "test-shares"] + portables)
    assert result.exit_code == 2
    assert "DIFFERENT identity" in result.output


def test_recovery_test_shares_returns_two_for_quorum_against_no_identity(tmp_path, monkeypatch):
    """A daemon with no master.seed yet: a valid quorum exits 2
    (amber: 'no master seed to compare against'). Common case on a
    fresh audit-only device."""
    from one_link import paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    seed = os.urandom(32)
    portables, _ = _make_portable_shares(seed, k=2, n=2)
    result = CliRunner().invoke(cli, ["recovery", "test-shares"] + portables)
    assert result.exit_code == 2
    assert "no master seed" in result.output.lower()


def test_recovery_test_shares_rejects_one_share(tmp_path, monkeypatch):
    """Single share cannot reconstruct (Shamir K>=2 by design); the
    CLI must surface the 'need at least 2' message + non-zero exit,
    NOT crash on the combine call with something cryptic."""
    from one_link import paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    seed = os.urandom(32)
    portables, _ = _make_portable_shares(seed, k=2, n=2)
    result = CliRunner().invoke(cli, ["recovery", "test-shares", portables[0]])
    # ClickException -> exit 1, with a clear message
    assert result.exit_code != 0
    assert "at least 2" in result.output.lower()


def test_recovery_test_shares_rejects_too_short_payload(tmp_path, monkeypatch):
    """Garbage that base64-decodes to <2 bytes can't carry an index
    + share, so the CLI's length guard must surface a clear 'too
    short' message + non-zero exit (NOT a Python traceback). The
    user typo'd / mis-pasted a share string."""
    from one_link import paths
    from one_link.cli import cli

    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    # 'a' base64-decodes to <1 byte; 'ab' decodes to 1 byte. Both
    # fail the < 2 guard. (Truly-invalid chars like '*' would be
    # silently stripped by lenient base64 decoding without
    # validate=True, so we use short-but-valid b64 here.)
    result = CliRunner().invoke(
        cli, ["recovery", "test-shares", "ab", "ab"],
    )
    assert result.exit_code != 0
    assert "too short" in result.output.lower()


def test_recovery_test_shares_help_text_documents_exit_codes():
    from one_link.cli import cli

    result = CliRunner().invoke(cli, ["recovery", "test-shares", "--help"])
    assert result.exit_code == 0
    assert "0" in result.output
    assert "1" in result.output
    assert "2" in result.output
    assert "green" in result.output.lower()
    assert "amber" in result.output.lower()
    assert "red" in result.output.lower()


# ── command registration smoke-tests ────────────────────────────────


def test_all_three_test_commands_registered():
    """A user typing `--help` against each group should see the new
    commands. Pin so a future CLI refactor that drops one of them
    surfaces in CI."""
    from one_link.cli import cli

    result = CliRunner().invoke(cli, ["backup", "--help"])
    assert result.exit_code == 0
    assert "test" in result.output
    assert "test-bundle" in result.output

    result = CliRunner().invoke(cli, ["recovery", "--help"])
    assert result.exit_code == 0
    assert "test-shares" in result.output
