"""v0.20.7 encrypted backup bundles. Pin the round-trip + tamper-resistance."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from one_link import backup_bundle, master_seed
from one_link.backup_bundle import (
    BUNDLE_MAGIC, HEADER_LEN, BundleHeader,
    create_bundle, extract_bundle_to_dir, open_bundle,
)


def _make_data_dir(tmp_path: Path) -> Path:
    """Set up a fake daemon data dir with realistic file shapes."""
    d = tmp_path / "data"
    d.mkdir()
    (d / "state.db").write_bytes(b"SQLite format 3\x00" + os.urandom(4096))
    (d / "master.seed").write_bytes(os.urandom(32))
    (d / "data-root-key.bin").write_bytes(os.urandom(32))
    (d / "lockbox.salt").write_bytes(os.urandom(16))
    (d / "ui.token").write_text("XYZ" * 30)
    inbox = d / "inbox"
    inbox.mkdir()
    (inbox / "report.pdf").write_bytes(os.urandom(2048))
    return d


def test_bundle_round_trip(tmp_path):
    seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = create_bundle(seed=seed, data_dir=data)
    assert bundle.startswith(BUNDLE_MAGIC)
    header, plaintext = open_bundle(seed=seed, bundle_bytes=bundle)
    assert header.magic == BUNDLE_MAGIC
    assert header.plaintext_len == len(plaintext)

    target = tmp_path / "restore"
    written = extract_bundle_to_dir(plaintext=plaintext, target_dir=target)
    assert "state.db" in written
    assert "master.seed" in written
    # ui.token + lockbox.salt also in DEFAULT_INCLUDE.
    assert "ui.token" in written
    assert "lockbox.salt" in written
    # inbox NOT included unless include_files=True.
    assert not any("inbox" in w for w in written)
    # Bytes restored byte-equal.
    assert (target / "state.db").read_bytes() == (data / "state.db").read_bytes()
    assert (target / "master.seed").read_bytes() == (data / "master.seed").read_bytes()


def test_bundle_with_inbox(tmp_path):
    seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = create_bundle(seed=seed, data_dir=data, include_files=True)
    header, plaintext = open_bundle(seed=seed, bundle_bytes=bundle)
    target = tmp_path / "restore"
    written = extract_bundle_to_dir(plaintext=plaintext, target_dir=target)
    assert any(w.startswith("inbox/") for w in written), written
    assert (target / "inbox" / "report.pdf").read_bytes() == (data / "inbox" / "report.pdf").read_bytes()


def test_bundle_wrong_seed_fails(tmp_path):
    seed = os.urandom(32)
    other_seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = create_bundle(seed=seed, data_dir=data)
    with pytest.raises(ValueError, match="bundle decrypt failed"):
        open_bundle(seed=other_seed, bundle_bytes=bundle)


def test_bundle_tampered_header_fails(tmp_path):
    seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = bytearray(create_bundle(seed=seed, data_dir=data))
    # Flip a byte inside the AAD-protected header (the created_ms field).
    bundle[30] ^= 0xff
    with pytest.raises(ValueError):
        open_bundle(seed=seed, bundle_bytes=bytes(bundle))


def test_bundle_tampered_ciphertext_fails(tmp_path):
    seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = bytearray(create_bundle(seed=seed, data_dir=data))
    bundle[HEADER_LEN + 100] ^= 0xff
    with pytest.raises(ValueError):
        open_bundle(seed=seed, bundle_bytes=bytes(bundle))


def test_bundle_truncated_fails(tmp_path):
    seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = create_bundle(seed=seed, data_dir=data)
    with pytest.raises(ValueError):
        open_bundle(seed=seed, bundle_bytes=bundle[:-50])
    with pytest.raises(ValueError):
        open_bundle(seed=seed, bundle_bytes=bundle[:HEADER_LEN])


def test_bundle_wrong_magic_fails(tmp_path):
    seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = bytearray(create_bundle(seed=seed, data_dir=data))
    bundle[0:8] = b"NOTABACK"
    with pytest.raises(ValueError, match="bad magic"):
        open_bundle(seed=seed, bundle_bytes=bytes(bundle))


def test_extract_refuses_overwrite_by_default(tmp_path):
    seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = create_bundle(seed=seed, data_dir=data)
    _, plaintext = open_bundle(seed=seed, bundle_bytes=bundle)
    target = tmp_path / "preexisting"
    target.mkdir()
    (target / "state.db").write_bytes(b"existing content")
    with pytest.raises(FileExistsError):
        extract_bundle_to_dir(plaintext=plaintext, target_dir=target)
    # The pre-existing file MUST NOT be overwritten on refuse.
    assert (target / "state.db").read_bytes() == b"existing content"


def test_extract_overwrite_replaces_existing(tmp_path):
    seed = os.urandom(32)
    data = _make_data_dir(tmp_path)
    bundle = create_bundle(seed=seed, data_dir=data)
    _, plaintext = open_bundle(seed=seed, bundle_bytes=bundle)
    target = tmp_path / "preexisting"
    target.mkdir()
    (target / "state.db").write_bytes(b"old")
    extract_bundle_to_dir(
        plaintext=plaintext, target_dir=target, overwrite=True,
    )
    assert (target / "state.db").read_bytes() == (data / "state.db").read_bytes()


def test_extract_refuses_path_traversal(tmp_path):
    """A bundle that claims it contains an entry like '../etc/passwd'
    or '/absolute/path/file' is malicious — refuse before any file
    is touched on disk."""
    import gzip, struct, tarfile, secrets, time
    from io import BytesIO
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from one_link.master_seed import derive_backup_key
    from one_link.backup_bundle import BUNDLE_MAGIC, NONCE_LEN

    # Forge a bundle whose archive contains a `../escape` path.
    seed = os.urandom(32)
    buf = BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            ti = tarfile.TarInfo(name="../escape")
            ti.size = 4
            tf.addfile(ti, BytesIO(b"evil"))
    plaintext = buf.getvalue()
    # Wrap in our envelope.
    nonce = secrets.token_bytes(NONCE_LEN)
    created_ms = int(time.time() * 1000)
    header = (
        BUNDLE_MAGIC + struct.pack(">Q", len(plaintext))
        + nonce + struct.pack(">Q", created_ms)
    )
    key = derive_backup_key(seed)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, header)
    bundle = header + ct

    _, plain = open_bundle(seed=seed, bundle_bytes=bundle)
    with pytest.raises(ValueError, match="unsafe archive entry"):
        extract_bundle_to_dir(plaintext=plain, target_dir=tmp_path / "out")


def test_full_recovery_scenario(tmp_path):
    """End-to-end: original install → export bundle → fresh install
    can't decrypt → fresh install with the 24-word phrase CAN decrypt
    + extract → restored install has byte-equal state.db."""
    from one_link import mnemonic
    original_dir = tmp_path / "original"
    original_dir.mkdir()
    (original_dir / "state.db").write_bytes(b"sqlite-format-3-content")
    (original_dir / "master.seed").write_bytes(b"\xaa" * 32)
    seed = b"\xaa" * 32
    bundle = create_bundle(seed=seed, data_dir=original_dir)

    # Verify the seed can be encoded to a 24-word phrase that
    # round-trips back to the same key the bundle was sealed with.
    phrase = mnemonic.encode(seed)
    assert mnemonic.decode(phrase) == seed
    backup_key_orig = master_seed.derive_backup_key(seed)
    backup_key_recovered = master_seed.derive_backup_key(mnemonic.decode(phrase))
    assert backup_key_orig == backup_key_recovered

    # New install with NO seed: bundle is opaque.
    other_seed = os.urandom(32)
    with pytest.raises(ValueError):
        open_bundle(seed=other_seed, bundle_bytes=bundle)

    # New install with the recovered seed: bundle decrypts.
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    _, plaintext = open_bundle(seed=mnemonic.decode(phrase), bundle_bytes=bundle)
    extract_bundle_to_dir(plaintext=plaintext, target_dir=new_dir)
    assert (new_dir / "state.db").read_bytes() == (original_dir / "state.db").read_bytes()
