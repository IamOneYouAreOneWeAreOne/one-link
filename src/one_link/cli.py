"""one-link CLI."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import sys
import threading
from pathlib import Path

import click

from one_link import __version__
from one_link import daemon as daemon_mod
from one_link.identity import load_or_create


def _connect_control(timeout: float = 5.0) -> tuple[socket.socket, int]:
    try:
        port = daemon_mod.read_control_port()
    except RuntimeError as e:
        raise click.ClickException(
            f"daemon not running ({e}).\nstart it with:  one-link daemon"
        )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect(("127.0.0.1", port))
    except OSError as e:
        raise click.ClickException(
            f"could not reach daemon on 127.0.0.1:{port}: {e}\n"
            f"is the daemon running? try:  one-link daemon"
        )
    s.settimeout(timeout)
    return s, port


def _request(cmd: str, *, timeout: float = 5.0, **kwargs) -> dict:
    s, _ = _connect_control(timeout=timeout)
    try:
        s.sendall((json.dumps({"cmd": cmd, **kwargs}) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip() or "{}")
    finally:
        s.close()


@click.group()
@click.version_option(__version__, prog_name="one-link")
def cli():
    """One Link — peer-to-peer LAN chat + file sync."""


@cli.command()
@click.option("-v", "--verbose", is_flag=True)
@click.option("--tray/--no-tray", default=True,
              help="Run a system tray icon alongside the daemon (default: on).")
def daemon(verbose, tray):
    """Run the One Link daemon (leave this in a terminal/service)."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # v0.10.5/v0.12.2: optional tray icon. Start it off the critical daemon
    # boot path so slow Windows/Pillow/pystray initialization cannot delay
    # discovery, the control socket, or the local web UI coming online.
    tray_icon_holder: dict[str, object | None] = {"icon": None}

    def _start_tray_icon() -> None:
        try:
            from one_link.tray import TrayIcon
            from one_link.paths import inbox_dir
            tray_icon = TrayIcon(
                on_quit=lambda: os.kill(os.getpid(), signal.SIGINT),
                inbox_path=inbox_dir(),
            )
            tray_icon_holder["icon"] = tray_icon
            if tray_icon.available:
                tray_icon.start()
                logging.getLogger("one_link.tray").info(
                    "tray icon active. Right-click for menu; click to open UI."
                )
        except Exception as e:
            logging.getLogger("one_link.tray").info(
                "tray init skipped: %s", e,
            )

    if tray:
        threading.Thread(
            target=_start_tray_icon,
            daemon=True,
            name="one-link-tray-loader",
        ).start()
    try:
        asyncio.run(daemon_mod.run())
    except RuntimeError as e:
        if "already running" in str(e):
            raise click.ClickException(str(e))
        raise
    finally:
        tray_icon = tray_icon_holder.get("icon")
        if tray_icon is not None:
            try: tray_icon.stop()
            except Exception: pass


@cli.command()
def whoami():
    """Show this device's identity."""
    me = load_or_create()
    click.echo(f"hostname:    {me.hostname}")
    click.echo(f"short_id:    {me.short_id}")
    click.echo(f"fingerprint: {me.fingerprint}")


@cli.group()
def backup():
    """Manage your 24-word recovery phrase.

    The phrase is your sovereign backup: write it down on paper,
    keep the paper somewhere safe. If you lose the device, type
    the phrase on a new install and your identity + at-rest
    data unlock — peers continue to recognize you.

    The phrase is NEVER transmitted off-device, NEVER synced to
    any cloud, NEVER stored in any third-party service. It exists
    only on your paper backup + the daemon's encrypted local state.
    """


@backup.command("show")
def backup_show():
    """Print the 24-word recovery phrase. Write it down on paper."""
    from one_link import master_seed, mnemonic
    from one_link.paths import data_dir
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        click.echo(
            "No master seed has been provisioned for this install.\n"
            "Run `one-link backup init` to create one (seed + identity\n"
            "will rotate; existing peers will see this as a key change).",
            err=True,
        )
        raise click.exceptions.Exit(1)
    phrase = mnemonic.encode(seed)
    click.echo("=" * 64)
    click.echo("WRITE THESE 24 WORDS DOWN ON PAPER. KEEP THE PAPER SAFE.")
    click.echo("This is the ONLY way to recover your One Link identity")
    click.echo("if you lose this device.")
    click.echo("=" * 64)
    words = phrase.split()
    for row in range(0, len(words), 4):
        line_words = words[row:row + 4]
        numbered = [f"{i+row+1:>2}. {w:<10}" for i, w in enumerate(line_words)]
        click.echo("  ".join(numbered))
    click.echo("=" * 64)
    click.echo("Anyone with these 24 words can take over your identity.")
    click.echo("Treat them like a physical bank PIN: paper-only, never typed")
    click.echo("into a website, never photographed, never sent to anyone.")
    click.echo("=" * 64)


@backup.command("init")
@click.option(
    "--force", is_flag=True,
    help="Rotate identity even if existing keys are in use.",
)
def backup_init(force):
    """Create a recoverable master seed for this install.

    Use this on an existing One Link install (which already has
    randomly-generated, non-recoverable keys) to switch to a
    seed-backed setup. After running this, your old identity is
    replaced — peers will see you as a "new" device with a
    different fingerprint and you'll need to re-pair with them.

    On a fresh install (no existing identity.key), the daemon
    auto-creates a seed on first launch. This command is for
    EXISTING installs that want to opt into recovery.
    """
    from one_link import master_seed
    from one_link.paths import data_dir, key_path
    if master_seed.has_seed(data_dir()):
        click.echo(
            "A master seed already exists. Run `one-link backup show`\n"
            "to view its 24-word phrase. To rotate the seed (and thus\n"
            "the identity), delete the seed file at\n"
            f"  {data_dir() / master_seed.SEED_FILENAME}\n"
            "and re-run this command.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    if key_path().is_file() and not force:
        click.echo(
            "An existing identity key is in use. Initializing a master\n"
            "seed at this point will REPLACE that identity (peers will\n"
            "see you as a different device after the swap).\n"
            "Re-run with --force to confirm rotation.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    # If --force was passed and an identity exists: delete the old
    # identity so the daemon will derive a fresh one from the seed.
    if key_path().is_file() and force:
        try:
            key_path().unlink()
        except OSError as e:
            click.echo(f"Could not remove old identity: {e}", err=True)
            raise click.exceptions.Exit(1)
        # Also drop the DRK so it gets re-derived from the seed.
        from one_link.lockbox import DRK_FILENAME
        drk_path = data_dir() / DRK_FILENAME
        with __import__("contextlib").suppress(OSError):
            drk_path.unlink()
    seed, _ = master_seed.load_or_create_seed(data_dir())
    click.echo(
        "Master seed created. Run `one-link backup show` and write\n"
        "down the 24 words on paper. Then start the daemon — it will\n"
        "derive a fresh identity + at-rest key from the seed."
    )


@backup.command("restore")
@click.argument("phrase_words", nargs=-1)
@click.option(
    "--force", is_flag=True,
    help="Overwrite existing identity even if one is present.",
)
def backup_restore(phrase_words, force):
    """Restore identity from a 24-word recovery phrase.

    Use on a NEW device that you want to be the same identity as
    your old (lost) device. Type the 24 words separated by spaces:

        one-link backup restore word1 word2 ... word24

    Or paste them when prompted (no arguments).

    Refuses to run if an identity already exists, unless --force.
    The seed file is created from the phrase; on next daemon
    launch the identity + DRK derive from it.
    """
    from one_link import master_seed, mnemonic
    from one_link.paths import data_dir, key_path
    if master_seed.has_seed(data_dir()) and not force:
        click.echo(
            "A master seed already exists on this install. To replace\n"
            "it with a restored seed, re-run with --force.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    if key_path().is_file() and not force:
        click.echo(
            "An existing identity key is in use. Restoring will\n"
            "REPLACE that identity. Re-run with --force to confirm.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    if not phrase_words:
        click.echo(
            "Type the 24 words separated by spaces, then press Enter.\n"
            "(Hidden input; the phrase will not be echoed.)"
        )
        raw = click.prompt(
            "phrase", hide_input=True, prompt_suffix="> ",
        )
    else:
        raw = " ".join(phrase_words)
    try:
        seed = mnemonic.decode(raw)
    except ValueError as e:
        click.echo(f"Invalid phrase: {e}", err=True)
        raise click.exceptions.Exit(1)
    # Force-mode: clear out the old identity + DRK so they
    # re-derive from the restored seed on next launch.
    if force:
        with __import__("contextlib").suppress(OSError):
            key_path().unlink()
        from one_link.lockbox import DRK_FILENAME
        with __import__("contextlib").suppress(OSError):
            (data_dir() / DRK_FILENAME).unlink()
    master_seed.store_seed(data_dir(), seed)
    click.echo(
        "Master seed restored. Start the daemon — it will derive\n"
        "your identity + at-rest key from the restored seed.\n"
        "Peers paired with the original device will recognize you."
    )


@backup.command("export")
@click.argument("out_path", type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--include-files", is_flag=True,
    help=(
        "Also include everything under inbox/. Inboxes can be GB-sized; "
        "default is to bundle only the load-bearing state (sqlite + keys + "
        "settings). Identity, chat history, groups, and folder configs are "
        "ALWAYS included regardless of this flag."
    ),
)
def backup_export(out_path, include_files):
    """Write an encrypted backup bundle to OUT_PATH (a .olbak file).

    The bundle is sealed with a key derived from your master seed
    (the same seed your 24-word phrase encodes). It can ONLY be
    decrypted by an install that knows the seed: either this same
    daemon, or a fresh install where you've typed the 24 words via
    `one-link backup restore`.

    Without the seed the bundle is ciphertext indistinguishable
    from random. Drop it on a USB stick, upload to any cloud, mail
    it to yourself — without the 24 words it's unintelligible.

    Refuses to run if no master seed has been provisioned (run
    `one-link backup init` first to create one).
    """
    from one_link import backup_bundle, master_seed
    from one_link.paths import data_dir
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        click.echo(
            "No master seed has been provisioned for this install.\n"
            "Run `one-link backup init` first.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    out_path = out_path.expanduser().resolve()
    if out_path.exists():
        click.echo(
            f"Refusing to overwrite existing file: {out_path}\n"
            "Pick a different path, or remove it first.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    try:
        n = backup_bundle.create_bundle_to_file(
            seed=seed,
            data_dir=data_dir(),
            out_path=out_path,
            include_files=include_files,
        )
    except (OSError, ValueError) as e:
        raise click.ClickException(f"export failed: {e}")
    click.echo(f"wrote {n} bytes -> {out_path}")
    click.echo(
        "This file is encrypted under your master seed. To restore it on a\n"
        "new device, copy it there + run `one-link backup import <path>`\n"
        "AFTER you've restored the 24-word phrase on that device."
    )


@backup.command("import")
@click.argument("bundle_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--overwrite", is_flag=True,
    help="Replace files at the target if they already exist.",
)
@click.option(
    "--target-dir", type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Override the install's data dir (advanced; default is correct).",
)
def backup_import(bundle_path, overwrite, target_dir):
    """Decrypt and unpack a .olbak bundle into this install's data dir.

    Requires a master seed already provisioned on this install (via
    `one-link backup restore <24 words>`). The seed must match the
    one that sealed the bundle, or decryption fails.

    Default behavior refuses to clobber existing files in the
    target dir. Pass --overwrite to allow replacement (this is
    destructive: existing chat history etc. will be overwritten).
    """
    from one_link import backup_bundle, master_seed
    from one_link.paths import data_dir
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        click.echo(
            "No master seed on this install. Run\n"
            "  one-link backup restore <word1> <word2> ... <word24>\n"
            "first, using the 24-word phrase from the device this bundle came from.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    target = Path(target_dir).expanduser().resolve() if target_dir else data_dir()
    try:
        header, written = backup_bundle.restore_bundle_from_file(
            seed=seed,
            bundle_path=Path(bundle_path).expanduser().resolve(),
            target_dir=target,
            overwrite=overwrite,
        )
    except FileExistsError as e:
        click.echo(
            f"Refusing to overwrite existing file: {e}\n"
            "Re-run with --overwrite to replace, or pick a clean --target-dir.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    except ValueError as e:
        # Wrong seed, tampered file, bad magic, traversal attempt, etc.
        raise click.ClickException(f"import failed: {e}")
    except OSError as e:
        raise click.ClickException(f"import failed: {e}")
    click.echo(f"restored {len(written)} file(s) into {target}")
    if written:
        for name in written[:20]:
            click.echo(f"  - {name}")
        if len(written) > 20:
            click.echo(f"  ... and {len(written) - 20} more")
    click.echo(
        "Restart the daemon (or `one-link daemon`) so the new state is\n"
        "loaded into memory."
    )


@cli.group()
def recovery():
    """Social recovery — your social graph IS your backup layer.

    Instead of keeping a 24-word phrase on paper (and hoping it's
    not lost / read by a thief / destroyed in a fire), split your
    master seed into 5 Shamir shares and hand each to a different
    trusted contact. ANY 3 of the 5 reconstruct your identity on a
    new device. Up to 2 contacts can be malicious or coerced and
    still gain nothing — Shamir's information-theoretic threshold
    holds.

    Trust model: you trust that 3 of your 5 chosen contacts won't
    all collude against you. Different from custodial recovery
    (Apple iCloud, Google account) where ONE entity holds every-
    thing; here no platform — and no single person — can lock you
    out of your own identity.

    Workflow:

      one-link recovery setup <name1> <ed_pub_hex_1> ... <name5> <ed_pub_hex_5>
        Mints 5 wrapped shares + writes each to ./shares/<name>.olshare
        ready to deliver to the named contact (USB stick, in-person
        QR, encrypted email, channel message — the medium is up to
        you, the wrap is sealed).

      one-link recovery unwrap <share_path>
        For a CONTACT who has received a share addressed to them:
        decrypt it with this device's identity and print the share
        bytes (also as a QR-friendly base64 string ready to scan
        back to the recovering user).

      one-link recovery restore <share_blob_1> ... <share_blob_K>
        On a fresh device: reconstruct the master seed from K
        decrypted shares (each is the base64 the unwrap step
        emitted) and persist it. On next daemon start, identity +
        DRK + everything else derives from the recovered seed.
    """


@recovery.command("setup")
@click.argument("guardians", nargs=-1)
@click.option(
    "--threshold", "threshold_k", default=3, type=int,
    help="K in K-of-N (default 3)",
)
@click.option(
    "--out-dir", type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Where to write the wrapped shares (default ./shares/).",
)
def recovery_setup(guardians, threshold_k, out_dir):
    """Split this device's master seed into wrapped shares.

    GUARDIANS is a flat list of (name ed_pub_hex) pairs:

        one-link recovery setup \\
            mom    a1b2c3...64hex \\
            dad    11223344...64hex \\
            sister deadbeef...64hex \\
            old-laptop  abcdef...64hex \\
            backup-yubikey 99887766...64hex
    """
    from one_link import master_seed, social_recovery
    from one_link.paths import data_dir
    if len(guardians) % 2 != 0 or len(guardians) < 4:
        raise click.ClickException(
            "GUARDIANS must be (name pub_hex) pairs; need at least 2 guardians.\n"
            "Example: one-link recovery setup mom abc... dad def... sister 123..."
        )
    parsed: list[tuple[str, bytes]] = []
    for i in range(0, len(guardians), 2):
        name = guardians[i]
        try:
            pub = bytes.fromhex(guardians[i + 1])
        except ValueError:
            raise click.ClickException(
                f"guardian {name!r}: pub_hex is not valid hex"
            )
        if len(pub) != 32:
            raise click.ClickException(
                f"guardian {name!r}: pub_hex must be 32 bytes (64 hex chars), "
                f"got {len(pub)} bytes"
            )
        parsed.append((name, pub))
    total_n = len(parsed)
    if not (2 <= threshold_k <= total_n):
        raise click.ClickException(
            f"--threshold must be 2 ≤ K ≤ N (got K={threshold_k}, N={total_n})"
        )
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        raise click.ClickException(
            "No master seed on this install. Run `one-link backup init` "
            "first to provision one (or `one-link backup restore <24 words>` "
            "to recover an existing identity)."
        )
    shares = social_recovery.setup_social_recovery(
        seed=seed, guardians=parsed, threshold_k=threshold_k,
    )
    target_dir = (
        Path(out_dir).expanduser().resolve() if out_dir
        else Path("./shares").expanduser().resolve()
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    for name, share in shares:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        out = target_dir / f"{safe_name}.olshare"
        out.write_bytes(share.encoded)
    click.echo(
        f"wrote {len(shares)} shares ({threshold_k}-of-{total_n}) -> {target_dir}\n"
        f"deliver each .olshare file to the named guardian. Any {threshold_k} "
        f"of the {total_n} reconstruct your seed."
    )


@recovery.command("unwrap")
@click.argument(
    "share_path", type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def recovery_unwrap(share_path):
    """Decrypt a share addressed to this device.

    Run as a guardian who has received a .olshare file from someone
    asking you to be a recovery contact. Prints the decrypted share
    bytes (hex) and a QR-friendly base64 form. The recovering
    person will paste / scan that base64 along with K-1 others.
    """
    import base64

    from one_link import master_seed, social_recovery
    from one_link.paths import data_dir, key_path
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        # Fall back to the raw identity key — older daemons without a
        # master seed still have an Ed25519 priv on disk.
        if not key_path().is_file():
            raise click.ClickException(
                "no master seed AND no identity.key — this device has no "
                "private key to unwrap a share with"
            )
        # Best-effort load of the raw priv seed from PEM:
        from cryptography.hazmat.primitives import serialization
        try:
            from one_link.identity import _identity_key_passphrase
            pw = _identity_key_passphrase()
        except Exception:
            pw = None
        try:
            priv_obj = serialization.load_pem_private_key(
                key_path().read_bytes(), password=pw,
            )
            ed_seed = priv_obj.private_bytes_raw()
        except Exception as e:
            raise click.ClickException(f"identity key load failed: {e}")
    else:
        ed_seed = master_seed.derive_identity_priv(seed).private_bytes_raw()

    blob = Path(share_path).read_bytes()
    try:
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=blob, my_ed_priv_seed=ed_seed,
        )
    except ValueError as e:
        raise click.ClickException(f"unwrap failed: {e}")
    parsed = social_recovery.WrappedShare.parse(blob)
    click.echo(
        f"share index:  {idx}\n"
        f"threshold:    {parsed.threshold}-of-{parsed.total}\n"
        f"setup_ms:     {parsed.setup_ms}\n"
    )
    # Encode as base64 for in-person paste / QR.
    payload = bytes([idx]) + share_bytes
    portable = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    click.echo(
        "Send this single string to the person recovering. They will\n"
        "combine it with shares from K-1 other contacts to reconstruct\n"
        "their identity. Treat it as sensitive: anyone holding K shares\n"
        "can take over the original device's identity.\n"
    )
    click.echo(portable)


@recovery.command("restore")
@click.argument("portable_shares", nargs=-1)
@click.option(
    "--force", is_flag=True,
    help="Overwrite an existing master seed on this device.",
)
def recovery_restore(portable_shares, force):
    """Reconstruct the master seed from K guardian shares.

    PORTABLE_SHARES is the list of base64 strings collected from the
    `recovery unwrap` step on each of K guardian devices.
    """
    import base64

    from one_link import master_seed, social_recovery
    from one_link.paths import data_dir, key_path
    if len(portable_shares) < 2:
        raise click.ClickException(
            "need at least 2 portable shares (from `recovery unwrap` on "
            "each guardian device)"
        )
    if master_seed.has_seed(data_dir()) and not force:
        click.echo(
            "A master seed already exists on this install. Re-run with\n"
            "--force to replace it. The existing identity will be REPLACED.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    decrypted: list[tuple[int, bytes]] = []
    for s in portable_shares:
        try:
            pad = "=" * ((4 - len(s) % 4) % 4)
            payload = base64.urlsafe_b64decode((s + pad).encode("ascii"))
        except Exception as e:
            raise click.ClickException(f"share {s[:8]}…: not valid base64 ({e})")
        if len(payload) < 2:
            raise click.ClickException(f"share {s[:8]}…: too short")
        idx = payload[0]
        share_bytes = payload[1:]
        decrypted.append((idx, share_bytes))
    try:
        seed = social_recovery.reconstruct_from_decrypted_shares(decrypted)
    except ValueError as e:
        raise click.ClickException(f"reconstruct failed: {e}")
    if force:
        with __import__("contextlib").suppress(OSError):
            key_path().unlink()
        from one_link.lockbox import DRK_FILENAME
        with __import__("contextlib").suppress(OSError):
            (data_dir() / DRK_FILENAME).unlink()
    master_seed.store_seed(data_dir(), seed)
    click.echo(
        "master seed reconstructed + persisted. Start the daemon — it\n"
        "will derive your identity + at-rest key from the recovered seed.\n"
        "Peers paired with the original device will recognize you."
    )


@cli.command("native-status")
def native_status():
    """Show whether the native transfer accelerator is active."""
    from one_link.native_cdc import native_cdc_status

    st = native_cdc_status()
    click.echo(f"native_cdc: {'yes' if st.available else 'no'}")
    click.echo(f"engine:     {st.engine}")
    if st.library:
        click.echo(f"library:    {st.library}")
    if st.reason:
        click.echo(f"reason:     {st.reason}")


@cli.command()
def peers():
    """List discovered peers on the LAN."""
    res = _request("peers")
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "unknown error"))
    me = res["me"]
    click.echo(f"me: {me['short_id']}  {me['hostname']}")
    plist = res["peers"]
    if not plist:
        click.echo("(no peers discovered yet — give it a few seconds)")
        return
    click.echo("")
    click.echo(f"{'short_id':10} {'hostname':24} {'address':18} port")
    click.echo("-" * 60)
    for p in plist:
        click.echo(
            f"{p['short_id']:10} {p['hostname']:24} {p['address']:18} {p['port']}"
        )


@cli.command()
@click.argument("peer")
@click.argument("body")
def send(peer, body):
    """Send a chat message to PEER (short_id or hostname)."""
    res = _request("send", timeout=30.0, peer=peer, body=body)
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "send failed"))
    r = res["result"]
    click.echo(f"sent  id={r['sent']['id'][:8]}  ack={r['ack']['t']}")


@cli.command("send-file")
@click.argument("peer")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def send_file(peer, path):
    """Send a file to PEER. Any size."""
    size = path.stat().st_size
    click.echo(f"sending {path.name} ({size} bytes)...")
    timeout = max(300.0, min(3600.0, size / (512 * 1024)))
    res = _request(
        "send_file",
        timeout=timeout,
        peer=peer,
        path=str(path.resolve()),
    )
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "send-file failed"))
    r = res["result"]
    click.echo(
        f"sent  blob={r['blob'][:12]}  chunks={r['chunks']}  size={r['size']}"
    )


@cli.command()
@click.option("--no-browser", is_flag=True, help="Don't auto-open a browser tab.")
@click.option(
    "--lan",
    is_flag=True,
    help=(
        "Bind to 0.0.0.0 so devices on your local Wi-Fi (your phone, "
        "another laptop) can reach the UI. Prints the LAN URL + a "
        "security warning. Default is loopback-only."
    ),
)
def app(no_browser, lan):
    """Open the One Link desktop app (auto-starts daemon, opens browser UI)."""
    from one_link.app import run_app
    raise SystemExit(run_app(no_browser=no_browser, lan=lan))


@cli.command()
def chat():
    """Open the interactive terminal REPL. Auto-starts a daemon if none running."""
    from one_link.chat import run_chat
    raise SystemExit(run_chat())


@cli.command()
def audit():
    """Print a self-audit of this binary's network surface.

    Reports every kind of network call this build can make, sourced from
    the registered HTTP routes and the peer protocol's declared message
    types. Useful for verifying 'no telemetry, no calls home' claims.
    """
    res = _request("audit")
    if res.get("error") or res.get("ok") is False:
        # The control socket doesn't have audit; we go via the UI port.
        from one_link import server as server_mod
        try:
            ui_port = server_mod.read_server_port()
            token = server_mod.read_ui_token()
        except RuntimeError as e:
            raise click.ClickException(f"daemon not running ({e})")
        import urllib.request
        import json as _json
        req = urllib.request.Request(
            f"http://127.0.0.1:{ui_port}/api/audit",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                res = _json.loads(r.read())
        except Exception as e:
            raise click.ClickException(f"audit fetch failed: {e}")

    click.echo(f"One Link version {res.get('version', '?')}")
    click.echo(f"  UI bind:           {res.get('ui_bind')}")
    click.echo(f"  UI auth:           {res.get('ui_auth')}")
    click.echo(f"  External telemetry: {'NO' if res.get('no_external_telemetry') else 'YES'}")
    doctrine = res.get("sovereign_network", {})
    if doctrine:
        click.echo(f"  Mission:            {doctrine.get('mission', '')}")
        click.echo("  Principles:")
        for p in doctrine.get("principles", []):
            click.echo(f"    - {p}")
        click.echo("  Sovereign capabilities:")
        for c in doctrine.get("capabilities", []):
            click.echo(f"    - {c['name']} [{c['status']}]")
    pp = res.get("peer_protocol", {})
    click.echo("  Peer protocol:")
    click.echo(f"    transport:   {pp.get('transport')}")
    click.echo(f"    auth:        {pp.get('auth')}")
    click.echo(f"    encryption:  {pp.get('encryption')}")
    click.echo(f"    msg types:   {', '.join(pp.get('message_types', []))}")
    click.echo(f"    max frame:   {pp.get('max_frame_bytes')} bytes")
    if res.get("local_capabilities"):
        click.echo(f"    local caps:  {', '.join(res.get('local_capabilities', []))}")
    if pp.get("sessions"):
        click.echo("    sessions:")
        for s in pp.get("sessions", []):
            click.echo(f"      - {s.get('name')}")
    click.echo("  Outbound destinations:")
    for o in res.get("outbound_destinations", []):
        click.echo(f"    - {o['kind']}: {o['destination']}")
        click.echo(f"        protocol: {o['protocol']}")
    click.echo("  Local UI routes:")
    for r in res.get("local_ui_routes", []):
        click.echo(f"    {r['method']:6} {r['path']}")
    primitives = res.get("sovereign_primitives", [])
    if primitives:
        click.echo("  Sovereign primitives:")
        for p in primitives:
            status = p.get("status", "?")
            ref = p.get("audit_ref", "")
            click.echo(
                f"    {p['name']:42} [{status}]  {ref}"
            )
            click.echo(f"      {p['summary']}")


@cli.command()
@click.argument("query")
@click.option("--peer", default=None, help="Filter by peer (short_id or fingerprint).")
@click.option("--limit", default=50, type=int, help="Max results.")
def search(query, peer, limit):
    """Full-text search across message history."""
    from one_link import server as server_mod
    try:
        ui_port = server_mod.read_server_port()
        token = server_mod.read_ui_token()
    except RuntimeError as e:
        raise click.ClickException(f"daemon not running ({e})")

    import urllib.parse
    import urllib.request
    import json as _json
    qs = {"q": query, "limit": str(limit)}
    if peer:
        qs["peer"] = peer
    url = f"http://127.0.0.1:{ui_port}/api/search?{urllib.parse.urlencode(qs)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            res = _json.loads(r.read())
    except Exception as e:
        raise click.ClickException(f"search failed: {e}")

    msgs = res.get("messages", [])
    click.echo(f"{len(msgs)} result(s) for {query!r}\n")
    for m in msgs:
        if m.get("t") != "TEXT":
            continue
        ts = m.get("ts", 0)
        peer = m.get("peer", "?")
        body = m.get("body", "")
        click.echo(f"  [{ts}] {peer}: {body}")


@cli.command()
def tail():
    """Stream incoming and outgoing message events. Ctrl-C to stop."""
    s, _ = _connect_control()
    s.settimeout(None)
    try:
        s.sendall((json.dumps({"cmd": "tail"}) + "\n").encode("utf-8"))
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                obj = json.loads(line.decode("utf-8"))
                if obj.get("ok") is True and obj.get("tailing"):
                    click.echo("(tailing — Ctrl-C to stop)")
                    continue
                msg = obj.get("msg") or obj
                _print_event(msg)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()


def _print_event(m: dict) -> None:
    direction = m.get("dir", "?")
    arrow = "<-" if direction == "in" else "->"
    peer = m.get("peer", "?")
    t = m.get("t", "?")
    if t == "TEXT":
        click.echo(f"[{m.get('ts','')}] {arrow} {peer}: {m.get('body','')}")
    elif t == "FILE_OFFER":
        click.echo(
            f"[{m.get('ts','')}] {arrow} {peer} OFFER {m.get('name','')} "
            f"({m.get('size','?')} bytes, blob={m.get('blob','')[:8]})"
        )
    elif t == "FILE_DONE":
        ok = "OK" if m.get("ok") else "BAD"
        click.echo(
            f"[{m.get('ts','')}] {arrow} {peer} FILE_DONE [{ok}] "
            f"{m.get('name','')} -> {m.get('path','')}"
        )
    else:
        click.echo(f"[{m.get('ts','')}] {arrow} {peer} {t}")


def _ui_request(method: str, path: str, *, payload=None) -> dict:
    """Helper for hitting the daemon's UI API from CLI commands."""
    from one_link import server as server_mod
    try:
        ui_port = server_mod.read_server_port()
        token = server_mod.read_ui_token()
    except RuntimeError as e:
        raise click.ClickException(f"daemon not running ({e})")

    import urllib.error
    import urllib.request
    import json as _json
    body = None
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        body = _json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"http://127.0.0.1:{ui_port}{path}",
        data=body, headers=headers, method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return _json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return _json.loads(e.read())
        except Exception:
            raise click.ClickException(f"{path} failed: {e}")
    except Exception as e:
        raise click.ClickException(f"{path} failed: {e}")


@cli.group()
def folder():
    """Synced-folder management. Folders sync between paired peers."""


@folder.command("add")
@click.argument("name")
@click.argument("local_path", type=click.Path(file_okay=False, path_type=Path))
@click.option("--share", "share", multiple=True,
              help="Peer fingerprint to share with (repeatable).")
def folder_add(name, local_path, share):
    """Designate a folder to sync. NAME is a label, LOCAL_PATH is the directory."""
    res = _ui_request("POST", "/api/folders", payload={
        "name": name,
        "local_path": str(local_path.expanduser().resolve()),
        "shared_with": list(share),
    })
    if res.get("error"):
        raise click.ClickException(res["error"])
    f = res.get("folder", {})
    click.echo(f"added: {f.get('name')}  ->  {f.get('local_path')}")
    if f.get("shared_with"):
        click.echo("  shared with:")
        for fp in f["shared_with"]:
            click.echo(f"    {fp[:16]}…")


@folder.command("list")
def folder_list():
    """List all configured sync folders."""
    res = _ui_request("GET", "/api/folders")
    folders = res.get("folders", [])
    if not folders:
        click.echo("(no folders configured — try: one-link folder add)")
        return
    click.echo(f"{'name':16} {'files':>6} {'in_store':>9}  path")
    click.echo("-" * 60)
    for f in folders:
        click.echo(
            f"{f['name']:16} {f.get('files', 0):>6} {f.get('in_store', 0):>9}  "
            f"{f['local_path']}"
        )
        if f.get("shared_with"):
            click.echo(f"{'':16} shared with: " + ", ".join(
                fp[:8] + "…" for fp in f["shared_with"]
            ))


@folder.command("share")
@click.argument("name")
@click.argument("fingerprint")
def folder_share(name, fingerprint):
    """Add a peer FINGERPRINT to the sharing list of folder NAME."""
    res = _ui_request("POST", f"/api/folders/{name}/share",
                      payload={"peer_fp": fingerprint})
    if res.get("error"):
        raise click.ClickException(res["error"])
    click.echo(f"shared {name!r} with {fingerprint[:16]}…")


@folder.command("remove")
@click.argument("name")
def folder_remove(name):
    """Stop syncing folder NAME. Local files are not deleted."""
    res = _ui_request("DELETE", f"/api/folders/{name}")
    if res.get("error"):
        raise click.ClickException(res["error"])
    click.echo(f"removed: {name}")


@folder.command("sync")
@click.argument("name")
def folder_sync(name):
    """Force an immediate sync cycle for folder NAME."""
    res = _ui_request("POST", f"/api/folders/{name}/sync", payload={})
    if res.get("error"):
        raise click.ClickException(res["error"])
    for r in res.get("results", []):
        peer = r.get("peer_fp", "?")[:8] + "…"
        if r["status"] == "pushed":
            click.echo(
                f"  {peer}  pushed  wants={r.get('wants', 0)}  "
                f"blobs_sent={r.get('blobs_sent', 0)}"
            )
        else:
            click.echo(f"  {peer}  {r['status']}")


def main():
    cli()


if __name__ == "__main__":
    sys.exit(main() or 0)
