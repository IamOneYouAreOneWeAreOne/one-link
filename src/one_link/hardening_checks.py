"""Boot-time security hardening checks.

Surfaced at daemon startup so the operator sees a clear picture of the
at-rest + bind posture they're running with — and any items that need
their attention. Never blocks startup; logs every finding at INFO
(passes) or WARNING (concerns) so it shows up in stderr + any log
collector.

Audit categories:
  1. File permissions — every sensitive file in data_dir should be
     owner-only (0600 on POSIX, owner-only ACL on Windows).
  2. Cloud-sync co-location — warn loudly if data_dir is inside a
     OneDrive / iCloud / Dropbox path, because the plaintext-or-
     encrypted state.db would auto-upload to a third party.
  3. Network bind — warn if bind_host is non-loopback without the
     operator explicitly using --lan.
  4. At-rest encryption status — report whether SQLCipher is active
     + which keychain backend supplied the key.
"""
from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Iterable, NamedTuple

log = logging.getLogger("one_link.hardening")


SENSITIVE_FILE_NAMES = (
    "state.db",
    "state.db-wal",
    "state.db-shm",
    "ui.token",
    "data-root-key.bin",
    "cap_root.key",
    "courier.json",
)

# Substring matches against the data_dir's full path. Case-insensitive
# (Windows paths are CI; macOS HFS+ defaults to CI too). These cover
# the consumer cloud-sync clients that auto-pull every file in their
# tree into a remote cache.
CLOUD_SYNC_MARKERS = (
    "onedrive",
    "icloud",
    "icloudd",
    "dropbox",
    "google drive",
    "googledrive",
    "box sync",
    "pcloud",
    "mega",
    "sync.com",
)


class Finding(NamedTuple):
    severity: str   # "info" / "warn" / "fail"
    category: str
    message: str


def check_file_permissions(data_dir: Path) -> list[Finding]:
    """For every known-sensitive file under data_dir, verify it isn't
    world / group readable. Best-effort across OS:

      POSIX  → stat().st_mode bits — flag if group/other read are set
      Windows → no st_mode equivalent; we can't enforce ACL semantics
                from stdlib alone, so we surface 'permissions check not
                supported on Windows' INFO + recommend FileVault /
                BitLocker as the right answer
    """
    findings: list[Finding] = []
    if os.name == "nt":
        findings.append(Finding(
            "info", "file_permissions",
            "Windows: per-file owner-only ACLs aren't checked here. "
            "Rely on full-disk encryption (BitLocker) for at-rest "
            "protection of the data directory.",
        ))
        return findings
    for name in SENSITIVE_FILE_NAMES:
        p = data_dir / name
        if not p.exists():
            continue
        try:
            mode = p.stat().st_mode
        except OSError:
            continue
        # Mask out file-type bits; keep permission bits.
        perm = stat.S_IMODE(mode)
        # We want 0o600 or 0o400 (no group / other access).
        group_or_other = perm & 0o077
        if group_or_other:
            findings.append(Finding(
                "warn", "file_permissions",
                f"{name} is mode 0o{perm:o}; should be 0o600. Other "
                f"OS users can read it. Fixing.",
            ))
            try:
                os.chmod(p, 0o600)
                findings.append(Finding(
                    "info", "file_permissions",
                    f"{name}: re-set to 0o600.",
                ))
            except OSError as e:
                findings.append(Finding(
                    "fail", "file_permissions",
                    f"{name}: chmod 0o600 failed ({e}). Fix manually.",
                ))
        else:
            findings.append(Finding(
                "info", "file_permissions",
                f"{name}: owner-only (0o{perm:o}) — OK.",
            ))
    return findings


def check_cloud_sync_colocation(data_dir: Path) -> list[Finding]:
    """Warn if the data directory is inside a consumer cloud-sync
    tree. Such trees auto-upload every file to a third-party server,
    which defeats every layer of local-only / no-corps design.

    The check is substring-match against the absolute path. False
    positives are possible (a folder literally named 'OneDrive Test')
    but the warning is informational; we never block startup."""
    findings: list[Finding] = []
    try:
        abs_path = str(data_dir.resolve()).lower()
    except Exception:
        return findings
    hits: list[str] = []
    for marker in CLOUD_SYNC_MARKERS:
        if marker in abs_path:
            hits.append(marker)
    if hits:
        findings.append(Finding(
            "warn", "cloud_sync",
            f"Data directory {data_dir} appears to be inside a "
            f"consumer cloud-sync folder ({', '.join(hits)}). Your "
            f"state.db + identity keys + message history will "
            f"auto-upload to a third-party server. Move the data "
            f"directory to a non-synced location for true local-only "
            f"operation (ONE_LINK_HOME env var).",
        ))
    else:
        findings.append(Finding(
            "info", "cloud_sync",
            f"Data directory not inside any known cloud-sync folder — OK.",
        ))
    return findings


def check_network_bind(bind_host: str, lan_explicit: bool) -> list[Finding]:
    """Warn if the daemon is bound to a non-loopback address WITHOUT
    the operator explicitly requesting LAN mode. Default-loopback is
    the right posture for a personal app; LAN binding has to be an
    informed choice."""
    findings: list[Finding] = []
    loopback_hosts = {"127.0.0.1", "::1", "localhost"}
    if bind_host in loopback_hosts:
        findings.append(Finding(
            "info", "network_bind",
            f"Bound to {bind_host} (loopback) — only this machine "
            f"can talk to the daemon. OK.",
        ))
        return findings
    if bind_host == "0.0.0.0" and lan_explicit:
        findings.append(Finding(
            "info", "network_bind",
            f"Bound to {bind_host} (all interfaces) per explicit "
            f"--lan flag. Phones / other devices on the same Wi-Fi "
            f"can pair via the connect-another-device URL.",
        ))
        return findings
    findings.append(Finding(
        "warn", "network_bind",
        f"Bound to {bind_host} but --lan flag was NOT set. The "
        f"daemon is reachable from outside loopback; this is unusual "
        f"and likely unintended. Restart with the default bind or "
        f"pass --lan if exposure to your local network is intended.",
    ))
    return findings


def check_at_rest_encryption(is_encrypted: bool) -> list[Finding]:
    """Report the SQLCipher status + name the keychain backend that
    supplied the key, so the operator can audit WHERE the encryption
    key lives (Windows Credential Manager / macOS Keychain / etc)."""
    findings: list[Finding] = []
    if is_encrypted:
        from one_link import keychain as _kc
        backend = _kc.backend_label()
        findings.append(Finding(
            "info", "encryption",
            f"state.db: AES-256 at-rest encryption ACTIVE; key from {backend}.",
        ))
        return findings
    findings.append(Finding(
        "warn", "encryption",
        "state.db: at-rest encryption is OFF (plaintext SQLite on "
        "disk). Install `sqlcipher3` + `keyring`, or set "
        "ONE_LINK_PASSPHRASE in the env, to enable AES-256 page "
        "encryption with an auto-generated key.",
    ))
    return findings


def run_all_checks(
    *,
    data_dir: Path,
    bind_host: str,
    lan_explicit: bool,
    is_encrypted: bool,
) -> list[Finding]:
    """Run every check + return a single list of findings ordered by
    severity (fails / warns first). Callers should log each finding
    + may optionally surface them in the Privacy panel for the
    operator to audit interactively."""
    all_findings: list[Finding] = []
    all_findings.extend(check_at_rest_encryption(is_encrypted))
    all_findings.extend(check_file_permissions(data_dir))
    all_findings.extend(check_cloud_sync_colocation(data_dir))
    all_findings.extend(check_network_bind(bind_host, lan_explicit))
    order = {"fail": 0, "warn": 1, "info": 2}
    all_findings.sort(key=lambda f: order.get(f.severity, 3))
    return all_findings


def log_findings(findings: Iterable[Finding]) -> None:
    """Standard 'log every finding at the right level' loop. Called
    once at daemon boot."""
    for f in findings:
        prefix = f"[security:{f.category}]"
        if f.severity == "fail":
            log.error("%s %s", prefix, f.message)
        elif f.severity == "warn":
            log.warning("%s %s", prefix, f.message)
        else:
            log.info("%s %s", prefix, f.message)
