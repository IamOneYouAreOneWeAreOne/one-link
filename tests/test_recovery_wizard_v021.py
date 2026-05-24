"""v0.21.x recovery wizard.

Pin the three-track recovery wizard at the API surface (recovery_api.py,
server.py endpoints) and the UI surface (index.html wizard markup +
JS function symbols). The old self-attestation modal was a chicken-
and-egg dead end: it asked the user to confirm they had set up
recovery elsewhere when no in-app flow existed to actually set it
up. This test file pins the replacement: real flows for the BIP-39
phrase, Shamir 3-of-5 trusted contacts, and the .olbak encrypted
backup file.
"""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _server_src() -> str:
    return (ROOT / "src" / "one_link" / "server.py").read_text(encoding="utf-8")


def _index_html() -> str:
    return (ROOT / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")


# ── recovery_api module ──────────────────────────────────────────────


def test_recovery_api_settings_keys_are_namespaced():
    """Per-track state must live under named setting keys so the
    setup snapshot can render each card's status independently."""
    from one_link import recovery_api as ra
    assert ra.SETTING_PHRASE_VERIFIED_AT_MS == "one_setup_recovery_phrase_verified_at_ms"
    assert ra.SETTING_BACKUP_LAST_EXPORT_AT_MS == "one_setup_recovery_backup_last_export_at_ms"
    assert ra.SETTING_BACKUP_LAST_EXPORT_SIZE == "one_setup_recovery_backup_last_export_size"
    assert ra.SETTING_SOCIAL_CONFIGURED_AT_MS == "one_setup_recovery_social_configured_at_ms"
    assert ra.SETTING_SOCIAL_GUARDIAN_COUNT == "one_setup_recovery_social_guardian_count"
    assert ra.SETTING_SOCIAL_THRESHOLD_K == "one_setup_recovery_social_threshold_k"
    # Legacy ANY-track ready flag preserved for back-compat with the
    # existing setup_action("recovery_configured") path.
    assert ra.SETTING_LEGACY_CONFIGURED_AT_MS == "one_setup_recovery_configured_at_ms"


def test_snapshot_status_reports_each_track_independently(tmp_path):
    from one_link import recovery_api as ra
    state = _fake_state()
    # No seed file -> phrase + backup unavailable, social unavailable.
    snap = ra.snapshot_status(state, tmp_path)
    assert snap.phrase.available is False
    assert snap.backup.available is False
    assert snap.social.available is False
    assert snap.any_ready is False

    # Drop a seed file; phrase + backup go available.
    (tmp_path / "master.seed").write_bytes(os.urandom(32))
    snap = ra.snapshot_status(state, tmp_path)
    assert snap.phrase.available is True
    assert snap.backup.available is True
    # Social still unavailable until 2+ pinned peers exist.
    assert snap.social.available is False
    assert snap.any_ready is False


def test_snapshot_to_dict_serializes_per_track_state(tmp_path):
    from one_link import recovery_api as ra
    state = _fake_state()
    (tmp_path / "master.seed").write_bytes(os.urandom(32))
    snap = ra.snapshot_status(state, tmp_path)
    d = snap.to_dict()
    for track in ("phrase", "social", "backup"):
        assert track in d
        assert "ready" in d[track]
        assert "available" in d[track]
        assert "last_action_at_ms" in d[track]
    assert d["any_ready"] is False


def test_mark_phrase_verified_sets_both_track_and_legacy(tmp_path):
    from one_link import recovery_api as ra
    state = _fake_state()
    ts = ra.mark_phrase_verified(state)
    assert int(state.settings[ra.SETTING_PHRASE_VERIFIED_AT_MS]) == ts
    # Legacy flag set too so the global "recovery configured" check
    # stays true even if the snapshot fields are later renamed.
    assert int(state.settings[ra.SETTING_LEGACY_CONFIGURED_AT_MS]) == ts


def test_verify_phrase_positions_round_trip(tmp_path):
    """Generate a known phrase, pick 3 positions, verify they match."""
    from one_link import recovery_api as ra
    from one_link import master_seed, mnemonic
    seed = master_seed.load_or_create_seed(tmp_path)[0]
    phrase = mnemonic.encode(seed).split()
    indices = [3, 11, 21]
    words = [phrase[i - 1] for i in indices]
    ok, mismatches = ra.verify_phrase_positions(
        data_dir=tmp_path, indices=indices, words=words,
    )
    assert ok is True
    assert mismatches == []

    # One wrong word -> reports the position.
    bad_words = list(words)
    bad_words[1] = "zebra"
    ok, mismatches = ra.verify_phrase_positions(
        data_dir=tmp_path, indices=indices, words=bad_words,
    )
    assert ok is False
    assert mismatches == [11]


def test_verify_phrase_positions_case_insensitive(tmp_path):
    from one_link import recovery_api as ra
    from one_link import master_seed, mnemonic
    seed = master_seed.load_or_create_seed(tmp_path)[0]
    phrase = mnemonic.encode(seed).split()
    # Uppercase + whitespace must canonicalize.
    ok, _ = ra.verify_phrase_positions(
        data_dir=tmp_path,
        indices=[1, 2, 3],
        words=[f"  {phrase[0].upper()}  ", phrase[1].title(), phrase[2]],
    )
    assert ok is True


def test_verify_phrase_positions_rejects_out_of_range(tmp_path):
    from one_link import recovery_api as ra
    from one_link import master_seed
    master_seed.load_or_create_seed(tmp_path)
    with pytest.raises(ValueError):
        ra.verify_phrase_positions(
            data_dir=tmp_path, indices=[0, 1, 2], words=["a", "b", "c"],
        )
    with pytest.raises(ValueError):
        ra.verify_phrase_positions(
            data_dir=tmp_path, indices=[1, 2, 99], words=["a", "b", "c"],
        )


def test_verify_phrase_positions_no_seed_raises(tmp_path):
    from one_link import recovery_api as ra
    with pytest.raises(FileNotFoundError):
        ra.verify_phrase_positions(
            data_dir=tmp_path, indices=[1, 2, 3], words=["a", "b", "c"],
        )


def test_build_backup_bundle_round_trips(tmp_path):
    """Wizard's bundle bytes must decrypt back with the master seed."""
    from one_link import recovery_api as ra
    from one_link import backup_bundle, master_seed
    # Minimal data dir contents the bundle pulls from.
    (tmp_path / "state.db").write_bytes(b"SQLite format 3\x00" + os.urandom(2048))
    seed = master_seed.load_or_create_seed(tmp_path)[0]
    bundle = ra.build_backup_bundle(data_dir=tmp_path)
    # Round-trip: bundle decrypts with the same seed.
    header, plaintext = backup_bundle.open_bundle(seed=seed, bundle_bytes=bundle)
    assert header.magic == backup_bundle.BUNDLE_MAGIC
    assert len(plaintext) == header.plaintext_len


def test_build_backup_bundle_without_seed_raises(tmp_path):
    from one_link import recovery_api as ra
    with pytest.raises(FileNotFoundError):
        ra.build_backup_bundle(data_dir=tmp_path)


def test_backup_filename_has_timestamp():
    from one_link import recovery_api as ra
    name = ra.backup_filename(now_ms=0)
    assert name.startswith("one-link-backup-")
    assert name.endswith(".olbak")


def test_issue_social_shares_round_trip(tmp_path):
    """Shares produced by the wizard must unwrap correctly with each
    guardian's Ed25519 private seed."""
    from one_link import recovery_api as ra
    from one_link import master_seed, social_recovery
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    seed = master_seed.load_or_create_seed(tmp_path)[0]

    # Generate three guardian identities + collect public bytes.
    guardian_keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    guardians = [
        {
            "label": f"Guardian {i+1}",
            "pubkey_b64": _b64(g.public_key().public_bytes_raw()),
        }
        for i, g in enumerate(guardian_keys)
    ]
    shares = ra.issue_social_shares(
        data_dir=tmp_path, guardians=guardians, threshold_k=2,
    )
    assert len(shares) == 3
    for s in shares:
        assert s["threshold_k"] == 2
        assert s["total_n"] == 3
        assert s["filename"].endswith(".olss")
        assert s["filename"].startswith(f"one-link-share-{s['share_index']}-of-3-")

    # Decrypt 2 of 3 + combine back to original seed.
    import base64
    decrypted = []
    for s, gk in list(zip(shares, guardian_keys))[:2]:
        blob = base64.urlsafe_b64decode(s["blob_b64u"])
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=blob,
            my_ed_priv_seed=gk.private_bytes_raw(),
        )
        decrypted.append((idx, share_bytes))
    recovered = social_recovery.combine_shares(decrypted)
    assert recovered == seed


def test_issue_social_shares_rejects_bad_threshold(tmp_path):
    from one_link import recovery_api as ra
    from one_link import master_seed
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    master_seed.load_or_create_seed(tmp_path)
    guardians = [
        {"label": "A", "pubkey_b64": _b64(Ed25519PrivateKey.generate().public_key().public_bytes_raw())},
        {"label": "B", "pubkey_b64": _b64(Ed25519PrivateKey.generate().public_key().public_bytes_raw())},
    ]
    with pytest.raises(ValueError, match="threshold_k"):
        ra.issue_social_shares(data_dir=tmp_path, guardians=guardians, threshold_k=1)
    with pytest.raises(ValueError, match="cannot exceed"):
        ra.issue_social_shares(data_dir=tmp_path, guardians=guardians, threshold_k=5)


def test_issue_social_shares_rejects_duplicate_pubkey(tmp_path):
    from one_link import recovery_api as ra
    from one_link import master_seed
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    master_seed.load_or_create_seed(tmp_path)
    pub = _b64(Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    guardians = [
        {"label": "A", "pubkey_b64": pub},
        {"label": "B", "pubkey_b64": pub},
    ]
    with pytest.raises(ValueError, match="duplicate"):
        ra.issue_social_shares(data_dir=tmp_path, guardians=guardians, threshold_k=2)


def test_configured_track_labels_lists_each_real_track(tmp_path):
    from one_link import recovery_api as ra
    state = _fake_state()
    ra.mark_phrase_verified(state)
    ra.mark_backup_exported(state, size_bytes=1024)
    ra.mark_social_configured(state, guardian_count=5, threshold_k=3)
    labels = ra.configured_track_labels(state)
    assert "recovery phrase" in labels
    assert "trusted contacts" in labels
    assert "encrypted backup" in labels


def test_reset_all_recovery_state_wipes_every_setting(tmp_path):
    from one_link import recovery_api as ra
    state = _fake_state()
    ra.mark_phrase_verified(state)
    ra.mark_backup_exported(state, size_bytes=42)
    ra.mark_social_configured(state, guardian_count=3, threshold_k=2)
    assert state.settings  # something was set
    ra.reset_all_recovery_state(state)
    # All recovery keys gone.
    for key in (
        ra.SETTING_PHRASE_VERIFIED_AT_MS,
        ra.SETTING_BACKUP_LAST_EXPORT_AT_MS,
        ra.SETTING_BACKUP_LAST_EXPORT_SIZE,
        ra.SETTING_SOCIAL_CONFIGURED_AT_MS,
        ra.SETTING_SOCIAL_GUARDIAN_COUNT,
        ra.SETTING_SOCIAL_THRESHOLD_K,
        ra.SETTING_LEGACY_CONFIGURED_AT_MS,
    ):
        assert key not in state.settings


# ── server.py route + handler wiring ─────────────────────────────────


def test_recovery_routes_are_registered_under_v1_namespace():
    """The wizard's HTTP surface must live at /api/v1/recovery/* so it
    is clearly versioned + separate from the legacy /api/setup/* tree."""
    from one_link.server import UIServer
    daemon = SimpleNamespace(state=None, peer_rtc=None)
    server = UIServer(daemon)
    routes_by_path: dict[str, set[str]] = {}
    for resource in server.app.router.resources():
        info = resource.get_info()
        path = info.get("path") or info.get("formatter") or ""
        if not path:
            continue
        for route in resource:
            routes_by_path.setdefault(path, set()).add(route.method)
    expected = [
        ("GET",  "/api/v1/recovery/status"),
        ("POST", "/api/v1/recovery/phrase"),
        ("POST", "/api/v1/recovery/phrase/verify"),
        ("GET",  "/api/v1/recovery/backup/export"),
        ("GET",  "/api/v1/recovery/social/candidates"),
        ("POST", "/api/v1/recovery/social/issue"),
    ]
    for method, path in expected:
        assert method in routes_by_path.get(path, set()), (
            f"missing route {method} {path}; got {sorted(routes_by_path.get(path, set()))}"
        )


def test_recovery_routes_are_token_guarded():
    """Every recovery route must go through `_guarded` so the 24-word
    phrase + .olbak bundle + wrapped shares require the UI auth
    token. A misplaced bare-route line here would leak the master
    seed to anyone who could reach the daemon."""
    src = _server_src()
    for path in (
        "/api/v1/recovery/status",
        "/api/v1/recovery/phrase",
        "/api/v1/recovery/phrase/verify",
        "/api/v1/recovery/backup/export",
        "/api/v1/recovery/social/candidates",
        "/api/v1/recovery/social/issue",
    ):
        # Find the route registration line.
        marker = f'"{path}"'
        idx = src.find(marker)
        assert idx > 0, f"route {path} not registered"
        line_start = src.rfind("\n", 0, idx) + 1
        line_end = src.find("\n", idx)
        line = src[line_start:line_end]
        assert "self._guarded(" in line, (
            f"{path} is not behind _guarded: {line!r}"
        )


def test_recovery_handlers_emit_no_store_cache_headers():
    """The phrase + backup endpoints carry the master seed material
    in the response body. Belt-and-braces: those responses must NOT
    be cacheable by the browser / service worker / intermediaries.

    The shared helper `_recovery_no_store_headers` carries the
    Cache-Control: no-store + Pragma: no-cache + Expires: 0 trio.
    Every recovery handler must invoke it on its response.
    """
    src = _server_src()
    idx = src.find("def _recovery_no_store_headers(")
    assert idx > 0, "_recovery_no_store_headers helper missing"
    helper = src[idx:idx + 700]
    assert '"Cache-Control"' in helper
    assert "no-store" in helper
    assert '"Pragma"' in helper
    assert '"Expires"' in helper

    for handler in (
        "api_recovery_status",
        "api_recovery_phrase",
        "api_recovery_phrase_verify",
        "api_recovery_backup_export",
        "api_recovery_social_candidates",
        "api_recovery_social_issue",
    ):
        h_idx = src.find(f"async def {handler}(")
        assert h_idx > 0, f"handler {handler} missing"
        # Look forward only as far as the next handler definition.
        next_idx = src.find("\n    async def ", h_idx + 1)
        if next_idx < 0:
            next_idx = h_idx + 4000
        body = src[h_idx:next_idx]
        assert "_recovery_no_store_headers" in body, (
            f"{handler} does not call _recovery_no_store_headers"
        )


def test_phrase_verify_is_rate_limited():
    """Brute-forcing 3 random positions out of 24 words is feasible
    without a rate-limit. Confirm the handler buckets attempts per
    client IP and refuses after the limit."""
    src = _server_src()
    idx = src.find("async def api_recovery_phrase_verify(")
    assert idx > 0
    body = src[idx:idx + 3000]
    assert "_rate_limited(" in body
    assert '"recovery_phrase_verify"' in body
    assert "too many verification attempts" in body


def test_setup_action_reset_wipes_per_track_recovery_state():
    """The existing `reset` action on /api/setup must clear the new
    per-track keys too, not leave them orphaned with the old keys."""
    src = _server_src()
    idx = src.find("elif action == \"reset\":")
    assert idx > 0
    body = src[idx:idx + 2500]
    assert "recovery_api" in body
    assert "reset_all_recovery_state" in body


def test_recovery_row_is_recommended_not_optional():
    """The Setup checklist row for Recovery must be RECOMMENDED (not
    OPTIONAL). The modal copy already says this is the ONLY way back
    in if every device is lost — calling that 'optional' contradicts
    the wizard's own pitch."""
    src = _server_src()
    # Find the recovery checklist row.
    idx = src.find('"id": "recovery",')
    assert idx > 0
    snippet = src[idx:idx + 1200]
    # Status must be "recommended" not "optional" when not ready.
    assert '"recommended"' in snippet
    assert '"optional"' not in snippet


def test_setup_snapshot_carries_per_track_recovery_tracks():
    """The setup snapshot the UI consumes must include the per-track
    state so the wizard's status pills can render without a second
    round-trip."""
    src = _server_src()
    idx = src.find("def _one_setup_snapshot(")
    assert idx > 0
    snippet = src[idx:idx + 16000]
    assert "recovery_api.snapshot_status" in snippet
    assert "recovery_snap.to_dict()" in snippet
    assert '"tracks":' in snippet


# ── index.html wizard markup + JS symbols ────────────────────────────


def test_index_html_exposes_new_recovery_api_methods():
    html = _index_html()
    assert 'recoveryStatus() { return this.get("/api/v1/recovery/status"); }' in html
    assert 'recoveryPhrase() { return this.post("/api/v1/recovery/phrase", {}); }' in html
    assert "recoveryPhraseVerify(indices, words)" in html
    assert "recoverySocialCandidates()" in html
    assert "recoverySocialIssue(guardians, threshold_k)" in html
    assert "recoveryBackupExportUrl(includeFiles)" in html


def test_index_html_recovery_wizard_modal_replaces_self_attest_modal():
    """The old `_ensureRecoveryVerifyModal` builder + `recovery-verify-
    modal` element are gone, replaced by `_ensureRecoveryWizard` + a
    `recovery-wizard` element with three track cards."""
    html = _index_html()
    # Old symbols must be gone.
    assert "_ensureRecoveryVerifyModal" not in html
    assert "_loadRecoveryPhraseForModal" not in html
    assert "_showRecoveryVerifyModal" not in html
    assert "recovery-verify-modal" not in html

    # New symbols present.
    assert "function _ensureRecoveryWizard()" in html
    assert "async function _showRecoveryWizard()" in html
    assert "async function _recwizRefreshStatus()" in html
    assert 'id="recwiz-track-phrase"' in html
    assert 'id="recwiz-track-social"' in html
    assert 'id="recwiz-track-backup"' in html


def test_recovery_wizard_phrase_track_verifies_three_positions():
    html = _index_html()
    # _recwizPhraseStartVerify must pick 3 random positions and
    # POST them to /api/v1/recovery/phrase/verify.
    idx = html.find("function _recwizPhraseStartVerify()")
    assert idx > 0
    body = html[idx:idx + 4000]
    assert "positions.length < 3" in body
    assert "api.recoveryPhraseVerify" in body
    assert "mismatches" in body


def test_recovery_wizard_social_track_downloads_share_files():
    """The social track must NOT auto-deliver shares over the wire.
    The user picks guardians, the daemon returns sealed share bytes,
    and the UI offers them as file downloads. This keeps 'recovery
    is set up' independent of every guardian's daemon being online
    + accepting at the time of setup."""
    html = _index_html()
    issue_idx = html.find("async function _recwizSocialIssue(")
    assert issue_idx > 0
    issue = html[issue_idx:issue_idx + 4000]
    assert "api.recoverySocialIssue" in issue
    # Per-share download wiring.
    assert "_recwizDownloadShare" in issue

    dl_idx = html.find("function _recwizDownloadShare(")
    assert dl_idx > 0
    dl = html[dl_idx:dl_idx + 1500]
    assert "URL.createObjectURL" in dl
    assert "blob_b64u" in dl
    assert ".olss" in dl  # default share extension


def test_recovery_wizard_backup_track_streams_olbak_download():
    html = _index_html()
    idx = html.find("async function _recwizBackupExport(")
    assert idx > 0
    body = html[idx:idx + 2500]
    assert "api.recoveryBackupExportUrl" in body
    assert "Content-Disposition" in body
    assert ".olbak" in body


# ── restore-from-phrase ──────────────────────────────────────────────


def test_restore_seed_from_phrase_round_trips(tmp_path):
    """A fresh seed encoded as 24 words decodes back to the same
    bytes and persists to disk."""
    from one_link import master_seed, mnemonic, recovery_api
    seed_in, _ = master_seed.load_or_create_seed(tmp_path)
    phrase = mnemonic.encode(seed_in)
    # Wipe the just-created seed file; restore should re-write it.
    (tmp_path / "master.seed").unlink()
    assert not master_seed.has_seed(tmp_path)
    seed_out = recovery_api.restore_seed_from_phrase(
        data_dir=tmp_path,
        phrase=phrase,
        delete_identity_files=False,
    )
    assert master_seed.has_seed(tmp_path)
    assert master_seed.load_seed(tmp_path) == seed_in
    assert seed_out == seed_in


def test_restore_seed_from_phrase_rejects_bad_checksum(tmp_path):
    """A typo in the phrase fails the BIP-39 checksum and raises
    ValueError BEFORE touching disk."""
    from one_link import master_seed, mnemonic, recovery_api
    seed_in, _ = master_seed.load_or_create_seed(tmp_path)
    phrase = mnemonic.encode(seed_in).split()
    # Corrupt the last word to break the checksum.
    phrase[-1] = "zebra"
    bad = " ".join(phrase)
    # Pre-existing seed should NOT change after a failed decode.
    original_bytes = (tmp_path / "master.seed").read_bytes()
    with pytest.raises(ValueError):
        recovery_api.restore_seed_from_phrase(
            data_dir=tmp_path, phrase=bad, delete_identity_files=False,
        )
    assert (tmp_path / "master.seed").read_bytes() == original_bytes


def test_is_install_clean_for_restore_counts_each_dimension():
    """The dirty signals: pinned peers, groups, self-mesh devices.
    Any one of them flips the install from clean to dirty."""
    from one_link import recovery_api as ra
    state = _fake_state()
    clean, ev = ra.is_install_clean_for_restore(state)
    assert clean is True
    assert ev["pinned_peers"] == 0

    class _Peer:
        def __init__(self, trust):
            self.trust = trust
            self.pubkey = b"\x00" * 32
    state._peers = [_Peer("pinned")]
    clean, ev = ra.is_install_clean_for_restore(state)
    assert clean is False
    assert ev["pinned_peers"] == 1


def test_restore_phrase_endpoint_registered_and_guarded():
    """Route registered + behind _guarded + rate-limited."""
    from one_link.server import UIServer
    daemon = SimpleNamespace(state=None, peer_rtc=None)
    server = UIServer(daemon)
    routes_by_path: dict[str, set[str]] = {}
    for resource in server.app.router.resources():
        info = resource.get_info()
        path = info.get("path") or info.get("formatter") or ""
        if not path:
            continue
        for route in resource:
            routes_by_path.setdefault(path, set()).add(route.method)
    assert "GET" in routes_by_path.get("/api/v1/recovery/restore/preflight", set())
    assert "POST" in routes_by_path.get("/api/v1/recovery/restore/phrase", set())

    src = _server_src()
    for path in ("/api/v1/recovery/restore/preflight", "/api/v1/recovery/restore/phrase"):
        idx = src.find(f'"{path}"')
        assert idx > 0
        line_start = src.rfind("\n", 0, idx) + 1
        line_end = src.find("\n", idx)
        line = src[line_start:line_end]
        assert "self._guarded(" in line, f"{path} not guarded: {line!r}"

    # Rate-limit on the destructive POST handler.
    handler_idx = src.find("async def api_recovery_restore_phrase(")
    assert handler_idx > 0
    body = src[handler_idx:handler_idx + 4000]
    assert "_rate_limited(" in body
    assert '"recovery_restore_phrase"' in body
    assert "too many restore attempts" in body


def test_restore_phrase_handler_refuses_destructive_without_force():
    """The destructive_restore_requires_confirmation guard must be
    in the handler source so a future refactor can't silently turn
    restore into a one-click identity-replace."""
    src = _server_src()
    idx = src.find("async def api_recovery_restore_phrase(")
    assert idx > 0
    body = src[idx:idx + 4000]
    assert "destructive_restore_requires_confirmation" in body
    assert "confirmed_replace" in body
    assert "is_install_clean_for_restore" in body


def test_index_html_exposes_restore_api_methods():
    html = _index_html()
    assert 'recoveryRestorePreflight() { return this.get("/api/v1/recovery/restore/preflight"); }' in html
    assert "recoveryRestorePhrase(phrase, force, confirmedReplace)" in html
    assert '"/api/v1/recovery/restore/phrase"' in html


def test_index_html_restore_modal_wired_to_two_entry_points():
    """Both entry points (onboarding step 3 'I already have one' and
    the Settings wizard's Restore card) must route into the same
    function `openRecoveryRestoreModal`."""
    html = _index_html()
    # The modal builder + opener exist.
    assert "async function openRecoveryRestoreModal()" in html
    assert "function _ensureRecoveryRestoreModal()" in html
    assert 'm.id = "recovery-restore-modal"' in html

    # Onboarding entry point: button id + click handler.
    assert 'id="one-setup-restore-identity"' in html
    assert '$("#one-setup-restore-identity")?.addEventListener("click", openRecoveryRestoreModal)' in html

    # Wizard entry point: 4th card with data-recwiz-action="open-restore".
    assert 'id="recwiz-track-restore"' in html
    assert 'data-recwiz-action="open-restore"' in html
    # And the wizard's click router dispatches it.
    assert 'if (action === "open-restore")' in html


def test_restore_modal_blocks_submit_until_24_words_and_confirm():
    """The submit button must stay disabled unless tokens.length === 24,
    AND (when dirty) the confirmation checkbox is ticked."""
    html = _index_html()
    idx = html.find("function _renderRecoveryRestoreInput(")
    assert idx > 0
    body = html[idx:idx + 5000]
    # Validates token count.
    assert "tokens.length < 24" in body
    assert "tokens.length > 24" in body
    # Dirty-install branch wires the checkbox into submit-disabled.
    assert "recwiz-restore-confirm" in body
    assert "confirmBox" in body
    # Submit posts to the restore endpoint.
    submit_idx = html.find("async function _recoveryRestoreSubmit(")
    assert submit_idx > 0
    submit_body = html[submit_idx:submit_idx + 2500]
    assert "api.recoveryRestorePhrase" in submit_body
    # After success, prompts restart.
    assert "Restart One Link" in submit_body or "recwiz-restart-card" in submit_body


# ── helpers ──────────────────────────────────────────────────────────


def _fake_state():
    """Minimal state-shape stand-in. Holds settings in a dict + lets
    list_peers return whatever the test sets."""
    settings: dict[str, str] = {}

    class _S:
        def __init__(self):
            self.settings = settings
            self._peers: list = []

        def get_setting(self, key):
            return self.settings.get(key)

        def set_setting(self, key, value):
            self.settings[key] = str(value)

        def delete_setting(self, key):
            self.settings.pop(key, None)

        def list_peers(self):
            return list(self._peers)

    return _S()


def _b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("ascii")
