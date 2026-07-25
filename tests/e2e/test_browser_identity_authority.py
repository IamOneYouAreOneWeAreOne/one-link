"""Live fail-closed proofs for the browser peer's OPFS identity authority."""

from __future__ import annotations

import contextlib
import re
import time
from typing import Any

from playwright.sync_api import Browser, BrowserContext, Page


_IDENTITY_PASSPHRASE = "correct horse battery staple 2026"


def _daemon_https_origin(live_daemon: Any, timeout_s: float = 20.0) -> str:
    deadline = time.monotonic() + timeout_s
    pattern = re.compile(r"UI server HTTPS up.*?https://[^:]+:(\d+)/")
    last_log = ""
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            last_log = live_daemon.log.read_text(
                encoding="utf-8", errors="replace"
            )
            matches = pattern.findall(last_log)
            if matches:
                return f"https://127.0.0.1:{int(matches[-1])}"
        if live_daemon.proc.poll() is not None:
            raise RuntimeError(
                "daemon exited before HTTPS became ready\n" + last_log[-4000:]
            )
        time.sleep(0.05)
    raise RuntimeError(
        f"daemon HTTPS did not become ready within {timeout_s:.0f}s\n"
        + last_log[-4000:]
    )


def _context(browser: Browser) -> BrowserContext:
    return browser.new_context(ignore_https_errors=True)


def _open_ready_peer(page: Page, origin: str) -> None:
    response = page.goto(
        f"{origin}/peer", wait_until="domcontentloaded", timeout=30_000
    )
    assert response is not None and response.status == 200
    page.wait_for_function(
        """() => Boolean(
            window.__oneLinkPeer?.state?.rec?.private_key_jwk ||
            window.__oneLinkPeer?.state?.pending_rec?.private_key_jwk ||
            window.__oneLinkPeer?.state?.envelope ||
            window.__oneLinkPeer?.state?.boot_error_msg
        )""",
        timeout=20_000,
    )
    phase = page.evaluate(
        """() => ({
            ready: Boolean(window.__oneLinkPeer.state.rec),
            setup: Boolean(window.__oneLinkPeer.state.pending_rec),
            locked: Boolean(window.__oneLinkPeer.state.envelope),
            error: window.__oneLinkPeer.state.boot_error_msg || null,
        })"""
    )
    assert phase["error"] is None, phase["error"]
    if phase["setup"]:
        page.locator("#identity-setup-passphrase").fill(_IDENTITY_PASSPHRASE)
        page.locator("#identity-setup-confirm").fill(_IDENTITY_PASSPHRASE)
        page.locator("#btn-identity-setup").click()
    elif phase["locked"] and not phase["ready"]:
        page.locator("#unlock-passphrase").fill(_IDENTITY_PASSPHRASE)
        page.locator("#btn-unlock").click()
    page.wait_for_function(
        "() => Boolean(window.__oneLinkPeer?.state?.rec?.private_key_jwk)",
        timeout=150_000,
    )


def test_ed25519_wasm_fallback_generates_signs_and_verifies_live(
    browser: Browser,
    live_daemon: Any,
) -> None:
    """Force the unsupported-engine path and prove its full identity cycle."""

    origin = _daemon_https_origin(live_daemon)
    context = _context(browser)
    try:
        page = context.new_page()
        page.add_init_script(
            """(() => {
                const unsupported = () => Promise.reject(
                    new DOMException(
                        'The operation is not supported.', 'NotSupportedError'
                    )
                );
                for (const method of ['generateKey', 'importKey', 'sign', 'verify']) {
                    const original = SubtleCrypto.prototype[method];
                    SubtleCrypto.prototype[method] = function(algorithm, ...args) {
                        const name = typeof algorithm === 'string'
                            ? algorithm : algorithm && algorithm.name;
                        if (name === 'Ed25519') return unsupported();
                        return original.call(this, algorithm, ...args);
                    };
                }
            })();"""
        )
        _open_ready_peer(page, origin)
        proof = page.evaluate(
            """async () => {
                const api = window.__oneLinkPeer;
                const message = new TextEncoder().encode(
                    'one-link-live-ed25519-fallback-proof/v1'
                );
                const signature = await api._signEd25519(
                    api.state.rec.private_key_jwk, message
                );
                const publicKey = api.b64UrlToBytes(
                    api.state.rec.public_key_b64u
                );
                const valid = await api._verifyEd25519(
                    publicKey, signature, message
                );
                signature[0] ^= 1;
                const tampered = await api._verifyEd25519(
                    publicKey, signature, message
                );
                return {
                    valid,
                    tampered,
                    signatureLength: signature.length,
                    publicLength: publicKey.length,
                    wasmRequests: performance.getEntriesByType('resource')
                        .filter((entry) => new URL(entry.name).pathname ===
                            '/browser-crypto/ed25519-v1.wasm').length,
                };
            }"""
        )
        assert proof == {
            "valid": True,
            "tampered": False,
            "signatureLength": 64,
            "publicLength": 32,
            "wasmRequests": 1,
        }
    finally:
        context.close()


def test_corrupt_primary_never_regenerates_or_promotes_unrelated_stage(
    browser: Browser,
    live_daemon: Any,
) -> None:
    """A truncated authority plus a valid unrelated stage must stay blocked.

    This is the exact silent-identity-roll regression: the old implementation
    parsed failure as absence, generated a new key, and overwrote the evidence.
    """

    origin = _daemon_https_origin(live_daemon)
    context = _context(browser)
    try:
        page = context.new_page()
        _open_ready_peer(page, origin)
        original_fp = page.evaluate("() => window.__oneLinkPeer.state.rec.fingerprint")
        unrelated = page.evaluate(
            "() => window.__oneLinkPeer.generateIdentity()"
        )
        assert unrelated["fingerprint"] != original_fp

        page.evaluate(
            """async ({pending}) => {
                const api = window.__oneLinkPeer;
                await api._identityTestWriteRaw(
                    'pending', JSON.stringify(pending),
                );
                await api._identityTestWriteRaw('primary', '{"v":');
            }""",
            {"pending": unrelated},
        )

        page.add_init_script(
            """(() => {
                window.__olIdentityKeygenCalls = 0;
                const original = crypto.subtle.generateKey.bind(crypto.subtle);
                crypto.subtle.generateKey = (...args) => {
                    window.__olIdentityKeygenCalls += 1;
                    return original(...args);
                };
            })();"""
        )
        page.reload(wait_until="domcontentloaded", timeout=30_000)
        page.wait_for_function(
            """() => String(
                window.__oneLinkPeer?.state?.boot_error_msg || ''
            ).startsWith('identity storage blocked:')""",
            timeout=20_000,
        )

        state = page.evaluate(
            """() => ({
                rec: window.__oneLinkPeer.state.rec,
                envelope: window.__oneLinkPeer.state.envelope,
                keygenCalls: window.__olIdentityKeygenCalls,
                pill: document.querySelector('#ident-state')?.textContent,
                status: document.querySelector('#ident-status')?.textContent,
            })"""
        )
        assert state["rec"] is None
        assert state["envelope"] is None
        assert state["keygenCalls"] == 0
        assert state["pill"] == "identity blocked"
        assert "did not replace it or connect to peers" in state["status"]

        persisted = page.evaluate(
            """async () => {
                const api = window.__oneLinkPeer;
                const primary = await api._identityTestReadRaw('primary');
                const pending = JSON.parse(
                    await api._identityTestReadRaw('pending')
                );
                return {primary, pendingFingerprint: pending.fingerprint};
            }"""
        )
        assert persisted == {
            "primary": '{"v":',
            "pendingFingerprint": unrelated["fingerprint"],
        }
    finally:
        context.close()


def test_missing_primary_recovers_only_the_exact_valid_stage(
    browser: Browser,
    live_daemon: Any,
) -> None:
    """An interrupted first publish may recover when no authority exists."""

    origin = _daemon_https_origin(live_daemon)
    context = _context(browser)
    try:
        page = context.new_page()
        _open_ready_peer(page, origin)
        original = page.evaluate(
            """async () => ({
                rec: JSON.parse(JSON.stringify(window.__oneLinkPeer.state.rec)),
                envelope: JSON.parse(JSON.stringify(
                    await window.__oneLinkPeer.readIdentity()
                )),
            })"""
        )
        backend = page.evaluate(
            "() => window.__oneLinkPeer.identityStorageBackend()"
        )
        page.evaluate(
            """async (record) => {
                const api = window.__oneLinkPeer;
                await api._identityTestWriteRaw(
                    'pending', JSON.stringify(record),
                );
                await api._identityTestDeleteRaw('primary');
            }""",
            original["envelope"],
        )

        page.reload(wait_until="domcontentloaded", timeout=30_000)
        if backend == "indexeddb":
            page.wait_for_function(
                "() => Boolean(window.__oneLinkPeer?.state?.pending_rec)",
                timeout=20_000,
            )
            proof = page.evaluate(
                """async () => ({
                    freshFingerprint: window.__oneLinkPeer.state.pending_rec.fingerprint,
                    primary: await window.__oneLinkPeer._identityTestReadRaw('primary'),
                    staged: JSON.parse(
                        await window.__oneLinkPeer._identityTestReadRaw('pending')
                    ).fingerprint,
                })"""
            )
            assert proof["freshFingerprint"] != original["rec"]["fingerprint"]
            assert proof["primary"] is None
            assert proof["staged"] == original["rec"]["fingerprint"]
            return
        page.wait_for_function(
            "() => Boolean(window.__oneLinkPeer?.state?.envelope)",
            timeout=20_000,
        )
        page.locator("#unlock-passphrase").fill(_IDENTITY_PASSPHRASE)
        page.locator("#btn-unlock").click()
        page.wait_for_function(
            "() => Boolean(window.__oneLinkPeer?.state?.rec?.fingerprint)",
            timeout=150_000,
        )
        recovered = page.evaluate(
            """async () => {
                const api = window.__oneLinkPeer;
                const pendingExists =
                    await api._identityTestReadRaw('pending') !== null;
                return {
                    fingerprint: api.state.rec.fingerprint,
                    pendingExists,
                    primary: JSON.parse(
                        await api._identityTestReadRaw('primary')
                    ).fingerprint,
                };
            }"""
        )
        assert recovered == {
            "fingerprint": original["rec"]["fingerprint"],
            "pendingExists": False,
            "primary": original["rec"]["fingerprint"],
        }
    finally:
        context.close()


def test_argon_v2_envelope_is_ciphertext_only_and_aad_authenticated(
    browser: Browser,
    live_daemon: Any,
) -> None:
    origin = _daemon_https_origin(live_daemon)
    context = _context(browser)
    try:
        page = context.new_page()
        _open_ready_peer(page, origin)
        stored = page.evaluate(
            """async () => {
                const raw = await window.__oneLinkPeer._identityTestReadRaw(
                    'primary'
                );
                return {raw, envelope: JSON.parse(raw)};
            }"""
        )
        envelope = stored["envelope"]
        assert envelope["v"] == 2
        assert envelope["kdf"] == "argon2id-v19"
        assert envelope["kdf_memory_kib"] == 256 * 1024
        assert envelope["kdf_time_cost"] == 3
        assert envelope["kdf_parallelism"] == 1
        assert envelope["cipher"] == "aes-256-gcm"
        assert "private_key_jwk" not in stored["raw"]

        page.reload(wait_until="domcontentloaded", timeout=30_000)
        page.wait_for_selector("#unlock-passphrase", state="visible", timeout=20_000)
        page.locator("#unlock-passphrase").fill("definitely the wrong passphrase")
        page.locator("#btn-unlock").click()
        page.wait_for_function(
            "() => !document.querySelector('#unlock-status').hidden",
            timeout=150_000,
        )
        wrong = page.evaluate(
            """async () => {
                return {
                    raw: await window.__oneLinkPeer._identityTestReadRaw('primary'),
                    ready: Boolean(window.__oneLinkPeer.state.rec),
                };
            }"""
        )
        assert wrong == {"raw": stored["raw"], "ready": False}

        page.locator("#unlock-passphrase").fill(_IDENTITY_PASSPHRASE)
        page.locator("#btn-unlock").click()
        page.wait_for_function(
            "() => Boolean(window.__oneLinkPeer.state.rec)", timeout=150_000
        )

        tampered = dict(envelope)
        tampered["wrapped_ms"] += 1
        page.evaluate(
            """async (record) => {
                await window.__oneLinkPeer._identityTestWriteRaw(
                    'primary', JSON.stringify(record),
                );
            }""",
            tampered,
        )
        page.reload(wait_until="domcontentloaded", timeout=30_000)
        page.wait_for_selector("#unlock-passphrase", state="visible", timeout=20_000)
        page.locator("#unlock-passphrase").fill(_IDENTITY_PASSPHRASE)
        page.locator("#btn-unlock").click()
        page.wait_for_function(
            "() => !document.querySelector('#unlock-status').hidden",
            timeout=150_000,
        )
        assert page.evaluate("() => window.__oneLinkPeer.state.rec") is None
        assert "authenticated data" in page.locator("#unlock-status").inner_text()
    finally:
        context.close()


def test_hostile_argon_profile_is_rejected_before_worker_allocation(
    browser: Browser,
    live_daemon: Any,
) -> None:
    origin = _daemon_https_origin(live_daemon)
    context = _context(browser)
    try:
        page = context.new_page()
        _open_ready_peer(page, origin)
        hostile_raw = page.evaluate(
            """async () => {
                const api = window.__oneLinkPeer;
                const record = JSON.parse(
                    await api._identityTestReadRaw('primary')
                );
                record.kdf_memory_kib += 1;
                const raw = JSON.stringify(record);
                await api._identityTestWriteRaw('primary', raw);
                return raw;
            }"""
        )
        page.add_init_script(
            """(() => {
                window.__olWorkerCalls = 0;
                const RealWorker = window.Worker;
                window.Worker = class extends RealWorker {
                    constructor(...args) {
                        window.__olWorkerCalls += 1;
                        super(...args);
                    }
                };
            })();"""
        )
        page.reload(wait_until="domcontentloaded", timeout=30_000)
        page.wait_for_function(
            """() => String(
                window.__oneLinkPeer?.state?.boot_error_msg || ''
            ).startsWith('identity storage blocked:')""",
            timeout=20_000,
        )
        proof = page.evaluate(
            """async () => {
                return {
                    raw: await window.__oneLinkPeer._identityTestReadRaw('primary'),
                    workerCalls: window.__olWorkerCalls,
                    ready: Boolean(window.__oneLinkPeer.state.rec),
                };
            }"""
        )
        assert proof == {"raw": hostile_raw, "workerCalls": 0, "ready": False}
    finally:
        context.close()


def test_legacy_pbkdf_unlock_migrates_before_identity_becomes_ready(
    browser: Browser,
    live_daemon: Any,
) -> None:
    origin = _daemon_https_origin(live_daemon)
    context = _context(browser)
    legacy_passphrase = "short7!"
    try:
        page = context.new_page()
        _open_ready_peer(page, origin)
        original_fp = page.evaluate("() => window.__oneLinkPeer.state.rec.fingerprint")
        legacy_raw = page.evaluate(
            """async ({passphrase}) => {
                const api = window.__oneLinkPeer;
                const rec = JSON.parse(JSON.stringify(api.state.rec));
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const base = await crypto.subtle.importKey(
                    'raw', new TextEncoder().encode(passphrase),
                    {name: 'PBKDF2'}, false, ['deriveKey'],
                );
                const key = await crypto.subtle.deriveKey(
                    {name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000},
                    base, {name: 'AES-GCM', length: 256}, false, ['encrypt'],
                );
                const ct = await crypto.subtle.encrypt(
                    {name: 'AES-GCM', iv}, key,
                    new TextEncoder().encode(JSON.stringify(rec)),
                );
                const envelope = {
                    v: 1, wrapped: true, kdf: 'pbkdf2-sha256',
                    kdf_iterations: 600000,
                    kdf_salt_b64u: api.bytesToB64Url(salt),
                    iv_b64u: api.bytesToB64Url(iv),
                    ct_b64u: api.bytesToB64Url(new Uint8Array(ct)),
                    fingerprint: rec.fingerprint,
                    public_key_b64u: rec.public_key_b64u,
                    created_ms: rec.created_ms,
                    wrapped_ms: Date.now(),
                };
                const raw = JSON.stringify(envelope);
                await api._identityTestWriteRaw('primary', raw);
                return raw;
            }""",
            {"passphrase": legacy_passphrase},
        )

        page.reload(wait_until="domcontentloaded", timeout=30_000)
        page.wait_for_selector("#unlock-passphrase", state="visible", timeout=20_000)
        assert page.evaluate("() => window.__oneLinkPeer.state.envelope.v") == 1
        page.locator("#unlock-passphrase").fill(legacy_passphrase)
        page.locator("#btn-unlock").click()
        page.wait_for_function(
            "() => Boolean(window.__oneLinkPeer.state.rec)", timeout=150_000
        )
        migrated = page.evaluate(
            """async () => {
                const record = await window.__oneLinkPeer.readIdentity();
                const raw = await window.__oneLinkPeer._identityTestReadRaw(
                    'primary'
                );
                return {
                    record,
                    raw,
                    readyFp: window.__oneLinkPeer.state.rec.fingerprint,
                };
            }"""
        )
        assert migrated["record"]["v"] == 2
        assert migrated["record"]["kdf"] == "argon2id-v19"
        assert migrated["readyFp"] == original_fp
        assert "private_key_jwk" not in migrated["raw"]
        assert migrated["raw"] != legacy_raw
    finally:
        context.close()
