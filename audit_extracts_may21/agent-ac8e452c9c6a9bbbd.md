Perfect. Now let me compile the security audit.

## Service Worker Security Audit — One Link

**Scope:** `sw.js:1-219` | Registration: `index.html:17361` | Manifest: `manifest.json`

### CRITICAL FINDINGS

**1. Unconditional `skipWaiting()` + `clients.claim()` (sw.js:37, 50)**
- `skipWaiting()` on install forces the new SW to take over immediately, replacing the old worker without user consent.
- Combined with `clients.claim()` on activate, this means a fresh SW deploy instantly controls all tabs.
- **Risk:** A compromised SW update can hijack live sessions in-place. No intermediate state where the old SW continues serving.
- **Status:** CRITICAL — but mitigated by the fact that the daemon (127.0.0.1) is local and source is trusted in dev. In production OTA, this is a high-velocity vector.

**2. Missing pinned-signature verification (no evidence in codebase)**
- The audit doc notes "Service Worker pinned-pubkey signature verification (queued)" — the SW source code contains NO signature checks, no pinned key storage, no verification before cache or execution.
- On `/` fetch (network-first, sw.js:66–79), the SW caches `res.status === 200` with zero integrity validation.
- On static assets (sw.js:84–98), the same: any 200 response is cached, no Content-Type or signature check.
- **Risk:** If the daemon serves a poisoned index.html (MITM, daemon compromise, or malicious JS injection), the SW caches and serves it indefinitely until manual user cache clear.
- **Status:** CRITICAL — design gap. Not exploitable locally (127.0.0.1 is LAN-only), but the signature feature **must** ship before any wider deployment.

### HIGH-RISK FINDINGS

**3. postMessage handler without source/origin verification (sw.js:172–194)**
- Two commands accepted: `type === "drain-now"` and `type === "incoming-call-notification"`.
- No check of `event.source.url` or `event.source.frameType`.
- **Risk:** Any page loaded in scope `/` (including adversarial cross-origin frames if framed by the app, or injected XSS) can trigger `drainOutbox()` or spawn notifications with arbitrary title/body/peer data.
- `incoming-call-notification` accepts unsanitized `event.data.title`, `body`, `call_id`, `peer` → passed directly to `showNotification()`. Notification data is echoed back to the page on click (sw.js:210–215).
- **Impact:** Notification spam, phishing notifications ("You have a call from Bank of America—tap to verify"), or exfiltration of queued outbox items via repeated drain commands.
- **Status:** HIGH — no origin guard. Partially mitigated by same-origin-only scope registration, but XSS in the main app can abuse it.

**4. Stale-while-revalidate on static assets — indefinite cache fallback (sw.js:88–97)**
- Cache-first for `/manifest.json` and `/static/*`: if the network fetch fails (`.catch(() => cached)`), the SW returns the cached copy **indefinitely**.
- If a cached manifest or icon is poisoned (or becomes outdated), the browser will never see the updated version unless the cache is manually purged.
- **Risk:** Outdated manifest can prevent app reinstall or hide security-relevant changes. Poisoned icon or manifest can mislead the user about the app's state or origin.
- **Status:** HIGH — no cache expiry, no stale-while-revalidate timeout. In practice, acceptable for icons but suboptimal for `manifest.json` (which declares scope and start_url).

**5. Origin not checked in fetch handler (sw.js:53–99)**
- The fetch handler dispatches on `url.pathname` alone—no check of `event.request.headers.get("origin")` or `event.clientId`.
- **Risk:** Low in practice (scope is `/`, same-origin only), but if a subpath (e.g., `/admin/`) is controlled by an attacker or a user-uploaded file, the SW can be tricked into caching and serving it.
- **Status:** MEDIUM — architectural simplification, not exploitable under current scope declaration.

### ADVISORY FINDINGS

**6. No Content-Type validation before cache (sw.js:72, 91–93)**
- `c.put(event.request, copy)` accepts any Content-Type (or missing header) if `res.status === 200`.
- If a `.js` asset is served as `text/plain` or an HTML file as `image/png`, the cache will preserve the wrong type.
- **Status:** POLISH — browsers re-detect MIME type on serve, so low risk, but explicit `res.headers.get("content-type")` check would harden.

**7. IDB queue survives tab close; no expiry on queued items (sw.js:112–161)**
- Outbox items (failed sends) are persisted in IDB with no TTL. A message queued while offline can sit in the queue indefinitely if the browser never syncs or the device never comes online.
- **Risk:** User sends a private message, browser crashes, device offline for months, then syncs—old message sends silently without user re-consent.
- **Status:** ADVISORY — acceptable for UX (resilience), but worth documenting or adding a per-item TTL.

**8. `notificationclick` handler calls `clients.openWindow("/")` unconditionally (sw.js:206)**
- If the app is already open, this may navigate an existing tab. If not, it opens a new tab.
- No check for `data.call_id` validity before opening. A crafted notification (via the postMessage XSS vector) can spam new tabs.
- **Status:** ADVISORY — mitigated by the postMessage XSS risk above; fix #3 first.

### REGISTRATION & LIFECYCLE (index.html)

- **Scope:** `/` (global, same-origin only) — appropriate for a PWA.
- **Update check:** Implicit browser behavior; no `reg.onupdatefound()` handler visible in audit excerpt. The app relies on the browser's default update schedule.
- **No ready handler:** The code does not wait for `reg.ready` or `reg.waiting` before using the outbox. Degradation is graceful (if SW unavailable, sends behave as v0.13).

---

### SUMMARY & NEXT STEPS

**Currently safe** for local 127.0.0.1 deployment *only*. The daemon is trusted and not network-accessible, so cache poisoning and malicious updates are not threats.

**Before production/wider access:**
1. **Implement pinned-signature verification** — verify SW and shell HTML against a hard-coded public key hash before caching or serving.
2. **Add origin/source checks to postMessage handlers** — validate `event.source.url` matches expected scope origin.
3. **Add per-item TTL to outbox queue** — discard sends older than (e.g.) 7 days.
4. **Optional: add `updateViaCache: "none"` or implement custom update-check** to avoid serving stale SW code during deploy.