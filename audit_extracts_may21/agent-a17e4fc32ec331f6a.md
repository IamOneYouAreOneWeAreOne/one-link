I have plenty. Let me finalize the audit.

# Top 15 Audit Findings — `One_link/src/one_link/server.py`

1. **CRITICAL — server.py:1796 / `api_file_download` (12965)** — Path-traversal regex too loose. Route is `r"/api/files/{name:.+}"` which allows `/` in `{name}`. The handler defends with `safe = Path(name).name; safe != name → 400`, but on Windows `Path("..\\foo").name == "foo"` only after the OS strip, and a name like `foo/bar` will fail this check correctly **but** `foo%2Fbar` is URL-decoded by aiohttp before regex — confirmed to be rejected, however the same handler trusts `inbox_dir() / safe` without a final `.resolve().is_relative_to(inbox_dir())` check. **Fix:** add `if not path.resolve().is_relative_to(inbox_dir().resolve()): 400`.

2. **HIGH — server.py:6157 `api_setup_device_invite_confirm`** — Confirms enrollment + mints device cert with no SAS verification. Whoever holds the bearer-token invite + calls `/claim` then `/confirm` gets a self-mesh device cert. The SAS in `claim` is computed but never required to match before `confirm`. **Fix:** require `confirm` to include the SAS the operator read off the screen and compare to `pending["trust_code"]`.

3. **HIGH — server.py:8043+ `api_courier_export` family** — Multiple `{"ok": false, "error": "<code>", "message": str(exc)}` paths return `str(exc)`. `str(exc)` can be an absolute Windows path (Permission denied: 'C:\\Users\\Josh\\…'), leaking host filesystem layout to whoever has the token (likely fine inside the trust boundary, but breaks the public-surface promise). **Fix:** map exceptions through `_translate_send_error`-style translator that strips paths.

4. **HIGH — server.py:9684 `api_remove_folder`** — `name = request.match_info["name"]` passed straight to `folder_engine.remove_folder(name)`, then exception's `str(e)` returned in 500. No length cap, no validation that the folder name is one this daemon owns vs an arbitrary string. Same pattern in `api_share_folder`, `api_unshare_folder`, `api_set_folder_policy`. **Fix:** validate `name` via existing `get_folder()` check **before** calling the engine.

5. **HIGH — server.py:11196 `api_set_rendezvous`** — Accepts arbitrary `urls: list[str]` and live-applies. No scheme/host validation in this handler (delegated to `state.set_rendezvous_urls`, but a malicious browser-tab CSRF could swap rendezvous to attacker-controlled. POST has no Origin/Referer check anywhere in `_guarded`. **Fix:** add Origin-header allowlist (`http://127.0.0.1:<port>`) check in `_guarded` for state-mutating verbs.

6. **HIGH — server.py:1848 `_guarded`** — No CSRF defense. Cookie-based auth (`COOKIE_NAME`) + state-mutating POST/DELETE → if a victim opens a malicious page on `localhost:other_port` (or any same-site dev server), it can issue cross-origin POSTs with `credentials: 'include'` and ride the cookie. **Fix:** require either `Authorization: Bearer` OR a custom `X-One-Link-CSRF` header that mirrors the cookie value, on all non-GET routes.

7. **HIGH — server.py:12586 `api_send_file` exception sink** — `log.exception("send_file failed: %s", e)` + `_translate_send_error(e)` — confirmed the empty-string-exception path lands here; if `_translate_send_error` returns the default with `e=""`, response body's `"error": ""`. The fix this session put in `_translate_send_error` should be cross-checked at line 12603 to ensure `translated["error"]` is never empty (fallback `e.__class__.__name__`).

8. **MEDIUM — server.py:11021 `api_global_search`** — No rate limiting on FTS5 + inbox-scan + peer-table-scan. `q=*` or pathological FTS5 query can pin the daemon. Same for `api_search` (12250). **Fix:** add `_rate_limited("search", ...)` with a tight bucket (e.g., 10/sec/client).

9. **MEDIUM — server.py:13132 `api_file_reveal`** — `path = (inbox_dir() / safe).resolve()` then `subprocess.Popen(["explorer.exe", f"/select,{path}"])`. The resolve happens *after* the `safe != name` check, so symlinks inside inbox would point outside. Also no check that `path.is_relative_to(inbox_dir().resolve())` after the resolve. **Fix:** add that check between resolve and Popen.

10. **MEDIUM — server.py:8085, 6085** — `qr_url` and `/api/setup/device-invite/qr.svg?token=...` carry the invite token in the query string. The QR endpoint is `_guarded` so the UI token is also implicitly required to fetch — fine — but the *invite token* travels in URL → server access log (`aiohttp.access` logger) → disk. **Fix:** suppress query string in access-log format string for `/api/setup/device-invite/qr.svg`, or move token to header.

11. **MEDIUM — server.py:9819 `api_folder_tree`** — No cap on `entries_raw` count. `list_manifest(name)` of a million-entry folder + filter + serialize → JSON in one allocation. Daemon OOM. **Fix:** add a hard `limit` query param defaulting to e.g. 10_000, and bail/paginate beyond that.

12. **MEDIUM — server.py:11459 `api_edit_message` / 11499 `api_delete_message`** — No authorization that the caller "is" the sender beyond `rec.direction == "out"`. Since the daemon's UI is single-user this is fine, but anyone with the token can rewrite history for any conversation. Add note in audit log. **Fix:** record actor + IP in `state.update_message` audit row.

13. **MEDIUM — server.py:7567 `api_self_mesh_remote_instruct`** — `scope = body.get("scope") or {}` — no schema validation on `scope` dict (path/action/etc). A buggy/malicious browser-tab can craft a remote-instruction with surprising scope and sign it with this device's cert. **Fix:** validate `scope` keys against an allowlist + cap string lengths.

14. **MEDIUM — server.py:1992 `_index`** — `bootstrap_ok = request.query.get("t") == self.token` uses `==` not `hmac.compare_digest`. Inconsistent with `_check_token` at 1814. Timing oracle on the bootstrap path. **Fix:** `hmac.compare_digest(request.query.get("t",""), self.token)`.

15. **LOW — server.py:10286 `api_set_presence`, 11541 `api_set_typing`, 11566 `api_set_read_marker`** — All broadcast via `self.broadcast({...})` *after* state mutation with no lock. The WS-broadcast loop iterates `self.ws_clients`; if a concurrent request adds/removes a client mid-iteration, `set changed size during iteration` is possible. **Fix:** snapshot `list(self.ws_clients)` inside `broadcast()` before the for-loop.

**Cross-cutting:** every `api_*` route I sampled IS behind `_guarded` — no missing-auth bypass found in the route table. The two unguarded routes (`api_peer_rtc_ice_config_public`, `api_public_self_mesh_enrollment_invite_preview`) are intentional + documented and return only STUN/preview info. The real systemic gaps are #1 (no resolve-traversal check), #6 (no CSRF), #3/#4 (raw `str(exc)` leakage), and #14 (timing-unsafe bootstrap compare).