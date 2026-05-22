**Bug**: `_fallback_quic_batch_to_webrtc` decryption side — the native session ratchet on receiver was already advanced by previous successful QUIC chunks. Now resending those exact same already-encrypted chunks over WebRTC means the receiver's decrypt will fail (ratchet position desync). Looking at decrypt_chunk above (line 468) — `_ratchet.next_key()` is called pre-decrypt. If `chunk_index` ordering reflects the per-frame index that the AEAD uses, then re-sending may still work IF the nonce comes from chunk_index. But the ratchet state mismatches.

Actually re-checking: decrypt_chunk uses `_fast_aead` with `nonce = record.chunk_index.to_bytes(12, "little")`. Re-sending the same chunks works because chunk_index is preserved. But `_ratchet.next_key()` advancement before each call MIGHT not be load-bearing if the `_fast_aead` path doesn't use the ratchet key. **However**, if the path is `_cipher.decrypt_chunk` (non-fast), the ratchet IS load-bearing. So the fallback may break depending on backend.

OK, I have enough. Let me also check `_quic_outbound` state coherence on connection mismatch errors.

Now write up the findings.

# Top 15 Findings

## 1. CRITICAL: FILE_OFFER over QUIC computes peer_fp from empty bytes
**file:line:** `daemon.py:21049` (`_handle_inbound_quic_frame` → `_on_peer_message(synth_channel, msg)`)
**What:** When a FILE_OFFER arrives over QUIC, the inbound dispatch routes it through `_on_peer_message(synth_channel, msg)`. `_on_peer_message` re-derives `peer_fp = fingerprint_of(channel.peer_ed_pub)` at line 4289, but `_NoopChannel.peer_ed_pub = b""`. So the FILE_OFFER is processed under the BLAKE3 fingerprint of empty bytes.
**Why:** Every cap check (`_capability_allowed(peer_fp, FILES)`) is against a non-existent peer → rejects every QUIC FILE_OFFER. Transfer-ids and IncomingFile buckets collide across all QUIC peers (they all share the same bogus fp).
**Fix sketch:** Set `_NoopChannel.peer_ed_pub = _real_channel.peer_ed_pub if _real_channel else b""` AND/OR pass `peer_fp` through a dispatch that doesn't re-derive (introduce `_on_peer_message(..., peer_fp_override=peer_fp)`).

## 2. CRITICAL: `_capability_allowed` fails OPEN on seed-tamper detect exception
**file:line:** `daemon.py:11370-11389`
**What:** The `detect_seed_file_tamper()` call is wrapped in `try/except Exception: pass`. If the tamper-detector itself raises (e.g. file-permission error, OSError on stat), we fall through to the normal cap-check path and the cap is allowed.
**Why:** A seed-swap attack could induce the FS error that masks the tamper detector. The whole purpose of the gate is fail-safe deny — current logic is fail-open.
**Fix sketch:** `except Exception as exc: log.warning("seed tamper check raised: %s", exc); return False` and record a `seed_tamper_check_failed` denial counter.

## 3. CRITICAL: send_file capability check is skipped when peer_fp_for_policy is None
**file:line:** `daemon.py:16857, 17802`
**What:** `if peer_fp_for_policy and not self._capability_allowed(peer_fp_for_policy, FILES): raise` — if `_peer_fp_from_peer(peer)` returns None/"" (e.g. peer.ed_pub_hex unset on a freshly-resolved relay-routed peer), the entire FILES check is bypassed and the send proceeds.
**Why:** The intent is "deny if explicitly disabled, allow if unknown" but the unknown case may be a half-resolved peer that the user actually revoked.
**Fix sketch:** `if not peer_fp_for_policy: raise RuntimeError("send_file refused: peer fingerprint unresolved")`. Mid-stream check at 17802 similarly should fail closed.

## 4. HIGH: Sender ignores legacy `NATIVE_TRANSFER_V1` cap when peer advertises only old name
**file:line:** `daemon.py:17966` (and 17108, 17121, 17699, 17710)
**What:** Sender treats native-transfer eligible ONLY when `NATIVE_TRANSFER_INDEXED_V1 in peer_feature_set`. The legacy `NATIVE_TRANSFER_V1` is imported and re-advertised locally (10337-10341) but the sender never honours an inbound `NATIVE_TRANSFER_V1`-only peer.
**Why:** Mixed-version mesh: a v0.20.4 peer advertising only the legacy cap silently degrades to FILE_BIN_CHUNK, losing native AEAD + ChunkRatchet, no degradation event fires.
**Fix sketch:** Compute `peer_native_ok = NATIVE_TRANSFER_INDEXED_V1 in s or NATIVE_TRANSFER_V1 in s`. Omit `chunk_index` field for legacy peers (receiver at 7800 already falls back to `seq`).

## 5. HIGH: NativeTransferSession.decrypt_chunk advances ratchet before AEAD verifies
**file:line:** `native_transfer.py:468`
**What:** `_ratchet.next_key()` is called UNCONDITIONALLY before the AEAD decrypt. A replayed, reordered, or tampered chunk advances the receiver's ratchet but the sender's stays put.
**Why:** Permanent desync. QUIC parallel-lane delivery is explicitly out-of-order; the WebRTC fallback path (`_fallback_quic_batch_to_webrtc`, 18129) re-sends already-shipped chunks → receiver's ratchet was already advanced for some, breaks the rest on the slow-cipher backend.
**Fix sketch:** Pass `chunk_index` to ratchet so it derives the absolute key for that index (idempotent), or move `next_key()` to AFTER successful decrypt.

## 6. HIGH: Outbox flush "already inflight" guard reads before the lock acquires
**file:line:** `daemon.py:16407` (in `_schedule_outbox_flush`)
**What:** Schedule checks `if peer_fp in self._outbox_flush_inflight: return`. But the set is populated INSIDE the lock at 16348 — only after the schedule fired. A burst of N session-up events on the same peer (e.g. multi-channel reconnect) creates N concurrent flush tasks; only one wins the lock at a time, others poll-and-skip via `lock.locked()`, but each one has already enqueued a coroutine + made the `state.get_peer` + `resolve_for_send` round-trip.
**Why:** Wasted DB hits + DNS resolutions per reconnect; on a flaky peer this stacks. Not a correctness bug but a thundering-herd amplifier on session churn.
**Fix sketch:** `_outbox_flush_inflight.add(peer_fp)` immediately in `_schedule_outbox_flush` before `create_task`, then schedule into a wrapper that handles discard in finally.

## 7. HIGH: FILE_OFFER_BATCH swallows per-offer errors without surfacing
**file:line:** `daemon.py:4587-4593`
**What:** Inner `await self._on_peer_message(channel, inner)` is wrapped in `except Exception as e: log.warning(...)`. The outer ACK reports `batch_processed=<successful count>` with no per-offer error detail. A receiver hitting `_abort_incoming_file` (raised RuntimeError) on one offer silently drops it.
**Why:** Sender has no way to know WHICH offers failed → resume protocol can't target the failed ones. Aligns with the "silent fallback" pattern you already wired degradation events for.
**Fix sketch:** Collect `failures: list[dict] = []` per offer (id, reason); emit them in the outer ACK as `failed_offers: [{id, reason}, ...]` AND push a `degradation_events` entry `kind=file_offer_batch_inner_failed`.

## 8. HIGH: `derive_native_transfer_secret` cache miss path still raises after ratchet activation if cache pre-derivation was skipped
**file:line:** `channel.py:220-226` 
**What:** The `_native_transfer_seed` is only populated by `maybe_activate_ratchet`. If `establish_native_transfer` is called BEFORE `maybe_activate_ratchet` (i.e. on a still-bootstrapping channel where one side hasn't received the other's CAPS yet, but the daemon eagerly calls `get_or_create_native_transfer_session()` on first chunk send), `_dr_shared` is still set → secret is derived AND cached at 220. But if CAPS arrives mid-derivation and `maybe_activate_ratchet` wipes `_dr_shared`, the next concurrent caller sees neither `_native_transfer_seed` NOR `_dr_shared` and raises.
**Why:** Race: CAPS-receive task vs first-chunk send_file task. Comment at 215-218 notes the intent but the race window is real.
**Fix sketch:** Hold a per-channel asyncio.Lock around `derive_native_transfer_secret` + the ratchet activation wipe. Or derive AND cache during `__post_init__`/handshake completion, not lazily.

## 9. HIGH: Empty `error` strings still possible on best-effort send paths
**file:line:** `daemon.py:16180, 16215` (`send_read_marker`, `send_typing`)
**What:** Returns `{"sent": m, "error": str(e)}` — if exception has empty `str()` (e.g. bare `OSError()`), the API consumer sees `{"error": ""}`. We fixed send_file's variant; these mirror the same anti-pattern.
**Why:** UI shows empty error toasts; analytics can't categorise; same class of bug as the one fixed at 18609.
**Fix sketch:** Use the same `err_repr = f"{type(e).__name__}: {e}"` helper everywhere — make it a module-level `_format_error(e)` utility.

## 10. HIGH: `_inbound_live_channels` mutation during `call_signal` send iteration
**file:line:** `daemon.py:2935-2951`
**What:** `live = list(self._inbound_live_channels.get(peer_fp, ()))` snapshots, but inside the loop a channel send can fail → `channel.close()` is NOT called by the iterator. The recv-loop's `finally` at 4283 mutates the underlying list while another task may be iterating a different code path (e.g. `_handle_inbound_quic_frame` at 21014 reads `_inbound_live_channels.get(peer_fp)` without snapshotting).
**Why:** Iteration vs disconnect-loop concurrent mutation. `list.remove` at 4284 races with `_live_inbound[-1]` at 21015 — could index a list mid-removal returning the just-removed channel.
**Fix sketch:** All readers should snapshot via `tuple(self._inbound_live_channels.get(peer_fp) or ())`. Make the list-of-channels container into a tuple-replacement pattern (immutable swap) to remove the iter-vs-mutate hazard.

## 11. MEDIUM: FILE_BIN_CHUNK / FILE_NATIVE_CHUNK seq mismatch RAISES vs FILE_CHUNK rejects
**file:line:** `daemon.py:7788, 7929, 5028-5033`
**What:** `_handle_file_native_chunk` and `_handle_file_binary_chunk` raise `RuntimeError("FILE_*_CHUNK sequence mismatch …")` on seq mismatch. The legacy `FILE_CHUNK` handler at 5028 returns ACK with `rejected="file_chunk_sequence_mismatch"`. The raise propagates up to the per-message dispatch's outer `except Exception as e: log.warning("peer loop error...")` at 4264 → channel CLOSED.
**Why:** A single reordered chunk on the native path kills the entire channel; on the legacy path the peer can recover. Inconsistent failure semantics + native path is more brittle than legacy.
**Fix sketch:** Native handlers should match FILE_CHUNK behaviour: ACK reject with reason, don't raise. The `_abort_incoming_file` already cleans the per-transfer state.

## 12. MEDIUM: Mid-stream cap re-check in CDC send swallowed by outer except blocks during QUIC dispatch
**file:line:** `daemon.py:17802-17808`
**What:** `raise RuntimeError("files capability revoked mid-transfer...")` runs inside the CDC chunk loop. The QUIC pre-dial and batch flush are inside a broader `try/except Exception` for the send path. The receiver's mid-stream cap re-check (7778) handles its own side; if the sender's raise is caught by an upstream wrap (e.g. the `_get_outbound_session` retry wrapper at 17008-17012), the user's revoke may be RETRIED rather than honoured.
**Why:** Cap revoke must be terminal, not retryable. The transient/retry classifier at `_is_transient_send_error` may include RuntimeError.
**Fix sketch:** Define a `CapabilityRevokedError(Exception)` distinct from transient errors; `_is_transient_send_error` returns False for it; ledger marks transfer as `failed-cap-revoked` not `paused`.

## 13. MEDIUM: `_finish_cdc_file`-style quarantine missing on FILE_CHUNK legacy path
**file:line:** `daemon.py:5080-5083`
**What:** On hash mismatch, legacy FILE_CHUNK handler does `with contextlib.suppress(OSError): f.out_path.unlink()`. No `.failed.<hex>` quarantine like the binary path at 7977-7990 OR the CDC finisher.
**Why:** Loss of forensic trail. M23 quarantine discipline was added to other paths but the legacy stream path was missed.
**Fix sketch:** Lift the quarantine block from `_handle_file_binary_chunk` into a shared `_quarantine_failed_inbox(path)` helper, call from all three EOF handlers.

## 14. MEDIUM: Capability-grant handler dual-imports + recursive call drops base64 length check on inner offers
**file:line:** `daemon.py:4424-4466`
**What:** `CAPABILITY_GRANT` enforces `len(grant_b64) > 12_000` rejection. But `_cap_store.accept(grant_blob, ...)` is wrapped in a single `try/except Exception as e` that ACKs with `rejected=f"grant_rejected: {e}"`. An exception from the deeper macaroon verifier with a stringified error containing user-supplied bytes (e.g. caveat strings) is reflected back verbatim to the peer.
**Why:** Information leak: the sender learns which caveat / verifier rule rejected the grant, useful for probing the local cap store's internal state.
**Fix sketch:** Map known verifier exception classes to coarse reasons (`grant_rejected: bad_signature`, `grant_rejected: caveat_invalid`); fall through to `grant_rejected: invalid` for the rest. Log the detailed `str(e)` server-side only.

## 15. MEDIUM: `_dispatch_living_presence` style provenance handler swallows broadcast errors
**file:line:** `daemon.py:5667-5675`
**What:** `_handle_file_provenance` wraps both `to_ui_dict` and `_broadcast_tail` in `except Exception: pass / return`. A bug in tail broadcast (e.g. a writer that's mid-removal) silently drops the provenance event for ALL subscribers, including operator dashboards.
**Why:** Provenance is supposed to be the auditable artifact; silent drop defeats the purpose. No `degradation_events` entry like the ones added for transfer fallbacks.
**Fix sketch:** Replace the swallow with `log.warning("provenance broadcast failed: %s", exc)` AND push a `degradation_events` entry `kind=provenance_broadcast_failed` — same pattern already in use for the transfer-side silent-fallbacks.

### Honourable mentions (not in top 15)
- `daemon.py:17343-17348` — `make_msg("FILE_OFFER", ...)` doesn't currently include `native_transfer_indexed_v1=True` hint; if peer expects an explicit hint to enable its receive-side native path, mismatch is invisible.
- `daemon.py:10343` — telemetry `try/except Exception: pass # pragma: no cover` hides ImportError vs AttributeError — `_NT_LEGACY` could be referenced before the import succeeds; mostly benign but obscures real diagnostics.
- `daemon.py:18611-18613` — when `last_error is None` BUT all peers failed (e.g. zero-peer-candidates branch), error message reads "no peer succeeded (no transient errors recorded)" which is technically truthful but UI-hostile.