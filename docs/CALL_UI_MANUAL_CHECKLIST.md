# Call UI manual checklist — May 15 2026

Quick visual / interaction checklist for the call-overlay revamp +
voice/video capability split. Use this when verifying after a UI
change that touches `web/index.html` between roughly line 6815 (peer
row buttons), the `.call-overlay-*` CSS rules, the
`#call-outgoing-overlay` markup, `startLivingPresenceCall(...)`, or
`showOutgoingOverlay(...)`.

## Pre-flight (terminal)

| | |
|---|---|
| Daemon healthy | `curl -H "Authorization: Bearer $(cat ~/AppData/Local/Coherence/One_link/ui.token)" http://127.0.0.1:7117/api/me` → 200 with `app_version` |
| Computer 2 listed | `/api/peers` returns exactly 1 peer (Computer 2) with `online: true` |
| Cap policy clean | `/api/peers/<fp>/capabilities` returns `allowed: null` (allow-all) |
| Cover-traffic quiet | `tail -20 dev-daemon.err.log` shows ≤ 1 `cover-traffic` WARNING per minute (was 60+/min before the M4-aware fix) |

## Sidebar — peer row

- [ ] Two distinct buttons appear next to **Computer 2**: a green phone (`call-btn-voice`) and a blue video camera (`call-btn-video`).
- [ ] Hovering the phone tints the button green; hovering the video tints it blue.
- [ ] Title attribute reads `Voice call Computer 2` and `Video call Computer 2` respectively.
- [ ] Clicking the gear icon opens the device drawer; clicking either call icon does NOT open the drawer (`ev.stopPropagation` works).

## Cap-revoke filter (sidebar)

1. Revoke voice_call: `curl -X POST -d '{"capability":"voice_call"}' /api/peers/<fp>/capabilities/revoke`
- [ ] Phone icon disappears from the sidebar after the next peer-list refresh (~5 s) or a manual page reload.
- [ ] Video icon STILL appears.
2. Revoke video_call: `curl -X POST -d '{"capability":"video_call"}' /api/peers/<fp>/capabilities/revoke`
- [ ] Both icons gone (only the gear remains).
3. Restore allow-all: `curl -X POST -d '{"allowed":null}' /api/peers/<fp>/capabilities`
- [ ] Both icons return on next refresh.

## Outgoing call overlay — Voice path

Click the green phone next to Computer 2:

- [ ] Overlay fades in, backdrop blurred.
- [ ] Avatar circle shows initials **C2** in a purple→blue gradient.
- [ ] Two pulse rings staggered 800 ms apart radiate outward.
- [ ] "Computer 2" name in 28px text.
- [ ] Kind badge below name: green border, reads **📞 Voice call**.
- [ ] Status line reads **Calling… 0:01**, ticking every second.
- [ ] Route line shows something like **Wi-Fi (LAN) · 12 ms** (or **connecting…** for the first ~2 s, then updates).
- [ ] Two pre-call control buttons visible: 🎙️ Mute, NO camera button (camera button is hidden for voice-only).
- [ ] No self-preview PIP tile in the top-right (video only).
- [ ] Pressing 🎙️ toggles it to a red-tinted pressed state; title attribute changes to "Microphone muted — peer will hear nothing on pickup".
- [ ] At 8 s elapsed: "Send a message instead" link fades in below End button.
- [ ] Clicking End: overlay closes immediately, no error toast.
- [ ] Clicking "Send a message instead": overlay closes, sidebar selects Computer 2, message composer focuses.

## Outgoing call overlay — Video path

Click the blue video icon next to Computer 2:

- [ ] Overlay opens; everything as above EXCEPT:
- [ ] Kind badge: blue border, reads **📹 Video call**.
- [ ] Self-preview PIP tile (160×120) in the top-right shows the local camera feed (or remains black if camera permission denied — that's expected).
- [ ] Pre-call controls include BOTH 🎙️ Mute and 📹 Cam-off.
- [ ] Pressing 📹 Cam-off: button toggles red-tinted; the self-preview tile's video tracks should stop (PIP goes black/static).

## Re-entrance / state cleanup

- [ ] End the call, then click Voice → overlay re-opens cleanly with fresh state (timer back to 0:00, pre-mute toggle reset, no leftover camera light).
- [ ] End the call, then click Video → camera indicator light should turn ON only after Video click, not before.
- [ ] Close the call AFTER pressing 🎙️ Mute → no zombie process keeping the mic engaged (check OS-level mic indicator).
- [ ] Switch from Voice call (ended) to Video call without page refresh → overlay correctly shows blue badge + PIP appears.

## Permissions panel (gear → device drawer)

- [ ] Permissions section has 5 cap pills in this order: **Chat · Files · Folders · Voice · Video**.
- [ ] Help text reads "Default for paired devices is allow all (chat, files, folders, voice calls, video calls). Toggle off if you want to grant capabilities individually below."
- [ ] Each pill independently togglable.
- [ ] Toggling Voice off and saving: sidebar's phone icon for that peer disappears on next refresh.

## Title bar

- [ ] Tab title reads exactly **One Link** (no `[vp 1707x996] [win ...] [chrome-px ...] [.top y=...]` debug text).
- [ ] Window favicon shows the One Link round glyph.

## Daemon log sanity

Tail `dev-daemon.err.log` while doing the above; expect to see:

- [ ] On call-start: `ROW-10` / `ratchet` / `frame_provenance` lines (existing call wiring).
- [ ] NO `RuntimeError: cover-traffic peel: expected deliver` — that's the regression I shipped + just fixed.
- [ ] NO `Traceback` blocks.
- [ ] Per-minute `WARNING` count ≤ 5 (cover-traffic + handshake-failure churn is OK at low rate; floods indicate a real bug).

## Two-machine smoke (cross-device)

After pairing a second machine (Computer 3, say):

- [ ] Both daemons see each other in `/api/peers` with `online: true` and matching SDP fingerprint.
- [ ] Voice call from A → B: B's incoming-ring overlay shows `Voice call` (NOT `Video call`).
- [ ] Accept on B → both sides land in the active-call surface; B's camera light stays OFF (voice-only).
- [ ] Video call from A → B: incoming-ring shows `Video call`; on accept, both sides have camera feed; recording badge stable.
- [ ] Mid-call mute toggle: works on both ends independently.

---

If any item above fails, capture (1) the exact step, (2) what you
saw vs expected, (3) the relevant daemon.err.log tail, and either
file an issue or hand the trace back to the dev loop. The Python
test suite (`tests/test_call_caps_voice_video_wiring.py`, 37 tests)
locks the underlying invariants; the items above are the things
those tests CAN'T see — pixels, animations, and OS-level effects.
