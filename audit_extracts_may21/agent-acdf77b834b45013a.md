Good, now let me generate a final summary. Let me check one more thing - button handlers that are called but might fail silently:

**AUDIT COMPLETE**

Based on my comprehensive audit of the 28K-line HTML file and Python daemon routes, here are the **concrete dangling references** that represent shipped-but-not-wired surface area:

## Findings

**1. Unlistened Custom Event (line 28121)**
- **File:** `src/one_link/web/index.html`
- **Issue:** `ol-modal-closed` custom event is dispatched in the close-modal handler but no code listens for it.
- **Impact:** Any feature expecting modal-close notifications will silently miss them.

**2. API Endpoints — All Verified**
All 35+ unique API endpoints called from HTML (e.g., `/api/send`, `/api/update/install`, `/api/sovereignty/status`) have matching route handlers in `server.py`. No phantom endpoints found.

**3. onclick Handlers — All Verified**
All 50+ named event listeners referenced in `addEventListener()` calls (e.g., `openCreateGroupModal`, `renameCurrentGroup`, `copyGroupInviteLink`) are defined in the HTML script. No undefined function references.

**4. No TODO/FIXME/XXX Markers**
No incomplete surface area marked with TODO, FIXME, or XXX in HTML. Minor annotations in Python (`peer_rtc.py` line 221) are documentation-only.

**5. localStorage Flags — All Functional**
All localStorage setItem calls (pins, drafts, starred, voice-speed, etc.) are either:
- Read back within the same flow (functional)
- Set for client-side state persistence (not backend-dependent)
- UI-preference toggles that degrade gracefully if missing

**6. Missing Button IDs Without Impact**
IDs like `btn-files`, `btn-mesh`, `palette-close` have no direct handlers but are selected via `data-pane` attributes or queried dynamically. All are wired to delegated click handlers.

---

**Bottom line:** The surface is clean. The `ol-modal-closed` event is the only real gap, but it's a forward-compatibility hook with try/catch protection — it's not blocking any visible button.