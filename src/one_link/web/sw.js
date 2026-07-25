// v0.14.1 — One Link Service Worker.
//
// Two jobs only:
// 1. Background sync: when the browser fires a `sync` event tagged
//    "ol-outbox", we POST each queued outbox item to /api/send.
//    Items survive tab close and the device coming back online,
//    which is the asyncronous-by-default promise from PRINCIPLES.md.
// 2. Cache-first served-from-disk for the index.html shell so the
//    UI paints before /api/me resolves. Network-first for everything
//    /api/* — we never serve stale data for live state.
//
// We deliberately do NOT do push notifications here (no remote
// server to subscribe to) and we do NOT cache encrypted payloads.

// Loopback-origin hardening — bump to v4 so clients evict v3 entries that may
// have used a bootstrap ``/?t=...`` URL as a CacheStorage request key.
// May 16 2026 — v3 originally ensured existing clients evicted the
// stale shell on first load after this update. The bigger fix is
// removing "/" from SHELL_FILES + serving the index NETWORK-FIRST
// in the fetch handler below. Cache-first for the SPA shell was
// causing users to keep seeing the OLD UI on every reload until
// they hit Ctrl+Shift+R. The daemon runs locally on 127.0.0.1 so
// "offline" is never a real state for the index page; cache-first
// has zero benefit and one large cost (stale UI).
const CACHE_NAME = "one-link-shell-v4";
const SHELL_FILES = [
  // Static-only entries here. The index itself is intentionally
  // omitted so it always comes from the live daemon — see fetch
  // handler below.
  "/manifest.json",
  "/static/one-glyph.png",
  "/static/one-glyph-app.png",
];

// Owner API auth is origin-scoped, never cookie-scoped, on plaintext
// loopback. Cookies do not include a port in their security boundary and would
// leak to an unrelated local web server. The page sends a revocable session
// bearer after bootstrap; persistent mode stores that bearer in this origin's
// IndexedDB so background sync can still authenticate after the page closes.
const AUTH_DB_NAME = "one-link-owner-auth-v1";
const AUTH_STORE = "authority";
const AUTH_RECORD = "owner-session";
let ownerBearer = "";
let ownerBearerGeneration = 0;

function validOwnerBearer(value) {
  return typeof value === "string"
    && value.length >= 32
    && value.length <= 256
    && /^[A-Za-z0-9_-]+$/.test(value);
}

function openAuthDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(AUTH_DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(AUTH_STORE)) {
        db.createObjectStore(AUTH_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function readPersistedOwnerBearer() {
  try {
    const db = await openAuthDB();
    const tx = db.transaction(AUTH_STORE, "readonly");
    const req = tx.objectStore(AUTH_STORE).get(AUTH_RECORD);
    const value = await new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return validOwnerBearer(value) ? value : "";
  } catch {
    return "";
  }
}

async function persistOwnerBearer(value) {
  try {
    const db = await openAuthDB();
    const tx = db.transaction(AUTH_STORE, "readwrite");
    const store = tx.objectStore(AUTH_STORE);
    if (validOwnerBearer(value)) store.put(value, AUTH_RECORD);
    else store.delete(AUTH_RECORD);
    await new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  } catch {
    // The page's in-memory bearer still works when IDB is unavailable.
  }
}

const ownerBearerLoaded = readPersistedOwnerBearer().then((value) => {
  if (value && ownerBearerGeneration === 0) ownerBearer = value;
});

async function authenticatedApiFetch(request) {
  await ownerBearerLoaded;
  const headers = new Headers(request.headers);
  if (ownerBearer && !headers.has("authorization")) {
    headers.set("Authorization", `Bearer ${ownerBearer}`);
  }
  const credentials = self.location.protocol === "http:"
    ? "omit"
    : request.credentials;
  return fetch(new Request(request, { headers, credentials }));
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((c) => c.addAll(SHELL_FILES)).catch(() => null),
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k.startsWith("one-link-shell-") && k !== CACHE_NAME)
          .map((k) => caches.delete(k)),
      ),
    ),
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // Network-first for the live API. The user's data must always be
  // fresh; never serve stale messages or peers.
  if (
    url.origin === self.location.origin
    && url.pathname.startsWith("/api/")
  ) {
    event.respondWith(authenticatedApiFetch(event.request));
    return;
  }
  // May 16 2026 — Network-FIRST for the index page itself. The
  // daemon runs locally; the user is never offline with respect to
  // it. Serving cached HTML caused the "I only see new UI after
  // Ctrl+Shift+R" bug. Try network, fall back to cache only when
  // the network actually fails (which on 127.0.0.1 essentially
  // means daemon is down).
  if (url.pathname === "/") {
    const carriesBootstrapToken = url.searchParams.has("t");
    // A valid persistent session may need to recover an old bootstrap URL.
    // Attach its explicit bearer without ever copying it into the URL. Never
    // put a request URL containing ``?t=`` into CacheStorage: cache request
    // keys are persistent, script-readable browser storage.
    const networkRequest = carriesBootstrapToken
      ? authenticatedApiFetch(event.request)
      : fetch(event.request);
    event.respondWith(
      networkRequest.then((res) => {
        // Refresh the cache copy so a future genuinely-offline
        // load (rare; only when daemon is down) still has SOMETHING
        // to render.
        if (res && res.status === 200 && !carriesBootstrapToken) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(event.request, copy));
        }
        return res;
      }).catch(() => caches.match("/")),
    );
    return;
  }
  // Stale-while-revalidate for the small static assets (manifest,
  // icons). Serve from cache instantly for snappy first paint, but
  // ALWAYS kick off a background network refresh so a poisoned or
  // simply outdated cache entry self-heals on the next load.
  //
  // Previously this branch was pure cache-first with a network
  // fallback, which meant a bad cache entry would persist
  // indefinitely until the user manually cleared site data.
  if (
    url.pathname === "/manifest.json" ||
    url.pathname.startsWith("/static/")
  ) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        const networkFetch = fetch(event.request).then((res) => {
          if (res && res.status === 200) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(event.request, copy));
          }
          return res;
        }).catch(() => null);
        return cached || networkFetch;
      }),
    );
  }
});

// Cap user-supplied notification strings so a postMessage caller
// can't ship a 1 MB title or hide a payload inside control chars.
function _sanitizeNotifText(s, maxLen) {
  if (typeof s !== "string") return "";
  // Strip C0 + DEL controls, normalize CR/LF/TAB to a single space.
  const cleaned = s.replace(/[\x00-\x1F\x7F]+/g, " ").trim();
  return cleaned.length > maxLen ? cleaned.slice(0, maxLen) : cleaned;
}

// ── Background sync (outbox) ──────────────────────────────────────
//
// When the user composes a message while offline OR the tab gets
// suspended mid-send, we save the payload into IndexedDB and
// register `sync.register("ol-outbox")`. The browser fires the sync
// event when connectivity comes back; we drain the IDB queue.
//
// IDB is used instead of localStorage because:
//   1. localStorage isn't available in service worker scope
//   2. IDB has a richer API for queue semantics
//   3. We can store binary payloads if we ever queue files
const IDB_NAME = "one-link-outbox-v1";
const IDB_STORE = "queue";
const IDB_META_STORE = "meta";
const IDB_QUARANTINE_STORE = "quarantine";
const IDB_VERSION = 3;
const OUTBOX_LEASE_KEY = "drain-lease";
const OUTBOX_LEASE_TTL_MS = 45 * 1000;
const OUTBOX_FETCH_TIMEOUT_MS = 25 * 1000;
const OUTBOX_MAX_ROWS = 2000;
const OUTBOX_MAX_BODY_BYTES = 128 * 1024;
const OUTBOX_MAX_BATCHES_PER_DRAIN = 4;
const OUTBOX_QUARANTINE_MAX_ROWS = 256;
const outboxLeaseOwner = (self.crypto && self.crypto.randomUUID)
  ? self.crypto.randomUUID()
  : `${Date.now()}-${Math.random()}`;
let outboxDrainTail = Promise.resolve();

function idbRequest(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("IndexedDB request failed"));
  });
}

function idbTransactionDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error || new Error("IndexedDB transaction aborted"));
    tx.onerror = () => reject(tx.error || new Error("IndexedDB transaction failed"));
  });
}

function openOutboxDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = req.result;
      let queue;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        queue = db.createObjectStore(
          IDB_STORE, { keyPath: "id", autoIncrement: true },
        );
        queue.createIndex("dedupe_key", "dedupe_key", { unique: true });
      } else {
        queue = req.transaction.objectStore(IDB_STORE);
        if (!queue.indexNames.contains("dedupe_key")) {
          queue.createIndex("dedupe_key", "dedupe_key", { unique: true });
        }
      }
      if (!db.objectStoreNames.contains(IDB_META_STORE)) {
        db.createObjectStore(IDB_META_STORE, { keyPath: "key" });
      }
      if (!db.objectStoreNames.contains(IDB_QUARANTINE_STORE)) {
        db.createObjectStore(
          IDB_QUARANTINE_STORE,
          { keyPath: "quarantine_id", autoIncrement: true },
        );
      }
      if (event.oldVersion < 2) {
        const seen = new Map();
        const cursorReq = queue.openCursor();
        cursorReq.onsuccess = () => {
          const cursor = cursorReq.result;
          if (!cursor) return;
          const item = cursor.value || {};
          let clientId = "";
          try {
            const parsed = JSON.parse(item.body || "null");
            clientId = parsed && typeof parsed.client_msg_id === "string"
              ? parsed.client_msg_id : "";
          } catch {}
          let dedupeKey = /^[A-Za-z0-9_-]{8,128}$/.test(clientId)
            ? `send:${clientId.toLowerCase()}`
            : `legacy:${String(cursor.primaryKey)}`;
          const prior = seen.get(dedupeKey);
          if (prior && prior.url === item.url && prior.method === item.method
              && prior.body === item.body) {
            cursor.delete();
          } else {
            if (prior) dedupeKey = `legacy-conflict:${String(cursor.primaryKey)}`;
            seen.set(dedupeKey, item);
            cursor.update({ ...item, method: item.method || "POST", dedupe_key: dedupeKey });
          }
          cursor.continue();
        };
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function _acquireOutboxLease(db) {
  const tx = db.transaction(IDB_META_STORE, "readwrite");
  const store = tx.objectStore(IDB_META_STORE);
  const now = Date.now();
  const current = await idbRequest(store.get(OUTBOX_LEASE_KEY));
  if (current && current.owner !== outboxLeaseOwner && current.expires_ms > now) {
    await idbTransactionDone(tx);
    return false;
  }
  store.put({
    key: OUTBOX_LEASE_KEY,
    owner: outboxLeaseOwner,
    expires_ms: now + OUTBOX_LEASE_TTL_MS,
  });
  await idbTransactionDone(tx);
  return true;
}

async function _renewOutboxLease(db) {
  const tx = db.transaction(IDB_META_STORE, "readwrite");
  const store = tx.objectStore(IDB_META_STORE);
  const current = await idbRequest(store.get(OUTBOX_LEASE_KEY));
  if (!current || current.owner !== outboxLeaseOwner) {
    tx.abort();
    try { await idbTransactionDone(tx); } catch {}
    return false;
  }
  store.put({
    key: OUTBOX_LEASE_KEY,
    owner: outboxLeaseOwner,
    expires_ms: Date.now() + OUTBOX_LEASE_TTL_MS,
  });
  await idbTransactionDone(tx);
  return true;
}

async function _releaseOutboxLease(db) {
  const tx = db.transaction(IDB_META_STORE, "readwrite");
  const store = tx.objectStore(IDB_META_STORE);
  const current = await idbRequest(store.get(OUTBOX_LEASE_KEY));
  if (current && current.owner === outboxLeaseOwner) store.delete(OUTBOX_LEASE_KEY);
  await idbTransactionDone(tx);
}

function _sameQueuedDispatch(a, b) {
  return Boolean(a && b)
    && a.id === b.id
    && a.dedupe_key === b.dedupe_key
    && a.url === b.url
    && (a.method || "POST") === (b.method || "POST")
    && a.body === b.body;
}

function _validQueuedSend(item) {
  if (!item || item.url !== "/api/send" || item.method !== "POST"
      || typeof item.body !== "string"
      || item.body.length > OUTBOX_MAX_BODY_BYTES
      || new TextEncoder().encode(item.body).byteLength > OUTBOX_MAX_BODY_BYTES
      || typeof item.dedupe_key !== "string") return false;
  try {
    const payload = JSON.parse(item.body);
    const clientId = payload && typeof payload.client_msg_id === "string"
      ? payload.client_msg_id : "";
    const allowed = new Set([
      "peer", "body", "queue_on_failure", "reply_to", "client_msg_id",
    ]);
    return payload && !Array.isArray(payload)
      && !Object.keys(payload).some((key) => !allowed.has(key))
      && /^[A-Za-z0-9_-]{8,128}$/.test(clientId)
      && item.dedupe_key === `send:${clientId.toLowerCase()}`
      && typeof payload.peer === "string" && payload.peer.length > 0
      && payload.peer.length <= 256
      && typeof payload.body === "string" && payload.body.trim().length > 0
      && new TextEncoder().encode(payload.body).byteLength <= 64 * 1024
      && (payload.queue_on_failure === undefined
        || typeof payload.queue_on_failure === "boolean")
      && (payload.reply_to === undefined || payload.reply_to === null
        || (typeof payload.reply_to === "string"
          && /^[A-Za-z0-9_-]{8,128}$/.test(payload.reply_to)));
  } catch {
    return false;
  }
}

function _outboxQuarantineSummary(item, reason) {
  const clipped = (value, max) => typeof value === "string"
    ? value.slice(0, max) : `[${typeof value}]`;
  return {
    quarantined_ms: Date.now(),
    reason: clipped(reason || "invalid queued send", 160),
    source_id: Number.isSafeInteger(item && item.id) ? item.id : null,
    dedupe_key: clipped(item && item.dedupe_key, 160),
    url: clipped(item && item.url, 256),
    method: clipped(item && item.method, 16),
    // Never copy a poisoned body into the quarantine store. Keeping only its
    // bounded shape is enough to diagnose the rejected legacy/schema family
    // without letting an attacker double storage consumption.
    body_code_units: typeof (item && item.body) === "string"
      ? Math.min(item.body.length, Number.MAX_SAFE_INTEGER) : null,
  };
}

async function _quarantineInvalidOutboxItems(db, snapshotItems, reason) {
  if (!snapshotItems.length) return 0;
  // One queue transaction for the entire poison family keeps the 2,000-row
  // adversarial bound cheap. Every deletion is still exact-read-before-delete.
  const tx = db.transaction(IDB_STORE, "readwrite");
  const done = idbTransactionDone(tx);
  const store = tx.objectStore(IDB_STORE);
  const currentRows = await Promise.all(snapshotItems.map((item) =>
    idbRequest(store.get(item && item.id))
  ));
  const removed = [];
  for (let index = 0; index < snapshotItems.length; index += 1) {
    if (_sameQueuedDispatch(currentRows[index], snapshotItems[index])) {
      store.delete(snapshotItems[index].id);
      removed.push(snapshotItems[index]);
    }
  }
  await done;
  if (!removed.length) return 0;

  // Diagnostics are a bounded rolling window. Replacing the store in one
  // transaction avoids thousands of per-row commits and never copies bodies.
  try {
    const qtx = db.transaction(IDB_QUARANTINE_STORE, "readwrite");
    const qdone = idbTransactionDone(qtx);
    const quarantine = qtx.objectStore(IDB_QUARANTINE_STORE);
    const existing = await idbRequest(
      quarantine.getAll(null, OUTBOX_QUARANTINE_MAX_ROWS),
    );
    const summaries = (existing || []).concat(removed.map((item) =>
      _outboxQuarantineSummary(item, reason)
    )).slice(-OUTBOX_QUARANTINE_MAX_ROWS);
    quarantine.clear();
    for (const summary of summaries) {
      const copy = { ...summary };
      delete copy.quarantine_id;
      quarantine.add(copy);
    }
    await qdone;
  } catch {
    // Executable poison rows are already gone; diagnostics cannot roll back
    // the safety boundary when storage is exhausted.
  }
  return removed.length;
}

async function _deleteDeliveredOutboxItem(db, dispatched) {
  const tx = db.transaction(IDB_STORE, "readwrite");
  const store = tx.objectStore(IDB_STORE);
  const current = await idbRequest(store.get(dispatched.id));
  if (!_sameQueuedDispatch(current, dispatched)) {
    tx.abort();
    try { await idbTransactionDone(tx); } catch {}
    throw new Error("outbox row changed while delivery was in flight");
  }
  store.delete(dispatched.id);
  await idbTransactionDone(tx);
}

async function _drainOutboxOnce() {
  await ownerBearerLoaded;
  let db;
  try {
    db = await openOutboxDB();
  } catch {
    return; // IDB unavailable; nothing to drain
  }
  try {
    if (!await _acquireOutboxLease(db)) return;
    let lastBatchWasFull = false;
    for (let batch = 0; batch < OUTBOX_MAX_BATCHES_PER_DRAIN; batch += 1) {
      const snapshotTx = db.transaction(IDB_STORE, "readonly");
      const items = await idbRequest(
        snapshotTx.objectStore(IDB_STORE).getAll(null, OUTBOX_MAX_ROWS),
      );
      await idbTransactionDone(snapshotTx);
      lastBatchWasFull = (items || []).length >= OUTBOX_MAX_ROWS;
      const invalidItems = [];
      const validItems = [];
      for (const item of items || []) {
        if (_validQueuedSend(item)) validItems.push(item);
        else invalidItems.push(item);
      }
      if (invalidItems.length) {
        if (!await _renewOutboxLease(db)) return;
        await _quarantineInvalidOutboxItems(
          db, invalidItems, "invalid or unsupported queued-send schema",
        );
      }
      for (const item of validItems) {
        if (!await _renewOutboxLease(db)) return;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), OUTBOX_FETCH_TIMEOUT_MS);
        try {
          // No IndexedDB transaction is alive across this network await.
          const resp = await fetch(item.url, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              ...(ownerBearer ? { Authorization: `Bearer ${ownerBearer}` } : {}),
            },
            body: item.body,
            credentials: self.location.protocol === "http:" ? "omit" : "include",
            signal: controller.signal,
          });
          if (!resp.ok) return;
          let acknowledgement;
          try {
            acknowledgement = await resp.json();
          } catch {
            return;
          }
          if (!acknowledgement || acknowledgement.ok !== true) return;
          await _deleteDeliveredOutboxItem(db, item);
        } catch {
          return; // network still down; retain exact row for a later sync
        } finally {
          clearTimeout(timer);
        }
      }
      if (!lastBatchWasFull) break;
    }
    if (lastBatchWasFull
        && "sync" in self.registration) {
      try { await self.registration.sync.register("ol-outbox"); } catch {}
    }
  } finally {
    try { await _releaseOutboxLease(db); } catch {}
    db.close();
  }
}

function drainOutbox() {
  // Multiple sync/message/activate events in one worker share this mutex;
  // the IndexedDB lease covers overlapping old/new worker instances.
  const run = outboxDrainTail.then(_drainOutboxOnce, _drainOutboxOnce);
  outboxDrainTail = run.catch(() => undefined);
  return run;
}

self.addEventListener("sync", (event) => {
  if (event.tag === "ol-outbox") {
    event.waitUntil(drainOutbox());
  }
});

// Page-side communicates with the SW via postMessage. We expose
// "drain-now" so the UI can force a flush when the user comes
// online without waiting for the browser's sync event.
//
// Guard rails:
// - Reject any message whose origin is not our own. The SW scope
//   is same-origin only, so any `event.origin` that doesn't match
//   means something has changed the threat model out from under us
//   and we should drop the message rather than honor it.
// - Cap and sanitize all user-supplied notification strings to
//   prevent control-char or oversized payloads from being baked
//   into an OS notification.
self.addEventListener("message", (event) => {
  if (event.origin && event.origin !== self.origin) return;
  const data = event.data;
  if (!data || typeof data !== "object") return;
  if (data.type === "owner-auth-v1") {
    if (!validOwnerBearer(data.bearer)) return;
    ownerBearerGeneration += 1;
    ownerBearer = data.bearer;
    event.waitUntil(persistOwnerBearer(data.persist ? ownerBearer : ""));
    return;
  }
  if (data.type === "owner-auth-clear-v1") {
    ownerBearerGeneration += 1;
    ownerBearer = "";
    event.waitUntil(persistOwnerBearer(""));
    return;
  }
  if (data.type === "drain-now") {
    event.waitUntil(drainOutbox());
    return;
  }
  if (data.type === "incoming-call-notification") {
    const title = _sanitizeNotifText(data.title, 120) || "Incoming One Link call";
    const body = _sanitizeNotifText(data.body, 240) || "Tap to open One Link.";
    const callId = _sanitizeNotifText(data.call_id, 128);
    const peer = _sanitizeNotifText(data.peer, 128);
    event.waitUntil(
      self.registration.showNotification(title, {
        body,
        tag: callId ? `one-link-call-${callId}` : "one-link-call",
        renotify: true,
        data: { type: "incoming-call", call_id: callId, peer },
        actions: [
          { action: "accept-call", title: "Accept" },
          { action: "message-peer", title: "Message" },
        ],
      }).catch(() => null),
    );
  }
});

self.addEventListener("notificationclick", (event) => {
  const data = event.notification?.data || {};
  event.notification.close();
  event.waitUntil((async () => {
    const allClients = await self.clients.matchAll({
      type: "window",
      includeUncontrolled: true,
    });
    let client = allClients.find((c) => "focus" in c);
    if (!client && self.clients.openWindow) {
      client = await self.clients.openWindow("/");
    }
    if (client && "focus" in client) await client.focus();
    if (client && "postMessage" in client) {
      client.postMessage({
        type: "call-notification-action",
        action: event.action || "open-call",
        call_id: data.call_id || "",
        peer: data.peer || "",
      });
    }
  })());
});
