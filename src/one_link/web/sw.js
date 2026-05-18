// v0.14.0 — One Link Service Worker.
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

// May 16 2026 — bump cache name to v3 so existing clients evict the
// stale shell on first load after this update. The bigger fix is
// removing "/" from SHELL_FILES + serving the index NETWORK-FIRST
// in the fetch handler below. Cache-first for the SPA shell was
// causing users to keep seeing the OLD UI on every reload until
// they hit Ctrl+Shift+R. The daemon runs locally on 127.0.0.1 so
// "offline" is never a real state for the index page; cache-first
// has zero benefit and one large cost (stale UI).
const CACHE_NAME = "one-link-shell-v3";
const SHELL_FILES = [
  // Static-only entries here. The index itself is intentionally
  // omitted so it always comes from the live daemon — see fetch
  // handler below.
  "/manifest.json",
  "/static/one-glyph.png",
  "/static/one-glyph-app.png",
];

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
  if (url.pathname.startsWith("/api/")) {
    return; // let the browser handle normally
  }
  // May 16 2026 — Network-FIRST for the index page itself. The
  // daemon runs locally; the user is never offline with respect to
  // it. Serving cached HTML caused the "I only see new UI after
  // Ctrl+Shift+R" bug. Try network, fall back to cache only when
  // the network actually fails (which on 127.0.0.1 essentially
  // means daemon is down).
  if (url.pathname === "/") {
    event.respondWith(
      fetch(event.request).then((res) => {
        // Refresh the cache copy so a future genuinely-offline
        // load (rare; only when daemon is down) still has SOMETHING
        // to render.
        if (res && res.status === 200) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(event.request, copy));
        }
        return res;
      }).catch(() => caches.match(event.request)),
    );
    return;
  }
  // Cache-first for the small static assets (manifest, icons).
  // These rarely change, and serving them from cache makes the
  // first paint snappy.
  if (
    url.pathname === "/manifest.json" ||
    url.pathname.startsWith("/static/")
  ) {
    event.respondWith(
      caches.match(event.request).then((cached) =>
        cached || fetch(event.request).then((res) => {
          if (!res || res.status !== 200) return res;
          const copy = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(event.request, copy));
          return res;
        }).catch(() => cached),
      ),
    );
  }
});

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

function openOutboxDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE, { keyPath: "id", autoIncrement: true });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function drainOutbox() {
  let db;
  try {
    db = await openOutboxDB();
  } catch {
    return; // IDB unavailable; nothing to drain
  }
  const tx = db.transaction(IDB_STORE, "readwrite");
  const store = tx.objectStore(IDB_STORE);
  const allReq = store.getAll();
  await new Promise((res, rej) => {
    allReq.onsuccess = () => res(); allReq.onerror = () => rej(allReq.error);
  });
  const items = allReq.result || [];
  for (const item of items) {
    try {
      const resp = await fetch(item.url, {
        method: item.method || "POST",
        headers: item.headers || { "content-type": "application/json" },
        body: item.body,
        credentials: "include",
      });
      if (resp.ok) {
        store.delete(item.id);
      }
      // On non-2xx, leave it in the queue; the browser will retry
      // the sync event later (or we drain on next activate).
    } catch {
      // Network still down; bail and let the browser retry.
      return;
    }
  }
}

self.addEventListener("sync", (event) => {
  if (event.tag === "ol-outbox") {
    event.waitUntil(drainOutbox());
  }
});

// Page-side communicates with the SW via postMessage. We expose
// "drain-now" so the UI can force a flush when the user comes
// online without waiting for the browser's sync event.
self.addEventListener("message", (event) => {
  if (event.data?.type === "drain-now") {
    event.waitUntil(drainOutbox());
  }
  if (event.data?.type === "incoming-call-notification") {
    const title = event.data.title || "Incoming One Link call";
    const body = event.data.body || "Tap to open One Link.";
    const callId = event.data.call_id || "";
    const peer = event.data.peer || "";
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
