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

// v0.15.0: bump shell cache name so the SW upgrade picks up the
// manifest + new icon variants. The activate handler below evicts
// any older `one-link-shell-*` keys.
const CACHE_NAME = "one-link-shell-v2";
const SHELL_FILES = [
  "/",
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
  // Cache-first for static shell; falls back to network. v0.15.0
  // adds /manifest.json so the install prompt works offline (the
  // browser refetches the manifest before showing the prompt; if
  // we're offline we still serve from cache).
  if (
    url.pathname === "/" ||
    url.pathname === "/manifest.json" ||
    url.pathname.startsWith("/static/")
  ) {
    event.respondWith(
      caches.match(event.request).then((cached) =>
        cached || fetch(event.request).then((res) => {
          // Don't cache redirects or errors.
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
});
