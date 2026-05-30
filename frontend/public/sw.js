/**
 * VulnForge Service Worker
 *
 * Caches the SPA shell and chunks so repeat visits paint the UI before the
 * network responds. Ported from TideWatch/MyGarage with the same hardening:
 *   - Cache names include APP_VERSION (passed in via ?v=<...> on the script
 *     URL), so every release evicts the previous deploy's cache on activate.
 *     Hardcoded cache names produce the classic "white screen on restart"
 *     when chunk hashes change.
 *   - Static-asset fetches retry on network failure (3 attempts with
 *     exponential backoff) before surfacing the error. Survives the
 *     backend's cold-start window after `docker compose up`.
 *   - Asset and API caching are gated to small/idempotent paths only.
 *     Caching multi-MB binary bodies or realtime streams is at best wasted,
 *     and at worst stalls responses because `response.clone()` tees the
 *     underlying network stream until the cache.put drains.
 */

const SW_URL = new URL(self.location.href);
const SW_VERSION = SW_URL.searchParams.get('v') || 'dev';
const CACHE_NAME = `vulnforge-static-${SW_VERSION}`;
const RUNTIME_CACHE = `vulnforge-runtime-${SW_VERSION}`;
const OFFLINE_URL = '/offline.html';

// Precache only immutable shell pieces. Do NOT precache `/` or `/index.html`:
// those are mutable on each deploy and the navigation handler already serves
// them network-first with a cache fallback.
const STATIC_ASSETS = [OFFLINE_URL];

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);
      await Promise.all(
        STATIC_ASSETS.map((url) =>
          cache.add(url).catch((err) => console.warn('[SW] Precache failed:', url, err))
        )
      );
    })()
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(
        names
          .filter((name) => name !== CACHE_NAME && name !== RUNTIME_CACHE)
          .map((name) => caches.delete(name))
      );
      await self.clients.claim();
    })()
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  if (request.method !== 'GET') {
    return;
  }

  // Same-origin only. Cross-origin bypasses the SW.
  if (url.origin !== self.location.origin) {
    return;
  }

  // Navigation requests (the HTML shell): network-first with a 5s timeout and a
  // cache fallback. We also catch non-navigate *document* requests
  // (request.destination === 'document'): browser link-prefetch and Cloudflare
  // Speculative Loading fetch SPA routes with mode !== 'navigate'. Without this
  // they fell through to the static-asset branch below, whose deliberate
  // `throw lastError` surfaced as an "Uncaught (in promise) Failed to fetch"
  // whenever the speculative fetch was cancelled or hit a transient edge error.
  if (request.mode === 'navigate' || request.destination === 'document') {
    event.respondWith(
      Promise.race([
        fetch(request),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Navigation timeout')), 5000)
        ),
      ]).catch(async () => {
        const cache = await caches.open(CACHE_NAME);
        return (await cache.match(OFFLINE_URL)) || Response.error();
      })
    );
    return;
  }

  // API requests: network-first, cache fallback for offline. We deliberately
  // skip caching long-lived realtime channels and large binary downloads —
  // `response.clone()` tees the underlying network stream until the cache.put
  // drains, which stalls the user's response behind the cache write.
  if (url.pathname.startsWith('/api/')) {
    const shouldCache = !(
      url.pathname.startsWith('/api/v1/scans/') &&
      (url.pathname.includes('/stream') || url.pathname.includes('/events'))
    );

    event.respondWith(
      fetch(request)
        .then((response) => {
          if (shouldCache && response.ok) {
            const clone = response.clone();
            caches.open(RUNTIME_CACHE).then((cache) => {
              cache.put(request, clone);
            });
          }
          return response;
        })
        .catch(() => {
          return caches.match(request).then((cached) => {
            if (cached) return cached;
            return new Response(
              JSON.stringify({ error: 'Offline - data unavailable' }),
              {
                headers: { 'Content-Type': 'application/json' },
                status: 503,
              }
            );
          });
        })
    );
    return;
  }

  // Static assets (Vite-hashed JS/CSS/images): cache-first, network on miss
  // with three retries (0/500/1500ms) before propagating the error. The
  // retry covers the backend's cold-start window after `docker compose up`
  // without producing a silent 503 that would manifest as a white screen.
  event.respondWith(
    caches.match(request).then(async (cached) => {
      if (cached) return cached;

      const delays = [0, 500, 1500];
      let lastError;
      for (const delay of delays) {
        if (delay > 0) {
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
        try {
          const response = await fetch(request);
          if (response && response.status === 200 && response.type === 'basic') {
            const clone = response.clone();
            caches.open(RUNTIME_CACHE).then((cache) => {
              cache.put(request, clone);
            });
          }
          return response;
        } catch (err) {
          lastError = err;
        }
      }
      throw lastError;
    })
  );
});

// Allow the page to ask the SW to take over immediately on a controlled
// reload (e.g. after a manual "New version available, reload" prompt).
self.addEventListener('message', (event) => {
  if (event.origin !== self.location.origin) {
    return;
  }
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
