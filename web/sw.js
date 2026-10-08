const SHELLX_DRIVE_CACHE = "shellx-drive-app-shell-2026-10-05-cold-click1";
const SHELLX_DRIVE_SHELL = [
  "/",
  "/assets/drive.css?v=2026-09-08-mobile-rail1",
  "/assets/shellx-drive-icon.svg?v=2026-07-03-icon",
  "/assets/admin-backups.js?v=2026-09-23-admin-history1",
  "/assets/download-tickets.js?v=2026-08-26-auth-epoch1",
  "/assets/upload-progress.js?v=2026-07-18-collab1",
  "/assets/drive-uploads.js?v=2026-08-25-account-separation2",
  "/assets/drive-file-moves.js?v=2026-10-02-shared-scope2",
  "/assets/drive-browser.js?v=2026-08-25-account-separation2",
  "/assets/drive-preview.js?v=2026-08-26-preview-bound1",
  "/assets/drive-agent-delegations.js?v=2026-09-24-delegation-pages1",
  "/assets/drive-agent-access.js?v=2026-10-05-cold-click1",
  "/assets/drive-invitation-link.js?v=2026-09-02-invitation-link-v1",
  "/assets/drive-workspace-invitations.js?v=2026-09-07-invitation-link-copy1",
  "/assets/drive-human-sharing-contract.js?v=2026-10-02-shared-scope1",
  "/assets/drive-human-sharing-drawer.js?v=2026-09-02-human-sharing-v2",
  "/assets/drive-everyone-grant-policy.js?v=2026-09-02-everyone-policy-v1",
  "/assets/drive-human-sharing-admin.js?v=2026-09-03-admin-item-v1",
  "/assets/drive-human-sharing-browser.js?v=2026-10-02-shared-scope1",
  "/assets/drive-human-sharing-pages.js?v=2026-09-23-browse-pages1",
  "/assets/drive-human-sharing.js?v=2026-10-02-shared-scope1",
  "/assets/drive-guest-links.js?v=2026-10-05-cold-click1",
  "/assets/drive-collaboration.js?v=2026-10-05-cold-click1",
  "/assets/drive-debug.js?v=2026-07-18-debug1",
  "/assets/drive-format.js?v=2026-07-18-modular1",
  "/assets/drive-file-types.js?v=2026-09-07-office-formats1",
  "/assets/drive-settings.js?v=2026-07-22-password1",
  "/assets/drive-sessions.js?v=2026-08-28-session-retention1",
  "/assets/drive-workspace-policy.js?v=2026-08-26-policy-lease1",
  "/assets/admin-clarity.js?v=2026-08-25-securitylog1",
  "/assets/admin-password-reset.js?v=2026-09-02-manual-recovery1",
  "/assets/admin-security.js?v=2026-09-23-admin-history1",
  "/assets/drive-account.js?v=2026-08-25-account-separation2",
  "/assets/drive-account-state.js?v=2026-08-26-security-fix1",
  "/assets/drive-mobile-sync.js?v=2026-10-05-cold-click1",
  "/assets/drive-auth-lifecycle.js?v=2026-08-26-auth-epoch1",
  "/assets/drive-auth-hydration.js?v=2026-08-26-auth-epoch1",
  "/assets/drive-api.js?v=2026-08-26-auth-epoch1",
  "/assets/drive-version.js?v=2026-08-13-modular1",
  "/assets/drive.js?v=2026-10-05-cold-click1",
  "/manifest.webmanifest",
  "/assets/shellx-drive-icon.svg",
];
const SHELLX_DRIVE_SHELL_URLS = new Set(
  SHELLX_DRIVE_SHELL.map((asset) => new URL(asset, self.location.origin).href),
);

function isSuccessfulSameOriginResponse(response) {
  return response.ok && new URL(response.url).origin === self.location.origin;
}

async function cacheSuccessfulResponse(request, response) {
  if (!isSuccessfulSameOriginResponse(response)) return;

  try {
    const cache = await caches.open(SHELLX_DRIVE_CACHE);
    await cache.put(request, response.clone());
  } catch {
    // A storage failure must not turn a fresh response into an offline fallback.
  }
}

async function cacheShell() {
  const cache = await caches.open(SHELLX_DRIVE_CACHE);
  await Promise.all(
    SHELLX_DRIVE_SHELL.map(async (asset) => {
      const request = new Request(new URL(asset, self.location.origin).href);
      const response = await fetch(request);
      if (!isSuccessfulSameOriginResponse(response)) {
        throw new Error(`Unable to cache ShellX Drive shell asset: ${asset}`);
      }
      await cache.put(request, response.clone());
    }),
  );
}

async function cachedShell() {
  const cache = await caches.open(SHELLX_DRIVE_CACHE);
  return (await cache.match("/")) || Response.error();
}

async function cachedAsset(request) {
  const cache = await caches.open(SHELLX_DRIVE_CACHE);
  return (await cache.match(request)) || Response.error();
}

async function networkFirst(request, offlineFallback, cacheRequest) {
  try {
    const response = await fetch(request);
    if (cacheRequest) await cacheSuccessfulResponse(cacheRequest, response);
    return response;
  } catch {
    return offlineFallback();
  }
}

function isPublicCapabilityNavigation(url) {
  return (
    url.pathname === "/reset-password" ||
    url.pathname.startsWith("/pub/shares/") ||
    url.pathname.startsWith("/pub/drops/") ||
    url.pathname.startsWith("/pub/invitations/") ||
    url.pathname.startsWith("/office/launch/")
  );
}

function offlinePublicResponse() {
  return new Response("Offline", {
    status: 503,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

self.addEventListener("install", (event) => {
  event.waitUntil(cacheShell().then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(
          names
            .filter((name) => name.startsWith("shellx-drive-app-shell") && name !== SHELLX_DRIVE_CACHE)
            .map((name) => caches.delete(name)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === "navigate") {
    if (isPublicCapabilityNavigation(url)) {
      event.respondWith(networkFirst(request, offlinePublicResponse));
      return;
    }

    const cacheRequest = url.pathname === "/" && !url.search ? request : undefined;
    event.respondWith(networkFirst(request, cachedShell, cacheRequest));
    return;
  }

  if (SHELLX_DRIVE_SHELL_URLS.has(url.href)) {
    event.respondWith(networkFirst(request, () => cachedAsset(request), request));
  }
});
