// Redacted browser diagnostics. This module owns client-side snapshots and
// generic read-only Debug API buttons so drive.js remains a composition root.
(function attachDriveDebug(root) {
  "use strict";

  const ACTIVE_UPLOADS = new Set([
    "preflight", "queued", "retrying", "starting", "uploading", "finalizing",
  ]);
  const MODALS = [
    "preview-modal",
    "confirm-dialog",
    "move-dialog",
    "create-dialog",
    "share-drawer",
    "settings-drawer",
    "workspace-settings-drawer",
    "advanced-workbench",
  ];

  function sanitizePath(value) {
    try {
      const url = new URL(String(value || "/"), root.location?.origin || "http://local");
      return url.pathname
        .split("/")
        .map((segment) => (/^[a-f0-9]{64}$/i.test(segment) ? ":opaque" : segment))
        .join("/")
        .slice(0, 256);
    } catch {
      return "/invalid";
    }
  }

  function errorCode(text, status) {
    try {
      const parsed = JSON.parse(text || "{}");
      const code = String(parsed.error || "");
      if (/^[a-z0-9_]{1,64}$/.test(code)) return code;
    } catch {
      // Error bodies are intentionally not retained in diagnostics.
    }
    return status ? `http_${status}` : "network_error";
  }

  function opaqueRef(prefix, value) {
    if (!value) return null;
    let hash = 2166136261;
    for (const byte of new TextEncoder().encode(String(value))) {
      hash ^= byte;
      hash = Math.imul(hash, 16777619);
    }
    return `${prefix}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
  }

  function queueSnapshot(queue) {
    const statusCounts = {};
    let totalBytes = 0;
    let acknowledgedBytes = 0;
    let active = 0;
    for (const item of queue || []) {
      const status = String(item.status || "unknown").slice(0, 32);
      statusCounts[status] = (statusCounts[status] || 0) + 1;
      totalBytes += Number.isFinite(item.totalBytes) ? Math.max(0, item.totalBytes) : 0;
      acknowledgedBytes += Number.isFinite(item.uploadedBytes) ? Math.max(0, item.uploadedBytes) : 0;
      if (ACTIVE_UPLOADS.has(status)) active += 1;
    }
    return {
      items: (queue || []).length,
      active,
      total_bytes: totalBytes,
      acknowledged_bytes: acknowledgedBytes,
      statuses: statusCounts,
    };
  }

  function activeModal(documentRef) {
    for (const id of MODALS) {
      const element = documentRef?.getElementById(id);
      if (element && !element.hidden) return id;
    }
    return null;
  }

  function buildSnapshot({ state, documentRef, online, build, serviceWorker, lastFailure }) {
    return {
      schema: "shellx-drive-browser-debug-v1",
      captured_at: new Date().toISOString(),
      view: String(state.activeView || "unknown").slice(0, 64),
      workspace_ref: opaqueRef("workspace", state.currentWorkspace?.id),
      workspace_storage_mode: state.currentWorkspace?.storage_mode || null,
      folder_ref: opaqueRef("folder", state.currentFolderId),
      active_modal: activeModal(documentRef),
      selected_items: Array.isArray(state.bulkSelectedIds) ? state.bulkSelectedIds.length : 0,
      selected_file_kind: state.selectedFile?.kind || null,
      upload_queue: queueSnapshot(state.uploadQueue),
      connectivity: { online: Boolean(online) },
      build: {
        loaded: build?.loaded || null,
        live: build?.live || null,
        service_worker_cache: serviceWorker || null,
      },
      last_failed_request: lastFailure,
      redaction: {
        names: true,
        identifiers: "opaque",
        credentials: true,
        request_bodies: true,
        response_bodies: true,
      },
    };
  }

  function createController(options) {
    let lastFailure = null;

    function recordFailure({ method, path, status, responseText }) {
      lastFailure = {
        method: String(method || "GET").toUpperCase().slice(0, 12),
        path: sanitizePath(path),
        status: Number.isFinite(status) ? status : 0,
        code: errorCode(responseText, status),
        at: new Date().toISOString(),
      };
    }

    function snapshot() {
      const workerUrl = root.navigator?.serviceWorker?.controller?.scriptURL || "";
      let workerCache = null;
      try {
        workerCache = new URL(workerUrl).searchParams.get("v");
      } catch {
        workerCache = null;
      }
      const build = options.getBuild?.() || {};
      return buildSnapshot({
        state: options.state,
        documentRef: options.documentRef,
        online: root.navigator?.onLine,
        build,
        serviceWorker: workerCache,
        lastFailure,
      });
    }

    function bind() {
      options.documentRef?.addEventListener("click", (event) => {
        const requestButton = event.target.closest("[data-debug-path]");
        if (requestButton) {
          const method = requestButton.dataset.debugMethod || "GET";
          options.api(requestButton.dataset.debugPath, { method })
            .then((data) => { options.output.textContent = options.pretty(data); })
            .catch((error) => { options.output.textContent = error.message; });
          return;
        }
        if (event.target.closest("[data-client-debug-snapshot]")) {
          options.output.textContent = options.pretty(snapshot());
        }
      });
    }

    return Object.freeze({ bind, buildSnapshot: snapshot, recordFailure });
  }

  root.ShellXDriveDebug = Object.freeze({
    buildSnapshot,
    createController,
    errorCode,
    opaqueRef,
    queueSnapshot,
    sanitizePath,
  });
})(window);
