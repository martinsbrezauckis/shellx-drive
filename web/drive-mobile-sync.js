// Metadata-only mobile sync and rclone import/export orchestration.
(function attachDriveMobileSync(root) {
  "use strict";

  function snapshotKey(prefix, actor, workspaceId) {
    return `${prefix}${actor || "server-token"}:${workspaceId || "none"}`;
  }

  function parseSnapshot(raw) {
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  function createController(options) {
    const { state, els, api, storage = root.localStorage, storagePrefix, callbacks } = options;

    function setStatus(message) {
      if (els.mobileOfflineStatus) els.mobileOfflineStatus.textContent = message;
    }

    function currentSnapshotKey(workspaceId = state.currentWorkspace?.id) {
      const actor = state.actor || state.currentAccount?.email || "server-token";
      return snapshotKey(storagePrefix, actor, workspaceId);
    }

    function writeSnapshot(data, workspaceId) {
      try {
        storage.setItem(
          currentSnapshotKey(workspaceId),
          JSON.stringify({ saved_at: new Date().toISOString(), data }),
        );
        setStatus("Metadata-only file list saved for offline browsing. File bodies are not stored by this web build.");
      } catch (error) {
        setStatus(`Metadata-only file list could not be saved: ${error.message}`);
      }
    }

    function readSnapshot(workspaceId) {
      try {
        return parseSnapshot(storage.getItem(currentSnapshotKey(workspaceId)));
      } catch {
        return null;
      }
    }

    async function loadManifest({
      workspaceId = state.currentWorkspace?.id,
      isCurrent = () => true,
    } = {}) {
      if (!workspaceId) {
        if (!isCurrent()) return;
        state.mobileManifest = null;
        els.mobileOutput.textContent = "";
        setStatus("Select a workspace to save its metadata-only file list.");
        callbacks.renderSelectionSummary();
        return;
      }
      try {
        const data = await api(
          `/sync/mobile/workspaces/${workspaceId}/manifest`,
        );
        if (!isCurrent()) return;
        state.mobileManifest = data;
        writeSnapshot(data, workspaceId);
        els.mobileOutput.textContent = callbacks.pretty(data);
      } catch (error) {
        if (window.ShellXDriveAuthLifecycle?.isStale?.(error)) throw error;
        if (!isCurrent()) return;
        const snapshot = readSnapshot(workspaceId);
        if (!snapshot?.data) {
          setStatus(`Metadata-only file list unavailable: ${error.message}`);
          throw error;
        }
        state.mobileManifest = snapshot.data;
        els.mobileOutput.textContent = callbacks.pretty(snapshot.data);
        setStatus(
          `Showing metadata-only file list saved ${callbacks.compactDate(snapshot.saved_at)}. Download marked files on mobile while online.`,
        );
      }
      if (!isCurrent()) return;
      if (state.hasCurrentBaseFiles && (state.activeView === "offline" || state.browserPreferences?.stateFilter === "offline")) callbacks.renderFiles(state.currentBaseFiles);
      else callbacks.renderSelectionSummary();
    }

    async function setSelectedOffline(offline) {
      if (!state.selectedFile) return;
      const data = await api("/sync/mobile/offline", {
        method: "POST",
        body: JSON.stringify({ file_id: state.selectedFile.id, offline }),
      });
      els.mobileOutput.textContent = callbacks.pretty(data);
      await loadManifest().catch((error) => {
        els.mobileOutput.textContent = error.message;
      });
      callbacks.showToast(
        offline
          ? "Marked for mobile download. This web build does not store the file locally; download it on mobile while online."
          : "Mobile download mark removed.",
      );
    }

    async function importBundle() {
      if (!state.currentWorkspace || !callbacks.canWrite()) return;
      const text = els.importBundle.value.trim();
      if (!text) return;
      const data = await api(`/workspaces/${state.currentWorkspace.id}/import/rclone`, {
        method: "POST",
        body: JSON.stringify(JSON.parse(text)),
      });
      els.importExportOutput.textContent = callbacks.pretty(data);
      await callbacks.loadWorkspaceManifest(state.currentWorkspace.id);
      await callbacks.loadSyncHealth().catch((error) => {
        els.syncOutput.textContent = error.message;
      });
      callbacks.showToast("Bundle imported.");
    }

    async function previewImportBundle() {
      if (!state.currentWorkspace || !callbacks.canWrite()) return;
      const text = els.importBundle.value.trim();
      if (!text) return;
      const data = await api(
        `/workspaces/${state.currentWorkspace.id}/import/rclone/preview`,
        { method: "POST", body: JSON.stringify(JSON.parse(text)) },
      );
      els.importExportOutput.textContent = callbacks.pretty(data);
      callbacks.showToast("Import preview ready.");
    }

    async function exportBundle() {
      if (!state.currentWorkspace) return;
      const data = await api(`/workspaces/${state.currentWorkspace.id}/export/rclone`);
      els.importBundle.value = callbacks.pretty(data);
      els.importExportOutput.textContent = callbacks.pretty(data);
      callbacks.showToast("Bundle exported.");
    }

    return Object.freeze({
      exportBundle,
      importBundle,
      loadManifest,
      previewImportBundle,
      setSelectedOffline,
    });
  }

  root.ShellXDriveMobileSync = Object.freeze({
    createController,
    parseSnapshot,
    snapshotKey,
  });
})(window);
