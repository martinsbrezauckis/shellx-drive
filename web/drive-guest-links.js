// Selected-item guest links: current permission, lookup state, and reply leases.
(() => {
  function isActiveShare(share, now = Date.now()) {
    if (!share || share.revoked) return false;
    if (!share.expires_at) return true;
    const expiresAt = Date.parse(share.expires_at);
    return Number.isFinite(expiresAt) && expiresAt > now;
  }

  function createController({ state, api, callbacks }) {
    const { isActiveShare, canManageGuestLink, syncInspectorShareForm, renderShareSummary,
      renderShareDrawer, setSelectionControlState, syncSharedItemBadge, renderManagedShares } = callbacks;

    function selectedWorkspaceId() {
      const workspaceId = state.browseScope ? state.selectedFile?.workspace_id : state.currentWorkspace?.id;
      return state.selectedFile?.workspace_id && state.selectedFile.workspace_id !== workspaceId ? null : workspaceId;
    }

    function isCurrent(lookup) {
      return selectedWorkspaceId() === lookup.workspaceId && state.selectedFile?.id === lookup.fileId
        && state.selectedFile.guest_link_lookup === lookup;
    }

    function show(lookup, status) {
      if (!isCurrent(lookup)) return false;
      lookup.status = status;
      renderShareSummary();
      renderShareDrawer();
      setSelectionControlState();
      return true;
    }

    async function loadSelected(file = state.selectedFile, { preserveForm = false } = {}) {
      if (!file || file.trashed || file.id !== state.selectedFile?.id || !selectedWorkspaceId()) return [];
      const lookup = { workspaceId: selectedWorkspaceId(), fileId: file.id, status: "loading" };
      state.selectedFile.guest_link_lookup = lookup;
      show(lookup, "loading");
      try {
        const data = await api(`/files/${encodeURIComponent(file.id)}/action-capabilities`);
        if (!isCurrent(lookup)) return [];
        if (typeof data?.action_capabilities?.manage_guest_links !== "boolean") throw new Error("Guest-link access could not be verified.");
        if (file.workspace_id && (data.file_id !== lookup.fileId || data.workspace_id !== lookup.workspaceId)) throw new Error("Guest-link item context could not be verified.");
        state.selectedFile = { ...state.selectedFile, action_capabilities: data.action_capabilities, access_generation: data.access_generation };
        if (!canManageGuestLink(state.selectedFile)) { show(lookup, "unavailable"); return []; }
        return await loadShares({ lookup, preserveForm });
      } catch (error) {
        if (!show(lookup, "error")) return [];
        throw error;
      }
    }

    async function loadShares({ lookup = null, preserveForm = false } = {}) {
      const workspaceId = selectedWorkspaceId();
      const selectedFileId = state.selectedFile?.id;
      if (!workspaceId || !selectedFileId) return [];
      if (!canManageGuestLink(state.selectedFile)) throw new Error("Guest-link access is not authorized for this item.");
      lookup ||= { workspaceId, fileId: selectedFileId, status: "loading" };
      state.selectedFile.guest_link_lookup = lookup;
      show(lookup, "loading");
      let data;
      try {
        if (state.browseScope) {
          const response = await api(`/workspaces/${encodeURIComponent(workspaceId)}/policy`);
          if (!isCurrent(lookup)) return [];
          if (response?.policy?.workspace_id !== workspaceId) throw new Error("Guest-link workspace policy could not be verified.");
          lookup.policy = response.policy;
        }
        data = await api(`/files/${selectedFileId}/shares`);
        if (!Array.isArray(data?.shares) || data.shares.some((share) => share?.file_id !== selectedFileId || typeof share?.id !== "string" || !share.id)) {
          throw new Error("Guest-link details could not be verified.");
        }
      } catch (error) {
        if (!show(lookup, "error")) return [];
        throw error;
      }
      if (!isCurrent(lookup)) return [];
      state.managedShares = data.shares;
      state.workspaceShares = [
        ...(state.workspaceShares || []).filter((share) => share.file_id !== selectedFileId),
        ...data.shares,
      ];
      const active = data.shares.find(isActiveShare) || null;
      if (!preserveForm || state.latestShareMeta?.id !== active?.id) syncInspectorShareForm(active);
      state.latestShareUrl = active ? `${window.location.origin}/pub/shares/${active.id}` : "";
      state.latestShareMeta = active;
      state.selectedShareId = active?.id || data.shares[0]?.id || "";
      lookup.shares = data.shares;
      show(lookup, "loaded");
      syncSharedItemBadge(selectedFileId);
      renderManagedShares();
      return data.shares;
    }

    return { loadSelected, loadShares };
  }
  window.ShellXDriveGuestLinks = { isActiveShare, createController };
})();
