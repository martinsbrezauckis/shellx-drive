// Public facade: joins the narrow contract, drawer, and admin-inventory modules.
(() => {
  const contract = window.ShellXDriveHumanSharingContract;
  const drawerModule = window.ShellXDriveHumanSharingDrawer;
  const adminModule = window.ShellXDriveHumanSharingAdmin;
  const pagesModule = window.ShellXDriveHumanSharingPages;

  function createController({ state, api, callbacks = {}, endpoints } = {}) {
    const adapter = contract.createAdapter(api, endpoints);
    const drawer = drawerModule.createController({ state, adapter, callbacks });
    const admin = adminModule.createController({ adapter, escapeHtml: callbacks.escapeHtml });
    const { loadRoots, loadDefaultFiles } = pagesModule.createPager({ state, api, adapter, contract, callbacks });

    function rootMeta(root) {
      if (root.human_share_list === "shared-by-me") return contract.sharedByMeSummary(root);
      const parts = ["Shared", root.owner_label || "Owner", contract.roleLabel(root.effective_role)];
      if (root.grant_source === "inherited") parts.push("Inherited");
      if (root.expires_at) parts.push(contract.displayExpiry(root.expires_at));
      return parts.join(" · ");
    }
    async function loadCapabilities(file = state.selectedFile) {
      const fileId = String(file?.id || "");
      if (!fileId) return null;
      const data = await adapter.capabilities(fileId);
      if (state.selectedFile?.id !== fileId || !data?.action_capabilities) return null;
      state.selectedFile = { ...state.selectedFile, action_capabilities: data.action_capabilities, access_generation: data.access_generation };
      callbacks.refreshAfterMutation?.();
      return data;
    }
    async function readScopedRoot(root, isCurrent) {
      try {
        const manifest = await adapter.scopedRootManifest(root);
        return isCurrent() ? { root, manifest } : null;
      } catch (error) {
        if (!isCurrent()) return null;
        if (error?.status !== 412 || error?.code !== "precondition_failed") throw error;
        const currentRoot = await adapter.revalidateScopedRoot(root);
        if (!isCurrent()) return null;
        const manifest = await adapter.scopedRootManifest(currentRoot);
        return isCurrent() ? { root: currentRoot, manifest } : null;
      }
    }
    async function refreshScopedRoot(root, isCurrent) {
      try {
        const current = await readScopedRoot(root, isCurrent);
        if (!current) return false;
        callbacks.presentScopedRoot?.(current.root, current.manifest, { preserveSelection: true });
        return true;
      } catch (error) {
        if (!isCurrent()) return false;
        if (error?.status === 404) callbacks.presentRemovedRoot?.();
        throw error;
      }
    }
    async function openScopedRoot(root) {
      const sequence = state.browseRequestSequence = (state.browseRequestSequence || 0) + 1;
      const isCurrent = () => sequence === state.browseRequestSequence;
      const accessRemoved = () => {
        callbacks.presentRemovedRoot?.();
        throw new Error("Access to this shared item has been removed. Refresh Shared with me.");
      };
      const retryableFailure = (error) => {
        const message = error?.status === 401
          ? "Your session needs to be refreshed before this shared item can be opened. Sign in again, then retry."
          : "This shared item could not be verified. Your current view is still available; retry when the connection is ready.";
        callbacks.presentRetryableRoot?.(root, message);
        throw new Error(message);
      };
      // Only a server-confirmed missing route can remove the row. Network,
      // authorization, rate-limit, and server failures leave recovery visible.
      const isVerifiedMissingRoot = (error) => error?.status === 404;
      try {
        const current = await readScopedRoot(root, isCurrent);
        if (!current) return null;
        callbacks.presentScopedRoot?.(current.root, current.manifest);
        return current.manifest;
      } catch (error) {
        if (!isCurrent() || window.ShellXDriveAuthLifecycle?.isStale?.(error)) return null;
        if (isVerifiedMissingRoot(error)) return accessRemoved();
        return retryableFailure(error);
      }
    }
    function badgeForFile(file) {
      if (file?.human_share_root) {
        const escape = callbacks.escapeHtml || String;
        const label = file.human_share_list === "shared-by-me"
          ? contract.sharedByMeSummary(file)
          : contract.roleLabel(file.effective_role);
        return `<span class="shared-item-badge human-share-badge" title="${escape(rootMeta(file))}"><svg class="icon" aria-hidden="true"><use href="#i-share"/></svg><span>${escape(label)}</span></span>`;
      }
      return drawer.badgeForFile(file);
    }
    function bind({ shareDrawer, adminInventory, adminSearch } = {}) {
      drawer.bind(shareDrawer); admin.bind(adminInventory, adminSearch);
    }
    function clear() { drawer.clear(); admin.clear(); }
    return {
      adapter, model: { drawer: drawer.model, admin: admin.model }, bind, clear, loadGrants: drawer.load, renderDrawer: drawer.render,
      loadRoots, loadDefaultFiles, loadCapabilities, openScopedRoot, refreshScopedRoot, loadAdminInventory: admin.load, loadAdminDetails: admin.loadDetails, renderAdminInventory: admin.render, badgeForFile, rootMeta,
    };
  }

  window.ShellXDriveHumanSharing = { ...contract, createController };
})();
