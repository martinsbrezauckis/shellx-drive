// Browser-state projection for canonical roots. No route calls live here.
(() => {
  function createPresenter({ state, callbacks = {} } = {}) {
    const clearBrowse = callbacks.clearBrowse;
    const reset = callbacks.resetSelection;
    const render = callbacks.renderFiles;
    const renderSelection = callbacks.renderSelection;
    const setView = callbacks.setActiveView;

    function setAccountRoots(scope, roots, nextCursor = null, { cursor = null, pageIndex = 0 } = {}) {
      state.manifestRequestSequence += 1;
      state.browseScope = scope; state.browseFiles = roots; state.browseNextCursor = nextCursor;
      state.browsePageCursors = pageIndex ? state.browsePageCursors.slice(0, pageIndex + 1) : [null];
      state.browsePageCursors[pageIndex] = cursor;
      state.browsePageIndex = pageIndex; state.browseLoading = false;
      state.currentViewTitle = scope === "shared-by-me" ? "Shared by me" : "Shared with me";
      state.currentFolderId = null; state.bulkSelectedIds = []; state.browserPage = 0;
      const railView = scope === "shared-with-me" ? "shared" : scope;
      reset(); setView(railView); render(roots); renderSelection();
    }

    function presentDefaultFiles(files, partial = "", nextCursor = null, { cursor = null, pageIndex = 0 } = {}) {
      state.manifestRequestSequence += 1;
      state.browseScope = "files"; state.browseFiles = files; state.browseNextCursor = nextCursor;
      state.browsePageCursors = pageIndex ? state.browsePageCursors.slice(0, pageIndex + 1) : [null];
      state.browsePageCursors[pageIndex] = cursor;
      state.browsePageIndex = pageIndex; state.browseLoading = false;
      state.currentViewTitle = partial ? `Files · ${partial}` : "Files";
      state.currentFolderId = null; state.bulkSelectedIds = []; state.browserPage = 0;
      reset(); setView("my-drive"); render(files); renderSelection();
      if (partial) callbacks.showToast?.(`Files loaded partially: ${partial} Retry Files to refresh.`);
    }

    function presentRemovedRoot() {
      clearBrowse(); state.currentViewTitle = "Access removed"; state.files = [];
      reset(); render([]); renderSelection();
    }

    function presentRetryableRoot(root, message) {
      // Do not clear a previously rendered root list for an offline, aborted,
      // rate-limited, or server failure. The row remains the explicit retry
      // control; reset selection so no stale authority can drive an action.
      const rootId = root?.sync_root_id || root?.id;
      state.browseFiles = (state.browseFiles || []).map((candidate) =>
        (candidate.sync_root_id || candidate.id) === rootId
          ? { ...candidate, human_share_retry_message: message }
          : candidate,
      );
      state.bulkSelectedIds = []; state.browserPage = 0;
      reset(); render(state.browseFiles); renderSelection();
    }

    function presentScopedRoot(root, manifest, { preserveSelection = false } = {}) {
      const selectedId = preserveSelection ? state.selectedFile?.id : null;
      const folderId = preserveSelection ? state.currentFolderId : null;
      clearBrowse(); state.files = manifest?.files || [];
      state.folderTree = { nodes: state.files };
      state.workspaceShares = []; state.mobileManifest = null;
      state.members = []; state.workspaceInvitations = []; state.managedDrops = [];
      root = { ...root, access_generation: manifest?.root?.access_generation || root.access_generation, effective_role: manifest?.root?.role || root.effective_role };
      // The opaque root subject is not a workspace membership assertion.
      state.currentWorkspace = {
        id: root.workspace_id, name: root.owner_label || "Shared with me", role: root.effective_role,
        scoped_root_id: root.sync_root_id || root.root_subject_id || root.grant_id || "",
        scoped_root: root,
      };
      state.currentViewTitle = `Shared with me · ${root.owner_label || "Owner"}`;
      state.bulkSelectedIds = []; state.browserPage = 0; reset(); setView("shared");
      if (root.kind === "folder") {
        state.currentFolderId = state.files.some((file) => file.id === folderId && file.kind === "folder") ? folderId : root.id;
        render();
      }
      else {
        state.currentFolderId = null; render();
        const file = state.files.find((item) => item.id === root.id);
        if (file) callbacks.selectFile?.(file);
      }
      if (selectedId) {
        const file = state.files.find((item) => item.id === selectedId);
        if (file) callbacks.selectFile?.(file);
      }
      renderSelection();
    }
    return { presentHumanShareRoots: setAccountRoots, presentDefaultFiles, presentRemovedRoot, presentRetryableRoot, presentScopedRoot };
  }
  window.ShellXDriveHumanSharingBrowser = { createPresenter };
})();
