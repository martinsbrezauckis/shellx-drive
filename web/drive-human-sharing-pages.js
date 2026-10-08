// Account paging joins owned workspace roots with canonical shared roots.
(() => {
  function createPager({ state, api, adapter, contract, callbacks }) {
    function beginBrowse() {
      state.browseRequestSequence = (state.browseRequestSequence || 0) + 1;
      state.searchRequestSequence = (state.searchRequestSequence || 0) + 1;
      callbacks.clearSearchInput?.();
      return state.browseRequestSequence;
    }

    async function loadRoots(listKind, { cursor = null, pageIndex = 0 } = {}) {
      const requestSequence = beginBrowse();
      const data = listKind === "shared-by-me" ? await adapter.sharedByMe({ cursor }) : await adapter.sharedWithMe({ cursor });
      if (requestSequence !== state.browseRequestSequence) return [];
      const roots = contract.dedupeCanonicalRoots(data?.roots || data?.items || data?.files || [], listKind);
      callbacks.presentRoots?.(listKind, roots, data?.next_cursor || null, { cursor, pageIndex });
      return roots;
    }

    async function loadDefaultFiles({ cursor = null, pageIndex = 0 } = {}) {
      const requestSequence = beginBrowse();
      const source = cursor?.source || "mine";
      let files, nextCursor, partial = "";
      if (source === "mine") {
        const query = new URLSearchParams({ scope: "mine", limit: "100" });
        if (cursor?.cursor) query.set("cursor", cursor.cursor);
        let data;
        try {
          data = await api(`/browse/files?${query}`);
        } catch (error) {
          if (cursor) throw error;
          partial = "My files could not be loaded.";
          data = { files: [] };
        }
        files = data.files || [];
        nextCursor = data.next_cursor ? { source: "mine", cursor: data.next_cursor } : null;
        if (!nextCursor && files.length < 100) {
          let shared;
          try {
            shared = await adapter.sharedWithMe({ limit: 100 - files.length });
          } catch (error) {
            if (partial) throw new Error("Could not load My files or Shared with me.");
            partial = "Shared with me could not be loaded.";
            shared = { roots: [] };
          }
          const roots = contract.dedupeCanonicalRoots(shared?.roots || [], "shared-with-me");
          const ownedKeys = new Set(files.map((file) => `${file.workspace_id}:${file.id}`));
          files = files.concat(roots.filter((root) => !ownedKeys.has(`${root.workspace_id}:${root.id}`)));
          nextCursor = shared?.next_cursor ? { source: "shared", cursor: shared.next_cursor } : null;
        } else if (!nextCursor) {
          try {
            const shared = await adapter.sharedWithMe({ limit: 1 });
            const pendingRoot = contract.dedupeCanonicalRoots(shared?.roots || [], "shared-with-me")[0];
            nextCursor = pendingRoot ? { source: "shared", cursor: shared?.next_cursor || null, pendingRoot } : null;
          } catch {
            partial = "Shared with me could not be loaded.";
          }
        }
      } else {
        const pending = cursor.pendingRoot ? [cursor.pendingRoot] : [];
        const data = cursor.cursor || !pending.length
          ? await adapter.sharedWithMe({ cursor: cursor.cursor, limit: 100 - pending.length })
          : { roots: [], next_cursor: null };
        files = pending.concat(contract.dedupeCanonicalRoots(data?.roots || [], "shared-with-me"));
        nextCursor = data?.next_cursor ? { source: "shared", cursor: data.next_cursor } : null;
      }
      if (requestSequence !== state.browseRequestSequence) return null;
      callbacks.presentDefaultFiles?.(files, partial, nextCursor, { cursor, pageIndex });
      return { files, nextCursor, partial };
    }
    return { loadRoots, loadDefaultFiles };
  }
  window.ShellXDriveHumanSharingPages = { createPager };
})();
