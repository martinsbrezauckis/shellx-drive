// Folder destination picker and collision-aware move operations.
//
// This stays separate from drive.js so the shell owns state composition while
// this controller owns destination discovery, selected collision policy, and
// the result a person sees after each PATCH settles.

(() => {
  const POLICIES = new Set(["keep_both", "replace", "cancel"]);

  function policy(value) {
    return POLICIES.has(value) ? value : "keep_both";
  }

  function sameParent(node, destinationId) {
    return (node?.parent_id || null) === (destinationId || null);
  }

  // A replace needs the selected source revision plus the occupied target's
  // exact ID and revision. A file listing is advisory, so any missing or
  // stale-looking target deliberately becomes a keep-both request.
  function moveRequestFor(source, nodes, destinationId, requestedPolicy) {
    const base = destinationId
      ? { parent_id: destinationId }
      : { move_to_root: true };
    if (policy(requestedPolicy) !== "replace") {
      return { body: { ...base, collision_policy: policy(requestedPolicy) }, fallback: "" };
    }
    if (source?.kind !== "file") {
      return {
        body: { ...base, collision_policy: "keep_both" },
        fallback: "folder",
      };
    }
    const target = (nodes || []).find((node) => (
      node?.id !== source.id
      && !node?.trashed
      && sameParent(node, destinationId)
      && node?.name === source.name
    ));
    if (
      target?.kind !== "file"
      || !Number.isInteger(Number(source?.revision))
      || !Number.isInteger(Number(target?.revision))
    ) {
      return {
        body: { ...base, collision_policy: "keep_both" },
        fallback: target ? "unavailable_target" : "no_target",
      };
    }
    return {
      body: {
        ...base,
        collision_policy: "replace",
        base_revision: Number(source.revision),
        replace_target_id: target.id,
        replace_target_revision: Number(target.revision),
      },
      fallback: "",
      targetId: target.id,
    };
  }

  function createController({ state, els, api, callbacks, documentRef = document }) {
    const { canWrite, closeFileMenu, fileNodesById, loadManifest, showToast } = callbacks;

    function folderDescendantIds(folderId) {
      const nodes = state.folderTree?.nodes || state.files || [];
      const childrenByParent = new Map();
      for (const node of nodes) {
        if (node.kind !== "folder") continue;
        const parent = node.parent_id || null;
        if (!childrenByParent.has(parent)) childrenByParent.set(parent, []);
        childrenByParent.get(parent).push(node.id);
      }
      const out = new Set();
      const stack = [folderId];
      while (stack.length) {
        const current = stack.pop();
        for (const childId of childrenByParent.get(current) || []) {
          if (!out.has(childId)) {
            out.add(childId);
            stack.push(childId);
          }
        }
      }
      return out;
    }

    function buildDestinations(excludeIds) {
      const folders = (state.folderTree?.nodes || state.files || []).filter(
        (node) => node.kind === "folder" && !node.trashed && !excludeIds.has(node.id),
      );
      const presentIds = new Set(folders.map((node) => node.id));
      const childrenByParent = new Map();
      for (const node of folders) {
        const parent = node.parent_id && presentIds.has(node.parent_id) ? node.parent_id : "__root__";
        if (!childrenByParent.has(parent)) childrenByParent.set(parent, []);
        childrenByParent.get(parent).push(node);
      }
      for (const list of childrenByParent.values()) {
        list.sort((left, right) => String(left.name).localeCompare(String(right.name)));
      }
      const out = [];
      const walk = (parentKey, depth) => {
        for (const node of childrenByParent.get(parentKey) || []) {
          out.push({ id: node.id, name: node.name, depth });
          walk(node.id, depth + 1);
        }
      };
      walk("__root__", 0);
      return out;
    }

    function makeOption(name, depth, { isRoot = false } = {}) {
      const button = documentRef.createElement("button");
      button.type = "button";
      button.setAttribute("role", "menuitem");
      button.className = `move-option${isRoot ? " is-root" : ""}`;
      button.style.setProperty("--move-depth", String(depth));
      button.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-folder"/></svg>';
      const label = documentRef.createElement("span");
      label.textContent = name;
      button.append(label);
      return button;
    }

    function closeDialog() {
      if (!els.moveDialog) return;
      els.moveDialog.hidden = true;
      els.moveDialogList.replaceChildren();
      state.moveDialogOpen = false;
    }

    function setReplaceAvailability(ids, byId) {
      const option = els.moveCollisionPolicy?.querySelector('option[value="replace"]');
      if (!option) return;
      const containsFolder = ids.some((id) => byId.get(id)?.kind === "folder");
      option.hidden = containsFolder;
      option.disabled = containsFolder;
      if (containsFolder && els.moveCollisionPolicy.value === "replace") {
        els.moveCollisionPolicy.value = "keep_both";
      }
    }

    async function moveFilesToDestination(fileIds, destId, destName, requestedPolicy = "keep_both") {
      if (!state.currentWorkspace || !canWrite()) {
        showToast("You can't move files in this workspace.");
        return;
      }
      const targets = (fileIds || []).filter((id) => id && id !== destId);
      if (!targets.length) return;
      const collisionPolicy = policy(requestedPolicy);
      let moved = 0;
      let failed = 0;
      let canceled = 0;
      let replaced = 0;
      let unconfirmedReplacements = 0;
      const fallbacks = new Map();
      const renamed = [];
      const byId = fileNodesById();
      for (const id of targets) {
        try {
          const before = byId.get(id);
          const request = moveRequestFor(before, [...byId.values()], destId, collisionPolicy);
          if (request.fallback) {
            fallbacks.set(request.fallback, (fallbacks.get(request.fallback) || 0) + 1);
          }
          const response = await api(`/files/${id}`, {
            method: "PATCH",
            body: JSON.stringify(request.body),
          });
          moved += 1;
          const finalName = String(response?.file?.name || "");
          if (finalName && finalName !== before?.name) renamed.push(finalName);
          if (request.targetId) {
            if (response?.file?.id === request.targetId) replaced += 1;
            else unconfirmedReplacements += 1;
          }
        } catch (error) {
          if (collisionPolicy === "cancel" && error?.status === 409) canceled += 1;
          else failed += 1;
        }
      }
      state.bulkSelectedIds = [];
      state.selectionAnchorIndex = null;
      if (state.selectedFile && targets.includes(state.selectedFile.id)) {
        state.selectedFile = null;
        state.selectedPreview = null;
        state.selectedMetadata = null;
      }
      await loadManifest(state.currentWorkspace.id);
      const label = destName || "My Drive";
      if (moved) {
        let message = `Moved ${moved} ${moved === 1 ? "item" : "items"} to ${label}.`;
        if (renamed.length === 1) message += ` Kept both as ${renamed[0]}.`;
        else if (renamed.length > 1) message += ` Kept both for ${renamed.length} items.`;
        if (replaced) message += ` Replaced ${replaced} matching ${replaced === 1 ? "file" : "files"}.`;
        if (unconfirmedReplacements) message += " A replacement response could not be confirmed; the list was refreshed.";
        if (fallbacks.get("no_target")) message += " No matching file existed for the requested replacement; Keep both was used for any later collision.";
        if (fallbacks.get("unavailable_target")) message += " The replacement target was no longer available; Keep both was used.";
        if (fallbacks.get("folder")) message += " Folders cannot replace an occupied destination; Keep both was used.";
        if (canceled) message += ` ${canceled} collision${canceled === 1 ? " was" : "s were"} canceled.`;
        if (failed) message += ` ${failed} failed.`;
        showToast(message);
      } else if (canceled) {
        showToast(`Canceled ${canceled === 1 ? "the move" : `${canceled} moves`} because a name already exists.`);
      } else if (failed) {
        showToast(`Couldn't move ${failed === 1 ? "the file" : "files"} to ${label}.`);
      }
    }

    function openDialog(fileIds) {
      const ids = (fileIds || []).filter(Boolean);
      if (!ids.length || !els.moveDialog) return;
      if (!canWrite()) {
        showToast("You can't move files in this workspace.");
        return;
      }
      const scopedRoot = state.currentWorkspace?.scoped_root;
      if (scopedRoot && (scopedRoot.kind !== "folder" || ids.includes(scopedRoot.id))) {
        showToast("You can't move the shared root. Move an item inside a shared folder instead.");
        return;
      }
      closeFileMenu();
      const byId = fileNodesById();
      const exclude = new Set();
      for (const id of ids) {
        const node = byId.get(id);
        if (node?.kind === "folder") {
          exclude.add(id);
          for (const descendant of folderDescendantIds(id)) exclude.add(descendant);
        }
      }
      setReplaceAvailability(ids, byId);
      els.moveDialogTitle.textContent = ids.length === 1 ? "Move to…" : `Move ${ids.length} items to…`;
      els.moveDialogList.replaceChildren();
      const selectedPolicy = () => policy(els.moveCollisionPolicy?.value);
      const rootId = scopedRoot?.id || null;
      const rootName = scopedRoot?.name || "My Drive";
      if (rootId) exclude.add(rootId);
      const rootButton = makeOption(`${rootName} (root)`, 0, { isRoot: true });
      rootButton.addEventListener("click", () => {
        closeDialog();
        moveFilesToDestination(ids, rootId, rootName, selectedPolicy()).catch((error) => showToast(error.message));
      });
      els.moveDialogList.append(rootButton);
      for (const dest of buildDestinations(exclude)) {
        const button = makeOption(dest.name, dest.depth + 1);
        button.addEventListener("click", () => {
          closeDialog();
          moveFilesToDestination(ids, dest.id, dest.name, selectedPolicy()).catch((error) => showToast(error.message));
        });
        els.moveDialogList.append(button);
      }
      els.moveDialog.hidden = false;
      state.moveDialogOpen = true;
      rootButton.focus();
    }

    return Object.freeze({ closeDialog, moveFilesToDestination, openDialog });
  }

  window.ShellXDriveFileMoves = Object.freeze({ createController, moveRequestFor });
})();
