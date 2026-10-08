// Bounded file-browser ordering, filtering, pagination, and preference state.
// Kept outside drive.js so large-folder rules remain testable without the app.

(() => {
  const PAGE_SIZE = 100;
  const SORT_KEYS = new Set(["name", "modified", "size", "type"]);
  const DIRECTIONS = new Set(["asc", "desc"]);
  const TYPE_FILTERS = new Set([
    "all",
    "folders",
    "docs",
    "sheets",
    "pdfs",
    "images",
    "videos",
    "audio",
    "archives",
  ]);
  const OWNER_SCOPES = new Set(["any", "owned", "shared"]);
  const MODIFIED_RANGES = new Set(["any", "7", "30", "365"]);
  const LOCATION_SCOPES = new Set(["any", "workspace", "folder"]);
  const STATE_FILTERS = new Set(["any", "shared", "starred", "offline"]);
  const LAYOUTS = new Set(["list", "grid"]);
  const STORAGE_PREFIX = "shellx-drive-browser:v2:";
  const LEGACY_STORAGE_PREFIX = "shellx-drive-browser:";

  function defaults() {
    return {
      sortKey: "name",
      direction: "asc",
      foldersFirst: true,
      typeFilter: "all",
      ownerScope: "any",
      modifiedRange: "any",
      locationScope: "any",
      stateFilter: "any",
      layout: "list",
      folderId: null,
    };
  }

  function choice(value, allowed, fallback) {
    return allowed.has(String(value)) ? String(value) : fallback;
  }

  function normalizePreferences(input = {}) {
    const base = defaults();
    return {
      sortKey: choice(input.sortKey, SORT_KEYS, base.sortKey),
      direction: choice(input.direction, DIRECTIONS, base.direction),
      foldersFirst: input.foldersFirst !== false,
      typeFilter: choice(input.typeFilter, TYPE_FILTERS, base.typeFilter),
      ownerScope: choice(input.ownerScope, OWNER_SCOPES, base.ownerScope),
      modifiedRange: choice(input.modifiedRange, MODIFIED_RANGES, base.modifiedRange),
      locationScope: choice(input.locationScope, LOCATION_SCOPES, base.locationScope),
      stateFilter: choice(input.stateFilter, STATE_FILTERS, base.stateFilter),
      layout: choice(input.layout, LAYOUTS, base.layout),
      folderId: typeof input.folderId === "string" && input.folderId ? input.folderId : null,
    };
  }

  function normalizeActor(actor) {
    return String(actor || "local").trim().toLocaleLowerCase() || "local";
  }

  function actorStoragePrefix(actor) {
    return `${STORAGE_PREFIX}${encodeURIComponent(normalizeActor(actor))}:`;
  }

  function storageKey(actor, workspaceId) {
    return `${actorStoragePrefix(actor)}${encodeURIComponent(workspaceId || "global")}`;
  }

  function loadPreferences(storage, actor, workspaceId) {
    if (workspaceId === undefined) {
      workspaceId = actor;
      actor = "public";
    }
    try {
      const raw = storage?.getItem(storageKey(actor, workspaceId));
      return normalizePreferences(raw ? JSON.parse(raw) : {});
    } catch {
      return defaults();
    }
  }

  function savePreferences(storage, actor, workspaceId, preferences) {
    if (preferences === undefined && workspaceId && typeof workspaceId === "object") {
      preferences = workspaceId;
      workspaceId = actor;
      actor = "public";
    }
    const normalized = normalizePreferences(preferences);
    try {
      storage?.setItem(storageKey(actor, workspaceId), JSON.stringify(normalized));
    } catch {
      // Private browsing/storage denial must not disable the file browser.
    }
    return normalized;
  }

  function clearActorPreferences(storage, actor) {
    try {
      const prefix = actorStoragePrefix(actor);
      const keys = [];
      for (let index = 0; index < Number(storage?.length || 0); index += 1) {
        const key = storage.key(index);
        const legacy = key?.startsWith(LEGACY_STORAGE_PREFIX) && !key.startsWith(STORAGE_PREFIX);
        if (key?.startsWith(prefix) || legacy) keys.push(key);
      }
      for (const key of keys) storage?.removeItem(key);
    } catch {
      // Storage cleanup is best-effort when the browser denies persistence.
    }
  }

  function extension(file) {
    const match = String(file?.name || "").toLowerCase().match(/\.([^.]+)$/);
    return match ? match[1] : "";
  }

  function typeGroup(file) {
    if (file?.kind === "folder") return "folders";
    const ext = extension(file);
    if (["doc", "docx", "md", "odt", "rtf", "txt"].includes(ext)) return "docs";
    if (["csv", "ods", "xls", "xlsx"].includes(ext)) return "sheets";
    if (ext === "pdf") return "pdfs";
    if (["bmp", "gif", "jpeg", "jpg", "png", "webp"].includes(ext)) return "images";
    if (["mkv", "mov", "mp4", "webm"].includes(ext)) return "videos";
    if (["flac", "m4a", "mp3", "ogg", "wav"].includes(ext)) return "audio";
    if (["7z", "gz", "rar", "tar", "zip"].includes(ext)) return "archives";
    return "other";
  }

  function logicalSize(file) {
    const value = Number(file?.kind === "folder" ? file.folder_size_bytes : file?.size_bytes);
    return Number.isFinite(value) && value >= 0 ? value : null;
  }

  function contextValue(collection, key) {
    // Feature/unit harnesses can pass cross-realm Map/Set values, where
    // `instanceof` is false even though the collection contract is valid.
    if (typeof collection?.get === "function") return collection.get(key);
    if (typeof collection?.has === "function") return collection.has(key);
    return collection?.[key];
  }

  function belongsToFolderScope(file, context) {
    if (!context.currentWorkspaceId || file.workspace_id !== context.currentWorkspaceId) return false;
    if (!context.currentFolderId) return true;
    const nodes = context.nodesById;
    let parentId = file.parent_id || null;
    const seen = new Set();
    while (parentId && !seen.has(parentId)) {
      if (parentId === context.currentFolderId) return true;
      seen.add(parentId);
      parentId = contextValue(nodes, parentId)?.parent_id || null;
    }
    return false;
  }

  function matchesFilters(file, preferences, context) {
    if (preferences.typeFilter !== "all" && typeGroup(file) !== preferences.typeFilter) {
      return false;
    }
    const role = contextValue(context.workspaceRoleById, file.workspace_id);
    // Account-wide browse rows carry their own access relationship. Retaining
    // the workspace-role fallback keeps the existing single-workspace manifest
    // browser compatible with older servers and sync clients.
    const owned =
      typeof file?.owned_by_actor === "boolean" ? file.owned_by_actor : role === "owner";
    if (preferences.ownerScope === "owned" && !owned) return false;
    if (preferences.ownerScope === "shared" && owned) return false;

    if (preferences.modifiedRange !== "any") {
      const modified = Date.parse(file.updated_at);
      const now = Number.isFinite(context.now) ? context.now : Date.now();
      const cutoff = now - Number(preferences.modifiedRange) * 86_400_000;
      if (!Number.isFinite(modified) || modified < cutoff) return false;
    }

    if (
      preferences.locationScope === "workspace" &&
      file.workspace_id !== context.currentWorkspaceId
    ) {
      return false;
    }
    if (preferences.locationScope === "folder" && !belongsToFolderScope(file, context)) {
      return false;
    }

    if (preferences.stateFilter === "shared" && !contextValue(context.sharedIds, file.id)) {
      return false;
    }
    if (preferences.stateFilter === "starred" && !file.starred) return false;
    if (preferences.stateFilter === "offline" && !contextValue(context.offlineIds, file.id)) {
      return false;
    }
    return true;
  }

  function comparePrimary(left, right, sortKey) {
    if (sortKey === "modified") {
      return (Date.parse(left.updated_at) || 0) - (Date.parse(right.updated_at) || 0);
    }
    if (sortKey === "size") {
      const leftSize = logicalSize(left);
      const rightSize = logicalSize(right);
      if (leftSize === null && rightSize === null) return 0;
      if (leftSize === null) return 1;
      if (rightSize === null) return -1;
      return leftSize - rightSize;
    }
    if (sortKey === "type") {
      const type = typeGroup(left).localeCompare(typeGroup(right));
      if (type !== 0) return type;
    }
    return String(left.name || "").localeCompare(String(right.name || ""), undefined, {
      numeric: true,
      sensitivity: "base",
    });
  }

  function organize(files, inputPreferences = {}, context = {}) {
    const preferences = normalizePreferences(inputPreferences);
    return (files || [])
      .filter((file) => matchesFilters(file, preferences, context))
      .map((file, index) => ({ file, index }))
      .sort((left, right) => {
        if (preferences.foldersFirst && left.file.kind !== right.file.kind) {
          return left.file.kind === "folder" ? -1 : 1;
        }
        const primary = comparePrimary(left.file, right.file, preferences.sortKey);
        if (primary !== 0) return preferences.direction === "desc" ? -primary : primary;
        const name = String(left.file.name || "").localeCompare(String(right.file.name || ""));
        return name || left.index - right.index;
      })
      .map((entry) => entry.file);
  }

  function paginate(files, requestedPage = 0, pageSize = PAGE_SIZE) {
    const size = Math.max(1, Math.min(PAGE_SIZE, Number(pageSize) || PAGE_SIZE));
    const total = files?.length || 0;
    const pageCount = Math.max(1, Math.ceil(total / size));
    const page = Math.max(0, Math.min(pageCount - 1, Number(requestedPage) || 0));
    const offset = page * size;
    const items = (files || []).slice(offset, offset + size);
    return {
      items,
      page,
      pageCount,
      total,
      start: total === 0 ? 0 : offset + 1,
      end: offset + items.length,
      pageSize: size,
    };
  }

  // State-changing bulk controls are only available when every selected row is
  // compatible with the requested transition. Keep this pure and shared so a
  // stale DOM state cannot turn a mixed selection into a network request.
  function bulkActionAvailability(files, selectedIds, options = {}) {
    const ids = [...new Set(Array.from(selectedIds || []))];
    const byId = new Map((files || []).map((file) => [file.id, file]));
    const selected = ids.map((id) => byId.get(id)).filter(Boolean);
    const complete = selected.length === ids.length;
    const hasSelection = complete && selected.length > 0;
    const writable = hasSelection && options.canWrite === true && options.accountBrowse !== true;
    const every = (predicate) => hasSelection && selected.every(predicate);

    return {
      selected,
      hasSelection,
      download: hasSelection && options.accountBrowse !== true,
      move: writable && every((file) => !file.trashed),
      trash: writable && every((file) => !file.trashed),
      restore: writable && every((file) => file.trashed),
      star: writable && every((file) => !file.starred),
      unstar: writable && every((file) => file.starred),
    };
  }

  const api = Object.freeze({
    PAGE_SIZE,
    clearActorPreferences,
    bulkActionAvailability,
    defaults,
    loadPreferences,
    logicalSize,
    normalizePreferences,
    organize,
    paginate,
    savePreferences,
    storageKey,
    typeGroup,
  });
  if (typeof window !== "undefined") window.ShellXDriveBrowser = api;
  else globalThis.ShellXDriveBrowser = api;
})();
