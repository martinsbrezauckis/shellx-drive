// ShellX Drive public share browser.
// All capability reads stay on the current origin; the password is used only
// for the initial X-Share-Password check, then a short-lived token takes over.

const app = document.getElementById("public-share-app");

if (app) {
  const state = {
    shareId: app.dataset.shareId || "",
    metadata: null,
    currentPath: "",
    folderPage: 0,
    folderQuery: "",
    browserPreferences: window.ShellXDriveBrowser.loadPreferences(
      sessionStorage,
      "public-share",
    ),
    selectedPaths: new Set(),
    thumbnailGeneration: 0,
    thumbnailUrls: new Set(),
    thumbnailLoads: 0,
    thumbnailWaiters: [],
  };

  const els = {
    rootIcon: document.getElementById("share-root-icon"),
    rootTitle: document.getElementById("share-title"),
    rootMeta: document.getElementById("share-root-meta"),
    accessPanel: document.getElementById("share-access-panel"),
    accessForm: document.getElementById("share-access-form"),
    password: document.getElementById("share-password"),
    accessButton: document.getElementById("share-access-button"),
    status: document.getElementById("share-status"),
    filePanel: document.getElementById("shared-file-panel"),
    fileVisual: document.getElementById("shared-file-visual"),
    fileName: document.getElementById("shared-file-name"),
    fileAttributes: document.getElementById("shared-file-attributes"),
    filePreview: document.getElementById("shared-file-preview"),
    fileDownload: document.getElementById("shared-file-download"),
    fileUnavailable: document.getElementById("shared-file-unavailable"),
    folderPanel: document.getElementById("shared-folder-panel"),
    breadcrumb: document.getElementById("share-breadcrumb"),
    folderCount: document.getElementById("share-folder-count"),
    folderSearch: document.getElementById("share-folder-search"),
    folderSort: document.getElementById("share-folder-sort"),
    folderSortDirection: document.getElementById("share-folder-sort-direction"),
    foldersFirst: document.getElementById("share-folders-first"),
    layoutList: document.getElementById("share-layout-list"),
    layoutGrid: document.getElementById("share-layout-grid"),
    selectVisible: document.getElementById("share-select-visible"),
    selectionCount: document.getElementById("share-selection-count"),
    selectionClear: document.getElementById("share-selection-clear"),
    selectionDownload: document.getElementById("share-selection-download"),
    selectionToolbar: document.querySelector(".share-selection-toolbar"),
    entryList: document.getElementById("share-entry-list"),
    folderPagination: document.getElementById("share-folder-pagination"),
    folderPagePrevious: document.getElementById("share-folder-page-previous"),
    folderPagePosition: document.getElementById("share-folder-page-position"),
    folderPageNext: document.getElementById("share-folder-page-next"),
    folderEmpty: document.getElementById("share-folder-empty"),
    folderEmptyTitle: document.getElementById("share-folder-empty-title"),
    folderEmptyCopy: document.getElementById("share-folder-empty-copy"),
    emptyFolderIcon: document.querySelector(".empty-folder-icon"),
    previewModal: document.getElementById("share-preview-modal"),
    previewTitle: document.getElementById("share-preview-title"),
    previewBody: document.getElementById("share-preview-body"),
    previewClose: document.getElementById("share-preview-close"),
    previewDownload: document.getElementById("share-preview-download"),
    previewPrevious: document.getElementById("share-preview-previous"),
    previewNext: document.getElementById("share-preview-next"),
    previewPosition: document.getElementById("share-preview-position"),
  };

  const access = window.ShellXPublicShareAccess.createController({
    passwordInput: els.password,
  });

  const previewController = window.ShellXPublicPreview?.createController({
    shareId: state.shareId,
    getAccessToken: access.token,
    onAccessTokenInvalid: discardInvalidAccessToken,
    modal: els.previewModal,
    title: els.previewTitle,
    body: els.previewBody,
    closeButton: els.previewClose,
    downloadButton: els.previewDownload,
    previousButton: els.previewPrevious,
    nextButton: els.previewNext,
    position: els.previewPosition,
    getSequence: () => browserChildren(state.currentPath),
    onDownload: (entry, button) => downloadEntry(entry, button),
    onStatus: setStatus,
  });

  /** Build a small, consistent SVG icon without interpolating user content. */
  function makeIcon(kind, name = "") {
    const type = iconType(kind, name);
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.75");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    const paths = {
      folder: ["M3.5 6.5h6l2 2h9v9.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z", "M3.5 9h17"],
      image: ["M5 3.5h14a1.5 1.5 0 0 1 1.5 1.5v14a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 19V5A1.5 1.5 0 0 1 5 3.5z", "m5.5 17 4.25-4.5 3.2 3.1 2.2-2.1 3.35 3.5", "M8.2 8.2h.01"],
      video: ["M4.5 5.5h11v13h-11z", "m15.5 10 4-2v8l-4-2z"],
      audio: ["M9 18V6l9-2v12", "M9 16.5c-3-1-5.5.3-5.5 2S6 21.5 9 20.5", "M18 14.5c-3-1-5.5.3-5.5 2s2.5 3 5.5 2"],
      document: ["M6 2.5h8l4 4v15H6z", "M14 2.5v4h4", "M9 12h6", "M9 16h6"],
      archive: ["M6 2.5h12v19H6z", "M10 2.5v3h4v3h-4v3h4", "M10 16h4"],
      code: ["M6 2.5h8l4 4v15H6z", "m10 12 2 2-2 2", "m8 12-2 2 2 2"],
      sheet: ["M6 2.5h8l4 4v15H6z", "M8.5 11h7v7h-7z", "M12 11v7", "M8.5 14.5h7"],
      pdf: ["M6 2.5h8l4 4v15H6z", "M14 2.5v4h4", "M8.5 16.5v-5h2a1.5 1.5 0 0 1 0 3h-2", "M13 11.5h1.2c1.5 0 2.3.9 2.3 2.5s-.8 2.5-2.3 2.5H13z"],
    }[type] || ["M6 2.5h8l4 4v15H6z", "M14 2.5v4h4"];
    for (const d of paths) {
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", d);
      svg.append(path);
    }
    return svg;
  }

  function iconType(kind, name) {
    if (kind === "folder") return "folder";
    const extension = String(name).split(".").pop()?.toLowerCase() || "";
    if (["png", "jpg", "jpeg", "gif", "webp", "bmp"].includes(extension)) return "image";
    if (extension === "pdf") return "pdf";
    if (["mp4", "webm", "mov"].includes(extension)) return "video";
    if (["mp3", "wav", "ogg", "m4a"].includes(extension)) return "audio";
    if (["csv", "xls", "xlsx", "ods"].includes(extension)) return "sheet";
    if (["zip", "tar", "gz", "7z", "rar"].includes(extension)) return "archive";
    if (["js", "ts", "rs", "py", "go", "json", "html", "css"].includes(extension)) return "code";
    return "document";
  }

  function formatSize(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes)) return "—";
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let size = bytes / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
    return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
  }

  function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Unknown";
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function formatExpiry(value) {
    return value ? `Expires ${formatDate(value)}` : "No expiry";
  }

  function fileTypeLabel(name, kind = "file") {
    if (kind === "folder") return "Folder";
    const extension = String(name).split(".").pop()?.toUpperCase();
    return extension && extension !== String(name).toUpperCase() ? `${extension} file` : "File";
  }

  function requestHeaders() {
    return access.requestHeaders();
  }

  function setStatus(message = "", type = "") {
    els.status.textContent = message;
    els.status.dataset.state = type;
  }

  async function fetchMetadata(password = "") {
    const headers = password ? { "x-share-password": password } : {};
    const response = await fetch(`/pub/shares/${encodeURIComponent(state.shareId)}?format=json`, { headers });
    if (!response.ok) {
      if (response.status === 401) throw new Error("That password did not match. Try again.");
      if (response.status === 429) throw new Error("Too many attempts. Wait a few minutes and try again.");
      throw new Error("This share is unavailable or has expired.");
    }
    return response.json();
  }

  function discardInvalidAccessToken(responseOrError) {
    if (!access.discardUnauthorized(responseOrError)) return false;
    if (!state.metadata?.requires_password) return true;
    state.metadata = null;
    state.currentPath = "";
    state.folderPage = 0;
    state.folderQuery = "";
    state.selectedPaths.clear();
    clearThumbnailUrls();
    previewController?.close();
    els.filePanel.hidden = true;
    els.folderPanel.hidden = true;
    els.accessPanel.hidden = false;
    setStatus("Share access expired. Enter the link password to continue.", "error");
    els.password.focus();
    return true;
  }

  function renderRoot(metadata) {
    if (els.rootTitle) els.rootTitle.textContent = metadata.name;
    document.title = `${metadata.name} · ShellX Drive Share`;
    els.rootIcon.replaceChildren(makeIcon(metadata.kind, metadata.name));
    els.rootMeta.replaceChildren();
    const values = [
      metadata.kind === "folder" ? "Folder" : fileTypeLabel(metadata.name),
      metadata.kind === "folder"
        ? metadata.folder_size_bytes === null || metadata.folder_size_bytes === undefined
          ? "Size unavailable"
          : `${formatSize(metadata.folder_size_bytes)} contents`
        : formatSize(metadata.size_bytes),
      formatExpiry(metadata.expires_at),
      metadata.max_uses === null || metadata.max_uses === undefined
        ? "Unlimited visits"
        : `${metadata.uses_remaining} of ${metadata.max_uses} visits remaining`,
      `Modified ${formatDate(metadata.updated_at)}`,
    ];
    values.forEach((value, index) => {
      const span = document.createElement("span");
      span.textContent = value;
      if (index === 1) {
        const logicalSize = metadata.kind === "folder"
          ? metadata.folder_size_bytes
          : metadata.size_bytes;
        const exactSize = Number(logicalSize);
        if (Number.isSafeInteger(exactSize) && exactSize >= 0) {
          const label = `${exactSize.toLocaleString()} ${exactSize === 1 ? "byte" : "bytes"}${metadata.kind === "folder" ? " in folder contents" : ""}`;
          span.title = label;
          span.setAttribute("aria-label", label);
        }
      }
      els.rootMeta.append(span);
    });
  }

  function addAttribute(term, description) {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = term;
    dd.textContent = description;
    els.fileAttributes.append(dt, dd);
  }

  function renderFile(metadata) {
    const thumbnailGeneration = clearThumbnailUrls();
    els.folderPanel.hidden = true;
    els.filePanel.hidden = false;
    els.fileName.textContent = metadata.name;
    els.fileVisual.replaceChildren(makeIcon("file", metadata.name));
    els.fileAttributes.replaceChildren();
    addAttribute("Type", fileTypeLabel(metadata.name));
    addAttribute("Size", formatSize(metadata.size_bytes));
    addAttribute("Modified", formatDate(metadata.updated_at));
    addAttribute("Access", "Read only");
    if (metadata.recipient_note) addAttribute("Owner note", metadata.recipient_note);
    const rootEntry = { ...metadata, path: "" };
    const previewable = Boolean(previewController?.canPreview(rootEntry));
    const unavailable = !previewable && !metadata.allow_download;
    els.filePreview.hidden = !previewable;
    els.filePreview.onclick = () => previewController?.open(rootEntry, els.filePreview);
    els.fileDownload.hidden = !metadata.allow_download;
    els.fileUnavailable.hidden = !unavailable;
    els.previewDownload.hidden = !metadata.allow_download;
    if (iconType("file", metadata.name) === "image") {
      loadThumbnail(null, els.fileVisual, thumbnailGeneration).catch(() => {});
    }
  }

  function directChildren(path) {
    const prefix = path ? `${path}/` : "";
    return (state.metadata?.entries || [])
      .filter((entry) => {
        if (!entry.path.startsWith(prefix)) return false;
        return !entry.path.slice(prefix.length).includes("/");
      });
  }

  function persistBrowserPreferences() {
    state.browserPreferences = window.ShellXDriveBrowser.savePreferences(
      sessionStorage,
      "public-share",
      state.browserPreferences,
    );
  }

  function syncBrowserControls() {
    const preferences = state.browserPreferences;
    els.folderSort.value = preferences.sortKey;
    els.foldersFirst.checked = preferences.foldersFirst;
    const descending = preferences.direction === "desc";
    els.folderSortDirection.textContent = descending ? "Descending" : "Ascending";
    els.folderSortDirection.setAttribute("aria-pressed", String(descending));
    const list = preferences.layout === "list";
    els.layoutList.setAttribute("aria-pressed", String(list));
    els.layoutGrid.setAttribute("aria-pressed", String(!list));
    els.folderPanel.dataset.layout = preferences.layout;
  }

  function setBrowserPreference(key, value) {
    state.browserPreferences = window.ShellXDriveBrowser.normalizePreferences({
      ...state.browserPreferences,
      [key]: value,
    });
    state.folderPage = 0;
    persistBrowserPreferences();
    syncBrowserControls();
    renderFolderPage();
  }

  function browserChildren(path = state.currentPath) {
    const query = state.folderQuery.trim().toLocaleLowerCase();
    const filtered = directChildren(path).filter(
      (entry) => !query || entry.name.toLocaleLowerCase().includes(query),
    );
    return window.ShellXDriveBrowser.organize(filtered, state.browserPreferences);
  }

  function renderBreadcrumb() {
    els.breadcrumb.replaceChildren();
    const segments = state.currentPath ? state.currentPath.split("/") : [];
    const root = document.createElement("button");
    root.type = "button";
    root.textContent = state.metadata.name;
    if (!segments.length) root.setAttribute("aria-current", "page");
    root.addEventListener("click", () => openFolder(""));
    els.breadcrumb.append(root);
    let built = "";
    segments.forEach((segment, index) => {
      const separator = document.createElement("span");
      separator.textContent = "/";
      built = built ? `${built}/${segment}` : segment;
      const destination = built;
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = segment;
      if (index === segments.length - 1) button.setAttribute("aria-current", "page");
      button.addEventListener("click", () => openFolder(destination));
      els.breadcrumb.append(separator, button);
    });
  }

  function makeEntryRow(entry, thumbnailGeneration) {
    const row = document.createElement("article");
    row.className = "share-entry-row";
    row.dataset.entryKind = entry.kind;
    row.dataset.entryPath = entry.path;

    const selectionEnabled = Boolean(state.metadata?.allow_download);
    if (!selectionEnabled) row.classList.add("preview-only");
    let selection = null;
    if (selectionEnabled) {
      selection = document.createElement("input");
      selection.type = "checkbox";
      selection.className = "share-entry-selection";
      selection.checked = state.selectedPaths.has(entry.path);
      selection.setAttribute("aria-label", `Select ${entry.name}`);
      selection.addEventListener("change", () => {
        if (selection.checked) state.selectedPaths.add(entry.path);
        else state.selectedPaths.delete(entry.path);
        syncSelectionUi();
      });
    }

    const main = document.createElement("button");
    main.type = "button";
    main.className = "share-entry-main";
    const previewable = Boolean(previewController?.canPreview(entry));
    main.setAttribute(
      "aria-label",
      entry.kind === "folder"
        ? `Open ${entry.name}`
        : previewable
          ? `Preview ${entry.name}`
          : `Download ${entry.name}`,
    );

    const visual = document.createElement("span");
    visual.className = `share-entry-visual${entry.kind === "folder" ? " folder" : ""}`;
    visual.append(makeIcon(entry.kind, entry.name));
    const copy = document.createElement("span");
    copy.className = "share-entry-copy";
    const title = document.createElement("strong");
    title.textContent = entry.name;
    title.title = entry.name;
    const type = document.createElement("span");
    type.textContent = fileTypeLabel(entry.name, entry.kind);
    copy.append(title, type);
    main.append(visual, copy);

    const modified = document.createElement("span");
    modified.className = "share-entry-modified";
    modified.textContent = formatDate(entry.updated_at);
    const size = document.createElement("span");
    size.className = "share-entry-size";
    const logicalSize = entry.kind === "folder" ? entry.folder_size_bytes : entry.size_bytes;
    size.textContent = formatSize(logicalSize);
    const exactSize = Number(logicalSize);
    if (Number.isSafeInteger(exactSize) && exactSize >= 0) {
      const label = `${exactSize.toLocaleString()} ${exactSize === 1 ? "byte" : "bytes"}${entry.kind === "folder" ? " in folder contents" : ""}`;
      size.title = label;
      size.setAttribute("aria-label", label);
    } else {
      size.title = "Size unavailable";
      size.setAttribute("aria-label", "Size unavailable");
    }
    const action = document.createElement("button");
    action.type = "button";
    action.className = "share-entry-action";
    action.textContent = entry.kind === "folder" ? "Open" : "Download";
    if (entry.kind === "file" && !state.metadata.allow_download) action.hidden = true;
    if (entry.kind === "file" && !previewable && !state.metadata.allow_download) {
      main.disabled = true;
      main.setAttribute("aria-label", `Preview and download unavailable for ${entry.name}. Ask the link owner for a downloadable version.`);
      action.hidden = false;
      action.disabled = true;
      action.textContent = "Unavailable";
      action.title = "Preview and download are unavailable. Ask the link owner for a downloadable version.";
    }

    const activateMain = () => {
      if (entry.kind === "folder") openFolder(entry.path);
      else if (previewable) previewController.open(entry, main);
      else if (state.metadata.allow_download) downloadEntry(entry, action).catch((error) => setStatus(error.message, "error"));
    };
    const activateAction = () => {
      if (entry.kind === "folder") openFolder(entry.path);
      else downloadEntry(entry, action).catch((error) => setStatus(error.message, "error"));
    };
    main.addEventListener("click", activateMain);
    action.addEventListener("click", activateAction);
    row.append(...(selection ? [selection] : []), main, modified, size, action);

    if (entry.kind === "file" && iconType(entry.kind, entry.name) === "image") {
      loadThumbnail(entry.path, visual, thumbnailGeneration).catch(() => {});
    }
    return row;
  }

  function openFolder(path) {
    state.currentPath = path;
    state.folderPage = 0;
    state.selectedPaths.clear();
    renderBreadcrumb();
    const children = browserChildren(path);
    renderFolderPage(children);
  }

  function renderFolderPage(children = browserChildren()) {
    const thumbnailGeneration = clearThumbnailUrls();
    const unfilteredCount = directChildren(state.currentPath).length;
    const page = window.ShellXDriveBrowser.paginate(children, state.folderPage);
    state.folderPage = page.page;
    const filtered = state.folderQuery.trim() && page.total !== unfilteredCount;
    const totalLabel = filtered ? `${page.total} of ${unfilteredCount} items` : `${page.total} ${page.total === 1 ? "item" : "items"}`;
    const showing = page.total > page.pageSize ? ` · Showing ${page.start}–${page.end}` : "";
    els.folderCount.textContent = `${totalLabel}${showing}`;
    els.entryList.replaceChildren(
      ...page.items.map((entry) => makeEntryRow(entry, thumbnailGeneration)),
    );
    els.folderEmpty.hidden = page.total !== 0;
    els.folderEmptyTitle.textContent = unfilteredCount ? "No matching items" : "This folder is empty";
    els.folderEmptyCopy.textContent = unfilteredCount
      ? "Try a different search in this folder."
      : "There are no files or subfolders here.";
    els.folderPagination.hidden = page.pageCount <= 1;
    els.folderPagePrevious.disabled = page.page <= 0;
    els.folderPageNext.disabled = page.page >= page.pageCount - 1;
    els.folderPagePosition.textContent = `Page ${page.page + 1} of ${page.pageCount}`;
    syncSelectionUi(children);
  }

  function syncSelectionUi(children = browserChildren(state.currentPath)) {
    if (!state.metadata?.allow_download) {
      state.selectedPaths.clear();
      return;
    }
    const visiblePaths = new Set(children.map((entry) => entry.path));
    for (const path of [...state.selectedPaths]) {
      if (!visiblePaths.has(path)) state.selectedPaths.delete(path);
    }
    const count = state.selectedPaths.size;
    els.selectionCount.textContent = count
      ? `${count} ${count === 1 ? "item" : "items"} selected`
      : "No items selected";
    els.selectionDownload.disabled = count === 0;
    els.selectionClear.hidden = count === 0;
    els.selectVisible.disabled = children.length === 0;
    els.selectVisible.checked = children.length > 0 && count === children.length;
    els.selectVisible.indeterminate = count > 0 && count < children.length;
    els.entryList.querySelectorAll(".share-entry-row").forEach((row) => {
      const selected = state.selectedPaths.has(row.dataset.entryPath || "");
      row.classList.toggle("selected", selected);
      const checkbox = row.querySelector(".share-entry-selection");
      if (checkbox) checkbox.checked = selected;
    });
  }

  async function downloadSelection() {
    const paths = [...state.selectedPaths];
    if (!paths.length) return;
    els.selectionDownload.disabled = true;
    setStatus(`Preparing ${paths.length} ${paths.length === 1 ? "item" : "items"}…`);
    try {
      await window.ShellXDownloadTickets.start({
        endpoint: `/pub/shares/${encodeURIComponent(state.shareId)}/download-zip`,
        body: { base_path: state.currentPath, paths },
        headers: requestHeaders(),
      });
      setStatus("Your ZIP download is starting.");
    } catch (error) {
      if (!discardInvalidAccessToken(error)) throw error;
    } finally {
      syncSelectionUi();
    }
  }

  function renderFolder(metadata) {
    els.filePanel.hidden = true;
    els.folderPanel.hidden = false;
    state.currentPath = "";
    state.selectedPaths.clear();
    els.selectionToolbar.hidden = !metadata.allow_download;
    els.folderPanel.classList.toggle("preview-only", !metadata.allow_download);
    els.previewDownload.hidden = !metadata.allow_download;
    syncBrowserControls();
    openFolder("");
  }

  function clearThumbnailUrls() {
    state.thumbnailGeneration += 1;
    for (const url of state.thumbnailUrls) URL.revokeObjectURL(url);
    state.thumbnailUrls.clear();
    return state.thumbnailGeneration;
  }

  function acquireThumbnailSlot() {
    if (state.thumbnailLoads < 6) {
      state.thumbnailLoads += 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => state.thumbnailWaiters.push(resolve));
  }

  function releaseThumbnailSlot() {
    const next = state.thumbnailWaiters.shift();
    if (next) next();
    else state.thumbnailLoads = Math.max(0, state.thumbnailLoads - 1);
  }

  function releaseThumbnailUrl(url) {
    if (!state.thumbnailUrls.delete(url)) return;
    URL.revokeObjectURL(url);
  }

  async function loadThumbnail(path, container, thumbnailGeneration) {
    await acquireThumbnailSlot();
    try {
      if (thumbnailGeneration !== state.thumbnailGeneration) return;
      const query = path ? `?${new URLSearchParams({ path })}` : "";
      const response = await fetch(`/pub/shares/${encodeURIComponent(state.shareId)}/thumbnail${query}`, {
        headers: requestHeaders(),
      });
      if (!response.ok) {
        discardInvalidAccessToken(response);
        return;
      }
      const url = URL.createObjectURL(await response.blob());
      if (thumbnailGeneration !== state.thumbnailGeneration || !container.isConnected) {
        URL.revokeObjectURL(url);
        return;
      }
      state.thumbnailUrls.add(url);
      const image = document.createElement("img");
      image.addEventListener("load", () => releaseThumbnailUrl(url), { once: true });
      image.addEventListener("error", () => releaseThumbnailUrl(url), { once: true });
      image.src = url;
      image.alt = "";
      container.replaceChildren(image);
    } finally {
      releaseThumbnailSlot();
    }
  }

  async function downloadEntry(entry, button) {
    if (!state.metadata?.allow_download) throw new Error("Downloads are disabled for this link.");
    button.disabled = true;
    setStatus(`Preparing ${entry.name}…`);
    try {
      await window.ShellXDownloadTickets.start({
        endpoint: `/pub/shares/${encodeURIComponent(state.shareId)}/download`,
        headers: requestHeaders(),
        body: { path: entry.path || null },
      });
      setStatus(`Download started for ${entry.name}.`);
    } catch (error) {
      if (!discardInvalidAccessToken(error)) throw error;
    } finally {
      button.disabled = false;
    }
  }

  function activate(metadata) {
    const { access_token: accessToken, ...shareMetadata } = metadata;
    const hasAccessToken = access.accept(accessToken);
    if (shareMetadata.requires_password && !hasAccessToken) {
      throw new Error("The protected share did not provide an access token. Try again.");
    }
    state.metadata = shareMetadata;
    renderRoot(shareMetadata);
    els.accessPanel.hidden = true;
    setStatus("");
    if (shareMetadata.kind === "folder") renderFolder(shareMetadata);
    else renderFile(shareMetadata);
  }

  els.accessForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    els.accessButton.disabled = true;
    setStatus("Checking password…");
    try {
      const password = els.password.value;
      const metadata = await fetchMetadata(password);
      activate(metadata);
    } catch (error) {
      setStatus(error.message, "error");
      els.password.select();
    } finally {
      els.accessButton.disabled = false;
    }
  });

  els.fileDownload.addEventListener("click", () => {
    if (!state.metadata) return;
    downloadEntry({ name: state.metadata.name, path: "" }, els.fileDownload)
      .catch((error) => setStatus(error.message, "error"));
  });

  els.selectVisible.addEventListener("change", () => {
    const children = browserChildren();
    state.selectedPaths.clear();
    if (els.selectVisible.checked) {
      children.forEach((entry) => state.selectedPaths.add(entry.path));
    }
    syncSelectionUi(children);
  });
  els.selectionClear.addEventListener("click", () => {
    state.selectedPaths.clear();
    syncSelectionUi();
  });
  els.selectionDownload.addEventListener("click", () => {
    downloadSelection().catch((error) => {
      setStatus(error?.message || "The selected items could not be downloaded.", "error");
      syncSelectionUi();
    });
  });
  els.folderPagePrevious.addEventListener("click", () => {
    state.folderPage = Math.max(0, state.folderPage - 1);
    renderFolderPage();
  });
  els.folderPageNext.addEventListener("click", () => {
    state.folderPage += 1;
    renderFolderPage();
  });
  els.folderSearch.addEventListener("input", () => {
    state.folderQuery = els.folderSearch.value;
    state.folderPage = 0;
    state.selectedPaths.clear();
    renderFolderPage();
  });
  els.folderSort.addEventListener("change", () => {
    setBrowserPreference("sortKey", els.folderSort.value);
  });
  els.folderSortDirection.addEventListener("click", () => {
    setBrowserPreference(
      "direction",
      state.browserPreferences.direction === "asc" ? "desc" : "asc",
    );
  });
  els.foldersFirst.addEventListener("change", () => {
    setBrowserPreference("foldersFirst", els.foldersFirst.checked);
  });
  els.layoutList.addEventListener("click", () => setBrowserPreference("layout", "list"));
  els.layoutGrid.addEventListener("click", () => setBrowserPreference("layout", "grid"));

  els.emptyFolderIcon?.append(makeIcon("folder"));
  window.addEventListener("pagehide", () => {
    access.clear();
    clearThumbnailUrls();
  });

  fetchMetadata("")
    .then((metadata) => {
      if (metadata.requires_password) {
        els.accessPanel.hidden = false;
        setStatus("Enter the link password to continue.");
        els.password.focus();
      } else {
        activate(metadata);
      }
    })
    .catch((error) => {
      els.accessPanel.hidden = true;
      setStatus(error.message, "error");
    });
}
