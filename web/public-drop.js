(() => {
  const app = document.getElementById("public-drop-app");
  if (!app) return;

  const dropId = app.dataset.dropId;
  const protectedDrop = app.dataset.passwordRequired === "true";
  const dropTitle = document.getElementById("drop-title");
  const password = document.getElementById("drop-password");
  const passwordSection = document.querySelector(".drop-auth");
  const passwordLabel = document.getElementById("drop-password-label");
  const passwordCheckButton = document.getElementById("drop-password-check-button");
  const passwordGuidance = document.getElementById("drop-password-guidance");
  const zone = document.getElementById("drop-zone");
  const filePicker = document.getElementById("file-picker");
  const folderPicker = document.getElementById("folder-picker");
  const progressRoot = document.getElementById("drop-progress");
  const queueRoot = document.getElementById("drop-upload-queue");
  const aggregateRoot = progressRoot.querySelector("[data-upload-aggregate]");
  const status = document.getElementById("drop-status");
  const progress = window.ShellXUploadProgress;
  const access = window.ShellXPublicDropAccess.createController({ passwordInput: password });
  const queue = [];
  const MAX_FILES_PER_SELECTION = 256;
  const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024;
  const CHUNK_BYTES = 8 * 1024 * 1024;
  let processing = false;
  let passwordVerified = false;

  function formatBytes(value) {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let scaled = bytes;
    let unit = -1;
    do {
      scaled /= 1024;
      unit += 1;
    } while (scaled >= 1024 && unit < units.length - 1);
    return `${scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)} ${units[unit]}`;
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function passwordHeader() {
    const bytes = new TextEncoder().encode(password.value);
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 8192) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
    }
    return btoa(binary);
  }

  function setPasswordVerified(verified) {
    passwordVerified = verified;
    if (!verified) access.reject();
    if (!verified && protectedDrop) {
      dropTitle.textContent = "Protected Drop";
      document.title = "ShellX Drive Drop · Protected Drop";
    }
    if (!protectedDrop) passwordSection.hidden = verified;
    zone.setAttribute("aria-disabled", String(!verified));
    zone.tabIndex = verified ? 0 : -1;
    filePicker.disabled = !verified;
    folderPicker.disabled = !verified;
    document.getElementById("choose-files").disabled = !verified;
    document.getElementById("choose-folder").disabled = !verified;
    passwordGuidance.textContent = protectedDrop
      ? verified ? "Password accepted. You can now choose files or folders." : "Check the password before choosing files."
      : "Retry connecting to this Drop before choosing files.";
  }

  function preflightError(response) {
    if (response.status === 423 || response.status === 429) {
      return "Too many attempts. Wait a few minutes and try again.";
    }
    return protectedDrop
      ? "We could not verify this Drop. Check the password or ask the sender for a new link."
      : "We could not open this Drop. Ask the sender for a new link or try again.";
  }

  async function verifyPassword() {
    if (protectedDrop && !password.value) {
      setStatus("Enter the Drop password first.", true);
      password.focus();
      return false;
    }
    passwordCheckButton.disabled = true;
    setStatus("Checking password…");
    try {
      const response = await fetch(`/pub/drops/${encodeURIComponent(dropId)}/preflight`, {
        method: "POST",
        headers: { "x-shellx-drop-password-b64": passwordHeader() },
      });
      if (!response.ok) {
        setPasswordVerified(false);
        setStatus(preflightError(response), true);
        if (protectedDrop) password.select();
        return false;
      }
      const grant = await response.json().catch(() => ({}));
      if (!grant.access_token) throw new Error("Drop grant was missing");
      if (!access.accept(grant.access_token)) throw new Error("Drop grant was missing");
      if (typeof grant.name !== "string") throw new Error("Drop name was missing");
      setPasswordVerified(true);
      dropTitle.textContent = grant.name;
      document.title = `ShellX Drive Drop · ${grant.name}`;
      setStatus(protectedDrop ? "Password accepted. Choose files or folders to upload." : "Drop ready. Choose files or folders to upload.");
      return true;
    } catch {
      setPasswordVerified(false);
      setStatus("We could not open this Drop. Check your connection and try again.", true);
      return false;
    } finally {
      passwordCheckButton.disabled = false;
    }
  }

  async function responseJson(response) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) {
        access.clear();
        setPasswordVerified(false);
      }
      throw new Error(body.message || `Upload request failed (${response.status})`);
    }
    return body;
  }

  function render() {
    progressRoot.hidden = queue.length === 0;
    queueRoot.replaceChildren(
      ...queue.map((item) => progress.buildRow(item, { formatBytes, escapeHtml, onRetry: retryUpload })),
    );
    progress.renderAggregate(aggregateRoot, progress.aggregateProgress(queue), { formatBytes });
  }

  function setStatus(message, error = false) {
    status.textContent = message;
    status.classList.toggle("error", error);
  }

  function displayError(error) {
    const message = error instanceof Error ? error.message : "Upload failed";
    return message.length > 180 ? `${message.slice(0, 177)}…` : message;
  }

  async function uploadItem(item) {
    item.status = "starting";
    item.statusLabel = "Starting secure upload";
    render();
    const headers = {
      "content-type": "application/json",
      ...access.requestHeaders(),
    };
    const created = await responseJson(
      await fetch(`/pub/drops/${encodeURIComponent(dropId)}/uploads`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          name: item.file.name,
          path: item.relativePath === item.file.name ? null : item.relativePath,
          total_size: item.file.size,
          content_type: item.file.type || "application/octet-stream",
        }),
      }),
    );
    item.sessionId = created.session.id;
    let offset = Number(created.session.received_bytes) || 0;

    do {
      const end = Math.min(item.file.size, offset + CHUNK_BYTES);
      const finish = end === item.file.size;
      item.status = finish ? "finalizing" : "uploading";
      item.statusLabel = finish ? "Finalizing" : "Uploading";
      render();
      const chunk = await item.file.slice(offset, end).arrayBuffer();
      const response = await responseJson(
        await fetch(
          `/pub/drops/${encodeURIComponent(dropId)}/uploads/${encodeURIComponent(item.sessionId)}?offset=${offset}&finish=${finish}`,
          {
            method: "PUT",
            headers: {
              "content-type": "application/octet-stream",
              ...access.requestHeaders(),
            },
            body: chunk,
          },
        ),
      );
      offset = Number(response.session.received_bytes) || 0;
      item.uploadedBytes = offset;
      if (response.session.status === "completed") {
        break;
      }
    } while (offset < item.file.size);

    item.status = "done";
    item.statusLabel = "Upload complete";
    item.uploadedBytes = item.file.size;
    render();
  }

  async function processQueue() {
    if (processing) return;
    processing = true;
    try {
      for (const item of queue) {
        if (item.status !== "queued") continue;
        try {
          await uploadItem(item);
        } catch (error) {
          item.status = "failed";
          item.statusLabel = displayError(error);
          render();
        }
      }
      const summary = progress.aggregateProgress(queue);
      if (summary.failed > 0) {
        setStatus(`${summary.done} complete · ${summary.failed} failed`, true);
      } else {
        setStatus(`${summary.done} file${summary.done === 1 ? "" : "s"} uploaded`);
      }
    } finally {
      processing = false;
      if (queue.some((item) => item.status === "queued")) processQueue();
    }
  }

  function retryUpload(item) {
    if (item.status !== "failed") return;
    if (!passwordVerified) {
      setStatus("Check the Drop password before retrying this upload.", true);
      password.focus();
      return;
    }
    // A public Drop intentionally has no read/status route for its write-only
    // sessions. Retrying starts a fresh bounded session with the in-memory File
    // object; it never guesses a remote offset or exposes server-side state.
    item.sessionId = null;
    item.uploadedBytes = 0;
    item.status = "queued";
    item.statusLabel = "Queued to retry";
    item.retryCount = (item.retryCount || 0) + 1;
    render();
    setStatus(`Retrying ${item.displayName}.`);
    processQueue();
  }

  function queueFiles(entries) {
    if (!passwordVerified) {
      setStatus("Check the Drop password before choosing files.", true);
      return;
    }
    if (!entries.length) return;
    if (entries.length > MAX_FILES_PER_SELECTION) {
      setStatus(`Choose at most ${MAX_FILES_PER_SELECTION} files at a time.`, true);
      return;
    }
    const accepted = entries.filter(({ file }) => {
      if (file.size <= MAX_FILE_BYTES) return true;
      setStatus(`${file.name} is larger than the 2 GB Drop limit.`, true);
      return false;
    });
    queue.push(
      ...accepted.map(({ file, relativePath }) => ({
        file,
        name: file.name,
        displayName: relativePath,
        relativePath,
        totalBytes: file.size,
        uploadedBytes: 0,
        status: "queued",
        statusLabel: "Queued",
      })),
    );
    render();
    setStatus(`${accepted.length} file${accepted.length === 1 ? "" : "s"} queued`);
    processQueue();
  }

  function pickerEntries(files) {
    return [...files].map((file) => ({
      file,
      relativePath: file.webkitRelativePath || file.name,
    }));
  }

  function readFileEntry(entry) {
    return new Promise((resolve, reject) => entry.file(resolve, reject));
  }

  async function directoryChildren(reader) {
    const all = [];
    for (;;) {
      const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      if (!batch.length) return all;
      all.push(...batch);
    }
  }

  async function walkEntry(entry, prefix = "") {
    if (entry.isFile) {
      const file = await readFileEntry(entry);
      return [{ file, relativePath: `${prefix}${file.name}` }];
    }
    if (!entry.isDirectory) return [];
    const children = await directoryChildren(entry.createReader());
    const nested = await Promise.all(
      children.map((child) => walkEntry(child, `${prefix}${entry.name}/`)),
    );
    return nested.flat();
  }

  async function droppedEntries(dataTransfer) {
    const entries = [...dataTransfer.items]
      .map((item) => item.webkitGetAsEntry?.())
      .filter(Boolean);
    if (!entries.length) return pickerEntries(dataTransfer.files);
    return (await Promise.all(entries.map((entry) => walkEntry(entry)))).flat();
  }

  document.getElementById("choose-files").addEventListener("click", () => filePicker.click());
  document.getElementById("choose-folder").addEventListener("click", () => folderPicker.click());
  document.getElementById("drop-upload-form").addEventListener("submit", (event) => {
    event.preventDefault();
    verifyPassword();
  });
  password.addEventListener("input", () => setPasswordVerified(false));
  window.addEventListener("pagehide", () => access.clear(), { once: true });
  filePicker.addEventListener("change", () => {
    queueFiles(pickerEntries(filePicker.files));
    filePicker.value = "";
  });
  folderPicker.addEventListener("change", () => {
    queueFiles(pickerEntries(folderPicker.files));
    folderPicker.value = "";
  });

  for (const eventName of ["dragenter", "dragover"]) {
    zone.addEventListener(eventName, (event) => {
      if (!passwordVerified) return;
      event.preventDefault();
      zone.classList.add("drag-active");
    });
  }
  for (const eventName of ["dragleave", "drop"]) {
    zone.addEventListener(eventName, (event) => {
      if (!passwordVerified) return;
      event.preventDefault();
      zone.classList.remove("drag-active");
    });
  }
  zone.addEventListener("drop", async (event) => {
    if (!passwordVerified) return;
    try {
      queueFiles(await droppedEntries(event.dataTransfer));
    } catch (error) {
      setStatus(displayError(error), true);
    }
  });
  zone.addEventListener("keydown", (event) => {
    if (!passwordVerified) return;
    if (event.target !== zone || !["Enter", " "].includes(event.key)) return;
    event.preventDefault();
    filePicker.click();
  });
  setPasswordVerified(false);
  if (!protectedDrop) {
    password.hidden = true;
    passwordLabel.hidden = true;
    passwordCheckButton.textContent = "Try again";
    setStatus("Opening Drop…");
    void verifyPassword();
  }
})();
