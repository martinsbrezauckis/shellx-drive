// Resilient browser upload queue. This module owns raw chunk transport,
// bounded concurrency, recovery metadata, and per-file state transitions so
// drive.js remains a composition root rather than an upload implementation.

(() => {
  const root = typeof window === "undefined" ? globalThis : window;
  const CHUNK_SIZE = 4 * 1024 * 1024;
  const MAX_CONCURRENCY = 3;
  const MAX_QUEUE_ITEMS = 512;
  const FINGERPRINT_SAMPLE_BYTES = 64 * 1024;
  const STORAGE_PREFIX = "shellx-drive-upload-queue:v2:";
  const TERMINAL_STATUSES = new Set(["done", "skipped", "canceled"]);
  const RUNNABLE_STATUSES = new Set(["queued", "retrying"]);

  function finiteNonnegative(value) {
    const number = Number(value);
    return Number.isFinite(number) ? Math.max(0, number) : 0;
  }

  function browserUploadName(file) {
    return (file?.name || "untitled").replace(/[\\/]/g, "_");
  }

  function displayName(file, relativePath = "") {
    return relativePath || file?.webkitRelativePath || file?.name || "untitled";
  }

  function uploadPath(file, relativePath = "") {
    const value = relativePath || file?.webkitRelativePath || "";
    return value.includes("/") ? value : "";
  }

  function normalizeActor(actor) {
    return String(actor || "local").trim().toLocaleLowerCase() || "local";
  }

  function storageKey(actor) {
    return `${STORAGE_PREFIX}${encodeURIComponent(normalizeActor(actor))}`;
  }

  function clearQueue(storage, actor) {
    try {
      const legacyKey = `${STORAGE_PREFIX}${encodeURIComponent(actor || "local")}`;
      for (const key of new Set([storageKey(actor), legacyKey])) storage?.removeItem(key);
    } catch {
      // Storage denial must not prevent local session separation.
    }
  }

  function serializableItem(item) {
    const replacementBaseRevision = Number(item.replacementBaseRevision);
    return {
      id: String(item.id || ""),
      batchId: String(item.batchId || ""),
      sessionId: String(item.sessionId || ""),
      workspaceId: String(item.workspaceId || ""),
      parentId: item.parentId || null,
      name: String(item.name || "untitled"),
      displayName: String(item.displayName || item.name || "untitled"),
      relativePath: String(item.relativePath || ""),
      totalBytes: finiteNonnegative(item.totalBytes ?? item.size),
      uploadedBytes: finiteNonnegative(item.uploadedBytes),
      lastModified: finiteNonnegative(item.lastModified),
      fingerprint: item.fingerprint ? String(item.fingerprint) : "",
      // `skip` was the earlier spelling for cancelling a collision. Retain it
      // when recovering an old queue, but only issue the current policy names
      // for newly queued files.
      duplicatePolicy: ["keep_both", "replace", "cancel", "skip"].includes(item.duplicatePolicy)
        ? item.duplicatePolicy
        : "keep_both",
      replacementTargetId: item.replacementTargetId ? String(item.replacementTargetId) : "",
      replacementBaseRevision:
        Number.isInteger(replacementBaseRevision) && replacementBaseRevision >= 0
          ? replacementBaseRevision
          : null,
      collisionFallback: item.collisionFallback === "keep_both_no_target"
        ? "keep_both_no_target"
        : "",
      status: String(item.status || "needs-file"),
      statusLabel: String(item.statusLabel || item.status || "Needs attention"),
      createdAt: finiteNonnegative(item.createdAt || Date.now()),
      errorCode: item.errorCode ? String(item.errorCode) : "",
    };
  }

  function recoverPersistedItem(value) {
    if (!value || typeof value !== "object" || !value.id || !value.workspaceId) return null;
    const item = serializableItem(value);
    if (!TERMINAL_STATUSES.has(item.status)) {
      item.status = "needs-file";
      item.statusLabel = item.sessionId
        ? `Reselect this file to resume at ${item.uploadedBytes} bytes`
        : "Reselect this file to restart the upload";
    }
    return item;
  }

  function loadQueue(storage, actor) {
    try {
      const parsed = JSON.parse(storage?.getItem(storageKey(actor)) || "[]");
      if (!Array.isArray(parsed)) return [];
      return parsed.slice(0, MAX_QUEUE_ITEMS).map(recoverPersistedItem).filter(Boolean);
    } catch {
      return [];
    }
  }

  function saveQueue(storage, actor, queue) {
    try {
      const bounded = (queue || []).slice(-MAX_QUEUE_ITEMS).map(serializableItem);
      storage?.setItem(storageKey(actor), JSON.stringify(bounded));
      return bounded;
    } catch {
      return [];
    }
  }

  function hex(bytes) {
    return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
  }

  async function sampleFingerprint(file, cryptoApi = root.crypto || globalThis.crypto) {
    if (!file || typeof file.slice !== "function" || !cryptoApi?.subtle) return "";
    const size = finiteNonnegative(file.size);
    const firstEnd = Math.min(size, FINGERPRINT_SAMPLE_BYTES);
    const lastStart = Math.max(firstEnd, size - FINGERPRINT_SAMPLE_BYTES);
    const samples = [file.slice(0, firstEnd)];
    if (lastStart < size) samples.push(file.slice(lastStart, size));
    const body = await new Blob(samples).arrayBuffer();
    const metadata = new TextEncoder().encode(`${file.name || ""}\n${size}\n`);
    const combined = new Uint8Array(metadata.byteLength + body.byteLength);
    combined.set(metadata, 0);
    combined.set(new Uint8Array(body), metadata.byteLength);
    return hex(await cryptoApi.subtle.digest("SHA-256", combined));
  }

  function validateReselectedFile(expected, file, fingerprint) {
    if (!file) return { ok: false, reason: "No file was selected." };
    if (browserUploadName(file) !== expected.name) {
      return { ok: false, reason: `Choose ${expected.name}; the selected file name is different.` };
    }
    if (finiteNonnegative(file.size) !== finiteNonnegative(expected.totalBytes)) {
      return { ok: false, reason: "The selected file size does not match the interrupted upload." };
    }
    if (expected.fingerprint && fingerprint && expected.fingerprint !== fingerprint) {
      return { ok: false, reason: "The selected file content fingerprint does not match." };
    }
    if (
      !expected.fingerprint &&
      expected.lastModified &&
      file.lastModified &&
      finiteNonnegative(file.lastModified) !== finiteNonnegative(expected.lastModified)
    ) {
      return { ok: false, reason: "The selected file modification time does not match." };
    }
    return { ok: true, reason: "" };
  }

  function reconcileItem(item, session) {
    const next = { ...item };
    next.sessionId = session?.id || next.sessionId || "";
    next.uploadedBytes = finiteNonnegative(session?.received_bytes ?? next.uploadedBytes);
    if (session?.completed) {
      next.status = "done";
      next.statusLabel = "Uploaded";
      next.uploadedBytes = finiteNonnegative(session.total_size ?? next.totalBytes);
    } else if (session?.canceled) {
      next.status = "canceled";
      next.statusLabel = "Canceled";
    } else if (!next.file) {
      next.status = "needs-file";
      next.statusLabel = `Reselect this file to resume at ${next.uploadedBytes} bytes`;
    }
    return next;
  }

  function preflightPlan(items, response, duplicatePolicy, getFileById = () => null) {
    const conflicts = new Map(
      (response?.conflicts || []).map((conflict) => [Number(conflict.index), conflict]),
    );
    return (items || []).map((item, index) => {
      const conflict = conflicts.get(index);
      if (conflict?.kind === "path_blocked") {
        return {
          ...item,
          status: "failed",
          statusLabel: "Upload path is blocked by an existing file or folder",
          errorCode: "path_blocked",
        };
      }
      if (conflict?.kind === "duplicate" && ["cancel", "skip"].includes(duplicatePolicy)) {
        return {
          ...item,
          status: "canceled",
          statusLabel: "Canceled — duplicate exists",
          errorCode: "duplicate_canceled",
        };
      }
      if (conflict?.kind === "duplicate" && duplicatePolicy === "replace") {
        const target = getFileById(conflict.existing_file_id);
        const baseRevision = Number(target?.revision);
        if (!target || target.kind !== "file") {
          return {
            ...item,
            status: "failed",
            statusLabel: "Replace is available only when the existing item is a file",
            errorCode: "replace_unavailable",
          };
        }
        if (!Number.isInteger(baseRevision) || baseRevision < 0) {
          return {
            ...item,
            status: "failed",
            statusLabel: "Refresh the file list before replacing this file",
            errorCode: "replace_revision_missing",
          };
        }
        return {
          ...item,
          duplicatePolicy: "replace",
          replacementTargetId: target.id,
          replacementBaseRevision: baseRevision,
          status: "queued",
          statusLabel: "Queued — replacing existing file",
        };
      }
      if (response && response.fits === false) {
        return {
          ...item,
          status: "failed",
          statusLabel: "Not enough workspace capacity for this batch",
          errorCode: "capacity",
        };
      }
      return {
        ...item,
        // An advisory preflight can be stale. There is no safely identified
        // target to replace when it found no duplicate, so a later collision
        // must keep both rather than overwrite an unknown file.
        duplicatePolicy: duplicatePolicy === "replace" ? "keep_both" : duplicatePolicy,
        collisionFallback: duplicatePolicy === "replace" ? "keep_both_no_target" : "",
        status: "queued",
        statusLabel:
          conflict?.kind === "duplicate"
            ? "Queued — keeping both"
            : duplicatePolicy === "replace"
              ? "Queued — no existing file was found; keeping both if a name appears"
              : duplicatePolicy === "cancel"
                ? "Queued — cancel if a name appears"
                : "Queued",
      };
    });
  }

  function actionsForItem(item) {
    if (["preflight", "queued", "retrying", "starting", "uploading", "finalizing"].includes(item.status)) {
      return ["pause", "cancel"];
    }
    if (item.status === "paused") return ["resume", "cancel"];
    if (["waiting-network", "failed"].includes(item.status)) {
      return [item.file ? "retry" : "reselect", "cancel"];
    }
    if (item.status === "needs-file") return ["reselect", "cancel"];
    return [];
  }

  function actionLabel(action) {
    return {
      pause: "Pause",
      resume: "Resume",
      retry: "Retry",
      reselect: "Reselect file",
      cancel: "Cancel",
    }[action];
  }

  function createController(options) {
    const {
      state,
      elements,
      api,
      formatBytes,
      escapeHtml,
      showToast,
      canWrite,
      getWorkspace,
      getFolderId,
      getFileById,
      getActor,
      onFileFinished,
      onQueueSettled,
    } = options;
    const storage = options.storage || root.localStorage;
    const running = new Map();
    const aborters = new Map();
    const pauseModes = new Map();
    let activeActor = "";
    let restored = false;
    let panelDismissed = false;
    let resumeTargetId = "";
    let refreshPending = false;

    const queue = () => state.uploadQueue || [];
    const itemById = (id) => queue().find((item) => item.id === id);

    function persist() {
      if (activeActor) saveQueue(storage, activeActor, queue());
    }

    function setQueue(next, { reveal = true } = {}) {
      state.uploadQueue = next.slice(-MAX_QUEUE_ITEMS);
      if (reveal) panelDismissed = false;
      persist();
      render();
    }

    function update(id, patch, options = {}) {
      setQueue(
        queue().map((item) => (item.id === id ? { ...item, ...patch } : item)),
        options,
      );
      return itemById(id);
    }

    function buildRow(item) {
      const row = root.ShellXUploadProgress.buildRow(item, { formatBytes, escapeHtml });
      const actions = actionsForItem(item);
      if (actions.length) {
        const actionBar = document.createElement("span");
        actionBar.className = "upload-queue-actions";
        for (const action of actions) {
          const button = document.createElement("button");
          button.type = "button";
          button.dataset.uploadAction = action;
          button.dataset.uploadId = item.id;
          button.textContent = actionLabel(action);
          if (action === "cancel") button.className = "upload-cancel-action";
          actionBar.append(button);
        }
        row.append(actionBar);
      }
      return row;
    }

    function render() {
      const items = queue();
      const aggregate = root.ShellXUploadProgress.aggregateProgress(items);
      const { done, failed, blocked, active, total } = aggregate;
      if (elements.queue) elements.queue.replaceChildren(...items.map(buildRow));
      if (elements.summary) {
        elements.summary.textContent =
          total === 0
            ? "Choose files or folders to upload into the current folder."
            : `${done}/${total} uploaded · ${formatBytes(aggregate.uploadedBytes)} of ${formatBytes(aggregate.totalBytes)} · ${aggregate.percent}%${failed ? ` · ${failed} failed` : ""}${blocked ? ` · ${blocked} need attention` : ""}`;
      }
      for (const aggregateRoot of elements.aggregates || []) {
        root.ShellXUploadProgress.renderAggregate(aggregateRoot, aggregate, { formatBytes });
      }
      if (elements.statusList) elements.statusList.replaceChildren(...items.map(buildRow));
      if (elements.statusPanel) elements.statusPanel.hidden = total === 0 || panelDismissed;
      if (elements.statusTitle && total > 0) {
        elements.statusTitle.textContent =
          active > 0
            ? `Uploading ${active} file${active === 1 ? "" : "s"}…`
            : failed || blocked
              ? `${done} uploaded · ${failed} failed · ${blocked} need attention`
              : `${done} upload${done === 1 ? "" : "s"} complete`;
      }
      if (elements.dismiss) {
        elements.dismiss.disabled = active > 0;
        elements.dismiss.title = active > 0 ? "Pause or finish uploads before dismissing" : "Dismiss uploads";
      }
      if (elements.clearCompleted) {
        elements.clearCompleted.disabled = !items.some((item) => TERMINAL_STATUSES.has(item.status));
      }
    }

    async function activate() {
      const actor = getActor() || "local";
      if (restored && activeActor === actor) return;
      deactivate(false);
      activeActor = actor;
      restored = true;
      state.uploadQueue = loadQueue(storage, actor);
      render();
      await reconcileRecovered();
    }

    function deactivate(clearVisible = true) {
      for (const controller of aborters.values()) controller.abort();
      aborters.clear();
      pauseModes.clear();
      running.clear();
      if (clearVisible) state.uploadQueue = [];
      activeActor = "";
      restored = false;
      render();
    }

    function clearPersistedActor(actor) {
      clearQueue(storage, actor);
    }

    async function reconcileRecovered() {
      for (const item of [...queue()]) {
        if (TERMINAL_STATUSES.has(item.status)) continue;
        if (!item.sessionId) {
          update(item.id, {
            status: "needs-file",
            statusLabel: "Reselect this file to restart the upload",
          });
          continue;
        }
        try {
          const response = await api(`/uploads/resumable/${encodeURIComponent(item.sessionId)}`);
          update(item.id, reconcileItem(itemById(item.id), response.session));
        } catch (error) {
          update(item.id, {
            sessionId: error.status === 404 ? "" : item.sessionId,
            status: "needs-file",
            statusLabel:
              error.status === 404
                ? "Upload session expired — reselect this file to restart"
                : "Could not verify the upload session — reconnect and reselect the file",
            errorCode: error.status === 404 ? "session_missing" : "reconcile_failed",
          });
        }
      }
    }

    async function enqueueFiles(fileList) {
      const entries = Array.from(fileList || [])
        .filter((file) => file && file.name)
        .map((file) => ({ file, relativePath: file.webkitRelativePath || "" }));
      return enqueueEntries(entries);
    }

    async function enqueueEntries(entries) {
      const workspace = getWorkspace();
      if (!workspace || !canWrite()) {
        showToast("Select a workspace where you can upload.");
        return [];
      }
      const valid = (entries || []).filter((entry) => entry?.file && entry.file.name);
      if (!valid.length) return [];
      if (valid.length > MAX_QUEUE_ITEMS) {
        showToast(`Choose at most ${MAX_QUEUE_ITEMS} files in one upload batch.`);
        return [];
      }
      await activate();
      const selectedPolicy = String(elements.duplicatePolicy?.value || "keep_both");
      const duplicatePolicy = ["keep_both", "replace", "cancel"].includes(selectedPolicy)
        ? selectedPolicy
        : "keep_both";
      const batchId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const createdAt = Date.now();
      const parentId = getFolderId() || null;
      const items = valid.map((entry, index) => {
        const relativePath = entry.relativePath || entry.file.webkitRelativePath || "";
        return {
          id: `${batchId}-${index}`,
          batchId,
          sessionId: "",
          workspaceId: workspace.id,
          parentId,
          file: entry.file,
          relativePath,
          name: browserUploadName(entry.file),
          displayName: displayName(entry.file, relativePath),
          totalBytes: finiteNonnegative(entry.file.size),
          uploadedBytes: 0,
          lastModified: finiteNonnegative(entry.file.lastModified),
          fingerprint: "",
          duplicatePolicy,
          status: "preflight",
          statusLabel: "Checking capacity and duplicates",
          createdAt,
          errorCode: "",
        };
      });
      setQueue([...queue(), ...items]);
      let response;
      try {
        response = await api("/uploads/preflight", {
          method: "POST",
          body: JSON.stringify({
            workspace_id: workspace.id,
            ...(parentId ? { parent_id: parentId } : {}),
            files: items.map((item) => ({
              name: item.name,
              size: item.totalBytes,
              ...(uploadPath(item.file, item.relativePath) ? { path: uploadPath(item.file, item.relativePath) } : {}),
            })),
          }),
        });
      } catch (error) {
        for (const item of items) {
          update(item.id, {
            status: "failed",
            statusLabel: `Preflight failed: ${error.message}`,
            errorCode: "preflight_failed",
          });
        }
        return items;
      }
      const planned = preflightPlan(items, response, duplicatePolicy, getFileById);
      const byId = new Map(planned.map((item) => [item.id, item]));
      setQueue(queue().map((item) => byId.get(item.id) || item));
      if (response.fits === false) {
        const remaining = response.remaining_bytes;
        showToast(
          remaining == null
            ? "This upload batch does not fit the workspace capacity."
            : `This batch needs ${formatBytes(response.requested_bytes)}; ${formatBytes(remaining)} remains.`,
        );
      }
      schedule();
      return planned;
    }

    function schedule() {
      if (root.navigator && root.navigator.onLine === false) return;
      while (running.size < MAX_CONCURRENCY) {
        const next = queue().find(
          (item) => RUNNABLE_STATUSES.has(item.status) && item.file && !running.has(item.id),
        );
        if (!next) break;
        const promise = performUpload(next.id)
          .catch(() => {})
          .finally(async () => {
            running.delete(next.id);
            aborters.delete(next.id);
            pauseModes.delete(next.id);
            schedule();
            if (running.size === 0 && !queue().some((item) => RUNNABLE_STATUSES.has(item.status))) {
              if (refreshPending) {
                refreshPending = false;
                await onQueueSettled?.();
              }
            }
          });
        running.set(next.id, promise);
      }
    }

    async function ensureSession(item) {
      if (item.sessionId) {
        try {
          const response = await api(`/uploads/resumable/${encodeURIComponent(item.sessionId)}`);
          const reconciled = reconcileItem(itemById(item.id), response.session);
          update(item.id, reconciled);
          if (response.session.completed || response.session.canceled) return response.session;
          return response.session;
        } catch (error) {
          if (error.status !== 404) throw error;
          update(item.id, { sessionId: "", uploadedBytes: 0, errorCode: "session_missing" });
        }
      }
      const current = itemById(item.id);
      update(item.id, { status: "starting", statusLabel: "Starting upload" });
      try {
        const replacement = current.replacementTargetId && Number.isInteger(current.replacementBaseRevision);
        const created = await api("/uploads/resumable", {
          method: "POST",
          body: JSON.stringify({
            total_size: current.totalBytes,
            ...(replacement
              ? {
                  target_file_id: current.replacementTargetId,
                  base_revision: current.replacementBaseRevision,
                  duplicate_policy: "replace",
                }
              : {
                  workspace_id: current.workspaceId,
                  ...(current.parentId ? { parent_id: current.parentId } : {}),
                  name: current.name,
                  ...(uploadPath(current.file, current.relativePath)
                    ? { path: uploadPath(current.file, current.relativePath) }
                    : {}),
                  duplicate_policy: current.duplicatePolicy,
                }),
          }),
        });
        update(item.id, {
          sessionId: created.session.id,
          uploadedBytes: finiteNonnegative(created.session.received_bytes),
        });
        return created.session;
      } catch (error) {
        if (error.status === 409 && ["cancel", "skip"].includes(current.duplicatePolicy)) {
          update(item.id, {
            status: "canceled",
            statusLabel: "Canceled — duplicate exists",
            errorCode: "duplicate_canceled",
          });
          return null;
        }
        throw error;
      }
    }

    async function performUpload(id) {
      let item = itemById(id);
      if (!item?.file) {
        update(id, { status: "needs-file", statusLabel: "Reselect this file to continue" });
        return;
      }
      try {
        if (!item.fingerprint) {
          update(id, { status: "starting", statusLabel: "Preparing resumable fingerprint" });
          const fingerprint = await sampleFingerprint(item.file);
          update(id, { fingerprint });
          item = itemById(id);
        }
        const session = await ensureSession(item);
        if (!session || TERMINAL_STATUSES.has(itemById(id)?.status)) return;
        if (session.completed) {
          update(id, {
            status: "done",
            statusLabel: item.replacementTargetId
              ? "Replaced existing file"
              : item.collisionFallback
                ? "Uploaded — no existing file was found to replace"
                : "Uploaded",
            uploadedBytes: item.totalBytes,
          });
          return;
        }
        if (session.canceled) {
          update(id, { status: "canceled", statusLabel: "Canceled" });
          return;
        }

        let offset = finiteNonnegative(session.received_bytes);
        let staleReconciliations = 0;
        while (true) {
          item = itemById(id);
          const pauseMode = pauseModes.get(id);
          if (pauseMode) {
            update(id, {
              status: pauseMode === "network" ? "waiting-network" : "paused",
              statusLabel:
                pauseMode === "network" ? "Connection lost — resumes when online" : "Paused",
            });
            return;
          }
          if (!item?.file) {
            update(id, { status: "needs-file", statusLabel: "Reselect this file to continue" });
            return;
          }
          if (offset > item.totalBytes) throw new Error("Server upload offset exceeds file size.");
          const end = Math.min(offset + CHUNK_SIZE, item.totalBytes);
          const finish = end >= item.totalBytes;
          const controller = new AbortController();
          aborters.set(id, controller);
          update(id, {
            status: finish ? "finalizing" : "uploading",
            statusLabel: finish ? "Finalizing" : "Uploading",
          });
          try {
            const response = await api(
              `/uploads/resumable/${encodeURIComponent(item.sessionId)}/content?offset=${offset}&finish=${finish}`,
              {
                method: "PUT",
                body: item.file.slice(offset, end),
                headers: { "content-type": "application/octet-stream" },
                signal: controller.signal,
              },
            );
            offset = finiteNonnegative(response.session?.received_bytes ?? end);
            update(id, { uploadedBytes: offset });
            if (response.file || response.session?.completed) {
              const finalName = String(response.file?.name || item.name || "");
              update(id, {
                uploadedBytes: item.totalBytes,
                status: "done",
                statusLabel: item.replacementTargetId
                  ? "Replaced existing file"
                  : item.collisionFallback
                    ? finalName && finalName !== item.name
                      ? `Kept both as ${finalName}; replacement target was unavailable`
                      : "Uploaded — no existing file was found to replace"
                  : finalName && finalName !== item.name
                    ? `Uploaded as ${finalName}`
                    : "Uploaded",
                errorCode: "",
              });
              refreshPending = true;
              if (response.file) await onFileFinished?.(response.file);
              return;
            }
          } catch (error) {
            const pauseModeAfterAbort = pauseModes.get(id);
            if (error.name === "AbortError" && pauseModeAfterAbort) {
              update(id, {
                status: pauseModeAfterAbort === "network" ? "waiting-network" : "paused",
                statusLabel:
                  pauseModeAfterAbort === "network"
                    ? "Connection lost — resumes when online"
                    : "Paused",
              });
              return;
            }
            if (error.status === 409 && staleReconciliations < 2) {
              staleReconciliations += 1;
              const reconciled = await api(
                `/uploads/resumable/${encodeURIComponent(item.sessionId)}`,
              );
              offset = finiteNonnegative(reconciled.session.received_bytes);
              update(id, reconcileItem(itemById(id), reconciled.session));
              if (reconciled.session.completed || reconciled.session.canceled) return;
              continue;
            }
            if (error.status === 404) {
              update(id, {
                sessionId: "",
                uploadedBytes: 0,
                status: "failed",
                statusLabel: "Upload session expired — retry to restart",
                errorCode: "session_missing",
              });
              return;
            }
            throw error;
          } finally {
            if (aborters.get(id) === controller) aborters.delete(id);
          }
        }
      } catch (error) {
        const offline = root.navigator && root.navigator.onLine === false;
        update(id, {
          status: offline ? "waiting-network" : "failed",
          statusLabel: offline
            ? "Connection lost — resumes when online"
            : `Upload failed: ${error.message}`,
          errorCode: offline ? "offline" : "upload_failed",
        });
      }
    }

    function pause(id, mode = "user") {
      const item = itemById(id);
      if (!item || TERMINAL_STATUSES.has(item.status)) return;
      pauseModes.set(id, mode);
      aborters.get(id)?.abort();
      if (!running.has(id)) {
        update(id, {
          status: mode === "network" ? "waiting-network" : "paused",
          statusLabel: mode === "network" ? "Connection lost — resumes when online" : "Paused",
        });
      }
    }

    function resume(id) {
      const item = itemById(id);
      if (!item) return;
      pauseModes.delete(id);
      if (!item.file) {
        update(id, { status: "needs-file", statusLabel: "Reselect this file to continue" });
        requestReselect(id);
        return;
      }
      update(id, { status: "queued", statusLabel: "Queued to resume", errorCode: "" });
      schedule();
    }

    function retry(id) {
      const item = itemById(id);
      if (!item?.file) {
        requestReselect(id);
        return;
      }
      update(id, { status: "retrying", statusLabel: "Retrying", errorCode: "" });
      schedule();
    }

    async function cancel(id) {
      let item = itemById(id);
      if (!item || TERMINAL_STATUSES.has(item.status)) return;
      pauseModes.set(id, "cancel");
      aborters.get(id)?.abort();
      await running.get(id)?.catch(() => {});
      item = itemById(id);
      if (!item?.sessionId) {
        update(id, { status: "canceled", statusLabel: "Canceled", file: null });
        return;
      }
      update(id, { status: "canceling", statusLabel: "Canceling" });
      try {
        await api(`/uploads/resumable/${encodeURIComponent(item.sessionId)}/cancel`, {
          method: "POST",
        });
        update(id, { status: "canceled", statusLabel: "Canceled", file: null });
      } catch (error) {
        if (error.status === 409) {
          const response = await api(`/uploads/resumable/${encodeURIComponent(item.sessionId)}`);
          update(id, reconcileItem(itemById(id), response.session));
          return;
        }
        update(id, {
          status: "failed",
          statusLabel: `Cancel failed: ${error.message}`,
          errorCode: "cancel_failed",
        });
      }
    }

    function requestReselect(id) {
      if (!elements.resumePicker) return;
      resumeTargetId = id;
      elements.resumePicker.value = "";
      elements.resumePicker.click();
    }

    async function acceptReselectedFile(file) {
      const item = itemById(resumeTargetId);
      resumeTargetId = "";
      if (!item || !file) return;
      const fingerprint = await sampleFingerprint(file);
      const match = validateReselectedFile(item, file, fingerprint);
      if (!match.ok) {
        update(item.id, { status: "needs-file", statusLabel: match.reason, errorCode: "file_mismatch" });
        showToast(match.reason);
        return;
      }
      update(item.id, {
        file,
        fingerprint: fingerprint || item.fingerprint,
        lastModified: finiteNonnegative(file.lastModified),
        status: "queued",
        statusLabel: item.sessionId ? "Queued to resume" : "Queued to restart",
        errorCode: "",
      });
      schedule();
    }

    function clearCompleted() {
      setQueue(queue().filter((item) => !TERMINAL_STATUSES.has(item.status)));
    }

    function dismiss() {
      if (running.size > 0) return;
      clearCompleted();
      panelDismissed = true;
      render();
    }

    async function handleAction(event) {
      const button = event.target.closest?.("[data-upload-action][data-upload-id]");
      if (!button) return;
      const { uploadAction: action, uploadId: id } = button.dataset;
      if (action === "pause") pause(id);
      if (action === "resume") resume(id);
      if (action === "retry") retry(id);
      if (action === "reselect") requestReselect(id);
      if (action === "cancel") await cancel(id);
    }

    for (const target of [elements.queue, elements.statusList]) {
      target?.addEventListener("click", (event) => {
        handleAction(event).catch((error) => showToast(error.message));
      });
    }
    elements.resumePicker?.addEventListener("change", () => {
      acceptReselectedFile(elements.resumePicker.files?.[0]).catch((error) => showToast(error.message));
    });
    elements.clearCompleted?.addEventListener("click", clearCompleted);
    elements.dismiss?.addEventListener("click", dismiss);
    root.addEventListener?.("offline", () => {
      for (const item of queue()) {
        if (running.has(item.id) || RUNNABLE_STATUSES.has(item.status)) pause(item.id, "network");
      }
    });
    root.addEventListener?.("online", () => {
      for (const item of queue()) {
        if (item.status !== "waiting-network") continue;
        if (item.file) {
          pauseModes.delete(item.id);
          update(item.id, { status: "queued", statusLabel: "Connection restored — resuming" });
        } else {
          update(item.id, { status: "needs-file", statusLabel: "Reselect this file to resume" });
        }
      }
      schedule();
    });

    return Object.freeze({
      activate,
      clearPersistedActor,
      deactivate,
      enqueueEntries,
      enqueueFiles,
      render,
      pause,
      resume,
      retry,
      cancel,
      clearCompleted,
      collectDropEntries,
    });
  }

  function readAllDirectoryEntries(reader) {
    return new Promise((resolve, reject) => {
      reader.readEntries((entries) => resolve(entries), (error) => reject(error));
    });
  }

  function fileFromEntry(entry) {
    return new Promise((resolve, reject) => {
      entry.file((file) => resolve(file), (error) => reject(error));
    });
  }

  async function walkFileSystemEntry(entry, prefix, out) {
    if (entry.isFile) {
      const file = await fileFromEntry(entry);
      out.push({ file, relativePath: prefix ? `${prefix}/${file.name}` : file.name });
      return;
    }
    if (!entry.isDirectory) return;
    const directory = prefix ? `${prefix}/${entry.name}` : entry.name;
    const reader = entry.createReader();
    let batch = await readAllDirectoryEntries(reader);
    while (batch.length) {
      for (const child of batch) await walkFileSystemEntry(child, directory, out);
      batch = await readAllDirectoryEntries(reader);
    }
  }

  async function collectDropEntries(dataTransfer) {
    const flatFiles = Array.from(dataTransfer?.files || []);
    const items = dataTransfer?.items ? Array.from(dataTransfer.items) : [];
    const supportsEntries = items.length > 0 && typeof items[0].webkitGetAsEntry === "function";
    if (!supportsEntries) return flatFiles.map((file) => ({ file, relativePath: "" }));
    const roots = [];
    for (const item of items) {
      if (item.kind !== "file") continue;
      const entry = item.webkitGetAsEntry();
      if (entry) roots.push({ entry });
      else {
        const file = item.getAsFile?.();
        if (file) roots.push({ file });
      }
    }
    if (!roots.length) return flatFiles.map((file) => ({ file, relativePath: "" }));
    const out = [];
    for (const candidate of roots) {
      if (candidate.entry) await walkFileSystemEntry(candidate.entry, "", out);
      else if (candidate.file) out.push({ file: candidate.file, relativePath: "" });
    }
    return out;
  }

  root.ShellXDriveUploads = Object.freeze({
    CHUNK_SIZE,
    MAX_CONCURRENCY,
    MAX_QUEUE_ITEMS,
    actionsForItem,
    clearQueue,
    collectDropEntries,
    createController,
    loadQueue,
    preflightPlan,
    reconcileItem,
    recoverPersistedItem,
    sampleFingerprint,
    saveQueue,
    serializableItem,
    storageKey,
    validateReselectedFile,
  });
})();
