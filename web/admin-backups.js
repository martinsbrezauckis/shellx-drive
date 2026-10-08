window.ShellXDriveAdminBackups = Object.freeze({
  createController(dependencies) {
    const {
      api,
      authHeaders,
      compactDate,
      els,
      escapeHtml,
      formatBytes,
      loadAdminSummary,
      loadReadinessStatus,
      relativeTime,
      renderAdminEmpty,
      renderAdminSkeleton,
      renderAdminStats,
      runAuthenticated,
      showToast,
      state,
      titleCase,
    } = dependencies;
  const pageCursors = [null];
  let pageIndex = 0;
  let nextCursor = null;

  async function loadAdminBackups({ page = 0 } = {}) {
    const query = new URLSearchParams({ limit: "8" });
    if (pageCursors[page]) query.set("cursor", pageCursors[page]);
    const data = await api(`/admin/backups?${query}`);
    pageIndex = page;
    nextCursor = data.next_cursor || null;
    if (nextCursor) pageCursors[page + 1] = nextCursor;
    pageCursors.length = nextCursor ? page + 2 : page + 1;
    state.adminBackups = data.backups || [];
    if (
      state.selectedAdminBackupId &&
      !state.adminBackups.some((backup) => backup.backup_id === state.selectedAdminBackupId)
    ) {
      state.selectedAdminBackupId = "";
    }
    renderAdminBackups();
    return data;
  }

  async function loadBackupPolicy() {
    const data = await api("/admin/backup-policy");
    state.backupPolicy = data.policy;
    renderBackupPolicy();
    return data;
  }

  // Human label for the backup schedule stat tile.
  function backupScheduleLabel(policy) {
    if (!policy || !policy.enabled) return "Manual";
    return (
      { hourly: "Hourly", daily: "Daily", weekly: "Weekly", manual: "Manual" }[
        policy.schedule
      ] || "Manual"
    );
  }

  function renderBackupPolicy() {
    const policy = state.backupPolicy;
    if (policy) {
      if (els.adminBackupPolicyEnabled) els.adminBackupPolicyEnabled.checked = Boolean(policy.enabled);
      if (els.adminBackupPolicySchedule) els.adminBackupPolicySchedule.value = policy.schedule || "manual";
      if (els.adminBackupPolicyRetention) els.adminBackupPolicyRetention.value = policy.retention_count || 7;
      if (els.adminBackupPolicySchedule) els.adminBackupPolicySchedule.disabled = !policy.enabled;
    }
    const backups = state.adminBackups || [];
    const latest = backups[0];
    renderAdminStats(els.adminBackupsSummary, [
      ["Shown on this page", backups.length],
      ["Automatic schedule", policy ? backupScheduleLabel(policy) : "—"],
      ["Newest on this page", latest ? relativeTime(latest.created_at) : "None"],
      ["Off-host copies", "Not tracked"],
    ]);
  }

  function renderAdminBackups() {
    if (!els.adminBackupsSummary) return;
    if (els.adminBackupsPrevious) els.adminBackupsPrevious.disabled = pageIndex === 0;
    if (els.adminBackupsNext) els.adminBackupsNext.disabled = !nextCursor;
    if (els.adminBackupsPage) els.adminBackupsPage.textContent = `Page ${pageIndex + 1}`;
    renderBackupPolicy();
    setAdminBackupActionState();
    if (!state.adminBackups) {
      renderAdminSkeleton(els.adminBackupsList, "rows", 2);
      return;
    }
    if (state.adminBackups.length === 0) {
      renderAdminEmpty(
        els.adminBackupsList,
        "No backups yet",
        "Create your first snapshot with the Create backup button.",
      );
      return;
    }
    els.adminBackupsList.classList.remove("admin-skeleton", "admin-skeleton-tiles");
    els.adminBackupsList.replaceChildren(
      ...state.adminBackups.map((backup) => {
        const row = document.createElement("div");
        row.className = `admin-live-row backup-row${
          backup.backup_id === selectedAdminBackupId() ? " active" : ""
        }`;
        row.dataset.backupId = backup.backup_id;
        const fileCount = Number(backup.blob_count || 0);
        const status = backup.status || "succeeded";
        const format = backup.format === "shellx-drive-backup-v2" ? "v2 streaming archive" : "v1 legacy archive";
        const archiveSize = backup.archive_bytes ? ` · ${formatBytes(backup.archive_bytes)}` : "";
        const phase = backup.phase && backup.phase !== "complete" ? ` · ${titleCase(backup.phase)}` : "";
        const error = backup.last_error
          ? `<small class="backup-error" title="${escapeHtml(backup.last_error)}">${escapeHtml(backup.last_error)}</small>`
          : "";
        row.setAttribute("role", "button");
        row.tabIndex = 0;
        row.setAttribute(
          "aria-pressed",
          backup.backup_id === selectedAdminBackupId() ? "true" : "false",
        );
        row.innerHTML = `
          <span>
            <b>${escapeHtml(compactDate(backup.created_at))}</b>
            <small>${escapeHtml(relativeTime(backup.created_at))} · ${escapeHtml(format)}${escapeHtml(archiveSize)} · ${escapeHtml(status === "succeeded" ? "Completed" : titleCase(status))}${escapeHtml(phase)}</small>
            ${error}
          </span>
          <strong>${backup.backup_id === selectedAdminBackupId() ? "Selected · " : ""}${status === "succeeded" ? `${escapeHtml(fileCount.toLocaleString())} ${fileCount === 1 ? "file" : "files"}` : escapeHtml(titleCase(status))}</strong>
        `;
        const selectBackup = () => {
          state.selectedAdminBackupId = backup.backup_id;
          renderAdminBackups();
        };
        row.addEventListener("click", selectBackup);
        row.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            selectBackup();
          }
        });
        return row;
      }),
    );
    setAdminBackupActionState();
  }

  async function createAdminBackup() {
    const data = await api("/admin/backups", { method: "POST" });
    state.selectedAdminBackupId = data.job.backup_id;
    await loadAdminBackups();
    showToast("Backup queued. Drive is creating a streamed snapshot.");
    await waitForAdminBackupJob(data.job.id);
    await loadAdminBackups();
    await loadAdminSummary().catch((error) => {
      els.adminOutput.textContent = error.message;
    });
    showToast("Backup created.");
    return data;
  }

  async function waitForAdminBackupJob(jobId) {
    for (let attempt = 0; attempt < 2400; attempt += 1) {
      const data = await api(`/admin/backup-jobs/${jobId}`);
      if (data.job.status === "succeeded") return data;
      if (["failed", "interrupted"].includes(data.job.status)) {
        await loadAdminBackups();
        throw new Error(data.job.last_error || `Backup job ${data.job.status}.`);
      }
      if (attempt % 3 === 0) await loadAdminBackups();
      await new Promise((resolve) => window.setTimeout(resolve, 750));
    }
    throw new Error("Backup job did not finish within 30 minutes.");
  }

  async function saveBackupPolicy(event) {
    event.preventDefault();
    const data = await api("/admin/backup-policy", {
      method: "PATCH",
      body: JSON.stringify({
        enabled: els.adminBackupPolicyEnabled.checked,
        schedule: els.adminBackupPolicySchedule.value,
        retention_count: Number(els.adminBackupPolicyRetention.value || 7),
      }),
    });
    state.backupPolicy = data.policy;
    renderBackupPolicy();
    await loadAdminSummary().catch((error) => {
      els.adminOutput.textContent = error.message;
    });
    showToast("Backup policy saved.");
    return data;
  }

  function selectedAdminBackupId() {
    const backupId = state.selectedAdminBackupId;
    if (backupId) return backupId;
    const firstBackup = (state.adminBackups || [])[0];
    return firstBackup?.backup_id || "";
  }

  function setAdminBackupActionState() {
    const backupId = selectedAdminBackupId();
    const selected = (state.adminBackups || []).find((backup) => backup.backup_id === backupId);
    const disabled = !selected || (selected.status && selected.status !== "succeeded");
    if (els.adminBackupSelection) {
      els.adminBackupSelection.textContent = selected
        ? `Selected backup: ${compactDate(selected.created_at)} · ${selected.backup_id}`
        : "Selected backup: none";
    }
    for (const button of [
      els.adminBackupValidateButton,
      els.adminBackupDownloadButton,
      els.adminBackupRestoreButton,
      els.adminBackupDeleteButton,
    ]) {
      if (button) button.disabled = disabled;
    }
  }

  async function validateSelectedAdminBackup() {
    const backupId = selectedAdminBackupId();
    if (!backupId) return null;
    const data = await api(`/admin/backups/${backupId}/validate`, { method: "POST" });
    if (data.job) await waitForAdminBackupJob(data.job.id);
    await loadAdminBackups();
    await loadAdminSummary().catch(() => {});
    showToast(data.job || data.valid ? "Backup checked — no problems found." : `Backup has issues: ${(data.issues || []).join(", ") || "unknown"}`);
    return data;
  }

  async function downloadSelectedAdminBackup() {
    return runAuthenticated(async (signal) => {
    const backupId = selectedAdminBackupId();
    if (!backupId) return null;
    const selected = (state.adminBackups || []).find((backup) => backup.backup_id === backupId);
    const isV2 = selected?.format === "shellx-drive-backup-v2";
    const downloadUrl = `/admin/backups/${backupId}/download`;
    const suggestedName = `shellx-drive-backup-${backupId}.${isV2 ? "sxdbackup" : "json"}`;

    // Authenticated backup streams remain abortable across account changes.
    // V2 archives therefore require a browser-native writable stream instead
    // of an unobservable anchor navigation.
    let writable = null;
    if (isV2) {
      if (!("showSaveFilePicker" in window)) {
        throw new Error(
          "This browser cannot stream an authenticated backup to disk. Use the documented curl download command.",
        );
      }
      const handle = await window.showSaveFilePicker({ suggestedName });
      writable = await handle.createWritable();
    }

    const response = await fetch(downloadUrl, { headers: authHeaders(), signal });
    if (!response.ok) {
      if (writable) await writable.abort().catch(() => {});
      throw new Error((await response.text()) || `${response.status} ${response.statusText}`);
    }
    const contentType = response.headers.get("content-type") || "";
    if (isV2) {
      if (!response.body || !writable) {
        if (writable) await writable.abort().catch(() => {});
        throw new Error("Streaming backup response is unavailable.");
      }
      await response.body.pipeTo(writable);
      signal.throwIfAborted();
      await loadAdminSummary().catch(() => {});
      signal.throwIfAborted();
      showToast("Backup downloaded.");
      return true;
    }

    let blob;
    let extension;
    if (contentType.includes("application/json")) {
      const data = await response.json();
      blob = new Blob([JSON.stringify(data.bundle, null, 2)], { type: "application/json" });
      extension = "json";
    } else {
      blob = await response.blob();
      extension = selected?.format === "shellx-drive-backup-v2" ? "sxdbackup" : "bin";
    }
    signal.throwIfAborted();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `shellx-drive-backup-${backupId}.${extension}`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
    await loadAdminSummary().catch(() => {});
    signal.throwIfAborted();
    showToast("Backup downloaded.");
    return true;
    });
  }

  async function restoreSelectedAdminBackup() {
    const backupId = selectedAdminBackupId();
    if (!backupId) return null;
    if (!window.confirm("Restore this complete server backup? All workspace state will roll back to the selected snapshot and writes will pause until it finishes.")) {
      return null;
    }
    const data = await api(`/admin/backups/${backupId}/restore`, { method: "POST" });
    if (data.job) await waitForAdminBackupJob(data.job.id);
    await Promise.all([loadAdminBackups(), loadAdminSummary(), loadReadinessStatus()]);
    showToast("Backup restored successfully.");
    return data;
  }

  async function deleteSelectedAdminBackup() {
    const backupId = selectedAdminBackupId();
    if (!backupId) return null;
    if (!window.confirm("Delete this backup generation permanently?")) return null;
    const data = await api(`/admin/backups/${backupId}`, { method: "DELETE" });
    state.selectedAdminBackupId = "";
    await loadAdminBackups();
    await loadAdminSummary().catch(() => {});
    showToast("Backup deleted.");
    return data;
  }
    els.adminBackupsPrevious?.addEventListener("click", () => {
      if (pageIndex > 0) loadAdminBackups({ page: pageIndex - 1 }).catch((error) => showToast(error.message));
    });
    els.adminBackupsNext?.addEventListener("click", () => {
      if (nextCursor) loadAdminBackups({ page: pageIndex + 1 }).catch((error) => showToast(error.message));
    });

    return Object.freeze({
      createAdminBackup,
      deleteSelectedAdminBackup,
      downloadSelectedAdminBackup,
      loadAdminBackups,
      loadBackupPolicy,
      renderAdminBackups,
      restoreSelectedAdminBackup,
      saveBackupPolicy,
      validateSelectedAdminBackup,
    });
  },
});
