// Browser upload progress presentation. Kept separate from drive.js so byte
// accounting and accessibility behavior can be tested without the full app.

(() => {
  function nonnegativeFinite(value) {
    const number = Number(value);
    return Number.isFinite(number) ? Math.max(0, number) : 0;
  }

  function itemProgress(item) {
    const totalBytes = nonnegativeFinite(item.totalBytes ?? item.size ?? 0);
    const uploadedBytes = Math.min(totalBytes, nonnegativeFinite(item.uploadedBytes ?? 0));
    let percent =
      totalBytes === 0
        ? item.status === "done"
          ? 100
          : 0
        : Math.max(0, Math.min(100, Math.round((uploadedBytes / totalBytes) * 100)));
    if (item.status !== "done" && percent >= 100) percent = 99;
    return { uploadedBytes, totalBytes, percent };
  }

  function aggregateProgress(queue) {
    const items = (queue || []).map((item) => ({ item, ...itemProgress(item) }));
    const totalBytes = items.reduce((sum, entry) => sum + entry.totalBytes, 0);
    const uploadedBytes = items.reduce((sum, entry) => sum + entry.uploadedBytes, 0);
    const done = items.filter((entry) => entry.item.status === "done").length;
    const failed = items.filter((entry) => entry.item.status === "failed").length;
    const active = items.filter((entry) =>
      ["preflight", "queued", "retrying", "starting", "uploading", "finalizing", "canceling"].includes(
        entry.item.status,
      ),
    ).length;
    const blocked = items.filter((entry) =>
      ["paused", "waiting-network", "needs-file"].includes(entry.item.status),
    ).length;
    let percent =
      totalBytes === 0
        ? items.length === 0
          ? 0
          : Math.round((done / items.length) * 100)
        : Math.round((uploadedBytes / totalBytes) * 100);
    if ((active > 0 || failed > 0 || blocked > 0) && percent >= 100) percent = 99;
    if (active === 0 && failed === 0 && blocked === 0 && items.length > 0) percent = 100;
    return { uploadedBytes, totalBytes, percent, done, failed, blocked, active, total: items.length };
  }

  function buildRow(item, { formatBytes, escapeHtml, onRetry } = {}) {
    const row = document.createElement("div");
    row.className = `upload-queue-row ${item.status}`;
    const progress = itemProgress(item);
    const displayName = item.displayName || item.name;
    const valueText = `${formatBytes(progress.uploadedBytes)} of ${formatBytes(progress.totalBytes)}, ${progress.percent}%`;
    const retry = item.status === "failed" && typeof onRetry === "function"
      ? `<button class="upload-retry-button secondary" type="button" data-upload-retry>Retry upload</button>`
      : "";
    row.innerHTML = `
      <span class="upload-queue-copy">
        <span>
          <b title="${escapeHtml(displayName)}">${escapeHtml(displayName)}</b>
          <small class="upload-queue-state">${escapeHtml(item.statusLabel || item.status)}</small>
        </span>
        <small class="upload-queue-metrics">${escapeHtml(formatBytes(progress.uploadedBytes))} of ${escapeHtml(formatBytes(progress.totalBytes))} · ${progress.percent}%</small>
      </span>
      <span class="upload-progress-track" role="progressbar" aria-label="${escapeHtml(displayName)} upload progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${progress.percent}" aria-valuetext="${escapeHtml(valueText)}">
        <span class="upload-progress-bar"></span>
      </span>
      ${retry}
    `;
    // CSP blocks style attributes; assigning through CSSOM is allowed.
    row.querySelector(".upload-progress-bar").style.width = `${progress.percent}%`;
    row.querySelector("[data-upload-retry]")?.addEventListener("click", () => onRetry(item));
    return row;
  }

  function renderAggregate(root, progress, { formatBytes }) {
    if (!root) return;
    root.hidden = progress.total === 0;
    if (progress.total === 0) return;
    const value = root.querySelector("[data-upload-aggregate-value]");
    const track = root.querySelector("[data-upload-aggregate-track]");
    const bar = root.querySelector("[data-upload-aggregate-bar]");
    const fileProgress = `${progress.done}/${progress.total} file${progress.total === 1 ? "" : "s"}`;
    const byteProgress = `${formatBytes(progress.uploadedBytes)} of ${formatBytes(progress.totalBytes)}`;
    if (value) value.textContent = `${byteProgress} · ${progress.percent}% · ${fileProgress}`;
    if (track) {
      track.setAttribute("aria-valuenow", String(progress.percent));
      track.setAttribute(
        "aria-valuetext",
        `${byteProgress}, ${progress.percent}%, ${fileProgress}`,
      );
    }
    if (bar) bar.style.width = `${progress.percent}%`;
  }

  window.ShellXUploadProgress = Object.freeze({
    aggregateProgress,
    buildRow,
    itemProgress,
    renderAggregate,
  });
})();
