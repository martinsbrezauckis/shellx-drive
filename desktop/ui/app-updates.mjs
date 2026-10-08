export function emptyDesktopUpdateState() {
  return { status: "idle", info: null, error: "", received: 0, total: null };
}

export function desktopUpdatePercent(state) {
  if (!Number.isFinite(state.total) || state.total <= 0) return null;
  return Math.min(100, Math.floor((state.received / state.total) * 100));
}

export function applyDesktopUpdateEvent(state, message) {
  if (!message || typeof message.event !== "string") return state;
  if (message.event === "started") {
    const total = Number(message.data?.contentLength);
    return { ...state, status: "downloading", received: 0, total: Number.isFinite(total) && total > 0 ? total : null };
  }
  if (message.event === "progress") {
    const chunk = Number(message.data?.chunkLength);
    return { ...state, status: "downloading", received: state.received + (Number.isFinite(chunk) && chunk > 0 ? chunk : 0) };
  }
  if (message.event === "downloaded") return { ...state, status: "installing" };
  if (message.event === "verified" || message.event === "restarting") return { ...state, status: "restarting" };
  return state;
}

export function renderDesktopUpdateNotice(state, escape) {
  if (state.status !== "available") return "";
  const version = escape(state.info?.version || "new");
  return `<section class="desktop-update-notice" role="status" aria-label="Desktop update available"><div><strong>ShellX Drive Desktop ${version} is available</strong><span>Review the signed update before installing it.</span></div><button class="button" data-action="desktop-update-open">Review update</button></section>`;
}

export function renderDesktopUpdateRecoveryNotice(targetVersion, currentVersion, escape) {
  if (!targetVersion) return "";
  const target = escape(targetVersion);
  const current = escape(currentVersion || "an earlier version");
  return `<section class="desktop-update-notice" role="alert" aria-label="Desktop update needs attention"><div><strong>ShellX Drive Desktop update needs attention</strong><span>An earlier update to version ${target} could not be confirmed. Version ${current} is currently running.</span></div><button class="button" data-action="desktop-update-open">Open update settings</button></section>`;
}

export function renderDesktopUpdate(state, currentVersion, escape) {
  const version = escape(currentVersion || "version unavailable");
  const signedCopy = "Updates are accepted only when their signature matches this installed app.";
  let body = `<p class="when">${signedCopy}</p>`;
  if (state.status === "checking") {
    body += `<p class="when" role="status">Checking the official release…</p>`;
  } else if (state.status === "current") {
    body += `<p class="update-current" role="status">This desktop app is up to date.</p>`;
  } else if (state.status === "available") {
    body += `<div class="desktop-update-available" role="status"><strong>Version ${escape(state.info?.version || "new")} is available</strong>${state.info?.notes ? `<p>${escape(state.info.notes.slice(0, 500))}</p>` : ""}</div>`;
  } else if (state.status === "confirming") {
    body += `<div class="review-confirmation" role="alert"><p>Download and install signed ShellX Drive Desktop ${escape(state.info?.version || "update")}? The app will restart after signature verification and installation.</p><div class="action-row"><button class="button" data-action="desktop-update-cancel">Cancel</button><button class="button primary" data-action="desktop-update-install">Download and install</button></div></div>`;
  } else if (state.status === "downloading") {
    const percent = desktopUpdatePercent(state);
    const progress = percent === null ? "Downloading signed update…" : `Downloading signed update… ${percent}%`;
    body += `<div class="desktop-update-progress" role="status"><span>${progress}</span><progress ${percent === null ? "" : `value="${percent}"`} max="100"></progress></div>`;
  } else if (state.status === "installing") {
    body += `<p class="update-current" role="status">Download complete. Verifying the signature and installing the signed update.</p>`;
  } else if (state.status === "restarting") {
    body += `<p class="update-current" role="status">Signature verified. Restarting ShellX Drive Desktop to complete installation.</p>`;
  } else if (state.status === "error") {
    body += `<p class="diagnostic" role="alert">${escape(state.error || "The update check could not complete.")}</p>`;
  }
  const busy = ["checking", "downloading", "installing", "restarting"].includes(state.status);
  const action = ["available", "confirming", "downloading", "installing", "restarting"].includes(state.status)
    ? ""
    : `<div class="action-row"><button class="button" data-action="desktop-update-check" ${busy ? "disabled" : ""}>Check for updates</button></div>`;
  const availableAction = state.status === "available"
    ? `<div class="action-row"><button class="button primary" data-action="desktop-update-confirm">Review update</button></div>`
    : "";
  return `<section class="settings-section" aria-labelledby="desktop-update-heading"><h3 id="desktop-update-heading">Desktop app</h3><p class="app-version">Installed version ${version}</p>${body}${action}${availableAction}</section>`;
}
