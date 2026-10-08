import { activityHistoryPage } from "./activity-history.mjs";
import { statusCopy } from "./ui-state.mjs";

export const SYNC_INTERVALS = Object.freeze([
  [20, "20 seconds"], [60, "1 minute"], [300, "5 minutes"],
  [900, "15 minutes"], [1800, "30 minutes"], [3600, "1 hour"],
]);

export function intervalLabel(seconds) {
  return SYNC_INTERVALS.find(([value]) => value === Number(seconds))?.[1] || `${seconds} seconds`;
}

export function normalizeConnectionsView(raw, normalizeDesktopView) {
  if (!raw || !raw.preferences || !Array.isArray(raw.connections)) throw new Error("The desktop service returned an invalid server list.");
  const preferences = raw.preferences;
  const defaultInterval = Number(preferences.defaultSyncIntervalSeconds ?? preferences.default_sync_interval_seconds ?? 20);
  if (!SYNC_INTERVALS.some(([seconds]) => seconds === defaultInterval)) throw new Error("The desktop service returned an invalid sync check interval.");
  const ids = new Set();
  const connections = raw.connections.map((connection) => {
    if (typeof connection.id !== "string" || !connection.id || ids.has(connection.id) || !connection.view) throw new Error("The desktop service returned an invalid connection identity.");
    ids.add(connection.id);
    const intervalSeconds = connection.intervalSeconds ?? connection.interval_seconds ?? null;
    const effectiveIntervalSeconds = Number(connection.effectiveIntervalSeconds ?? connection.effective_interval_seconds ?? intervalSeconds ?? defaultInterval);
    if ((intervalSeconds !== null && !SYNC_INTERVALS.some(([seconds]) => seconds === Number(intervalSeconds)))
      || !SYNC_INTERVALS.some(([seconds]) => seconds === effectiveIntervalSeconds)) throw new Error("The desktop service returned an invalid connection interval.");
    return {
      id: connection.id,
      name: String(connection.name || "Drive server"),
      intervalSeconds: intervalSeconds === null ? null : Number(intervalSeconds),
      effectiveIntervalSeconds,
      lifecycle: String(connection.lifecycle ?? "active").toLowerCase(),
      connectionFolder: String(connection.connectionFolder ?? connection.connection_folder ?? ""),
      view: normalizeDesktopView(connection.view),
    };
  });
  return {
    appVersion: String(raw.appVersion ?? raw.app_version ?? ""),
    preferences: {
      initialized: Boolean(preferences.initialized),
      theme: ["system", "light", "dark"].includes(preferences.theme) ? preferences.theme : "system",
      launchAtLogin: Boolean(preferences.launchAtLogin ?? preferences.launch_at_login),
      defaultSyncIntervalSeconds: defaultInterval,
    },
    connections,
  };
}

export function connectionArguments(connectionId, args = {}) {
  if (typeof connectionId !== "string" || !connectionId) throw new Error("Select a saved server connection before continuing.");
  return { ...args, connectionId };
}

export function connectionFolder(connection) {
  return connection.connectionFolder || connection.view.localRoot || "";
}

export function connectionDraft(connection = null) {
  return {
    mode: connection ? "edit" : "add",
    connectionId: connection?.id ?? null,
    step: 1,
    name: connection?.name ?? "",
    serverUrl: connection?.view.serverUrl ?? "",
    accountEmail: connection?.view.account ?? "",
    intervalSeconds: connection?.intervalSeconds ?? null,
    folder: connection ? connectionFolder(connection) : "",
    originalFolder: connection ? connectionFolder(connection) : "",
    folderChanged: false,
    folderConfirmed: false,
  };
}

export function verifiedDuplicate(connections, connectionId, serverUrl, verifiedEmail) {
  if (!verifiedEmail) return null;
  const url = String(serverUrl).replace(/\/$/, "");
  const email = String(verifiedEmail).trim().toLowerCase();
  return connections.find((connection) => connection.id !== connectionId
    && connection.view.serverUrl.replace(/\/$/, "") === url
    && connection.view.account.trim().toLowerCase() === email) || null;
}

export function duplicateConnectionFromError(connections, error) {
  // This native error is emitted only after server-confirmed identity admission.
  // Resolve its exact durable ID; never guess a duplicate from submitted email.
  const message = error?.message ?? String(error);
  const id = /this server account already belongs to [\s\S]*? \(connection ([^)]+)\)/i.exec(message)?.[1];
  return id ? connections.find((connection) => connection.id === id) || null : null;
}

export function intervalOptions(selected, defaultSeconds = null) {
  const inherited = defaultSeconds === null ? "" : `<option value="default" ${selected === null ? "selected" : ""}>Use app default (${intervalLabel(defaultSeconds)})</option>`;
  return inherited + SYNC_INTERVALS.map(([seconds, label]) => `<option value="${seconds}" ${Number(selected) === seconds ? "selected" : ""}>${label}</option>`).join("");
}

export function icon(name) {
  const paths = {
    drive: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M3 14h18M7 17h.01M11 17h.01M7 9h10"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    arrow: '<path d="m9 5-7 7 7 7M2 12h19"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    alert: '<path d="m12 3 10 18H2zM12 9v4M12 17h.01"/>',
    pause: '<path d="M8 5v14M16 5v14"/>',
    refresh: '<path d="M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 3M18 18a8 8 0 0 1-13-3"/>',
  };
  return `<svg class="icon${name === "refresh" ? " spinner" : ""}" viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.drive}</svg>`;
}

export function connectionStatus(connection) {
  if (connection.lifecycle === "removing") return { label: "Removing", detail: "Retiring this connection safely. Local files stay in their folders." };
  if (connection.view.disconnectCleanupPending) return { label: "Needs attention", detail: "Complete the saved connection's retirement before changing its setup." };
  if (connection.view.credentialRecoveryPending) return { label: "Needs reconnect", detail: "Unlock the credential store and renew this account's saved sign-in." };
  if (connection.lifecycle === "recovery") return { label: "Finish setup", detail: connection.view.activePairId ? "Resume setup using this account’s saved sign-in and paired folder." : "Remove this unfinished connection, then add the server again to choose its local folder." };
  return statusCopy(connection.view.status);
}

export function renderServers(model, escape, errors = new Map()) {
  const head = `<div class="page-head"><div><h1 id="page-heading" tabindex="-1">Servers</h1><p>Manage each account connection independently.</p></div><button class="button primary" id="add-server" data-action="add-server">+ Add server</button></div>`;
  if (!model.connections.length) return `${head}<section class="empty-state"><div>${icon("drive")}</div><h2>Add your first server</h2><p>Connect an account to a separate local folder. App preferences and desktop updates are available in App settings.</p></section>`;
  return `${head}<div class="server-list">${model.connections.map((connection) => {
    const copy = connectionStatus(connection);
    const view = connection.view;
    const state = view.status.replaceAll("_", "-");
    const folder = connectionFolder(connection);
    const error = errors.get(connection.id) || view.error;
    return `<article class="server-row" data-connection-row="${escape(connection.id)}"><div class="server-row-top"><button class="button text server-name" data-action="select-connection" data-connection-id="${escape(connection.id)}">${escape(connection.name)}</button><span class="status-label ${state}">${icon(view.status === "synced" ? "check" : view.status === "syncing" ? "refresh" : view.status === "paused" ? "pause" : "alert")}${escape(copy.label)}</span></div><p class="host">${escape(view.serverHost || view.serverUrl)} · ${escape(view.account || "Sign-in needs attention")}</p>${folder ? `<button class="button text folder-link" data-action="open-connection-folder" data-connection-id="${escape(connection.id)}" aria-label="Open local folder for ${escape(connection.name)}">${icon("folder")}<span class="folder-path">${escape(folder)}</span></button>` : `<p class="host">No local folder is paired.</p>`}<div class="server-row-bottom"><span class="interval-copy">Checks every ${escape(intervalLabel(connection.effectiveIntervalSeconds))}${connection.intervalSeconds === null ? " · app default" : ""}</span><button class="button small" data-action="select-connection" data-connection-id="${escape(connection.id)}">Manage</button></div>${error ? `<p class="connection-error" role="status">${escape(error)}</p>` : ""}</article>`;
  }).join("")}</div><p class="context-note">All configured, unpaused connections keep syncing. Selecting a server changes only the displayed details.</p>`;
}

export function renderAppPreferences(model, draft, escape, first = false) {
  const preferences = draft || model.preferences;
  return `<div class="page-head"><div><h1 id="page-heading" tabindex="-1">${first ? "App preferences" : "App settings"}</h1><p>${first ? "Choose your preferences before adding a server." : "These settings apply to the app."}</p></div></div><form id="settings-form"><div class="settings-body"><div class="setting-row"><label for="setting-theme">Appearance<select id="setting-theme" name="theme">${["system", "light", "dark"].map((theme) => `<option value="${theme}" ${preferences.theme === theme ? "selected" : ""}>${theme[0].toUpperCase() + theme.slice(1)}</option>`).join("")}</select></label><p>System follows this device's appearance.</p></div><div class="setting-row"><label for="launch-at-login">Launch at login<input id="launch-at-login" name="launchAtLogin" type="checkbox" ${preferences.launchAtLogin ? "checked" : ""} /></label><p>Your choice stays in place when adding another server.</p></div><div class="setting-row"><label for="setting-interval">Default sync check interval<select id="setting-interval" name="defaultSyncIntervalSeconds">${intervalOptions(preferences.defaultSyncIntervalSeconds)}</select></label><p>Applies to connections using the app default. Overrides remain unchanged. A sync pass can take longer than this delay.</p></div></div><div class="form-actions"><button class="button${first ? " primary" : ""}" type="submit">${first ? "Save and continue" : "Save app settings"}</button></div></form>`;
}

export function renderConnectionEditor(draft, connection, defaultInterval, escape) {
  const view = connection.view;
  return `<button class="button text back" data-action="cancel-editor">${icon("arrow")}${escape(connection.name)}</button><h1 id="page-heading" tabindex="-1">Edit server</h1><form id="connection-edit-form"><div class="form-block"><h2>Connection identity</h2><div class="identity"><div>${escape(view.serverHost || view.serverUrl)}</div><div class="muted">${escape(view.account)}</div></div><p class="readonly-label">Host and account stay saved. Add another connection for a different account.</p><div class="account-access"><span>${escape(connectionStatus(connection).label)}</span><button class="button small" id="update-signin" type="button" data-action="update-signin">Update sign-in</button></div><p class="account-help">Use your new password after changing or resetting it on the server. Your local folder and sync settings stay saved.</p><label class="field" for="server-name">Friendly name<input id="server-name" name="name" value="${escape(draft.name)}" maxlength="40" required /></label><label class="field" for="server-interval">Sync check interval<select id="server-interval" name="intervalSeconds">${intervalOptions(draft.intervalSeconds, defaultInterval)}</select></label><div class="field"><span id="folder-label">Local folder</span><div class="folder-picker-row"><output class="folder-readout" id="folder-readout" aria-labelledby="folder-label">${escape(draft.folder || "No folder selected")}</output><button class="button" type="button" data-action="choose-edit-folder">Browse…</button></div><span class="hint">Choose a separate empty folder with the system folder picker.</span></div>${draft.folderChanged ? `<div class="notice warning" id="folder-change-note"><strong>Start syncing in a new empty folder</strong><p>Files stay in ${escape(draft.originalFolder)}. Drive starts a fresh sync in ${escape(draft.folder)}.</p></div><label class="check-field"><input id="change-consent" name="folderConfirmed" type="checkbox" ${draft.folderConfirmed ? "checked" : ""} /><span>I understand old files remain and the new folder starts a fresh sync.</span></label><button class="button text small" type="button" data-action="cancel-folder-change">Keep current folder</button>` : ""}</div><div class="form-actions"><button class="button" type="button" data-action="cancel-editor">Cancel</button><button class="button primary" type="submit" ${draft.folderChanged && !draft.folderConfirmed ? "disabled aria-describedby=\"folder-change-note\"" : ""}>Save server</button></div></form>`;
}

export function renderPasswordFields(needsSecondFactor, escape, email, emailReadonly = false) {
  return `<label class="field" for="server-email">Account email<input id="server-email" name="email" type="email" autocomplete="username" value="${escape(email)}" ${emailReadonly ? "readonly" : "required"} /></label><label class="field" for="server-password">Server password<input id="server-password" name="password" type="password" autocomplete="current-password" required aria-describedby="server-password-hint" /><span id="server-password-hint" class="hint">If your password was changed or reset, enter the new password here.</span></label>${needsSecondFactor ? `<p class="context-note">Enter a current TOTP or recovery code with the same server password.</p><label class="field" for="totp-code">TOTP code<input id="totp-code" name="totpCode" inputmode="numeric" autocomplete="one-time-code" /></label><label class="field" for="recovery-code">Or recovery code<input id="recovery-code" name="recoveryCode" autocomplete="off" /></label>` : ""}`;
}

export function connectionHistoryEntries(connections, connectionId = "all") {
  return connections.filter((connection) => connectionId === "all" || connection.id === connectionId).flatMap((connection) => connection.view.activity.map((entry) => ({
    ...entry, connectionId: connection.id, connectionName: connection.name, account: connection.view.account,
    // Reuse the history helper's search, range, sorting, and bounded paging.
    direction: `${entry.direction || ""} ${connection.name} ${connection.view.account}`,
  })));
}

export function connectionHistoryPage(connections, history, connectionId = "all", now) {
  return activityHistoryPage(connectionHistoryEntries(connections, connectionId), history, now);
}

export function renderConnectionHistory(model, history, connectionId, escape) {
  const result = connectionHistoryPage(model.connections, history, connectionId);
  const options = model.connections.map((connection) => `<option value="${escape(connection.id)}" ${connection.id === connectionId ? "selected" : ""}>${escape(connection.name)} · ${escape(connection.view.account)}</option>`).join("");
  const filtered = connectionId !== "all" || history.query || history.range !== "7d";
  return `<div class="page-head"><div><h1 id="page-heading" tabindex="-1">History</h1><p>Activity across your saved connections.</p></div></div><form id="history-filter-form" class="history-filters"><div class="history-filter-pair"><label class="field" for="history-connection">Connection<select id="history-connection" name="historyConnection"><option value="all" ${connectionId === "all" ? "selected" : ""}>All connections</option>${options}</select></label><label class="field" for="history-range">Time frame<select id="history-range" name="historyRange">${[["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["all", "All retained"]].map(([value, label]) => `<option value="${value}" ${history.range === value ? "selected" : ""}>${label}</option>`).join("")}</select></label></div><div class="history-search-row"><label class="field" for="history-query">Search history<input id="history-query" name="historyQuery" type="search" value="${escape(history.query)}" placeholder="File, action or result" /></label><div class="history-filter-actions"><button class="button" type="submit">Apply filters</button>${filtered ? `<button class="button text" type="button" data-action="history-clear">Clear filters</button>` : ""}</div></div></form><section class="history-results" aria-label="Filtered history"><div class="activity-head"><h2>${connectionId === "all" ? "All connections" : escape(model.connections.find((connection) => connection.id === connectionId)?.name || "Connection")}</h2><span class="history-count" role="status">${result.total} ${result.total === 1 ? "event" : "events"}</span></div>${result.entries.length ? `<ol class="activity-list connection-history-list">${result.entries.map((entry) => `<li><time datetime="${escape(entry.at)}" title="${escape(new Date(entry.at).toLocaleString())}">${escape(new Date(entry.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))}</time><div><span class="history-server-name">${escape(entry.connectionName)} · ${escape(entry.account)}</span><span class="history-entry-title">${escape(entry.path ?? entry.relativePath ?? entry.relative_path ?? "")}</span><small>${escape(entry.result || "")}</small></div></li>`).join("")}</ol>` : `<p class="history-empty">${model.connections.some((connection) => connection.view.activity.length) ? "No history matches these filters." : "History will appear after the first completed sync."}</p>`}${result.pageCount > 1 ? `<nav class="history-pagination" aria-label="History pages"><button class="button small" data-action="history-previous" ${result.page === 1 ? "disabled" : ""}>Previous</button><span>Page ${result.page} of ${result.pageCount}</span><button class="button small" data-action="history-next" ${result.page === result.pageCount ? "disabled" : ""}>Next</button></nav>` : ""}</section>`;
}
