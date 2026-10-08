import { deletionReviewChoices, mayRecheckReviews, mayRunSync, reviewActionLabel, reviewConfirmationCopy, } from "./ui-state.mjs";
import { frontendMode, routeDesktopInvoke } from "./bootstrap-state.mjs";
import { applyLoginReply, beginWorkspaceDiscovery, driveLocationChoices, emptySetupState, failWorkspaceDiscovery, pairSelectionReady, selectLocalRoot } from "./setup-state.mjs";
import { completeWorkspacePage, selectDiscoveredRoot } from "./setup-pages.mjs";
import { formatByteSize, normalizeSyncLocations, renderDiscoveredRoots, renderSyncLocations } from "./sync-locations.mjs";
import { bindActivityHistory, emptyHistoryState } from "./activity-history.mjs";
import { applyDesktopUpdateEvent, emptyDesktopUpdateState, renderDesktopUpdate, renderDesktopUpdateNotice, renderDesktopUpdateRecoveryNotice } from "./app-updates.mjs";
import { connectionArguments, connectionDraft, connectionFolder, connectionHistoryPage, connectionStatus, duplicateConnectionFromError, icon, intervalLabel, intervalOptions, normalizeConnectionsView, renderAppPreferences, renderConnectionEditor, renderConnectionHistory, renderPasswordFields, renderServers, verifiedDuplicate } from "./connection-management.mjs";

const app = document.querySelector("#app");
const nativeInvoke = window.__TAURI__?.core?.invoke;
const NativeChannel = window.__TAURI__?.core?.Channel;
const nativeListen = window.__TAURI__?.event?.listen;
const frontend = frontendMode({ hasNativeInvoke: typeof nativeInvoke === "function", search: window.location.search });
const browserPreview = frontend.kind === "demo";
let invokeDemo = null;
let appModel = null;
let screen = "servers";
let selectedConnectionId = null;
let currentView = null;
let showSettings = false;
let showReviews = false;
let editor = null;
let lastAddDraft = null;
let signin = null;
let setup = emptySetupState();
let settingsDraft = null;
let history = emptyHistoryState();
let historyConnectionId = "all";
let addRootPicker = null;
let syncLocationsFilter = "";
let desktopUpdate = emptyDesktopUpdateState();
let actionError = "";
const connectionErrors = new Map();
let pendingReviewConfirmation = null;
let pendingDisconnectConfirmation = false;
let pendingDesktopAgentControl = null;
let pendingFocusSelector = null;
let foregroundActionInFlight = false;
let backgroundRefreshInFlight = false;
let viewGeneration = 0;
let disconnectRequestInFlight = false;
let cleanupRetryState = "idle";
let cleanupRetryError = null;

async function invoke(command, args = {}) {
  return routeDesktopInvoke(frontend, nativeInvoke, invokeDemo, command, args);
}

function invokeConnection(command, connectionId, args = {}) {
  return invoke(command, connectionArguments(connectionId, args));
}

function escape(value = "") {
  return String(value).replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;" })[character]);
}

function displayTime(value) {
  const date = value ? new Date(value) : null;
  return !date || Number.isNaN(date.valueOf()) ? "No completed sync yet" : `Last synced ${date.toLocaleString()}`;
}

function normalizeView(raw) {
  const activePairId = raw.activePairId ?? raw.active_pair_id ?? null;
  const driveLocation = raw.driveLocation ?? raw.drive_location ?? "";
  const localRoot = raw.localRoot ?? raw.local_root ?? "";
  return {
    status: raw.status ?? "needs_setup",
    appVersion: raw.appVersion ?? raw.app_version ?? "",
    account: raw.account ?? raw.account_email ?? "",
    serverHost: raw.serverHost ?? raw.server_host ?? "",
    serverUrl: raw.serverUrl ?? raw.server_url ?? "",
    driveLocation,
    localRoot,
    localUsageBytes: raw.localUsageBytes ?? raw.local_usage_bytes ?? null,
    localUsageFileCount: raw.localUsageFileCount ?? raw.local_usage_file_count ?? null,
    localUsageFolderCount: raw.localUsageFolderCount ?? raw.local_usage_folder_count ?? null,
    activePairId,
    syncLocations: normalizeSyncLocations(raw.syncLocations ?? raw.sync_locations, activePairId, { driveLocation, localRoot }),
    rootDiscoveryOverflow: raw.rootDiscoveryOverflow ?? raw.root_discovery_overflow ?? false,
    lastSuccessfulSync: raw.lastSuccessfulSync ?? raw.last_successful_sync ?? null,
    reviewCount: raw.reviewCount ?? raw.review_count ?? raw.reviews?.length ?? 0,
    pendingRemoteRevocations: raw.pendingRemoteRevocations ?? raw.pending_remote_revocations ?? 0,
    credentialRecoveryPending: raw.credentialRecoveryPending ?? raw.credential_recovery_pending ?? false,
    disconnectAvailable: raw.disconnectAvailable ?? raw.disconnect_available ?? false,
    disconnectRequested: raw.disconnectRequested ?? raw.disconnect_requested ?? false,
    disconnectCleanupPending: raw.disconnectCleanupPending ?? raw.disconnect_cleanup_pending ?? false,
    disconnectRemoteRetirementConfirmed: raw.disconnectRemoteRetirementConfirmed ?? raw.disconnect_remote_retirement_confirmed ?? false,
    activeFiles: raw.activeFiles ?? raw.active_files ?? null,
    reviews: raw.reviews ?? [],
    activity: raw.activity ?? [],
    paused: raw.paused ?? false,
    launchAtLogin: raw.launchAtLogin ?? raw.launch_at_login ?? true,
    desktopAgentEnabled: raw.desktopAgentEnabled ?? raw.desktop_agent_enabled ?? false,
    desktopAgentReady: raw.desktopAgentReady ?? raw.desktop_agent_ready ?? false,
    updateRecoveryTargetVersion: raw.updateRecoveryTargetVersion ?? raw.update_recovery_target_version ?? "",
    error: raw.error ?? raw.last_error ?? null,
  };
}


function selectedConnection() {
  return appModel?.connections.find((connection) => connection.id === selectedConnectionId) || null;
}

function applyConnectionsView(raw) {
  const previous = selectedConnection();
  appModel = normalizeConnectionsView(raw, normalizeView);
  if (!appModel.preferences.initialized) screen = "preferences";
  if (selectedConnectionId && !selectedConnection() && editor?.mode !== "add") {
    selectedConnectionId = null;
    editor = null;
    signin = null;
    addRootPicker = null;
    pendingReviewConfirmation = null;
    pendingDisconnectConfirmation = false;
    if (["detail", "editor", "signin"].includes(screen)) screen = "servers";
  }
  if (historyConnectionId !== "all" && !appModel.connections.some((connection) => connection.id === historyConnectionId)) historyConnectionId = "all";
  const next = selectedConnection();
  if (previous && next && (previous.view.serverUrl !== next.view.serverUrl || previous.view.account.toLowerCase() !== next.view.account.toLowerCase())) {
    resetConnectionSurfaces();
    editor = null;
    signin = null;
    screen = "detail";
    actionError = "This server's saved identity changed. Review its current details before continuing.";
    connectionErrors.set(next.id, actionError);
  }
  const theme = appModel.preferences.theme;
  if (theme === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.dataset.theme = theme;
}

async function reloadConnections({ renderResult = true, preserveViewport = false } = {}) {
  applyConnectionsView(await invoke("get_connections_view"));
  if (renderResult) render(null, { preserveViewport });
}

function applyConnectionReply(connectionId, raw) {
  if (!raw || typeof raw.status !== "string") throw new Error("The desktop service returned an invalid server status.");
  const connection = appModel.connections.find((item) => item.id === connectionId);
  if (connection) connection.view = normalizeView(raw);
}

function pendingRemoteRevocationNotice(view) {
  if (view.disconnectCleanupPending) return "";
  const count = Number(view.pendingRemoteRevocations) || 0;
  if (!count) return "";
  const sessions = count === 1 ? "session" : "sessions";
  return `<p class="notice warning" data-remote-revocation-notice role="status">Local credentials are removed. Remote revocation is pending for ${count} ${sessions}; ShellX Drive retries after the next successful sign-in to the same server and account, or drops the record after expiry.</p>`;
}

function removalConfirmation(connection) {
  if (!pendingDisconnectConfirmation) return "";
  return `<div class="review-confirmation" role="alert"><strong>Remove ${escape(connection.name)} from this app?</strong><p>${escape(connection.view.serverHost || connection.view.serverUrl)} · ${escape(connection.view.account)}</p><p class="dialog-path">${escape(connectionFolder(connection) || "No paired folder")}</p><p>Only this connection stops and its saved session is retired. Local files stay in every managed folder. Other servers and app preferences stay available.</p><div class="action-row"><button class="button" data-action="disconnect-cancel">Cancel</button><button class="button danger" data-action="disconnect-confirm">Remove server</button></div></div>`;
}

function disconnectRecoveryCopy(view) {
  return view.disconnectRemoteRetirementConfirmed ? {
    heading: "Finish disconnect cleanup", action: "Finish disconnect cleanup",
    idle: "Remote retirement is confirmed. ShellX Drive still needs to remove the exact local marker and saved credential slots.",
  } : {
    heading: "Retry remote retirement", action: "Retry remote retirement",
    idle: "Remote retirement is not confirmed. Your local Drive pair and saved credentials are retained; local cleanup is blocked.",
  };
}

function disconnectCleanupRecoveryView(view) {
  const copy = disconnectRecoveryCopy(view);
  return `<section class="section-divider cleanup-recovery" aria-label="${escape(copy.heading)}"><h2>${escape(copy.heading)}</h2><p class="context-note" role="status">${escape(cleanupRetryState === "running" ? "Retiring only this connection. Keep this window open." : copy.idle)}</p>${view.error ? `<p class="notice error" role="alert">${escape(view.error)}</p>` : ""}${cleanupRetryError ? `<p class="notice error" role="alert">${escape(cleanupRetryError)}</p>` : ""}<div class="actions"><button class="button primary" data-action="finish-disconnect-cleanup" ${cleanupRetryState === "running" ? "disabled aria-busy=\"true\"" : ""}>${escape(copy.action)}</button></div></section>`;
}

function reviews(view) {
  if (!view.reviews.length) {
    return view.reviewCount > 0
      ? `<div class="empty">A different managed Drive root has a decision waiting. Open Managed Drive roots to identify that location; its review stays attached to the correct local files.</div>`
      : `<div class="empty">There are no decisions waiting for you.</div>`;
  }
  return view.reviews.map((item) => {
    const choices = deletionReviewChoices(item);
    const pending = pendingReviewConfirmation?.reviewId === item.id;
    const descendants = item.descendantCount ?? item.descendant_count ?? 0;
    const buttons = choices.map((action) => `<button class="button" data-action="review-choice" data-review-id="${escape(item.id)}" data-review-action="${escape(action)}">${escape(reviewActionLabel(action))}</button>`).join("");
    const confirmation = pending ? `<div class="review-confirmation" role="alert"><p>${escape(reviewConfirmationCopy(item, pendingReviewConfirmation.action))}</p><div class="action-row"><button class="button danger" data-action="review-cancel">Cancel</button><button class="button primary" data-action="review-confirm">Confirm ${escape(reviewActionLabel(pendingReviewConfirmation.action))}</button></div></div>` : "";
    const unavailable = choices.length ? "" : "<small>Use Open folder to inspect or safely rename the item, then choose Recheck review. Drive will not guess a destructive resolution.</small>";
    return `<article class="review">
      <div><strong>${escape(item.relativePath ?? item.relative_path ?? "")}</strong><p>${escape(item.summary)}</p>${descendants ? `<small>${descendants} descendants affected</small>` : ""}${unavailable}${confirmation}</div>
      ${choices.length && !pending ? `<div class="action-row">${buttons}</div>` : ""}
    </article>`;
  }).join("");
}


function renderAddRootPicker(view) {
  if (!addRootPicker) return "";
  const available = addRootPicker.workspacesLoaded ? driveLocationChoices(addRootPicker.workspaces) : [];
  return `<section class="section-divider" aria-label="Add a Drive root"><div class="activity-head"><h2>Add a Drive root</h2><button class="button small" data-action="close-add-root">Close</button></div><p class="context-note">Choose one available location. Browsing does not add it to this connection.</p>${addRootPicker.workspaceDiscoveryError ? `<p class="notice error" role="alert">${escape(addRootPicker.workspaceDiscoveryError)}</p><button class="button" data-action="retry-add-root">Retry roots</button>` : ""}${available.length ? renderDiscoveredRoots(available, escape, addRootPicker.selectedSyncRootId, "addSyncRootId") : addRootPicker.workspacesLoaded ? "<p>No locations on this page.</p>" : "<p aria-busy=\"true\">Loading Drive roots…</p>"}<div class="actions">${addRootPicker.rootPageIndex ? `<button class="button" data-action="first-add-root-page">Start over</button>` : ""}<button class="button" data-action="next-add-root-page" ${addRootPicker.nextRootCursor ? "" : "disabled"}>More roots</button><button class="button primary" data-action="confirm-add-root" ${addRootPicker.workspacesLoaded && addRootPicker.selectedSyncRootId && view.syncLocations.length < 100 ? "" : "disabled"}>Add selected root</button></div>${view.syncLocations.length >= 100 ? "<p role=\"status\">This connection has reached its 100-root limit. Browsing remains available.</p>" : ""}</section>`;
}

function detailView(connection) {
  const view = connection.view;
  const copy = connectionStatus(connection);
  const blocked = view.disconnectCleanupPending || connection.lifecycle === "removing";
  const recovering = connection.lifecycle === "recovery";
  const recheck = mayRecheckReviews(view);
  const hasIdentity = Boolean(view.account && view.serverUrl);
  const signinRequired = view.status === "needs_reconnect" || view.credentialRecoveryPending;
  const canResumeSetup = recovering && Boolean(view.activePairId) && !blocked && !signinRequired;
  const canSync = connection.lifecycle === "active" && !blocked && !signinRequired && (recheck || mayRunSync(view.status));
  const syncAction = recheck ? "recheck-reviews" : "sync-now";
  const syncLabel = recheck ? "Recheck review" : view.status === "offline" ? "Retry connection" : view.status === "syncing" ? "Syncing…" : "Sync now";
  const agentControl = pendingDesktopAgentControl === null
    ? `<button class="button small" data-action="desktop-agent-control">${view.desktopAgentEnabled ? "Disable" : "Enable"} remote agent control</button>`
    : `<div class="review-confirmation" role="alert"><p>${pendingDesktopAgentControl ? "Allow remote agent control from this paired desktop? An authenticated account owner or delegate can request sync and exact signed updates." : "Disable remote agent control for this connection?"}</p><div class="actions"><button class="button" data-action="desktop-agent-cancel">Cancel</button><button class="button" data-action="desktop-agent-confirm">Confirm</button></div></div>`;
  return `<button class="button text back" data-action="back-to-servers">${icon("arrow")}Servers</button><div class="detail-heading"><div><h1 id="page-heading" tabindex="-1">${escape(connection.name)}</h1><p class="host">${escape(view.serverHost || view.serverUrl)} · ${escape(view.account)}</p></div>${!blocked ? `<button class="button small" data-action="edit-server">Edit server</button>` : ""}</div><section class="detail-state"><h2 id="status-title" tabindex="-1"><span class="status-label ${view.status.replaceAll("_", "-")}">${icon(view.status === "synced" ? "check" : view.status === "syncing" ? "refresh" : "alert")}${escape(copy.label)}</span></h2><p>${escape(copy.detail)}</p>${view.error && !blocked ? `<p class="notice error" data-backend-error role="alert">${escape(view.error)}</p>` : ""}${view.disconnectRequested || disconnectRequestInFlight ? `<p class="notice warning" data-disconnect-requested role="status">Stopping synchronization before removing this server. Saved credentials and device access stay in place until the active operation finishes safely.</p>` : ""}</section>${pendingRemoteRevocationNotice(view)}${blocked ? disconnectCleanupRecoveryView(view) : `<div class="actions">${signinRequired && hasIdentity ? `<button class="button primary" data-action="update-signin">Reconnect</button>` : canResumeSetup ? `<button class="button primary" data-action="resume-setup">Resume setup</button>` : view.paused && !recovering ? `<button class="button primary" data-action="pause-resume">Resume sync</button>` : `<button class="button ${view.status === "offline" ? "primary" : ""}" data-action="${syncAction}" ${canSync ? "" : "disabled"}>${syncLabel}</button>`}<button class="button" data-action="open-local-folder" ${view.localRoot ? "" : "disabled"}>Open folder</button>${hasIdentity ? `<button class="button" data-action="open-drive">Open Drive</button>` : ""}${!recovering && !signinRequired && !view.paused ? `<button class="button" data-action="pause-resume" ${view.status === "syncing" ? "disabled" : ""}>Pause sync</button>` : ""}</div><dl class="properties"><div><dt>Local folder</dt><dd>${escape(connectionFolder(connection) || "No folder paired")}</dd></div><div><dt>Sync check interval</dt><dd>${escape(intervalLabel(connection.effectiveIntervalSeconds))}${connection.intervalSeconds === null ? " · app default" : ""}</dd></div><div><dt>Saved session</dt><dd>Protected by this operating system’s credential store</dd></div><div><dt>Local disk usage (all locations)</dt><dd>${escape(formatByteSize(view.localUsageBytes))}</dd></div><div><dt>Last completed sync</dt><dd>${escape(displayTime(view.lastSuccessfulSync))}</dd></div></dl>${view.rootDiscoveryOverflow ? `<p class="notice warning" data-root-discovery-overflow role="status">Configured Drive roots continue syncing. Browse the available roots in pages to add another.</p>` : ""}${view.credentialRecoveryPending && !hasIdentity ? `<p class="notice warning" role="alert">Unlock this operating system's credential store, then close and reopen ShellX Drive to retry. Drive cannot safely identify this interrupted sign-in.</p>` : ""}${showReviews || view.status === "needs_review" ? `<section class="section-divider"><div class="activity-head"><h2 id="daily-section-title" tabindex="-1">Needs review</h2><span>${view.reviewCount} awaiting a decision</span></div>${reviews(view)}</section>` : ""}${renderSyncLocations(view, escape, syncLocationsFilter)}<div class="actions">${hasIdentity && !signinRequired && !recovering ? `<button class="button" data-action="open-add-root" ${view.status === "syncing" ? "disabled" : ""}>Add Drive root</button>` : ""}<button class="button text" data-action="view-history">View history</button></div>${renderAddRootPicker(view)}${view.activePairId && !recovering ? `<section class="section-divider"><h2>Remote agent control</h2><p class="context-note">${view.desktopAgentEnabled ? view.desktopAgentReady ? "Enabled for this connection." : "Enabled; enrollment needs attention." : "Disabled for this connection."}</p>${agentControl}</section>` : ""}<section class="section-divider management"><button class="button danger" data-action="disconnect">Remove server</button><span class="small-copy muted">Local files stay in their folders.</span></section>${removalConfirmation(connection)}`}`;
}

function setupView() {
  const activeStep = !setup.serverValidated ? 1 : !setup.signedIn ? 2 : 3;
  const steps = ["Server", "Account", "Folder"];
  const head = `<button class="button text back" data-action="editor-back">${icon("arrow")}${activeStep === 1 ? "Servers" : "Back"}</button><h1 id="page-heading" tabindex="-1">Add server</h1><div class="stepper" aria-label="Step ${activeStep} of 3">${steps.map((label, index) => `<span class="${activeStep === index + 1 ? "active" : ""}"><i>${index + 1}</i>${label}</span>${index < 2 ? "<b>›</b>" : ""}`).join("")}</div>`;
  const cancel = `<button class="button" type="button" data-action="cancel-editor">Cancel</button>`;
  if (!setup.serverValidated) return `${head}<form id="server-form"><div class="form-block"><h2>Connect a server</h2><p class="intro">Use a friendly name for each account connection, such as Work or Personal.</p><label class="field" for="server-url">Server URL<input id="server-url" name="serverUrl" type="url" value="${escape(editor.serverUrl)}" placeholder="https://drive.example.com" required /><span class="hint">Use HTTPS. The host shown after validation is the one that receives your sign-in.</span></label><label class="field" for="server-name">Friendly name<input id="server-name" name="name" value="${escape(editor.name)}" maxlength="40" required /></label></div><div class="form-actions">${cancel}<button class="button primary" type="submit">Validate server</button></div></form>`;
  if (!setup.signedIn) return `${head}<form id="login-form"><div class="form-block"><h2>Sign in to this server</h2><div class="notice"><strong>Validated server</strong><p>${escape(setup.serverUrl)}</p></div>${renderPasswordFields(setup.authNeeds2fa, escape, editor.accountEmail)}<p class="context-note">Each authenticated account has its own local folder and sync settings. This desktop session is protected by this operating system’s credential store.</p>${editor.existingConnectionId ? `<button class="button" type="button" data-action="open-existing-connection">Open existing connection</button>` : ""}</div><div class="form-actions">${cancel}<button class="button primary" type="submit">${setup.authNeeds2fa ? "Continue sign-in" : "Sign in"}</button></div></form>`;
  const locations = driveLocationChoices(setup.workspaces);
  const roots = setup.workspaceDiscoveryError ? `<p class="notice error" role="alert">${escape(setup.workspaceDiscoveryError)}</p>` : !setup.workspacesLoaded ? `<p aria-busy="true">Loading Drive roots…</p>` : locations.length ? renderDiscoveredRoots(locations, escape, setup.selectedSyncRootId) : `<p>No available roots on this page.</p>`;
  return `${head}<form id="pair-form"><div class="form-block"><h2>Choose a Drive root and local folder</h2><p class="intro">${escape(editor.name)} · ${escape(setup.accountEmail)}</p><p class="context-note">Select one location to sync below your local Drive folder. Shared Viewer roots download only. Add more roots from this server's details later.</p>${roots}<div class="actions">${setup.rootPageIndex ? `<button class="button small" type="button" data-action="first-root-page">Start over</button>` : ""}${setup.nextRootCursor ? `<button class="button small" type="button" data-action="next-root-page">More Drive roots</button>` : ""}${setup.workspaceDiscoveryError || !locations.length ? `<button class="button small" type="button" data-action="retry-workspaces">Retry Drive roots</button>` : ""}</div><div class="field"><span id="local-folder-label">Local Drive folder</span><div class="folder-picker-row"><output class="folder-readout" id="local-root-summary" role="status">${escape(setup.selectedLocalRoot || "No folder selected")}</output><button class="button" type="button" data-action="choose-local-root">Browse…</button></div><span class="hint">Choose a separate empty folder through the system picker. Its path cannot be typed here.</span></div><label class="field" for="server-interval">Sync check interval<select id="server-interval" name="intervalSeconds">${intervalOptions(editor.intervalSeconds, appModel.preferences.defaultSyncIntervalSeconds)}</select></label></div><div class="form-actions">${cancel}<button class="button primary" type="submit" ${pairSelectionReady(setup) ? "" : "disabled"}>Connect and start syncing</button></div></form>`;
}

function reconnectView(view) {
  return `<button class="button text back" data-action="cancel-signin">${icon("arrow")}${signin.returnTo === "editor" ? "Edit server" : "Server details"}</button><h1 id="page-heading" tabindex="-1">${view.credentialRecoveryPending ? "Recover saved sign-in" : "Update sign-in"}</h1><p class="intro">Your local Drive folder, managed roots, and last verified baseline stay in place.</p><form id="reconnect-form"><div class="form-block"><h2>Sign in to ${escape(view.serverHost || view.serverUrl)}</h2>${view.credentialRecoveryPending ? `<p class="context-note">Unlock this operating system's credential store before retrying.</p>` : ""}${renderPasswordFields(signin.authNeeds2fa, escape, view.account, true)}</div><div class="form-actions"><button class="button" type="button" data-action="cancel-signin">Cancel</button><button class="button primary" type="submit">${signin.authNeeds2fa ? "Continue sign-in" : "Update sign-in"}</button></div></form>`;
}

function settings(view) {
  return `${renderAppPreferences(appModel, settingsDraft, escape, screen === "preferences")}${renderDesktopUpdateRecoveryNotice(view.updateRecoveryTargetVersion, view.appVersion, escape)}${renderDesktopUpdate(desktopUpdate, view.appVersion, escape)}`;
}

function shell(_view, contents) {
  const tab = showSettings ? "settings" : screen === "history" ? "history" : "servers";
  const label = { servers: "Servers", settings: "App settings", history: "History" };
  const count = appModel.connections.length;
  const tabs = ["servers", "settings", "history"].map((name) => {
    const unavailable = editor || signin || (!appModel.preferences.initialized && name !== "settings");
    const guidance = editor || signin ? "Finish or cancel this server form before switching sections." : "Save app preferences before adding a server.";
    return `<button id="tab-${name}" class="tab" role="tab" data-action="navigate" data-screen="${name}" aria-selected="${tab === name}" aria-controls="main" tabindex="${tab === name ? 0 : -1}" ${unavailable ? `disabled title="${guidance}"` : ""}>${label[name]}</button>`;
  }).join("");
  return `<div class="desktop-app">
    <header class="topbar"><div class="brand">${icon("drive")}ShellX Drive</div><span class="platform-label">${browserPreview ? "Browser preview" : "Desktop sync"}</span></header>
    <nav class="tabs" role="tablist" aria-label="App sections">${tabs}</nav>
    <main class="viewport" id="main" role="tabpanel" aria-labelledby="tab-${tab}"><p class="notice error live-feedback" data-action-error role="alert" ${actionError ? "" : "hidden"}>${escape(actionError)}</p>${contents}</main>
    <footer class="app-footer"><span>${browserPreview ? "Synthetic preview · no server requests" : `Version ${escape(appModel.appVersion || "unavailable")}`}</span><span>${count} ${count === 1 ? "connection" : "connections"}</span></footer>
  </div>`;
}

function focusSelectorFor(element) {
  if (!(element instanceof HTMLElement)) return null;
  if (element.id) return `#${CSS.escape(element.id)}`;
  if (element.matches("[data-sync-locations-filter]")) return "[data-sync-locations-filter]";
  if (element.name && element.closest("form")?.id) return `#${CSS.escape(element.closest("form").id)} [name='${CSS.escape(element.name)}']`;
  const action = element.dataset?.action;
  const id = element.dataset?.connectionId;
  const pair = element.dataset?.pairId;
  return action ? `[data-action='${CSS.escape(action)}']${id ? `[data-connection-id='${CSS.escape(id)}']` : ""}${pair ? `[data-pair-id='${CSS.escape(pair)}']` : ""}` : null;
}

function captureBackgroundViewport() {
  const focused = document.activeElement;
  return {
    surface: `${screen}:${selectedConnectionId || ""}`,
    focus: focusSelectorFor(focused),
    selection: Number.isInteger(focused?.selectionStart) ? [focused.selectionStart, focused.selectionEnd, focused.selectionDirection] : null,
    values: [...app.querySelectorAll("input:not([type='password']), select")].map((input) => ({ selector: focusSelectorFor(input), value: input.value, checked: input.checked })),
    containers: [".viewport", ".sync-location-list", ".discovered-root-list"].flatMap((selector) => [...app.querySelectorAll(selector)].map((element, index) => ({ selector, index, left: element.scrollLeft, top: element.scrollTop }))),
    left: window.scrollX, top: window.scrollY,
  };
}

function restoreBackgroundViewport(viewport) {
  for (const field of viewport.values) {
    const input = field.selector ? app.querySelector(field.selector) : null;
    if (input) { input.value = field.value; if (typeof field.checked === "boolean") input.checked = field.checked; }
  }
  const focused = viewport.focus ? app.querySelector(viewport.focus) : null;
  focused?.focus({ preventScroll: true });
  if (viewport.selection && typeof focused?.setSelectionRange === "function") focused.setSelectionRange(...viewport.selection);
  for (const saved of viewport.containers) {
    const element = app.querySelectorAll(saved.selector)[saved.index];
    if (element) { element.scrollLeft = saved.left; element.scrollTop = saved.top; }
  }
  window.scrollTo(viewport.left, viewport.top);
}

function render(view = null, { preserveViewport = false } = {}) {
  if (!appModel) return;
  const viewport = preserveViewport && !pendingFocusSelector ? captureBackgroundViewport() : null;
  showSettings = screen === "settings" || screen === "preferences";
  const connection = selectedConnection();
  currentView = { ...(view || connection?.view || normalizeView({ appVersion: appModel.appVersion })), formOpen: Boolean(editor || signin) };
  // Update recovery belongs to the existing default updater owner, independently of selection.
  const recovery = appModel.connections.map((item) => item.view).find((item) => item.updateRecoveryTargetVersion);
  const globalView = { ...currentView, appVersion: appModel.appVersion, updateRecoveryTargetVersion: recovery?.updateRecoveryTargetVersion || "" };
  let contents;
  if (showSettings) contents = settings(globalView);
  else if (screen === "history") {
    history = { ...history, page: connectionHistoryPage(appModel.connections, history, historyConnectionId).page };
    contents = renderConnectionHistory(appModel, history, historyConnectionId, escape);
  }
  else if (screen === "signin" && connection && signin) contents = reconnectView(connection.view);
  else if (screen === "editor" && editor) contents = editor.mode === "add" ? setupView() : connection ? renderConnectionEditor(editor, connection, appModel.preferences.defaultSyncIntervalSeconds, escape) : renderServers(appModel, escape);
  else if (screen === "detail" && connection) contents = detailView(connection);
  else contents = renderServers(appModel, escape, connectionErrors);
  if (!showSettings && !["editor", "signin"].includes(screen)) contents += renderDesktopUpdateRecoveryNotice(globalView.updateRecoveryTargetVersion, globalView.appVersion, escape) + renderDesktopUpdateNotice(desktopUpdate, escape);
  app.innerHTML = shell(globalView, contents);
  document.title = connection ? `ShellX Drive — ${connection.name} · ${connectionStatus(connection).label}` : "ShellX Drive";
  bind(currentView);
  if (foregroundActionInFlight) setBusy(true);
  if (pendingReviewConfirmation) document.querySelector("[data-action='review-cancel']")?.focus();
  else if (pendingDisconnectConfirmation) document.querySelector("[data-action='disconnect-cancel']")?.focus();
  else if (pendingFocusSelector) {
    const target = app.querySelector(pendingFocusSelector) || app.querySelector("#page-heading");
    pendingFocusSelector = null;
    target?.focus();
  } else if (viewport && viewport.surface === `${screen}:${selectedConnectionId || ""}`) restoreBackgroundViewport(viewport);
}

function setBusy(busy) {
  for (const button of app.querySelectorAll("button")) {
    if (busy) { button.dataset.wasDisabled = String(button.disabled); button.disabled = true; }
    else if (button.dataset.wasDisabled !== undefined) { button.disabled = button.dataset.wasDisabled === "true"; delete button.dataset.wasDisabled; }
  }
  app.setAttribute("aria-busy", String(busy));
}

function showActionError(error, connectionId = null) {
  actionError = error?.message ?? String(error);
  if (connectionId) connectionErrors.set(connectionId, actionError);
  const surface = app.querySelector("[data-action-error]");
  if (!surface) return;
  surface.textContent = actionError;
  surface.hidden = false;
  surface.scrollIntoView({ block: "nearest" });
}

function clearActionError() {
  actionError = "";
  const surface = app.querySelector("[data-action-error]");
  if (surface) { surface.textContent = ""; surface.hidden = true; }
}

function clearPasswordInputs() {
  for (const input of app.querySelectorAll("input[type='password'], [name='totpCode'], [name='recoveryCode']")) input.value = "";
}

function captureEditor() {
  if (!editor) return;
  const form = app.querySelector("#connection-edit-form, #server-form, #login-form, #pair-form");
  if (!form) return;
  const data = new FormData(form);
  if (data.has("name")) editor.name = String(data.get("name")).trim();
  if (data.has("serverUrl")) editor.serverUrl = String(data.get("serverUrl")).trim();
  if (data.has("email")) editor.accountEmail = String(data.get("email")).trim();
  if (data.has("intervalSeconds")) editor.intervalSeconds = data.get("intervalSeconds") === "default" ? null : Number(data.get("intervalSeconds"));
  if (data.has("folderConfirmed") || app.querySelector("#change-consent")) editor.folderConfirmed = data.has("folderConfirmed");
}

function resetConnectionSurfaces() {
  addRootPicker = null;
  showReviews = false;
  syncLocationsFilter = "";
  pendingReviewConfirmation = null;
  pendingDisconnectConfirmation = false;
  pendingDesktopAgentControl = null;
  cleanupRetryState = "idle";
  cleanupRetryError = null;
}

async function foreground(operation, connectionId = null) {
  if (foregroundActionInFlight) return;
  captureEditor();
  viewGeneration += 1;
  foregroundActionInFlight = true;
  setBusy(true);
  try { await operation(); }
  catch (error) {
    const duplicate = editor?.mode === "add" ? duplicateConnectionFromError(appModel.connections, error) : null;
    if (duplicate) { editor.existingConnectionId = duplicate.id; setup.signedIn = false; render(); }
    showActionError(error, connectionId);
  }
  finally { foregroundActionInFlight = false; setBusy(false); }
}

async function run(command, args = {}, focusSelector = null, connectionId = selectedConnectionId) {
  await foreground(async () => {
    const raw = await invokeConnection(command, connectionId, args);
    applyConnectionReply(connectionId, raw);
    connectionErrors.delete(connectionId);
    clearActionError();
    pendingFocusSelector = focusSelector;
    render(null, { preserveViewport: true });
  }, connectionId);
}

async function openFolder(connectionId) {
  await foreground(async () => {
    await invokeConnection("open_local_folder", connectionId);
    connectionErrors.delete(connectionId);
    clearActionError();
  }, connectionId);
}

async function cancelEditor() {
  if (foregroundActionInFlight) return;
  captureEditor();
  clearPasswordInputs();
  if (editor?.mode === "add") {
    const draft = editor;
    lastAddDraft = { name: draft.name, serverUrl: draft.serverUrl, accountEmail: draft.accountEmail, intervalSeconds: draft.intervalSeconds };
    await foreground(async () => {
      if (draft.connectionId) await invokeConnection("cancel_connection", draft.connectionId);
      editor = null;
      signin = null;
      setup = emptySetupState();
      screen = "servers";
      selectedConnectionId = null;
      clearActionError();
      pendingFocusSelector = "#add-server";
      await reloadConnections();
    }, draft.connectionId);
  } else {
    editor = null;
    screen = "detail";
    clearActionError();
    actionError = connectionErrors.get(selectedConnectionId) || "";
    pendingFocusSelector = "[data-action='edit-server']";
    render();
  }
}

async function returnToServerStep() {
  captureEditor();
  const draft = editor;
  await foreground(async () => {
    if (draft.connectionId && (setup.signedIn || setup.authNeeds2fa)) {
      await invokeConnection("cancel_connection", draft.connectionId);
      draft.connectionId = null;
    }
    setup = { ...emptySetupState(), serverUrl: draft.serverUrl, accountEmail: draft.accountEmail };
    clearActionError();
    pendingFocusSelector = "#server-url";
    render();
  }, draft.connectionId);
}

async function loadSetupWorkspaces(_view, cursor = null) {
  const draft = editor;
  if (!draft?.connectionId) return;
  setup = beginWorkspaceDiscovery(setup);
  const discoverySetup = setup;
  render();
  try {
    const page = await invokeConnection("list_workspace_page", draft.connectionId, { cursor });
    if (editor !== draft || setup !== discoverySetup) return;
    setup = completeWorkspacePage(setup, page, cursor);
    clearActionError();
    pendingFocusSelector = driveLocationChoices(setup.workspaces).length ? "input[name='syncRootId']" : "[data-action='retry-workspaces']";
  } catch (error) {
    if (editor !== draft || setup !== discoverySetup) return;
    const latestReply = await invokeConnection("get_desktop_view", draft.connectionId).catch(() => null);
    if (editor !== draft || setup !== discoverySetup) return;
    const latest = latestReply ? normalizeView(latestReply) : null;
    if (latest && !latest.account && !latest.serverUrl && latest.status === "needs_setup") {
      setup = { ...emptySetupState(), serverUrl: draft.serverUrl, serverValidated: true, accountEmail: draft.accountEmail };
      showActionError(new Error("This sign-in has expired. Sign in again to load your Drive roots."), draft.connectionId);
      pendingFocusSelector = "#server-password";
    } else {
      setup = failWorkspaceDiscovery(setup, error);
      pendingFocusSelector = "[data-action='retry-workspaces']";
    }
  }
  render();
}

async function loadAddRootPage(_view, cursor = null) {
  const connectionId = selectedConnectionId;
  if (!addRootPicker) return;
  addRootPicker = beginWorkspaceDiscovery(addRootPicker);
  const original = addRootPicker;
  render();
  try {
    const page = await invokeConnection("list_workspace_page", connectionId, { cursor });
    if (addRootPicker !== original || selectedConnectionId !== connectionId) return;
    addRootPicker = completeWorkspacePage(original, page, cursor);
  } catch (error) {
    if (addRootPicker !== original || selectedConnectionId !== connectionId) return;
    addRootPicker = failWorkspaceDiscovery(original, error);
  }
  render(null, { preserveViewport: true });
}

async function refreshFromBackground() {
  if (browserPreview || document.hidden || foregroundActionInFlight || backgroundRefreshInFlight || pendingReviewConfirmation || pendingDisconnectConfirmation || !appModel) return;
  backgroundRefreshInFlight = true;
  const generation = viewGeneration;
  const before = JSON.stringify(appModel);
  try {
    const raw = await invoke("get_connections_view");
    if (generation !== viewGeneration || foregroundActionInFlight || pendingReviewConfirmation || pendingDisconnectConfirmation) return;
    applyConnectionsView(raw);
    if (before === JSON.stringify(appModel)) return;
    // A live form remains the same DOM object, including transient password/2FA input.
    // Status is retained in the model and painted when the form closes.
    if (editor || signin) return;
    render(null, { preserveViewport: true });
  } catch { /* A foreground action owns actionable errors; polling retries quietly. */ }
  finally { backgroundRefreshInFlight = false; }
}

function navigate(next) {
  if (foregroundActionInFlight || editor || signin) return;
  viewGeneration += 1;
  screen = next;
  settingsDraft = next === "settings" ? { ...appModel.preferences } : null;
  resetConnectionSurfaces();
  clearActionError();
  pendingFocusSelector = `#tab-${next}`;
  render();
}

function bind(view) {
  const connectionId = selectedConnectionId;
  app.querySelectorAll("[data-action='navigate']").forEach((button) => {
    button.addEventListener("click", () => navigate(button.dataset.screen));
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const tabs = ["servers", "settings", "history"];
      const index = tabs.indexOf(button.dataset.screen);
      const next = event.key === "Home" ? 0 : event.key === "End" ? 2 : (index + (event.key === "ArrowRight" ? 1 : 2)) % 3;
      navigate(tabs[next]);
    });
  });
  app.querySelector("[data-action='add-server']")?.addEventListener("click", () => {
    resetConnectionSurfaces();
    editor = { ...connectionDraft(), ...lastAddDraft };
    setup = { ...emptySetupState(), accountEmail: editor.accountEmail };
    selectedConnectionId = null;
    screen = "editor";
    clearActionError();
    pendingFocusSelector = "#server-url";
    render();
  });
  app.querySelectorAll("[data-action='select-connection']").forEach((button) => button.addEventListener("click", () => {
    viewGeneration += 1;
    selectedConnectionId = button.dataset.connectionId;
    resetConnectionSurfaces();
    screen = "detail";
    clearActionError();
    actionError = connectionErrors.get(selectedConnectionId) || "";
    pendingFocusSelector = "#page-heading";
    render();
  }));
  app.querySelectorAll("[data-action='open-connection-folder']").forEach((button) => button.addEventListener("click", () => openFolder(button.dataset.connectionId)));
  app.querySelector("[data-action='back-to-servers']")?.addEventListener("click", () => navigate("servers"));
  app.querySelector("[data-action='edit-server']")?.addEventListener("click", () => {
    editor = connectionDraft(selectedConnection());
    screen = "editor";
    clearActionError();
    pendingFocusSelector = "#server-name";
    render();
  });
  app.querySelectorAll("[data-action='cancel-editor']").forEach((button) => button.addEventListener("click", cancelEditor));
  app.querySelector("[data-action='editor-back']")?.addEventListener("click", () => setup.serverValidated ? returnToServerStep() : cancelEditor());
  app.querySelector("[data-action='update-signin']")?.addEventListener("click", () => {
    captureEditor();
    signin = { connectionId, authNeeds2fa: false, returnTo: screen === "editor" ? "editor" : "detail" };
    screen = "signin";
    clearActionError();
    pendingFocusSelector = "#server-password";
    render();
  });
  app.querySelectorAll("[data-action='cancel-signin']").forEach((button) => button.addEventListener("click", () => {
    const activeSignin = signin;
    clearPasswordInputs();
    foreground(async () => {
      await invokeConnection("cancel_login", activeSignin.connectionId);
      screen = activeSignin.returnTo;
      signin = null;
      clearActionError();
      pendingFocusSelector = "[data-action='update-signin']";
      render();
    }, activeSignin.connectionId);
  }));
  app.querySelector("[data-action='open-local-folder']")?.addEventListener("click", () => openFolder(connectionId));
  app.querySelector("[data-action='open-drive']")?.addEventListener("click", () => foreground(async () => { await invokeConnection("open_drive", connectionId); }, connectionId));
  app.querySelector("[data-action='resume-setup']")?.addEventListener("click", () => foreground(async () => {
    applyConnectionsView(await invokeConnection("complete_connection", connectionId));
    connectionErrors.delete(connectionId);
    clearActionError();
    pendingFocusSelector = "#status-title";
    render(null, { preserveViewport: true });
  }, connectionId));
  app.querySelector("[data-action='sync-now']")?.addEventListener("click", () => run("sync_now", {}, "[data-action='sync-now']", connectionId));
  app.querySelector("[data-action='recheck-reviews']")?.addEventListener("click", () => run("recheck_reviews", {}, "[data-action='recheck-reviews']", connectionId));
  app.querySelector("[data-action='pause-resume']")?.addEventListener("click", () => run("set_paused", { paused: !view.paused }, "[data-action='pause-resume']", connectionId));
  app.querySelector("[data-action='view-history']")?.addEventListener("click", () => {
    historyConnectionId = connectionId;
    history = { ...history, page: 1 };
    navigate("history");
  });
  app.querySelector("#history-connection")?.addEventListener("change", (event) => { historyConnectionId = event.target.value; history = { ...history, page: 1 }; render(null, { preserveViewport: true }); });
  app.querySelector("[data-action='history-clear']")?.addEventListener("click", () => { historyConnectionId = "all"; });
  bindActivityHistory(document, history, (next, focusSelector) => {
    history = next;
    pendingFocusSelector = focusSelector;
    render();
  });
  bindConnectionForms(connectionId, view);
  app.querySelector("[data-action='disconnect']")?.addEventListener("click", () => { pendingDisconnectConfirmation = true; render(); });
  app.querySelector("[data-action='disconnect-cancel']")?.addEventListener("click", () => { pendingDisconnectConfirmation = false; pendingFocusSelector = "[data-action='disconnect']"; render(); });
  app.querySelector("[data-action='disconnect-confirm']")?.addEventListener("click", () => { pendingDisconnectConfirmation = false; runDisconnect(view, connectionId); });
  app.querySelector("[data-action='finish-disconnect-cleanup']")?.addEventListener("click", () => finishDisconnectCleanup(view, connectionId));
  app.querySelector("[data-action='desktop-agent-control']")?.addEventListener("click", () => { pendingDesktopAgentControl = !view.desktopAgentEnabled; render(); });
  app.querySelector("[data-action='desktop-agent-cancel']")?.addEventListener("click", () => { pendingDesktopAgentControl = null; render(); });
  app.querySelector("[data-action='desktop-agent-confirm']")?.addEventListener("click", () => { const enabled = pendingDesktopAgentControl; pendingDesktopAgentControl = null; run("set_desktop_agent_control", { enabled }, "[data-action='desktop-agent-control']", connectionId); });
  app.querySelector("[data-action='desktop-update-check']")?.addEventListener("click", () => checkDesktopUpdate(view));
  app.querySelectorAll("[data-action='desktop-update-install']").forEach((button) => button.addEventListener("click", () => installDesktopUpdate(view)));
  app.querySelectorAll("[data-action='desktop-update-open']").forEach((button) => button.addEventListener("click", () => {
    if (editor || signin) return;
    screen = "settings";
    settingsDraft = { ...appModel.preferences };
    pendingFocusSelector = desktopUpdate.status === "available" ? "[data-action='desktop-update-install']" : "[data-action='desktop-update-check']";
    render();
  }));
  bindRootsAndReviews(connectionId, view);
}

function bindConnectionForms(connectionId, view) {
  app.querySelector("#server-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    captureEditor();
    const draft = editor;
    foreground(async () => {
      if (!draft.name) throw new Error("Enter a friendly name for this account connection.");
      if (!draft.connectionId) {
        const result = await invoke("begin_connection", { name: draft.name });
        const id = result?.connectionId ?? result?.connection_id;
        connectionArguments(id);
        draft.connectionId = id;
      }
      const validation = await invokeConnection("validate_server", draft.connectionId, { serverUrl: draft.serverUrl });
      if (validation.setupRequired ?? validation.setup_required) throw new Error("This Drive server needs first-time owner setup. Open the server in a browser, complete setup, then validate it again.");
      const normalizedUrl = validation.normalizedUrl ?? validation.normalized_url;
      if (typeof normalizedUrl !== "string" || !normalizedUrl) throw new Error("The desktop service did not confirm this server address.");
      draft.serverUrl = normalizedUrl;
      setup = { ...setup, serverUrl: normalizedUrl, serverValidated: true };
      clearActionError();
      pendingFocusSelector = "#server-email";
      render();
    }, draft.connectionId);
  });
  app.querySelector("#login-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    captureEditor();
    const draft = editor;
    const args = { serverUrl: setup.serverUrl, email: draft.accountEmail, password: String(data.get("password") || "") };
    if (setup.authNeeds2fa) { args.totpCode = data.get("totpCode") || null; args.recoveryCode = data.get("recoveryCode") || null; }
    clearPasswordInputs();
    foreground(async () => {
      const reply = await invokeConnection(setup.authNeeds2fa ? "continue_login" : "login_password", draft.connectionId, args);
      if (editor !== draft) return;
      setup = applyLoginReply(setup, reply, draft.accountEmail);
      draft.accountEmail = setup.accountEmail || draft.accountEmail;
      clearActionError();
      const duplicate = setup.signedIn ? verifiedDuplicate(appModel.connections, draft.connectionId, setup.serverUrl, setup.accountEmail) : null;
      if (duplicate) { draft.existingConnectionId = duplicate.id; setup.signedIn = false; render(); throw new Error(`${duplicate.name} already connects this account to this server. Open it to manage the existing connection.`); }
      if (setup.signedIn) await loadSetupWorkspaces(view);
      else { pendingFocusSelector = "#totp-code"; render(); }
    }, draft.connectionId);
  });
  app.querySelector("#reconnect-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const activeSignin = signin;
    const args = { serverUrl: view.serverUrl, email: view.account, password: String(data.get("password") || "") };
    if (activeSignin.authNeeds2fa) { args.totpCode = data.get("totpCode") || null; args.recoveryCode = data.get("recoveryCode") || null; }
    clearPasswordInputs();
    foreground(async () => {
      const reply = await invokeConnection(activeSignin.authNeeds2fa ? "continue_login" : "login_password", activeSignin.connectionId, args);
      if (signin !== activeSignin) return;
      activeSignin.authNeeds2fa = reply.kind === "requires_second_factor";
      clearActionError();
      if (reply.kind === "authenticated") {
        await reloadConnections({ renderResult: false });
        screen = activeSignin.returnTo;
        signin = null;
        pendingFocusSelector = screen === "editor" ? "[data-action='update-signin']" : "#page-heading";
      } else pendingFocusSelector = "#totp-code";
      render();
    }, activeSignin.connectionId);
  });
  app.querySelector("#pair-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    captureEditor();
    const draft = editor;
    foreground(async () => {
      if (!pairSelectionReady(setup)) throw new Error("Choose a Drive root and a separate empty local folder first.");
      if (!draft.paired) {
        await invokeConnection("start_pair", draft.connectionId, { workspaceId: setup.selectedWorkspaceId, remoteRootId: setup.selectedRemoteRootId, syncRootId: setup.selectedSyncRootId, localRoot: setup.selectedLocalRoot });
        draft.paired = true;
      }
      // Save metadata before publishing the completed connection; a failed save
      // keeps the durable draft owned and available for a retry.
      await invokeConnection("save_connection", draft.connectionId, { name: draft.name, intervalSeconds: draft.intervalSeconds });
      applyConnectionsView(await invokeConnection("complete_connection", draft.connectionId));
      selectedConnectionId = draft.connectionId;
      editor = null;
      setup = emptySetupState();
      lastAddDraft = null;
      screen = "detail";
      clearActionError();
      pendingFocusSelector = "#page-heading";
      render();
    }, draft.connectionId);
  });
  app.querySelector("#settings-form")?.addEventListener("input", (event) => {
    const data = new FormData(event.currentTarget);
    settingsDraft = { ...appModel.preferences, theme: String(data.get("theme")), launchAtLogin: data.has("launchAtLogin"), defaultSyncIntervalSeconds: Number(data.get("defaultSyncIntervalSeconds")) };
  });
  app.querySelector("#settings-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    foreground(async () => {
      const first = !appModel.preferences.initialized;
      applyConnectionsView(await invoke("save_app_preferences", { theme: String(data.get("theme")), launchAtLogin: data.has("launchAtLogin"), defaultSyncIntervalSeconds: Number(data.get("defaultSyncIntervalSeconds")) }));
      settingsDraft = null;
      screen = first ? "servers" : "settings";
      clearActionError();
      pendingFocusSelector = first ? "#add-server" : "#setting-theme";
      render();
    });
  });
  app.querySelector("#connection-edit-form")?.addEventListener("input", () => {
    captureEditor();
    const submit = app.querySelector("#connection-edit-form button[type='submit']");
    if (submit) submit.disabled = editor.folderChanged && !editor.folderConfirmed;
  });
  app.querySelector("#connection-edit-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    captureEditor();
    const draft = editor;
    foreground(async () => {
      if (draft.folderChanged) {
        if (!draft.folderConfirmed) throw new Error("Confirm that files stay in the current folder and the new folder starts a fresh sync.");
        applyConnectionsView(await invokeConnection("replace_connection_folder", draft.connectionId, { localRoot: draft.folder, confirmed: true }));
        draft.originalFolder = draft.folder;
        draft.folderChanged = false;
        draft.folderConfirmed = false;
      }
      applyConnectionsView(await invokeConnection("save_connection", draft.connectionId, { name: draft.name, intervalSeconds: draft.intervalSeconds }));
      editor = null;
      screen = "detail";
      clearActionError();
      pendingFocusSelector = "[data-action='edit-server']";
      render();
    }, draft.connectionId);
  });
  app.querySelector("[data-action='choose-edit-folder']")?.addEventListener("click", () => {
    captureEditor();
    const draft = editor;
    foreground(async () => {
      const path = await invokeConnection("pick_local_root", draft.connectionId);
      if (!path || editor !== draft) return;
      draft.folder = String(path);
      draft.folderChanged = draft.folder !== draft.originalFolder;
      draft.folderConfirmed = false;
      clearActionError();
      pendingFocusSelector = draft.folderChanged ? "#change-consent" : "[data-action='choose-edit-folder']";
      render();
    }, draft.connectionId);
  });
  app.querySelector("[data-action='cancel-folder-change']")?.addEventListener("click", () => { captureEditor(); editor.folder = editor.originalFolder; editor.folderChanged = false; editor.folderConfirmed = false; render(); });
  app.querySelector("[data-action='open-existing-connection']")?.addEventListener("click", () => {
    const existingId = editor.existingConnectionId;
    foreground(async () => {
      if (editor.connectionId) await invokeConnection("cancel_connection", editor.connectionId);
      editor = null;
      setup = emptySetupState();
      selectedConnectionId = existingId;
      screen = "detail";
      clearActionError();
      await reloadConnections();
    }, editor.connectionId);
  });
}

function bindRootsAndReviews(connectionId, view) {
  app.querySelectorAll("input[name='syncRootId']").forEach((input) => input.addEventListener("change", (event) => { setup = selectDiscoveredRoot(setup, event.target.value); render(null, { preserveViewport: true }); }));
  app.querySelector("[data-action='choose-local-root']")?.addEventListener("click", () => {
    const draft = editor;
    foreground(async () => { const path = await invokeConnection("pick_local_root", draft.connectionId); if (!path || editor !== draft) return; setup = selectLocalRoot(setup, path); clearActionError(); pendingFocusSelector = "[data-action='choose-local-root']"; render(); }, draft.connectionId);
  });
  for (const [action, cursor] of [["retry-workspaces", null], ["first-root-page", null], ["next-root-page", setup.nextRootCursor]]) app.querySelector(`[data-action='${action}']`)?.addEventListener("click", () => foreground(() => loadSetupWorkspaces(view, cursor), editor.connectionId));
  app.querySelector("[data-action='open-add-root']")?.addEventListener("click", () => { addRootPicker = emptySetupState(); foreground(() => loadAddRootPage(view), connectionId); });
  app.querySelector("[data-action='close-add-root']")?.addEventListener("click", () => { addRootPicker = null; render(); });
  app.querySelectorAll("input[name='addSyncRootId']").forEach((input) => input.addEventListener("change", (event) => { addRootPicker = selectDiscoveredRoot(addRootPicker, event.target.value); render(null, { preserveViewport: true }); }));
  for (const [action, cursor] of [["retry-add-root", null], ["first-add-root-page", null], ["next-add-root-page", addRootPicker?.nextRootCursor]]) app.querySelector(`[data-action='${action}']`)?.addEventListener("click", () => foreground(() => loadAddRootPage(view, cursor), connectionId));
  app.querySelector("[data-action='confirm-add-root']")?.addEventListener("click", () => {
    const picker = addRootPicker;
    if (!picker?.selectedSyncRootId) return;
    foreground(async () => {
      const next = await invokeConnection("add_root", connectionId, { workspaceId: picker.selectedWorkspaceId, remoteRootId: picker.selectedRemoteRootId, syncRootId: picker.selectedSyncRootId });
      applyConnectionReply(connectionId, next);
      addRootPicker = null;
      clearActionError();
      render();
    }, connectionId);
  });
  app.querySelector("[data-sync-locations-filter]")?.addEventListener("input", (event) => { syncLocationsFilter = event.currentTarget.value; render(null, { preserveViewport: true }); });
  app.querySelectorAll("[data-action='review-location']").forEach((button) => button.addEventListener("click", () => foreground(async () => {
    const pairId = button.dataset.pairId;
    pendingReviewConfirmation = null;
    showReviews = false;
    render(null, { preserveViewport: true });
    const next = await invokeConnection("select_pair", connectionId, { pairId });
    applyConnectionReply(connectionId, next);
    showReviews = true;
    pendingFocusSelector = "#daily-section-title";
    render();
  }, connectionId)));
  app.querySelectorAll("[data-action='review-choice']").forEach((button) => button.addEventListener("click", () => foreground(async () => {
    const reviewId = button.dataset.reviewId;
    const action = button.dataset.reviewAction;
    const prepared = await invokeConnection("prepare_review_action", connectionId, { reviewId, action });
    pendingReviewConfirmation = { connectionId, reviewId, action, confirmationId: prepared.confirmationId ?? prepared.confirmation_id };
    render();
  }, connectionId)));
  app.querySelector("[data-action='review-cancel']")?.addEventListener("click", () => { pendingReviewConfirmation = null; pendingFocusSelector = "[data-action='review-choice']"; render(); });
  app.querySelector("[data-action='review-confirm']")?.addEventListener("click", () => {
    const pending = pendingReviewConfirmation;
    foreground(async () => {
      const next = await invokeConnection("choose_review_action", pending.connectionId, { reviewId: pending.reviewId, action: pending.action, confirmationId: pending.confirmationId });
      applyConnectionReply(pending.connectionId, next);
      pendingReviewConfirmation = null;
      clearActionError();
      pendingFocusSelector = "#status-title";
      render();
    }, pending.connectionId);
  });
}

async function checkDesktopUpdate(view, { silent = false } = {}) {
  if (["checking", "downloading", "installing", "restarting"].includes(desktopUpdate.status)) return;
  desktopUpdate = { ...emptyDesktopUpdateState(), status: "checking" };
  if (!silent || showSettings) render(view, { preserveViewport: silent });
  try {
    const info = await invoke("check_desktop_update");
    desktopUpdate = info
      ? { ...emptyDesktopUpdateState(), status: "available", info }
      : { ...emptyDesktopUpdateState(), status: "current" };
  } catch (error) {
    desktopUpdate = silent
      ? emptyDesktopUpdateState()
      : { ...emptyDesktopUpdateState(), status: "error", error: error?.message ?? String(error) };
  }
  // Retain the result for the next render without replacing an in-progress
  // setup or reconnect form when the startup check finishes in the background.
  const nextView = currentView || view;
  if (silent && !showSettings && (nextView.formOpen || nextView.credentialRecoveryPending || ["needs_setup", "needs_reconnect"].includes(nextView.status))) return;
  if (!silent || showSettings || desktopUpdate.status === "available") render(nextView, { preserveViewport: silent });
}

async function installDesktopUpdate(view) {
  if (desktopUpdate.status !== "available") return;
  const candidateId = desktopUpdate.info?.candidateId;
  if (typeof candidateId !== "string" || !candidateId) {
    desktopUpdate = {
      ...desktopUpdate,
      status: "error",
      error: "The checked update no longer has a trusted installation target. Check again before installing.",
    };
    render(view);
    return;
  }
  if (typeof NativeChannel !== "function") {
    desktopUpdate = { ...desktopUpdate, status: "error", error: "This installation cannot report signed update progress. Reopen ShellX Drive and try again." };
    render(view);
    return;
  }
  const events = new NativeChannel();
  events.onmessage = (message) => {
    desktopUpdate = applyDesktopUpdateEvent(desktopUpdate, message);
    render(currentView || view);
  };
  desktopUpdate = { ...desktopUpdate, status: "downloading", received: 0, total: null, error: "" };
  render(view);
  try {
    await invoke("install_desktop_update", { candidateId, events });
    // The typed native stream reports verification and restart before this
    // command resolves. Do not replace that final state with stale copy.
    if (!["restarting", "error"].includes(desktopUpdate.status)) {
      desktopUpdate = { ...desktopUpdate, status: "installing" };
    }
  } catch (error) {
    desktopUpdate = { ...desktopUpdate, status: "error", error: error?.message ?? String(error) };
  }
  render(currentView || view);
}


async function finishDisconnectCleanup(view, connectionId = selectedConnectionId) {
  return runDisconnect(view, connectionId);
}

async function runDisconnect(view, connectionId) {
  await foreground(async () => {
    disconnectRequestInFlight = true;
    cleanupRetryState = "running";
    cleanupRetryError = null;
    render(view);
    try {
      await invokeConnection("remove_connection", connectionId);
      await reloadConnections({ renderResult: false });
      if (appModel.connections.some((connection) => connection.id === connectionId)) {
        cleanupRetryState = "failed";
        cleanupRetryError = "This server is still retained for safe retirement. Retry the displayed recovery step.";
        screen = "detail";
        selectedConnectionId = connectionId;
      } else {
        resetConnectionSurfaces();
        screen = "servers";
        selectedConnectionId = null;
        clearActionError();
      }
    } catch (error) {
      await reloadConnections({ renderResult: false }).catch(() => {});
      cleanupRetryState = "failed";
      cleanupRetryError = error?.message ?? String(error);
      showActionError(error, connectionId);
    } finally {
      disconnectRequestInFlight = false;
      pendingFocusSelector = selectedConnection() ? "[data-action='finish-disconnect-cleanup']" : "#add-server";
      render();
    }
  }, connectionId);
}

function cancelOpenConfirmation() {
  if (foregroundActionInFlight) return false;
  if (pendingReviewConfirmation) { pendingReviewConfirmation = null; pendingFocusSelector = "[data-action='review-choice']"; render(); return true; }
  if (pendingDisconnectConfirmation) { pendingDisconnectConfirmation = false; pendingFocusSelector = "[data-action='disconnect']"; render(); return true; }
  if (pendingDesktopAgentControl !== null) { pendingDesktopAgentControl = null; render(); return true; }
  if (signin) { app.querySelector("[data-action='cancel-signin']")?.click(); return true; }
  if (editor) { cancelEditor(); return true; }
  return false;
}

async function openConnectionFromNative(event) {
  const connectionId = event?.payload;
  if (typeof connectionId !== "string" || !connectionId || foregroundActionInFlight || editor || signin) return;
  viewGeneration += 1;
  await reloadConnections({ renderResult: false });
  if (!appModel.connections.some((connection) => connection.id === connectionId)) return;
  selectedConnectionId = connectionId;
  resetConnectionSurfaces();
  screen = "detail";
  clearActionError();
  pendingFocusSelector = "#page-heading";
  render();
}

async function openReviewsFromNative(event) {
  if (foregroundActionInFlight || editor || signin) return;
  viewGeneration += 1;
  resetConnectionSurfaces();
  render(null, { preserveViewport: true });
  await reloadConnections({ renderResult: false });
  const requestedId = typeof event?.payload === "string" ? event.payload : null;
  const connection = appModel.connections.find((item) => item.id === requestedId) || appModel.connections.find((item) => item.view.reviewCount > 0);
  if (!connection) return;
  selectedConnectionId = connection.id;
  resetConnectionSurfaces();
  showReviews = true;
  screen = "detail";
  clearActionError();
  pendingFocusSelector = connection.view.reviews.length ? "#daily-section-title" : "#sync-locations-heading";
  render();
}

function renderBackendFailure() {
  document.title = "ShellX Drive could not start";
  app.innerHTML = `<section class="shell"><section class="status"><h1>ShellX Drive could not start</h1><p class="diagnostic">The desktop service did not respond, so no files or settings were changed.</p><p>Close and reopen ShellX Drive. If this keeps happening, reinstall the latest version or contact your server administrator.</p></section></section>`;
}

async function start() {
  if (frontend.kind === "blocked") { renderBackendFailure(); return; }
  try {
    if (browserPreview) {
      const { createConnectionDemo } = await import("./connection-demo.mjs");
      invokeDemo = createConnectionDemo(frontend.demo);
    }
    applyConnectionsView(await invoke("get_connections_view"));
    document.addEventListener("keydown", (event) => { if (event.key === "Escape" && currentView && cancelOpenConfirmation(currentView)) event.preventDefault(); });
    render();
    if (typeof nativeListen === "function") {
      try {
        await nativeListen("shellx-drive-open-connection", (event) => openConnectionFromNative(event).catch(showActionError));
        await nativeListen("shellx-drive-open-reviews", (event) => openReviewsFromNative(event).catch(showActionError));
      } catch (error) {
        showActionError(new Error(`A tray shortcut is unavailable: ${error?.message ?? String(error)}`));
      }
    }
    checkDesktopUpdate(currentView, { silent: true });
    window.setInterval(refreshFromBackground, 2000);
    window.addEventListener("focus", refreshFromBackground);
    document.addEventListener("visibilitychange", refreshFromBackground);
  } catch (error) {
    console.error("ShellX Drive desktop startup failed.", error);
    renderBackendFailure();
  }
}

start();
