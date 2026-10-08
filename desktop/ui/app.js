import { deletionReviewChoices, mayRecheckReviews, mayRunSync, reviewActionLabel, reviewConfirmationCopy, statusCopy, trayTooltip } from "./ui-state.mjs";
import { backendHandshakeIsValid, frontendMode, routeDesktopInvoke } from "./bootstrap-state.mjs";
import { desktopViewChanged, shouldDeferCredentialRecoveryRender, shouldDeferReconnectRender, shouldPreserveBackgroundViewport, shouldRefreshDesktopView } from "./background-refresh.mjs";
import { applyLoginReply, beginWorkspaceDiscovery, driveLocationChoices, emptySetupState, failWorkspaceDiscovery, hasRetiredSetupSession, pairSelectionReady, resetExpiredSetupSession, selectLocalRoot } from "./setup-state.mjs";
import { completeWorkspacePage, selectDiscoveredRoot } from "./setup-pages.mjs";
import { formatByteSize, normalizeSyncLocations, renderDiscoveredRoots, renderSyncLocations } from "./sync-locations.mjs";
import { bindActivityHistory, emptyHistoryState, renderActivityHistory } from "./activity-history.mjs";
import { applyDesktopUpdateEvent, emptyDesktopUpdateState, renderDesktopUpdate, renderDesktopUpdateNotice, renderDesktopUpdateRecoveryNotice } from "./app-updates.mjs";

const app = document.querySelector("#app");
let showReviews = false;
let showSettings = false;
let actionError = "";
let pendingReviewConfirmation = null;
let pendingDisconnectConfirmation = false;
let disconnectRequestInFlight = false;
let pendingDesktopAgentControl = null;
let pendingFocusSelector = null;
let currentView = null;
let foregroundActionInFlight = false;
let backgroundRefreshInFlight = false;
let cleanupRetryState = "idle";
let cleanupRetryError = null;
let setup = emptySetupState();
let addRootPicker = null;
let history = emptyHistoryState();
let desktopUpdate = emptyDesktopUpdateState();
let syncLocationsFilter = "";
const nativeInvoke = window.__TAURI__?.core?.invoke;
const NativeChannel = window.__TAURI__?.core?.Channel;
const nativeListen = window.__TAURI__?.event?.listen;
const frontend = frontendMode({
  hasNativeInvoke: typeof nativeInvoke === "function",
  search: window.location.search,
});
const browserPreview = frontend.kind === "demo";

const demo = {
  status: "needs_setup",
  appVersion: "0.1.1",
  account: "",
  serverHost: "",
  serverUrl: "",
  driveLocation: "",
  localRoot: "",
  localUsageBytes: null,
  localUsageFileCount: null,
  localUsageFolderCount: null,
  activePairId: null,
  syncLocations: [],
  lastSuccessfulSync: null,
  reviewCount: 0,
  pendingRemoteRevocations: 0,
  disconnectCleanupPending: false,
  disconnectRemoteRetirementConfirmed: false,
  activeFiles: null,
  reviews: [],
  activity: [],
  paused: false,
  launchAtLogin: true,
  desktopAgentEnabled: false,
  desktopAgentReady: false,
  error: null,
};

// Browser-only visual fixtures. They deliberately contain no authentication
// values and never perform an HTTP request, so a screenshot run can exercise
// the operational states without changing native desktop behavior.
function applyBrowserDemo() {
  if (!browserPreview) return;
  const scenario = frontend.demo;
  const now = new Date().toISOString();
  const base = {
    status: "synced",
    appVersion: "0.1.1",
    account: "avery@example.test",
    serverHost: "drive.example.test",
    serverUrl: "https://drive.example.test",
    driveLocation: "My files",
    localRoot: "C:\\Users\\Avery\\ShellX Drive\\My files",
    localUsageBytes: 5_531_157_045,
    localUsageFileCount: 125,
    localUsageFolderCount: 8,
    activePairId: "demo-pair-1",
    syncLocations: [{
      id: "demo-pair-1",
      driveLocation: "My files",
      localRoot: "C:\\Users\\Avery\\ShellX Drive\\My files",
      active: true,
      syncStatus: "Synced",
    }, {
      id: "demo-pair-2",
      driveLocation: "Shared with me / Avery / Projects / Briefs",
      localRoot: "C:\\Users\\Avery\\ShellX Drive\\Shared with Avery - Projects - Briefs",
      active: false,
      syncStatus: "Synced",
    }],
    lastSuccessfulSync: now,
    reviewCount: 0,
    pendingRemoteRevocations: 0,
    disconnectCleanupPending: false,
    disconnectRemoteRetirementConfirmed: false,
    activeFiles: null,
    paused: false,
    launchAtLogin: true,
    desktopAgentEnabled: false,
    desktopAgentReady: false,
    error: null,
    reviews: [],
    activity: Array.from({ length: 14 }, (_, index) => ({
      at: new Date(new Date(now).valueOf() - index * 60 * 60 * 1000).toISOString(),
      direction: index % 2 ? "Local to Drive" : "Drive to local",
      path: `Projects / history-item-${index + 1}.md`,
      result: index % 3 ? "Verified" : "Downloaded safely",
    })),
  };
  const scenarios = {
    needs_reconnect: {
      ...base,
      status: "needs_reconnect",
      activity: [{ at: now, direction: "Desktop session", path: "Drive pair", result: "Sign in again; local files and pair retained" }],
    },
    synced: base,
    syncing: {
      ...base,
      status: "syncing",
      activity: [{ at: now, direction: "Drive", path: "Designs / mark.svg", result: "Downloading safely" }],
    },
    offline: {
      ...base,
      status: "offline",
      activity: [{ at: now, direction: "Drive", path: "Network", result: "Offline; retry remains available" }],
    },
    needs_review: {
      ...base,
      status: "needs_review",
      reviewCount: 1,
      reviews: [{
        id: "demo-review",
        kind: "remote_deletion",
        relativePath: "Projects / launch-plan.md",
        summary: "Deleted in Drive. Your local copy is retained until you choose a recoverable action.",
        descendantCount: 0,
        actions: ["remove_local_copy", "restore_to_drive"],
      }],
    },
    needs_review_other_root: {
      ...base,
      status: "needs_review",
      reviewCount: 1,
      syncLocations: base.syncLocations.map((location) => location.id === "demo-pair-2" ? {
        ...location,
        syncStatus: "needs_review",
        error: "Drive returned an error while preserving this review.",
      } : location),
      reviews: [],
    },
    error: {
      ...base,
      status: "error",
      error: "Drive could not verify a completed transfer. Check the connection, then retry.",
      activity: [{ at: now, direction: "Drive", path: "Transfer", result: "Stopped without replacing local data" }],
    },
    disconnect_cleanup_pending: {
      ...base,
      status: "error",
      account: "",
      serverHost: "",
      serverUrl: "",
      driveLocation: "",
      localRoot: "",
      activePairId: null,
      syncLocations: [],
      disconnectCleanupPending: true,
      disconnectRemoteRetirementConfirmed: true,
      error: "Disconnect cleanup is still pending. Finish the exact local cleanup before setting up Drive again.",
      activity: [],
    },
    disconnect_remote_retirement_pending: {
      ...base,
      status: "error",
      pendingRemoteRevocations: 1,
      disconnectCleanupPending: true,
      disconnectRemoteRetirementConfirmed: false,
      error: "Drive could not confirm remote session retirement. Local cleanup remains blocked until you retry.",
      activity: [],
    },
  };
  if (scenario && scenarios[scenario]) Object.assign(demo, scenarios[scenario]);
}

applyBrowserDemo();

async function invoke(command, args = {}) {
  return routeDesktopInvoke(frontend, nativeInvoke, invokeDemo, command, args);
}

async function invokeDemo(command, args = {}) {
  // Browser fallback exists solely for deterministic UI checks; it stores no
  // credentials and never contacts a server.
  switch (command) {
    case "get_desktop_view": return { ...demo };
    case "check_desktop_update": return null;
    case "install_desktop_update": return null;
    case "validate_server": return { normalizedUrl: args.serverUrl.replace(/\/$/, ""), setupRequired: false };
    case "login_password":
    case "continue_login":
      if (demo.status === "needs_reconnect") demo.status = "synced";
      return { kind: "authenticated", accountEmail: args.email };
    case "list_workspace_page": return { workspaces: [{
      id: "demo",
      name: "Demo workspace",
      locations: [
        { remoteRootId: null, syncRootId: "workspace:demo", ownerLabel: "You", role: "owner", label: "Demo workspace" },
        { remoteRootId: "briefs", syncRootId: "item-grant:demo-briefs", ownerLabel: "Avery", role: "viewer", label: "Projects / Briefs" },
      ],
    }], nextCursor: null };
    case "pick_local_root": return "C:\\Users\\You\\ShellX Drive";
    case "start_pair": {
      const localBase = args.localRoot;
      demo.activePairId = "demo-pair-1";
      demo.syncLocations = [{
        id: "demo-pair-1",
        driveLocation: "My files",
        localRoot: `${localBase}\\My files`,
        active: true,
        syncStatus: "Synced",
      }, {
        id: "demo-pair-2",
        driveLocation: "Shared with me / Avery / Projects / Briefs",
        localRoot: `${localBase}\\Shared with Avery - Projects - Briefs`,
        active: false,
        syncStatus: "Synced",
      }];
      Object.assign(demo, {
        status: "synced",
        account: "you@example.test",
        serverHost: "drive.example.test",
        serverUrl: setup.serverUrl,
        driveLocation: "My files",
        localRoot: `${localBase}\\My files`,
        lastSuccessfulSync: new Date().toISOString(),
      });
      return { ...demo };
    }
    case "sync_now":
      demo.activity = [{ at: new Date().toISOString(), direction: "Drive", path: "Ready to reconcile", result: "No changes in browser preview" }, ...demo.activity];
      return { ...demo };
    case "recheck_reviews":
      demo.activity = [{ at: new Date().toISOString(), direction: "Review", path: "Pending decision", result: "Rechecked in browser preview only; no files were moved" }, ...demo.activity];
      return { ...demo };
    case "select_pair": {
      const selected = demo.syncLocations.find((location) => location.id === args.pairId);
      if (!selected) throw new Error("That preview Drive root is no longer available.");
      const review = args.pairId === "demo-pair-2" ? {
        id: "demo-review-other-root",
        kind: "remote_deletion",
        relativePath: "Projects / launch-plan.md",
        summary: "Drive deleted this file. Choose the recoverable action for this root.",
        descendantCount: 0,
        actions: ["remove_local_copy", "restore_to_drive"],
      } : null;
      Object.assign(demo, {
        activePairId: selected.id,
        driveLocation: selected.driveLocation,
        localRoot: selected.localRoot,
        status: review ? "needs_review" : "synced",
        reviews: review ? [review] : [],
        syncLocations: demo.syncLocations.map((location) => ({
          ...location,
          active: location.id === selected.id,
          syncStatus: location.id === selected.id && review ? "needs_review" : location.syncStatus,
        })),
      });
      return { ...demo };
    }
    case "set_paused": demo.paused = args.paused; demo.status = args.paused ? "paused" : "synced"; return { ...demo };
    case "set_launch_at_login": demo.launchAtLogin = args.enabled; return { ...demo };
    case "disconnect": Object.assign(demo, { status: "needs_setup", account: "", serverHost: "", serverUrl: "", driveLocation: "", localRoot: "", activePairId: null, syncLocations: [], reviews: [], reviewCount: 0, disconnectCleanupPending: false, disconnectRemoteRetirementConfirmed: false, activity: [] }); return { ...demo };
    case "open_local_folder":
    case "open_drive": return { ...demo };
    case "prepare_review_action": {
      const item = demo.reviews.find((review) => review.id === args.reviewId);
      if (!item) throw new Error("That preview review is no longer pending.");
      return {
        confirmationId: `preview-${item.id}-${args.action}`,
        relativePath: item.relativePath,
        descendantCount: item.descendantCount ?? 0,
        action: args.action,
      };
    }
    case "choose_review_action": {
      const item = demo.reviews.find((review) => review.id === args.reviewId);
      if (!item || !args.confirmationId) throw new Error("Confirm this preview action before applying it.");
      Object.assign(demo, {
        status: "synced",
        reviews: [],
        reviewCount: 0,
        activity: [{ at: new Date().toISOString(), direction: "Preview", path: item.relativePath, result: "Review action shown in browser preview only" }, ...demo.activity],
      });
      return { ...demo };
    }
    default: throw new Error(`Desktop command unavailable: ${command}`);
  }
}

function displayTime(value) {
  if (!value) return "No completed sync yet";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "No completed sync yet" : `Last synced ${date.toLocaleString()}`;
}

function escape(value = "") {
  return String(value).replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;" })[character]);
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

function shell(view, contents) {
  const copy = statusCopy(view.status);
  const mark = view.status.replaceAll("_", "-");
  const navigationLabel = showSettings ? "Back to Drive" : "Settings";
  return `<div class="shell">
    <header class="title-row">
      <div><div class="brand">ShellX Drive</div><div class="account">${escape(view.account || view.serverHost || "Desktop sync")}</div></div>
      <button class="button" data-action="settings-navigation" aria-expanded="${showSettings}">${navigationLabel}</button>
    </header>
    <section class="status" aria-labelledby="status-title">
      <div class="status-top">
        <div class="inline"><span class="status-mark ${mark}" aria-hidden="true"></span><div><h1 id="status-title" tabindex="-1">${copy.label}</h1><p>${copy.detail}</p></div></div>
        <span class="sync-time">${escape(displayTime(view.lastSuccessfulSync))}</span>
      </div>
      ${view.driveLocation && view.localRoot ? `<div class="active-location"><span>Current root details</span><strong>${escape(view.driveLocation)}</strong><small>${escape(view.localRoot)} · Configured Drive roots sync automatically.</small></div>` : ""}
    </section>
    ${view.rootDiscoveryOverflow ? `<p class="diagnostic" data-root-discovery-overflow role="status">Configured Drive roots continue syncing. Browse the available roots in pages to add another.</p>` : ""}
    ${pendingRemoteRevocationNotice(view)}
    ${view.disconnectRequested || disconnectRequestInFlight ? `<p class="diagnostic" data-disconnect-requested role="status">Stopping synchronization before Disconnect. Saved credentials and device access remain in place until the active file or network operation finishes safely.</p>` : ""}
    <p class="diagnostic action-error" data-action-error role="alert" ${actionError ? "" : "hidden"}>${escape(actionError)}</p>
    ${renderDesktopUpdateRecoveryNotice(view.updateRecoveryTargetVersion, view.appVersion, escape)}
    ${renderDesktopUpdateNotice(desktopUpdate, escape)}
    ${showSettings ? settings(view) : contents}
  </div>`;
}

function pendingRemoteRevocationNotice(view) {
  // An active durable Disconnect has phase-specific recovery copy. Its local
  // credentials may still be retained, so do not show the post-logout claim.
  if (view.disconnectCleanupPending) return "";
  const count = Number(view.pendingRemoteRevocations) || 0;
  if (count < 1) return "";
  const sessions = count === 1 ? "session" : "sessions";
  return `<div class="diagnostic" data-remote-revocation-notice role="status">Local credentials are removed. Remote revocation is pending for ${count} ${sessions}; ShellX Drive retries after the next successful sign-in to the same server and account, or drops the record after expiry.</div>`;
}

function settings(view) {
  if (view.disconnectCleanupPending) {
    const phase = disconnectRecoveryCopy(view);
    return `<section class="settings" aria-label="Settings">
      <h2>Settings</h2>
      <p class="when">${escape(phase.settings)}</p>
      ${renderDesktopUpdate(desktopUpdate, view.appVersion, escape)}
    </section>`;
  }
  const connected = Boolean(view.account && view.serverUrl && view.localRoot && view.driveLocation);
  const canDisconnect = !view.credentialRecoveryPending && (connected || view.disconnectAvailable);
  const rootCount = view.syncLocations.length || (connected ? 1 : 0);
  const rootNoun = rootCount === 1 ? "root" : "roots";
  const disconnectDetail = connected
    ? `The saved desktop session and all ${rootCount} managed ${rootNoun} are removed. Files in every listed local folder stay in place.`
    : "Ends Drive sign-in on this PC and removes any saved desktop sessions and credentials. No local Drive folder is currently connected.";
  const localUsage = view.localUsageBytes === null
    ? "Unavailable until every configured local folder can be safely measured"
    : `${formatByteSize(view.localUsageBytes)} · ${view.localUsageFileCount ?? 0} files · ${view.localUsageFolderCount ?? 0} folders`;
  const disconnectPending = view.disconnectRequested || disconnectRequestInFlight;
  const disconnect = !canDisconnect ? "" : disconnectPending ? `<div class="review-confirmation" role="status"><p>Stopping synchronization before Disconnect. Keep this window open.</p><div class="action-row"><button class="button danger" disabled>Disconnecting…</button></div></div>` : pendingDisconnectConfirmation ? `<div class="review-confirmation" role="alert">
    <p>Disconnect this PC from ${escape(view.serverHost || "Drive")}? ${disconnectDetail}</p>
    <div class="action-row"><button class="button" data-action="disconnect-cancel">Cancel</button><button class="button danger" data-action="disconnect-confirm">Disconnect this PC</button></div>
  </div>` : `<div class="action-row"><button class="button danger" data-action="disconnect">Disconnect</button></div>`;
  const agentControl = !connected ? "" : pendingDesktopAgentControl === null
    ? `<label class="inline"><input id="desktop-agent-control" type="checkbox" ${view.desktopAgentEnabled ? "checked" : ""} /> Allow remote agent control from this paired desktop</label><p class="when">This device uses an outbound encrypted Drive connection. Enabling or disabling it requires confirmation on this PC.</p>${view.desktopAgentEnabled && !view.desktopAgentReady ? `<p class="diagnostic" role="status">Remote agent control is enrolled but unavailable until its local credential and paired session are ready.</p>` : ""}`
    : `<div class="review-confirmation" role="alert"><p>${pendingDesktopAgentControl ? "Enable remote agent control for this paired desktop?" : "Disable remote agent control for this paired desktop?"}</p><div class="action-row"><button class="button" data-action="desktop-agent-cancel">Cancel</button><button class="button ${pendingDesktopAgentControl ? "" : "danger"}" data-action="desktop-agent-confirm">${pendingDesktopAgentControl ? "Enable remote agent control" : "Disable remote agent control"}</button></div></div>`;
  return `<section class="settings" aria-label="Settings">
    <h2>Settings</h2>
    ${connected ? `<section class="settings-section" aria-labelledby="connection-heading">
      <h3 id="connection-heading">Connection</h3>
      <dl class="connection-list">
        <div><dt>Account</dt><dd>${escape(view.account)}</dd></div>
        <div><dt>Server</dt><dd>${escape(view.serverHost)}</dd></div>
        <div><dt>Saved session</dt><dd>Protected by this operating system’s credential store</dd></div>
        <div><dt>Local disk usage (all locations)</dt><dd>${escape(localUsage)}</dd></div>
      </dl>
    </section>
    ${renderSyncLocations(view, escape, syncLocationsFilter)}
    <section class="settings-section" aria-labelledby="startup-heading">
      <h3 id="startup-heading">Startup</h3>
      <label class="inline"><input id="launch-at-login" type="checkbox" ${view.launchAtLogin ? "checked" : ""} /> Start ShellX Drive when I sign in</label>
    </section>
    ${connected ? `<section class="settings-section" aria-labelledby="desktop-agent-heading">
      <h3 id="desktop-agent-heading">Remote agent control</h3>
      ${agentControl}
    </section>` : ""}` : canDisconnect ? "" : `<p class="when">Complete setup to connect one Drive server and account, then choose one empty local Drive folder on this PC.</p>`}
    ${canDisconnect ? `<section class="settings-section danger-zone" aria-labelledby="disconnect-heading">
      <h3 id="disconnect-heading">Disconnect this PC</h3>
      <p class="when">${connected ? `Removes the saved desktop session and all ${rootCount} managed ${rootNoun}. Files in every listed local folder stay on this PC.` : disconnectDetail}</p>
      ${disconnect}
    </section>` : ""}
    ${renderDesktopUpdate(desktopUpdate, view.appVersion, escape)}
  </section>`;
}

function cleanupCompletionNotice() {
  return cleanupRetryState === "succeeded"
    ? `<p class="cleanup-success" role="status">Disconnect cleanup finished. This PC is ready to set up Drive.</p>`
    : "";
}

function disconnectRecoveryCopy(view) {
  return view.disconnectRemoteRetirementConfirmed ? {
    heading: "Finish disconnect cleanup",
    idle: "Remote retirement is confirmed. ShellX Drive still needs to remove the exact local marker and saved credential slots.",
    running: "Finishing the exact local cleanup. Keep this window open.",
    action: "Finish disconnect cleanup",
    runningAction: "Finishing disconnect cleanup…",
    retryError: "Local disconnect cleanup is still pending. Retry to continue.",
    settings: "Finish the remaining local Disconnect cleanup before changing this PC's Drive setup.",
  } : {
    heading: "Retry remote retirement",
    idle: "Remote retirement is not confirmed. Your local Drive pair and saved credentials are retained; local cleanup is blocked.",
    running: "Retrying remote retirement before any local cleanup. Keep this window open.",
    action: "Retry remote retirement",
    runningAction: "Retrying remote retirement…",
    retryError: "Remote retirement is still not confirmed. Retry to continue.",
    settings: "Retry remote retirement before changing this PC's Drive setup; local cleanup remains blocked.",
  };
}

function disconnectCleanupRecoveryView(view) {
  const copy = disconnectRecoveryCopy(view);
  const busy = cleanupRetryState === "running";
  const backendError = view.error
    ? `<p class="diagnostic" role="alert">${escape(view.error)}</p>`
    : "";
  const retryError = cleanupRetryError
    ? `<p class="diagnostic" role="alert">${escape(cleanupRetryError)}</p>`
    : "";
  const progress = busy
    ? `<p class="when" role="status" aria-live="polite">${escape(copy.running)}</p>`
    : `<p class="when">${escape(copy.idle)}</p>`;
  return shell(view, `<section class="content cleanup-recovery" aria-label="${escape(copy.heading)}">
    <div class="section-head"><h2>${escape(copy.heading)}</h2><span>Required</span></div>
    <div class="cleanup-recovery-body">
      ${progress}
      ${backendError}${retryError}
      <div class="action-row"><button class="button primary" data-action="finish-disconnect-cleanup" ${busy ? "disabled aria-busy=\"true\"" : ""}>${escape(busy ? copy.runningAction : copy.action)}</button></div>
    </div>
  </section>`);
}

function activity(view) {
  return renderActivityHistory(view.activity, history, escape);
}

function credentialRecoveryView(view) {
  const retainedIdentity = Boolean(view.account && view.serverUrl);
  return shell(view, `<section class="content" aria-label="Recover saved sign-in">
    <section class="setup-step">
      <h2>Recover saved sign-in</h2>
      <p>${view.activePairId ? "Your local Drive folder, managed roots, and last verified baseline stay in place." : "Drive needs to finish the interrupted sign-in before you can choose a local folder."}</p>
      ${view.error ? `<p class="diagnostic" role="alert">${escape(view.error)}</p>` : ""}
      ${retainedIdentity ? `<p>Unlock this operating system’s credential store, then sign in to the same server and account to retry safely.</p>
      <form id="credential-recovery-form" class="fields">
        <label>Server URL<input name="serverUrl" type="url" value="${escape(view.serverUrl)}" readonly /></label>
        <label>Email<input name="email" type="email" autocomplete="username" value="${escape(view.account)}" readonly /></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
        ${setup.authNeeds2fa ? `<p>Enter a current TOTP or recovery code with the same account password.</p><label>TOTP code<input name="totpCode" inputmode="numeric" autocomplete="one-time-code" /></label><label>Or recovery code<input name="recoveryCode" autocomplete="off" /></label>` : ""}
        <div><button class="button primary" type="submit">${setup.authNeeds2fa ? "Continue sign-in" : "Retry sign-in"}</button></div>
      </form>` : `<p>Drive cannot safely identify the interrupted sign-in. Unlock this operating system’s credential store in your current login session, then close and reopen ShellX Drive to retry. If this continues, contact your server administrator or support before changing this PC’s Drive setup.</p>`}
    </section>
  </section>`);
}

function reviews(view) {
  if (!view.reviews.length) {
    return view.reviewCount > 0
      ? `<div class="empty">A different managed Drive root has a decision waiting. Open Settings to identify that location; its review stays attached to the correct local files.</div>`
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

function daily(view) {
  const reviewMode = showReviews || view.status === "needs_review";
  const error = view.status === "error" && view.error ? `<div class="diagnostic" data-backend-error>${escape(view.error)}</div>` : "";
  const rechecking = mayRecheckReviews(view);
  const syncDisabled = rechecking ? false : !mayRunSync(view.status);
  const syncReason = view.status === "syncing" ? "A sync pass is already active." : view.status === "paused" ? "Resume before starting a new pass." : view.status === "needs_review" ? "Use Recheck review to safely refresh the pending decision." : "";
  const syncLabel = rechecking ? "Recheck review" : view.status === "offline" ? "Retry now" : view.status === "syncing" ? "Syncing" : "Sync now";
  const syncAction = rechecking ? "recheck-reviews" : "sync-now";
  const available = addRootPicker?.workspacesLoaded ? driveLocationChoices(addRootPicker.workspaces) : [];
  const addRootSection = !addRootPicker ? "" : `<section class="content" aria-label="Add a Drive root">
    <div class="section-head"><h2>Add a Drive root</h2><button class="button" data-action="close-add-root">Close</button></div>
    <p>Choose one available location. Browsing does not add it to this desktop.</p>
    ${addRootPicker.workspaceDiscoveryError ? `<p role="alert">${escape(addRootPicker.workspaceDiscoveryError)}</p><button class="button" data-action="retry-add-root">Retry roots</button>` : ""}
    ${available.length ? renderDiscoveredRoots(available, escape, addRootPicker.selectedSyncRootId, "addSyncRootId") : addRootPicker.workspacesLoaded ? "<p>No locations on this page.</p>" : "<p aria-busy=\"true\">Loading Drive roots...</p>"}
    <div class="action-row">${addRootPicker.rootPageIndex ? `<button class="button" data-action="first-add-root-page">Start over</button>` : ""}<button class="button" data-action="next-add-root-page" ${addRootPicker.nextRootCursor ? "" : "disabled"}>More roots</button>
    <button class="button primary" data-action="confirm-add-root" ${addRootPicker.workspacesLoaded && addRootPicker.selectedSyncRootId && view.syncLocations.length < 100 ? "" : "disabled"}>Add selected root</button></div>
    ${view.syncLocations.length >= 100 ? "<p role=\"status\">This desktop has reached its 100-root limit. Browsing remains available.</p>" : ""}
  </section>`;
  return shell(view, `${error}<section class="content" aria-label="${reviewMode ? "Needs review" : "Activity"}">
    <div class="section-head"><h2 id="daily-section-title" tabindex="-1">${reviewMode ? "Needs review" : "History"}</h2><span>${reviewMode ? `${view.reviewCount} awaiting a decision` : "Newest first"}</span></div>
    ${reviewMode ? reviews(view) : activity(view)}
  </section>${addRootSection}
  <nav class="action-row" aria-label="Drive actions">
    <button class="button ${view.status === "synced" ? "primary" : ""}" data-action="open-local-folder">Open folder</button>
    <button class="button" data-action="open-drive">Open Drive</button>
    <button class="button ${view.status === "offline" ? "primary" : ""}" data-action="${syncAction}" ${syncDisabled ? `disabled title="${syncReason}"` : ""}>${syncLabel}</button>
    <button class="button" data-action="open-add-root">Add Drive root</button>
    <button class="button ${view.status === "paused" ? "primary" : ""}" data-action="pause-resume" ${view.status === "syncing" ? "disabled title=\"A sync pass is active.\"" : ""}>${view.paused ? "Resume" : "Pause"}</button>
    ${view.status === "error" ? `<button class="button primary" data-action="show-error">View error</button>` : ""}
  </nav>`);
}

function setupView(view) {
  const completedServer = setup.serverValidated ? `<section class="setup-step complete">
    <div><h2>1. Drive server</h2><p>${escape(setup.serverUrl)}</p></div>
    <button class="button" type="button" data-action="change-setup">Change</button>
  </section>` : `<section class="setup-step"><h2>1. Drive server</h2><p>Use HTTPS. The host shown after validation is the one that receives your sign-in.</p>
    <form id="server-form" class="fields"><label>Server URL<input name="serverUrl" type="url" placeholder="https://drive.example.com" value="${escape(setup.serverUrl)}" required /></label><div><button class="button primary" type="submit">Validate server</button></div></form>
  </section>`;
  const loginSection = setup.serverValidated && !setup.signedIn ? `<section class="setup-step">
    <h2>2. Sign in</h2><p>${setup.authNeeds2fa ? "Enter a current TOTP or a recovery code to continue this sign-in." : "Use your Drive account. The desktop session is protected by this operating system’s credential store, never in this folder."}</p>
    <form id="login-form" class="fields">
      <label>Email<input name="email" type="email" autocomplete="username" value="${escape(setup.accountEmail)}" required /></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
      ${setup.authNeeds2fa ? `<label>TOTP code<input name="totpCode" inputmode="numeric" autocomplete="one-time-code" /></label><label>Or recovery code<input name="recoveryCode" autocomplete="off" /></label>` : ""}
      <div><button class="button primary" type="submit">${setup.authNeeds2fa ? "Continue sign-in" : "Sign in"}</button></div>
    </form>
  </section>` : setup.signedIn ? `<section class="setup-step complete">
    <div><h2>2. Signed in</h2><p>${escape(setup.accountEmail)}</p></div>
  </section>` : "";
  const locations = driveLocationChoices(setup.workspaces);
  const discoveryRetry = `<button class="button primary" type="button" data-action="retry-workspaces">Retry Drive roots</button>`;
  const pageControls = `${setup.rootPageIndex ? `<button class="button" type="button" data-action="first-root-page">Start over</button>` : ""}${setup.nextRootCursor ? `<button class="button" type="button" data-action="next-root-page">More Drive roots</button>` : ""}`;
  const pairSection = !setup.signedIn ? "" : setup.workspaceDiscoveryError ? `<section class="setup-step" role="alert">
    <h2>3. Drive roots unavailable</h2><p>${escape(setup.workspaceDiscoveryError)}</p><div>${discoveryRetry}</div>
  </section>` : !setup.workspacesLoaded ? `<section class="setup-step" aria-busy="true">
    <h2>3. Loading Drive roots</h2><p>Your desktop session is saved. ShellX Drive is checking the roots available to this account.</p>
  </section>` : locations.length === 0 ? `<section class="setup-step">
    <h2>3. Drive roots</h2><p>${setup.nextRootCursor ? "No locations on this page. Continue to browse available roots." : "This account has no visible owned or shared roots yet."}</p><div>${pageControls}${discoveryRetry}</div>
  </section>` : `<section class="setup-step">
    <h2>3. Choose a Drive root</h2><p>Select one location to sync below your local Drive folder. You can browse more available locations without adding them. Shared Viewer roots download only; local changes stay on this PC for review and are never uploaded.</p>
    ${renderDiscoveredRoots(locations, escape, setup.selectedSyncRootId)}
    <div>${pageControls}</div>
    <form id="pair-form" class="fields">
      <div class="local-folder-choice" aria-labelledby="local-folder-label">
        <div class="local-folder-copy"><span id="local-folder-label">Local Drive folder</span><output id="local-root-summary" role="status">${setup.selectedLocalRoot ? escape(setup.selectedLocalRoot) : "No folder selected"}</output><small>Choose an existing empty folder. Its path cannot be typed or edited here.</small></div>
        <button class="button" type="button" data-action="choose-local-root">${setup.selectedLocalRoot ? "Change folder" : "Choose folder"}</button>
      </div>
      <div class="action-row"><button class="button primary" type="submit" ${pairSelectionReady(setup) ? "" : "disabled title=\"Choose a Drive root and local folder first.\""}>Connect and start syncing</button></div>
    </form>
  </section>`;
  return shell(view, `<section class="content" aria-label="Set up ShellX Drive">
    ${cleanupCompletionNotice()}
    ${completedServer}${loginSection}${pairSection}
  </section>`);
}

function reconnectView(view) {
  return shell(view, `<section class="content" aria-label="Reconnect ShellX Drive">
    <section class="setup-step complete"><div><h2>Retained Drive pair</h2><p>${escape(view.account)} · ${escape(view.serverHost)}</p></div></section>
    <section class="setup-step">
      <h2>Sign in again</h2><p>${setup.authNeeds2fa ? "Enter a current TOTP or recovery code with the same account password." : "Your local Drive folder, managed roots, and last verified baseline stay in place."}</p>
      <form id="reconnect-form" class="fields">
        <label>Email<input name="email" type="email" autocomplete="username" value="${escape(view.account)}" readonly /></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
        ${setup.authNeeds2fa ? `<label>TOTP code<input name="totpCode" inputmode="numeric" autocomplete="one-time-code" /></label><label>Or recovery code<input name="recoveryCode" autocomplete="off" /></label>` : ""}
        <div><button class="button primary" type="submit">${setup.authNeeds2fa ? "Continue sign-in" : "Reconnect"}</button></div>
      </form>
    </section>
  </section>`);
}

function backgroundSurface(view) {
  if (showSettings) return "settings";
  return showReviews || view.status === "needs_review" ? "reviews" : "activity";
}

function captureBackgroundViewport() {
  const focused = document.activeElement;
  const scrolling = document.scrollingElement;
  return {
    surface: backgroundSurface(currentView),
    focus: focusSelectorFor(focused),
    selection: Number.isInteger(focused?.selectionStart)
      ? [focused.selectionStart, focused.selectionEnd, focused.selectionDirection] : null,
    left: scrolling?.scrollLeft ?? window.scrollX,
    top: scrolling?.scrollTop ?? window.scrollY,
    containers: [".sync-location-list", ".discovered-root-list"].flatMap((selector) =>
      [...app.querySelectorAll(selector)].map((element, index) => ({
        selector, index, left: element.scrollLeft, top: element.scrollTop,
      }))),
  };
}

function restoreBackgroundViewport(viewport) {
  const focused = viewport.focus ? app.querySelector(viewport.focus) : null;
  focused?.focus({ preventScroll: true });
  if (viewport.selection && typeof focused?.setSelectionRange === "function") {
    focused.setSelectionRange(...viewport.selection);
  }
  for (const saved of viewport.containers) {
    const element = app.querySelectorAll(saved.selector)[saved.index];
    if (element) { element.scrollLeft = saved.left; element.scrollTop = saved.top; }
  }
  const scrolling = document.scrollingElement;
  if (scrolling) { scrolling.scrollLeft = viewport.left; scrolling.scrollTop = viewport.top; }
}

function render(view, { preserveViewport = false } = {}) {
  const viewport = preserveViewport && !pendingFocusSelector
    && !pendingReviewConfirmation && !pendingDisconnectConfirmation
    && shouldPreserveBackgroundViewport(currentView, view) ? captureBackgroundViewport() : null;
  if (currentView && (currentView.account !== view.account || currentView.serverUrl !== view.serverUrl)) {
    addRootPicker = null;
  }
  if (showReviews && view.status !== "needs_review" && view.reviews.length === 0) showReviews = false;
  if (!view.syncLocations.length) syncLocationsFilter = "";
  currentView = view;
  document.title = trayTooltip(view);
  app.innerHTML = view.disconnectCleanupPending ? disconnectCleanupRecoveryView(view) : view.credentialRecoveryPending ? credentialRecoveryView(view) : view.status === "needs_setup" ? setupView(view) : view.status === "needs_reconnect" ? reconnectView(view) : daily(view);
  bind(view);
  // The review row is rebuilt after choosing a consequential action. Keep
  // keyboard users at the new, safe cancellation point rather than sending
  // focus back to the document start.
  if (pendingReviewConfirmation) document.querySelector("[data-action='review-cancel']")?.focus();
  else if (pendingDisconnectConfirmation) document.querySelector("[data-action='disconnect-cancel']")?.focus();
  else if (pendingFocusSelector) {
    const target = document.querySelector(pendingFocusSelector) ?? document.querySelector("#status-title");
    pendingFocusSelector = null;
    target?.focus();
  }
  else if (viewport && viewport.surface === backgroundSurface(view)) restoreBackgroundViewport(viewport);
}

async function refresh() {
  const next = normalizeView(await invoke("get_desktop_view"));
  clearCompletedDisconnectUiState(next, completedDisconnectUiTransition(currentView, next));
  clearActionError();
  render(next);
}

async function refreshFromBackground() {
  if (!shouldRefreshDesktopView({
    browserPreview,
    documentHidden: document.hidden,
    foregroundActionInFlight,
    backgroundRefreshInFlight,
    confirmationOpen: Boolean(pendingReviewConfirmation || pendingDisconnectConfirmation),
    status: currentView?.status,
  })) return;
  backgroundRefreshInFlight = true;
  try {
    const next = normalizeView(await invoke("get_desktop_view"));
    // The user may have opened a confirmation while this request was in
    // flight. Recheck the foreground gates before applying its older view.
    if (!shouldRefreshDesktopView({
      browserPreview,
      documentHidden: document.hidden,
      foregroundActionInFlight,
      backgroundRefreshInFlight: false,
      confirmationOpen: Boolean(pendingReviewConfirmation || pendingDisconnectConfirmation),
      status: currentView?.status,
    })) return;
    if (!desktopViewChanged(currentView, next)) return;
    // A reconnect form contains an unpersisted password. Keep that draft while
    // nonterminal data changes for the same retained pair, but admit a changed
    // pair identity or completed Disconnect transition immediately.
    if (shouldDeferReconnectRender(currentView, next)) return;
    if (!showSettings && shouldDeferCredentialRecoveryRender(currentView, next)) return;
    // A desktop-agent Disconnect can finish between background polls. A prior
    // pending cleanup or a paired view that becomes an unpaired needs_setup
    // view proves that offboarding completed. Ordinary password sign-in keeps
    // no prior pair while its root picker is still required.
    clearCompletedDisconnectUiState(next, completedDisconnectUiTransition(currentView, next));
    render(next, { preserveViewport: true });
  } catch {
    // A foreground command projects actionable errors. Background liveness
    // checks stay quiet and retry on the next bounded interval.
  } finally {
    backgroundRefreshInFlight = false;
  }
}

function bind(view) {
  document.querySelector("[data-action='settings-navigation']")?.addEventListener("click", () => {
    showSettings = !showSettings;
    pendingDisconnectConfirmation = false;
    pendingDesktopAgentControl = null;
    pendingFocusSelector = "[data-action='settings-navigation']";
    render(view);
  });
  document.querySelector("[data-action='show-error']")?.addEventListener("click", () => document.querySelector("[data-backend-error]")?.scrollIntoView({ block: "nearest" }));
  bindActivityHistory(document, history, (next, focusSelector) => {
    history = next;
    pendingFocusSelector = focusSelector;
    render(view);
  });
  document.querySelector("[data-action='open-local-folder']")?.addEventListener("click", () => run("open_local_folder"));
  document.querySelector("[data-action='open-drive']")?.addEventListener("click", () => run("open_drive"));
  document.querySelector("[data-action='sync-now']")?.addEventListener("click", () => run("sync_now"));
  document.querySelector("[data-action='recheck-reviews']")?.addEventListener("click", () => run("recheck_reviews"));
  document.querySelector("[data-action='pause-resume']")?.addEventListener("click", () => run("set_paused", { paused: !view.paused }, "[data-action='pause-resume']"));
  document.querySelector("[data-action='disconnect']")?.addEventListener("click", () => {
    pendingDisconnectConfirmation = true;
    render(view);
  });
  document.querySelector("[data-action='disconnect-cancel']")?.addEventListener("click", () => {
    pendingDisconnectConfirmation = false;
    pendingFocusSelector = "[data-action='disconnect']";
    render(view);
  });
  document.querySelector("[data-action='disconnect-confirm']")?.addEventListener("click", () => {
    pendingDisconnectConfirmation = false;
    runDisconnect(view);
  });
  document.querySelector("[data-action='finish-disconnect-cleanup']")?.addEventListener("click", () => finishDisconnectCleanup(view));
  document.querySelector("[data-action='change-setup']")?.addEventListener("click", async () => {
    const changingSetup = { ...setup };
    setup = changingSetup;
    pendingFocusSelector = "[data-action='change-setup']";
    render(view);
    try {
      // A second-factor step also leaves a password continuation only in
      // native memory. Disconnect clears that pending login before the UI
      // offers another server/account.
      if (setup.signedIn || setup.authNeeds2fa) await invoke("disconnect");
      if (setup !== changingSetup) return;
      setup = emptySetupState();
      pendingFocusSelector = "#server-form input[name='serverUrl']";
      await refresh();
    } catch (error) {
      if (setup === changingSetup) showActionError(error);
    }
  });
  document.querySelector("[data-action='choose-local-root']")?.addEventListener("click", async () => {
    try {
      const path = await invoke("pick_local_root");
      if (!path) return;
      setup = selectLocalRoot(setup, path);
      clearActionError();
      pendingFocusSelector = "[data-action='choose-local-root']";
      render(view);
    } catch (error) { showActionError(error); }
  });
  document.querySelector("[data-action='retry-workspaces']")?.addEventListener("click", () => loadSetupWorkspaces(view));
  document.querySelector("[data-action='next-root-page']")?.addEventListener("click", () => loadSetupWorkspaces(view, setup.nextRootCursor));
  document.querySelector("[data-action='first-root-page']")?.addEventListener("click", () => loadSetupWorkspaces(view));
  document.querySelectorAll("input[name='syncRootId']").forEach((input) => input.addEventListener("change", () => {
    setup = selectDiscoveredRoot(setup, input.value);
    pendingFocusSelector = `input[name='syncRootId']:checked`;
    render(view);
  }));
  document.querySelector("[data-action='open-add-root']")?.addEventListener("click", () => {
    addRootPicker = { ...emptySetupState(), signedIn: true };
    loadAddRootPage(view);
  });
  document.querySelector("[data-action='close-add-root']")?.addEventListener("click", () => {
    addRootPicker = null;
    render(view);
  });
  document.querySelector("[data-action='next-add-root-page']")?.addEventListener("click", () => loadAddRootPage(view, addRootPicker?.nextRootCursor));
  document.querySelector("[data-action='first-add-root-page']")?.addEventListener("click", () => loadAddRootPage(view));
  document.querySelector("[data-action='retry-add-root']")?.addEventListener("click", () => loadAddRootPage(view));
  document.querySelectorAll("input[name='addSyncRootId']").forEach((input) => input.addEventListener("change", () => {
    if (!addRootPicker) return;
    addRootPicker = selectDiscoveredRoot(addRootPicker, input.value);
    pendingFocusSelector = "input[name='addSyncRootId']:checked";
    render(view);
  }));
  document.querySelector("[data-action='confirm-add-root']")?.addEventListener("click", async () => {
    if (!addRootPicker?.selectedSyncRootId || view.syncLocations.length >= 100) return;
    const args = { workspaceId: addRootPicker.selectedWorkspaceId,
      remoteRootId: addRootPicker.selectedRemoteRootId, syncRootId: addRootPicker.selectedSyncRootId };
    if (await run("add_root", args)) {
      addRootPicker = null;
      render(currentView);
    }
  });
  document.querySelectorAll("[data-action='review-location']").forEach((button) => button.addEventListener("click", async () => {
    const pairId = button.dataset.pairId;
    if (!pairId || foregroundActionInFlight) return;
    pendingReviewConfirmation = null;
    pendingDisconnectConfirmation = false;
    foregroundActionInFlight = true;
    try {
      const next = normalizeView(await invoke("select_pair", { pairId }));
      showSettings = false;
      showReviews = true;
      pendingFocusSelector = "[data-action='review-choice']";
      clearActionError();
      render(next);
    } catch (error) {
      render(view);
      showActionError(error);
    } finally {
      foregroundActionInFlight = false;
    }
  }));
  document.querySelectorAll("[data-action='review-choice']").forEach((button) => button.addEventListener("click", async () => {
    try {
      const confirmation = await invoke("prepare_review_action", { reviewId: button.dataset.reviewId, action: button.dataset.reviewAction });
      pendingReviewConfirmation = {
        reviewId: button.dataset.reviewId,
        action: button.dataset.reviewAction,
        confirmationId: confirmation.confirmationId ?? confirmation.confirmation_id,
      };
      clearActionError();
      render(view);
    } catch (error) { showActionError(error); }
  }));
  document.querySelector("[data-action='review-cancel']")?.addEventListener("click", () => {
    pendingReviewConfirmation = null;
    pendingFocusSelector = "[data-action='review-choice']";
    render(view);
  });
  document.querySelector("[data-action='review-confirm']")?.addEventListener("click", () => {
    const confirmation = pendingReviewConfirmation;
    pendingReviewConfirmation = null;
    if (confirmation) run("choose_review_action", { reviewId: confirmation.reviewId, action: confirmation.action, confirmationId: confirmation.confirmationId });
  });
  document.querySelector("#launch-at-login")?.addEventListener("change", (event) => setLaunchAtLogin(event.target.checked));
  document.querySelector("#desktop-agent-control")?.addEventListener("change", (event) => {
    pendingDesktopAgentControl = event.currentTarget.checked;
    pendingFocusSelector = pendingDesktopAgentControl ? "[data-action='desktop-agent-confirm']" : "[data-action='desktop-agent-confirm']";
    render(view);
  });
  document.querySelector("[data-action='desktop-agent-cancel']")?.addEventListener("click", () => {
    pendingDesktopAgentControl = null;
    pendingFocusSelector = "#desktop-agent-control";
    render(view);
  });
  document.querySelector("[data-action='desktop-agent-confirm']")?.addEventListener("click", async () => {
    const enabled = pendingDesktopAgentControl;
    if (enabled === null) return;
    pendingFocusSelector = "#desktop-agent-control";
    foregroundActionInFlight = true;
    try {
      const next = normalizeView(await invoke("set_desktop_agent_control", { enabled }));
      pendingDesktopAgentControl = null;
      clearActionError();
      render(next);
    } catch (error) {
      showActionError(error);
      render(view);
    } finally {
      foregroundActionInFlight = false;
    }
  });
  document.querySelector("[data-sync-locations-filter]")?.addEventListener("input", (event) => {
    syncLocationsFilter = event.currentTarget.value;
    render(view);
    const input = document.querySelector("[data-sync-locations-filter]");
    input?.focus();
    input?.setSelectionRange(syncLocationsFilter.length, syncLocationsFilter.length);
  });
  document.querySelector("[data-action='desktop-update-check']")?.addEventListener("click", () => checkDesktopUpdate(view));
  document.querySelector("[data-action='desktop-update-open']")?.addEventListener("click", () => {
    showSettings = true;
    pendingFocusSelector = desktopUpdate.status === "available"
      ? "[data-action='desktop-update-confirm']"
      : "[data-action='desktop-update-check']";
    render(view);
  });
  document.querySelector("[data-action='desktop-update-confirm']")?.addEventListener("click", () => {
    desktopUpdate = { ...desktopUpdate, status: "confirming", error: "" };
    render(view);
  });
  document.querySelector("[data-action='desktop-update-cancel']")?.addEventListener("click", () => {
    desktopUpdate = { ...desktopUpdate, status: "available", error: "" };
    render(view);
  });
  document.querySelector("[data-action='desktop-update-install']")?.addEventListener("click", () => installDesktopUpdate(view));
  document.querySelector("#server-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const serverUrl = new FormData(event.currentTarget).get("serverUrl").trim();
    try {
      const validation = await invoke("validate_server", { serverUrl });
      if (validation.setupRequired ?? validation.setup_required) {
        throw new Error("This Drive server needs first-time owner setup. Open the server in a browser, complete setup, then validate it again.");
      }
      setup.serverUrl = validation.normalizedUrl ?? validation.normalized_url ?? serverUrl;
      setup.serverValidated = true;
      clearActionError();
      pendingFocusSelector = "#login-form input[name='email']";
      render(view);
    } catch (error) { showActionError(error); }
  });
  document.querySelector("#login-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const args = { serverUrl: setup.serverUrl, email: data.get("email"), password: data.get("password") };
    if (setup.authNeeds2fa) {
      args.totpCode = data.get("totpCode") || null;
      args.recoveryCode = data.get("recoveryCode") || null;
    }
    try {
      const reply = await invoke(setup.authNeeds2fa ? "continue_login" : "login_password", args);
      setup = applyLoginReply(setup, reply, data.get("email"));
      clearActionError();
      if (setup.signedIn) await loadSetupWorkspaces(view);
      else {
        pendingFocusSelector = "#login-form input[name='totpCode']";
        render(view);
      }
    } catch (error) { showActionError(error); }
  });
  document.querySelector("#reconnect-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const args = {
      serverUrl: view.serverUrl,
      email: view.account,
      password: data.get("password"),
    };
    if (setup.authNeeds2fa) {
      args.totpCode = data.get("totpCode") || null;
      args.recoveryCode = data.get("recoveryCode") || null;
    }
    try {
      const reply = await invoke(setup.authNeeds2fa ? "continue_login" : "login_password", args);
      setup.authNeeds2fa = reply.kind === "requires_second_factor";
      clearActionError();
      if (reply.kind === "authenticated") {
        setup = emptySetupState();
        await refresh();
      } else {
        pendingFocusSelector = "#reconnect-form input[name='totpCode']";
        render(view);
      }
    } catch (error) { showActionError(error); }
  });
  document.querySelector("#credential-recovery-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (foregroundActionInFlight || !view.account || !view.serverUrl || view.disconnectCleanupPending) return;
    const data = new FormData(event.currentTarget);
    const button = event.currentTarget.querySelector("button[type='submit']");
    const args = { serverUrl: view.serverUrl, email: view.account, password: data.get("password") };
    if (setup.authNeeds2fa) {
      args.totpCode = data.get("totpCode") || null;
      args.recoveryCode = data.get("recoveryCode") || null;
    }
    foregroundActionInFlight = true;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    try {
      const reply = await invoke(setup.authNeeds2fa ? "continue_login" : "login_password", args);
      setup = applyLoginReply(setup, reply, view.account);
      clearActionError();
      if (setup.signedIn) {
        const next = normalizeView(await invoke("get_desktop_view"));
        if (!next.credentialRecoveryPending && !next.disconnectCleanupPending && !next.activePairId && next.status === "needs_setup") {
          setup = { ...setup, serverUrl: next.serverUrl || view.serverUrl, serverValidated: true };
          await loadSetupWorkspaces(next);
        } else {
          setup = emptySetupState();
          render(next);
        }
      } else {
        pendingFocusSelector = "#credential-recovery-form input[name='totpCode']";
        render(view);
      }
    } catch (error) { showActionError(error); }
    finally {
      foregroundActionInFlight = false;
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  });
  document.querySelector("#pair-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!pairSelectionReady(setup)) {
      pendingFocusSelector = "[data-action='choose-local-root']";
      render(view);
      return;
    }
    const args = {
      workspaceId: setup.selectedWorkspaceId,
      remoteRootId: setup.selectedRemoteRootId,
      syncRootId: setup.selectedSyncRootId,
      localRoot: setup.selectedLocalRoot,
    };
    await run("start_pair", args);
  });
}

async function checkDesktopUpdate(view, { silent = false } = {}) {
  if (["checking", "downloading", "installing"].includes(desktopUpdate.status)) return;
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
  if (silent && !showSettings && (nextView.credentialRecoveryPending || ["needs_setup", "needs_reconnect"].includes(nextView.status))) return;
  if (!silent || showSettings || desktopUpdate.status === "available") render(nextView, { preserveViewport: silent });
}

async function installDesktopUpdate(view) {
  if (desktopUpdate.status !== "confirming") return;
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

async function finishDisconnectCleanup(view) {
  if (cleanupRetryState === "running") return;
  cleanupRetryState = "running";
  cleanupRetryError = null;
  pendingFocusSelector = "#status-title";
  foregroundActionInFlight = true;
  render(view);
  try {
    const next = normalizeView(await invoke("disconnect"));
    clearCompletedDisconnectUiState(next, true);
    clearActionError();
    if (next.disconnectCleanupPending) {
      cleanupRetryState = "failed";
      cleanupRetryError = next.error ?? disconnectRecoveryCopy(next).retryError;
      pendingFocusSelector = "[data-action='finish-disconnect-cleanup']";
    } else {
      cleanupRetryState = "succeeded";
      cleanupRetryError = null;
      pendingFocusSelector = "#status-title";
    }
    render(next);
  } catch (error) {
    const next = await refreshAfterDisconnectFailure(view);
    if (!next.disconnectCleanupPending) {
      clearCompletedDisconnectUiState(next, true);
      render(next);
      showActionError(error);
      return;
    }
    cleanupRetryState = "failed";
    cleanupRetryError = error?.message ?? String(error);
    pendingFocusSelector = "[data-action='finish-disconnect-cleanup']";
    render(next);
  } finally {
    foregroundActionInFlight = false;
  }
}

async function runDisconnect(view) {
  pendingFocusSelector = "#status-title";
  foregroundActionInFlight = true;
  disconnectRequestInFlight = true;
  render(view);
  try {
    const next = normalizeView(await invoke("disconnect"));
    disconnectRequestInFlight = false;
    clearCompletedDisconnectUiState(next, true);
    clearActionError();
    render(next);
  } catch (error) {
    const next = await refreshAfterDisconnectFailure(view);
    disconnectRequestInFlight = false;
    if (next.disconnectCleanupPending) {
      cleanupRetryState = "failed";
      cleanupRetryError = error?.message ?? String(error);
      pendingFocusSelector = "[data-action='finish-disconnect-cleanup']";
      render(next);
    } else {
      clearCompletedDisconnectUiState(next, true);
      render(next);
      showActionError(error);
    }
  } finally {
    disconnectRequestInFlight = false;
    foregroundActionInFlight = false;
  }
}

async function refreshAfterDisconnectFailure(fallback) {
  try {
    return normalizeView(await invoke("get_desktop_view"));
  } catch {
    return fallback;
  }
}

function completedDisconnectUiTransition(previous, next) {
  return Boolean(previous?.disconnectCleanupPending) || (
    Boolean(previous?.activePairId)
    && next.status === "needs_setup"
    && !next.activePairId
    && !next.disconnectCleanupPending
  );
}

function clearCompletedDisconnectUiState(next, completedDisconnect) {
  // `needs_setup` alone is not an offboarding signal: a successful password
  // login stays in that state while it loads roots and waits for a local-folder
  // choice. Only an explicit Disconnect result, a pending-Disconnect
  // completion, or a paired-to-unpaired transition may retire its cached
  // setup state.
  if (!completedDisconnect || next.disconnectCleanupPending || next.status !== "needs_setup") {
    return false;
  }
  setup = emptySetupState();
  addRootPicker = null;
  history = emptyHistoryState();
  syncLocationsFilter = "";
  showReviews = false;
  pendingReviewConfirmation = null;
  pendingDisconnectConfirmation = false;
  pendingDesktopAgentControl = null;
  cleanupRetryState = "succeeded";
  cleanupRetryError = null;
  return true;
}

async function loadSetupWorkspaces(view, cursor = null) {
  setup = beginWorkspaceDiscovery(setup);
  const discoverySetup = setup;
  render(view);
  try {
    const page = await invoke("list_workspace_page", { cursor });
    if (setup !== discoverySetup) return;
    setup = completeWorkspacePage(setup, page, cursor);
    clearActionError();
    pendingFocusSelector = setup.workspaces.some((workspace) => (workspace.locations ?? []).length > 0)
      ? "input[name='syncRootId']"
      : setup.nextRootCursor ? "[data-action='next-root-page']" : "[data-action='retry-workspaces']";
  } catch (error) {
    if (setup !== discoverySetup) return;
    if (await restoreExpiredSetupSession(discoverySetup) || setup !== discoverySetup) return;
    setup = failWorkspaceDiscovery(setup, error);
    pendingFocusSelector = "[data-action='retry-workspaces']";
  }
  render(view);
}

async function loadAddRootPage(view, cursor = null) {
  if (!addRootPicker) return;
  addRootPicker = beginWorkspaceDiscovery(addRootPicker);
  const original = addRootPicker;
  render(view);
  try {
    const page = await invoke("list_workspace_page", { cursor });
    if (addRootPicker !== original) return;
    addRootPicker = completeWorkspacePage(original, page, cursor);
  } catch (error) {
    if (addRootPicker !== original) return;
    addRootPicker = failWorkspaceDiscovery(original, error);
  }
  render(view);
}

async function run(command, args = {}, focusSelector = null) {
  const setupAtStart = command === "start_pair" ? setup : null;
  pendingFocusSelector = focusSelector ?? focusSelectorFor(document.activeElement) ?? "#status-title";
  foregroundActionInFlight = true;
  try {
    const next = normalizeView(await invoke(command, args));
    if (setupAtStart && setup !== setupAtStart) return;
    clearActionError();
    render(next);
    return true;
  }
  catch (error) {
    if (setupAtStart && setup !== setupAtStart) return;
    if (command === "start_pair" && (await restoreExpiredSetupSession(setupAtStart) || setup !== setupAtStart)) return;
    showActionError(error);
    return false;
  }
  finally { foregroundActionInFlight = false; }
}

async function restoreExpiredSetupSession(expectedSetup) {
  try {
    const next = normalizeView(await invoke("get_desktop_view"));
    if (setup !== expectedSetup || !hasRetiredSetupSession(expectedSetup, next)) return false;
    setup = resetExpiredSetupSession(expectedSetup);
    clearActionError();
    pendingFocusSelector = "#login-form input[name='email']";
    render(next);
    return true;
  } catch {
    return false;
  }
}

async function setLaunchAtLogin(enabled) {
  pendingFocusSelector = "#launch-at-login";
  foregroundActionInFlight = true;
  try {
    const next = normalizeView(await invoke("set_launch_at_login", { enabled }));
    clearActionError();
    render(next);
  } catch (error) {
    // The checkbox has already changed in the DOM. Re-read the backend before
    // rendering so a failed OS autostart mutation cannot leave a stale check.
    const next = await refreshAfterActionFailure(currentView);
    render(next);
    showActionError(error);
  } finally {
    foregroundActionInFlight = false;
  }
}

async function refreshAfterActionFailure(fallback) {
  try {
    return normalizeView(await invoke("get_desktop_view"));
  } catch {
    return fallback;
  }
}

function focusSelectorFor(element) {
  if (!(element instanceof HTMLElement)) return null;
  if (element.id) return `#${CSS.escape(element.id)}`;
  if (element.matches("[data-sync-locations-filter]")) return "[data-sync-locations-filter]";
  const action = element.dataset?.action;
  const pair = element.dataset?.pairId;
  return action ? `[data-action='${CSS.escape(action)}']${pair ? `[data-pair-id='${CSS.escape(pair)}']` : ""}` : null;
}

function cancelOpenConfirmation(view) {
  if (pendingReviewConfirmation) {
    pendingReviewConfirmation = null;
    pendingFocusSelector = "[data-action='review-choice']";
    render(view);
    return true;
  }
  if (pendingDisconnectConfirmation) {
    pendingDisconnectConfirmation = false;
    pendingFocusSelector = "[data-action='disconnect']";
    render(view);
    return true;
  }
  return false;
}

function showActionError(error) {
  actionError = error?.message ?? String(error);
  const surface = app.querySelector("[data-action-error]");
  if (!surface) return;
  surface.textContent = actionError;
  surface.hidden = false;
  surface.scrollIntoView({ block: "nearest" });
}

function clearActionError() {
  actionError = "";
  const surface = app.querySelector("[data-action-error]");
  if (!surface) return;
  surface.textContent = "";
  surface.hidden = true;
}

function focusReviewSurface() {
  const target = document.querySelector("[data-action='review-choice']")
    ?? document.querySelector("#daily-section-title")
    ?? document.querySelector("#status-title");
  target?.focus();
}

async function openReviewsFromNative() {
  pendingReviewConfirmation = null;
  pendingDisconnectConfirmation = false;
  pendingDesktopAgentControl = null;
  pendingFocusSelector = null;
  if (desktopUpdate.status === "confirming") desktopUpdate = { ...desktopUpdate, status: "available", error: "" };
  foregroundActionInFlight = true;
  try {
    const next = normalizeView(await invoke("get_desktop_view"));
    const needsAnotherRoot = next.status === "needs_review" && next.reviews.length === 0;
    showReviews = !needsAnotherRoot;
    showSettings = needsAnotherRoot;
    pendingFocusSelector = needsAnotherRoot ? "[data-action='review-location']" : null;
    clearActionError();
    render(next);
    if (!showSettings) focusReviewSurface();
  } catch (error) {
    if (currentView) render(currentView);
    showActionError(error);
  } finally {
    foregroundActionInFlight = false;
  }
}

function renderBackendFailure() {
  document.title = "ShellX Drive could not start";
  app.innerHTML = `<section class="shell"><section class="status"><h1>ShellX Drive could not start</h1><p class="diagnostic">The desktop service did not respond, so no files or settings were changed.</p><p>Close and reopen ShellX Drive. If this keeps happening, reinstall the latest version or contact your server administrator.</p></section></section>`;
}

async function start() {
  if (frontend.kind === "blocked") {
    renderBackendFailure();
    return;
  }
  try {
    const handshake = await invoke("get_desktop_view");
    if (!backendHandshakeIsValid(handshake)) throw new Error("The desktop backend returned an invalid startup response.");
    const view = normalizeView(handshake);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && currentView && cancelOpenConfirmation(currentView)) event.preventDefault();
    });
    render(view);
    if (typeof nativeListen === "function") {
      try {
        await nativeListen("shellx-drive-open-reviews", openReviewsFromNative);
      } catch (error) {
        showActionError(new Error(`The Review issues shortcut is unavailable: ${error?.message ?? String(error)}`));
      }
    }
    checkDesktopUpdate(view, { silent: true });
    window.setInterval(refreshFromBackground, 2000);
    window.addEventListener("focus", refreshFromBackground);
    document.addEventListener("visibilitychange", refreshFromBackground);
  } catch (error) {
    console.error("ShellX Drive desktop startup failed.", error);
    renderBackendFailure();
  }
}

start();
