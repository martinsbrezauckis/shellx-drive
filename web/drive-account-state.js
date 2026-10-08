// Exhaustive browser-side account separation. This module owns sensitive
// in-memory and DOM cleanup so every confirmed separation uses one contract.
(function attachDriveAccountState(root) {
  "use strict";

  function destroyOneTimeCredentialNodes(documentRef = document) {
    for (const node of documentRef.querySelectorAll(".drawer-agent-token, [data-agent-token]")) {
      node.replaceChildren();
      node.remove();
    }
  }

  function scrubSensitiveAccountDom({ documentRef = document, els, resetTotpSetupUi }) {
    resetTotpSetupUi();
    destroyOneTimeCredentialNodes(documentRef);
    for (const element of documentRef.querySelectorAll(
      "#admin-command-center .admin-live-list, #admin-command-center .admin-stat-grid",
    )) element.replaceChildren();
    for (const element of documentRef.querySelectorAll([
      "#account-security-output",
      "#self-sessions-list",
      "#self-security-events-list",
      "#admin-sessions-summary",
      "#admin-auth-summary",
      "#admin-auth-output",
      "#admin-auth-attempts",
      "#admin-security-events-list",
      "#admin-email-summary",
      "#admin-email-list",
    ].join(","))) element.replaceChildren();
    els.adminAuthUpdateForm?.reset();
    els.adminAuthUpdateEmail?.replaceChildren();
    if (els.adminSecurityEventsPolicy) els.adminSecurityEventsPolicy.textContent = "";
    for (const details of documentRef.querySelectorAll(
      ".totp-uri-details, #settings-two-factor-section > details",
    )) details.open = false;
    if (els.totpStatusChip) {
      els.totpStatusChip.textContent = "Not enabled";
      els.totpStatusChip.className = "status-chip";
    }
  }

  function scrubSensitiveAccountState(options) {
    const { state, documentRef = document } = options;
    options.stopAuthenticatedWork?.();
    options.closeAuthenticatedSurfaces?.();
    options.clearActorBrowserData?.(options.departingActor || "");
    options.resetAccountController?.();
    options.clearSession?.();
    options.clearCollaborationState?.();

    for (const key of [
      "workspaces", "files", "members", "workspaceInvitations", "bulkSelectedIds",
      "uploadSessions", "uploadQueue", "syncChanges", "syncConflicts", "managedShares",
      "workspaceShares", "managedDrops", "notifications", "authAccounts", "authAttempts",
      "securityEvents", "selfSessions", "selfSecurityEvents", "selectedRevisions",
      "selectedComments", "folderTemplates", "browseFiles", "currentBaseFiles",
      "lastRenderedFiles", "lastOrderedFiles",
    ]) state[key] = [];
    for (const key of [
      "currentWorkspace", "selectedFile", "folderTree", "currentFolderId", "groupsData",
      "adminSummary", "adminBackups", "backupPolicy", "adminSessions", "adminEmail",
      "registrationPolicy", "readinessStatus", "supportBundle", "currentAccount",
      "pendingTotpSecret", "workspaceUsage", "workspacePolicy", "syncHealth", "sandboxProfile",
      "sandboxPreview", "maintenanceStatus", "retentionPreview", "selectedBaseRevision",
      "selectedMetadata", "selectedPreview", "previewFile", "officeProviderStatus",
      "officeProvider", "selectedRevisionStorage", "mobileManifest", "uploadSession",
      "currentViewTitle", "browseScope", "browseNextCursor", "latestShareMeta",
      "draggingFileIds", "selectionAnchorIndex",
    ]) state[key] = null;
    for (const key of [
      "selectedUploadSessionId", "selectedAdminBackupId", "selectedAdminAuthEmail",
      "selectedShareId", "selectedDropId", "browserPreferenceWorkspaceId", "latestShareUrl",
      "latestDropUrl", "openFileMenuId",
    ]) state[key] = "";
    Object.assign(state, {
      activeView: "my-drive",
      activeAdminSection: "overview",
      activeFileFilter: "all",
      fileLayout: "list",
      browserPreferences: options.defaultBrowserPreferences?.() || {},
      browserPage: 0,
      browsePageCursors: [null],
      browsePageIndex: 0,
      browseLoading: false,
      browseRequestSequence: Number(state.browseRequestSequence || 0) + 1,
      manifestRequestSequence: Number(state.manifestRequestSequence || 0) + 1,
      searchRequestSequence: Number(state.searchRequestSequence || 0) + 1,
      hasCurrentBaseFiles: false,
      notificationUnreadCount: 0,
      shareDraftExpiry: 604800,
      adminVisible: false,
      authUncertain: false,
      offlineShell: false,
      confirmResolver: null,
      moveDialogOpen: false,
    });

    for (const form of documentRef.querySelectorAll("form")) form.reset();
    for (const field of documentRef.querySelectorAll(
      'input:not([type]), input[type="text"], input[type="search"], input[type="email"], input[type="password"], input[type="url"], input[type="tel"], input[type="file"], textarea',
    )) field.value = "";
    for (const output of documentRef.querySelectorAll(".operation-output")) {
      output.textContent = "";
      output.hidden = true;
    }
    options.scrubSensitiveDom?.();
    options.renderSignedOutState?.();
  }

  root.ShellXDriveAccountState = Object.freeze({
    scrubSensitiveAccountDom,
    scrubSensitiveAccountState,
  });
})(window);
