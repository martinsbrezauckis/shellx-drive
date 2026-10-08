const {
  compactDate,
  compactShareExpiry,
  displayFileSize,
  exactFileSizeLabel,
  fileExtension,
  formatBytes,
  formatDate,
  formatDurationSeconds,
  formatFileSize,
  formatShareExpiry,
} = window.ShellXDriveFormat;
const { fileTypeInfo } = window.ShellXDriveFileTypes;
const adminClarity = window.ShellXDriveAdminClarity;
const adminSecurityModule = window.ShellXDriveAdminSecurity;

const state = {
  token: "",
  actor: sessionStorage.getItem("shellx-drive-actor") || "",
  currentSessionId: sessionStorage.getItem("shellx-drive-session-id") || "",
  workspaces: [],
  currentWorkspace: null,
  files: [],
  trashFiles: [],
  selectedFile: null,
  members: [],
  workspaceInvitations: [],
  folderTree: null,
  currentFolderId: null,
  // Ignore a file-preview double-click that belongs to the same physical
  // gesture which just replaced a folder row with its children.
  suppressPreviewUntil: 0,
  bulkSelectedIds: [],
  selectionAnchorIndex: null,
  draggingFileIds: null,
  uploadSessions: [],
  selectedUploadSessionId: "",
  uploadQueue: [],
  uploadStatusHideTimer: null,
  syncChanges: [],
  syncConflicts: [],
  managedShares: [],
  // Workspace-wide share metadata drives persistent row badges. It contains no
  // password hashes or capability secrets beyond the share ids already needed
  // to construct/copy links for authorized workspace writers.
  workspaceShares: [],
  managedDrops: [],
  notifications: [],
  notificationUnreadCount: 0,
  selectedShareId: "",
  selectedDropId: "",
  groupsData: null,
  adminSummary: null,
  adminBackups: null,
  selectedAdminBackupId: "",
  backupPolicy: null,
  adminSessions: null,
  adminEmail: null,
  registrationPolicy: null,
  readinessStatus: null,
  supportBundle: null,
  authBootstrapRequired: null,
  authUncertain: false,
  // A cold offline reload cannot prove the HttpOnly session is still valid.
  // It may expose only the navigation shell and reconnect action, never files
  // or authenticated controls, until the server confirms the session again.
  offlineShell: false,
  currentAccount: null,
  authAccounts: null,
  authAttempts: null,
  securityEvents: null,
  selfSessions: null,
  selfSecurityEvents: null,
  selectedAdminAuthEmail: "",
  pendingTotpSecret: null,
  workspaceUsage: null,
  workspacePolicy: null,
  syncHealth: null,
  sandboxProfile: null,
  sandboxPreview: null,
  maintenanceStatus: null,
  retentionPreview: null,
  selectedBaseRevision: null,
  selectedMetadata: null,
  selectedPreview: null,
  previewFile: null,
  officeProviderStatus: null,
  // Availability of an online-editing provider (`{ configured, name }` or null),
  // fetched once from GET /office/status after sign-in. Null = no provider.
  officeProvider: null,
  selectedRevisions: [],
  selectedRevisionStorage: null,
  selectedComments: [],
  folderTemplates: [],
  mobileManifest: null,
  uploadSession: null,
  currentViewTitle: null,
  activeView: "my-drive",
  activeAdminSection: "overview",
  activeFileFilter: "all",
  fileLayout: "list",
  browserPreferences: window.ShellXDriveBrowser?.defaults() || {},
  browserPreferenceWorkspaceId: "",
  browserPage: 0,
  // Account-wide Files/Mine/Shared with me/Recent pages are explicitly
  // keyset-paginated by the server. Keep their materialized rows separate from
  // the selected workspace manifest so a cross-workspace listing can never be
  // mistaken for a mutable folder tree.
  browseScope: null,
  browseFiles: [],
  browseNextCursor: null,
  browsePageCursors: [null],
  browsePageIndex: 0,
  browseLoading: false,
  browseRequestSequence: 0,
  browseModifiedSince: null,
  manifestRequestSequence: 0,
  searchRequestSequence: 0,
  currentBaseFiles: [],
  hasCurrentBaseFiles: false,
  lastRenderedFiles: [],
  lastOrderedFiles: [],
  toastTimer: null,
  latestShareUrl: "",
  latestShareMeta: null,
  shareDraftExpiry: 604800,
  latestDropUrl: "",
  theme: localStorage.getItem("shellx-drive-theme") || "system",
  adminVisible: false,
  openFileMenuId: "",
  confirmResolver: null,
  moveDialogOpen: false,
};

let browserUploads = null;
let collaboration = null;
let humanSharing = null;
let humanSharingBrowser = null;
let driveDebug = null;
let settingsController = null;
let accountController = null;
let mobileSync = null;
let workspacePolicyController = null;
let fileMoves = null;

const MOBILE_MANIFEST_STORAGE_PREFIX = "shellx-drive-mobile-manifest:";
const LAST_WORKSPACE_STORAGE_PREFIX = "shellx-drive:last-workspace:";

const els = {
  serverState: document.getElementById("server-state"),
  tokenForm: document.getElementById("token-form"),
  tokenInput: document.getElementById("token-input"),
  actorInput: document.getElementById("actor-input"),
  authCardTitle: document.getElementById("auth-card-title"),
  authStatus: document.getElementById("auth-status"),
  loginForm: document.getElementById("login-form"),
  loginEmail: document.getElementById("login-email"),
  loginPassword: document.getElementById("login-password"),
  loginSecondFactor: document.getElementById("login-second-factor"),
  forgotPasswordButton: document.getElementById("forgot-password-button"),
  passwordResetRequestForm: document.getElementById("password-reset-request-form"),
  passwordResetEmail: document.getElementById("password-reset-email"),
  passwordResetStatus: document.getElementById("password-reset-status"),
  bootstrapForm: document.getElementById("bootstrap-form"),
  bootstrapOperatorToken: document.getElementById("bootstrap-operator-token"),
  bootstrapEmail: document.getElementById("bootstrap-email"),
  bootstrapPassword: document.getElementById("bootstrap-password"),
  bootstrapPasswordConfirm: document.getElementById("bootstrap-password-confirm"),
  bootstrapWorkspaceName: document.getElementById("bootstrap-workspace-name"),
  accountMenuButton: document.getElementById("account-menu-button"),
  accountMenuInitial: document.getElementById("account-menu-initial"),
  accountMenuLabel: document.getElementById("account-menu-label"),
  notificationsButton: document.getElementById("notifications-button"),
  notificationCount: document.getElementById("notification-count"),
  notificationPanel: document.getElementById("notification-panel"),
  notificationList: document.getElementById("notification-list"),
  markAllNotificationsReadButton: document.getElementById("mark-all-notifications-read-button"),
  accountPanel: document.getElementById("account-panel"),
  accountPanelEyebrow: document.getElementById("account-panel-eyebrow"),
  accountPanelEmail: document.getElementById("account-panel-email"),
  accountPanelRole: document.getElementById("account-panel-role"),
  accountSettingsDetail: document.getElementById("account-settings-detail"),
  logoutButton: document.getElementById("logout-button"),
  refreshSelfSessionsButton: document.getElementById("refresh-self-sessions-button"),
  selfSessionsList: document.getElementById("self-sessions-list"),
  refreshSelfSecurityEventsButton: document.getElementById("refresh-self-security-events-button"),
  selfSecurityEventsList: document.getElementById("self-security-events-list"),
  refreshButton: document.getElementById("refresh-button"),
  workspaceList: document.getElementById("workspace-list"),
  workspaceForm: document.getElementById("workspace-form"),
  workspaceName: document.getElementById("workspace-name"),
  workspaceOwner: document.getElementById("workspace-owner"),
  workspaceTitle: document.getElementById("workspace-title"),
  workspaceSubtitle: document.getElementById("workspace-subtitle"),
  workspaceLifecyclePanel: document.getElementById("workspace-lifecycle-panel"),
  workspaceRenameForm: document.getElementById("workspace-rename-form"),
  workspaceRenameName: document.getElementById("workspace-rename-name"),
  workspaceArchiveButton: document.getElementById("workspace-archive-button"),
  workspaceUnarchiveButton: document.getElementById("workspace-unarchive-button"),
  workspaceTransferForm: document.getElementById("workspace-transfer-form"),
  workspaceTransferEmail: document.getElementById("workspace-transfer-email"),
  workspaceLeaveButton: document.getElementById("workspace-leave-button"),
  workspaceLifecycleOutput: document.getElementById("workspace-lifecycle-output"),
  currentViewLabel: document.getElementById("current-view-label"),
  viewMyDriveButton: document.getElementById("view-my-drive-button"),
  mineButton: document.getElementById("mine-button"),
  offlineButton: document.getElementById("offline-button"),
  trashViewButton: document.getElementById("trash-view-button"),
  searchInput: document.getElementById("search-input"),
  recentButton: document.getElementById("recent-button"),
  sharedButton: document.getElementById("shared-button"),
  sharedByMeButton: document.getElementById("shared-by-me-button"),
  starredButton: document.getElementById("starred-button"),
  uploadFocusButton: document.getElementById("upload-focus-button"),
  newMenuButton: document.getElementById("new-menu-button"),
  listViewButton: document.getElementById("list-view-button"),
  gridViewButton: document.getElementById("grid-view-button"),
  quickCreateTitle: document.getElementById("quick-create-title"),
  fileForm: document.getElementById("file-form"),
  fileName: document.getElementById("file-name"),
  fileContent: document.getElementById("file-content"),
  createFolderForm: document.getElementById("create-folder-form"),
  createFolderName: document.getElementById("create-folder-name"),
  createFolderButton: document.getElementById("create-folder-button"),
  uploadDropZone: document.getElementById("upload-drop-zone"),
  chooseFilesButton: document.getElementById("choose-files-button"),
  chooseFolderButton: document.getElementById("choose-folder-button"),
  cameraUploadButton: document.getElementById("camera-upload-button"),
  uploadFilePicker: document.getElementById("upload-file-picker"),
  uploadFolderPicker: document.getElementById("upload-folder-picker"),
  cameraUploadInput: document.getElementById("camera-upload-input"),
  uploadQueue: document.getElementById("upload-queue"),
  uploadProgressSummary: document.getElementById("upload-progress-summary"),
  uploadAggregates: Array.from(document.querySelectorAll("[data-upload-aggregate]")),
  uploadStatusPanel: document.getElementById("upload-status-panel"),
  uploadStatusTitle: document.getElementById("upload-status-title"),
  uploadStatusList: document.getElementById("upload-status-list"),
  uploadStatusDismiss: document.getElementById("upload-status-dismiss"),
  uploadStatusClearCompleted: document.getElementById("upload-status-clear-completed"),
  uploadDuplicatePolicy: document.getElementById("upload-duplicate-policy"),
  uploadResumePicker: document.getElementById("upload-resume-picker"),
  resumableUploadForm: document.getElementById("resumable-upload-form"),
  uploadSessionName: document.getElementById("upload-session-name"),
  uploadSessionTotalSize: document.getElementById("upload-session-total-size"),
  uploadChunkContent: document.getElementById("upload-chunk-content"),
  appendUploadButton: document.getElementById("append-upload-button"),
  finishUploadButton: document.getElementById("finish-upload-button"),
  refreshUploadSessionsButton: document.getElementById("refresh-upload-sessions-button"),
  cancelUploadSessionButton: document.getElementById("cancel-upload-session-button"),
  cleanupUploadsButton: document.getElementById("cleanup-uploads-button"),
  uploadSessionList: document.getElementById("upload-session-list"),
  uploadStatus: document.getElementById("upload-status"),
  fileRows: document.getElementById("file-rows"),
  fileCount: document.getElementById("file-count"),
  fileSortKey: document.getElementById("file-sort-key"),
  fileSortDirection: document.getElementById("file-sort-direction"),
  foldersFirst: document.getElementById("folders-first"),
  browserFilterToggle: document.getElementById("browser-filter-toggle"),
  browserFilterCount: document.getElementById("browser-filter-count"),
  browserFilterPanel: document.getElementById("browser-filter-panel"),
  browserFilterScopeNote: document.getElementById("browser-filter-scope-note"),
  browserTypeFilter: document.getElementById("browser-type-filter"),
  browserOwnerFilter: document.getElementById("browser-owner-filter"),
  browserModifiedFilter: document.getElementById("browser-modified-filter"),
  browserLocationFilter: document.getElementById("browser-location-filter"),
  browserStateFilter: document.getElementById("browser-state-filter"),
  browserFilterClear: document.getElementById("browser-filter-clear"),
  filePagination: document.getElementById("file-pagination"),
  filePagePrevious: document.getElementById("file-page-previous"),
  filePagePosition: document.getElementById("file-page-position"),
  filePageNext: document.getElementById("file-page-next"),
  folderBreadcrumb: document.getElementById("folder-breadcrumb"),
  selectVisibleFiles: document.getElementById("select-visible-files"),
  bulkActionToolbar: document.getElementById("bulk-action-toolbar"),
  bulkSelectionCount: document.getElementById("bulk-selection-count"),
  bulkDownloadButton: document.getElementById("bulk-download-button"),
  bulkMoveButton: document.getElementById("bulk-move-button"),
  bulkTrashButton: document.getElementById("bulk-trash-button"),
  bulkRestoreButton: document.getElementById("bulk-restore-button"),
  bulkStarButton: document.getElementById("bulk-star-button"),
  bulkUnstarButton: document.getElementById("bulk-unstar-button"),
  storageSummaryName: document.getElementById("storage-summary-name"),
  storageSummaryMode: document.getElementById("storage-summary-mode"),
  storageSummaryUsed: document.getElementById("storage-summary-used"),
  storageUsage: document.getElementById("storage-usage"),
  storageUsageTrack: document.getElementById("storage-usage-track"),
  storageUsageFill: document.getElementById("storage-usage-fill"),
  storageUsageLabel: document.getElementById("storage-usage-label"),
  selectedTitle: document.getElementById("selected-title"),
  selectedMeta: document.getElementById("selected-meta"),
  selectionPreview: document.getElementById("selection-preview"),
  activityList: document.getElementById("activity-list"),
  versionsList: document.getElementById("versions-list"),
  inspectorActivitySection: document.getElementById("inspector-activity-section"),
  inspectorVersionsSection: document.getElementById("inspector-versions-section"),
  fileDetailName: document.getElementById("file-detail-name"),
  fileParentSelect: document.getElementById("file-parent-select"),
  fileLabels: document.getElementById("file-labels"),
  fileMetadata: document.getElementById("file-metadata"),
  saveFileDetailsButton: document.getElementById("save-file-details-button"),
  copyFileButton: document.getElementById("copy-file-button"),
  selectedContent: document.getElementById("selected-content"),
  loadContentButton: document.getElementById("load-content-button"),
  saveContentButton: document.getElementById("save-content-button"),
  loadRevisionsButton: document.getElementById("load-revisions-button"),
  revisionSelect: document.getElementById("revision-select"),
  restoreRevisionButton: document.getElementById("restore-revision-button"),
  revisionPinButton: document.getElementById("revision-pin-button"),
  revisionUnpinButton: document.getElementById("revision-unpin-button"),
  revisionDownloadButton: document.getElementById("revision-download-button"),
  revisionDeleteButton: document.getElementById("revision-delete-button"),
  revisionPruneButton: document.getElementById("revision-prune-button"),
  revisionsOutput: document.getElementById("revisions-output"),
  commentList: document.getElementById("comment-list"),
  commentForm: document.getElementById("comment-form"),
  commentBody: document.getElementById("comment-body"),
  downloadButton: document.getElementById("download-button"),
  downloadFolderZipButton: document.getElementById("download-folder-zip-button"),
  starButton: document.getElementById("star-button"),
  closeSelectionButton: document.getElementById("close-selection-button"),
  trashButton: document.getElementById("trash-button"),
  restoreButton: document.getElementById("restore-button"),
  shareForm: document.getElementById("share-form"),
  sharePassword: document.getElementById("share-password"),
  shareAllowDownload: document.getElementById("share-allow-download"),
  shareRecipientNote: document.getElementById("share-recipient-note"),
  shareMaxUses: document.getElementById("share-max-uses"),
  shareExpiry: document.getElementById("share-expiry"),
  shareSummary: document.getElementById("share-summary"),
  shareDrawer: document.getElementById("share-drawer"),
  openShareDrawerButton: document.getElementById("open-share-drawer-button"),
  openEditorButton: document.getElementById("open-editor-button"),
  officeProviderStatus: document.getElementById("office-provider-status"),
  closeShareDrawerButton: document.getElementById("close-share-drawer-button"),
  bottomShareButton: document.getElementById("bottom-share-button"),
  bottomDownloadButton: document.getElementById("bottom-download-button"),
  bottomOpenButton: document.getElementById("bottom-open-button"),
  dropForm: document.getElementById("drop-form"),
  dropName: document.getElementById("drop-name"),
  dropPassword: document.getElementById("drop-password"),
  copyDropLinkButton: document.getElementById("copy-drop-link-button"),
  shareOutput: document.getElementById("share-output"),
  shareManagementRefreshButton: document.getElementById("share-management-refresh-button"),
  shareManagementList: document.getElementById("share-management-list"),
  dropManagementRefreshButton: document.getElementById("drop-management-refresh-button"),
  dropManagementList: document.getElementById("drop-management-list"),
  dropUpdateForm: document.getElementById("drop-update-form"),
  dropUpdateSelect: document.getElementById("drop-update-select"),
  dropUpdateName: document.getElementById("drop-update-name"),
  dropUpdatePassword: document.getElementById("drop-update-password"),
  dropUpdateExpiry: document.getElementById("drop-update-expiry"),
  dropUpdateButton: document.getElementById("drop-update-button"),
  dropOpenInboxButton: document.getElementById("drop-open-inbox-button"),
  dropRevokeButton: document.getElementById("drop-revoke-button"),
  mobileOfflineButton: document.getElementById("mobile-offline-button"),
  mobileOnlineButton: document.getElementById("mobile-online-button"),
  mobileManifestButton: document.getElementById("mobile-manifest-button"),
  mobileOutput: document.getElementById("mobile-output"),
  mobileOfflineStatus: document.getElementById("mobile-offline-status"),
  offlineShellNotice: document.getElementById("offline-shell-notice"),
  offlineRetryButton: document.getElementById("offline-retry-button"),
  memberList: document.getElementById("member-list"),
  invitationList: document.getElementById("invitation-list"),
  workspaceInvitationForm: document.getElementById("workspace-invitation-form"),
  workspaceInvitationLink: document.getElementById("workspace-invitation-link"),
  workspaceInvitationEmail: document.getElementById("workspace-invitation-email"),
  workspaceInvitationRole: document.getElementById("workspace-invitation-role"),
  workspaceInvitationExpiry: document.getElementById("workspace-invitation-expiry"),
  workspaceInvitationButton: document.getElementById("workspace-invitation-button"),
  clearFileLabelsButton: document.getElementById("clear-file-labels-button"),
  memberForm: document.getElementById("member-form"),
  memberEmail: document.getElementById("member-email"),
  memberRole: document.getElementById("member-role"),
  memberRemoveForm: document.getElementById("member-remove-form"),
  memberRemoveEmail: document.getElementById("member-remove-email"),
  templateList: document.getElementById("template-list"),
  templateForm: document.getElementById("template-form"),
  templateName: document.getElementById("template-name"),
  templateDescription: document.getElementById("template-description"),
  templateItems: document.getElementById("template-items"),
  templateSelect: document.getElementById("template-select"),
  templateRootName: document.getElementById("template-root-name"),
  applyTemplateButton: document.getElementById("apply-template-button"),
  templateOutput: document.getElementById("template-output"),
  adminRefreshButton: document.getElementById("admin-refresh-button"),
  adminStatusServer: document.getElementById("admin-status-server"),
  adminReadinessStatus: document.getElementById("admin-readiness-status"),
  adminStatusSandbox: document.getElementById("admin-status-sandbox"),
  adminStatusMaintenance: document.getElementById("admin-status-maintenance"),
  adminMetrics: document.getElementById("admin-metrics"),
  adminOutput: document.getElementById("admin-output"),
  adminSectionSelect: document.getElementById("admin-section-select"),
  adminCanonicalRefreshButton: document.getElementById("admin-canonical-refresh-button"),
  adminCanonicalInventory: document.getElementById("admin-canonical-inventory"),
  adminCanonicalSearch: document.getElementById("admin-canonical-search"),
  adminActivitySearch: document.getElementById("admin-activity-search"),
  adminActivityFilter: document.getElementById("admin-activity-filter"),
  adminTeamsSummary: document.getElementById("admin-teams-summary"),
  adminStorageSummary: document.getElementById("admin-storage-summary"),
  adminSharingSummary: document.getElementById("admin-sharing-summary"),
  storagePolicyForm: document.getElementById("storage-policy-form"),
  policyQuotaBytes: document.getElementById("policy-quota-bytes"),
  policyTrashRetentionDays: document.getElementById("policy-trash-retention-days"),
  policyRevisionRetentionDays: document.getElementById("policy-revision-retention-days"),
  storagePolicySaveButton: document.getElementById("storage-policy-save-button"),
  storagePolicyRefreshButton: document.getElementById("storage-policy-refresh-button"),
  storagePolicyOutput: document.getElementById("storage-policy-output"),
  sharingPolicyForm: document.getElementById("sharing-policy-form"),
  policyPublicLinksEnabled: document.getElementById("policy-public-links-enabled"),
  policyLinkPasswordRequired: document.getElementById("policy-link-password-required"),
  policyAllowNeverExpire: document.getElementById("policy-allow-never-expire"),
  policyMaxLinkTtlSeconds: document.getElementById("policy-max-link-ttl-seconds"),
  policyDropPasswordRequired: document.getElementById("policy-drop-password-required"),
  policyMaxDropTtlSeconds: document.getElementById("policy-max-drop-ttl-seconds"),
  sharingPolicySaveButton: document.getElementById("sharing-policy-save-button"),
  sharingPolicyOutput: document.getElementById("sharing-policy-output"),
  adminBackupCreateButton: document.getElementById("admin-backup-create-button"),
  adminBackupsRefreshButton: document.getElementById("admin-backups-refresh-button"),
  adminBackupPolicyForm: document.getElementById("admin-backup-policy-form"),
  adminBackupPolicyEnabled: document.getElementById("admin-backup-policy-enabled"),
  adminBackupPolicySchedule: document.getElementById("admin-backup-policy-schedule"),
  adminBackupPolicyRetention: document.getElementById("admin-backup-policy-retention"),
  adminBackupPolicySaveButton: document.getElementById("admin-backup-policy-save-button"),
  adminBackupPolicyRefreshButton: document.getElementById("admin-backup-policy-refresh-button"),
  adminBackupsList: document.getElementById("admin-backups-list"),
  adminBackupsPrevious: document.getElementById("admin-backups-previous"),
  adminBackupsNext: document.getElementById("admin-backups-next"),
  adminBackupsPage: document.getElementById("admin-backups-page"),
  adminBackupSelection: document.getElementById("admin-backup-selection"),
  adminBackupValidateButton: document.getElementById("admin-backup-validate-button"),
  adminBackupDownloadButton: document.getElementById("admin-backup-download-button"),
  adminBackupRestoreButton: document.getElementById("admin-backup-restore-button"),
  adminBackupDeleteButton: document.getElementById("admin-backup-delete-button"),
  adminBackupsSummary: document.getElementById("admin-backups-summary"),
  adminSessionsSummary: document.getElementById("admin-sessions-summary"),
  adminSessionsSearch: document.getElementById("admin-sessions-search"),
  adminSecurityEventsList: document.getElementById("admin-security-events-list"),
  adminSecurityEventsPolicy: document.getElementById("admin-security-events-policy"),
  adminSecurityEventsSearch: document.getElementById("admin-security-events-search"),
  adminSecurityEventsCategory: document.getElementById("admin-security-events-category"),
  adminSecurityEventsOutcome: document.getElementById("admin-security-events-outcome"),
  adminSecurityEventsRefresh: document.getElementById("admin-security-events-refresh"),
  adminSecurityEventsMore: document.getElementById("admin-security-events-more"),
  adminEmailSummary: document.getElementById("admin-email-summary"),
  adminEmailList: document.getElementById("admin-email-list"),
  adminEmailRefreshButton: document.getElementById("admin-email-refresh-button"),
  adminEmailRunButton: document.getElementById("admin-email-run-button"),
  adminAuthSummary: document.getElementById("admin-auth-summary"),
  adminAccountsSearch: document.getElementById("admin-accounts-search"),
  adminAccountsFilter: document.getElementById("admin-accounts-filter"),
  authAccountForm: document.getElementById("auth-account-form"),
  authUserEmail: document.getElementById("auth-user-email"),
  authUserPassword: document.getElementById("auth-user-password"),
  authUserAdmin: document.getElementById("auth-user-admin"),
  adminAuthUpdateForm: document.getElementById("admin-auth-update-form"),
  adminAuthUpdateEmail: document.getElementById("admin-auth-update-email"),
  adminAuthResetPassword: document.getElementById("admin-auth-reset-password"),
  adminAuthDisabled: document.getElementById("admin-auth-disabled"),
  adminAuthAdmin: document.getElementById("admin-auth-admin"),
  adminAuthReset2fa: document.getElementById("admin-auth-reset-2fa"),
  adminAuthUpdateButton: document.getElementById("admin-auth-update-button"),
  adminAuthRevokeSessionsButton: document.getElementById("admin-auth-revoke-sessions-button"),
  adminAuthOutput: document.getElementById("admin-auth-output"),
  adminAuthAttempts: document.getElementById("admin-auth-attempts"),
  adminAuthAttemptsSearch: document.getElementById("admin-auth-attempts-search"),
  adminAuthAttemptsFilter: document.getElementById("admin-auth-attempts-filter"),
  adminRegistrationSummary: document.getElementById("admin-registration-summary"),
  totpSetupPassword: document.getElementById("totp-setup-password"),
  totpSetupCurrentFactorField: document.getElementById("totp-setup-current-factor-field"),
  totpSetupCurrentFactor: document.getElementById("totp-setup-current-factor"),
  totpSetupButton: document.getElementById("totp-setup-button"),
  totpEnableCode: document.getElementById("totp-enable-code"),
  totpEnableButton: document.getElementById("totp-enable-button"),
  totpDisableCode: document.getElementById("totp-disable-code"),
  totpDisableButton: document.getElementById("totp-disable-button"),
  recoveryRotateCode: document.getElementById("recovery-rotate-code"),
  recoveryRotateButton: document.getElementById("recovery-rotate-button"),
  accountSecurityOutput: document.getElementById("account-security-output"),
  // Settings drawer (account-security home + 2FA QR flow)
  accountSettingsButton: document.getElementById("account-settings-button"),
  accountWorkspaceSettingsButton: document.getElementById("account-workspace-settings-button"),
  settingsDrawer: document.getElementById("settings-drawer"),
  settingsClose: document.getElementById("settings-close"),
  settingsAccountEmail: document.getElementById("settings-account-email"),
  settingsCredentialNotice: document.getElementById("settings-credential-notice"),
  settingsCredentialTitle: document.getElementById("settings-credential-title"),
  settingsCredentialCopy: document.getElementById("settings-credential-copy"),
  settingsTwoFactorSection: document.getElementById("settings-two-factor-section"),
  settingsPasswordSection: document.getElementById("settings-password-section"),
  settingsSessionsSection: document.getElementById("settings-sessions-section"),
  totpStatusChip: document.getElementById("totp-status-chip"),
  totpSetupResult: document.getElementById("totp-setup-result"),
  totpQr: document.getElementById("totp-qr"),
  totpSecretDisplay: document.getElementById("totp-secret-display"),
  totpOtpauthUri: document.getElementById("totp-otpauth-uri"),
  adminMaintenanceSummary: document.getElementById("admin-maintenance-summary"),
  adminReadinessSummary: document.getElementById("admin-readiness-summary"),
  adminReadinessRefreshButton: document.getElementById("admin-readiness-refresh-button"),
  adminSupportBundleButton: document.getElementById("admin-support-bundle-button"),
  groupForm: document.getElementById("group-form"),
  groupName: document.getElementById("group-name"),
  groupMemberForm: document.getElementById("group-member-form"),
  groupMemberSelect: document.getElementById("group-member-select"),
  groupMemberEmail: document.getElementById("group-member-email"),
  groupMemberAddButton: document.getElementById("group-member-add-button"),
  groupGrantForm: document.getElementById("group-grant-form"),
  groupGrantSelect: document.getElementById("group-grant-select"),
  groupGrantRole: document.getElementById("group-grant-role"),
  groupGrantButton: document.getElementById("group-grant-button"),
  groupRevokeButton: document.getElementById("group-revoke-button"),
  groupsOutput: document.getElementById("groups-output"),
  sandboxForm: document.getElementById("sandbox-form"),
  sandboxMode: document.getElementById("sandbox-mode"),
  sandboxBind: document.getElementById("sandbox-bind"),
  sandboxDataDir: document.getElementById("sandbox-data-dir"),
  sandboxWritePaths: document.getElementById("sandbox-write-paths"),
  sandboxSaveButton: document.getElementById("sandbox-save-button"),
  sandboxPreviewButton: document.getElementById("sandbox-preview-button"),
  sandboxApplyIntentButton: document.getElementById("sandbox-apply-intent-button"),
  sandboxOutput: document.getElementById("sandbox-output"),
  retentionPreviewButton: document.getElementById("retention-preview-button"),
  retentionApplyButton: document.getElementById("retention-apply-button"),
  retentionOutput: document.getElementById("retention-output"),
  maintenanceRefreshButton: document.getElementById("maintenance-refresh-button"),
  maintenanceOutput: document.getElementById("maintenance-output"),
  syncRefreshButton: document.getElementById("sync-refresh-button"),
  syncCursorInput: document.getElementById("sync-cursor-input"),
  syncChangesButton: document.getElementById("sync-changes-button"),
  syncConflictsButton: document.getElementById("sync-conflicts-button"),
  syncMetrics: document.getElementById("sync-metrics"),
  syncChangeList: document.getElementById("sync-change-list"),
  syncOutput: document.getElementById("sync-output"),
  importBundle: document.getElementById("import-bundle"),
  importPreviewButton: document.getElementById("import-preview-button"),
  importBundleButton: document.getElementById("import-bundle-button"),
  exportBundleButton: document.getElementById("export-bundle-button"),
  importExportOutput: document.getElementById("import-export-output"),
  adminAuthAttemptsButton: document.getElementById("admin-auth-attempts-button"),
  debugOutput: document.getElementById("debug-output"),
  advancedWorkbench: document.getElementById("advanced-workbench"),
  advancedCloseButton: document.getElementById("advanced-close-button"),
  mobileFileSheet: document.getElementById("mobile-file-sheet"),
  mobileSheetSummary: document.getElementById("mobile-sheet-summary"),
  statusToast: document.getElementById("status-toast"),
  // ---- Redesign additions (menus, drawers, preview, gating, theme) ----
  newMenu: document.getElementById("new-menu"),
  newMenuFolder: document.getElementById("new-menu-folder"),
  newMenuFile: document.getElementById("new-menu-file"),
  newMenuUpload: document.getElementById("new-menu-upload"),
  newMenuUploadFolder: document.getElementById("new-menu-upload-folder"),
  uploadMenu: document.getElementById("upload-menu"),
  uploadMenuFiles: document.getElementById("upload-menu-files"),
  uploadMenuFolder: document.getElementById("upload-menu-folder"),
  uploadMenuDuplicatePolicy: document.getElementById("upload-menu-duplicate-policy"),
  quickCreateClose: document.getElementById("quick-create-close"),
  workspaceSettingsButton: document.getElementById("workspace-settings-button"),
  workspaceSettingsDrawer: document.getElementById("workspace-settings-drawer"),
  workspaceSettingsClose: document.getElementById("workspace-settings-close"),
  fileContextMenu: document.getElementById("file-context-menu"),
  themeToggleButton: document.getElementById("theme-toggle-button"),
  themeToggleState: document.getElementById("theme-toggle-state"),
  headerThemeToggle: document.getElementById("header-theme-toggle"),
  accountAdminButton: document.getElementById("account-admin-button"),
  accountAdvancedButton: document.getElementById("account-advanced-button"),
  previewModal: document.getElementById("preview-modal"),
  previewModalTitle: document.getElementById("preview-modal-title"),
  previewModalBody: document.getElementById("preview-modal-body"),
  previewModalClose: document.getElementById("preview-modal-close"),
  previewModalDownload: document.getElementById("preview-modal-download"),
  previewModalPrevious: document.getElementById("preview-modal-previous"),
  previewModalNext: document.getElementById("preview-modal-next"),
  previewModalPosition: document.getElementById("preview-modal-position"),
  previewOpenButton: document.getElementById("preview-open-button"),
  deletePermanentlyButton: document.getElementById("delete-permanently-button"),
  emptyTrashButton: document.getElementById("empty-trash-button"),
  emptyState: document.getElementById("empty-state"),
  confirmDialog: document.getElementById("confirm-dialog"),
  confirmDialogTitle: document.getElementById("confirm-dialog-title"),
  confirmDialogMessage: document.getElementById("confirm-dialog-message"),
  confirmDialogConfirm: document.getElementById("confirm-dialog-confirm"),
  confirmDialogCancel: document.getElementById("confirm-dialog-cancel"),
  moveDialog: document.getElementById("move-dialog"),
  moveDialogTitle: document.getElementById("move-dialog-title"),
  moveDialogList: document.getElementById("move-dialog-list"),
  moveCollisionPolicy: document.getElementById("move-collision-policy"),
  moveDialogCancel: document.getElementById("move-dialog-cancel"),
  moveDialogClose: document.getElementById("move-dialog-close"),
  createDialog: document.getElementById("create-dialog"),
  createDialogTitle: document.getElementById("create-dialog-title"),
  createDialogClose: document.getElementById("create-dialog-close"),
  advancedTabAdmin: document.getElementById("advanced-tab-admin"),
  updateBanner: document.getElementById("update-banner"),
  updateBannerDetail: document.getElementById("update-banner-detail"),
  updateBannerReload: document.getElementById("update-banner-reload"),
  updateBannerDismiss: document.getElementById("update-banner-dismiss"),
  aboutVersion: document.getElementById("about-version"),
  aboutBuild: document.getElementById("about-build"),
  aboutBuiltAt: document.getElementById("about-built-at"),
  aboutServerUpdatePanel: document.getElementById("about-server-update-panel"),
  aboutCheckUpdateButton: document.getElementById("about-check-update-button"),
  aboutUpdateStatus: document.getElementById("about-update-status"),
};

async function loadBoundedTextFile(file) {
  const preview = window.ShellXDrivePreview;
  const refusal = preview.textPreviewRefusal(file);
  if (refusal) throw new Error(refusal.copy);
  const range = preview.textPreviewRange(file);
  return authenticatedFetch(
    `/files/${encodeURIComponent(file.id)}/content`,
    { headers: { accept: "text/plain", ...(range ? { range } : {}) } },
    async (response) => {
      if (!response.ok) throw new Error(`Text preview request failed (${response.status}).`);
      return preview.readBoundedTextResponse(response, preview.MAX_TEXT_PREVIEW_BYTES);
    },
  );
}

const previewController = window.ShellXDrivePreview?.createController({
  modal: els.previewModal,
  title: els.previewModalTitle,
  body: els.previewModalBody,
  closeButton: els.previewModalClose,
  downloadButton: els.previewModalDownload,
  previousButton: els.previewModalPrevious,
  nextButton: els.previewModalNext,
  position: els.previewModalPosition,
  getSequence: () => state.lastOrderedFiles,
  fileInfo: fileTypeInfo,
  prepareContentUrl: async (file) => {
    const prepared = await api(`/files/${encodeURIComponent(file.id)}/preview`, {
      method: "POST",
    });
    if (!/^\/downloads\/files\/[a-f0-9]{64}$/.test(prepared.content_url || "")) {
      throw new Error("Drive returned an invalid preview capability.");
    }
    return prepared.content_url;
  },
  loadText: loadBoundedTextFile,
  onDownload: triggerDownload,
  onCurrentChange: (file) => {
    state.previewFile = file;
  },
  onStatus: (message) => showToast(message),
});

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  window.addEventListener("load", () => {
  navigator.serviceWorker.register("/sw.js?v=2026-10-05-cold-click1").catch(() => {});
  });
}

els.tokenInput.value = state.token;
els.actorInput.value = state.actor;
els.loginEmail.value = state.actor;

driveDebug = window.ShellXDriveDebug.createController({
  state,
  documentRef: document,
  output: els.debugOutput,
  api,
  pretty,
  getBuild: () => ({
    loaded: versionWatch?.loadedBuild || null,
    live: versionWatch?.info?.build || null,
  }),
});
driveDebug.bind();
window.ShellXDriveAdminPasswordReset.createController({ api, getSelectedEmail: () => els.adminAuthUpdateEmail?.value, showToast, onError: (error) => { els.adminAuthOutput.textContent = error.message; showToast(error.message); } });
window.ShellXDriveSettings.mountScopedSurfaces();
settingsController = window.ShellXDriveSettings.createController({
  api,
  getCurrentWorkspace: () => state.currentWorkspace,
  canManageWorkspace: canManageCurrentWorkspace,
  hasAdminTools,
  formatBytes: formatFileSize,
  formatDate: compactDate,
  showToast,
  reloadWorkspaces: loadWorkspaces,
});
workspacePolicyController = window.ShellXDriveWorkspacePolicy.createController({
  api,
  getCurrentWorkspace: () => state.currentWorkspace,
  getWorkspaceUsage: () => state.workspaceUsage,
  setWorkspaceData: ({ usage, policy }) => {
    state.workspaceUsage = usage;
    state.workspacePolicy = policy;
  },
  render: renderWorkspacePolicyUsage,
});
accountController = window.ShellXDriveAccount.createPasswordChangeController({
  api,
  getAccountEmail: currentAccountEmail,
  onPasswordChanged: (email) => {
    closeSettings();
    clearSensitiveAccountState(email);
    els.loginEmail.value = email;
    showToast("Password changed. Sign in again.");
  },
});
mobileSync = window.ShellXDriveMobileSync.createController({
  state,
  els,
  api,
  storagePrefix: MOBILE_MANIFEST_STORAGE_PREFIX,
  callbacks: {
    pretty,
    compactDate,
    renderFiles,
    renderSelectionSummary,
    showToast,
    canWrite: canWriteCurrentWorkspace,
    loadWorkspaceManifest: loadManifest,
    loadSyncHealth,
  },
});

fileMoves = window.ShellXDriveFileMoves.createController({
  state,
  els,
  api,
  callbacks: {
    canWrite: canWriteCurrentWorkspace,
    closeFileMenu,
    fileNodesById,
    loadManifest,
    showToast,
  },
});

collaboration = window.ShellXDriveCollaboration.createController({
  state,
  els,
  api,
  callbacks: {
    escapeHtml,
    compactDate,
    compactShareExpiry,
    formatShareExpiry,
    formatFileSize,
    pretty,
    showToast,
    canWrite: canWriteSelectedFile, canWriteWorkspace: canWriteCurrentWorkspace,
    canManage: canManageCurrentWorkspace,
    isAdmin: () => !state.actor || Boolean(state.currentAccount?.is_admin),
    renderSelectionSummary,
    setSelectionControlState,
    renderAdminLiveList,
    loadManifest,
    loadSyncHealth,
    loadNotifications,
    loadAdminSummary,
    loadWorkspacePolicyAndUsage,
    syncSharedItemBadge,
    confirmAction,
    authHeaders,
    selectFile,
    closeWorkspaceSettings,
    initialsForEmail,
    renderHumanSharingDrawer: () => humanSharing?.renderDrawer() || "",
    openHumanSharing: (file) => humanSharing?.loadGrants(file),
    canManageGuestLink: () => selectedActionCapability("manage_guest_links"),
    canManageAiAccess: () => selectedActionCapability("manage_ai_access"),
  },
});
humanSharingBrowser = window.ShellXDriveHumanSharingBrowser.createPresenter({
  state, callbacks: { clearBrowse: clearAccountBrowseState, resetSelection: resetSelectedFileState, renderFiles, renderSelection, setActiveView, selectFile, showToast },
});
humanSharing = window.ShellXDriveHumanSharing.createController({
  state, api,
  callbacks: {
    escapeHtml, showToast, confirmAction,
    clearSearchInput: () => { els.searchInput.value = ""; },
    renderDrawer: () => collaboration?.renderShareDrawer(),
    refreshAfterMutation: () => {
      if (state.selectedFile?.id) syncSharedItemBadge(state.selectedFile.id);
      renderSelection();
    },
    presentRoots: humanSharingBrowser.presentHumanShareRoots,
    presentDefaultFiles: humanSharingBrowser.presentDefaultFiles,
    presentScopedRoot: humanSharingBrowser.presentScopedRoot,
    presentRemovedRoot: humanSharingBrowser.presentRemovedRoot,
    presentRetryableRoot: humanSharingBrowser.presentRetryableRoot,
  },
});
humanSharing.bind({ shareDrawer: els.shareDrawer, adminInventory: els.adminCanonicalInventory, adminSearch: els.adminCanonicalSearch });
collaboration.bind();

function persistSession(token, actor, sessionId = "") {
  state.token = token || "";
  state.actor = actor || "";
  state.currentSessionId = sessionId || "";
  sessionStorage.removeItem("shellx-drive-token");
  if (state.actor) sessionStorage.setItem("shellx-drive-actor", state.actor);
  else sessionStorage.removeItem("shellx-drive-actor");
  if (state.currentSessionId) {
    sessionStorage.setItem("shellx-drive-session-id", state.currentSessionId);
  } else {
    sessionStorage.removeItem("shellx-drive-session-id");
  }
  els.tokenInput.value = state.token;
  els.actorInput.value = state.actor;
  els.loginEmail.value = state.actor;
  renderCurrentAccount();
  updateVersionWatchActivity({ poll: hasAdminTools() });
}

function setStatus(text) {
  els.serverState.textContent = text;
  const connected = text === "Connected";
  setAdminStatusChip(els.adminStatusServer, connected ? "Online" : text, connected ? "good" : "bad");
  document.body.dataset.driveConnected = text === "Connected" ? "true" : "false";
}

// Set a status-strip chip's value and colour-coded state dot. `state` is one of
// good | warn | bad (or null to clear), applied to the chip so the dot tints.
function setAdminStatusChip(el, text, state) {
  if (!el) return;
  el.textContent = text;
  const chip = el.closest(".admin-status-chip");
  if (!chip) return;
  if (state) chip.dataset.state = state;
  else chip.removeAttribute("data-state");
}

function setAuthStatus(text) {
  if (els.authStatus) els.authStatus.textContent = text;
}

function showSecondFactorChallenge(show) {
  if (!els.loginSecondFactor) return;
  els.loginSecondFactor.hidden = !show;
  if (show) {
    els.loginSecondFactor.focus();
  } else {
    els.loginSecondFactor.value = "";
  }
}

function togglePasswordReset(show) {
  if (!els.passwordResetRequestForm || !els.forgotPasswordButton) return;
  const next = show ?? els.passwordResetRequestForm.hidden;
  els.passwordResetRequestForm.hidden = !next;
  els.forgotPasswordButton.setAttribute("aria-expanded", next ? "true" : "false");
  if (next) {
    setPasswordResetStatus("");
    els.passwordResetEmail.value = els.loginEmail.value.trim();
    els.passwordResetEmail.focus();
  }
}

function setPasswordResetStatus(message) {
  if (!els.passwordResetStatus) return;
  els.passwordResetStatus.textContent = message;
  els.passwordResetStatus.hidden = !message;
}

function currentAccountEmail() {
  return state.currentAccount?.actor || state.currentAccount?.email || state.actor || "";
}

function hasAuthenticatedSession() {
  return Boolean(state.token || state.currentSessionId || state.currentAccount);
}

function authCapability(name, legacyFallback = false) {
  const value = state.currentAccount?.[name];
  return typeof value === "boolean" ? value : legacyFallback;
}

function isOperatorSession() {
  return state.currentAccount?.auth_mode === "operator";
}

function isAppTokenSession() {
  return state.currentAccount?.auth_mode === "app_token";
}

function hasAccountSecurity() {
  return authCapability("account_security_available", hasAuthenticatedSession());
}

function hasSessionManagement() {
  return authCapability("session_management_available", hasAuthenticatedSession());
}

function hasNotifications() {
  return authCapability("notifications_available", hasAuthenticatedSession());
}

function hasAdminTools() {
  return authCapability("admin_tools_available", Boolean(state.currentAccount?.is_admin));
}

function renderCurrentAccount() {
  const email = currentAccountEmail();
  const initial = email ? email.trim().charAt(0) || "?" : "?";
  const isAdmin = Boolean(state.currentAccount?.is_admin);
  const operatorMode = isOperatorSession();
  const appTokenMode = isAppTokenSession();
  const accountRecord = (state.authAccounts || []).find((account) => account.email === email);
  if (els.accountMenuInitial) {
    els.accountMenuInitial.textContent = initial;
  }
  if (els.accountMenuLabel) {
    els.accountMenuLabel.textContent = email || "Account";
  }
  if (els.accountPanelEmail) {
    els.accountPanelEmail.textContent = email || "No account";
  }
  if (els.accountPanelEyebrow) {
    els.accountPanelEyebrow.textContent = operatorMode
      ? "Operator"
      : appTokenMode
        ? "Application access"
        : "Signed in";
  }
  if (els.accountSettingsDetail) {
    els.accountSettingsDetail.textContent = hasAccountSecurity() || hasSessionManagement()
      ? "Security & sessions"
      : "About & updates";
  }
  if (els.settingsAccountEmail) {
    els.settingsAccountEmail.textContent = email || "—";
  }
  // Populate the hidden username inputs paired with the account password forms
  // (2FA setup, change password) so browser password managers associate the
  // stored credential with the right account instead of warning about a missing
  // username field.
  document.querySelectorAll(".js-account-username").forEach((input) => {
    input.value = email || "";
  });
  if (els.accountPanelRole) {
    if (operatorMode) {
      els.accountPanelRole.textContent = "Server operator credential";
    } else if (appTokenMode) {
      els.accountPanelRole.textContent = "Workspace-scoped app credential";
    } else {
      const role = isAdmin ? "Admin" : "User";
      const secondFactor = accountRecord
        ? accountRecord.totp_enabled
          ? "2FA enabled"
          : "2FA not enabled"
        : hasAuthenticatedSession()
          ? "Connected"
          : "Password session required";
      els.accountPanelRole.textContent = email ? `${role} · ${secondFactor}` : secondFactor;
    }
  }
  if (els.notificationsButton) {
    els.notificationsButton.hidden = !hasNotifications();
    if (els.notificationsButton.hidden && els.notificationPanel && !els.notificationPanel.hidden) {
      els.notificationPanel.hidden = true;
      els.notificationsButton.setAttribute("aria-expanded", "false");
    }
  }
  document.body.dataset.driveAuthMode = state.currentAccount?.auth_mode || "unknown";
  collaboration?.renderAgentSettingsPanel();
  applyAdminDebugVisibility();
}

function toggleAccountPanel(show) {
  if (!els.accountPanel || !els.accountMenuButton) return;
  const next = show ?? els.accountPanel.hidden;
  els.accountPanel.hidden = !next;
  els.accountMenuButton.setAttribute("aria-expanded", String(next));
  if (next && els.notificationPanel && !els.notificationPanel.hidden) {
    toggleNotificationPanel(false);
  }
  if (next) {
    // Sessions + 2FA now live in the Settings drawer; the panel just needs the
    // current account header refreshed.
    renderCurrentAccount();
  }
}

function toggleNotificationPanel(show) {
  if (!els.notificationPanel || !els.notificationsButton) return;
  if (!hasNotifications()) {
    els.notificationPanel.hidden = true;
    els.notificationsButton.setAttribute("aria-expanded", "false");
    return;
  }
  const next = show ?? els.notificationPanel.hidden;
  els.notificationPanel.hidden = !next;
  els.notificationsButton.setAttribute("aria-expanded", String(next));
  if (next && els.accountPanel && !els.accountPanel.hidden) {
    toggleAccountPanel(false);
  }
  if (next) {
    loadNotifications(false).catch((error) => {
      renderAdminLiveList(els.notificationList, [["Notifications", error.message]]);
    });
  }
}

async function loadNotifications(unreadOnly = false) {
  if (!hasAuthenticatedSession() || !hasNotifications()) {
    state.notifications = [];
    state.notificationUnreadCount = 0;
    renderNotifications();
    return [];
  }
  const data = await api(`/notifications?unread_only=${unreadOnly ? "true" : "false"}`);
  state.notifications = data.notifications || [];
  state.notificationUnreadCount = Number(data.unread_count || 0);
  renderNotifications();
  return state.notifications;
}

function renderNotifications() {
  if (els.notificationCount) {
    els.notificationCount.textContent = String(state.notificationUnreadCount || 0);
    els.notificationCount.hidden = !state.notificationUnreadCount;
  }
  if (!els.notificationList) return;
  const notifications = state.notifications || [];
  if (!hasAuthenticatedSession()) {
    renderAdminLiveList(els.notificationList, [["Notifications", "Sign in to see updates."]]);
    return;
  }
  if (!notifications.length) {
    renderAdminLiveList(els.notificationList, [["Notifications", "No notifications."]]);
    return;
  }
  els.notificationList.replaceChildren(
    ...notifications.map((notification) => {
      const row = document.createElement("article");
      row.className = `notification-row${notification.read_at ? "" : " unread"}`;
      row.innerHTML = `
        <div>
          <strong>${escapeHtml(notification.title || notification.kind)}</strong>
          <span>${escapeHtml(notification.body || notification.kind)}</span>
          <small>${escapeHtml(notification.kind)} · ${escapeHtml(compactDate(notification.created_at))}</small>
        </div>
        <button type="button" data-read-notification="${escapeHtml(notification.id)}" ${notification.read_at ? "disabled" : ""}>Read</button>
      `;
      return row;
    }),
  );
}

async function markNotificationRead(notificationId) {
  if (!notificationId) return;
  await api(`/notifications/${notificationId}/read`, { method: "POST" });
  await loadNotifications(false);
  showToast("Notification marked read.");
}

async function markAllNotificationsRead() {
  await api("/notifications/read-all", { method: "POST" });
  await loadNotifications(false);
  showToast("Notifications marked read.");
}

function closeAuthenticatedSurfaces() {
  toggleAccountPanel(false);
  toggleNotificationPanel(false);
  closeSettings(); closeWorkspaceSettings(); closeShareDrawer(); closeAdvanced();
  closePreviewModal(); closeMoveDialog(); closeCreateDialog();
  closeNewMenu(); closeUploadMenu(); closeFileMenu();
  hideQuickCreate();
  if (state.confirmResolver) {
    state.confirmResolver(false);
  } else if (els.confirmDialog) {
    els.confirmDialog.hidden = true;
  }
}

function scrubSensitiveAccountDom() {
  window.ShellXDriveAccountState.scrubSensitiveAccountDom({
    documentRef: document,
    els,
    resetTotpSetupUi,
  });
}

function clearSensitiveAccountState(departingActor = currentAccountEmail(), options = {}) {
  if (options.advance !== false) authLifecycle.separate({ broadcast: options.broadcast !== false });
  workspacePolicyController?.invalidate();
  window.ShellXDriveAccountState.scrubSensitiveAccountState({
    state,
    departingActor,
    stopAuthenticatedWork: () => {
      stopVersionWatch();
      gridSnippetCache.clear();
      gridSnippetGeneration += 1;
      window.clearTimeout(state.uploadStatusHideTimer); state.uploadStatusHideTimer = null;
      window.clearTimeout(state.toastTimer); state.toastTimer = null;
      if (els.statusToast) els.statusToast.textContent = "";
      els.statusToast?.classList.remove("visible");
      browserUploads?.deactivate();
    },
    closeAuthenticatedSurfaces,
    clearActorBrowserData: (actor) => {
      browserUploads?.clearPersistedActor(actor);
      window.ShellXDriveBrowser.clearActorPreferences(localStorage, actor);
      discardRememberedWorkspace(actor);
      window.ShellXDriveAccount.clearLocalStoragePrefix(MOBILE_MANIFEST_STORAGE_PREFIX);
    },
    resetAccountController: () => accountController?.reset(true),
    clearSession: () => persistSession("", "", ""),
    clearCollaborationState: () => collaboration?.clearAgentState(),
    scrubSensitiveDom: scrubSensitiveAccountDom,
    defaultBrowserPreferences: window.ShellXDriveBrowser.defaults,
    renderSignedOutState: () => {
      setStatus("Disconnected");
      setAuthStatus(state.authBootstrapRequired ? "A server-generated setup token is required." : "Signed out");
      renderCurrentAccount(); renderSelfSessions(); renderWorkspaces(); renderFiles();
      renderMembers(); renderWorkspaceInvitations();
      renderManagedShares(); renderManagedDrops(); renderNotifications();
      renderUploadSessions(); renderSyncChangeList("changes", []); renderSelection(); applyUiState();
    },
  });
}

const sessionController = window.ShellXDriveSessions.createController({
  adminClarity,
  api,
  clearSensitiveAccountState,
  els,
  escapeHtml,
  formatDate,
  hasAuthenticatedSession,
  hasSessionManagement,
  loadAdminSummary,
  relativeTime,
  renderEmpty: renderAdminEmpty,
  renderLiveList: renderAdminLiveList,
  renderSkeleton: renderAdminSkeleton,
  settings: window.ShellXDriveSettings,
  showToast,
  state,
});
const {
  loadAdminSessions,
  loadAllAdminSessions,
  loadSelfSessions,
  renderAdminSessions,
  renderSelfSessions,
} = sessionController;
sessionController.bind();

const authHydration = window.ShellXDriveAuthHydration.createController({
  state, els, api, publicApi, authLifecycle, applyUiState,
  clearSensitiveAccountState, currentAccountEmail, hasAuthenticatedSession,
  loadCurrentAccount, loadNotifications, loadSelfSessions, loadWorkspaces, persistSession,
  setPasswordResetStatus, setStatus, setAuthStatus, showSecondFactorChallenge,
  showToast, togglePasswordReset,
});
const {
  bootstrapFirstAdmin, initializeAuthentication, loadBootstrapStatus,
  localLoginFailureCopy, loginWithPassword, reconcileRemoteAuthentication,
  reconcileRemoteCredentialRotation,
} = authHydration;
authLifecycle.setRemoteHandler((kind) => void (kind === "credential-rotation"
  ? reconcileRemoteCredentialRotation()
  : reconcileRemoteAuthentication()));

async function applyCredentialRotation(request, publish) {
  const actor = currentAccountEmail();
  let lease = authLifecycle.capture();
  try {
    const data = await request();
    if (!authLifecycle.isCurrent(lease) || currentAccountEmail() !== actor) return;
    persistSession(
      data.replacement_token || "",
      actor,
      data.replacement_session_id || "",
    );
    authLifecycle.rotateCredential();
    lease.cleanup();
    lease = authLifecycle.capture();
    state.selfSessions = null;
    renderSelfSessions();
    await loadSelfSessions().catch((error) => {
      if (window.ShellXDriveAuthLifecycle.isStale(error)) throw error;
    });
    // Publish synchronously under the replacement epoch: an awaited caller
    // continuation could otherwise restore secrets after account separation.
    if (!authLifecycle.isCurrent(lease) || currentAccountEmail() !== actor) return;
    publish(data);
  } finally {
    lease.cleanup();
  }
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function showToast(message) {
  if (!els.statusToast || !message) return;
  els.statusToast.textContent = message;
  els.statusToast.classList.add("visible");
  window.clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => {
    els.statusToast.classList.remove("visible");
  }, 2600);
}

function setActiveView(view) {
  if (state.activeView !== view) state.browserPage = 0;
  state.activeView = view;
  document.querySelectorAll("[data-view-button]").forEach((button) => {
    button.classList.toggle("active", button.dataset.viewButton === view);
  });
}

function isAccountBrowseView() {
  return Boolean(state.browseScope);
}

function clearAccountBrowseState() {
  // Invalidate any delayed page response before restoring a workspace-local
  // surface. A stale account-wide response must never overwrite a manifest.
  state.browseRequestSequence += 1;
  state.searchRequestSequence += 1;
  state.browseScope = null;
  state.browseFiles = [];
  state.browseNextCursor = null;
  state.browsePageCursors = [null];
  state.browsePageIndex = 0;
  state.browseLoading = false;
}

function browseTitle(scope) {
  return (
    {
      files: "Files",
      mine: "My files",
      "shared-with-me": "Shared with me",
      "shared-by-me": "Shared by me",
      recent: "Recent",
    }[scope] || "Files"
  );
}

async function loadBrowseFiles(scope, { cursor = null, pageIndex = 0 } = {}) {
  if (cursor && state.browseScope !== scope) return;
  state.searchRequestSequence += 1;
  els.searchInput.value = "";
  state.manifestRequestSequence += 1;
  const requestSequence = ++state.browseRequestSequence;
  state.browseLoading = true;
  try {
    const query = browseFilterQuery(scope, !cursor && pageIndex === 0);
    if (cursor) query.set("cursor", cursor);
    const data = await api(`/browse/files?${query.toString()}`);
    // A delayed response from a previous browse click must not replace the
    // selected scope. The response itself has no side effects, so ignoring it
    // is safe and keeps the UI deterministic.
    if (requestSequence !== state.browseRequestSequence) return;
    state.browseFiles = data.files || [];
    state.browseScope = scope;
    state.browseNextCursor = data.next_cursor || null;
    state.browsePageIndex = pageIndex;
    state.browsePageCursors = state.browsePageCursors.slice(0, pageIndex + 1);
    state.browsePageCursors[pageIndex] = cursor;
    state.currentViewTitle = browseTitle(scope);
    state.currentFolderId = null;
    state.bulkSelectedIds = [];
    state.browserPage = 0;
    resetSelectedFileState();
    setActiveView(scope === "files" ? "my-drive" : scope);
    renderFiles(state.browseFiles);
    renderSelection();
  } finally {
    if (requestSequence === state.browseRequestSequence) state.browseLoading = false;
  }
}

function browseFilterQuery(scope, resetModified = false) {
  const query = new URLSearchParams({ scope, limit: "100" });
  const preferences = state.browserPreferences;
  if (preferences.typeFilter !== "all") query.set("type_filter", preferences.typeFilter);
  if (preferences.ownerScope !== "any") query.set("owner_scope", preferences.ownerScope);
  if (preferences.modifiedRange !== "any") {
    if (resetModified || !state.browseModifiedSince) {
      state.browseModifiedSince = new Date(Date.now() - Number(preferences.modifiedRange) * 86_400_000).toISOString();
    }
    query.set("modified_since", state.browseModifiedSince);
  } else {
    state.browseModifiedSince = null;
  }
  if (preferences.locationScope !== "any" && state.currentWorkspace?.id) {
    query.set("workspace_id", state.currentWorkspace.id);
    if (preferences.locationScope === "folder" && preferences.folderId) query.set("folder_id", preferences.folderId);
  }
  if (preferences.stateFilter !== "any") query.set("state_filter", preferences.stateFilter);
  return query;
}

async function openBrowseFileLocation(file) {
  if (file.human_share_root && file.human_share_list === "shared-with-me") {
    return humanSharing.openScopedRoot(file);
  }
  const retryableSharedRootFailure = () => {
    const message = "This shared item could not be verified. Your current view is still available; retry when the connection is ready.";
    humanSharingBrowser.presentRetryableRoot(file, message);
    throw new Error(message);
  };
  try {
    const workspace = state.workspaces.find((candidate) => candidate.id === file.workspace_id);
    if (!workspace) {
      if (file.human_share_root) return retryableSharedRootFailure();
      throw new Error("This workspace is no longer available. Refresh Files and try again.");
    }
    setCurrentWorkspace(workspace);
    state.currentFolderId = null;
    if (!await loadManifest(workspace.id)) return;
    rememberWorkspace(workspace.id);
    const currentFile = state.files.find((candidate) => candidate.id === file.id);
    if (!currentFile) {
      if (file.human_share_root) return retryableSharedRootFailure();
      throw new Error("This file is no longer available. Refresh Files and try again.");
    }
    if (currentFile.kind === "folder") openFolder(currentFile.id);
    else {
      state.currentFolderId = currentFile.parent_id || null;
      renderFiles();
      selectFile(currentFile);
    }
  } catch (error) {
    if (file.human_share_root && !/could not be verified/.test(String(error?.message || ""))) return retryableSharedRootFailure();
    throw error;
  }
}

function actorWorkspaceStorageKey(actorOverride = currentAccountEmail()) {
  const actor = String(actorOverride || "")
    .trim()
    .toLocaleLowerCase();
  return actor ? `${LAST_WORKSPACE_STORAGE_PREFIX}${actor}` : "";
}

function rememberedWorkspaceId() {
  const key = actorWorkspaceStorageKey();
  if (!key) return "";
  try {
    return localStorage.getItem(key) || "";
  } catch {
    return "";
  }
}

function rememberWorkspace(workspaceId) {
  const key = actorWorkspaceStorageKey();
  if (!key || !workspaceId) return;
  try {
    localStorage.setItem(key, workspaceId);
  } catch {
    // Persistence is a convenience. Private/blocked storage must not stop Drive.
  }
}

function discardRememberedWorkspace(actor = currentAccountEmail()) {
  const key = actorWorkspaceStorageKey(actor);
  if (!key) return;
  try {
    localStorage.removeItem(key);
  } catch {
    // The normal first-accessible fallback still works when storage is blocked.
  }
}

function browserWorkspaceId() {
  return state.currentWorkspace?.id || "global";
}

function persistBrowserPreferences() {
  state.browserPreferences = window.ShellXDriveBrowser.savePreferences(
    localStorage,
    currentAccountEmail(),
    browserWorkspaceId(),
    {
      ...state.browserPreferences,
      typeFilter: state.activeFileFilter,
      layout: state.fileLayout,
      folderId: state.currentFolderId,
    },
  );
}

function activeBrowserFilterCount() {
  const preferences = state.browserPreferences;
  return [
    preferences.typeFilter !== "all",
    preferences.ownerScope !== "any",
    preferences.modifiedRange !== "any",
    preferences.locationScope !== "any",
    preferences.stateFilter !== "any",
  ].filter(Boolean).length;
}

function syncBrowserControls() {
  const preferences = state.browserPreferences;
  const accountBrowse = isAccountBrowseView();
  const sharedProjection = ["files", "shared-with-me", "shared-by-me"].includes(state.browseScope);
  const accountBrowseOrderHint =
    state.browseScope === "recent"
      ? "Recent is ordered by most recent change."
      : state.browseScope === "files"
        ? "Files shows owned roots first, then roots shared with you."
      : "Account-wide pages put folders first, then use a stable name order.";
  if (els.fileSortKey) els.fileSortKey.value = preferences.sortKey;
  if (els.fileSortKey) {
    els.fileSortKey.disabled = accountBrowse;
    els.fileSortKey.title = accountBrowse ? accountBrowseOrderHint : "";
  }
  if (els.fileSortDirection) {
    const descending = preferences.direction === "desc";
    els.fileSortDirection.textContent = descending ? "Descending" : "Ascending";
    els.fileSortDirection.setAttribute(
      "aria-label",
      descending ? "Sort descending" : "Sort ascending",
    );
    els.fileSortDirection.setAttribute("aria-pressed", String(descending));
    els.fileSortDirection.disabled = accountBrowse;
    els.fileSortDirection.title = accountBrowse ? accountBrowseOrderHint : "";
  }
  if (els.foldersFirst) {
    els.foldersFirst.checked = preferences.foldersFirst;
    els.foldersFirst.disabled = accountBrowse;
    els.foldersFirst.title = accountBrowse ? accountBrowseOrderHint : "";
  }
  const shownFilters = sharedProjection ? window.ShellXDriveBrowser.defaults() : preferences;
  if (els.browserTypeFilter) els.browserTypeFilter.value = shownFilters.typeFilter;
  if (els.browserOwnerFilter) els.browserOwnerFilter.value = shownFilters.ownerScope;
  if (els.browserModifiedFilter) els.browserModifiedFilter.value = shownFilters.modifiedRange;
  if (els.browserLocationFilter) els.browserLocationFilter.value = shownFilters.locationScope;
  if (els.browserStateFilter) els.browserStateFilter.value = shownFilters.stateFilter;
  for (const control of [els.browserTypeFilter, els.browserOwnerFilter, els.browserModifiedFilter, els.browserLocationFilter, els.browserStateFilter]) {
    if (control) control.disabled = sharedProjection;
  }
  if (els.browserFilterClear) els.browserFilterClear.disabled = sharedProjection;
  if (els.browserFilterScopeNote) els.browserFilterScopeNote.hidden = !sharedProjection;
  if (els.browserFilterToggle) els.browserFilterToggle.title = sharedProjection
    ? "Filters are available in My files and Recent"
    : "Filter files";
  document.querySelectorAll("[data-file-filter]").forEach((button) => {
    button.disabled = sharedProjection;
    button.title = sharedProjection ? "Filters are available in My files and Recent" : "";
    const active = !sharedProjection && button.dataset.fileFilter === preferences.typeFilter;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  const count = activeBrowserFilterCount();
  if (els.browserFilterCount) {
    els.browserFilterCount.hidden = sharedProjection || count === 0;
    els.browserFilterCount.textContent = String(count);
  }
}

function setBrowserPreference(key, value) {
  state.browserPreferences = window.ShellXDriveBrowser.normalizePreferences({
    ...state.browserPreferences,
    [key]: value,
  });
  state.activeFileFilter = state.browserPreferences.typeFilter;
  state.browserPage = 0;
  persistBrowserPreferences();
  syncBrowserControls();
  if (isAccountBrowseView()) reloadAccountBrowse();
  else renderFiles(state.hasCurrentBaseFiles ? state.currentBaseFiles : state.files);
}

function reloadAccountBrowse() {
  if (state.browseScope === "files") humanSharing.loadDefaultFiles().catch((error) => showToast(error.message));
  else if (["shared-with-me", "shared-by-me"].includes(state.browseScope)) {
    humanSharing.loadRoots(state.browseScope).catch((error) => showToast(error.message));
  } else loadBrowseFiles(state.browseScope).catch((error) => showToast(error.message));
}

function loadAccountPage(cursor, pageIndex) {
  if (state.browseScope === "files") return humanSharing.loadDefaultFiles({ cursor, pageIndex });
  if (["shared-with-me", "shared-by-me"].includes(state.browseScope)) {
    return humanSharing.loadRoots(state.browseScope, { cursor, pageIndex });
  }
  return loadBrowseFiles(state.browseScope, { cursor, pageIndex });
}

function setFileFilter(filter) {
  setBrowserPreference("typeFilter", filter);
}

function setViewMode(mode) {
  state.fileLayout = mode;
  document.body.dataset.fileLayout = mode;
  const listActive = mode === "list";
  els.listViewButton.classList.toggle("active", listActive);
  els.gridViewButton.classList.toggle("active", !listActive);
  els.listViewButton.setAttribute("aria-pressed", String(listActive));
  els.gridViewButton.setAttribute("aria-pressed", String(!listActive));
  // Tiles are the same rows re-styled by CSS, so switching to grid doesn't
  // re-render — hydrate the content snippets for the now-visible text tiles.
  if (!listActive) hydrateGridSnippets();
  state.browserPreferences = window.ShellXDriveBrowser.normalizePreferences({
    ...state.browserPreferences,
    layout: mode,
  });
  persistBrowserPreferences();
}

function setAdminSection(section) {
  const nextSection = section || "overview";
  state.activeAdminSection = nextSection;
  if (els.adminSectionSelect) els.adminSectionSelect.value = nextSection;
  document.querySelectorAll("[data-admin-section]").forEach((button) => {
    const active = button.dataset.adminSection === nextSection;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  document.querySelectorAll("[data-admin-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.adminPanel === nextSection);
  });
  if (nextSection === "content") {
    humanSharing?.loadAdminInventory();
  }
  if (nextSection === "workspaces") {
    settingsController?.loadAdminWorkspaces().catch((error) => showToast(error.message));
  }
  if (nextSection === "sandbox" && !state.sandboxProfile) {
    loadSandboxProfile().catch((error) => {
      els.sandboxOutput.textContent = error.message;
    });
  }
  if (nextSection === "teams" && !state.groupsData) {
    loadGroups().catch((error) => {
      els.groupsOutput.textContent = error.message;
    });
  }
  if (
    ["storage", "sharing"].includes(nextSection) &&
    state.currentWorkspace &&
    (!state.workspacePolicy || !state.workspaceUsage)
  ) {
    loadWorkspacePolicyAndUsage().catch((error) => {
      const target =
        nextSection === "storage" ? els.storagePolicyOutput : els.sharingPolicyOutput;
      target.textContent = error.message;
    });
  }
  if (nextSection === "sharing") everyoneGrantPolicyController.load().catch((error) => { document.getElementById("admin-everyone-grant-policy-output").textContent = error.message; });
  if (nextSection === "maintenance" && !state.maintenanceStatus) {
    loadReadinessStatus().catch((error) => {
      els.maintenanceOutput.textContent = error.message;
    });
    loadMaintenanceStatus().catch((error) => {
      els.maintenanceOutput.textContent = error.message;
    });
  }
  if (nextSection === "cleanup") {
    renderRetentionCleanup();
  }
  if (nextSection === "backups" && !state.adminBackups) {
    loadBackupPolicy().catch((error) => {
      els.adminBackupsSummary.textContent = error.message;
    });
    loadAdminBackups().catch((error) => {
      els.adminBackupsSummary.textContent = error.message;
    });
  }
  if (nextSection === "sessions" && !state.adminSessions) {
    loadAdminSessions().catch((error) => {
      els.adminSessionsSummary.textContent = error.message;
    });
  }
  if (nextSection === "accounts" && !state.authAccounts) {
    loadAuthAccounts().catch((error) => {
      els.adminAuthSummary.textContent = error.message;
    });
  }
  if (nextSection === "security" && !state.authAttempts) {
    loadAuthAttempts().catch((error) => {
      els.adminAuthAttempts.textContent = error.message;
    });
  }
  if (nextSection === "security" && !state.securityEvents) {
    adminSecurityController.load().catch((error) => {
      els.adminSecurityEventsList.textContent = error.message;
    });
  }
  if (nextSection === "accounts" && !state.registrationPolicy) {
    loadRegistrationPolicy().catch((error) => {
      els.adminRegistrationSummary.textContent = error.message;
    });
  }
  if (nextSection === "email" && !state.adminEmail) {
    loadAdminEmail().catch((error) => {
      els.adminEmailSummary.textContent = error.message;
    });
  }
}

function fileMatchesFilter(file) {
  if (state.activeFileFilter === "all") return true;
  if (state.activeFileFilter === "folders") return file.kind === "folder";
  const ext = fileExtension(file);
  if (state.activeFileFilter === "docs") {
    return file.kind === "file" && ["doc", "docx", "odt", "ppt", "pptx", "odp", "md", "rtf", "txt"].includes(ext);
  }
  if (state.activeFileFilter === "sheets") {
    return file.kind === "file" && ["csv", "xls", "xlsx", "ods"].includes(ext);
  }
  if (state.activeFileFilter === "pdfs") return file.kind === "file" && ext === "pdf";
  return true;
}

function filterFilesForContent(files) {
  // Trash lives in exactly one place: the Trash view shows ONLY trashed items;
  // every other view (My Drive, Recent, Shared, Starred, Offline, Search) shows
  // ONLY live items. Centralising it here means any re-render triggered by
  // loadManifest() — e.g. after a trash/restore — leaves the current view
  // correct without each caller re-filtering.
  const scoped =
    state.activeView === "trash"
      ? files.filter((file) => file.trashed)
      : files.filter((file) => !file.trashed);
  return scoped;
}

function fileNodesById() {
  const nodes = state.folderTree?.nodes || state.files || [];
  return new Map(nodes.map((file) => [file.id, file]));
}

function currentFolderNode() {
  if (!state.currentFolderId) return null;
  const node = fileNodesById().get(state.currentFolderId);
  return node?.kind === "folder" ? node : null;
}

function folderAncestors(folderId = state.currentFolderId) {
  const byId = fileNodesById();
  const ancestors = [];
  let current = folderId ? byId.get(folderId) : null;
  const seen = new Set();
  while (current && current.kind === "folder" && !seen.has(current.id)) {
    seen.add(current.id);
    ancestors.unshift(current);
    current = current.parent_id ? byId.get(current.parent_id) : null;
  }
  return ancestors;
}

function filesInCurrentFolder(files) {
  if (state.activeView === "shared" && state.currentWorkspace?.scoped_root?.kind === "folder") {
    return files.filter((file) => file.parent_id === state.currentFolderId);
  }
  if (state.activeView !== "my-drive" || state.currentViewTitle) {
    return files;
  }
  if (state.currentFolderId && !currentFolderNode()) {
    state.currentFolderId = null;
  }
  return files.filter((file) => (file.parent_id || null) === (state.currentFolderId || null));
}

function openFolder(folderId = null) {
  state.suppressPreviewUntil = Date.now() + 500;
  const scopedRoot = state.currentWorkspace?.scoped_root;
  state.currentFolderId = folderId || (scopedRoot?.kind === "folder" ? scopedRoot.id : null);
  state.browserPage = 0;
  state.browserPreferences = window.ShellXDriveBrowser.normalizePreferences({
    ...state.browserPreferences,
    folderId,
  });
  persistBrowserPreferences();
  state.bulkSelectedIds = [];
  state.currentViewTitle = scopedRoot ? `Shared with me · ${scopedRoot.owner_label || "Owner"}` : null;
  els.searchInput.value = "";
  setActiveView(scopedRoot ? "shared" : "my-drive");
  resetSelectedFileState();
  renderFiles();
  renderSelection();
}

function renderFolderBreadcrumb() {
  if (!els.folderBreadcrumb) return;
  els.folderBreadcrumb.replaceChildren();
  if (isAccountBrowseView()) {
    const label = document.createElement("span");
    label.textContent = `${browseTitle(state.browseScope)} across workspaces`;
    label.setAttribute("aria-current", "page");
    els.folderBreadcrumb.append(label);
    return;
  }
  if (state.currentViewTitle?.startsWith("Search results")) {
    const query = els.searchInput.value.trim();
    const label = document.createElement("span");
    label.textContent = query ? `Search results for “${query}”` : "Search results";
    label.setAttribute("aria-current", "page");
    const clear = document.createElement("button");
    clear.type = "button";
    clear.textContent = "Clear search";
    clear.addEventListener("click", clearSearch);
    els.folderBreadcrumb.append(label, clear);
    return;
  }
  const root = document.createElement("button");
  root.type = "button";
  root.textContent = "My Drive";
  root.className = state.currentFolderId ? "" : "active";
  root.addEventListener("click", () => openFolder(null));
  els.folderBreadcrumb.append(root);
  for (const folder of folderAncestors()) {
    const separator = document.createElement("span");
    separator.textContent = "/";
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = folder.name;
    button.className = folder.id === state.currentFolderId ? "active" : "";
    button.addEventListener("click", () => openFolder(folder.id));
    els.folderBreadcrumb.append(separator, button);
  }
}

function visibleFileIds() {
  return new Set((state.lastRenderedFiles || []).map((file) => file.id));
}

function selectedBulkIds() {
  const validIds = new Set(state.files.map((file) => file.id));
  state.bulkSelectedIds = state.bulkSelectedIds.filter((id) => validIds.has(id));
  return new Set(state.bulkSelectedIds);
}

function setBulkSelected(ids) {
  state.bulkSelectedIds = [...new Set(ids)];
  renderFiles(state.hasCurrentBaseFiles ? state.currentBaseFiles : state.files);
}

function toggleBulkSelection(fileId, selected) {
  const ids = selectedBulkIds();
  if (selected) {
    ids.add(fileId);
  } else {
    ids.delete(fileId);
  }
  setBulkSelected([...ids]);
}

function bulkActionAvailability() {
  return window.ShellXDriveBrowser.bulkActionAvailability(
    state.files,
    selectedBulkIds(),
    {
      canWrite: canWriteCurrentWorkspace(),
      accountBrowse: isAccountBrowseView(),
    },
  );
}

function renderBulkActionToolbar() {
  const selected = selectedBulkIds();
  const visible = visibleFileIds();
  const visibleSelected = [...visible].filter((id) => selected.has(id));
  const count = selected.size;
  document.body.dataset.driveBulk = count === 0 ? "none" : count > 1 ? "many" : "one";
  if (els.bulkSelectionCount) {
    els.bulkSelectionCount.textContent = count
      ? `${count} ${count === 1 ? "item" : "items"} selected`
      : "No items selected";
  }
  if (els.selectVisibleFiles) {
    els.selectVisibleFiles.checked = visible.size > 0 && visibleSelected.length === visible.size;
    els.selectVisibleFiles.indeterminate =
      visibleSelected.length > 0 && visibleSelected.length < visible.size;
    els.selectVisibleFiles.disabled = visible.size === 0;
  }
  const availability = bulkActionAvailability();
  if (els.bulkDownloadButton) els.bulkDownloadButton.disabled = !availability.download;
  if (els.bulkMoveButton) els.bulkMoveButton.disabled = !availability.move;
  if (els.bulkTrashButton) els.bulkTrashButton.disabled = !availability.trash;
  if (els.bulkRestoreButton) els.bulkRestoreButton.disabled = !availability.restore;
  if (els.bulkStarButton) els.bulkStarButton.disabled = !availability.star;
  if (els.bulkUnstarButton) els.bulkUnstarButton.disabled = !availability.unstar;
}

function renderViewTitle(title) {
  const accountBrowse = isAccountBrowseView();
  const fallback = accountBrowse
    ? "All accessible workspaces"
    : state.currentWorkspace
      ? state.currentWorkspace.name
      : "No workspace selected";
  const currentTitle = title || "My Drive";
  els.currentViewLabel.textContent = currentTitle;
  els.workspaceTitle.textContent = fallback;
  els.workspaceSubtitle.textContent = accountBrowse ? "Account view" : "Workspace";
}

function isActiveShare(share, now = Date.now()) {
  return window.ShellXDriveCollaboration.isActiveShare(share, now);
}

function activeShareForFile(fileId) {
  return collaboration.activeShareForFile(fileId);
}

function renderSharedItemBadge(file) {
  const humanBadge = humanSharing?.badgeForFile(file) || "";
  const retryBadge = file.human_share_retry_message
    ? `<span class="shared-item-badge is-retry" title="${escapeHtml(file.human_share_retry_message)}"><svg class="icon" aria-hidden="true"><use href="#i-refresh"/></svg><span>Not verified · Retry</span></span>`
    : "";
  if (isAccountBrowseView()) return `${humanBadge}${retryBadge}`;
  const share = activeShareForFile(file.id);
  if (!share) return `${humanBadge}${retryBadge}`;
  const expiry = share.expires_at ? `until ${formatShareExpiry(share.expires_at)}` : "without expiry";
  return `${humanBadge}${retryBadge}<span class="shared-item-badge" title="Guest link active ${escapeHtml(expiry)}"><svg class="icon" aria-hidden="true"><use href="#i-link"/></svg><span>Guest link</span></span>`;
}

function renderBrowseAccessBadge(file) {
  if (!isAccountBrowseView()) return "";
  const workspaceName = escapeHtml(file.workspace_name || "My files");
  if (file.owned_by_actor) {
    return `<span class="browse-access-badge browse-access-owned" title="You own this item">Owner · ${workspaceName}</span>`;
  }
  const role =
    {
      editor: "Editor",
      viewer: "Viewer · Read-only",
      admin: "Administrator access",
    }[file.effective_role || file.access_role] || "Shared access";
  const owner = escapeHtml(file.owner_label || "Owner");
  const inherited = file.grant_source === "inherited" ? " · Inherited" : "";
  return `<span class="browse-access-badge browse-access-shared" title="${escapeHtml(role)} from ${owner}">Shared · ${owner} · ${escapeHtml(role)}${inherited}</span>`;
}

// Refresh one row's badge without rebuilding the row. This keeps pointer and
// double-click targets stable while an asynchronous share lookup completes.
function syncSharedItemBadge(fileId) {
  const row = [...els.fileRows.querySelectorAll("tr[data-file-id]")].find(
    (candidate) => candidate.dataset.fileId === fileId,
  );
  if (!row) return;
  row.querySelectorAll(".shared-item-badge").forEach((badge) => badge.remove());
  const file = state.files.find((candidate) => candidate.id === fileId);
  const markup = file ? renderSharedItemBadge(file) : "";
  if (!markup) return;
  const template = document.createElement("template");
  template.innerHTML = markup;
  row.querySelector(".row-star-toggle")?.before(template.content.firstElementChild);
}

function fileKindLabel(file) {
  return fileTypeInfo(file).label;
}

/**
 * File-type icon: an SVG symbol tinted by the container's hue.
 * Raster images render their real server thumbnail (GET /files/{id}/thumbnail);
 * an `error` handler (wired via wireThumbnailFallbacks after insertion) swaps a
 * unavailable thumbnail back to the file-image icon.
 */
function renderFileIcon(file) {
  const info = fileTypeInfo(file);
  // A folder with a custom cover renders the cover image as its tile, with a
  // small folder badge overlaid so it still unmistakably reads as a folder. The
  // `data-file-icon` hook lets wireThumbnailFallbacks() swap back to the folder
  // icon if the cover fails to load (404/removed).
  if (info.isFolder && file?.has_cover && file?.id) {
    return `<span class="file-icon folder has-cover" data-file-icon="i-folder"><img class="row-thumb folder-cover" src="/files/${escapeHtml(file.id)}/cover" alt="" loading="lazy" /><span class="folder-cover-badge" aria-hidden="true"><svg class="icon"><use href="#i-folder"/></svg></span></span>`;
  }
  if (info.thumb && file?.id) {
    return `<span class="file-icon ${escapeHtml(info.hueClass)}" data-file-icon="${escapeHtml(info.icon)}"><img class="row-thumb" src="/files/${escapeHtml(file.id)}/thumbnail" alt="" loading="lazy" /></span>`;
  }
  return `<span class="file-icon ${escapeHtml(info.hueClass)}${info.isFolder ? " folder" : ""}" aria-hidden="true"><svg class="icon"><use href="#${escapeHtml(info.icon)}"/></svg></span>`;
}

function renderStatusChip(file) {
  if (file.trashed) return `<span class="status-chip danger">Trash</span>`;
  if (file.starred) return `<span class="status-chip warning">Starred</span>`;
  return `<span class="status-chip active">Ready</span>`;
}

function fileStateText(file) {
  if (file.trashed) return "Trash";
  if (file.starred) return "Starred";
  return "Ready";
}

function fileSyncText(file) {
  if (file.kind === "folder") return "Sync ready";
  if (isOfflineMarked(file)) return "Marked for mobile download";
  return "Sync ready";
}

function isOfflineMarked(file) {
  return Boolean(
    state.mobileManifest?.files?.some((entry) => entry.id === file.id && entry.offline_marked),
  );
}

function renderSyncChip(file) {
  if (file.kind === "folder") return `<span class="sync-chip ready">Sync ready</span>`;
  if (isOfflineMarked(file)) return `<span class="sync-chip ready">Marked for mobile download</span>`;
  return `<span class="sync-chip ready">Sync ready</span>`;
}

function renderStorageSummary() {
  const workspace = state.currentWorkspace;
  const total = state.files.length;
  const folders = state.files.filter((file) => file.kind === "folder").length;
  document.body.dataset.driveHasWorkspace = workspace ? "true" : "false";
  els.storageSummaryName.textContent = workspace ? workspace.name : "No workspace";
  els.storageSummaryMode.textContent = workspace
    ? "Drive storage"
    : "Connect to begin";
  els.storageSummaryUsed.textContent = `${total} items · ${folders} folders`;
  renderStorageUsage();
  renderWorkspaceLifecycleControls();
}

// Sidebar space-usage gauge (Google-Drive-style "<used> of <quota> used").
// Reads state.workspaceUsage (shared with the admin storage tiles); the fetch
// lives in refreshWorkspaceUsage(). Degrades gracefully: no workspace/usage =>
// hidden; no quota => "<used> used · No limit" with no bar.
function renderStorageUsage() {
  if (!els.storageUsage) return;
  const workspace = state.currentWorkspace;
  const usage = state.workspaceUsage;
  // Only surface a figure that actually belongs to the current workspace.
  if (!workspace || !usage || usage.workspace_id !== workspace.id) {
    els.storageUsage.hidden = true;
    return;
  }
  const used = Number(usage.current_file_bytes) || 0;
  const quota = usage.quota_bytes;
  const auxiliary = window.ShellXDriveSettings.auxiliaryStorageSummary(usage, formatFileSize);
  els.storageUsage.hidden = false;

  if (quota === null || quota === undefined) {
    // Unlimited workspace: show the used figure, no bar.
    if (els.storageUsageTrack) els.storageUsageTrack.hidden = true;
    els.storageUsageLabel.textContent = `${formatFileSize(used)} used · No file limit${auxiliary ? ` · ${auxiliary}` : ""}`;
    return;
  }

  const quotaBytes = Number(quota) || 0;
  const ratio = quotaBytes > 0 ? Math.min(1, used / quotaBytes) : 0;
  const pct = Math.round(ratio * 100);
  if (els.storageUsageTrack) {
    els.storageUsageTrack.hidden = false;
    els.storageUsageTrack.setAttribute("aria-valuenow", String(pct));
  }
  if (els.storageUsageFill) els.storageUsageFill.style.width = `${(ratio * 100).toFixed(1)}%`;
  els.storageUsageLabel.textContent = `${formatFileSize(used)} of ${formatFileSize(quotaBytes)} file storage used${auxiliary ? ` · ${auxiliary}` : ""}`;
}

// Fetch current-workspace usage (Read-permission endpoint, so any member can see
// it) and re-render the gauge. Called from loadManifest, so it refreshes on
// workspace load and after every action that reloads the manifest (upload,
// delete, trash, move, empty-trash). Fire-and-forget; failures degrade silently.
async function refreshWorkspaceUsage() {
  const workspace = state.currentWorkspace;
  if (!workspace) {
    state.workspaceUsage = null;
    renderStorageUsage();
    return;
  }
  try {
    const usage = await api(`/workspaces/${workspace.id}/usage`);
    // Guard against a workspace switch that landed mid-flight.
    if (state.currentWorkspace && usage && usage.workspace_id === state.currentWorkspace.id) {
      state.workspaceUsage = usage;
    }
  } catch {
    // No permission or offline — keep whatever we already show.
  }
  renderStorageUsage();
}

function renderWorkspaceLifecycleControls() {
  const hasWorkspace = Boolean(state.currentWorkspace);
  const canManage = hasWorkspace && canManageCurrentWorkspace();
  const archived = Boolean(state.currentWorkspace?.archived);
  [
    els.workspaceRenameName,
    els.workspaceTransferEmail,
    els.workspaceArchiveButton,
    els.workspaceUnarchiveButton,
    els.workspaceLeaveButton,
  ].forEach((element) => {
    if (element) element.disabled = !hasWorkspace || (!canManage && element !== els.workspaceLeaveButton);
  });
  if (els.workspaceRenameName && state.currentWorkspace) {
    els.workspaceRenameName.placeholder = state.currentWorkspace.name;
  }
  if (els.workspaceArchiveButton) {
    els.workspaceArchiveButton.hidden = archived;
    els.workspaceArchiveButton.disabled = !canManage || archived;
  }
  if (els.workspaceUnarchiveButton) {
    els.workspaceUnarchiveButton.hidden = !archived;
    els.workspaceUnarchiveButton.disabled = !canManage || !archived;
  }
  if (els.workspaceTransferEmail) {
    els.workspaceTransferEmail.disabled = !canManage;
  }
}

function renderShareSummary() {
  collaboration.renderShareSummary();
}

function activeShareForSelectedFile() {
  return collaboration.activeShareForSelectedFile();
}

function syncShareExpiryControls() {
  collaboration.syncShareExpiryControls();
}

function syncInspectorShareForm(activeShare) {
  collaboration.syncInspectorShareForm(activeShare);
}

function openShareDrawer() {
  collaboration.openShareDrawer();
}

function closeShareDrawer() {
  collaboration.closeShareDrawer();
}

async function createWorkspaceInvitation(eventOrData) {
  return collaboration.createWorkspaceInvitation(eventOrData);
}

async function resendWorkspaceInvitation(invitationId) {
  return collaboration.resendWorkspaceInvitation(invitationId);
}

async function cancelWorkspaceInvitation(invitationId) {
  return collaboration.cancelWorkspaceInvitation(invitationId);
}

function toggleAdvancedWorkbench(show) {
  els.advancedWorkbench.hidden = !show;
  if (show) {
    document.body.dataset.adminOpen = "true";
  } else {
    delete document.body.dataset.adminOpen;
  }
}

async function copyLatestShareLink() {
  return collaboration.copyLatestShareLink();
}

async function copyLatestDropLink() {
  if (!state.latestDropUrl) {
    showToast("Create a drop link first.");
    return;
  }
  try {
    await navigator.clipboard?.writeText(state.latestDropUrl);
  } catch {
    // Clipboard permission is optional; the visible link remains available.
  }
  showToast("Drop link copied.");
}

function initialsForEmail(email) {
  return (
    String(email || "?")
      .split("@")[0]
      .split(/[.\-_]/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase())
      .join("") || "?"
  );
}

async function loadWorkspaces() {
  const priorBrowseScope = state.browseScope;
  const needsInitialAccountBrowse = !state.hasCurrentBaseFiles;
  const navigation = [state.manifestRequestSequence, state.browseRequestSequence];
  const data = await api("/sync/workspaces");
  const navigationCurrent = navigation[0] === state.manifestRequestSequence && navigation[1] === state.browseRequestSequence;
  state.workspaces = data.workspaces || [];
  if (navigationCurrent) {
    const currentWorkspace = state.workspaces.find((workspace) => workspace.id === state.currentWorkspace?.id);
    if (currentWorkspace) {
      setCurrentWorkspace(currentWorkspace);
    } else if (state.workspaces.length) {
      const rememberedId = rememberedWorkspaceId();
      const rememberedWorkspace = state.workspaces.find((workspace) => workspace.id === rememberedId);
      setCurrentWorkspace(rememberedWorkspace || state.workspaces[0]);
      if (rememberedId && !rememberedWorkspace) {
        discardRememberedWorkspace();
      }
    } else {
      setCurrentWorkspace(null);
      if (rememberedWorkspaceId()) {
        discardRememberedWorkspace();
      }
    }
  }
  renderWorkspaces();
  if (state.currentWorkspace && navigationCurrent) {
    rememberWorkspace(state.currentWorkspace.id);
    if (priorBrowseScope || needsInitialAccountBrowse) {
      const scope = priorBrowseScope || "files";
      if (scope === "files") await humanSharing.loadDefaultFiles();
      else if (scope === "shared-with-me" || scope === "shared-by-me") await humanSharing.loadRoots(scope);
      else await loadBrowseFiles(scope);
    } else {
      await loadManifest(state.currentWorkspace.id);
    }
  } else if (!state.currentWorkspace && navigationCurrent) {
    clearAccountBrowseState();
    applyUiState();
  }
  if (hasAdminTools()) {
    await refreshAdminCommandCenter();
  }
  setStatus("Connected");
}
function setCurrentWorkspace(workspace) {
  const previousId = state.currentWorkspace?.id || null;
  state.currentWorkspace = workspace;
  if (previousId !== workspace?.id) {
    collaboration?.clearInvitationLink();
    state.workspacePolicy = null;
    state.workspaceUsage = null;
    state.trashFiles = [];
    workspacePolicyController?.invalidate();
  }
  return workspace;
}
function isManifestLeaseCurrent(lease) {
  return Boolean(
    lease &&
    lease.requestSequence === state.manifestRequestSequence &&
    state.currentWorkspace?.id === lease.workspaceId
  );
}

async function loadManifest(workspaceId) {
  clearAccountBrowseState();
  const lease = {
    requestSequence: ++state.manifestRequestSequence,
    workspaceId,
  };
  const isCurrent = () => isManifestLeaseCurrent(lease);
  if (state.currentWorkspace?.id !== workspaceId) return false;
  if (state.currentWorkspace.scoped_root) {
    return humanSharing.refreshScopedRoot(state.currentWorkspace.scoped_root, isCurrent);
  }
  const previousWorkspaceId = state.currentWorkspace?.id;
  const restoreBrowserState = state.browserPreferenceWorkspaceId !== workspaceId;
  if (restoreBrowserState) {
    state.files = [];
    state.folderTree = null;
    state.selectedFile = null;
    state.selectedComments = [];
    state.bulkSelectedIds = [];
    renderFiles();
    renderSelection();
  }
  const data = await api(`/sync/workspaces/${workspaceId}/manifest`);
  if (!isCurrent()) return false;
  state.files = data.files || [];
  state.currentViewTitle = null;
  setCurrentWorkspace(
    state.workspaces.find((workspace) => workspace.id === workspaceId) || state.currentWorkspace,
  );
  if (restoreBrowserState) {
    state.browserPreferences = window.ShellXDriveBrowser.loadPreferences(
      localStorage,
      currentAccountEmail(),
      workspaceId,
    );
    state.browserPreferenceWorkspaceId = workspaceId;
    state.activeFileFilter = state.browserPreferences.typeFilter;
    state.fileLayout = state.browserPreferences.layout;
    state.currentFolderId = state.browserPreferences.folderId;
    state.browserPage = 0;
    state.bulkSelectedIds = [];
    state.workspaceShares = [];
  } else if (previousWorkspaceId !== workspaceId) {
    state.currentFolderId = null;
    state.browserPage = 0;
    state.bulkSelectedIds = [];
    state.workspaceShares = [];
  } else {
    state.bulkSelectedIds = state.bulkSelectedIds.filter((id) =>
      state.files.some((file) => file.id === id),
    );
  }
  state.selectedFile = state.files.find((file) => file.id === state.selectedFile?.id) || null;
  if (!state.selectedFile) {
    state.selectedComments = [];
  }
  await loadWorkspaceTree(workspaceId, isCurrent).catch((error) => {
    if (!isCurrent()) return;
    state.folderTree = null;
    els.selectedMeta.textContent = error.message;
  });
  if (!isCurrent()) return false;
  state.browserPreferences = window.ShellXDriveBrowser.normalizePreferences({
    ...state.browserPreferences,
    folderId: state.currentFolderId,
    layout: state.fileLayout,
    typeFilter: state.activeFileFilter,
  });
  persistBrowserPreferences();
  syncBrowserControls();
  setViewMode(state.fileLayout);
  await loadWorkspaceShareState(workspaceId, isCurrent).catch(() => {
    if (!isCurrent()) return;
    // Share badges are useful context, not a reason to block the file browser.
    // A read-only member cannot call the writer-only listing route.
    state.workspaceShares = [];
  });
  if (!isCurrent()) return false;
  renderFiles();
  renderSelection();
  if (state.selectedFile && !state.selectedFile.trashed) {
    await collaboration.loadSelectedGuestLinks(state.selectedFile, { preserveForm: true }).catch(() => {});
    if (!isCurrent()) return false;
  }
  // Refresh the sidebar space-usage gauge (fire-and-forget; updates when ready).
  refreshWorkspaceUsage();
  await loadFolderTemplates(workspaceId, isCurrent).catch((error) => {
    if (!isCurrent()) return;
    els.templateOutput.textContent = error.message;
  });
  if (!isCurrent()) return false;
  await mobileSync.loadManifest({ workspaceId, isCurrent }).catch((error) => {
    if (!isCurrent()) return;
    els.mobileOutput.textContent = error.message;
  });
  if (!isCurrent()) return false;
  await loadUploadSessions(workspaceId, isCurrent).catch((error) => {
    if (!isCurrent()) return;
    els.uploadStatus.textContent = error.message;
  });
  if (!isCurrent()) return false;
  await browserUploads?.activate().catch((error) => {
    if (!isCurrent()) return;
    els.uploadStatus.textContent = error.message;
  });
  if (!isCurrent()) return false;
  if (canManageCurrentWorkspace()) {
    await loadMembers(workspaceId, isCurrent);
    if (!isCurrent()) return false;
    await loadWorkspaceInvitations(workspaceId, isCurrent);
    if (!isCurrent()) return false;
    await loadManagedDrops(workspaceId, isCurrent);
  } else {
    if (!isCurrent()) return false;
    state.members = [{ email: "Member management requires owner role", role: "read-only" }];
    state.workspaceInvitations = [];
    state.managedDrops = [];
    renderMembers();
    renderWorkspaceInvitations();
    renderManagedDrops();
  }
  return isCurrent();
}

async function loadTrashFiles(workspaceId = state.currentWorkspace?.id) {
  if (!workspaceId || state.activeView !== "trash") return false;
  const data = await api("/files");
  if (state.currentWorkspace?.id !== workspaceId || state.activeView !== "trash") return false;
  state.trashFiles = (data.files || []).filter(
    (file) => file.workspace_id === workspaceId && file.trashed,
  );
  state.currentViewTitle = "Trash";
  renderFiles(state.trashFiles);
  return true;
}

async function loadWorkspaceShareState(
  workspaceId = state.currentWorkspace?.id,
  isCurrent = () => true,
) {
  return collaboration.loadWorkspaceShareState(workspaceId, isCurrent);
}

async function loadWorkspaceTree(
  workspaceId = state.currentWorkspace?.id,
  isCurrent = () => true,
) {
  if (!workspaceId) {
    if (!isCurrent()) return null;
    state.folderTree = null;
    renderFolderBreadcrumb();
    return null;
  }
  const data = await api(`/workspaces/${workspaceId}/tree`);
  if (!isCurrent()) return null;
  state.folderTree = data;
  if (state.currentFolderId && !currentFolderNode()) {
    state.currentFolderId = null;
  }
  renderFolderBreadcrumb();
  return data;
}

async function loadMembers(workspaceId, isCurrent = () => true) {
  try {
    const data = await api(`/workspaces/${workspaceId}/members`);
    if (!isCurrent()) return [];
    state.members = data.members || [];
  } catch (error) {
    if (window.ShellXDriveAuthLifecycle.isStale(error)) throw error;
    if (!isCurrent()) return [];
    state.members = [{ email: error.message, role: "unavailable" }];
  }
  renderMembers();
  renderManagedShares();
  renderManagedDrops();
  return state.members;
}

async function loadWorkspaceInvitations(
  workspaceId = state.currentWorkspace?.id,
  isCurrent = () => true,
) {
  return collaboration.loadWorkspaceInvitations(workspaceId, isCurrent);
}

function canManageCurrentWorkspace() {
  return !state.actor || Boolean(state.currentAccount?.is_admin) || state.currentWorkspace?.role === "owner";
}

function canWriteCurrentWorkspace() {
  return (
    !state.actor ||
    Boolean(state.currentAccount?.is_admin) ||
    ["owner", "editor"].includes(state.currentWorkspace?.role)
  );
}

function selectedActionCapability(name) {
  const actions = state.selectedFile?.action_capabilities || state.selectedFile?.capabilities || state.selectedFile?.actions;
  return actions?.[name] === true;
}

function canWriteSelectedFile() {
  return !isAccountBrowseView() && (!state.selectedFile?.workspace_id || state.selectedFile.workspace_id === state.currentWorkspace?.id) && canWriteCurrentWorkspace();
}
function renderWorkspaces() {
  els.workspaceList.replaceChildren();
  for (const workspace of state.workspaces) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "workspace-item";
    button.dataset.workspaceId = workspace.id;
    if (workspace.id === state.currentWorkspace?.id) {
      button.classList.add("active");
    }
    button.innerHTML = `
      <span>
        <strong>${escapeHtml(workspace.name)}</strong>
        <span class="workspace-mode">Files and folders</span>
      </span>
      <span class="workspace-state">${workspace.id === state.currentWorkspace?.id ? "Current" : "Switch"}</span>
    `;
    button.addEventListener("click", async () => {
      setCurrentWorkspace(workspace);
      state.currentFolderId = null;
      state.bulkSelectedIds = [];
      state.retentionPreview = null;
      setActiveView("my-drive");
      if (!await loadManifest(workspace.id)) return;
      rememberWorkspace(workspace.id);
      if (["storage", "sharing"].includes(state.activeAdminSection)) {
        loadWorkspacePolicyAndUsage().catch((error) => {
          els.adminOutput.textContent = error.message;
        });
      }
      if (state.activeAdminSection === "cleanup") {
        renderRetentionCleanup();
      }
      renderWorkspaces();
    });
    els.workspaceList.append(button);
  }
  renderStorageSummary();
  if (state.groupsData) {
    renderGroups();
  }
}

function browserOrganizeContext() {
  return {
    currentWorkspaceId: state.currentWorkspace?.id || "",
    currentFolderId: state.currentFolderId,
    workspaceRoleById: new Map(
      state.workspaces.map((workspace) => [workspace.id, workspace.role || null]),
    ),
    nodesById: fileNodesById(),
    sharedIds: new Set(
      (state.workspaceShares || [])
        .filter((share) => isActiveShare(share))
        .map((share) => share.file_id),
    ),
    offlineIds: new Set(state.files.filter((file) => isOfflineMarked(file)).map((file) => file.id)),
  };
}

function renderFilePagination(page) {
  if (!els.filePagination) return;
  if (isAccountBrowseView()) {
    const hasServerNextPage = Boolean(state.browseNextCursor);
    els.filePagination.hidden = state.browsePageIndex === 0 && !hasServerNextPage;
    els.filePagePrevious.disabled = state.browsePageIndex === 0 || state.browseLoading;
    els.filePageNext.disabled = !hasServerNextPage || state.browseLoading;
    els.filePagePosition.textContent = `Page ${state.browsePageIndex + 1}`;
    return;
  }
  const hasNextPage = page.page < page.pageCount - 1;
  els.filePagination.hidden = page.pageCount <= 1;
  els.filePagePrevious.disabled = page.page <= 0;
  els.filePageNext.disabled = !hasNextPage || state.browseLoading;
  els.filePagePosition.textContent = `Page ${page.page + 1} of ${page.pageCount}`;
}

function renderFiles(files = state.files) {
  const baseFiles = Array.isArray(files) ? files : state.files;
  const accountBrowse = isAccountBrowseView();
  syncBrowserControls();
  state.currentBaseFiles = baseFiles;
  state.hasCurrentBaseFiles = true;
  const browseAcrossLocations =
    state.activeView === "my-drive" &&
    !state.currentViewTitle &&
    state.browserPreferences.locationScope !== "any";
  const workspaceCollectionView = ["starred", "offline", "trash"].includes(state.activeView);
  const scopedFiles =
    browseAcrossLocations || workspaceCollectionView ? baseFiles : filesInCurrentFolder(baseFiles);
  const filteredFiles = filterFilesForContent(scopedFiles);
  state.browserPreferences = window.ShellXDriveBrowser.normalizePreferences({
    ...state.browserPreferences,
    typeFilter: state.activeFileFilter,
  });
  // Account-wide pages use server-owned keysets. Re-sorting one fetched page
  // locally would make its next cursor lie about the order, so preserve the
  // server's folder/name ordering (or chronological Recent ordering) exactly.
  const orderedFiles =
    accountBrowse
      ? filteredFiles
      : window.ShellXDriveBrowser.organize(
          filteredFiles,
          state.browserPreferences,
          browserOrganizeContext(),
        );
  const page = window.ShellXDriveBrowser.paginate(orderedFiles, accountBrowse ? 0 : state.browserPage);
  state.browserPage = page.page;
  state.lastOrderedFiles = orderedFiles;
  const displayFiles = page.items;
  state.lastRenderedFiles = displayFiles;
  const bulkIds = selectedBulkIds();
  renderViewTitle(state.currentViewTitle);
  renderStorageSummary();
  renderFolderBreadcrumb();
  const filterSuffix =
    ["files", "shared-with-me", "shared-by-me"].includes(state.browseScope) || state.activeFileFilter === "all"
      ? "" : ` · ${filterLabel(state.activeFileFilter)}`;
  const folder = currentFolderNode();
  const folderSuffix =
    state.activeView === "my-drive" && !state.currentViewTitle && folder
      ? ` in ${folder.name}`
      : "";
  const pageSuffix = page.total > page.pageSize ? ` · Showing ${page.start}–${page.end}` : "";
  const countLabel = accountBrowse && state.browseNextCursor ? `${page.total}+` : page.total;
  els.fileCount.textContent = `${countLabel} ${page.total === 1 ? "item" : "items"}${filterSuffix}${folderSuffix}${pageSuffix}`;
  renderFilePagination(page);
  els.fileRows.replaceChildren();
  const canMove = !accountBrowse && canWriteCurrentWorkspace();
  for (const [index, file] of displayFiles.entries()) {
    const row = document.createElement("tr");
    row.className = `file-row-main${file.id === state.selectedFile?.id ? " selected" : ""}`;
    row.dataset.fileId = file.id;
    row.dataset.fileKind = file.kind;
    // Rows are draggable so files can be dragged onto folders to move them
    // when they are live rows in a writable workspace.
    if (canMove && !file.trashed) row.draggable = true;
    const selected = !accountBrowse && bulkIds.has(file.id);
    const folderOpenAction =
      file.kind === "folder" &&
      !file.trashed &&
      !accountBrowse &&
      ((state.activeView === "my-drive" && !state.currentViewTitle) || Boolean(state.currentWorkspace?.scoped_root));
    // The star is a real toggle button on every row (issue: the row star did
    // nothing and could not be turned off). Filled + green when starred, an
    // outline that reveals on hover/focus when not — click toggles either way.
    const starMark = accountBrowse
      ? ""
      : `<button type="button" class="row-star-toggle${file.starred ? " is-starred" : ""}" data-star-toggle aria-pressed="${file.starred}" aria-label="${file.starred ? "Unstar" : "Star"} ${escapeHtml(file.name)}" title="${file.starred ? "Starred — click to remove" : "Star this item"}"><svg class="icon" aria-hidden="true"><use href="#${file.starred ? "i-star-fill" : "i-star"}"/></svg></button>`;
    // Grid tiles show a content preview (Google-Drive style): images already
    // render a thumbnail; text/markdown files get a first-lines snippet fetched
    // async (hydrateGridSnippets). Eligible = a previewable text-ish type.
    const typeInfo = fileTypeInfo(file);
    const snippetEligible =
      !typeInfo.isFolder && ["text", "markdown"].includes(typeInfo.preview);
    const sizeLabel = displayFileSize(file);
    const exactSizeLabel = exactFileSizeLabel(file);
    row.innerHTML = `
      <td><input class="row-checkbox" type="checkbox" data-file-checkbox="${escapeHtml(file.id)}" ${selected ? "checked" : ""} ${accountBrowse ? "disabled" : ""} aria-label="Select ${escapeHtml(file.name)}" /></td>
      <td>
        <div class="file-name-cell${snippetEligible ? " has-snippet" : ""}">
          ${renderFileIcon(file)}
          ${snippetEligible ? `<div class="grid-snippet" data-grid-snippet aria-hidden="true"></div>` : ""}
          <span class="name-wrap">
            <strong title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</strong>
            ${renderBrowseAccessBadge(file)}
            ${renderSharedItemBadge(file)}
            ${starMark}
          </span>
          <span class="grid-file-meta" title="${escapeHtml(exactSizeLabel)}" aria-label="${escapeHtml(exactSizeLabel)}">${escapeHtml(fileKindLabel(file))} · ${escapeHtml(sizeLabel)}</span>
        </div>
        <button class="grid-kebab-button" type="button" data-grid-kebab aria-haspopup="menu" aria-expanded="false" aria-label="Actions for ${escapeHtml(file.name)}" title="Actions for ${escapeHtml(file.name)}"><svg class="icon" aria-hidden="true"><use href="#i-kebab"/></svg></button>
      </td>
      <td class="file-type-label">${escapeHtml(fileKindLabel(file))}</td>
      <td class="file-modified" data-compact-date="${escapeHtml(compactDate(file.updated_at))}">${escapeHtml(formatDate(file.updated_at))}</td>
      <td class="file-size" title="${escapeHtml(exactSizeLabel)}" aria-label="${escapeHtml(exactSizeLabel)}">${escapeHtml(sizeLabel)}</td>
      <td class="row-actions"><button class="row-action-button" type="button" aria-haspopup="menu" aria-expanded="false" aria-label="Actions for ${escapeHtml(file.name)}" title="Actions for ${escapeHtml(file.name)}"><svg class="icon" aria-hidden="true"><use href="#i-kebab"/></svg></button></td>
    `;
    row.addEventListener("click", (event) => {
      if (accountBrowse) {
        event.preventDefault();
        state.bulkSelectedIds = [];
        selectFile({ ...file, action_capabilities: {} }, baseFiles);
        return;
      }
      handleRowClick(event, file, index, baseFiles);
    });
    row.addEventListener("dblclick", () => {
      if (accountBrowse) {
        openBrowseFileLocation(file).catch((error) => showToast(error.message));
        return;
      }
      if (folderOpenAction) {
        openFolder(file.id);
      } else if (fileTypeInfo(file).previewable) {
        if (Date.now() < state.suppressPreviewUntil) return;
        openPreviewModal(file, row);
      }
    });
    // --- Internal drag source -------------------------------------------
    // A row-drag carries a CUSTOM MIME type only (never "Files"), so the
    // main-drive UPLOAD drop handler — which guards on `types.includes("Files")`
    // — ignores it. Dragging a row that is part of the current multi-selection
    // moves the whole selection; otherwise it moves just that row.
    if (!accountBrowse) {
      row.addEventListener("dragstart", (event) => beginRowDrag(event, file));
      row.addEventListener("dragend", clearRowDropTargets);
    }
    // --- Folder rows are internal drop targets ---------------------------
    if (file.kind === "folder" && !file.trashed && canMove) {
      row.addEventListener("dragover", (event) => handleFolderRowDragOver(event, file));
      row.addEventListener("dragleave", (event) => handleFolderRowDragLeave(event, row));
      row.addEventListener("drop", (event) => handleFolderRowDrop(event, file));
    }
    row.querySelector("[data-file-checkbox]").addEventListener("click", (event) => {
      event.stopPropagation();
      if (!accountBrowse) toggleBulkSelection(file.id, event.currentTarget.checked);
    });
    row.querySelector("[data-star-toggle]")?.addEventListener("click", (event) => {
      // Toggle the star without selecting the row or starting a drag.
      event.stopPropagation();
      event.preventDefault();
      toggleFileStar(file).catch((error) => showToast(error.message));
    });
    row.querySelector(".row-action-button").addEventListener("click", (event) => {
      event.stopPropagation();
      // Capture the anchor rect BEFORE selectFile() — it re-renders the rows and
      // detaches this button, which would zero out getBoundingClientRect().
      const rect = event.currentTarget.getBoundingClientRect();
      if (accountBrowse) {
        openBrowseFileLocation(file).catch((error) => showToast(error.message));
      } else {
        selectFile(file, baseFiles);
        openFileMenu(file, rect);
      }
    });
    // Grid-view tiles carry their own kebab (the list `.row-actions` cell is
    // hidden in grid). It opens the SAME #file-context-menu with identical
    // kind/role/trash-aware actions, so per-file actions are reachable from a
    // tile exactly as from a row.
    row.querySelector("[data-grid-kebab]")?.addEventListener("click", (event) => {
      event.stopPropagation();
      const rect = event.currentTarget.getBoundingClientRect();
      if (accountBrowse) {
        openBrowseFileLocation(file).catch((error) => showToast(error.message));
      } else {
        selectFile(file, baseFiles);
        openFileMenu(file, rect);
      }
    });
    els.fileRows.append(row);
  }
  wireThumbnailFallbacks(els.fileRows);
  renderBulkActionToolbar();
  renderSelectionSummary();
  applyUiState();
  hydrateGridSnippets();
}

function filterLabel(filter) {
  return (
    {
      folders: "Folders",
      docs: "Docs",
      sheets: "Sheets",
      pdfs: "PDFs",
      images: "Images",
      videos: "Videos",
      audio: "Audio",
      archives: "Archives",
    }[filter] || "All"
  );
}

function clearRailViewSelection() {
  state.searchRequestSequence += 1;
  state.bulkSelectedIds = [];
  state.selectionAnchorIndex = null;
  resetSelectedFileState();
  renderFileRowSelectionState();
  renderSelection();
}

/* ============================================================================
 * Row selection + internal drag-to-move
 * ==========================================================================*/

// Plain click = single select (inspector). Ctrl/Cmd+click toggles a row in the
// multi-selection. Shift+click selects the contiguous range from the anchor
// (last plain/ctrl click) to the clicked row. The multi-selection is the same
// `state.bulkSelectedIds` set the checkboxes + bulk toolbar already use.
function handleRowClick(event, file, index, baseFiles) {
  const additive = event.ctrlKey || event.metaKey;
  const rangeSelect = event.shiftKey;
  const rendered = state.lastRenderedFiles || [];

  if (rangeSelect && state.selectionAnchorIndex != null && rendered.length) {
    event.preventDefault(); // suppress the browser's text selection on shift-click
    const lo = Math.min(state.selectionAnchorIndex, index);
    const hi = Math.max(state.selectionAnchorIndex, index);
    state.bulkSelectedIds = rendered.slice(lo, hi + 1).map((f) => f.id);
    selectFile(file, baseFiles); // inspector follows the clicked row; re-renders
    return;
  }

  if (additive) {
    const ids = selectedBulkIds();
    // Seed the multi-selection with the currently single-selected file so the
    // first Ctrl+click yields a 2-item selection (owner's expectation).
    if (ids.size === 0 && state.selectedFile && state.selectedFile.id !== file.id) {
      ids.add(state.selectedFile.id);
    }
    if (ids.has(file.id)) ids.delete(file.id);
    else ids.add(file.id);
    state.bulkSelectedIds = [...ids];
    state.selectionAnchorIndex = index;
    selectFile(file, baseFiles);
    return;
  }

  // Plain click: single selection, reset multi-selection + anchor.
  state.selectionAnchorIndex = index;
  state.bulkSelectedIds = [];
  selectFile(file, baseFiles);
}

// Selection-only changes must not replace the table rows. Replacing a folder
// row after the first click destroys the browser's double-click target, and an
// asynchronous share lookup could repeat that replacement at any later point.
function renderFileRowSelectionState() {
  const bulkIds = selectedBulkIds();
  for (const row of els.fileRows.querySelectorAll("tr[data-file-id]")) {
    const fileId = row.dataset.fileId || "";
    row.classList.toggle("selected", fileId === state.selectedFile?.id);
    const checkbox = row.querySelector("[data-file-checkbox]");
    if (checkbox) checkbox.checked = bulkIds.has(fileId);
  }
  renderBulkActionToolbar();
}
function resetSelectedFileState() {
  collaboration?.clearInvitationLink();
  state.selectedFile = null;
  state.selectedBaseRevision = null;
  state.selectedMetadata = null;
  state.selectedPreview = null;
  state.selectedRevisions = [];
  state.selectedRevisionStorage = null;
  state.selectedComments = [];
  state.latestShareUrl = "";
  state.latestShareMeta = null;
  state.managedShares = [];
  state.selectedShareId = "";
  state.officeProviderStatus = null;
  els.selectedContent.value = "";
}

// Custom drag payload type: an INTERNAL row drag sets this and NOT "Files", so
// the main-drive upload drop handler (which requires "Files") never fires for it.
const INTERNAL_DRAG_TYPE = "application/x-shellx-file-ids";

// Which file ids does a drag of `file` carry? If the dragged row is part of a
// multi-selection, the whole selection moves; otherwise just that row.
function dragPayloadIds(file) {
  const bulk = selectedBulkIds();
  if (bulk.size > 1 && bulk.has(file.id)) return [...bulk];
  return [file.id];
}

function beginRowDrag(event, file) {
  if (!canWriteCurrentWorkspace() || file.trashed) {
    event.preventDefault();
    return;
  }
  const ids = dragPayloadIds(file);
  state.draggingFileIds = ids;
  if (event.dataTransfer) {
    event.dataTransfer.effectAllowed = "move";
    // Custom type ONLY — deliberately no "Files", so upload drop zones ignore it.
    event.dataTransfer.setData(INTERNAL_DRAG_TYPE, JSON.stringify(ids));
  }
}

function isInternalRowDrag(event) {
  return Array.from(event.dataTransfer?.types || []).includes(INTERNAL_DRAG_TYPE);
}

function clearRowDropTargets() {
  state.draggingFileIds = null;
  document
    .querySelectorAll(".file-row-main.drop-target")
    .forEach((row) => row.classList.remove("drop-target"));
}

function handleFolderRowDragOver(event, folder) {
  if (!isInternalRowDrag(event)) return; // ignore external file-upload drags
  const dragging = state.draggingFileIds || [];
  if (dragging.includes(folder.id)) return; // can't drop a folder into itself
  event.preventDefault();
  if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
  event.currentTarget.classList.add("drop-target");
}

function handleFolderRowDragLeave(event, row) {
  // Only clear when the pointer truly left the row (not on child enter).
  if (row.contains(event.relatedTarget)) return;
  row.classList.remove("drop-target");
}

function handleFolderRowDrop(event, folder) {
  if (!isInternalRowDrag(event)) return;
  event.preventDefault();
  event.stopPropagation(); // don't let the main-drive handler treat this as an upload
  event.currentTarget.classList.remove("drop-target");
  let ids = state.draggingFileIds || [];
  const raw = event.dataTransfer?.getData(INTERNAL_DRAG_TYPE);
  if (raw) {
    try { ids = JSON.parse(raw); } catch { /* keep state fallback */ }
  }
  clearRowDropTargets();
  moveFilesToFolder(ids, folder).catch((error) => showToast(error.message));
}

// The dedicated controller owns destination discovery and collision policy. Keep
// these two adapters here because row drag/drop and bulk menus are composed by
// the root shell.
async function moveFilesToFolder(fileIds, folder) {
  return fileMoves.moveFilesToDestination(fileIds, folder.id, folder.name);
}

function openMoveDialog(fileIds) {
  fileMoves.openDialog(fileIds);
}

function closeMoveDialog() {
  fileMoves?.closeDialog();
}

function selectFile(file, filesForRender = state.hasCurrentBaseFiles ? state.currentBaseFiles : state.files) {
  const selectedFileId = file.id;
  const changedFile = state.selectedFile?.id !== file.id;
  state.selectedFile = file;
  state.selectedBaseRevision = null;
  state.selectedMetadata = null;
  state.selectedPreview = null;
  state.selectedRevisions = [];
  state.selectedRevisionStorage = null;
  state.selectedComments = [];
  if (changedFile) {
    state.latestShareUrl = "";
    state.latestShareMeta = null;
    state.managedShares = [];
    state.selectedShareId = "";
    state.officeProviderStatus = null;
  }
  els.selectedContent.value = "";
  // `filesForRender` is retained for callers that select from a derived view;
  // the already-rendered rows are the source of truth until the view changes.
  state.currentBaseFiles = filesForRender;
  state.hasCurrentBaseFiles = true;
  renderFileRowSelectionState();
  renderSelection();
  // Trashed entries intentionally leave the live-file capability surface.
  // Restore is the boundary back to metadata, preview, comments, sharing, and
  // revision routes, so do not generate predictable 404s while the item is in
  // Trash.
  if (file.trashed) return;
  collaboration.loadSelectedGuestLinks(file).catch((error) => {
    if (state.selectedFile?.id !== selectedFileId) return;
    renderAdminLiveList(els.shareManagementList, [["Shares", error.message]]);
  });
  loadSelectedMetadata().catch((error) => {
    if (state.selectedFile?.id !== selectedFileId) return;
    els.selectedMeta.textContent = error.message;
  });
  loadSelectedPreview().catch(() => {
    if (state.selectedFile?.id !== selectedFileId) return;
    // A preview/thumbnail fetch that 404s (or otherwise fails) must NEVER leak
    // the raw error body (e.g. `{"error":"not_found"}`) into the UI. Fall back
    // to a clean "No preview available" state; the file-type icon + Download
    // affordance still let the user act on it; raw error bodies stay hidden.
    state.selectedPreview = {
      kind: "preview_unavailable",
      content: "No preview available for this file type.",
      status: "unavailable",
    };
    renderSelectionSummary();
  });
  loadSelectedComments().catch((error) => {
    if (state.selectedFile?.id !== selectedFileId) return;
    renderComments([{ id: "comments-error", body: error.message, replies: [] }]);
  });
}

function clearSelection() {
  resetSelectedFileState();
  renderFileRowSelectionState();
  renderSelection();
  showToast("Selection cleared.");
}

// Reflect the selected file's starred state on the inspector star button:
// filled + green (`is-starred`) when starred, an outline otherwise. Keeps the
// inspector star in sync with the row star (issue: it never showed colored).
function renderInspectorStar() {
  const button = els.starButton;
  if (!button) return;
  const starred = Boolean(state.selectedFile?.starred);
  button.classList.toggle("is-starred", starred);
  button.setAttribute("aria-pressed", String(starred));
  button.setAttribute("aria-label", starred ? "Unstar file" : "Star file");
  const use = button.querySelector("use");
  if (use) use.setAttribute("href", starred ? "#i-star-fill" : "#i-star");
}

function renderSelection() {
  const file = state.selectedFile;
  document.body.dataset.selectedTrashed = String(Boolean(file?.trashed));
  els.selectedTitle.textContent = file ? file.name : "Nothing selected";
  renderInspectorStar();
  els.selectedMeta.textContent = file ? pretty(file) : "";
  els.fileDetailName.value = file ? file.name : "";
  renderParentOptions();
  renderMetadataInputs(state.selectedMetadata);
  renderRevisionOptions();
  renderComments(state.selectedComments);
  renderSelectionSummary();
  renderOfficeProviderStatus();
  setSelectionControlState();
  applyUiState();
}

function renderOfficeProviderStatus() {
  if (!els.officeProviderStatus) return;
  // Show the handoff hint when an online-editing provider is configured.
  if (!officeProviderAvailable()) {
    els.officeProviderStatus.hidden = true;
    els.officeProviderStatus.textContent = "";
    return;
  }
  els.officeProviderStatus.hidden = false;
  const providerName = state.officeProvider?.name || "your editor";
  const status = state.officeProviderStatus;
  if (!state.selectedFile) {
    els.officeProviderStatus.textContent = `Select a file to edit online with ${providerName}.`;
    return;
  }
  if (!status) {
    els.officeProviderStatus.textContent = `Online editing available with ${providerName}.`;
    return;
  }
  els.officeProviderStatus.textContent = status;
}

function renderSelectionSummary() {
  const file = state.selectedFile;
  if (!file) {
    els.selectionPreview.innerHTML = `
      <span class="empty-icon" aria-hidden="true">▢</span>
      <p>Select a file to preview details, share access, comments, and sync state.</p>
    `;
    els.activityList.innerHTML = `<div class="activity-item"><span class="activity-dot"></span><span>No file activity selected.</span></div>`;
    renderVersionsLog();
    els.mobileSheetSummary.innerHTML = `
      <strong>No file selected</strong>
      <span>Select a file to share, comment, or mark for mobile download.</span>
    `;
    renderShareSummary();
    return;
  }

  const commentCount = state.selectedComments.length;
  const labels = state.selectedMetadata?.labels?.length
    ? state.selectedMetadata.labels.join(", ")
    : "No labels";
  const previewText =
    file.trashed
      ? "This item is in Trash. Restore it to preview, download, share, edit, or view history."
      : file.kind === "folder"
      ? "Folder — open it to see what's inside."
      : "Ready to preview, share, comment, and track versions.";
  const previewBody = renderFilePreviewBody(file, state.selectedPreview, previewText);
  const activities = [
    `${file.name} updated ${compactDate(file.updated_at)}`,
    `${commentCount} ${commentCount === 1 ? "comment" : "comments"} on this file`,
    `${file.starred ? "Starred" : "Ready"} in ${state.currentViewTitle || "My Drive"}`,
  ];
  // Keep Details pinned above the collapsible Activity and Versions logs.
  els.selectionPreview.innerHTML = `
    <article class="preview-doc">
      <header>
        ${renderFileIcon(file)}
        <div>
          <strong>${escapeHtml(file.name)}</strong>
          <span class="file-subline">${escapeHtml(fileKindLabel(file))}</span>
        </div>
      </header>
      ${previewBody}
      <div class="preview-meta">
        <span>Type<strong>${escapeHtml(fileKindLabel(file))}</strong></span>
        <span>Modified<strong>${escapeHtml(formatDate(file.updated_at))}</strong></span>
        <span>Size<strong title="${escapeHtml(exactFileSizeLabel(file))}">${escapeHtml(displayFileSize(file))}</strong></span>
        <span>Labels<strong>${escapeHtml(labels)}</strong></span>
        <span>Comments<strong>${commentCount}</strong></span>
      </div>
    </article>
  `;

  els.selectionPreview.querySelectorAll("img.preview-image").forEach((img) =>
    img.addEventListener("error", () => img.remove(), { once: true }),
  );
  // Wire the inline Download affordance rendered in the "No preview available"
  // fallback, routing failures to a toast.
  els.selectionPreview.querySelectorAll("[data-preview-download]").forEach((button) =>
    button.addEventListener("click", () =>
      triggerDownload(state.selectedFile).catch((error) => showToast(error.message)),
    ),
  );

  els.activityList.replaceChildren(
    ...activities.map((item) => {
      const row = document.createElement("div");
      row.className = "activity-item";
      row.innerHTML = `<span class="activity-dot"></span><span>${escapeHtml(item)}</span>`;
      return row;
    }),
  );
  renderVersionsLog();

  els.mobileSheetSummary.innerHTML = `
    <strong>${escapeHtml(file.name)}</strong>
    <span>${escapeHtml(fileKindLabel(file))} · updated ${escapeHtml(compactDate(file.updated_at))}</span>
  `;
  renderShareSummary();
}

// Populate the collapsible Versions log at the bottom of the inspector (issue
// #7). Revisions are lazily fetched the first time the section is expanded.
function renderVersionsLog() {
  collaboration.renderVersionsLog();
}

function renderFilePreviewBody(file, preview, fallbackText) {
  if (!preview) {
    return `<p>${escapeHtml(fallbackText)}</p>`;
  }
  if (preview.kind === "image_thumbnail" && file?.kind === "file") {
    const thumbnailSrc = `/files/${state.selectedFile.id}/thumbnail`;
    return `
      <img class="preview-image" src="${thumbnailSrc}" alt="${escapeHtml(file.name)} thumbnail" />
      <p>${escapeHtml(preview.content || "Image preview ready.")}</p>
    `;
  }
  if (preview.kind === "text_excerpt") {
    return `<p>${escapeHtml(preview.content || fallbackText)}</p>`;
  }
  if (preview.kind === "preview_unavailable" || preview.kind === "preview_pending") {
    const pending = preview.status === "pending";
    // Clean, never-raw fallback: heading + human message. For a genuinely
    // unavailable preview (not a transient pending state) offer a Download
    // affordance so a non-previewable file (e.g. an .exe) is still actionable.
    const downloadAffordance =
      !pending && file?.kind === "file"
        ? `<button type="button" class="preview-download-inline" data-preview-download><svg class="icon" aria-hidden="true"><use href="#i-download"/></svg><span>Download</span></button>`
        : "";
    return `
      <div class="preview-unavailable">
        <strong>${escapeHtml(pending ? "Preview pending" : "No preview available")}</strong>
        <span>${escapeHtml(preview.content || fallbackText)}</span>
        ${downloadAffordance}
      </div>
    `;
  }
  return `<p>${escapeHtml(preview.content || fallbackText)}</p>`;
}

function setSelectionControlState() {
  const hasFile = Boolean(state.selectedFile);
  const hasLoadedRevision = state.selectedBaseRevision !== null;
  const hasSelectedRevision = Boolean(els.revisionSelect.value);
  const selectedRevision = collaboration.selectedRevision();
  const selectedIsFolder = state.selectedFile?.kind === "folder";
  const selectedTrashed = Boolean(state.selectedFile?.trashed);
  const hasLiveFile = hasFile && !selectedTrashed;
  const canWrite = hasFile && canWriteSelectedFile();
  const canCreate = Boolean(state.currentWorkspace) && canWriteCurrentWorkspace();
  els.fileDetailName.disabled = !hasLiveFile || !canWrite;
  els.fileParentSelect.disabled = !hasLiveFile || !canWrite || state.currentWorkspace?.scoped_root?.id === state.selectedFile?.id;
  els.fileLabels.disabled = !hasLiveFile || !canWrite;
  els.fileMetadata.disabled = !hasLiveFile || !canWrite;
  els.saveFileDetailsButton.disabled = !hasLiveFile || !canWrite;
  els.copyFileButton.disabled = !hasLiveFile || !canWrite;
  els.selectedContent.disabled = !hasFile || selectedIsFolder || !hasLoadedRevision;
  // Show "Edit online" when an online-editing provider exists and the user can write.
  els.openEditorButton.hidden = !officeProviderAvailable() || !canWrite;
  els.openEditorButton.disabled = !hasLiveFile || selectedIsFolder || !canWrite;
  els.loadContentButton.disabled = !hasLiveFile || selectedIsFolder;
  els.downloadButton.disabled = !hasLiveFile;
  els.downloadFolderZipButton.disabled = !hasLiveFile || !selectedIsFolder;
  els.starButton.disabled = !hasLiveFile || isAccountBrowseView();
  els.closeSelectionButton.disabled = !hasFile;
  els.saveContentButton.disabled = !hasFile || selectedIsFolder || !hasLoadedRevision || !canWrite;
  els.loadRevisionsButton.disabled = !hasLiveFile || selectedIsFolder;
  els.revisionSelect.disabled = !hasFile || state.selectedRevisions.length === 0;
  els.restoreRevisionButton.disabled = !hasFile || !hasSelectedRevision || !canWrite;
  els.revisionPinButton.disabled = !hasFile || !hasSelectedRevision || !canWrite;
  els.revisionUnpinButton.disabled = !hasFile || !hasSelectedRevision || !canWrite;
  els.revisionDownloadButton.disabled = !hasFile || !selectedRevision?.has_content;
  els.revisionDeleteButton.disabled =
    !hasFile || !selectedRevision || selectedRevision.current || selectedRevision.pinned || !canWrite;
  els.revisionPruneButton.disabled = !hasFile || !canWriteSelectedFile() || !canManageCurrentWorkspace();
  els.clearFileLabelsButton.disabled =
    !hasFile || !canWrite || !(state.selectedMetadata?.labels || []).length;
  // A live item can be moved to trash; a trashed item can be restored or deleted
  // permanently. Show the actions for the selected item's current lifecycle
  // state, and hide all three when nothing is selected.
  els.trashButton.hidden = !hasFile || selectedTrashed;
  els.restoreButton.hidden = !hasFile || !selectedTrashed;
  els.deletePermanentlyButton.hidden = !hasFile || !selectedTrashed;
  els.trashButton.disabled = !hasFile || !canWrite;
  els.restoreButton.disabled = !hasFile || !canWrite;
  const canOpenShareDrawer = hasLiveFile && ["manage_human_sharing", "manage_guest_links", "manage_ai_access"].some(selectedActionCapability);
  const guestOptions = els.shareForm.closest("details.share-options");
  if (guestOptions) {
    guestOptions.hidden = !hasLiveFile || !selectedActionCapability("manage_guest_links") || state.selectedFile?.guest_link_lookup?.status !== "loaded";
    if (!hasLiveFile || state.selectedFile?.action_capabilities?.manage_guest_links === false) guestOptions.open = false;
  }
  els.openShareDrawerButton.disabled = !canOpenShareDrawer;
  els.openShareDrawerButton.title = canOpenShareDrawer ? "Share" : "Sharing is not available for this access role.";
  els.bottomShareButton.disabled = !canOpenShareDrawer;
  els.bottomShareButton.title = canOpenShareDrawer ? "Share" : "Sharing is not available for this access role.";
  els.bottomDownloadButton.disabled = !hasLiveFile;
  els.bottomOpenButton.disabled = !hasLiveFile;
  els.commentBody.disabled = !canWrite || selectedTrashed;
  els.commentForm.querySelector("button").disabled = !canWrite || selectedTrashed;
  els.mobileOfflineButton.disabled = !hasLiveFile || isAccountBrowseView();
  els.mobileOnlineButton.disabled = !hasLiveFile || isAccountBrowseView();
  if (els.createFolderName) {
    els.createFolderName.disabled = !canCreate;
  }
  if (els.createFolderButton) {
    els.createFolderButton.disabled = !canCreate;
  }
  document.querySelectorAll("[data-mobile-action]").forEach((button) => {
    button.disabled = !hasFile || (button.dataset.mobileAction === "offline" && isAccountBrowseView());
  });
  renderBulkActionToolbar();
}

function renderParentOptions() {
  els.fileParentSelect.replaceChildren();
  const scopedRoot = state.currentWorkspace?.scoped_root;
  const root = document.createElement("option");
  root.value = scopedRoot?.kind === "folder" ? scopedRoot.id : "";
  root.textContent = scopedRoot?.kind === "folder" ? scopedRoot.name : "Root";
  els.fileParentSelect.append(root);
  if (isAccountBrowseView() || (state.selectedFile?.workspace_id && state.selectedFile.workspace_id !== state.currentWorkspace?.id)) {
    root.value = state.selectedFile?.parent_id || "";
    root.textContent = root.value ? "Current folder" : "Root";
    return;
  }
  if (!state.currentWorkspace || !state.selectedFile) return;
  for (const file of state.files) {
    if (
      file.workspace_id !== state.currentWorkspace.id ||
      file.id === state.selectedFile.id ||
      file.id === scopedRoot?.id ||
      file.trashed ||
      file.kind !== "folder"
    ) {
      continue;
    }
    const option = document.createElement("option");
    option.value = file.id;
    option.textContent = file.name;
    option.selected = file.id === state.selectedFile.parent_id;
    els.fileParentSelect.append(option);
  }
}

function renderMetadataInputs(metadata) {
  if (!state.selectedFile || !metadata) {
    els.fileLabels.value = "";
    els.fileMetadata.value = "";
    return;
  }
  els.fileLabels.value = (metadata.labels || []).join(", ");
  els.fileMetadata.value = pretty(metadata.custom_metadata || {});
}

function renderRevisionOptions() {
  collaboration.renderRevisionOptions();
}

function renderComments(comments = []) {
  collaboration.renderComments(comments);
}

async function loadSelectedComments() {
  return collaboration.loadSelectedComments();
}

function renderFolderTemplates() {
  els.templateList.replaceChildren();
  els.templateSelect.replaceChildren();
  for (const template of state.folderTemplates) {
    const row = document.createElement("article");
    row.className = "template-row";
    row.innerHTML = `
      <header><span>${escapeHtml(template.name)}</span><span>${(template.items || []).length} items</span></header>
      <div class="template-body">${escapeHtml(template.description || template.id)}</div>
    `;
    els.templateList.append(row);

    const option = document.createElement("option");
    option.value = template.id;
    option.textContent = template.name;
    els.templateSelect.append(option);
  }
  const canWrite = Boolean(state.currentWorkspace) && canWriteCurrentWorkspace();
  els.templateName.disabled = !canWrite;
  els.templateDescription.disabled = !canWrite;
  els.templateItems.disabled = !canWrite;
  els.templateForm.querySelector("button").disabled = !canWrite;
  els.templateSelect.disabled = !canWrite || state.folderTemplates.length === 0;
  els.templateRootName.disabled = !canWrite || state.folderTemplates.length === 0;
  els.applyTemplateButton.disabled = !canWrite || state.folderTemplates.length === 0;
  els.mobileManifestButton.disabled = !state.currentWorkspace;
  els.importBundle.disabled = !canWrite;
  els.importBundleButton.disabled = !canWrite;
  els.exportBundleButton.disabled = !state.currentWorkspace;
}

async function loadFolderTemplates(
  workspaceId = state.currentWorkspace?.id,
  isCurrent = () => true,
) {
  if (!workspaceId) {
    if (!isCurrent()) return [];
    state.folderTemplates = [];
    renderFolderTemplates();
    return [];
  }
  const data = await api(`/workspaces/${workspaceId}/folder-templates`);
  if (!isCurrent()) return [];
  state.folderTemplates = data.templates || [];
  renderFolderTemplates();
  return state.folderTemplates;
}

async function createFolderTemplate(event) {
  event.preventDefault();
  if (!state.currentWorkspace || !canWriteCurrentWorkspace()) return;
  const name = els.templateName.value.trim();
  const itemsText = els.templateItems.value.trim();
  if (!name || !itemsText) return;
  const data = await api(`/workspaces/${state.currentWorkspace.id}/folder-templates`, {
    method: "POST",
    body: JSON.stringify({
      name,
      description: els.templateDescription.value.trim() || null,
      items: JSON.parse(itemsText),
    }),
  });
  els.templateName.value = "";
  els.templateDescription.value = "";
  els.templateItems.value = "";
  els.templateOutput.textContent = pretty(data);
  await loadFolderTemplates();
  await loadAdminSummary().catch((error) => {
    els.adminOutput.textContent = error.message;
  });
  showToast("Template created.");
}

async function applyFolderTemplate() {
  if (!state.currentWorkspace || !els.templateSelect.value || !canWriteCurrentWorkspace()) return;
  const data = await api(
    `/workspaces/${state.currentWorkspace.id}/folder-templates/${els.templateSelect.value}/apply`,
    {
      method: "POST",
      body: JSON.stringify({
        root_name: els.templateRootName.value.trim() || null,
      }),
    },
  );
  els.templateOutput.textContent = pretty(data);
  els.templateRootName.value = "";
  await loadManifest(state.currentWorkspace.id);
  await loadWorkspacePolicyAndUsage().catch((error) => {
    els.storagePolicyOutput.textContent = error.message;
  });
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast("Template applied.");
}

function renderMembers() {
  els.memberList.replaceChildren();
  for (const member of state.members) {
    const row = document.createElement("div");
    row.className = "member-row";
    const initials = initialsForEmail(member.email);
    row.innerHTML = `
      <span class="member-identity">
        <span class="avatar">${escapeHtml(initials || "?")}</span>
        <span>${escapeHtml(member.email)}</span>
      </span>
      <span class="member-role">${escapeHtml(titleCase(member.role))}${member.expires_at ? ` · until ${escapeHtml(compactDate(member.expires_at))}` : ""}</span>
    `;
    els.memberList.append(row);
  }
  const canManage = Boolean(state.currentWorkspace) && canManageCurrentWorkspace();
  els.workspaceInvitationEmail.disabled = !canManage;
  els.workspaceInvitationRole.disabled = !canManage;
  els.workspaceInvitationButton.disabled = !canManage;
  if (els.workspaceInvitationExpiry) {
    els.workspaceInvitationExpiry.disabled = !canManage || els.workspaceInvitationRole.value === "owner";
  }
  els.memberEmail.disabled = !canManage;
  els.memberRole.disabled = !canManage;
  els.memberRemoveEmail.disabled = !canManage;
  els.memberForm.querySelector("button").disabled = !canManage;
  els.memberRemoveForm.querySelector("button").disabled = !canManage;
}

function renderWorkspaceInvitations() {
  collaboration.renderWorkspaceInvitations();
}

async function loadAdminSummary() {
  const data = await api("/admin/summary");
  state.adminSummary = data;
  renderAdminSummary();
}

function renderAdminSummary() {
  const totals = state.adminSummary?.totals || {};
  const num = (value) => Number(value || 0).toLocaleString();
  renderAdminStats(els.adminMetrics, [
    ["Workspaces", num(totals.workspaces)],
    ["User accounts", num(totals.users)],
    ["Files", num(totals.files)],
    ["Folders", num(totals.folders)],
    ["Share links", num(totals.shares)],
    ["Upload drops", num(totals.drops)],
    ["Comments", num(totals.comments)],
    ["Templates", num(totals.folder_templates)],
  ]);
  renderAdminActivity();
  renderAdminStats(els.adminTeamsSummary, [
    ["User accounts", num(totals.users)],
    ["Members", num(totals.members)],
    ["Your role", titleCase(state.currentWorkspace?.role || "owner")],
  ]);
  renderAdminBackups();
  renderAdminSessions();
  renderWorkspacePolicyUsage();
}

function renderAdminActivity() {
  if (!els.adminOutput) return;
  if (!state.adminSummary) {
    renderAdminEmpty(els.adminOutput, "No activity loaded", "Refresh to see recent changes.");
    return;
  }
  adminClarity.renderActivity({
    element: els.adminOutput,
    summary: state.adminSummary,
    query: els.adminActivitySearch?.value,
    category: els.adminActivityFilter?.value,
    escapeHtml,
    relativeTime,
    renderEmpty: renderAdminEmpty,
  });
}

function loadWorkspacePolicyAndUsage() {
  if (state.currentWorkspace?.scoped_root) return Promise.resolve(null);
  return workspacePolicyController.load();
}

function renderWorkspacePolicyUsage() {
  const hasWorkspace = Boolean(state.currentWorkspace);
  const policy = state.workspacePolicy;
  const usage = state.workspaceUsage;
  const canManage = hasWorkspace && canManageCurrentWorkspace();

  const controls = [
    els.policyQuotaBytes,
    els.policyTrashRetentionDays,
    els.policyRevisionRetentionDays,
    els.policyPublicLinksEnabled,
    els.policyLinkPasswordRequired,
    els.policyAllowNeverExpire,
    els.policyMaxLinkTtlSeconds,
    els.policyDropPasswordRequired,
    els.policyMaxDropTtlSeconds,
  ];
  const saveControls = [
    els.storagePolicySaveButton,
    els.sharingPolicySaveButton,
  ];
  for (const control of controls) {
    if (control) control.disabled = !hasWorkspace || !canManage;
  }
  for (const control of saveControls) {
    if (control) control.disabled = !hasWorkspace || !canManage;
  }
  if (els.storagePolicyRefreshButton) {
    els.storagePolicyRefreshButton.disabled = !hasWorkspace;
  }

  if (!hasWorkspace) {
    renderAdminEmpty(els.adminStorageSummary, "No workspace selected", "Pick a workspace to see its storage usage.");
    renderAdminEmpty(els.adminSharingSummary, "No workspace selected", "Pick a workspace to see its sharing defaults.");
    renderAdminLiveList(els.storagePolicyOutput, [["Status", "No workspace selected"]]);
    renderAdminLiveList(els.sharingPolicyOutput, [["Status", "No workspace selected"]]);
    return;
  }

  if (!policy || !usage) {
    renderAdminStats(els.adminStorageSummary, [["Workspace", state.currentWorkspace.name], ["Usage", "Loading…"]]);
    renderAdminStats(els.adminSharingSummary, [["Workspace", state.currentWorkspace.name], ["Defaults", "Loading…"]]);
    return;
  }

  els.policyQuotaBytes.value = policy.quota_bytes == null
    ? ""
    : String(Math.round((Number(policy.quota_bytes) / (1024 ** 3)) * 10) / 10);
  els.policyTrashRetentionDays.value = policy.trash_retention_days ?? 30;
  els.policyRevisionRetentionDays.value = policy.revision_retention_days ?? 90;
  els.policyPublicLinksEnabled.value = String(policy.public_links_enabled);
  els.policyLinkPasswordRequired.value = String(policy.link_password_required);
  els.policyAllowNeverExpire.value = String(policy.allow_never_expire);
  els.policyMaxLinkTtlSeconds.value = policy.max_link_ttl_seconds ?? 2592000;
  els.policyDropPasswordRequired.value = String(policy.drop_password_required);
  els.policyMaxDropTtlSeconds.value = policy.max_drop_ttl_seconds ?? 2592000;

  renderAdminStats(els.adminStorageSummary, [
    ["In use", formatBytes(usage.current_file_bytes)],
    ["Quota", formatBytes(usage.quota_bytes)],
    ["Remaining", formatBytes(usage.remaining_bytes)],
    ["Version history", formatBytes(usage.revision_bytes)],
    ["In trash", formatBytes(usage.trashed_file_bytes)],
    ...window.ShellXDriveSettings.auxiliaryStorageRows(usage, formatBytes, hasAdminTools()),
  ]);
  renderAdminStats(els.adminSharingSummary, [
    ["Public links", policy.public_links_enabled ? "Allowed" : "Blocked", policy.public_links_enabled ? undefined : "warn"],
    ["Link passwords", policy.link_password_required ? "Required" : "Optional"],
    ["Permanent links", policy.allow_never_expire ? "Allowed" : "Blocked"],
    ["Link expiry", formatDurationSeconds(policy.max_link_ttl_seconds)],
    ["Drop passwords", policy.drop_password_required ? "Required" : "Optional"],
    ["Drop expiry", formatDurationSeconds(policy.max_drop_ttl_seconds)],
  ]);
  renderAdminLiveList(els.storagePolicyOutput, [
    ["Keeping trash", `${policy.trash_retention_days} days`],
    ["Keeping versions", `${policy.revision_retention_days} days`],
  ]);
  renderAdminLiveList(els.sharingPolicyOutput, [
    ["Last updated", relativeTime(policy.updated_at)],
  ]);
  syncShareExpiryControls();
}

function parseOptionalNumberInput(input) {
  const raw = input.value.trim();
  if (!raw) return null;
  return Number(raw);
}

function parseOptionalGigabytes(input) {
  const value = parseOptionalNumberInput(input);
  return value == null ? null : Math.round(value * (1024 ** 3));
}

function parseRequiredNumberInput(input) {
  const raw = input.value.trim();
  return raw ? Number(raw) : 0;
}

async function saveStoragePolicy(event) {
  event.preventDefault();
  const data = await workspacePolicyController.save({
    quota_bytes: parseOptionalGigabytes(els.policyQuotaBytes),
    trash_retention_days: parseRequiredNumberInput(els.policyTrashRetentionDays),
    revision_retention_days: parseRequiredNumberInput(els.policyRevisionRetentionDays),
  });
  if (!data) return;
  renderAdminLiveList(els.storagePolicyOutput, [
    ["Keeping trash", `${data.policy.trash_retention_days} days`],
    ["Keeping versions", `${data.policy.revision_retention_days} days`],
    ["Last updated", relativeTime(data.receipt?.created_at)],
  ]);
  showToast("Storage policy saved.");
}

async function saveSharingPolicy(event) {
  event.preventDefault();
  const data = await workspacePolicyController.save({
    public_links_enabled: els.policyPublicLinksEnabled.value === "true",
    link_password_required: els.policyLinkPasswordRequired.value === "true",
    allow_never_expire: els.policyAllowNeverExpire.value === "true",
    max_link_ttl_seconds: parseRequiredNumberInput(els.policyMaxLinkTtlSeconds),
    drop_password_required: els.policyDropPasswordRequired.value === "true",
    max_drop_ttl_seconds: parseRequiredNumberInput(els.policyMaxDropTtlSeconds),
  });
  if (!data) return;
  renderAdminLiveList(els.sharingPolicyOutput, [
    ["Last updated", relativeTime(data.receipt?.created_at)],
  ]);
  showToast("Sharing defaults saved.");
}

async function loadGroups() {
  const data = await api("/groups");
  state.groupsData = data;
  renderGroups();
  return data;
}

function renderGroups() {
  const groups = state.groupsData?.groups || [];
  const members = state.groupsData?.members || [];
  const grants = state.groupsData?.workspace_grants || [];
  const currentWorkspaceGrants = state.currentWorkspace
    ? grants.filter((grant) => grant.workspace_id === state.currentWorkspace.id)
    : [];
  renderAdminStats(els.adminTeamsSummary, [
    ["Teams", groups.length],
    ["Members", members.length],
    ["Grants here", currentWorkspaceGrants.length],
  ]);
  renderGroupOptions(els.groupMemberSelect, groups);
  renderGroupOptions(els.groupGrantSelect, groups);
  const hasGroups = groups.length > 0;
  const canGrant = hasGroups && Boolean(state.currentWorkspace) && canManageCurrentWorkspace();
  els.groupMemberSelect.disabled = !hasGroups;
  els.groupMemberEmail.disabled = !hasGroups;
  els.groupMemberAddButton.disabled = !hasGroups;
  els.groupGrantSelect.disabled = !canGrant;
  els.groupGrantRole.disabled = !canGrant;
  els.groupGrantButton.disabled = !canGrant;
  els.groupRevokeButton.disabled = !canGrant;
  if (!groups.length) {
    renderAdminEmpty(els.groupsOutput, "No teams yet", "Create a team below to grant several people access at once.");
    return;
  }
  const rows = groups.map((group) => {
    const memberCount = members.filter((member) => member.group_id === group.id).length;
    const grant = currentWorkspaceGrants.find((entry) => entry.group_id === group.id);
    const grantText = grant ? ` · can ${grant.role === "editor" ? "edit" : "view"} this workspace` : "";
    return [
      group.name,
      `${memberCount} ${memberCount === 1 ? "member" : "members"}${grantText}`,
    ];
  });
  renderAdminLiveList(els.groupsOutput, rows);
}

function renderGroupOptions(select, groups) {
  select.replaceChildren();
  if (groups.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No teams yet";
    select.append(option);
    return;
  }
  for (const group of groups) {
    const option = document.createElement("option");
    option.value = group.id;
    option.textContent = group.name;
    select.append(option);
  }
}

async function createGroup(event) {
  event.preventDefault();
  const name = els.groupName.value.trim();
  if (!name) return;
  await api("/groups", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
  els.groupName.value = "";
  els.groupsOutput.textContent = "Team saved.";
  await Promise.all([
    loadGroups(),
    loadAdminSummary().catch((error) => {
      els.adminOutput.textContent = error.message;
    }),
  ]);
  showToast("Team created.");
}

async function addGroupMember(event) {
  event.preventDefault();
  const groupId = els.groupMemberSelect.value;
  const email = els.groupMemberEmail.value.trim();
  if (!groupId || !email) return;
  await api(`/groups/${groupId}/members`, {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  els.groupMemberEmail.value = "";
  els.groupsOutput.textContent = "Team member saved.";
  await loadGroups();
  showToast("Team member added.");
}

async function grantGroupToCurrentWorkspace(event) {
  event.preventDefault();
  if (!state.currentWorkspace || !els.groupGrantSelect.value) return;
  await api(`/workspaces/${state.currentWorkspace.id}/group-grants`, {
    method: "POST",
    body: JSON.stringify({
      group_id: els.groupGrantSelect.value,
      role: els.groupGrantRole.value,
    }),
  });
  els.groupsOutput.textContent = "Workspace team grant saved.";
  await loadGroups();
  await loadWorkspaces().catch((error) => {
    els.adminOutput.textContent = error.message;
  });
  showToast("Workspace team grant saved.");
}

async function revokeGroupFromCurrentWorkspace() {
  if (!state.currentWorkspace || !els.groupGrantSelect.value) return;
  await api(
    `/workspaces/${state.currentWorkspace.id}/group-grants/${els.groupGrantSelect.value}`,
    { method: "DELETE" },
  );
  els.groupsOutput.textContent = "Workspace team grant revoked.";
  await loadGroups();
  showToast("Workspace team grant revoked.");
}

async function requestPasswordReset(event) {
  event.preventDefault();
  const email = els.passwordResetEmail.value.trim() || els.loginEmail.value.trim();
  if (!email) {
    setPasswordResetStatus("Enter your email first.");
    return;
  }
  const data = await publicApi("/auth/password/reset/request", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  els.passwordResetEmail.value = "";
  togglePasswordReset(false);
  setPasswordResetStatus(data.debug_token
    ? "Reset link queued in the local test mailbox."
    : "If the account exists, the request was queued for your Drive operator. This build does not send email.");
  showToast("Password reset request queued.");
}

async function loadCurrentAccount() {
  const data = await api("/auth/me");
  state.currentAccount = data;
  state.actor = data.actor || state.actor;
  sessionStorage.setItem("shellx-drive-actor", state.actor);
  els.actorInput.value = state.actor;
  els.loginEmail.value = state.actor;
  setAuthStatus(
    data.auth_mode === "operator" ? "Operator access" : data.is_admin ? "Admin session" : "Signed in",
  );
  renderCurrentAccount();
  updateVersionWatchActivity({ poll: hasAdminTools() });
  if (hasSessionManagement()) {
    loadSelfSessions().catch(() => {});
    selfSecurityController.load().catch(() => {});
  } else {
    state.selfSessions = [];
    state.selfSecurityEvents = [];
    renderSelfSessions();
    selfSecurityController.render();
  }
  if (hasNotifications()) {
    loadNotifications(false).catch(() => {});
  } else {
    state.notifications = [];
    state.notificationUnreadCount = 0;
    renderNotifications();
  }
  loadOfficeStatus().catch(() => {});
  return data;
}

// Check for an online-editing provider once after sign-in. Show "Edit online"
// and its handoff hint after a successful response confirms a provider.
async function loadOfficeStatus() {
  try {
    const status = await api("/office/status");
    state.officeProvider = status && status.configured ? status : null;
  } catch {
    state.officeProvider = null;
  }
  setSelectionControlState();
  renderOfficeProviderStatus();
}

function officeProviderAvailable() {
  return Boolean(state.officeProvider && state.officeProvider.configured);
}

async function logoutCurrentSession() {
  if (!state.token && !state.currentSessionId && !state.currentAccount) {
    clearSensitiveAccountState();
    return true;
  }
  const departingActor = currentAccountEmail();
  if (hasSessionManagement()) {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch (error) {
      if (window.ShellXDriveAuthLifecycle.isStale(error)) return false;
      setAuthStatus("Sign-out could not be confirmed. Try again.");
      showToast("Could not sign out. Check your connection and try again.");
      return false;
    }
  }
  clearSensitiveAccountState(departingActor);
  await loadBootstrapStatus().catch(() => {});
  showToast("Signed out.");
  return true;
}

async function loadAuthAccounts() {
  const data = await api("/admin/auth/users");
  state.authAccounts = data.accounts || [];
  renderAuthAccounts();
  return data;
}

async function loadAuthAttempts() {
  const data = await api("/admin/auth/attempts");
  state.authAttempts = data.attempts || [];
  renderAuthAttempts();
  return data;
}

function renderAuthAttempts() {
  if (!els.adminAuthAttempts) return;
  if (!state.authAttempts) {
    renderAdminSkeleton(els.adminAuthAttempts, "rows", 2);
    return;
  }
  adminClarity.renderAuthAttempts({
    element: els.adminAuthAttempts,
    attempts: state.authAttempts,
    query: els.adminAuthAttemptsSearch?.value,
    filter: els.adminAuthAttemptsFilter?.value,
    escapeHtml,
    formatDate,
    relativeTime,
    renderEmpty: renderAdminEmpty,
  });
}

async function unlockAuthAttempt(key) {
  await api("/admin/auth/attempts/unlock", {
    method: "POST",
    body: JSON.stringify({ key }),
  });
  await loadAuthAttempts();
  showToast("Sign-in throttle cleared.");
}

async function loadRegistrationPolicy() {
  const data = await api("/admin/registration-policy");
  state.registrationPolicy = data;
  renderRegistrationPolicy();
  return data;
}

function renderRegistrationPolicy() {
  if (!els.adminRegistrationSummary) return;
  renderAdminLiveList(els.adminRegistrationSummary, [
    ["Public sign-ups", "Unavailable in v0.1"],
    ["Supported onboarding", "Admin-created accounts and verified invitation links"],
  ]);
}

function renderAuthAccounts() {
  if (!els.adminAuthSummary) return;
  if (!state.authAccounts) {
    renderAdminSkeleton(els.adminAuthSummary, "rows", 3);
    renderAdminAuthUpdateForm();
    return;
  }
  if (state.authAccounts.length === 0) {
    renderAdminEmpty(els.adminAuthSummary, "No accounts yet", "Add the first user with the form below.");
    renderAdminAuthUpdateForm();
    return;
  }
  els.adminAuthSummary.classList.remove("admin-skeleton", "admin-skeleton-tiles");
  if (
    !state.selectedAdminAuthEmail ||
    !state.authAccounts.some((account) => account.email === state.selectedAdminAuthEmail)
  ) {
    state.selectedAdminAuthEmail = state.authAccounts[0].email;
  }
  adminClarity.renderAuthAccounts({
    element: els.adminAuthSummary,
    accounts: state.authAccounts,
    query: els.adminAccountsSearch?.value,
    filter: els.adminAccountsFilter?.value,
    selectedEmail: state.selectedAdminAuthEmail,
    escapeHtml,
    renderEmpty: renderAdminEmpty,
  });
  renderAdminAuthUpdateForm();
  renderCurrentAccount();
}

function selectedAdminAuthAccount() {
  return (state.authAccounts || []).find(
    (account) => account.email === state.selectedAdminAuthEmail,
  );
}

function renderAdminAuthUpdateForm() {
  if (!els.adminAuthUpdateForm || !els.adminAuthUpdateEmail) return;
  els.adminAuthUpdateEmail.replaceChildren(
    ...(state.authAccounts || []).map((account) => {
      const option = document.createElement("option");
      option.value = account.email;
      option.textContent = account.email;
      option.selected = account.email === state.selectedAdminAuthEmail;
      return option;
    }),
  );
  const account = selectedAdminAuthAccount();
  const hasAccount = Boolean(account);
  els.adminAuthUpdateEmail.disabled = !hasAccount;
  els.adminAuthResetPassword.disabled = !hasAccount;
  els.adminAuthDisabled.disabled = !hasAccount;
  els.adminAuthAdmin.disabled = !hasAccount;
  els.adminAuthReset2fa.disabled = !hasAccount;
  els.adminAuthUpdateButton.disabled = !hasAccount;
  els.adminAuthRevokeSessionsButton.disabled = !hasAccount;
  if (account) {
    els.adminAuthUpdateEmail.value = account.email;
    els.adminAuthDisabled.checked = Boolean(account.disabled);
    els.adminAuthAdmin.checked = Boolean(account.is_admin);
    els.adminAuthReset2fa.checked = false;
  } else {
    els.adminAuthDisabled.checked = false;
    els.adminAuthAdmin.checked = false;
    els.adminAuthReset2fa.checked = false;
  }
}

async function createAuthAccount(event) {
  event.preventDefault();
  const data = await api("/admin/auth/users", {
    method: "POST",
    body: JSON.stringify({
      email: els.authUserEmail.value,
      password: els.authUserPassword.value,
      is_admin: els.authUserAdmin.checked,
    }),
  });
  els.authUserPassword.value = "";
  els.authUserAdmin.checked = false;
  await loadAuthAccounts();
  renderAdminLiveList(els.adminAuthOutput, [
    ["Account created", data.account.email],
    ["Role", data.account.is_admin ? "Administrator" : "User"],
  ]);
  showToast("Account created.");
}

async function updateSelectedAuthAccount(event) {
  event.preventDefault();
  const email = els.adminAuthUpdateEmail.value;
  if (!email) return;
  const payload = {
    disabled: els.adminAuthDisabled.checked,
    is_admin: els.adminAuthAdmin.checked,
    reset_2fa: els.adminAuthReset2fa.checked,
  };
  const password = els.adminAuthResetPassword.value.trim();
  if (password) {
    payload.reset_password = password;
  }
  const data = await api(`/admin/auth/users/${encodeURIComponent(email)}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
  state.selectedAdminAuthEmail = data.account.email;
  els.adminAuthResetPassword.value = "";
  els.adminAuthReset2fa.checked = false;
  await loadAuthAccounts();
  await loadAdminSessions().catch(() => {});
  renderAdminLiveList(els.adminAuthOutput, [
    ["Account updated", data.account.email],
    ["Status", data.account.disabled ? "Disabled" : "Active"],
  ]);
  showToast("Account updated.");
}

async function revokeSelectedAuthSessions() {
  const email = els.adminAuthUpdateEmail.value;
  if (!email) return;
  const activeSessions = (await loadAllAdminSessions()).filter(
    (session) => session.actor_email === email && !session.revoked,
  );
  const revokesCurrentSession = activeSessions.some(
    (session) => session.id === state.currentSessionId,
  );
  const orderedSessions = [...activeSessions].sort((left, right) =>
    Number(left.id === state.currentSessionId) - Number(right.id === state.currentSessionId),
  );
  for (const session of orderedSessions) {
    await api(`/admin/sessions/${encodeURIComponent(session.id)}/revoke`, { method: "POST" });
  }
  if (revokesCurrentSession) {
    clearSensitiveAccountState();
    showToast("Sessions revoked. This browser was signed out.");
    return;
  }
  await loadAdminSessions();
  renderAdminLiveList(els.accountSecurityOutput, [
    ["Account", email],
    ["Revoked sessions", activeSessions.length],
  ]);
  showToast(activeSessions.length ? "Sessions revoked." : "No active sessions.");
}

// Group a base32 secret into 4-char blocks so it is readable if typed by hand.
function formatTotpSecret(secret) {
  return String(secret || "")
    .replace(/\s+/g, "")
    .replace(/(.{4})/g, "$1 ")
    .trim();
}

// Draw server-encoded QR modules with a theme-independent quiet zone. The
// browser validates its compact row-major input before it paints anything.
function renderTotpQr(qrSize, qrModules) {
  const canvas = els.totpQr;
  const size = Number(qrSize);
  const modules = String(qrModules || "");
  if (!canvas || !Number.isInteger(size) || size < 21 || size > 177 || (size - 17) % 4 !== 0
    || modules.length !== size * size || !/^[01]+$/.test(modules)) return false;
  const border = 4; // quiet zone (modules)
  const target = 204; // desired px size
  const count = size + border * 2;
  const scale = Math.max(2, Math.floor(target / count));
  const dim = count * scale;
  canvas.width = dim;
  canvas.height = dim;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, dim, dim);
  ctx.fillStyle = "#000000";
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      if (modules[y * size + x] === "1") {
        ctx.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
      }
    }
  }
  return true;
}

// Return the 2FA setup section to its "not started" state.
function resetTotpSetupUi() {
  state.pendingTotpSecret = null;
  if (els.totpSetupResult) els.totpSetupResult.hidden = true;
  if (els.totpEnableCode) els.totpEnableCode.value = "";
  if (els.totpSecretDisplay) els.totpSecretDisplay.textContent = "";
  if (els.totpOtpauthUri) els.totpOtpauthUri.textContent = "";
  if (els.totpQr) {
    els.totpQr.width = els.totpQr.width;
    els.totpQr.hidden = true;
  }
}

// Reflect whether this account has 2FA enabled (chip + settings header email).
function renderTotpStatus() {
  const email = currentAccountEmail();
  if (els.settingsAccountEmail) els.settingsAccountEmail.textContent = email || "—";
  const enabled = Boolean(state.currentAccount?.totp_enabled);
  if (els.totpStatusChip) {
    els.totpStatusChip.textContent = enabled ? "Enabled" : "Not enabled";
    els.totpStatusChip.className = `status-chip ${enabled ? "active" : "warning"}`;
  }
  if (els.totpSetupCurrentFactorField) {
    els.totpSetupCurrentFactorField.hidden = !enabled;
  }
  if (els.totpSetupButton) {
    els.totpSetupButton.textContent = enabled ? "Replace 2FA" : "Set up 2FA";
  }
  if (!enabled && els.totpSetupCurrentFactor) {
    els.totpSetupCurrentFactor.value = "";
  }
}

async function setupTotp() {
  const currentFactor = totpCodePayload(els.totpSetupCurrentFactor?.value || "");
  await applyCredentialRotation(() => api("/auth/2fa/setup", {
    method: "POST",
    body: JSON.stringify({ password: els.totpSetupPassword.value, ...currentFactor }),
  }), (data) => {
    state.pendingTotpSecret = data.secret;
    els.totpSetupPassword.value = "";
    if (els.totpSetupCurrentFactor) els.totpSetupCurrentFactor.value = "";
    const uri = data.otpauth_uri;
    const drewQr = renderTotpQr(data.qr_size, data.qr_modules);
    if (els.totpSecretDisplay) els.totpSecretDisplay.textContent = formatTotpSecret(data.secret);
    if (els.totpOtpauthUri) els.totpOtpauthUri.textContent = uri;
    if (els.totpQr) els.totpQr.hidden = !drewQr;
    if (els.totpSetupResult) els.totpSetupResult.hidden = false;
    // Clear any stale recovery-code / status output from a previous attempt.
    if (els.accountSecurityOutput) els.accountSecurityOutput.replaceChildren();
    window.setTimeout(() => els.totpEnableCode?.focus(), 0);
    showToast(drewQr ? "Scan the QR, then enter your 6-digit code." : "Enter the setup key, then your code.");
  });
}

async function enableTotp() {
  await applyCredentialRotation(() => api("/auth/2fa/enable", {
    method: "POST",
    body: JSON.stringify({ code: els.totpEnableCode.value }),
  }), (data) => {
    els.totpEnableCode.value = "";
    resetTotpSetupUi();
    state.currentAccount = { ...state.currentAccount, totp_enabled: true };
    renderTotpStatus();
    renderRecoveryCodes(data.recovery_codes || []);
    showToast("2FA enabled. Save your recovery codes.");
  });
}

function totpCodePayload(value) {
  const code = value.trim();
  if (!code) return {};
  return /^\d{6}$/.test(code) ? { code } : { recovery_code: code };
}

async function disableTotp() {
  await applyCredentialRotation(() => api("/auth/2fa/disable", {
    method: "POST",
    body: JSON.stringify(totpCodePayload(els.totpDisableCode.value)),
  }), (data) => {
    els.totpDisableCode.value = "";
    resetTotpSetupUi();
    state.currentAccount = { ...state.currentAccount, totp_enabled: Boolean(data.totp_enabled) };
    renderTotpStatus();
    renderAdminLiveList(els.accountSecurityOutput, [["Two-factor authentication", "Disabled"]]);
    showToast("2FA disabled.");
  });
}

async function rotateRecoveryCodes() {
  await applyCredentialRotation(() => api("/auth/recovery-codes/rotate", {
    method: "POST",
    body: JSON.stringify(totpCodePayload(els.recoveryRotateCode.value)),
  }), (data) => {
    els.recoveryRotateCode.value = "";
    renderRecoveryCodes(data.recovery_codes || []);
    showToast("Recovery codes rotated.");
  });
}

function renderRecoveryCodes(codes) {
  const rows = codes.length
    ? codes.map((code, index) => [`Recovery ${index + 1}`, code])
    : [["Recovery codes", "None returned"]];
  renderAdminLiveList(els.accountSecurityOutput, rows);
}

function renderAdminLiveList(element, rows) {
  if (!element) return;
  element.classList.remove("admin-skeleton", "admin-skeleton-tiles");
  element.replaceChildren(
    ...rows.map(([label, value]) => {
      const row = document.createElement("div");
      row.className = "admin-live-row";
      row.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? 0)}</strong>`;
      return row;
    }),
  );
}

// Stat tiles — the readable replacement for raw counts / JSON dumps. Each entry
// is [label, value] or [label, value, tone] where tone ∈ good|warn|bad tints the
// number. Empty/undefined values render as an em dash, never "0" or "null".
function renderAdminStats(element, entries) {
  if (!element) return;
  element.classList.remove("admin-skeleton", "admin-skeleton-tiles");
  element.replaceChildren(
    ...entries.map(([label, value, tone]) => {
      const tile = document.createElement("div");
      tile.className = "admin-stat";
      if (tone) tile.dataset.tone = tone;
      const valueEl = document.createElement("span");
      valueEl.className = "admin-stat-value";
      valueEl.textContent =
        value === null || value === undefined || value === "" ? "—" : String(value);
      const labelEl = document.createElement("span");
      labelEl.className = "admin-stat-label";
      labelEl.textContent = label;
      tile.append(valueEl, labelEl);
      return tile;
    }),
  );
}

// Loading skeleton — shimmer bars shown while a section's data is in flight.
// kind: "tiles" (stat grid) | "rows" (detail list). Cleared by any real render.
function renderAdminSkeleton(element, kind = "rows", count = 3) {
  if (!element) return;
  element.classList.add("admin-skeleton");
  element.classList.toggle("admin-skeleton-tiles", kind === "tiles");
  const bars = [];
  for (let index = 0; index < count; index += 1) {
    const bar = document.createElement("div");
    bar.className = "admin-skeleton-bar";
    bars.push(bar);
  }
  element.replaceChildren(...bars);
}

// Empty state — a friendly "nothing here yet" with an optional one-line hint,
// so a card never renders as a blank pane.
function renderAdminEmpty(element, title, hint) {
  if (!element) return;
  element.classList.remove("admin-skeleton", "admin-skeleton-tiles");
  const box = document.createElement("div");
  box.className = "admin-empty";
  const strong = document.createElement("strong");
  strong.textContent = title;
  box.append(strong);
  if (hint) {
    const span = document.createElement("span");
    span.textContent = hint;
    box.append(span);
  }
  element.replaceChildren(box);
}

// Human "time ago" for admin timestamps — "just now", "3 min ago", "2 hours
// ago", "3 days ago", then a calendar date. Never surfaces raw ISO/epoch values.
function relativeTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const diffSec = Math.round((Date.now() - date.getTime()) / 1000);
  if (diffSec < 0) return compactDate(value);
  if (diffSec < 45) return "just now";
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHour = Math.round(diffMin / 60);
  if (diffHour < 24) return `${diffHour} ${diffHour === 1 ? "hour" : "hours"} ago`;
  const diffDay = Math.round(diffHour / 24);
  if (diffDay < 7) return `${diffDay} ${diffDay === 1 ? "day" : "days"} ago`;
  return compactDate(value);
}

// Capitalise a single word/label for display (e.g. role "owner" -> "Owner").
function titleCase(value) {
  const text = String(value ?? "").replace(/[_-]+/g, " ").trim();
  if (!text) return "—";
  return text.charAt(0).toUpperCase() + text.slice(1);
}
const {
  createAdminBackup,
  deleteSelectedAdminBackup,
  downloadSelectedAdminBackup,
  loadAdminBackups,
  loadBackupPolicy,
  renderAdminBackups,
  restoreSelectedAdminBackup,
  saveBackupPolicy,
  validateSelectedAdminBackup,
} = window.ShellXDriveAdminBackups.createController({
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
  runAuthenticated: (task) => authLifecycle.run(task),
  showToast,
  state,
  titleCase,
});
const everyoneGrantPolicyController = window.ShellXDriveEveryoneGrantPolicy.createController({ api, relativeTime, showToast });
const adminSecurityController = adminSecurityModule.createController({
  api,
  browserDeviceLabel: adminClarity.browserDeviceLabel,
  els,
  escapeHtml,
  onError: (error) => {
    els.adminSecurityEventsList.textContent = error.message;
    showToast(error.message);
  },
  relativeTime,
  renderEmpty: renderAdminEmpty,
  renderSkeleton: renderAdminSkeleton,
  state,
});

const selfSecurityController = adminSecurityModule.createSelfController({
  api,
  browserDeviceLabel: adminClarity.browserDeviceLabel,
  element: els.selfSecurityEventsList,
  escapeHtml,
  relativeTime,
  renderEmpty: renderAdminEmpty,
  renderFallback: (rows) => renderAdminLiveList(els.selfSecurityEventsList, rows),
  state,
});

async function loadAdminEmail() {
  const data = await api("/admin/email");
  state.adminEmail = data;
  renderAdminEmail();
  return data;
}

async function runAdminEmailQueue() {
  const data = await api("/admin/email", { method: "POST" });
  state.adminEmail = data;
  renderAdminEmail();
  showToast("Waiting messages processed. No email was sent automatically.");
  return data;
}

function renderAdminEmail() {
  if (!els.adminEmailSummary) return;
  if (!state.adminEmail) {
    renderAdminSkeleton(els.adminEmailSummary, "tiles", 3);
    renderAdminSkeleton(els.adminEmailList, "rows", 2);
    return;
  }
  const emails = state.adminEmail.emails || [];
  const queued = emails.filter((email) => email.status === "queued").length;
  const sent = emails.filter((email) => email.status === "sent").length;
  const transportLabel = state.adminEmail.transport === "capture"
    ? "Local capture"
    : `Unavailable (${titleCase(state.adminEmail.transport || "unknown")})`;
  renderAdminStats(els.adminEmailSummary, [
    ["Waiting", queued, queued > 0 ? "warn" : undefined],
    ["Captured", sent],
    ["Mode", transportLabel],
  ]);
  if (!emails.length) {
    renderAdminEmpty(
      els.adminEmailList,
      "Queue is empty",
      "Outgoing invitations and notifications will appear here.",
    );
    return;
  }
  els.adminEmailList.classList.remove("admin-skeleton", "admin-skeleton-tiles");
  els.adminEmailList.replaceChildren(
    ...emails.slice(0, 12).map((email) => {
      const row = document.createElement("div");
      row.className = "admin-live-row admin-session-row";
      const statusLabel = state.adminEmail.transport === "capture" && email.status === "sent"
        ? "Captured"
        : titleCase(email.status || "queued");
      row.innerHTML = `
        <span>
          <b>${escapeHtml(email.subject || humanizeEventKind(email.kind))}</b>
          <small>To ${escapeHtml(email.recipient_email || "unknown")}</small>
        </span>
        <strong>${escapeHtml(statusLabel)}</strong>
      `;
      return row;
    }),
  );
}

// Paint shimmer skeletons into any admin card whose data has not loaded yet, so
// the first open of the admin center reads as "loading", never as blank panes.
function paintAdminSkeletons() {
  if (!state.adminSummary) {
    renderAdminSkeleton(els.adminMetrics, "tiles", 8);
    renderAdminSkeleton(els.adminOutput, "rows", 3);
    renderAdminSkeleton(els.adminTeamsSummary, "tiles", 3);
    renderAdminSkeleton(els.adminStorageSummary, "tiles", 5);
    renderAdminSkeleton(els.adminSharingSummary, "tiles", 5);
  }
  if (!state.adminBackups) renderAdminSkeleton(els.adminBackupsSummary, "tiles", 3);
  if (!state.adminSessions) renderAdminSkeleton(els.adminSessionsSummary, "rows", 3);
  if (!state.adminEmail) renderAdminSkeleton(els.adminEmailSummary, "tiles", 3);
  if (!state.authAccounts) renderAdminSkeleton(els.adminAuthSummary, "rows", 3);
  if (!state.authAttempts) renderAdminSkeleton(els.adminAuthAttempts, "rows", 2);
  if (!state.securityEvents) renderAdminSkeleton(els.adminSecurityEventsList, "rows", 4);
}

async function refreshAdminCommandCenter() {
  if (!hasAdminTools()) return;
  paintAdminSkeletons();
  await Promise.all([
    loadAdminSummary().catch((error) => {
      els.adminOutput.textContent = error.message;
    }),
    loadGroups().catch((error) => {
      els.groupsOutput.textContent = error.message;
    }),
    loadWorkspacePolicyAndUsage().catch((error) => {
      els.storagePolicyOutput.textContent = error.message;
    }),
    loadSandboxProfile().catch((error) => {
      els.sandboxOutput.textContent = error.message;
    }),
    loadReadinessStatus().catch((error) => {
      els.maintenanceOutput.textContent = error.message;
    }),
    loadMaintenanceStatus().catch((error) => {
      els.maintenanceOutput.textContent = error.message;
    }),
    loadBackupPolicy().catch((error) => {
      els.adminBackupsSummary.textContent = error.message;
    }),
    loadAdminBackups().catch((error) => {
      els.adminBackupsSummary.textContent = error.message;
    }),
    loadAdminSessions().catch((error) => {
      els.adminSessionsSummary.textContent = error.message;
    }),
    loadAdminEmail().catch((error) => {
      els.adminEmailSummary.textContent = error.message;
    }),
    loadAuthAccounts().catch((error) => {
      els.adminAuthSummary.textContent = error.message;
    }),
    loadAuthAttempts().catch((error) => {
      els.adminAuthAttempts.textContent = error.message;
    }),
    adminSecurityController.load().catch((error) => {
      els.adminSecurityEventsList.textContent = error.message;
    }),
    loadRegistrationPolicy().catch((error) => {
      els.adminRegistrationSummary.textContent = error.message;
    }),
  ]);
}

function sandboxRequestFromForm() {
  return {
    mode: els.sandboxMode.value,
    bind: els.sandboxBind.value.trim(),
    data_dir: els.sandboxDataDir.value.trim(),
    read_write_paths: els.sandboxWritePaths.value
      .split(",")
      .map((path) => path.trim())
      .filter(Boolean),
  };
}

async function loadSandboxProfile() {
  const data = await api("/admin/sandbox");
  state.sandboxProfile = data.profile;
  renderSandboxProfile();
  return data;
}

function renderSandboxProfile() {
  const profile = state.sandboxProfile;
  if (!profile) {
    setAdminStatusChip(els.adminStatusSandbox, "Not checked");
    renderAdminLiveList(els.sandboxOutput, [["Status", "Not checked"]]);
    return;
  }
  const modeLabel = { strict: "Strict VPS", "local-dev": "Local dev" }[profile.mode] || titleCase(profile.mode);
  setAdminStatusChip(els.adminStatusSandbox, "Draft only", "warn");
  els.sandboxMode.value = profile.mode || "strict";
  els.sandboxBind.value = profile.bind || "";
  els.sandboxDataDir.value = profile.data_dir || "";
  els.sandboxWritePaths.value = (profile.read_write_paths || []).join(", ");
  renderAdminLiveList(els.sandboxOutput, [
    ["Deployment state", "Saved draft — not applied or verified by Drive"],
    ["Proposed mode", modeLabel],
    ["Proposed listener", profile.bind],
    ["Proposed data folder", profile.data_dir],
    ["Proposed writable paths", (profile.read_write_paths || []).join(", ") || "None"],
  ]);
}

async function saveSandboxProfile(event) {
  event.preventDefault();
  const data = await api("/admin/sandbox", {
    method: "PATCH",
    body: JSON.stringify(sandboxRequestFromForm()),
  });
  state.sandboxProfile = data.profile;
  renderSandboxProfile();
  await loadAdminSummary().catch(() => {});
  showToast("Host profile draft saved. The live service was not changed.");
}

async function previewSandboxProfile() {
  const data = await api("/admin/sandbox/preview", { method: "POST" });
  state.sandboxPreview = data;
  state.sandboxProfile = data.profile;
  renderSandboxProfile();
  renderSandboxCommandPreview(data);
  showToast("Host commands generated for operator review.");
}

async function recordSandboxApplyIntent() {
  const data = await api("/admin/sandbox/apply-intent", { method: "POST" });
  state.sandboxPreview = data;
  state.sandboxProfile = data.profile;
  renderSandboxProfile();
  renderSandboxCommandPreview(data, data.receipt);
  await loadAdminSummary().catch((error) => {
    els.adminOutput.textContent = error.message;
  });
  showToast("Reviewed host plan recorded. Nothing was applied.");
}

function renderSandboxCommandPreview(data, receipt = null) {
  if (!els.sandboxOutput) return;
  const rows = [];
  if (receipt) {
    rows.push(["Reviewed plan recorded", relativeTime(receipt.created_at)]);
  }
  renderAdminLiveList(els.sandboxOutput, rows);
  for (const [label, value] of [
    ["Operator install command", (data.commands || [])[0] || "No command generated"],
    ["Operator verification command", (data.commands || [])[1] || "No status command generated"],
    ["Proposed systemd unit", data.unit_preview || "No unit preview"],
  ]) {
    const block = document.createElement("section");
    block.className = "admin-command-preview";
    const heading = document.createElement("span");
    heading.textContent = label;
    const body = document.createElement("code");
    body.textContent = value;
    block.append(heading, body);
    els.sandboxOutput.append(block);
  }
}

function renderRetentionCleanup() {
  if (!els.retentionOutput) return;
  const hasWorkspace = Boolean(state.currentWorkspace);
  if (els.retentionPreviewButton) {
    els.retentionPreviewButton.disabled = !hasWorkspace;
  }
  if (els.retentionApplyButton) {
    els.retentionApplyButton.disabled = !hasWorkspace;
  }
  if (!hasWorkspace) {
    renderAdminLiveList(els.retentionOutput, [["Workspace", "Select one"]]);
    return;
  }
  const preview = state.retentionPreview;
  if (!preview) {
    renderAdminLiveList(els.retentionOutput, [
      ["Workspace", state.currentWorkspace.name],
      ["Cleanup", "Not previewed"],
    ]);
    return;
  }
  renderAdminLiveList(els.retentionOutput, [
    ["Workspace", state.currentWorkspace.name],
    ["Trashed files", preview.totals?.trashed_files || 0],
    ["Old revisions", preview.totals?.revisions || 0],
    ["Bytes eligible", preview.totals?.content_bytes || 0],
    ["Mode", preview.dry_run ? "Preview" : "Applied"],
  ]);
}

async function runRetentionCleanup(apply = false) {
  if (!state.currentWorkspace) {
    renderRetentionCleanup();
    return null;
  }
  const data = await api(apply ? "/admin/retention/apply" : "/admin/retention/preview", {
    method: "POST",
    body: JSON.stringify({ workspace_id: state.currentWorkspace.id }),
  });
  state.retentionPreview = data;
  renderRetentionCleanup();
  await loadAdminSummary().catch((error) => {
    els.adminOutput.textContent = error.message;
  });
  showToast(apply ? "Cleanup applied." : "Cleanup preview ready.");
  return data;
}

async function loadMaintenanceStatus() {
  const data = await api("/admin/maintenance");
  state.maintenanceStatus = data.maintenance;
  renderMaintenanceStatus();
  return data;
}

async function loadReadinessStatus() {
  const data = await api("/ready");
  state.readinessStatus = data;
  renderReadinessStatus();
  return data;
}

function renderReadinessStatus() {
  const readiness = state.readinessStatus;
  if (!readiness) {
    setAdminStatusChip(els.adminReadinessStatus, "Not checked");
    renderAdminLiveList(els.adminReadinessSummary, [["Readiness", "Not checked"]]);
    return;
  }
  const ready = Boolean(readiness.ready);
  const stateLabel = String(readiness.state || (ready ? "ready" : "not_ready"))
    .replaceAll("_", " ");
  const isDegraded = stateLabel === "degraded";
  setAdminStatusChip(
    els.adminReadinessStatus,
    titleCase(stateLabel),
    stateLabel === "ready" ? "good" : isDegraded ? "warn" : "bad",
  );
  const rows = [
    ["Accepting requests", readiness.live ? "Yes" : "No"],
    ["Ready to serve", ready ? "Yes" : "No"],
    ["State", titleCase(stateLabel)],
  ];
  for (const check of (readiness.checks || []).slice(0, 6)) {
    const ok = String(check.status).toLowerCase() === "pass" || String(check.status).toLowerCase() === "ok";
    const checkLabels = {
      storage: "Database & files",
      backup_policy: "Backup schedule",
      backup_restore: "Backup restore",
      maintenance: "Host updates",
    };
    rows.push([checkLabels[check.name] || titleCase(check.name), ok ? "OK" : titleCase(check.message || check.status)]);
  }
  renderAdminLiveList(els.adminReadinessSummary, rows);
}

function maintenancePostureLabel(maintenance) {
  if (maintenance?.host_posture === "unassessed") {
    return "Not assessed";
  }
  return maintenance?.ubuntu_pro_attached ? "Managed (Ubuntu Pro)" : "Updates need attention";
}

// Map an internal maintenance policy value to human copy.
function maintenancePolicyLabel(value) {
  const map = {
    no_restarts: "Never restart automatically",
    security_only: "Security updates only",
    all: "All updates",
    manual: "Manual",
    attach_before_update: "Attach Ubuntu Pro before updating",
  };
  return map[value] || titleCase(String(value || "").replace(/_/g, " "));
}

function renderMaintenanceStatus() {
  const maintenance = state.maintenanceStatus;
  if (!maintenance) {
    setAdminStatusChip(els.adminStatusMaintenance, "Not checked");
    renderAdminLiveList(els.adminMaintenanceSummary, [["Status", "Not checked"]]);
    renderAdminLiveList(els.maintenanceOutput, []);
    return;
  }
  const posture = maintenancePostureLabel(maintenance);
  const postureAssessed = maintenance.host_posture !== "unassessed";
  setAdminStatusChip(
    els.adminStatusMaintenance,
    posture,
    postureAssessed && maintenance.ubuntu_pro_attached ? "good" : "warn",
  );
  renderAdminLiveList(els.adminMaintenanceSummary, [
    ["Live OS inspection", postureAssessed ? posture : "Not performed by Drive"],
    ["Saved restart policy", maintenancePolicyLabel(maintenance.restart_policy)],
    ["Saved update policy", maintenancePolicyLabel(maintenance.package_update_policy)],
    ["Recorded maintenance run", maintenance.last_result ? titleCase(maintenance.last_result) : "None"],
  ]);
  renderAdminLiveList(els.maintenanceOutput, []);
}

async function createSupportBundle() {
  const data = await api("/admin/support-bundle");
  state.supportBundle = data.bundle;
  renderAdminLiveList(els.maintenanceOutput, [
    ["Support bundle", "Ready to download"],
    ["Created", relativeTime(data.bundle?.generated_at)],
    ["Sensitive data", "Redacted"],
  ]);
  await loadAdminSummary().catch(() => {});
  showToast("Support bundle created.");
  return data;
}

async function loadSyncHealth() {
  const data = await api("/sync/health");
  state.syncHealth = data;
  renderSyncHealth();
}

async function loadSyncChanges() {
  const cursor = els.syncCursorInput.value.trim() || "0";
  const data = await api(`/sync/changes?cursor=${encodeURIComponent(cursor)}`);
  state.syncChanges = data.changes || [];
  els.syncCursorInput.value = data.next_cursor ?? cursor;
  renderSyncChangeList("changes", state.syncChanges);
  els.syncOutput.textContent = pretty(data);
  showToast("Sync changes loaded.");
}

async function loadSyncConflicts() {
  const data = await api("/sync/conflicts");
  state.syncConflicts = data.conflicts || [];
  renderSyncChangeList("conflicts", state.syncConflicts);
  els.syncOutput.textContent = pretty(data);
  showToast("Sync conflicts loaded.");
}

function renderSyncChangeList(kind, rows) {
  if (!els.syncChangeList) return;
  if (!rows || rows.length === 0) {
    renderAdminLiveList(els.syncChangeList, [
      [kind === "conflicts" ? "Conflicts" : "Changes", "None"],
    ]);
    return;
  }
  els.syncChangeList.replaceChildren(
    ...rows.slice(0, 8).map((item) => {
      const row = document.createElement("div");
      row.className = "sync-change-row";
      const title =
        kind === "conflicts"
          ? item.name || item.file_id
          : `${item.kind || "change"} · ${item.entity_type || "entity"}`;
      const detail =
        kind === "conflicts"
          ? `conflict of ${item.conflict_of_file_id || "file"} · r${item.conflict_of_revision || 0}`
          : `${item.workspace_id || ""} · cursor ${item.id || 0}`;
      row.innerHTML = `
        <span>
          <b>${escapeHtml(title)}</b>
          <small>${escapeHtml(detail)}</small>
        </span>
        <span class="member-role">${escapeHtml(kind)}</span>
      `;
      return row;
    }),
  );
}

function renderSyncHealth() {
  const sync = state.syncHealth?.sync || {};
  const totals = sync.totals || {};
  const jobTotals = state.syncHealth?.job_totals || {};
  const metrics = [
    ["Workspaces", totals.workspaces],
    ["Files", totals.files],
    ["Downloadable", totals.downloadable_files],
    ["Queued", jobTotals.queued],
    ["Failed", jobTotals.failed],
    ["Skipped", jobTotals.skipped],
  ];
  const rows = metrics.map(([label, value]) => {
    const row = document.createElement("div");
    row.className = "metric-row";
    row.innerHTML = `<span class="metric-label">${escapeHtml(label)}</span><span class="metric-value">${Number(value || 0)}</span>`;
    return row;
  });
  els.syncMetrics.replaceChildren(...rows);
  els.syncOutput.textContent = state.syncHealth
    ? pretty({
        generated_at: sync.generated_at,
        workspaces: sync.workspaces || [],
      })
    : "";
}

async function createWorkspace(event) {
  event.preventDefault();
  const name = els.workspaceName.value.trim();
  const owner = els.workspaceOwner.value.trim();
  if (!name || !owner) return;
  const data = await api("/workspaces", {
    method: "POST",
    body: JSON.stringify({
      name,
      owner_email: owner,
    }),
  });
  els.workspaceName.value = "";
  els.workspaceOwner.value = "";
  setCurrentWorkspace(data.workspace);
  rememberWorkspace(data.workspace.id);
  await loadWorkspaces();
  showToast("Workspace created.");
}

function replaceCurrentWorkspace(workspace) {
  setCurrentWorkspace(workspace);
  state.workspaces = state.workspaces
    .filter((item) => item.id !== workspace.id)
    .concat(workspace)
    .sort((left, right) => left.name.localeCompare(right.name));
  renderWorkspaces();
  renderViewTitle();
}

async function renameCurrentWorkspace(event) {
  event.preventDefault();
  if (!state.currentWorkspace || !canManageCurrentWorkspace()) return;
  const name = els.workspaceRenameName.value.trim();
  if (!name) return;
  const data = await api(`/workspaces/${state.currentWorkspace.id}`, {
    method: "PATCH",
    body: JSON.stringify({ name }),
  });
  els.workspaceRenameName.value = "";
  replaceCurrentWorkspace(data.workspace);
  els.workspaceLifecycleOutput.textContent = pretty(data);
  showToast("Workspace renamed.");
}

async function archiveCurrentWorkspace() {
  if (!state.currentWorkspace || !canManageCurrentWorkspace()) return;
  const data = await api(`/workspaces/${state.currentWorkspace.id}/archive`, { method: "POST" });
  setCurrentWorkspace(data.workspace);
  state.workspaces = state.workspaces.filter((workspace) => workspace.id !== data.workspace.id);
  renderWorkspaces();
  renderStorageSummary();
  els.workspaceLifecycleOutput.textContent = pretty(data);
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast("Workspace archived.");
}

async function unarchiveCurrentWorkspace() {
  if (!state.currentWorkspace || !canManageCurrentWorkspace()) return;
  const data = await api(`/workspaces/${state.currentWorkspace.id}/unarchive`, { method: "POST" });
  replaceCurrentWorkspace(data.workspace);
  els.workspaceLifecycleOutput.textContent = pretty(data);
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast("Workspace unarchived.");
}

async function transferCurrentWorkspaceOwner(event) {
  event.preventDefault();
  if (!state.currentWorkspace || !canManageCurrentWorkspace()) return;
  const email = els.workspaceTransferEmail.value.trim();
  if (!email) return;
  const data = await api(`/workspaces/${state.currentWorkspace.id}/transfer-owner`, {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  els.workspaceTransferEmail.value = "";
  els.workspaceLifecycleOutput.textContent = pretty(data);
  await loadMembers(state.currentWorkspace.id);
  await loadWorkspaces();
  showToast("Workspace owner transferred.");
}

async function leaveCurrentWorkspace() {
  if (!state.currentWorkspace) return;
  const data = await api(`/workspaces/${state.currentWorkspace.id}/leave`, { method: "POST" });
  els.workspaceLifecycleOutput.textContent = pretty(data);
  setCurrentWorkspace(null);
  state.browserPreferenceWorkspaceId = "";
  state.browserPage = 0;
  state.files = [];
  state.members = [];
  state.workspaceInvitations = [];
  renderFiles();
  renderMembers();
  renderWorkspaceInvitations();
  await loadWorkspaces();
  showToast("Left workspace.");
}

async function uploadFile(event) {
  event.preventDefault();
  if (!state.currentWorkspace) return;
  await api("/files", {
    method: "POST",
    body: JSON.stringify({
      workspace_id: state.currentWorkspace.id,
      ...(state.currentFolderId ? { parent_id: state.currentFolderId } : {}),
      name: els.fileName.value.trim(),
      kind: "file",
      content: els.fileContent.value,
    }),
  });
  els.fileName.value = "";
  els.fileContent.value = "";
  closeCreateDialog();
  await loadManifest(state.currentWorkspace.id);
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast("File uploaded.");
}

async function createFolder(event) {
  event.preventDefault();
  if (!state.currentWorkspace || !canWriteCurrentWorkspace()) return;
  const name = els.createFolderName.value.trim();
  if (!name) {
    showToast("Enter a folder name.");
    return;
  }
  const data = await api("/files", {
    method: "POST",
    body: JSON.stringify({
      workspace_id: state.currentWorkspace.id,
      ...(state.currentFolderId ? { parent_id: state.currentFolderId } : {}),
      name,
      kind: "folder",
    }),
  });
  els.createFolderName.value = "";
  closeCreateDialog();
  state.selectedFile = data.file;
  await loadManifest(state.currentWorkspace.id);
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast("Folder created.");
}

browserUploads = window.ShellXDriveUploads.createController({
  state,
  elements: {
    queue: els.uploadQueue,
    summary: els.uploadProgressSummary,
    aggregates: els.uploadAggregates,
    statusPanel: els.uploadStatusPanel,
    statusTitle: els.uploadStatusTitle,
    statusList: els.uploadStatusList,
    dismiss: els.uploadStatusDismiss,
    clearCompleted: els.uploadStatusClearCompleted,
    duplicatePolicy: els.uploadDuplicatePolicy,
    resumePicker: els.uploadResumePicker,
  },
  api,
  formatBytes,
  escapeHtml,
  showToast,
  canWrite: canWriteCurrentWorkspace,
  getWorkspace: () => state.currentWorkspace,
  getFolderId: () => state.currentFolderId,
  getFileById: (id) => fileNodesById().get(id) || null,
  getActor: () => state.currentAccount?.email || state.actor || "local",
  onFileFinished: async (file) => {
    if (file.workspace_id === state.currentWorkspace?.id) state.selectedFile = file;
  },
  onQueueSettled: async () => {
    if (!state.currentWorkspace) return;
    await loadManifest(state.currentWorkspace.id);
    await loadWorkspacePolicyAndUsage().catch((error) => {
      els.storagePolicyOutput.textContent = error.message;
    });
    await loadSyncHealth().catch((error) => {
      els.syncOutput.textContent = error.message;
    });
  },
});

for (const [source, target] of [
  [els.uploadDuplicatePolicy, els.uploadMenuDuplicatePolicy],
  [els.uploadMenuDuplicatePolicy, els.uploadDuplicatePolicy],
]) {
  source?.addEventListener("change", () => {
    if (target) target.value = source.value;
  });
}

function uploadBrowserFiles(fileList) {
  return browserUploads.enqueueFiles(fileList);
}

function uploadBrowserEntries(entries) {
  return browserUploads.enqueueEntries(entries);
}

async function uploadCameraFiles(fileList) {
  if (!fileList?.length) return;
  await uploadBrowserFiles(fileList);
  els.cameraUploadInput.value = "";
  showToast("Camera upload queued.");
}

function collectDropEntries(dataTransfer) {
  return browserUploads.collectDropEntries(dataTransfer);
}

function handleUploadDrop(event) {
  event.preventDefault();
  // Dropping on the box handles the upload itself; don't also let it bubble to
  // the whole-area .drive-main drop handler (that would upload twice).
  event.stopPropagation();
  els.uploadDropZone.classList.remove("drag-over");
  // `collectDropEntries` grabs the entry handles synchronously (before any
  // await), so it is safe to call from the drop event and traverse folders.
  collectDropEntries(event.dataTransfer)
    .then((entries) => uploadBrowserEntries(entries))
    .catch((error) => showToast(error.message));
}

async function createResumableUpload(event) {
  event.preventDefault();
  if (!state.currentWorkspace) return;
  const name = els.uploadSessionName.value.trim();
  if (!name) return;
  const totalSize = els.uploadSessionTotalSize.value.trim();
  const data = await api("/uploads/resumable", {
    method: "POST",
    body: JSON.stringify({
      workspace_id: state.currentWorkspace.id,
      ...(state.currentFolderId ? { parent_id: state.currentFolderId } : {}),
      name,
      ...(totalSize ? { total_size: Number(totalSize) } : {}),
    }),
  });
  state.uploadSession = data.session;
  state.selectedUploadSessionId = data.session.id;
  els.uploadStatus.textContent = pretty(data);
  await loadUploadSessions().catch((error) => {
    els.uploadStatus.textContent = error.message;
  });
  showToast("Resumable upload session started.");
}

async function loadUploadSessions(
  workspaceId = state.currentWorkspace?.id,
  isCurrent = () => true,
) {
  if (!workspaceId) {
    if (!isCurrent()) return [];
    state.uploadSessions = [];
    state.selectedUploadSessionId = "";
    renderUploadSessions();
    return [];
  }
  const data = await api(`/workspaces/${workspaceId}/uploads`);
  if (!isCurrent()) return [];
  state.uploadSessions = data.sessions || [];
  if (
    state.selectedUploadSessionId &&
    !state.uploadSessions.some((session) => session.id === state.selectedUploadSessionId)
  ) {
    state.selectedUploadSessionId = "";
  }
  if (!state.selectedUploadSessionId) {
    state.selectedUploadSessionId = state.uploadSessions[0]?.id || "";
  }
  renderUploadSessions();
  return state.uploadSessions;
}

function renderUploadSessions() {
  if (!els.uploadSessionList) return;
  const sessions = state.uploadSessions || [];
  if (!state.currentWorkspace) {
    renderAdminLiveList(els.uploadSessionList, [["Uploads", "Select a workspace"]]);
  } else if (sessions.length === 0) {
    renderAdminLiveList(els.uploadSessionList, [["Uploads", "No upload sessions for this account"]]);
  } else {
    els.uploadSessionList.replaceChildren(
      ...sessions.slice(0, 8).map((session) => {
        const row = document.createElement("button");
        row.type = "button";
        row.className = `upload-session-row${session.id === state.selectedUploadSessionId ? " selected" : ""}`;
        const status = session.completed ? "completed" : session.canceled ? "canceled" : "open";
        row.innerHTML = `
          <span>
            <b>${escapeHtml(session.name)}</b>
            <small>${escapeHtml(status)} · ${escapeHtml(formatBytes(session.received_bytes))} received · ${escapeHtml(compactDate(session.updated_at))}</small>
          </span>
          <span class="member-role">${escapeHtml(status)}</span>
        `;
        row.addEventListener("click", () => {
          state.selectedUploadSessionId = session.id;
          renderUploadSessions();
        });
        return row;
      }),
    );
  }
  const selected = sessions.find((session) => session.id === state.selectedUploadSessionId);
  els.refreshUploadSessionsButton.disabled = !state.currentWorkspace;
  els.cancelUploadSessionButton.disabled = !selected || selected.completed || selected.canceled;
  els.cleanupUploadsButton.disabled = !(state.token || state.currentAccount?.is_admin);
}

async function cancelSelectedUploadSession() {
  if (!state.selectedUploadSessionId) return;
  const data = await api(`/uploads/resumable/${state.selectedUploadSessionId}/cancel`, {
    method: "POST",
  });
  els.uploadStatus.textContent = pretty(data);
  await loadUploadSessions();
  showToast("Upload session canceled.");
}

async function cleanupUploadSessions() {
  const data = await api("/admin/uploads/cleanup", {
    method: "POST",
    body: JSON.stringify({ older_than_seconds: 0 }),
  });
  els.uploadStatus.textContent = pretty(data);
  await loadUploadSessions().catch(() => {});
  showToast("Stale upload sessions cleaned.");
}

async function appendUploadChunk(finish = false) {
  if (!state.uploadSession) return;
  const data = await api(`/uploads/resumable/${state.uploadSession.id}`, {
    method: "PUT",
    body: JSON.stringify({
      offset: state.uploadSession.received_bytes,
      content: els.uploadChunkContent.value,
      finish,
    }),
  });
  state.uploadSession = data.session;
  state.selectedUploadSessionId = data.session.id;
  els.uploadStatus.textContent = pretty(data);
  els.uploadChunkContent.value = "";
  await loadUploadSessions().catch(() => {});
  if (data.file) {
    const workspaceId = data.file.workspace_id;
    setCurrentWorkspace(
      state.workspaces.find((workspace) => workspace.id === workspaceId) || state.currentWorkspace,
    );
    state.selectedFile = data.file;
    await loadManifest(workspaceId);
    await loadWorkspacePolicyAndUsage().catch((error) => {
      els.storagePolicyOutput.textContent = error.message;
    });
    await loadSyncHealth().catch((error) => {
      els.syncOutput.textContent = error.message;
    });
    showToast("Upload finished.");
  }
}

async function downloadSelected() {
  if (!state.selectedFile) return;
  await triggerDownload(state.selectedFile);
}

async function downloadFolderZip() {
  if (!state.selectedFile || state.selectedFile.kind !== "folder") return;
  await window.ShellXDownloadTickets.start({
    endpoint: "/files/download-zip",
    body: { file_ids: [state.selectedFile.id] },
    headers: authHeaders(),
  });
  showToast("Preparing folder download.");
}

async function loadSelectedContent() {
  if (!state.selectedFile) return;
  const refusal = window.ShellXDrivePreview.textPreviewRefusal(state.selectedFile);
  if (refusal) throw new Error(refusal.copy);
  const open = await api(`/office/files/${state.selectedFile.id}/open`, { method: "POST" });
  const text = await loadBoundedTextFile(state.selectedFile);
  state.selectedBaseRevision = open.base_revision;
  els.selectedContent.value = text;
  setSelectionControlState();
  els.selectedMeta.textContent = pretty({
    file: open.file,
    base_revision: open.base_revision,
    locking: open.locking,
  });
  showToast("Opened local edit session.");
}

async function openSelectedEditor() {
  if (!canWriteSelectedFile()) return;
  if (!state.selectedFile || state.selectedFile.kind === "folder") return;
  const open = await api(`/office/files/${state.selectedFile.id}/open`, { method: "POST" });
  const session = open.edit_session;
  if (session?.launch_url) {
    const launchUrl = safeOfficeLaunchUrl(session.launch_url);
    if (!launchUrl) {
      state.officeProviderStatus = "Editor launch URL blocked.";
      renderOfficeProviderStatus();
      showToast("Editor launch URL blocked.");
      return;
    }
    state.officeProviderStatus = `${open.provider?.name || "Editor"} session expires ${compactDate(session.expires_at)}`;
    renderOfficeProviderStatus();
    window.open(launchUrl, "_blank", "noopener");
    els.selectedMeta.textContent = pretty({
      file: open.file,
      base_revision: open.base_revision,
      edit_session: {
        expires_at: session.expires_at,
      },
    });
    showToast("Editor session opened.");
    return;
  }
  state.officeProviderStatus = "Online editing isn't available for this file.";
  renderOfficeProviderStatus();
  els.selectedMeta.textContent = pretty({
    provider: open.provider,
    edit_session: null,
    save_url: open.save_url,
  });
  showToast("No editor provider configured.");
}

function safeOfficeLaunchUrl(value) {
  try {
    const url = new URL(value, window.location.origin);
    return url.origin === window.location.origin &&
      url.pathname.startsWith("/office/launch/") &&
      !url.search &&
      !url.hash
      ? url.href
      : "";
  } catch (error) {
    if (window.ShellXDriveAuthLifecycle.isStale(error)) return null;
    return "";
  }
}

async function saveSelectedContent() {
  if (!state.selectedFile || state.selectedBaseRevision === null || !state.currentWorkspace || !canWriteSelectedFile()) {
    return;
  }
  const data = await api(`/office/files/${state.selectedFile.id}/save`, {
    method: "POST",
    body: JSON.stringify({
      base_revision: state.selectedBaseRevision,
      content: els.selectedContent.value,
    }),
  });
  state.selectedBaseRevision = data.file.revision;
  state.selectedFile = data.file;
  setSelectionControlState();
  els.selectedMeta.textContent = pretty(data);
  await loadManifest(state.currentWorkspace.id);
  await loadWorkspacePolicyAndUsage().catch((error) => {
    els.storagePolicyOutput.textContent = error.message;
  });
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast("File saved.");
}

async function loadSelectedMetadata() {
  if (!state.selectedFile) return;
  const fileId = state.selectedFile.id;
  const metadata = await api(`/files/${fileId}/metadata`);
  if (state.selectedFile?.id !== fileId) return;
  state.selectedMetadata = metadata;
  renderMetadataInputs(metadata);
  renderSelectionSummary();
  setSelectionControlState();
}

async function loadSelectedPreview() {
  if (!state.selectedFile || state.selectedFile.kind !== "file") {
    state.selectedPreview = null;
    renderSelectionSummary();
    return null;
  }
  const fileId = state.selectedFile.id;
  const data = await api(`/files/${fileId}/preview`);
  if (state.selectedFile?.id !== fileId) return null;
  state.selectedPreview = data.preview || null;
  renderSelectionSummary();
  return state.selectedPreview;
}

async function saveFileDetails() {
  if (!state.selectedFile || !state.currentWorkspace || !canWriteSelectedFile()) return;
  const customText = els.fileMetadata.value.trim();
  const data = await api(`/files/${state.selectedFile.id}`, {
    method: "PATCH",
    body: JSON.stringify({
      name: els.fileDetailName.value.trim(),
      ...(state.currentWorkspace.scoped_root?.id === state.selectedFile.id ? {} : els.fileParentSelect.value
        ? { parent_id: els.fileParentSelect.value }
        : { move_to_root: true }),
      labels: els.fileLabels.value
        .split(",")
        .map((label) => label.trim())
        .filter(Boolean),
      custom_metadata: customText ? JSON.parse(customText) : {},
    }),
  });
  state.selectedFile = data.file;
  state.selectedMetadata = data.metadata;
  state.selectedBaseRevision = null;
  els.selectedContent.value = "";
  await loadManifest(state.currentWorkspace.id);
  els.selectedMeta.textContent = pretty(data);
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast("File details saved.");
}

async function copySelectedFile() {
  if (!state.selectedFile || !state.currentWorkspace || !canWriteSelectedFile()) return;
  const data = await api(`/files/${state.selectedFile.id}/copy`, {
    method: "POST",
    // The destination is deliberately omitted: the canonical copy route keeps
    // the source parent and derives an extension-preserving keep-both name.
    body: JSON.stringify({}),
  });
  state.selectedFile = data.file;
  state.selectedMetadata = data.metadata;
  state.selectedBaseRevision = null;
  state.selectedRevisions = [];
  state.selectedRevisionStorage = null;
  els.selectedContent.value = "";
  await loadManifest(state.currentWorkspace.id);
  els.selectedMeta.textContent = pretty(data);
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast(`Copied as ${data.file.name}.`);
}

async function loadSelectedRevisions() {
  return collaboration.loadSelectedRevisions();
}

async function runBulkFileAction(action) {
  const availability = bulkActionAvailability();
  if (!availability[action] || !state.currentWorkspace) {
    showToast("Every selected item must be compatible with that bulk action.");
    return;
  }
  const fileIds = availability.selected.map((file) => file.id);
  const returnToTrash = state.activeView === "trash";
  const data = await api("/files/bulk", {
    method: "POST",
    body: JSON.stringify({ action, file_ids: fileIds }),
  });
  state.bulkSelectedIds = [];
  // trash / restore move files out of the current view; drop the single
  // selection too so the inspector doesn't cling to a row that just left the
  // list. star / unstar keep the selection on the same file.
  const lifecycle = action === "trash" || action === "restore";
  const selectedId = lifecycle ? null : state.selectedFile?.id;
  if (lifecycle) {
    state.selectedFile = null;
    state.selectedPreview = null;
    state.selectedMetadata = null;
  }
  await loadManifest(state.currentWorkspace.id);
  if (returnToTrash) {
    setActiveView("trash");
    await loadTrashFiles();
  }
  if (selectedId) {
    state.selectedFile = state.files.find((file) => file.id === selectedId) || state.selectedFile;
    renderSelection();
  }
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  els.selectedMeta.textContent = pretty(data);
  showToast(`Bulk ${action} complete.`);
}

// Toggle a file's starred state from its row star, independent of the current
// inspector selection. Uses the existing /star & /unstar endpoints, then reloads
// the manifest so the row (and the inspector, if this file is selected) repaint
// with the real state. Does NOT change the current selection.
async function toggleFileStar(file) {
  if (!file || !state.currentWorkspace) return;
  const wasStarred = Boolean(file.starred);
  await api(`/files/${file.id}/${wasStarred ? "unstar" : "star"}`, { method: "POST" });
  await loadManifest(state.currentWorkspace.id);
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast(wasStarred ? "Removed star." : "Starred.");
}

async function mutateSelected(path, { clearAfter = false } = {}) {
  if (!state.selectedFile || !state.currentWorkspace || !canWriteSelectedFile()) return;
  const returnToTrash = state.activeView === "trash";
  await api(path.replace(":id", state.selectedFile.id), { method: "POST" });
  // Trash / restore move the file OUT of the current view, so drop the
  // selection first so loadManifest() refreshes the inspector for the remaining
  // list. Star / unstar keep the selection so the inspector stays put.
  if (clearAfter) {
    state.selectedFile = null;
    state.bulkSelectedIds = [];
    state.selectedPreview = null;
    state.selectedMetadata = null;
  }
  await loadManifest(state.currentWorkspace.id);
  if (returnToTrash) {
    setActiveView("trash");
    await loadTrashFiles();
  }
  await loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  });
  showToast("File updated.");
}

async function loadManagedShares(options) {
  return collaboration.loadManagedShares(options);
}

function renderManagedShares() {
  collaboration.renderManagedShares();
}

async function createDrop(event) {
  event.preventDefault();
  if (!state.currentWorkspace) return;
  const data = await api("/drops", {
    method: "POST",
    body: JSON.stringify({
      workspace_id: state.currentWorkspace.id,
      name: els.dropName.value.trim() || "Drop",
      password: els.dropPassword.value,
      expires_in_seconds: 3600,
    }),
  });
  state.latestDropUrl = `${window.location.origin}/pub/drops/${data.drop.id}`;
  els.shareOutput.textContent = `Drop link ready\n${state.latestDropUrl}\nExpires ${formatDate(data.drop.expires_at)}`;
  els.dropPassword.value = "";
  await loadManagedDrops().catch((error) => {
    els.shareOutput.textContent = error.message;
  });
  await loadNotifications(false).catch(() => {});
  showToast("Drop link created.");
}

async function loadManagedDrops(
  workspaceId = state.currentWorkspace?.id,
  isCurrent = () => true,
) {
  if (!workspaceId || !canManageCurrentWorkspace()) {
    if (!isCurrent()) return [];
    state.managedDrops = [];
    renderManagedDrops();
    return [];
  }
  const data =
    workspaceId === state.currentWorkspace?.id
      ? await api(`/workspaces/${state.currentWorkspace.id}/drops`)
      : await api(`/workspaces/${workspaceId}/drops`);
  if (!isCurrent()) return [];
  state.managedDrops = data.drops || [];
  if (
    !state.selectedDropId ||
    !state.managedDrops.some((drop) => drop.id === state.selectedDropId)
  ) {
    state.selectedDropId = state.managedDrops[0]?.id || "";
  }
  renderManagedDrops();
  return state.managedDrops;
}

function renderManagedDrops() {
  if (!els.dropManagementList) return;
  const drops = state.managedDrops || [];
  if (!state.currentWorkspace) {
    renderAdminLiveList(els.dropManagementList, [["Drops", "No workspace"]]);
  } else if (drops.length === 0) {
    renderAdminLiveList(els.dropManagementList, [["Drops", "None"]]);
  } else {
    els.dropManagementList.replaceChildren(
      ...drops.slice(0, 8).map((drop) => {
        const row = document.createElement("div");
        row.className = "managed-link-row";
        row.innerHTML = `
          <span>
            <b>${escapeHtml(drop.name)}</b>
            <small>${escapeHtml(drop.upload_count || 0)} uploads · ${escapeHtml(drop.revoked ? "revoked" : "active")} · expires ${escapeHtml(compactDate(drop.expires_at))}</small>
          </span>
          <button type="button" class="admin-inline-button" data-select-drop="${escapeHtml(drop.id)}">Manage</button>
          ${drop.inbox_file_id ? `<button type="button" class="admin-inline-button" data-open-drop-inbox="${escapeHtml(drop.id)}">Open inbox</button>` : ""}
        `;
        return row;
      }),
    );
  }
  els.dropUpdateSelect.replaceChildren(
    ...drops.map((drop) => {
      const option = document.createElement("option");
      option.value = drop.id;
      option.textContent = `${drop.name} · ${drop.revoked ? "revoked" : "active"}`;
      option.selected = drop.id === state.selectedDropId;
      return option;
    }),
  );
  const selected = drops.find((drop) => drop.id === state.selectedDropId);
  if (selected && !els.dropUpdateName.value) {
    els.dropUpdateName.placeholder = selected.name;
  }
  const enabled = drops.length > 0 && canWriteCurrentWorkspace();
  els.dropUpdateSelect.disabled = !enabled;
  els.dropUpdateName.disabled = !enabled;
  els.dropUpdatePassword.disabled = !enabled;
  els.dropUpdateExpiry.disabled = !enabled;
  els.dropUpdateButton.disabled = !enabled;
  els.dropOpenInboxButton.disabled = !enabled || !selected?.inbox_file_id;
  els.dropRevokeButton.disabled = !enabled;
}

function openManagedDropInbox(drop) {
  if (!drop?.inbox_file_id) return;
  const workspaceId = drop.workspace_id;
  if (state.currentWorkspace?.id !== workspaceId) return;
  const requestSequence = state.manifestRequestSequence + 1;
  const isCurrent = () => state.currentWorkspace?.id === workspaceId
    && state.manifestRequestSequence === requestSequence;
  loadManifest(workspaceId).then((current) => {
    if (!current || !isCurrent()) return;
    const inbox = fileNodesById().get(drop.inbox_file_id);
    if (!inbox || inbox.kind !== "folder" || inbox.trashed
        || inbox.parent_id || inbox.workspace_id !== workspaceId) {
      showToast("Inbox unavailable. Refresh Drops after the next upload.");
      return;
    }
    clearAccountBrowseState();
    closeWorkspaceSettings();
    openFolder(drop.inbox_file_id);
  }).catch((error) => {
    if (isCurrent()) showToast(error.message);
  });
}

async function updateSelectedDrop(event) {
  event.preventDefault();
  const dropId = els.dropUpdateSelect.value;
  if (!dropId) return;
  const payload = {
    expires_in_seconds: Number(els.dropUpdateExpiry.value || 604800),
  };
  if (els.dropUpdateName.value.trim()) {
    payload.name = els.dropUpdateName.value.trim();
  }
  if (els.dropUpdatePassword.value) {
    payload.password = els.dropUpdatePassword.value;
  }
  const data = await api(`/drops/${dropId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
  els.dropUpdateName.value = "";
  els.dropUpdatePassword.value = "";
  state.selectedDropId = data.drop.id;
  await loadManagedDrops();
  showToast("Drop updated.");
}

async function revokeManagedDrop() {
  const dropId = els.dropUpdateSelect.value;
  if (!dropId) return;
  await api(`/drops/${dropId}/revoke`, { method: "POST" });
  await loadManagedDrops();
  showToast("Drop revoked.");
}

async function saveMember(event) {
  event.preventDefault();
  if (!state.currentWorkspace || !canManageCurrentWorkspace()) return;
  await api(`/workspaces/${state.currentWorkspace.id}/members`, {
    method: "POST",
    body: JSON.stringify({
      email: els.memberEmail.value.trim(),
      role: els.memberRole.value,
    }),
  });
  els.memberEmail.value = "";
  await loadMembers(state.currentWorkspace.id);
  showToast("Member saved.");
}

async function removeMember(event) {
  event.preventDefault();
  if (!state.currentWorkspace || !canManageCurrentWorkspace()) return;
  await api(`/workspaces/${state.currentWorkspace.id}/members`, {
    method: "DELETE",
    body: JSON.stringify({
      email: els.memberRemoveEmail.value.trim(),
    }),
  });
  els.memberRemoveEmail.value = "";
  await loadMembers(state.currentWorkspace.id);
  showToast("Member removed.");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/* ============================================================================
 * UI STATE CONTROLLER
 * Every visible control derives from real state: auth, workspace, selection,
 * role, and admin/debug gating. `applyUiState()` is the single entry point,
 * called after every data/selection mutation (end of renderFiles / renderSelection
 * and on auth transitions).
 * ==========================================================================*/

function setShellState(stateName) {
  document.body.dataset.driveUiState = stateName;
  if (els.offlineShellNotice) els.offlineShellNotice.hidden = stateName !== "offline_shell";
}

function deriveUiState() {
  if (state.offlineShell) return "offline_shell";
  if (state.authUncertain) return "auth_uncertain";
  if (state.authBootstrapRequired) return "bootstrap_required";
  if (!state.token && !state.currentAccount) return "signed_out";
  if (!state.workspaces.length) return "signed_in_no_workspace";
  if (!state.currentWorkspace) return "signed_in_no_workspace";
  if (!state.files.length && !state.browseFiles.length && !(state.currentViewTitle?.startsWith("Search results") && state.lastRenderedFiles.length)) return "workspace_empty";
  if (state.bulkSelectedIds.length > 1) return "multi_selected";
  if (state.selectedFile?.kind === "folder") return "folder_selected";
  if (state.selectedFile) return "single_file_selected";
  return "workspace_files_no_selection";
}

function actionStateForSelection() {
  const file = state.selectedFile;
  const info = file ? fileTypeInfo(file) : null;
  return {
    hasFile: Boolean(file),
    isFolder: file?.kind === "folder",
    isFile: Boolean(file) && file.kind !== "folder",
    trashed: Boolean(file?.trashed),
    starred: Boolean(file?.starred),
    canWrite: canWriteSelectedFile(),
    previewable: Boolean(info?.previewable),
    editable: Boolean(info?.editable),
  };
}

function applyViewChrome() {
  document.body.dataset.driveView = state.activeView || "my-drive";
}

function applyAdminDebugVisibility() {
  const adminTools = hasAdminTools();
  if (els.accountAdminButton) els.accountAdminButton.hidden = !adminTools;
  document.body.dataset.driveAdmin = adminTools ? "true" : "false";
}

function noWorkspaceEmptyState() {
  const refresh = { label: "Refresh workspaces", run: () => loadWorkspaces() };
  if (!hasAdminTools()) {
    return {
      icon: "i-folder-plus",
      title: "No workspaces available",
      body: "Ask an administrator to invite you to a workspace or grant you access, then refresh to see it here.",
      primary: refresh,
    };
  }
  return {
    icon: "i-folder-plus",
    title: "No workspaces yet",
    body: "Create the first workspace in Admin center to start adding files.",
    primary: { label: "Create workspace", run: () => openAdminWorkspaceCreation() },
    secondary: refresh,
  };
}

const EMPTY_STATES = {
  "empty-workspace": {
    icon: "i-upload",
    title: "Nothing here yet",
    body: "Upload files or create a folder to get started.",
    primary: { label: "New", run: () => openNewMenu() },
    secondary: { label: "Upload files", run: () => els.uploadFilePicker.click() },
  },
  search: {
    icon: "i-search",
    title: "No results",
    body: "No files match your search in any of your workspaces.",
    primary: { label: "Clear search", run: () => clearSearch() },
  },
  trash: {
    icon: "i-trash",
    title: "Trash is empty",
    body: "Items remain in Trash until they reach the retention window and you use Empty trash, or you delete them individually.",
  },
  shared: { icon: "i-share", title: "Nothing shared with you", body: "Files shared to you by other members appear here." },
  starred: { icon: "i-star", title: "No starred files", body: "Star files to find them quickly here." },
  offline: {
    icon: "i-cloud-off",
    title: "No mobile download marks",
    body: "Mark files for mobile download. This web build saves only a metadata file list; download marked files on mobile while online.",
  },
  recent: { icon: "i-clock", title: "No recent activity", body: "Files you open or edit will appear here." },
};

function emptyStateKey() {
  const uiState = document.body.dataset.driveUiState;
  if (uiState === "signed_in_no_workspace") return "no-workspace";
  if (uiState === "workspace_empty") return "empty-workspace";
  if (!state.currentWorkspace) return "";
  const displayed = (state.lastRenderedFiles || []).length;
  if (displayed > 0) return "";
  if (state.currentViewTitle?.startsWith("Search results")) return "search";
  if (state.activeView === "trash") return "trash";
  if (state.activeView === "shared") return "shared";
  if (state.activeView === "starred") return "starred";
  if (state.activeView === "offline") return "offline";
  if (state.activeView === "recent") return "recent";
  return "empty-workspace";
}

function renderEmptyState(key) {
  if (!els.emptyState) return;
  els.emptyState.replaceChildren();
  const cfg = key === "no-workspace" ? noWorkspaceEmptyState() : EMPTY_STATES[key];
  if (!cfg) return;
  const icon = document.createElement("div");
  icon.className = "empty-state-icon";
  icon.innerHTML = `<svg class="icon" aria-hidden="true"><use href="#${cfg.icon}"/></svg>`;
  const heading = document.createElement("h2");
  heading.textContent = cfg.title;
  const body = document.createElement("p");
  body.textContent = cfg.body;
  els.emptyState.append(icon, heading, body);
  const actions = document.createElement("div");
  actions.className = "empty-state-actions";
  for (const [action, primary] of [
    [cfg.primary, true],
    [cfg.secondary, false],
  ]) {
    if (!action) continue;
    const button = document.createElement("button");
    button.type = "button";
    if (primary) button.className = "primary-action";
    button.textContent = action.label;
    button.addEventListener("click", () =>
      Promise.resolve(action.run()).catch((error) => showToast(error.message)),
    );
    actions.append(button);
  }
  if (actions.childElementCount) els.emptyState.append(actions);
}

function applyEmptyState() {
  const key = emptyStateKey();
  document.body.dataset.driveEmpty = key;
  renderEmptyState(key);
}

function applyWorkspaceNavigationAvailability() {
  const hasWorkspace = Boolean(state.currentWorkspace);
  if (els.workspaceSettingsButton) {
    const label = hasWorkspace
      ? (canManageCurrentWorkspace() ? "Workspace settings" : "Workspace details")
      : "Workspace settings unavailable: no workspace selected";
    els.workspaceSettingsButton.disabled = !hasWorkspace;
    els.workspaceSettingsButton.setAttribute("aria-disabled", String(!hasWorkspace));
    els.workspaceSettingsButton.setAttribute("aria-label", label);
    els.workspaceSettingsButton.title = hasWorkspace ? label : "No workspace selected";
  }
  if (els.accountWorkspaceSettingsButton) {
    els.accountWorkspaceSettingsButton.hidden = !hasWorkspace;
    els.accountWorkspaceSettingsButton.disabled = !hasWorkspace;
    els.accountWorkspaceSettingsButton.setAttribute("aria-disabled", String(!hasWorkspace));
  }
}

function applyUiState() {
  const next = deriveUiState();
  setShellState(next);
  applyViewChrome();
  applyAdminDebugVisibility();
  settingsController?.applyWorkspaceScope();
  applyWorkspaceNavigationAvailability();
  applyEmptyState();
}

/* ============================================================================
 * FILE-TYPE CLASSIFIER: icon + hue + human label + preview mode.
 * ==========================================================================*/

/* ============================================================================
 * THEME (header toggle by the notification bell + account-menu item; persisted
 * to localStorage; sets <html data-theme>). One quick toggle lives in the top
 * header bar (#header-theme-toggle); the account menu keeps a labelled mirror.
 * ==========================================================================*/

// Resolve the *effective* light/dark mode. An explicit stored preference wins;
// otherwise we follow the OS (prefers-color-scheme) so the very first paint and
// the toggle icon match the system default before the user has chosen.
function effectiveTheme() {
  if (state.theme === "light" || state.theme === "dark") return state.theme;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

// Point an icon-bearing <button>'s <use> at a sprite id and update its labels.
function setThemeButtonIcon(button, iconId, label) {
  if (!button) return;
  const use = button.querySelector("use");
  if (use) use.setAttribute("href", iconId);
  button.setAttribute("aria-pressed", String(effectiveTheme() === "dark"));
  button.setAttribute("aria-label", label);
  button.setAttribute("title", label);
}

// Apply the current theme to <html data-theme> and reflect it in every toggle.
// A concrete "light"/"dark" writes data-theme (overriding the OS); anything else
// clears it so the CSS `@media (prefers-color-scheme)` fallback drives the palette.
function applyTheme() {
  const theme = state.theme;
  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }
  const effective = effectiveTheme();
  // The button shows the mode it will switch TO: a moon while light, a sun while
  // dark. Label mirrors that action for screen readers.
  const nextLabel = effective === "dark" ? "Switch to light theme" : "Switch to dark theme";
  const nextIcon = effective === "dark" ? "#i-sun" : "#i-moon";
  setThemeButtonIcon(els.headerThemeToggle, nextIcon, nextLabel);
  setThemeButtonIcon(els.themeToggleButton, nextIcon, nextLabel);
  if (els.themeToggleState) {
    els.themeToggleState.textContent = effective === "dark" ? "Dark" : "Light";
  }
}

// A genuine light <-> dark toggle (issue: the theme control did nothing). Flips
// the effective mode, writes an explicit preference to localStorage, and repaints.
function toggleTheme() {
  state.theme = effectiveTheme() === "dark" ? "light" : "dark";
  localStorage.setItem("shellx-drive-theme", state.theme);
  applyTheme();
}

/* ============================================================================
 * "New" menu + quick-create surface
 * ==========================================================================*/

function openNewMenu() {
  if (!els.newMenu || !els.newMenuButton) return;
  els.newMenu.hidden = false;
  const rect = els.newMenuButton.getBoundingClientRect();
  els.newMenu.style.top = `${rect.bottom + 6}px`;
  els.newMenu.style.left = `${Math.max(12, rect.right - els.newMenu.offsetWidth)}px`;
  els.newMenuButton.setAttribute("aria-expanded", "true");
}

function closeNewMenu() {
  if (!els.newMenu) return;
  els.newMenu.hidden = true;
  els.newMenuButton?.setAttribute("aria-expanded", "false");
}

// The topbar "Upload" button opens its own tiny 2-item menu (Upload files /
// Upload folder) instead of the full drop-zone panel. Mirrors openNewMenu so
// positioning, aria, and outside-click/Escape behaviour stay identical.
function openUploadMenu() {
  if (!els.uploadMenu || !els.uploadFocusButton) return;
  closeNewMenu();
  els.uploadMenu.hidden = false;
  const rect = els.uploadFocusButton.getBoundingClientRect();
  els.uploadMenu.style.top = `${rect.bottom + 6}px`;
  els.uploadMenu.style.left = `${Math.max(12, rect.left)}px`;
  els.uploadFocusButton.setAttribute("aria-expanded", "true");
}

function closeUploadMenu() {
  if (!els.uploadMenu) return;
  els.uploadMenu.hidden = true;
  els.uploadFocusButton?.setAttribute("aria-expanded", "false");
}

// The quick-create surface is now upload-only (the drop-zone reached from the
// +New "Upload files/folder" items). New folder / New text file moved to the
// compact #create-dialog modal below.
const QUICK_CREATE_TITLES = {
  upload: "Add to this folder",
};

function showQuickCreate(focusEl, mode = "upload") {
  document.body.dataset.quickCreateMode = mode;
  document.body.classList.add("show-quick-create");
  if (els.quickCreateTitle) {
    els.quickCreateTitle.textContent = QUICK_CREATE_TITLES[mode] || QUICK_CREATE_TITLES.upload;
  }
  if (focusEl) window.setTimeout(() => focusEl.focus(), 0);
}

function hideQuickCreate() {
  document.body.classList.remove("show-quick-create");
}

// Compact create modal (issue: the old full-width name bar "feels very lazy").
// One dialog, two forms (folder / text) — CSS shows the one matching
// data-create-mode. The forms keep their original ids, so submit still runs
// createFolder()/uploadFile(); on success those close the dialog.
function openCreateDialog(mode) {
  if (!els.createDialog) return;
  if (!state.currentWorkspace) {
    showToast("Select a workspace first.");
    return;
  }
  if (!canWriteCurrentWorkspace()) {
    showToast("You do not have permission to create items here.");
    return;
  }
  // Switching to a create action supersedes the upload drop-zone panel.
  hideQuickCreate();
  els.createDialog.dataset.createMode = mode;
  if (els.createDialogTitle) {
    els.createDialogTitle.textContent = mode === "folder" ? "New folder" : "New text file";
  }
  // Start from a clean field each open (a prior Cancel could have left text).
  if (mode === "folder") {
    if (els.createFolderName) els.createFolderName.value = "";
  } else {
    if (els.fileName) els.fileName.value = "";
    if (els.fileContent) els.fileContent.value = "";
  }
  els.createDialog.hidden = false;
  const focusEl = mode === "folder" ? els.createFolderName : els.fileName;
  window.setTimeout(() => focusEl?.focus(), 0);
}

function closeCreateDialog() {
  if (els.createDialog) els.createDialog.hidden = true;
}

/* ============================================================================
 * Workspace settings drawer (lifecycle + members, off the primary file path)
 * ==========================================================================*/

function openWorkspaceSettings() {
  if (!state.currentWorkspace) {
    showToast("Select a workspace first.");
    return;
  }
  if (els.workspaceSettingsDrawer) els.workspaceSettingsDrawer.hidden = false;
  if (!settingsController?.applyWorkspaceScope()) return;
  loadWorkspacePolicyAndUsage().catch((error) => showToast(error.message));
  settingsController?.loadWorkspaceStatistics().catch((error) => showToast(error.message));
  loadManagedShares({ workspaceWide: true }).catch((error) => {
    renderAdminLiveList(els.shareManagementList, [["Shared links", error.message]]);
    showToast(error.message);
  });
  loadManagedDrops().catch((error) => showToast(error.message));
}

function closeWorkspaceSettings() {
  if (els.workspaceSettingsDrawer) els.workspaceSettingsDrawer.hidden = true;
}

/* ============================================================================
 * Settings drawer — the findable account-security home (2FA, password, sessions)
 * ==========================================================================*/

function openSettings() {
  if (!els.settingsDrawer) return;
  toggleAccountPanel(false);
  els.settingsDrawer.hidden = false;
  applySettingsMode();
  collaboration?.openAgentSettings();
  if (hasAccountSecurity()) {
    resetTotpSetupUi();
    renderTotpStatus();
  }
  if (hasSessionManagement()) {
    loadSelfSessions().catch((error) =>
      renderAdminLiveList(els.selfSessionsList, [["Sessions", error.message]]),
    );
    selfSecurityController.load().catch((error) =>
      renderAdminLiveList(els.selfSecurityEventsList, [["Sign-in activity", error.message]]),
    );
  } else {
    state.selfSessions = [];
    state.selfSecurityEvents = [];
    renderSelfSessions();
    selfSecurityController.render();
  }
  renderAbout();
}

function applySettingsMode() {
  const accountSecurity = hasAccountSecurity();
  const sessions = hasSessionManagement();
  if (els.settingsTwoFactorSection) els.settingsTwoFactorSection.hidden = !accountSecurity;
  if (els.settingsPasswordSection) els.settingsPasswordSection.hidden = !accountSecurity;
  if (els.settingsSessionsSection) els.settingsSessionsSection.hidden = !sessions;
  if (!els.settingsCredentialNotice) return;
  els.settingsCredentialNotice.hidden = accountSecurity;
  if (accountSecurity) return;

  if (isOperatorSession()) {
    els.settingsCredentialTitle.textContent = "Operator access";
    els.settingsCredentialCopy.textContent =
      "This browser is using the server operator token. Passwords, two-factor authentication, and browser sessions do not apply. Use Admin center for server operations; rotate the token outside Drive.";
  } else if (isAppTokenSession()) {
    els.settingsCredentialTitle.textContent = "Application access";
    els.settingsCredentialCopy.textContent =
      "This browser is using a workspace-scoped application token. Account security and browser-session controls do not apply.";
  } else {
    els.settingsCredentialTitle.textContent = "Identity provider access";
    els.settingsCredentialCopy.textContent = sessions
      ? "Your identity provider manages passwords and two-factor authentication. Drive session controls remain available below."
      : "Account security settings do not apply to this credential.";
  }
}

function closeSettings() {
  collaboration?.closeAgentSettings();
  if (els.settingsDrawer) els.settingsDrawer.hidden = true;
}

/* ============================================================================
 * Server administration (server admin/operator only)
 * ==========================================================================*/

function setAdvancedTab() {
  const grid = els.advancedWorkbench?.querySelector(".advanced-grid");
  if (grid) grid.dataset.advancedActive = "admin";
}

function openAdvanced() {
  if (!hasAdminTools()) return;
  state.adminVisible = true;
  toggleAdvancedWorkbench(true);
  setAdvancedTab();
  applyAdminDebugVisibility();
}

function openAdminWorkspaceCreation() {
  if (!hasAdminTools()) return;
  openAdvanced();
  setAdminSection("workspaces");
  window.setTimeout(() => els.workspaceName?.focus(), 0);
}

function closeAdvanced() {
  state.adminVisible = false;
  toggleAdvancedWorkbench(false);
  applyAdminDebugVisibility();
}

function authHeaders() {
  return {
    ...(state.token ? { authorization: `Bearer ${state.token}` } : {}),
    ...(state.actor ? { "X-ShellX-Actor": state.actor } : {}),
  };
}

async function triggerDownload(file) {
  if (!file) return;
  if (file.kind === "folder") {
    selectFile(file);
    await downloadFolderZip();
    return;
  }
  await window.ShellXDownloadTickets.start({
    endpoint: `/files/${encodeURIComponent(file.id)}/download`,
    body: {},
    headers: authHeaders(),
  });
  showToast(`Download started for ${file.name}.`);
}

// Folder covers use abortable authenticated requests so identity changes stop
// both the upload and its later manifest refresh.
function pickFolderCover(file) {
  if (!file || file.kind !== "folder") return;
  const input = document.createElement("input");
  input.type = "file";
  input.accept = "image/png,image/jpeg,image/gif,image/webp";
  input.style.display = "none";
  input.addEventListener(
    "change",
    async () => {
      const picked = input.files && input.files[0];
      input.remove();
      if (!picked) return;
      try {
        await uploadFolderCover(file, picked);
      } catch (error) {
        showToast(error.message);
      }
    },
    { once: true },
  );
  document.body.append(input);
  input.click();
}

// PUT the raw image bytes as the folder's cover, then reload the manifest.
async function uploadFolderCover(file, imageFile) {
  await authenticatedFetch(`/files/${encodeURIComponent(file.id)}/cover`, {
    method: "PUT",
    headers: { ...authHeaders(), "content-type": imageFile.type || "application/octet-stream" },
    body: imageFile,
  }, async (response) => {
    if (!response.ok) throw new Error((await response.text()) || `${response.status} ${response.statusText}`);
  });
  showToast(`Cover set for ${file.name}.`);
  if (state.currentWorkspace) await loadManifest(state.currentWorkspace.id);
}

// Remove a folder's cover image, then reload the manifest so the tile reverts
// to the generic folder look.
async function removeFolderCover(file) {
  if (!file || file.kind !== "folder") return;
  await authenticatedFetch(`/files/${encodeURIComponent(file.id)}/cover`, {
    method: "DELETE",
    headers: authHeaders(),
  }, async (response) => {
    if (!response.ok) throw new Error((await response.text()) || `${response.status} ${response.statusText}`);
  });
  showToast(`Cover removed from ${file.name}.`);
  if (state.currentWorkspace) await loadManifest(state.currentWorkspace.id);
}

/* ============================================================================
 * Preview surface — lifecycle and navigation live in drive-preview.js.
 * ==========================================================================*/

async function openPreviewModal(file = state.selectedFile, opener = document.activeElement) {
  return isAccountBrowseView() && file?.kind === "folder" ? openBrowseFileLocation(file) : previewController?.open(file, opener);
}

function closePreviewModal() {
  previewController?.close();
}

/* ============================================================================
 * Confirm dialog (destructive actions) — returns a Promise<boolean>.
 * ==========================================================================*/

function confirmAction({ title, message, confirmLabel = "Delete" }) {
  state.confirmResolver?.(false);
  const opener = document.activeElement;
  return new Promise((resolve) => {
    els.confirmDialogTitle.textContent = title;
    els.confirmDialogMessage.textContent = message;
    els.confirmDialogConfirm.textContent = confirmLabel;
    els.confirmDialog.hidden = false;
    state.confirmResolver = (value) => {
      els.confirmDialog.hidden = true;
      state.confirmResolver = null;
      if (opener?.isConnected) opener.focus?.();
      resolve(value);
    };
    els.confirmDialogCancel.focus();
  });
}

function handleConfirmDialogKeydown(event) {
  if (!els.confirmDialog || els.confirmDialog.hidden) return false;
  if (event.key === "Escape") {
    event.preventDefault();
    state.confirmResolver?.(false);
  } else if (event.key === "Tab") {
    event.preventDefault();
    const buttons = [els.confirmDialogCancel, els.confirmDialogConfirm].filter((button) => button && !button.disabled);
    const current = buttons.indexOf(document.activeElement);
    const next = current < 0 ? 0 : (current + (event.shiftKey ? -1 : 1) + buttons.length) % buttons.length;
    buttons[next]?.focus();
  }
  return true;
}

async function deleteSelectedPermanently(file = state.selectedFile) {
  if (!file || !state.currentWorkspace || !canWriteSelectedFile()) return;
  const ok = await confirmAction({
    title: `Delete "${file.name}"?`,
    message: "This permanently removes the item and every version. This cannot be undone.",
    confirmLabel: "Delete permanently",
  });
  if (!ok) return;
  await api(`/files/${file.id}`, { method: "DELETE" });
  await loadManifest(state.currentWorkspace.id);
  setActiveView("trash");
  await loadTrashFiles();
  showToast(`Deleted "${file.name}" permanently.`);
}

async function emptyWorkspaceTrashAction() {
  if (!state.currentWorkspace) return;
  const ok = await confirmAction({
    title: "Empty trash?",
    message: "Items past the retention window will be permanently deleted. Recent items stay in Trash. This cannot be undone.",
    confirmLabel: "Empty trash",
  });
  if (!ok) return;
  const data = await api(`/workspaces/${state.currentWorkspace.id}/trash/empty`, { method: "POST" });
  await loadManifest(state.currentWorkspace.id);
  setActiveView("trash");
  await loadTrashFiles();
  showToast(window.ShellXDriveFormat.emptyTrashToast(data));
}

function clearSearch() {
  els.searchInput.value = "";
  clearAccountBrowseState();
  state.currentViewTitle = null;
  state.browserPage = 0;
  setActiveView("my-drive");
  renderFiles();
}

/* ============================================================================
 * Shared file-row context menu — ONE positioned element, actions generated from
 * file kind + role + trash/star state (overhaul-plan Task 4).
 * ==========================================================================*/

function fileMenuActions(file) {
  const info = fileTypeInfo(file);
  const canWrite = canWriteSelectedFile();
  const trashed = Boolean(file.trashed);
  if (trashed) {
    if (!canWrite) return [];
    return [
      {
        label: "Restore",
        icon: "i-refresh",
        run: () => {
          selectFile(file);
          return mutateSelected("/files/:id/restore", { clearAfter: true });
        },
      },
      {
        label: "Delete permanently",
        icon: "i-trash",
        danger: true,
        run: () => deleteSelectedPermanently(file),
      },
    ];
  }
  const items = [];
  if (info.isFolder) {
    items.push({ label: "Open", icon: "i-folder", run: () => openFolder(file.id) });
    items.push({ label: "Download folder", icon: "i-download", run: () => { selectFile(file); return downloadFolderZip(); } });
    // Folder cover images are available to editors on live items.
    if (canWrite) {
      items.push({ label: "Set cover image", icon: "i-file-image", run: () => pickFolderCover(file) });
      if (file.has_cover) {
        items.push({ label: "Remove cover", icon: "i-trash", run: () => removeFolderCover(file) });
      }
    }
  } else {
    if (info.previewable) items.push({ label: "Preview", icon: "i-eye", run: () => openPreviewModal(file) });
    items.push({ label: "Download", icon: "i-download", run: () => triggerDownload(file) });
    if (info.editable && canWrite && officeProviderAvailable()) {
      items.push({ label: "Open in editor", icon: "i-edit", run: () => { selectFile(file); return openSelectedEditor(); } });
    }
  }
  items.push({ label: "Share", icon: "i-share", run: () => { selectFile(file); openShareDrawer(); } });
  if (canWrite) {
    items.push({
      label: "Rename & details", icon: "i-edit",
      run: () => {
        selectFile(file);
        window.setTimeout(() => {
          const details = document.querySelector(".details-card details");
          if (details) details.open = true;
          els.fileDetailName.focus();
          els.fileDetailName.select();
        }, 0);
      },
    });
    items.push({ label: "Copy", icon: "i-copy", run: () => { selectFile(file); return copySelectedFile(); } });
  }
  // "Move to…" — open the folder picker for THIS file. Live items only (moving a
  // trashed item makes no sense — restore it first). Root + any folder, so a file
  // can be moved OUT of its current folder, not just dragged into one.
  if (canWrite) {
    items.push({ label: "Move to…", icon: "i-move", run: () => openMoveDialog([file.id]) });
  }
  items.push({
    label: file.starred ? "Unstar" : "Star",
    icon: file.starred ? "i-star-fill" : "i-star",
    run: () => { selectFile(file); return mutateSelected(file.starred ? "/files/:id/unstar" : "/files/:id/star"); },
  });
  if (canWrite) {
    items.push({ divider: true });
    items.push({ label: "Move to trash", icon: "i-trash", run: () => { selectFile(file); return mutateSelected("/files/:id/trash", { clearAfter: true }); } });
  }
  return items;
}

function closeFileMenu() {
  if (!els.fileContextMenu) return;
  els.fileContextMenu.hidden = true;
  els.fileContextMenu.replaceChildren();
  state.openFileMenuId = "";
}

function openFileMenu(file, anchor) {
  closeFileMenu();
  const menu = els.fileContextMenu;
  if (!menu) return;
  // `anchor` may be an element or a DOMRect captured before a re-render.
  const rect = typeof anchor.getBoundingClientRect === "function" ? anchor.getBoundingClientRect() : anchor;
  menu.replaceChildren();
  for (const item of fileMenuActions(file)) {
    if (item.divider) {
      const divider = document.createElement("div");
      divider.className = "context-divider";
      menu.append(divider);
      continue;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("role", "menuitem");
    if (item.danger) button.className = "danger";
    button.innerHTML = `<svg class="icon" aria-hidden="true"><use href="#${item.icon}"/></svg><span>${escapeHtml(item.label)}</span>`;
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      closeFileMenu();
      Promise.resolve(item.run()).catch((error) => showToast(error.message));
    });
    menu.append(button);
  }
  state.openFileMenuId = file.id;
  menu.hidden = false;
  const width = menu.offsetWidth;
  const height = menu.offsetHeight;
  let left = rect.right - width;
  let top = rect.bottom + 4;
  if (left < 8) left = 8;
  if (left + width > window.innerWidth - 8) left = window.innerWidth - width - 8;
  if (top + height > window.innerHeight - 8) top = Math.max(8, rect.top - height - 4);
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
}

// Session cache of grid-tile snippets, keyed by `${id}:${updated_at}` so an
// edited file re-fetches. Snippets are tiny (first ~200 chars) content previews.
const gridSnippetCache = new Map();
let gridSnippetGeneration = 0;
const GRID_SNIPPET_MAX_CHARS = 200;
const GRID_SNIPPET_CONCURRENCY = 4;

// Fetch the first bytes of a text/markdown file for its grid preview. Uses a
// Range request so large files never download in full (the server answers 206);
// returns a short, plain-text slice. Never throws — a failed/empty fetch just
// means the tile keeps its icon. A stale authenticated request returns null
// so its worker stops when the account or credential changes.
async function fetchGridSnippet(fileId) {
  try {
    return await authenticatedFetch(`/files/${encodeURIComponent(fileId)}/content`, {
      headers: { ...authHeaders(), range: "bytes=0-511", accept: "text/plain" },
    }, async (response) => {
      if (!response.ok && response.status !== 206) return "";
      return (await response.text()).slice(0, GRID_SNIPPET_MAX_CHARS);
    });
  } catch (error) {
    if (window.ShellXDriveAuthLifecycle.isStale(error)) return null;
    return "";
  }
}

function hydrateGridSnippets() {
  if (state.fileLayout !== "grid" || !els.fileRows) return;
  const generation = gridSnippetGeneration;
  const holders = [...els.fileRows.querySelectorAll("[data-grid-snippet]")].filter(
    (holder) => !holder.dataset.snippetDone,
  );
  if (!holders.length) return;

  const applySnippet = (holder, text) => {
    holder.dataset.snippetDone = "1";
    if (text && text.trim()) {
      holder.textContent = text;
    } else {
      // Nothing readable → remove the snippet box and let the icon show again.
      const cell = holder.closest(".file-name-cell");
      if (cell) cell.classList.remove("has-snippet");
      holder.remove();
    }
  };

  const queue = holders.slice();
  const runNext = async () => {
    if (generation !== gridSnippetGeneration) return;
    const holder = queue.shift();
    if (!holder) return;
    const row = holder.closest("tr");
    const fileId = row?.dataset.fileId;
    if (!fileId) { applySnippet(holder, ""); return runNext(); }
    const file = (state.lastRenderedFiles || []).find((item) => item.id === fileId);
    const cacheKey = `${fileId}:${file?.updated_at || ""}`;
    let text = gridSnippetCache.get(cacheKey);
    if (text === undefined) {
      text = await fetchGridSnippet(fileId);
      if (text === null || generation !== gridSnippetGeneration) return;
      gridSnippetCache.set(cacheKey, text);
    }
    applySnippet(holder, text);
    return runNext();
  };

  const workers = Math.min(GRID_SNIPPET_CONCURRENCY, queue.length);
  for (let i = 0; i < workers; i++) runNext();
}

function wireThumbnailFallbacks(root) {
  root.querySelectorAll("img.row-thumb, img[data-fallback-icon]").forEach((img) => {
    img.addEventListener("error", () => {
      const holder = img.parentElement;
      if (!holder) { img.remove(); return; }
      const iconId = holder.dataset.fileIcon || "i-file-image";
      holder.innerHTML = `<svg class="icon"><use href="#${iconId}"/></svg>`;
    }, { once: true });
  });
}

els.tokenForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = els.tokenInput.value;
  const actor = els.actorInput.value.trim();
  clearSensitiveAccountState();
  persistSession(token, actor);
  try {
    await loadCurrentAccount();
    await loadWorkspaces();
  } catch (error) {
    if (window.ShellXDriveAuthLifecycle.isStale(error)) return;
    clearSensitiveAccountState(actor);
    setStatus("Auth failed");
    els.debugOutput.textContent = error.message;
  }
});
els.accountMenuButton.addEventListener("click", () => toggleAccountPanel());
els.notificationsButton.addEventListener("click", () => toggleNotificationPanel());
els.notificationList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-read-notification]");
  if (!button) return;
  markNotificationRead(button.dataset.readNotification).catch((error) => {
    showToast(error.message);
  });
});
els.markAllNotificationsReadButton.addEventListener("click", () =>
  markAllNotificationsRead().catch((error) => {
    showToast(error.message);
  }),
);
els.logoutButton.addEventListener("click", () =>
  logoutCurrentSession().catch((error) => {
    showToast(error.message);
  }),
);
els.refreshSelfSecurityEventsButton.addEventListener("click", () =>
  selfSecurityController.load().catch((error) => {
    renderAdminLiveList(els.selfSecurityEventsList, [["Sign-in activity", error.message]]);
  }),
);
els.loginForm.addEventListener("submit", (event) =>
  loginWithPassword(event).catch((error) => {
    const message = localLoginFailureCopy(error);
    setAuthStatus(message);
    showToast(message);
  }),
);
els.forgotPasswordButton?.addEventListener("click", () => togglePasswordReset());
els.loginEmail?.addEventListener("input", () => showSecondFactorChallenge(false));
els.loginPassword?.addEventListener("input", () => showSecondFactorChallenge(false));
els.passwordResetRequestForm?.addEventListener("submit", (event) =>
  requestPasswordReset(event).catch((error) => {
    setPasswordResetStatus(error.message);
    showToast(error.message);
  }),
);
els.bootstrapForm.addEventListener("submit", (event) =>
  bootstrapFirstAdmin(event).catch((error) => {
    setAuthStatus("Setup not completed");
    els.debugOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.refreshButton.addEventListener("click", () => loadWorkspaces());
els.workspaceForm.addEventListener("submit", createWorkspace);
els.workspaceRenameForm.addEventListener("submit", (event) =>
  renameCurrentWorkspace(event).catch((error) => {
    els.workspaceLifecycleOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.workspaceArchiveButton.addEventListener("click", () =>
  archiveCurrentWorkspace().catch((error) => {
    els.workspaceLifecycleOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.workspaceUnarchiveButton.addEventListener("click", () =>
  unarchiveCurrentWorkspace().catch((error) => {
    els.workspaceLifecycleOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.workspaceTransferForm.addEventListener("submit", (event) =>
  transferCurrentWorkspaceOwner(event).catch((error) => {
    els.workspaceLifecycleOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.workspaceLeaveButton.addEventListener("click", () =>
  leaveCurrentWorkspace().catch((error) => {
    els.workspaceLifecycleOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.fileForm.addEventListener("submit", uploadFile);
els.createFolderForm.addEventListener("submit", (event) =>
  createFolder(event).catch((error) => {
    els.selectedMeta.textContent = error.message;
    showToast(error.message);
  }),
);
els.chooseFilesButton.addEventListener("click", () => els.uploadFilePicker.click());
els.chooseFolderButton.addEventListener("click", () => els.uploadFolderPicker.click());
els.cameraUploadButton.addEventListener("click", () => els.cameraUploadInput.click());
els.uploadFilePicker.addEventListener("change", () => {
  uploadBrowserFiles(els.uploadFilePicker.files).catch((error) => showToast(error.message));
  els.uploadFilePicker.value = "";
});
els.uploadFolderPicker.addEventListener("change", () => {
  uploadBrowserFiles(els.uploadFolderPicker.files).catch((error) => showToast(error.message));
  els.uploadFolderPicker.value = "";
});
els.cameraUploadInput.addEventListener("change", () => {
  uploadCameraFiles(els.cameraUploadInput.files).catch((error) => showToast(error.message));
});
els.uploadDropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  els.uploadDropZone.classList.add("drag-over");
});
els.uploadDropZone.addEventListener("dragleave", () => {
  els.uploadDropZone.classList.remove("drag-over");
});
els.uploadDropZone.addEventListener("drop", handleUploadDrop);
els.uploadDropZone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    els.uploadFilePicker.click();
  }
});

// Drop files ANYWHERE on the main drive area (not only on the upload box) — the
// standard cloud-drive behavior. Uploads to the current folder via the same
// resumable-upload + queue path used by the box and the file picker.
const driveMainDropTarget = document.querySelector(".drive-main");
if (driveMainDropTarget) {
  let dragDepth = 0;
  const dragHasFiles = (event) =>
    Array.from(event.dataTransfer?.types || []).includes("Files");
  const dropHint = () => {
    const where = state.currentFolderId
      ? "this folder"
      : state.currentWorkspace?.name || "this workspace";
    return `Drop files to upload to ${where}`;
  };
  driveMainDropTarget.addEventListener("dragenter", (event) => {
    if (!dragHasFiles(event)) return;
    event.preventDefault();
    dragDepth += 1;
    driveMainDropTarget.dataset.dropHint = dropHint();
    driveMainDropTarget.classList.add("drag-over");
  });
  driveMainDropTarget.addEventListener("dragover", (event) => {
    if (!dragHasFiles(event)) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
  });
  driveMainDropTarget.addEventListener("dragleave", (event) => {
    if (!dragHasFiles(event)) return;
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) driveMainDropTarget.classList.remove("drag-over");
  });
  driveMainDropTarget.addEventListener("drop", (event) => {
    if (!dragHasFiles(event)) return;
    event.preventDefault();
    dragDepth = 0;
    driveMainDropTarget.classList.remove("drag-over");
    // Traverse dropped folders (empty FileList) via the entries API, preserving
    // nested structure; plain files fall back to a flat, path-less upload.
    collectDropEntries(event.dataTransfer)
      .then((entries) => uploadBrowserEntries(entries))
      .catch((error) => showToast(error.message));
  });
}
function handleOfflineShellNavigation(view) {
  if (!state.offlineShell) return false;
  setActiveView(view);
  showToast("Reconnect to browse files in this view.");
  return true;
}

els.viewMyDriveButton.addEventListener("click", () => {
  if (handleOfflineShellNavigation("my-drive")) return;
  state.searchRequestSequence += 1;
  humanSharing.loadDefaultFiles().catch((error) => showToast(error.message));
});
els.offlineRetryButton?.addEventListener("click", () => window.location.reload());
els.mineButton?.addEventListener("click", () => {
  if (handleOfflineShellNavigation("mine")) return;
  loadBrowseFiles("mine").catch((error) => showToast(error.message));
});
els.searchInput.addEventListener("input", async () => {
  const q = els.searchInput.value.trim();
  state.browserPage = 0;
  const requestSequence = ++state.searchRequestSequence;
  if (!q) {
    clearAccountBrowseState();
    state.currentViewTitle = null;
    setActiveView("my-drive");
    renderFiles();
    return;
  }
  try {
    const data = await api(`/search?q=${encodeURIComponent(q)}`);
    if (requestSequence !== state.searchRequestSequence || els.searchInput.value.trim() !== q) return;
    clearAccountBrowseState();
    state.currentViewTitle = data.has_more ? "Search results · first 100 matches" : "Search results";
    setActiveView("my-drive");
    renderFiles(data.files || []);
  } catch (error) {
    if (requestSequence === state.searchRequestSequence) showToast(`Search failed: ${error.message}`);
  }
});
els.recentButton.addEventListener("click", () => {
  if (handleOfflineShellNavigation("recent")) return;
  clearRailViewSelection();
  loadBrowseFiles("recent").catch((error) => showToast(error.message));
});
els.sharedButton.addEventListener("click", () => {
  if (handleOfflineShellNavigation("shared")) return;
  clearRailViewSelection();
  humanSharing.loadRoots("shared-with-me").catch((error) => showToast(error.message));
});
els.sharedByMeButton?.addEventListener("click", () => {
  if (handleOfflineShellNavigation("shared-by-me")) return;
  clearRailViewSelection(); humanSharing.loadRoots("shared-by-me").catch((error) => showToast(error.message));
});
els.starredButton.addEventListener("click", async () => {
  if (handleOfflineShellNavigation("starred")) return;
  clearAccountBrowseState();
  setActiveView("starred");
  clearRailViewSelection();
  const data = await api("/starred");
  state.currentViewTitle = "Starred files";
  renderFiles(data.files || []);
});
els.offlineButton.addEventListener("click", () => {
  if (handleOfflineShellNavigation("offline")) return;
  clearAccountBrowseState();
  setActiveView("offline");
  clearRailViewSelection();
  state.currentViewTitle = "Mobile downloads";
  renderFiles(state.files.filter((file) => isOfflineMarked(file)));
});
els.trashViewButton.addEventListener("click", () => {
  if (handleOfflineShellNavigation("trash")) return;
  clearAccountBrowseState();
  setActiveView("trash");
  clearRailViewSelection();
  state.currentViewTitle = "Trash";
  renderFiles([]);
  loadTrashFiles().catch((error) => showToast(error.message));
});
els.uploadFocusButton.addEventListener("click", (event) => {
  event.stopPropagation();
  if (els.uploadMenu.hidden) openUploadMenu();
  else closeUploadMenu();
});
els.uploadMenuFiles?.addEventListener("click", () => {
  closeUploadMenu();
  els.uploadFilePicker.click();
});
els.uploadMenuFolder?.addEventListener("click", () => {
  closeUploadMenu();
  els.uploadFolderPicker.click();
});
els.newMenuButton.addEventListener("click", (event) => {
  event.stopPropagation();
  if (els.newMenu.hidden) openNewMenu();
  else closeNewMenu();
});
els.listViewButton.addEventListener("click", () => setViewMode("list"));
els.gridViewButton.addEventListener("click", () => setViewMode("grid"));
els.fileSortKey?.addEventListener("change", () =>
  setBrowserPreference("sortKey", els.fileSortKey.value),
);
els.fileSortDirection?.addEventListener("click", () =>
  setBrowserPreference(
    "direction",
    state.browserPreferences.direction === "asc" ? "desc" : "asc",
  ),
);
els.foldersFirst?.addEventListener("change", () =>
  setBrowserPreference("foldersFirst", els.foldersFirst.checked),
);
[
  [els.browserTypeFilter, "typeFilter"],
  [els.browserOwnerFilter, "ownerScope"],
  [els.browserModifiedFilter, "modifiedRange"],
  [els.browserLocationFilter, "locationScope"],
  [els.browserStateFilter, "stateFilter"],
].forEach(([control, key]) => {
  control?.addEventListener("change", () => setBrowserPreference(key, control.value));
});
els.browserFilterToggle?.addEventListener("click", () => {
  const open = els.browserFilterPanel.hidden;
  els.browserFilterPanel.hidden = !open;
  els.browserFilterToggle.setAttribute("aria-expanded", String(open));
  if (open) els.browserTypeFilter.focus();
});
els.browserFilterClear?.addEventListener("click", () => {
  const defaults = window.ShellXDriveBrowser.defaults();
  state.browserPreferences = window.ShellXDriveBrowser.normalizePreferences({
    ...state.browserPreferences,
    typeFilter: defaults.typeFilter,
    ownerScope: defaults.ownerScope,
    modifiedRange: defaults.modifiedRange,
    locationScope: defaults.locationScope,
    stateFilter: defaults.stateFilter,
  });
  state.activeFileFilter = "all";
  state.browserPage = 0;
  persistBrowserPreferences();
  syncBrowserControls();
  if (isAccountBrowseView()) reloadAccountBrowse();
  else renderFiles(state.hasCurrentBaseFiles ? state.currentBaseFiles : state.files);
});
els.filePagePrevious?.addEventListener("click", () => {
  if (isAccountBrowseView() && state.browsePageIndex > 0) {
    const previousPageIndex = state.browsePageIndex - 1;
    loadAccountPage(state.browsePageCursors[previousPageIndex], previousPageIndex).catch((error) => showToast(error.message));
    return;
  }
  state.browserPage = Math.max(0, state.browserPage - 1);
  renderFiles(state.hasCurrentBaseFiles ? state.currentBaseFiles : state.files);
});
els.filePageNext?.addEventListener("click", () => {
  if (isAccountBrowseView() && state.browseNextCursor) {
    loadAccountPage(state.browseNextCursor, state.browsePageIndex + 1).catch((error) => showToast(error.message));
    return;
  }
  state.browserPage += 1;
  renderFiles(state.hasCurrentBaseFiles ? state.currentBaseFiles : state.files);
});
els.selectVisibleFiles.addEventListener("change", () => {
  const ids = selectedBulkIds();
  for (const id of visibleFileIds()) {
    if (els.selectVisibleFiles.checked) {
      ids.add(id);
    } else {
      ids.delete(id);
    }
  }
  setBulkSelected([...ids]);
});
els.bulkMoveButton?.addEventListener("click", () => {
  const availability = bulkActionAvailability();
  if (!availability.move) return;
  openMoveDialog(availability.selected.map((file) => file.id));
});
els.bulkDownloadButton?.addEventListener("click", async () => {
  const availability = bulkActionAvailability();
  if (!availability.download) return;
  const ids = availability.selected.map((file) => file.id);
  els.bulkDownloadButton.disabled = true;
  try {
    await window.ShellXDownloadTickets.start({
      endpoint: "/files/download-zip",
      body: { file_ids: ids },
      headers: authHeaders(),
    });
    showToast(`Preparing ${ids.length} ${ids.length === 1 ? "item" : "items"} for download.`);
  } catch (error) {
    if (!window.ShellXDriveAuthLifecycle.isStale(error)) {
      showToast(error.message || "The selected items could not be downloaded.");
    }
  } finally {
    renderBulkActionToolbar();
  }
});
els.moveDialogCancel?.addEventListener("click", closeMoveDialog);
els.moveDialogClose?.addEventListener("click", closeMoveDialog);
els.moveDialog?.addEventListener("click", (event) => {
  if (event.target === els.moveDialog) closeMoveDialog();
});
els.createDialogClose?.addEventListener("click", closeCreateDialog);
els.createDialog?.addEventListener("click", (event) => {
  if (event.target === els.createDialog) closeCreateDialog();
});
els.createDialog?.querySelectorAll("[data-create-cancel]").forEach((button) => {
  button.addEventListener("click", closeCreateDialog);
});
els.bulkStarButton.addEventListener("click", () =>
  runBulkFileAction("star").catch((error) => {
    els.selectedMeta.textContent = error.message;
    showToast(error.message);
  }),
);
els.bulkUnstarButton.addEventListener("click", () =>
  runBulkFileAction("unstar").catch((error) => {
    els.selectedMeta.textContent = error.message;
    showToast(error.message);
  }),
);
els.bulkTrashButton.addEventListener("click", () =>
  runBulkFileAction("trash").catch((error) => {
    els.selectedMeta.textContent = error.message;
    showToast(error.message);
  }),
);
els.bulkRestoreButton.addEventListener("click", () =>
  runBulkFileAction("restore").catch((error) => {
    els.selectedMeta.textContent = error.message;
    showToast(error.message);
  }),
);
document.querySelectorAll("[data-file-filter]").forEach((button) => {
  button.addEventListener("click", () => setFileFilter(button.dataset.fileFilter || "all"));
});
els.copyDropLinkButton?.addEventListener("click", copyLatestDropLink);
els.bottomDownloadButton.addEventListener("click", () =>
  downloadSelected().catch((error) => showToast(error.message)),
);
els.bottomOpenButton.addEventListener("click", () =>
  openPreviewModal().catch((error) => showToast(error.message)),
);
els.accountAdminButton?.addEventListener("click", () => {
  toggleAccountPanel(false);
  paintAdminSkeletons();
  openAdvanced();
  if (!state.adminSummary) {
    refreshAdminCommandCenter().catch(() => {});
  }
});
els.advancedCloseButton.addEventListener("click", closeAdvanced);
els.themeToggleButton?.addEventListener("click", toggleTheme);
els.headerThemeToggle?.addEventListener("click", toggleTheme);
els.workspaceSettingsButton?.addEventListener("click", openWorkspaceSettings);
els.accountWorkspaceSettingsButton?.addEventListener("click", () => {
  toggleAccountPanel(false);
  openWorkspaceSettings();
});
els.workspaceSettingsClose?.addEventListener("click", closeWorkspaceSettings);
els.workspaceSettingsDrawer?.addEventListener("click", (event) => {
  if (event.target === els.workspaceSettingsDrawer) closeWorkspaceSettings();
});
els.accountSettingsButton?.addEventListener("click", openSettings);
els.settingsClose?.addEventListener("click", closeSettings);
els.settingsDrawer?.addEventListener("click", (event) => {
  if (event.target === els.settingsDrawer) closeSettings();
});
els.quickCreateClose?.addEventListener("click", hideQuickCreate);
els.newMenuFolder?.addEventListener("click", () => {
  closeNewMenu();
  openCreateDialog("folder");
});
els.newMenuFile?.addEventListener("click", () => {
  closeNewMenu();
  openCreateDialog("text");
});
els.newMenuUpload?.addEventListener("click", () => {
  closeNewMenu();
  // Reveal the full drop-zone surface, then open the OS picker for convenience.
  showQuickCreate(null, "upload");
  els.uploadFilePicker.click();
});
els.newMenuUploadFolder?.addEventListener("click", () => {
  closeNewMenu();
  showQuickCreate(null, "upload");
  els.uploadFolderPicker.click();
});
els.previewOpenButton?.addEventListener("click", () =>
  openPreviewModal().catch((error) => showToast(error.message)),
);
els.deletePermanentlyButton?.addEventListener("click", () =>
  deleteSelectedPermanently().catch((error) => showToast(error.message)),
);
els.emptyTrashButton?.addEventListener("click", () =>
  emptyWorkspaceTrashAction().catch((error) => showToast(error.message)),
);
els.confirmDialogConfirm?.addEventListener("click", () => state.confirmResolver?.(true));
els.confirmDialogCancel?.addEventListener("click", () => state.confirmResolver?.(false));
els.confirmDialog?.addEventListener("click", (event) => {
  if (event.target === els.confirmDialog) state.confirmResolver?.(false);
});
document.querySelectorAll("[data-mobile-action]").forEach((button) => {
  button.addEventListener("click", () => {
    const action = button.dataset.mobileAction;
    if (action === "dismiss") {
      clearSelection();
      return;
    }
    if (action === "share") openShareDrawer();
    if (action === "comment") els.commentBody.focus();
    if (action === "open") {
      openPreviewModal().catch((error) => showToast(error.message));
    }
    if (action === "offline") {
      if (isAccountBrowseView()) return;
      mobileSync.setSelectedOffline(true).catch((error) => {
        els.mobileOutput.textContent = error.message;
        showToast(error.message);
      });
    }
  });
});
els.resumableUploadForm.addEventListener("submit", (event) =>
  createResumableUpload(event).catch((error) => {
    els.uploadStatus.textContent = error.message;
    showToast(error.message);
  }),
);
els.appendUploadButton.addEventListener("click", () =>
  appendUploadChunk(false).catch((error) => {
    els.uploadStatus.textContent = error.message;
    showToast(error.message);
  }),
);
els.finishUploadButton.addEventListener("click", () =>
  appendUploadChunk(true).catch((error) => {
    els.uploadStatus.textContent = error.message;
    showToast(error.message);
  }),
);
els.refreshUploadSessionsButton.addEventListener("click", () =>
  loadUploadSessions().catch((error) => {
    els.uploadStatus.textContent = error.message;
    showToast(error.message);
  }),
);
els.cancelUploadSessionButton.addEventListener("click", () =>
  cancelSelectedUploadSession().catch((error) => {
    els.uploadStatus.textContent = error.message;
    showToast(error.message);
  }),
);
els.cleanupUploadsButton.addEventListener("click", () =>
  cleanupUploadSessions().catch((error) => {
    els.uploadStatus.textContent = error.message;
    showToast(error.message);
  }),
);
els.downloadButton.addEventListener("click", () =>
  downloadSelected().catch((error) => showToast(error.message)),
);
els.downloadFolderZipButton.addEventListener("click", () =>
  downloadFolderZip().catch((error) => {
    els.selectedMeta.textContent = error.message;
    showToast(error.message);
  }),
);
els.loadContentButton.addEventListener("click", () =>
  loadSelectedContent().catch((error) => {
    els.selectedMeta.textContent = error.message;
  }),
);
els.openEditorButton.addEventListener("click", () =>
  openSelectedEditor().catch((error) => {
    els.selectedMeta.textContent = error.message;
    state.officeProviderStatus = error.message;
    renderOfficeProviderStatus();
  }),
);
els.saveContentButton.addEventListener("click", () =>
  saveSelectedContent().catch((error) => {
    els.selectedMeta.textContent = error.message;
  }),
);
els.saveFileDetailsButton.addEventListener("click", () =>
  saveFileDetails().catch((error) => {
    els.selectedMeta.textContent = error.message;
  }),
);
els.copyFileButton.addEventListener("click", () =>
  copySelectedFile().catch((error) => {
    els.selectedMeta.textContent = error.message;
  }),
);
els.starButton.addEventListener("click", () => {
  // Inspector star mirrors + toggles the selected file's real starred state.
  const file = state.selectedFile;
  if (!file) return;
  mutateSelected(file.starred ? "/files/:id/unstar" : "/files/:id/star").catch((error) =>
    showToast(error.message),
  );
});
els.closeSelectionButton.addEventListener("click", clearSelection);
els.trashButton.addEventListener("click", () =>
  mutateSelected("/files/:id/trash", { clearAfter: true }).catch((error) => showToast(error.message)),
);
els.restoreButton.addEventListener("click", () =>
  mutateSelected("/files/:id/restore", { clearAfter: true }).catch((error) => showToast(error.message)),
);
els.dropForm.addEventListener("submit", (event) =>
  createDrop(event).catch((error) => {
    els.shareOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.dropManagementRefreshButton.addEventListener("click", () =>
  loadManagedDrops().catch((error) => {
    els.shareOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.dropManagementList.addEventListener("click", (event) => {
  const openButton = event.target.closest("[data-open-drop-inbox]");
  if (openButton) {
    const drop = state.managedDrops.find((item) => item.id === openButton.dataset.openDropInbox);
    openManagedDropInbox(drop);
    return;
  }
  const button = event.target.closest("[data-select-drop]");
  if (!button) return;
  state.selectedDropId = button.dataset.selectDrop;
  renderManagedDrops();
});
els.dropOpenInboxButton.addEventListener("click", () => {
  const drop = state.managedDrops.find((item) => item.id === els.dropUpdateSelect.value);
  openManagedDropInbox(drop);
});
els.dropUpdateSelect.addEventListener("change", () => {
  state.selectedDropId = els.dropUpdateSelect.value;
  renderManagedDrops();
});
els.dropUpdateForm.addEventListener("submit", (event) =>
  updateSelectedDrop(event).catch((error) => {
    els.shareOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.dropRevokeButton.addEventListener("click", () =>
  revokeManagedDrop().catch((error) => {
    els.shareOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.mobileOfflineButton.addEventListener("click", () => !isAccountBrowseView() &&
  mobileSync.setSelectedOffline(true).catch((error) => {
    els.mobileOutput.textContent = error.message;
  }),
);
els.mobileOnlineButton.addEventListener("click", () => !isAccountBrowseView() &&
  mobileSync.setSelectedOffline(false).catch((error) => {
    els.mobileOutput.textContent = error.message;
  }),
);
els.mobileManifestButton.addEventListener("click", () =>
  mobileSync.loadManifest().catch((error) => {
    els.mobileOutput.textContent = error.message;
  }),
);
els.memberForm.addEventListener("submit", (event) =>
  saveMember(event).catch((error) => {
    els.selectedMeta.textContent = error.message;
    showToast(error.message);
  }),
);
els.memberRemoveForm.addEventListener("submit", (event) =>
  removeMember(event).catch((error) => {
    els.selectedMeta.textContent = error.message;
    showToast(error.message);
  }),
);
els.templateForm.addEventListener("submit", (event) =>
  createFolderTemplate(event).catch((error) => {
    els.templateOutput.textContent = error.message;
  }),
);
els.applyTemplateButton.addEventListener("click", () =>
  applyFolderTemplate().catch((error) => {
    els.templateOutput.textContent = error.message;
  }),
);
document.querySelectorAll("[data-admin-section]").forEach((button) => {
  button.addEventListener("click", () => setAdminSection(button.dataset.adminSection || "overview"));
});
els.adminSectionSelect?.addEventListener("change", () => setAdminSection(els.adminSectionSelect.value));
els.adminActivitySearch?.addEventListener("input", renderAdminActivity);
els.adminActivityFilter?.addEventListener("change", renderAdminActivity);
els.adminAccountsSearch?.addEventListener("input", renderAuthAccounts);
els.adminAccountsFilter?.addEventListener("change", renderAuthAccounts);
els.adminAuthAttemptsSearch?.addEventListener("input", renderAuthAttempts);
els.adminAuthAttemptsFilter?.addEventListener("change", renderAuthAttempts);
els.adminBackupPolicyEnabled?.addEventListener("change", () => {
  els.adminBackupPolicySchedule.disabled = !els.adminBackupPolicyEnabled.checked;
});
els.adminAuthSummary?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-admin-auth-email]");
  if (!button) return;
  state.selectedAdminAuthEmail = button.dataset.adminAuthEmail;
  renderAuthAccounts();
  renderAdminAuthUpdateForm();
});
els.adminAuthUpdateEmail?.addEventListener("change", () => {
  state.selectedAdminAuthEmail = els.adminAuthUpdateEmail.value;
  renderAuthAccounts();
  renderAdminAuthUpdateForm();
});
els.authAccountForm.addEventListener("submit", (event) =>
  createAuthAccount(event).catch((error) => {
    els.adminAuthOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminAuthUpdateForm?.addEventListener("submit", (event) =>
  updateSelectedAuthAccount(event).catch((error) => {
    els.adminAuthOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminAuthRevokeSessionsButton?.addEventListener("click", () =>
  revokeSelectedAuthSessions().catch((error) => {
    els.adminAuthOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminEmailRefreshButton?.addEventListener("click", () =>
  loadAdminEmail().catch((error) => {
    els.adminEmailSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminEmailRunButton?.addEventListener("click", () =>
  runAdminEmailQueue().catch((error) => {
    els.adminEmailSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.totpSetupButton.addEventListener("click", () =>
  setupTotp().catch((error) => {
    els.accountSecurityOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.totpEnableButton.addEventListener("click", () =>
  enableTotp().catch((error) => {
    els.accountSecurityOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.totpDisableButton.addEventListener("click", () =>
  disableTotp().catch((error) => {
    els.accountSecurityOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.recoveryRotateButton.addEventListener("click", () =>
  rotateRecoveryCodes().catch((error) => {
    els.accountSecurityOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.groupForm.addEventListener("submit", (event) =>
  createGroup(event).catch((error) => {
    els.groupsOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.groupMemberForm.addEventListener("submit", (event) =>
  addGroupMember(event).catch((error) => {
    els.groupsOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.groupGrantForm.addEventListener("submit", (event) =>
  grantGroupToCurrentWorkspace(event).catch((error) => {
    els.groupsOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.groupRevokeButton.addEventListener("click", () =>
  revokeGroupFromCurrentWorkspace().catch((error) => {
    els.groupsOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.storagePolicyForm.addEventListener("submit", (event) =>
  saveStoragePolicy(event).catch((error) => {
    els.storagePolicyOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.storagePolicyRefreshButton.addEventListener("click", () =>
  loadWorkspacePolicyAndUsage().catch((error) => {
    els.storagePolicyOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.sharingPolicyForm.addEventListener("submit", (event) =>
  saveSharingPolicy(event).catch((error) => {
    els.sharingPolicyOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminBackupPolicyForm?.addEventListener("submit", (event) =>
  saveBackupPolicy(event).catch((error) => {
    els.adminBackupsSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminBackupPolicyRefreshButton?.addEventListener("click", () =>
  loadBackupPolicy().catch((error) => {
    els.adminBackupsSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminBackupCreateButton?.addEventListener("click", () =>
  createAdminBackup().catch((error) => {
    els.adminBackupsSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminBackupsRefreshButton?.addEventListener("click", () =>
  loadAdminBackups().catch((error) => {
    els.adminBackupsSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminBackupValidateButton?.addEventListener("click", () =>
  validateSelectedAdminBackup().catch((error) => {
    els.adminBackupsSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminBackupDownloadButton?.addEventListener("click", () =>
  downloadSelectedAdminBackup().catch((error) => {
    els.adminBackupsSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminBackupRestoreButton?.addEventListener("click", () =>
  restoreSelectedAdminBackup().catch((error) => {
    els.adminBackupsSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminBackupDeleteButton?.addEventListener("click", () =>
  deleteSelectedAdminBackup().catch((error) => {
    els.adminBackupsSummary.textContent = error.message;
    showToast(error.message);
  }),
);
els.sandboxForm.addEventListener("submit", (event) =>
  saveSandboxProfile(event).catch((error) => {
    els.sandboxOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.sandboxPreviewButton.addEventListener("click", () =>
  previewSandboxProfile().catch((error) => {
    els.sandboxOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.sandboxApplyIntentButton?.addEventListener("click", () =>
  recordSandboxApplyIntent().catch((error) => {
    els.sandboxOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.retentionPreviewButton?.addEventListener("click", () =>
  runRetentionCleanup(false).catch((error) => {
    els.retentionOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.retentionApplyButton?.addEventListener("click", () =>
  runRetentionCleanup(true).catch((error) => {
    els.retentionOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.maintenanceRefreshButton.addEventListener("click", () =>
  loadMaintenanceStatus().catch((error) => {
    els.maintenanceOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminReadinessRefreshButton?.addEventListener("click", () =>
  loadReadinessStatus().catch((error) => {
    els.maintenanceOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminSupportBundleButton?.addEventListener("click", () =>
  createSupportBundle().catch((error) => {
    els.maintenanceOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.adminRefreshButton.addEventListener("click", () =>
  refreshAdminCommandCenter().catch((error) => {
    els.adminOutput.textContent = error.message;
  }),
);
els.adminCanonicalRefreshButton?.addEventListener("click", () => humanSharing.loadAdminInventory().catch((error) => showToast(error.message)));
els.syncRefreshButton.addEventListener("click", () =>
  loadSyncHealth().catch((error) => {
    els.syncOutput.textContent = error.message;
  }),
);
els.syncChangesButton.addEventListener("click", () =>
  loadSyncChanges().catch((error) => {
    els.syncOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.syncConflictsButton.addEventListener("click", () =>
  loadSyncConflicts().catch((error) => {
    els.syncOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.importPreviewButton.addEventListener("click", () =>
  mobileSync.previewImportBundle().catch((error) => {
    els.importExportOutput.textContent = error.message;
    showToast(error.message);
  }),
);
els.importBundleButton.addEventListener("click", () =>
  mobileSync.importBundle().catch((error) => {
    els.importExportOutput.textContent = error.message;
  }),
);
els.exportBundleButton.addEventListener("click", () =>
  mobileSync.exportBundle().catch((error) => {
    els.importExportOutput.textContent = error.message;
  }),
);
els.adminAuthAttemptsButton.addEventListener("click", () =>
  loadAuthAttempts().catch((error) => {
    els.adminAuthAttempts.textContent = error.message;
  }),
);
els.adminAuthAttempts.addEventListener("click", (event) => {
  const button = event.target.closest("[data-auth-attempt-unlock]");
  if (!button) return;
  unlockAuthAttempt(button.dataset.authAttemptUnlock).catch((error) => {
    els.adminAuthAttempts.textContent = error.message;
  });
});
window.addEventListener("keydown", (event) => {
  if (handleConfirmDialogKeydown(event)) return;
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    els.searchInput.focus();
    els.searchInput.select();
  }
  if (event.key === "Escape") {
    if (els.passwordResetRequestForm && !els.passwordResetRequestForm.hidden) {
      togglePasswordReset(false); els.forgotPasswordButton?.focus();
      return;
    }
    if (state.openFileMenuId) { closeFileMenu(); return; }
    if (els.createDialog && !els.createDialog.hidden) { closeCreateDialog(); return; }
    if (els.moveDialog && !els.moveDialog.hidden) { closeMoveDialog(); return; }
    if (els.newMenu && !els.newMenu.hidden) { closeNewMenu(); return; }
    if (els.uploadMenu && !els.uploadMenu.hidden) { closeUploadMenu(); return; }
    if (els.previewModal && !els.previewModal.hidden) { closePreviewModal(); return; }
    if (els.shareDrawer && !els.shareDrawer.hidden) { closeShareDrawer(); return; }
    if (els.settingsDrawer && !els.settingsDrawer.hidden) { closeSettings(); return; }
    if (els.workspaceSettingsDrawer && !els.workspaceSettingsDrawer.hidden) { closeWorkspaceSettings(); return; }
    if (els.advancedWorkbench && !els.advancedWorkbench.hidden) { closeAdvanced(); return; }
    if (els.accountPanel && !els.accountPanel.hidden) { toggleAccountPanel(false); return; }
    if (els.notificationPanel && !els.notificationPanel.hidden) { toggleNotificationPanel(false); return; }
  }
});
document.addEventListener("click", (event) => {
  if (
    state.openFileMenuId &&
    els.fileContextMenu &&
    !els.fileContextMenu.contains(event.target)
  ) {
    closeFileMenu();
  }
  if (
    els.newMenu &&
    !els.newMenu.hidden &&
    !els.newMenu.contains(event.target) &&
    !els.newMenuButton.contains(event.target)
  ) {
    closeNewMenu();
  }
  if (
    els.uploadMenu &&
    !els.uploadMenu.hidden &&
    !els.uploadMenu.contains(event.target) &&
    !els.uploadFocusButton.contains(event.target)
  ) {
    closeUploadMenu();
  }
  if (
    els.accountPanel &&
    !els.accountPanel.hidden &&
    !els.accountPanel.contains(event.target) &&
    !els.accountMenuButton.contains(event.target)
  ) {
    toggleAccountPanel(false);
  }
  if (
    els.notificationPanel &&
    !els.notificationPanel.hidden &&
    !els.notificationPanel.contains(event.target) &&
    !els.notificationsButton.contains(event.target)
  ) {
    toggleNotificationPanel(false);
  }
});
window.addEventListener("resize", () => {
  if (state.openFileMenuId) closeFileMenu();
  if (els.newMenu && !els.newMenu.hidden) closeNewMenu();
  if (els.uploadMenu && !els.uploadMenu.hidden) closeUploadMenu();
});

applyTheme();
setViewMode(state.fileLayout);
registerServiceWorker();

startVersionWatch();
setAdminSection(state.activeAdminSection);
setAdvancedTab();
renderCurrentAccount();
renderSelfSessions();
renderStorageSummary();
renderMembers();
renderWorkspaceInvitations();
renderManagedShares();
renderManagedDrops();
renderNotifications();
renderUploadSessions();
browserUploads.render();
renderSyncChangeList("changes", []);
renderFolderBreadcrumb();
renderBulkActionToolbar();
renderSelection();
renderFolderTemplates();
applyUiState();

initializeAuthentication();
