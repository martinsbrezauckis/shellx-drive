//! Safety-first, platform-neutral mirror engine for ShellX Drive Desktop.
//!
//! This crate deliberately has no dependency on the Drive server crate or on
//! Tauri.  It owns non-secret pairing state, reconciliation planning, and the
//! HTTP contract used by the desktop shell. It also owns the serialized
//! login/Disconnect admission boundary. Bearer tokens stay behind the
//! [`CredentialStore`] abstraction and are never part of [`DesktopState`].

mod auth_attempts;
mod auth_offboarding;
mod bounded_io;
mod budget;
mod conflicts;
mod coordinator;
mod credentials;
mod desktop_agent;
mod desktop_update;
mod disconnect_cleanup;
mod discovery_budget;
mod error;
mod folder_choices;
#[cfg(all(test, target_os = "linux"))]
mod glib_variant_iter_tests;
mod http;
mod local_scan;
mod mirror;
mod model;
mod pair_profiles;
mod paths;
mod pending_retirement;
mod response_binding;
mod session_revocations;
mod state;
mod state_limits;
#[cfg(test)]
mod state_pairing_tests;
mod sync_root_policy;
mod sync_roots;
mod uninstall_offboarding;
mod uninstall_readiness;

pub use auth_attempts::AuthAttemptEpoch;
pub use auth_offboarding::AuthOffboardingGate;
pub use bounded_io::{
    copy_and_hash_reader_bounded, hash_reader_bounded, hash_reader_bounded_with_cancellation,
    sync_cycle_local_read_limit, with_cycle_read_budget, ReadBudget,
};
pub use budget::{validate_sync_pass, SyncCycleBudget, SyncPassAdmission, SyncPassLimits};
pub use conflicts::conflict_copy_path;
pub use coordinator::{
    CoordinatorViewSnapshot, DisconnectRequest, LifecycleOperation, MirrorCoordinator, SyncRun,
};
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use credentials::uninstall_credential_registry_empty;
pub use credentials::{
    classify_exact_credential_readback, classify_exact_credential_removal,
    classify_exact_credential_write, CredentialStore, ExactCredentialRead, ExactCredentialRemoval,
    ExactCredentialWrite, FakeCredentialStore,
};
#[cfg(target_os = "linux")]
pub use credentials::{
    LinuxCredentialStore, LinuxDesktopAgentCredentialStore,
    LinuxDesktopAgentDisconnectCredentialStore, PendingLinuxCredentialStore,
};
#[cfg(target_os = "macos")]
pub use credentials::{
    MacOsCredentialStore, MacOsDesktopAgentCredentialStore,
    MacOsDesktopAgentDisconnectCredentialStore, PendingMacOsCredentialStore,
};
#[cfg(target_os = "windows")]
pub use credentials::{
    PendingWindowsCredentialStore, WindowsCredentialStore, WindowsDesktopAgentCredentialStore,
    WindowsDesktopAgentDisconnectCredentialStore,
};
pub use desktop_agent::{
    desktop_agent_disconnect_credential_key, desktop_agent_enrollment_fingerprint,
    desktop_agent_pair_fingerprint, product_label, review_cursor,
    validate_disconnect_completion_capability, validate_page_result, DesktopAgentAbandonmentReason,
    DesktopAgentClaim, DesktopAgentClaimPayload, DesktopAgentCommand,
    DesktopAgentCommandJournalEntry, DesktopAgentCommandJournalState, DesktopAgentCommandKind,
    DesktopAgentControlState, DesktopAgentDesktopViewPage, DesktopAgentDesktopViewPageRequest,
    DesktopAgentDesktopViewSection, DesktopAgentDeviceAssertion,
    DesktopAgentDisconnectBlockedReason, DesktopAgentDisconnectContinuation,
    DesktopAgentDisconnectPhase, DesktopAgentDisconnectTerminalReceipt,
    DesktopAgentDisconnectUnconfirmedDisposition, DesktopAgentDisconnectUnconfirmedTerminal,
    DesktopAgentJournalRecovery, DesktopAgentLocalGesture, DesktopAgentObservedStatus,
    DesktopAgentPairRow, DesktopAgentPairStatus, DesktopAgentPendingProgress, DesktopAgentPlatform,
    DesktopAgentProgressPhase, DesktopAgentRegistration, DesktopAgentResultCode,
    DesktopAgentResultPayload, DesktopAgentReviewRow, DesktopAgentRootRow,
    DesktopAgentRootSelectionStatus, DesktopAgentRootsPage, DesktopAgentRootsPageRequest,
    DesktopAgentTerminalCode, DesktopAgentTerminalStatus, DesktopAgentUpdateAvailability,
    CURRENT_DESKTOP_AGENT_PLATFORM, MAX_DESKTOP_AGENT_JOURNAL_ENTRIES,
    MAX_DESKTOP_AGENT_PAGE_BYTES, MAX_DESKTOP_AGENT_PAGE_ROWS,
};
pub use desktop_update::{DesktopUpdateRestartIntent, DesktopUpdateRestartReadback};
pub use disconnect_cleanup::{
    DisconnectCleanupIntent, DisconnectCredentialNamespace, DisconnectCredentialSlot,
    DisconnectMarkerCleanup, MAX_DISCONNECT_CLEANUP_CREDENTIAL_SLOTS,
};
pub use discovery_budget::WorkspaceDiscoveryBudget;
pub use error::{DesktopError, Result};
pub use folder_choices::{folder_choice_labels, FolderChoiceLabel};
pub use http::{
    DesktopAgentCommandEventDisposition, DesktopAgentDisconnectTransportError,
    DesktopAgentProgressReport, DesktopAgentTerminalReport, DriveHttpClient, ExistingFileTransfer,
    LoginOutcome, LogoutOutcome, RemoteFile, RemoteFileKind, RemoteMoveTransfer,
    RemoteSessionRevocationOutcome, ServerValidation, SyncRootManifest, SyncRootPage, Workspace,
};
pub use local_scan::{
    inspect_local_tree, inspect_local_tree_with_budget,
    inspect_local_tree_with_budget_and_cancellation, inspect_local_tree_with_cancellation,
    measure_local_tree_usage, measure_local_tree_usage_with_limits, LocalScanLimits,
    LocalTreeUsage,
};
pub use mirror::{
    apply_local_path_compatibility_reviews, capture_folder_remote_witness,
    download_precondition_matches, download_publication_disposition, folder_remote_witness_matches,
    folder_subtree_matches_precondition, hex_digest, is_path_compatibility_review,
    plan_reconciliation, reviewed_local_subtree_matches_baseline,
    reviewed_remote_subtree_matches_baseline, scan_local_tree, upload_precondition_matches,
    DownloadPrecondition, DownloadPublicationDisposition, FolderMoveEntry, FolderMovePrecondition,
    FolderRemoteWitness, FolderRemoteWitnessEntry, FolderRemoteWitnessNode, LocalEntry,
    LocalPathIssue, LocalTreeInspection, ReconcilePlan, RemoteEntry, RemoteEntryKind, SyncAction,
    SIMPLE_EXISTING_REPLACEMENT_LIMIT,
};
pub use model::{
    resolve_review_decision, review_confirmation_fingerprint, sync_pair_identity_matches,
    ActivityEntry, BaselineEntry, DesktopState, DirectoryIdentity, DirectoryIdentityPlatform,
    PairMarker, ReviewAction, ReviewDecision, ReviewItem, ReviewKind, SyncPair, SyncPairState,
    SyncStatus, WindowsDirectoryIdentity, CANDIDATE_RECOVERY_PAUSED_ERROR, STATUS_STATES,
};
pub use pair_profiles::{sync_pair_id, MAX_SYNC_PAIRS};
pub use paths::{
    capture_local_operation_boundary, download_staging_root, ensure_empty_local_root,
    ensure_local_operation_boundary, ensure_single_linked_regular_file, ensure_tree_has_no_links,
    initialize_owned_staging_root, inspect_remote_paths, map_remote_paths, restore_staging_root,
    upload_staging_root, validate_local_relative, validate_windows_compatible_relative,
    verify_local_operation_boundary, windows_paths_equal_ignore_case, LocalOperationBoundary,
    OwnedStagingRoot, PathIssue, RemotePathIssue, RemotePathMapping,
};
pub use paths::{ensure_private_staging_directory, validate_private_staging_file};
pub use pending_retirement::{
    confirm_direct_retirement, pending_record_requires_authorized_retirement,
    pending_record_requires_retirement, select_pending_retirement_authorizer,
};
pub use response_binding::{
    created_remote_response_matches, remote_move_response_matches,
    restored_remote_response_matches, trashed_remote_response_matches,
    updated_remote_response_matches,
};
pub use session_revocations::{
    candidate_recovery_locator, compare_staged_candidate_recovery_order,
    staged_candidate_recovery_action, state_after_confirmed_remote_retirement, RemoteSessionRecord,
    StagedCandidateRecoveryAction, MAX_PENDING_REMOTE_REVOCATIONS,
};
pub use state::private_state_directory;
pub use state::{default_state_path, persist_pairing_state, PairMarkerDisposition, StateStore};
pub use sync_root_policy::apply_sync_root_policy;
pub use sync_roots::{
    converge_sync_roots, converge_sync_roots_at, plan_local_root_locations,
    plan_selected_root_location, validate_root_pair_binding, LocalRootLocation, SyncRoot,
    SyncRootAccessRemoval, SyncRootAccessRemovalReason, SyncRootKind, SyncRootMetadata,
    SyncRootReconciliation, SyncRootRole, MAX_DISCOVERY_ROOTS,
};
pub use uninstall_offboarding::{confirm_pending_remote_retirements, confirm_remote_retirement};
