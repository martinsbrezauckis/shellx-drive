use std::{collections::BTreeMap, path::PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The eight user-visible statuses. Do not add an internal status here: window,
/// tray, tooltip, and notifications share this exact vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    NeedsSetup,
    NeedsReconnect,
    Synced,
    Syncing,
    Paused,
    Offline,
    NeedsReview,
    Error,
}

pub const STATUS_STATES: [SyncStatus; 8] = [
    SyncStatus::NeedsSetup,
    SyncStatus::NeedsReconnect,
    SyncStatus::Synced,
    SyncStatus::Syncing,
    SyncStatus::Paused,
    SyncStatus::Offline,
    SyncStatus::NeedsReview,
    SyncStatus::Error,
];

impl SyncStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::NeedsSetup => "Needs setup",
            Self::NeedsReconnect => "Needs reconnect",
            Self::Synced => "Synced",
            Self::Syncing => "Syncing",
            Self::Paused => "Paused",
            Self::Offline => "Offline",
            Self::NeedsReview => "Needs review",
            Self::Error => "Error",
        }
    }
}

/// One deliberately narrow, non-secret sync relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncPair {
    pub server_url: String,
    pub account_email: String,
    pub workspace_id: String,
    pub workspace_name: String,
    /// `None` means the workspace root; a value selects one folder within it.
    pub remote_root_id: Option<String>,
    pub remote_root_name: Option<String>,
    pub local_root: PathBuf,
    /// Stable identity of the exact native directory selected during pairing.
    /// Legacy internal-test state may omit it, but native operations fail
    /// closed until the location is paired again.
    #[serde(default)]
    pub local_root_identity: Option<DirectoryIdentity>,
}

/// One inactive sync location and its last verified reconciliation state.
/// Credentials and pending remote-session retirement remain application-wide
/// because v0.1 supports multiple locations only for one server/account.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncPairState {
    pub pair: SyncPair,
    pub baseline: BTreeMap<String, BaselineEntry>,
    pub change_cursor: i64,
    pub reviews: Vec<ReviewItem>,
    pub activity: Vec<ActivityEntry>,
    pub paused: bool,
    pub last_successful_sync: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

pub fn sync_pair_identity_matches(pair: &SyncPair, server_url: &str, email: &str) -> bool {
    pair.server_url.trim_end_matches('/') == server_url.trim_end_matches('/')
        && pair.account_email.trim().eq_ignore_ascii_case(email.trim())
}

/// The common ancestor used to classify a future local or remote edit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BaselineEntry {
    pub remote_id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    pub relative_path: PathBuf,
    pub kind: String,
    pub content_hash: Option<String>,
    pub revision: i64,
    /// A non-secret native directory identity captured after link checks.
    /// It is present only for folders observed after the v2 state migration.
    /// Missing identities deliberately disable automatic folder moves.
    #[serde(default)]
    pub directory_identity: Option<DirectoryIdentity>,
}

/// Filesystem family that supplied a native directory identity.
///
/// Old durable records deserialize as `Windows` so an old NTFS record can
/// still be checked on Windows, while a Unix adapter will never silently adopt
/// it as a Unix device/inode identity.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryIdentityPlatform {
    #[default]
    Windows,
    Unix,
}

/// Stable identity for one native directory. The fields intentionally remain
/// a fixed, non-secret shape across platforms: Windows records carry the
/// volume serial plus `FILE_ID_INFO` identifier, while Unix records carry the
/// device number plus inode encoded into `file_id`.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DirectoryIdentity {
    #[serde(default)]
    pub platform: DirectoryIdentityPlatform,
    pub volume_serial: u64,
    pub file_id: [u8; 16],
}

impl DirectoryIdentity {
    pub fn windows(volume_serial: u64, file_id: [u8; 16]) -> Self {
        Self {
            platform: DirectoryIdentityPlatform::Windows,
            volume_serial,
            file_id,
        }
    }

    pub fn unix(device: u64, inode: u64) -> Self {
        let mut file_id = [0; 16];
        file_id[..8].copy_from_slice(&inode.to_le_bytes());
        Self {
            platform: DirectoryIdentityPlatform::Unix,
            volume_serial: device,
            file_id,
        }
    }
}

/// Legacy Windows-native modules retain this alias while the shared durable
/// model uses [`DirectoryIdentity`]. It must not be used by new shared code.
pub type WindowsDirectoryIdentity = DirectoryIdentity;

/// Bind a confirmation to the exact pending review and the complete saved
/// subtree it would mutate. A same-path review recreated after a recheck has a
/// different fingerprint when any baseline field or review detail changed.
pub fn review_confirmation_fingerprint(
    state: &DesktopState,
    item: &ReviewItem,
) -> crate::Result<String> {
    if !state.reviews.iter().any(|current| current == item) {
        return Err(crate::DesktopError::InvalidState(
            "the confirmation review is no longer pending".to_string(),
        ));
    }
    let mut hasher = Sha256::new();
    hash_confirmation_field(&mut hasher, &format!("{:?}", item.kind));
    hash_confirmation_field(&mut hasher, &item.id);
    hash_confirmation_field(&mut hasher, &item.relative_path.to_string_lossy());
    hash_confirmation_field(&mut hasher, &item.descendant_count.to_string());
    hash_confirmation_field(&mut hasher, &item.is_directory.to_string());
    hash_confirmation_field(&mut hasher, &item.summary);
    for action in &item.actions {
        hash_confirmation_field(&mut hasher, &format!("{:?}", action));
    }
    let mut entries = state
        .baseline
        .values()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.remote_id.cmp(&right.remote_id));
    for entry in entries {
        hash_confirmation_field(&mut hasher, &entry.remote_id);
        hash_confirmation_field(&mut hasher, entry.parent_id.as_deref().unwrap_or(""));
        hash_confirmation_field(&mut hasher, &entry.relative_path.to_string_lossy());
        hash_confirmation_field(&mut hasher, &entry.kind);
        hash_confirmation_field(&mut hasher, entry.content_hash.as_deref().unwrap_or(""));
        hash_confirmation_field(&mut hasher, &entry.revision.to_string());
        match &entry.directory_identity {
            Some(identity) => {
                hash_confirmation_field(&mut hasher, "directory-identity-present");
                hash_confirmation_field(&mut hasher, &identity.volume_serial.to_string());
                hash_confirmation_field(&mut hasher, &crate::hex_digest(&identity.file_id));
            }
            None => hash_confirmation_field(&mut hasher, "directory-identity-missing"),
        }
    }
    Ok(crate::hex_digest(hasher.finalize().as_slice()))
}

fn hash_confirmation_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKind {
    LocalDeletion,
    RemoteDeletion,
    ContentConflict,
    DeleteEditConflict,
    PathConflict,
    UnsupportedTransfer,
    UnsafePath,
    UnsafeLink,
    /// A Viewer-root local change is intentionally not uploaded.
    ReadOnlyLocalChange,
    /// Discovery reported revocation or expiry; the already-downloaded local
    /// bytes remain until a later explicit local-copy decision.
    AccessRemoved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAction {
    DeleteFromDrive,
    RestoreLocalCopy,
    RemoveLocalCopy,
    RestoreToDrive,
    OpenConflictCopies,
    RenameLocalCopy,
    ChooseAnotherLocation,
    RetryWhenServerSupportsResumableReplacement,
}

/// The only review choices the v0.1 executor may mutate. Every decision is
/// recoverable: remote deletion is a Drive trash operation and local removal
/// is a move to the desktop recovery area. Other review kinds stay queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDecision {
    TrashRemote,
    RestoreLocal,
    RecoverLocal,
    RestoreRemote,
    /// An access-removed root is no longer allowed to contact Drive. The
    /// explicit local-copy action moves its complete local root to recovery
    /// and removes the pair instead of silently deleting modified bytes.
    RemoveRetainedRoot,
}

/// A deletion, conflict, or incompatible path that requires an explicit human
/// decision. Neither planning nor persistence executes any delete action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewItem {
    pub id: String,
    pub kind: ReviewKind,
    pub relative_path: PathBuf,
    pub descendant_count: usize,
    /// Folder trash is recursive. v0.1 never enables it without a server
    /// conditional-subtree contract, including for an empty folder.
    #[serde(default)]
    pub is_directory: bool,
    pub summary: String,
    pub actions: Vec<ReviewAction>,
}

/// Resolve an IPC/UI action against the exact review item. This is deliberately
/// separate from execution so invalid, stale, and conflict-review choices are
/// rejected before any filesystem or Drive mutation is attempted.
pub fn resolve_review_decision(
    item: &ReviewItem,
    action: ReviewAction,
) -> crate::Result<ReviewDecision> {
    if !item.actions.contains(&action) {
        return Err(crate::DesktopError::InvalidState(
            "this action is not available for the selected review item".to_string(),
        ));
    }
    match (item.kind.clone(), action) {
        (ReviewKind::LocalDeletion, ReviewAction::DeleteFromDrive) if !item.is_directory => {
            Ok(ReviewDecision::TrashRemote)
        }
        (ReviewKind::LocalDeletion, ReviewAction::RestoreLocalCopy) => {
            Ok(ReviewDecision::RestoreLocal)
        }
        (ReviewKind::RemoteDeletion, ReviewAction::RemoveLocalCopy) => {
            Ok(ReviewDecision::RecoverLocal)
        }
        (ReviewKind::RemoteDeletion, ReviewAction::RestoreToDrive) => {
            Ok(ReviewDecision::RestoreRemote)
        }
        (ReviewKind::AccessRemoved, ReviewAction::RemoveLocalCopy) => {
            Ok(ReviewDecision::RemoveRetainedRoot)
        }
        _ => Err(crate::DesktopError::InvalidState(
            "this review needs a recovery flow that is not available in this build".to_string(),
        )),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivityEntry {
    pub at: DateTime<Utc>,
    pub direction: String,
    pub relative_path: PathBuf,
    pub result: String,
}

/// Durable non-secret application state. It intentionally contains no token,
/// password, recovery code, cookie, authorization header, or file contents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DesktopState {
    pub schema_version: u32,
    pub pair: Option<SyncPair>,
    #[serde(default)]
    pub inactive_pairs: Vec<SyncPairState>,
    /// Non-secret server root/grant identity retained by pair ID. Legacy pairs
    /// have no entry until the role-aware root discovery flow adopts them.
    #[serde(default)]
    pub sync_roots: BTreeMap<String, crate::SyncRootMetadata>,
    /// The user-selected empty container for deterministic `My files` and
    /// `Shared with me` root materializations. It is a local path only; every
    /// individual child pair retains its own marker and Windows identity.
    #[serde(default)]
    pub sync_root_base: Option<PathBuf>,
    /// Full discovery exceeded the desktop bound. Saved roots are separately
    /// revalidated; new roots are not materialized until discovery fits again.
    #[serde(default)]
    pub root_discovery_overflow: bool,
    /// Pair to visit first after a cycle stopped at its aggregate resource limit.
    #[serde(default)]
    pub sync_cycle_resume_pair_id: Option<String>,
    pub baseline: BTreeMap<String, BaselineEntry>,
    pub change_cursor: i64,
    pub reviews: Vec<ReviewItem>,
    pub activity: Vec<ActivityEntry>,
    pub paused: bool,
    pub launch_at_login: bool,
    pub last_successful_sync: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    /// The currently published credential's non-secret server session locator.
    #[serde(default)]
    pub active_remote_session: Option<crate::RemoteSessionRecord>,
    /// Failed remote retirements retried only after a same-server/account login.
    #[serde(default)]
    pub pending_remote_revocations: Vec<crate::RemoteSessionRecord>,
    /// A replacement candidate whose separate Credential Manager slot has not
    /// yet been conclusively promoted or retired. This is a bounded locator,
    /// never an authentication secret.
    #[serde(default)]
    pub pending_candidate_session: Option<crate::RemoteSessionRecord>,
    /// Local marker and exact credential slots to remove only after remote
    /// retirement is confirmed. This journal contains no bearer material.
    #[serde(default)]
    pub pending_disconnect_cleanup: Option<crate::DisconnectCleanupIntent>,
    /// Non-secret target retained until the restarted app confirms its version.
    #[serde(default)]
    pub pending_desktop_update_restart: Option<crate::DesktopUpdateRestartIntent>,
    /// Local-only opt-in and bounded non-secret command journal for the
    /// outbound desktop-agent broker. The device credential is held solely in
    /// the platform's separate credential namespace.
    #[serde(default)]
    pub desktop_agent_control: crate::DesktopAgentControlState,
    /// A device-retired agent Disconnect retains only this non-secret
    /// completion locator until the capability-authenticated terminal receipt
    /// is accepted. Its raw capability stays in the platform credential store.
    #[serde(default)]
    pub pending_desktop_agent_disconnect: Option<crate::DesktopAgentDisconnectContinuation>,
    /// Latest broker Disconnect that could not be terminalized. This history
    /// has no secret or retry capability, so it never blocks later pairing.
    #[serde(default)]
    pub unconfirmed_desktop_agent_disconnect:
        Option<crate::DesktopAgentDisconnectUnconfirmedTerminal>,
}

/// The sole startup-recovery error that convergence may remove. Other errors
/// can describe independent actionable conditions and must remain visible.
pub const CANDIDATE_RECOVERY_PAUSED_ERROR: &str =
    "Drive credential recovery needs retry; automatic sync is paused";

impl Default for DesktopState {
    fn default() -> Self {
        Self {
            schema_version: 7,
            pair: None,
            inactive_pairs: Vec::new(),
            sync_roots: BTreeMap::new(),
            sync_root_base: None,
            root_discovery_overflow: false,
            sync_cycle_resume_pair_id: None,
            baseline: BTreeMap::new(),
            change_cursor: 0,
            reviews: Vec::new(),
            activity: Vec::new(),
            paused: false,
            launch_at_login: true,
            last_successful_sync: None,
            last_error: None,
            active_remote_session: None,
            pending_remote_revocations: Vec::new(),
            pending_candidate_session: None,
            pending_disconnect_cleanup: None,
            pending_desktop_update_restart: None,
            desktop_agent_control: crate::DesktopAgentControlState::default(),
            pending_desktop_agent_disconnect: None,
            unconfirmed_desktop_agent_disconnect: None,
        }
    }
}

impl DesktopState {
    /// Clear only the known, generic error recorded when staged-candidate
    /// recovery paused startup. Returns whether the caller needs to persist.
    pub fn clear_candidate_recovery_error(&mut self) -> bool {
        if self.last_error.as_deref() == Some(CANDIDATE_RECOVERY_PAUSED_ERROR) {
            self.last_error = None;
            true
        } else {
            false
        }
    }

    pub fn status(
        &self,
        active_run: bool,
        offline: bool,
        credential_available: bool,
    ) -> SyncStatus {
        if self.pending_disconnect_cleanup.is_some() {
            SyncStatus::Error
        } else if self.pair.is_none() {
            SyncStatus::NeedsSetup
        } else if !credential_available {
            SyncStatus::NeedsReconnect
        } else if active_run {
            SyncStatus::Syncing
        } else if self.paused {
            SyncStatus::Paused
        } else if self.has_any_reviews() {
            SyncStatus::NeedsReview
        } else if self.has_any_pair_error() {
            SyncStatus::Error
        } else if offline {
            SyncStatus::Offline
        } else {
            SyncStatus::Synced
        }
    }

    pub fn has_pending_disconnect_cleanup(&self) -> bool {
        self.pending_disconnect_cleanup.is_some()
    }

    pub fn pending_desktop_agent_disconnect(
        &self,
    ) -> Option<&crate::DesktopAgentDisconnectContinuation> {
        self.pending_desktop_agent_disconnect.as_ref()
    }

    pub fn begin_desktop_agent_disconnect(
        &mut self,
        continuation: crate::DesktopAgentDisconnectContinuation,
    ) -> crate::Result<()> {
        continuation.validate()?;
        if !self.has_pending_disconnect_cleanup() {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect continuation requires durable local cleanup".to_string(),
            ));
        }
        if self.pending_desktop_agent_disconnect.is_some() {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect continuation is already pending".to_string(),
            ));
        }
        self.pending_desktop_agent_disconnect = Some(continuation);
        Ok(())
    }

    pub fn mark_desktop_agent_disconnect_retired(&mut self) -> crate::Result<()> {
        let continuation = self
            .pending_desktop_agent_disconnect
            .as_mut()
            .ok_or_else(|| {
                crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect continuation is unavailable".to_string(),
                )
            })?;
        if continuation.phase != crate::DesktopAgentDisconnectPhase::RetiringRemote {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect retirement was not pending".to_string(),
            ));
        }
        continuation.phase = crate::DesktopAgentDisconnectPhase::LocalCleanup;
        continuation.retire_assertion = None;
        continuation.bound_owner_session = None;
        Ok(())
    }

    pub fn mark_desktop_agent_disconnect_reporting(&mut self) -> crate::Result<()> {
        let continuation = self
            .pending_desktop_agent_disconnect
            .as_mut()
            .ok_or_else(|| {
                crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect continuation is unavailable".to_string(),
                )
            })?;
        if continuation.phase != crate::DesktopAgentDisconnectPhase::LocalCleanup {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect continuation cannot report before local cleanup"
                    .to_string(),
            ));
        }
        continuation.phase = crate::DesktopAgentDisconnectPhase::Reporting;
        Ok(())
    }

    /// Finish local cleanup and begin capability-authenticated reporting in one
    /// in-memory state transition so no invalid LocalCleanup state is saved.
    pub fn finish_agent_disconnect_cleanup(&mut self) -> crate::Result<()> {
        self.finish_disconnect_cleanup()?;
        self.mark_desktop_agent_disconnect_reporting()
    }

    pub fn record_desktop_agent_disconnect_terminal(
        &mut self,
        receipt: crate::DesktopAgentDisconnectTerminalReceipt,
    ) -> crate::Result<()> {
        if self.has_pending_disconnect_cleanup() {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect terminal cannot be recorded before local cleanup"
                    .to_string(),
            ));
        }
        let continuation = self
            .pending_desktop_agent_disconnect
            .as_mut()
            .ok_or_else(|| {
                crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect continuation is unavailable".to_string(),
                )
            })?;
        if continuation.phase != crate::DesktopAgentDisconnectPhase::Reporting {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect terminal cannot be recorded before local cleanup"
                    .to_string(),
            ));
        }
        continuation.phase = crate::DesktopAgentDisconnectPhase::TerminalAccepted;
        continuation.terminal_receipt = Some(receipt);
        Ok(())
    }

    /// Atomically reserve the normal-bearer cancellation terminal after the
    /// capability retirement endpoint rejects the command before admission.
    /// The exact assertion and event sequence survive a crash or lost 204.
    pub fn reserve_desktop_agent_disconnect_retirement_cancellation(
        &mut self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::Result<u64> {
        let command_id = {
            let continuation = self
                .pending_desktop_agent_disconnect
                .as_ref()
                .ok_or_else(|| {
                    crate::DesktopError::InvalidState(
                        "desktop-agent Disconnect continuation is unavailable".to_string(),
                    )
                })?;
            if continuation.phase != crate::DesktopAgentDisconnectPhase::RetiringRemote {
                return Err(crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect retirement cancellation is not pending".to_string(),
                ));
            }
            let assertion = continuation.retire_assertion.as_ref().ok_or_else(|| {
                crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect cancellation has no assertion witness".to_string(),
                )
            })?;
            if !assertion.pending_disconnect_cleanup {
                return Err(crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect cancellation lacks cleanup intent".to_string(),
                ));
            }
            continuation.command_id.clone()
        };
        let sequence = self.desktop_agent_control.mark_terminal(
            &command_id,
            crate::DesktopAgentTerminalStatus::Interrupted,
            crate::DesktopAgentTerminalCode::CancellationRequested,
            None,
            None,
            now,
        )?;
        let continuation = self
            .pending_desktop_agent_disconnect
            .as_mut()
            .expect("Disconnect continuation was checked before journal reservation");
        let assertion = continuation
            .retire_assertion
            .as_mut()
            .expect("Disconnect assertion was checked before journal reservation");
        assertion.last_terminal_command_id = Some(command_id);
        continuation.phase = crate::DesktopAgentDisconnectPhase::RetirementCancelled;
        continuation.bound_owner_session = None;
        continuation.blocked_reason =
            Some(crate::DesktopAgentDisconnectBlockedReason::CancellationRequested);
        Ok(sequence)
    }

    /// Clear an unadmitted agent Disconnect only after its exact normal-bearer
    /// cancellation terminal has been accepted. No local session or remote
    /// retirement has occurred in this phase, so the untouched cleanup intent
    /// is rolled back and polling may resume.
    pub fn finish_desktop_agent_disconnect_retirement_cancellation(&mut self) -> crate::Result<()> {
        let command_id = {
            let continuation = self
                .pending_desktop_agent_disconnect
                .as_ref()
                .ok_or_else(|| {
                    crate::DesktopError::InvalidState(
                        "desktop-agent Disconnect cancellation disposition is unavailable"
                            .to_string(),
                    )
                })?;
            if continuation.phase != crate::DesktopAgentDisconnectPhase::RetirementCancelled
                || continuation
                    .retire_assertion
                    .as_ref()
                    .and_then(|assertion| assertion.last_terminal_command_id.as_deref())
                    != Some(continuation.command_id.as_str())
            {
                return Err(crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect cancellation terminal is not pending".to_string(),
                ));
            }
            continuation.command_id.clone()
        };
        let accepted = self
            .desktop_agent_control
            .command_journal
            .iter()
            .any(|entry| {
                entry.command_id == command_id
                    && entry.state == crate::DesktopAgentCommandJournalState::Interrupted
                    && entry.terminal_code
                        == Some(crate::DesktopAgentTerminalCode::CancellationRequested)
                    && entry.terminal_event_sequence.is_some()
            });
        if !accepted
            || self
                .pending_disconnect_cleanup
                .as_ref()
                .is_none_or(crate::DisconnectCleanupIntent::remote_retirement_confirmed)
        {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect cancellation cannot clear unconfirmed cleanup"
                    .to_string(),
            ));
        }
        self.pending_desktop_agent_disconnect = None;
        self.pending_disconnect_cleanup = None;
        Ok(())
    }

    pub fn block_desktop_agent_disconnect_retirement(
        &mut self,
        reason: crate::DesktopAgentDisconnectBlockedReason,
    ) -> crate::Result<()> {
        let continuation = self
            .pending_desktop_agent_disconnect
            .as_mut()
            .ok_or_else(|| {
                crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect continuation is unavailable".to_string(),
                )
            })?;
        if !matches!(
            continuation.phase,
            crate::DesktopAgentDisconnectPhase::RetiringRemote
                | crate::DesktopAgentDisconnectPhase::RetirementCancelled
        ) {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect retirement cannot be blocked from its current phase"
                    .to_string(),
            ));
        }
        continuation.phase = crate::DesktopAgentDisconnectPhase::RetirementBlocked;
        continuation.retire_assertion = None;
        continuation.bound_owner_session = None;
        continuation.blocked_reason = Some(reason);
        Ok(())
    }

    pub fn block_desktop_agent_disconnect_completion(
        &mut self,
        reason: crate::DesktopAgentDisconnectBlockedReason,
    ) -> crate::Result<()> {
        let continuation = self
            .pending_desktop_agent_disconnect
            .as_mut()
            .ok_or_else(|| {
                crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect continuation is unavailable".to_string(),
                )
            })?;
        if continuation.phase != crate::DesktopAgentDisconnectPhase::Reporting {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect completion cannot be blocked from its current phase"
                    .to_string(),
            ));
        }
        continuation.phase = crate::DesktopAgentDisconnectPhase::CompletionBlocked;
        continuation.blocked_reason = Some(reason);
        Ok(())
    }

    pub fn abandon_desktop_agent_disconnect_retirement(&mut self) -> crate::Result<()> {
        if !matches!(
            self.pending_desktop_agent_disconnect()
                .map(|continuation| continuation.phase),
            Some(crate::DesktopAgentDisconnectPhase::RetiringRemote)
        ) {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect retirement is not pending".to_string(),
            ));
        }
        self.pending_desktop_agent_disconnect = None;
        Ok(())
    }

    /// A locally initiated Disconnect may take over only after a remote
    /// capability retirement was definitively blocked before admission.
    pub fn clear_desktop_agent_disconnect_retirement_block(&mut self) -> crate::Result<()> {
        if self
            .pending_desktop_agent_disconnect()
            .is_some_and(|continuation| {
                continuation.phase == crate::DesktopAgentDisconnectPhase::RetirementBlocked
            })
        {
            self.archive_desktop_agent_disconnect_block()?;
            return Ok(());
        }
        if self.pending_desktop_agent_disconnect().is_some() {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect continuation cannot be replaced by local retirement"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Once its exact raw capability is removed, move a blocked agent
    /// terminal out of the active continuation. This retains the truthful
    /// unconfirmed result without preventing a later local recovery or pair.
    pub fn archive_desktop_agent_disconnect_block(&mut self) -> crate::Result<()> {
        let continuation = self
            .pending_desktop_agent_disconnect
            .as_ref()
            .ok_or_else(|| {
                crate::DesktopError::InvalidState(
                    "desktop-agent Disconnect continuation is unavailable".to_string(),
                )
            })?;
        let unconfirmed = continuation.unconfirmed_terminal()?;
        self.unconfirmed_desktop_agent_disconnect = Some(unconfirmed);
        self.pending_desktop_agent_disconnect = None;
        Ok(())
    }

    pub fn finish_desktop_agent_disconnect(&mut self) -> crate::Result<()> {
        if !matches!(
            self.pending_desktop_agent_disconnect()
                .map(|continuation| continuation.phase),
            Some(crate::DesktopAgentDisconnectPhase::TerminalAccepted)
        ) || self.has_pending_disconnect_cleanup()
        {
            return Err(crate::DesktopError::InvalidState(
                "desktop-agent Disconnect cannot finish before its accepted terminal receipt"
                    .to_string(),
            ));
        }
        self.pending_desktop_agent_disconnect = None;
        Ok(())
    }

    pub fn begin_disconnect_cleanup(
        &mut self,
        intent: crate::DisconnectCleanupIntent,
    ) -> crate::Result<()> {
        if self.pending_disconnect_cleanup.is_some() {
            return Err(crate::DesktopError::InvalidState(
                "disconnect cleanup is already pending".to_string(),
            ));
        }
        self.pending_disconnect_cleanup = Some(intent);
        Ok(())
    }

    pub fn pending_disconnect_cleanup(&self) -> Option<&crate::DisconnectCleanupIntent> {
        self.pending_disconnect_cleanup.as_ref()
    }

    pub fn pending_disconnect_cleanup_mut(
        &mut self,
    ) -> Option<&mut crate::DisconnectCleanupIntent> {
        self.pending_disconnect_cleanup.as_mut()
    }

    pub fn finish_disconnect_cleanup(&mut self) -> crate::Result<()> {
        if !self
            .pending_disconnect_cleanup
            .as_ref()
            .is_some_and(crate::DisconnectCleanupIntent::is_complete)
        {
            return Err(crate::DesktopError::InvalidState(
                "disconnect cleanup cannot finish before every exact local item is removed"
                    .to_string(),
            ));
        }
        self.pending_disconnect_cleanup = None;
        Ok(())
    }

    pub fn append_activity(&mut self, entry: ActivityEntry) {
        const MAX_ACTIVITY: usize = 200;
        self.activity.push(entry);
        let excess = self.activity.len().saturating_sub(MAX_ACTIVITY);
        if excess > 0 {
            self.activity.drain(0..excess);
        }
    }
}

/// Non-secret marker written under the chosen root after setup. It lets the
/// app recognize its pair without using the marker as a credentials store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PairMarker {
    pub schema_version: u32,
    pub workspace_id: String,
    pub remote_root_id: Option<String>,
    pub server_url: String,
    #[serde(default)]
    pub local_root_identity: Option<DirectoryIdentity>,
}

impl From<&SyncPair> for PairMarker {
    fn from(pair: &SyncPair) -> Self {
        Self {
            schema_version: 2,
            workspace_id: pair.workspace_id.clone(),
            remote_root_id: pair.remote_root_id.clone(),
            server_url: pair.server_url.clone(),
            local_root_identity: pair.local_root_identity.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review(kind: ReviewKind, actions: Vec<ReviewAction>) -> ReviewItem {
        ReviewItem {
            id: "review-1".to_string(),
            kind,
            relative_path: PathBuf::from("Projects/report.md"),
            descendant_count: 2,
            is_directory: false,
            summary: "test".to_string(),
            actions,
        }
    }

    #[test]
    fn retained_pair_without_a_credential_never_projects_synced() {
        let state = DesktopState {
            pair: Some(SyncPair {
                server_url: "https://drive.example".to_string(),
                account_email: "owner@example.test".to_string(),
                workspace_id: "workspace".to_string(),
                workspace_name: "Workspace".to_string(),
                remote_root_id: None,
                remote_root_name: None,
                local_root: PathBuf::from("C:/Drive"),
                local_root_identity: None,
            }),
            last_successful_sync: Some(Utc::now()),
            ..DesktopState::default()
        };

        assert_eq!(
            state.status(false, false, false),
            SyncStatus::NeedsReconnect
        );
        assert_eq!(state.status(false, false, true), SyncStatus::Synced);
    }

    #[test]
    fn reconnect_identity_cannot_switch_server_or_account() {
        let pair = SyncPair {
            server_url: "https://drive.example".to_string(),
            account_email: "Owner@Example.test".to_string(),
            workspace_id: "workspace".to_string(),
            workspace_name: "Workspace".to_string(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("C:/Drive"),
            local_root_identity: None,
        };

        assert!(sync_pair_identity_matches(
            &pair,
            "https://drive.example/",
            "owner@example.test"
        ));
        assert!(!sync_pair_identity_matches(
            &pair,
            "https://other.example",
            "owner@example.test"
        ));
        assert!(!sync_pair_identity_matches(
            &pair,
            "https://drive.example",
            "other@example.test"
        ));
    }

    #[test]
    fn candidate_recovery_only_clears_its_own_startup_error() {
        let mut state = DesktopState {
            last_error: Some(CANDIDATE_RECOVERY_PAUSED_ERROR.to_string()),
            ..DesktopState::default()
        };
        assert!(state.clear_candidate_recovery_error());
        assert_eq!(state.last_error, None);

        state.last_error = Some("unrelated actionable failure".to_string());
        assert!(!state.clear_candidate_recovery_error());
        assert_eq!(
            state.last_error.as_deref(),
            Some("unrelated actionable failure")
        );
    }

    #[test]
    fn retained_candidate_recovery_is_never_projected_as_synced() {
        let state = DesktopState {
            pair: Some(SyncPair {
                server_url: "https://drive.example.test".to_string(),
                account_email: "person@example.test".to_string(),
                workspace_id: "workspace".to_string(),
                workspace_name: "Workspace".to_string(),
                remote_root_id: None,
                remote_root_name: None,
                local_root: PathBuf::from("Drive"),
                local_root_identity: None,
            }),
            last_successful_sync: Some(Utc::now()),
            last_error: Some(CANDIDATE_RECOVERY_PAUSED_ERROR.to_string()),
            ..DesktopState::default()
        };

        assert_eq!(state.status(false, false, true), SyncStatus::Error);
    }

    #[test]
    fn deletion_decisions_are_exact_and_recoverable() {
        let local = review(
            ReviewKind::LocalDeletion,
            vec![
                ReviewAction::DeleteFromDrive,
                ReviewAction::RestoreLocalCopy,
            ],
        );
        assert_eq!(
            resolve_review_decision(&local, ReviewAction::DeleteFromDrive).unwrap(),
            ReviewDecision::TrashRemote
        );
        assert_eq!(
            resolve_review_decision(&local, ReviewAction::RestoreLocalCopy).unwrap(),
            ReviewDecision::RestoreLocal
        );

        let remote = review(
            ReviewKind::RemoteDeletion,
            vec![ReviewAction::RemoveLocalCopy, ReviewAction::RestoreToDrive],
        );
        assert_eq!(
            resolve_review_decision(&remote, ReviewAction::RemoveLocalCopy).unwrap(),
            ReviewDecision::RecoverLocal
        );
        assert_eq!(
            resolve_review_decision(&remote, ReviewAction::RestoreToDrive).unwrap(),
            ReviewDecision::RestoreRemote
        );
    }

    #[test]
    fn conflict_actions_never_map_to_a_deletion_mutation() {
        let conflict = review(
            ReviewKind::DeleteEditConflict,
            vec![ReviewAction::RestoreToDrive],
        );
        assert!(resolve_review_decision(&conflict, ReviewAction::RestoreToDrive).is_err());
        assert!(resolve_review_decision(&conflict, ReviewAction::RemoveLocalCopy).is_err());
    }

    #[test]
    fn folder_deletion_never_resolves_to_a_recursive_drive_trash() {
        for descendants in [0, 3] {
            let folder = ReviewItem {
                is_directory: true,
                descendant_count: descendants,
                ..review(
                    ReviewKind::LocalDeletion,
                    vec![
                        ReviewAction::DeleteFromDrive,
                        ReviewAction::RestoreLocalCopy,
                    ],
                )
            };
            assert!(resolve_review_decision(&folder, ReviewAction::DeleteFromDrive).is_err());
            assert_eq!(
                resolve_review_decision(&folder, ReviewAction::RestoreLocalCopy).unwrap(),
                ReviewDecision::RestoreLocal
            );
        }
    }

    #[test]
    fn reincarnated_same_path_review_has_a_new_confirmation_fingerprint() {
        let item = review(
            ReviewKind::RemoteDeletion,
            vec![ReviewAction::RemoveLocalCopy, ReviewAction::RestoreToDrive],
        );
        let mut state = DesktopState {
            reviews: vec![item.clone()],
            ..DesktopState::default()
        };
        state.baseline.insert(
            "file-1".to_string(),
            BaselineEntry {
                remote_id: "file-1".to_string(),
                parent_id: Some("folder-1".to_string()),
                relative_path: item.relative_path.clone(),
                kind: "file".to_string(),
                content_hash: Some("saved".to_string()),
                revision: 1,
                directory_identity: None,
            },
        );
        let first = review_confirmation_fingerprint(&state, &item).unwrap();

        // A later recheck can create the same deterministic review ID/path,
        // but a refreshed baseline makes it a new instance.
        state.baseline.get_mut("file-1").unwrap().revision = 2;
        let reincarnated = review_confirmation_fingerprint(&state, &item).unwrap();
        assert_ne!(first, reincarnated);
    }
}
