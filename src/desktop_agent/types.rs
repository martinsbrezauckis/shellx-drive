use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{payload::DesktopAgentCommandPayload, result::DesktopAgentResultPayload};

/// A command is always selected by this enum. The wire format must never
/// accept a Tauri invoke name, executable, path, URL, bytes, or secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentCommandKind {
    DesktopView,
    SyncNow,
    RecheckReviews,
    SetPaused,
    SetLaunchAtLogin,
    PrepareReviewAction,
    ConfirmReviewAction,
    CheckDesktopUpdate,
    InstallDesktopUpdate,
    Disconnect,
    OpenLocalFolder,
    OpenDrive,
    DiscoverRoots,
    StartPair,
    SelectPair,
    ValidateServer,
    ContinueLogin,
    ContinueMfa,
}

impl DesktopAgentCommandKind {
    /// A delivered lease is only retried automatically for observations with
    /// no local mutation. Every other stale lease becomes interrupted.
    pub const fn lease_replay_safe(self) -> bool {
        matches!(
            self,
            Self::DesktopView | Self::CheckDesktopUpdate | Self::ValidateServer
        )
    }

    pub const fn requires_local_gesture(self) -> bool {
        matches!(self, Self::ContinueLogin | Self::ContinueMfa)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DesktopView => "desktop_view",
            Self::SyncNow => "sync_now",
            Self::RecheckReviews => "recheck_reviews",
            Self::SetPaused => "set_paused",
            Self::SetLaunchAtLogin => "set_launch_at_login",
            Self::PrepareReviewAction => "prepare_review_action",
            Self::ConfirmReviewAction => "confirm_review_action",
            Self::CheckDesktopUpdate => "check_desktop_update",
            Self::InstallDesktopUpdate => "install_desktop_update",
            Self::Disconnect => "disconnect",
            Self::OpenLocalFolder => "open_local_folder",
            Self::OpenDrive => "open_drive",
            Self::DiscoverRoots => "discover_roots",
            Self::StartPair => "start_pair",
            Self::SelectPair => "select_pair",
            Self::ValidateServer => "validate_server",
            Self::ContinueLogin => "continue_login",
            Self::ContinueMfa => "continue_mfa",
        }
    }

    pub const fn successful_result_code(self) -> Option<DesktopAgentResultCode> {
        match self {
            Self::DesktopView => Some(DesktopAgentResultCode::ViewRead),
            Self::SyncNow => Some(DesktopAgentResultCode::SyncCompleted),
            Self::RecheckReviews => Some(DesktopAgentResultCode::ReviewsRechecked),
            Self::SetPaused => Some(DesktopAgentResultCode::PausePersisted),
            Self::SetLaunchAtLogin => Some(DesktopAgentResultCode::LaunchAtLoginPersisted),
            Self::PrepareReviewAction => Some(DesktopAgentResultCode::ReviewPrepared),
            Self::ConfirmReviewAction => Some(DesktopAgentResultCode::ReviewConfirmed),
            Self::CheckDesktopUpdate => Some(DesktopAgentResultCode::UpdateChecked),
            Self::InstallDesktopUpdate => Some(DesktopAgentResultCode::UpdateInstalled),
            Self::Disconnect => Some(DesktopAgentResultCode::DisconnectCompleted),
            Self::OpenLocalFolder => Some(DesktopAgentResultCode::LocalFolderDispatchAttempted),
            Self::OpenDrive => Some(DesktopAgentResultCode::DriveDispatchAttempted),
            Self::DiscoverRoots => Some(DesktopAgentResultCode::RootsDiscovered),
            Self::StartPair => Some(DesktopAgentResultCode::RootsRefreshed),
            Self::SelectPair => Some(DesktopAgentResultCode::PairSelected),
            Self::ValidateServer => Some(DesktopAgentResultCode::ServerValidated),
            Self::ContinueLogin | Self::ContinueMfa => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentReviewAction {
    DeleteFromDrive,
    RestoreLocalCopy,
    RemoveLocalCopy,
    RestoreToDrive,
    OpenConflictCopies,
    RenameLocalCopy,
    ChooseAnotherLocation,
    RetryWhenServerSupportsResumableReplacement,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentSubmitWireRequest {
    pub request_id: String,
    #[serde(default)]
    pub device_id: Option<String>,
    pub kind: DesktopAgentCommandKind,
    pub payload: Value,
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopAgentSubmitRequest {
    pub request_id: String,
    pub device_id: Option<String>,
    pub payload: DesktopAgentCommandPayload,
    pub expires_in_seconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentDevicePlatform {
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentDeviceRegistration {
    pub platform: DesktopAgentDevicePlatform,
    pub app_version: String,
    pub pair_fingerprint: String,
    pub status: DesktopAgentObservedStatus,
    pub pending_disconnect_cleanup: bool,
    pub candidate_recovery: bool,
    #[serde(default)]
    pub last_terminal_command_id: Option<String>,
}

impl DesktopAgentDeviceRegistration {
    pub fn assertion(&self) -> DesktopAgentDeviceAssertion {
        DesktopAgentDeviceAssertion {
            app_version: self.app_version.clone(),
            pair_fingerprint: self.pair_fingerprint.clone(),
            status: self.status,
            pending_disconnect_cleanup: self.pending_disconnect_cleanup,
            candidate_recovery: self.candidate_recovery,
            last_terminal_command_id: self.last_terminal_command_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentDeviceState {
    Active,
    Frozen,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DesktopAgentDevice {
    pub id: String,
    pub platform: DesktopAgentDevicePlatform,
    pub app_version: String,
    pub state: DesktopAgentDeviceState,
    pub last_seen_at: Option<String>,
    pub last_ready_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DesktopAgentDeviceListResponse {
    pub devices: Vec<DesktopAgentDevice>,
}

/// This value is returned only once from registration and must be persisted by
/// the desktop in its platform credential store. It is deliberately excluded
/// from `DesktopAgentDevice` and every command/event/result model.
#[derive(Clone, Serialize)]
pub struct DesktopAgentEnrollment {
    pub device_id: String,
    pub device_credential: String,
    pub credential_expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentObservedStatus {
    Ready,
    Paused,
    Error,
    NeedsSetup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentDeviceAssertion {
    pub app_version: String,
    pub pair_fingerprint: String,
    pub status: DesktopAgentObservedStatus,
    pub pending_disconnect_cleanup: bool,
    pub candidate_recovery: bool,
    #[serde(default)]
    pub last_terminal_command_id: Option<String>,
}

/// The desktop may ask for a bounded long-poll interval, but the server may
/// answer immediately with `{ claim: null }`; no open connection is required
/// for correctness.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentClaimRequest {
    pub app_version: String,
    pub pair_fingerprint: String,
    pub status: DesktopAgentObservedStatus,
    pub pending_disconnect_cleanup: bool,
    pub candidate_recovery: bool,
    #[serde(default)]
    pub last_terminal_command_id: Option<String>,
    #[serde(default)]
    pub wait_seconds: Option<u8>,
}

impl DesktopAgentClaimRequest {
    pub fn assertion(&self) -> DesktopAgentDeviceAssertion {
        DesktopAgentDeviceAssertion {
            app_version: self.app_version.clone(),
            pair_fingerprint: self.pair_fingerprint.clone(),
            status: self.status,
            pending_disconnect_cleanup: self.pending_disconnect_cleanup,
            candidate_recovery: self.candidate_recovery,
            last_terminal_command_id: self.last_terminal_command_id.clone(),
        }
    }

    pub fn valid_wait_seconds(&self) -> bool {
        self.wait_seconds.is_none_or(|value| value <= 20)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentCommandStatus {
    Queued,
    Leased,
    Acknowledged,
    Running,
    RelaunchPending,
    Succeeded,
    Failed,
    Rejected,
    CancelRequested,
    Cancelled,
    Expired,
    Interrupted,
    RequiresLocalGesture,
}

impl DesktopAgentCommandStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Rejected
                | Self::Cancelled
                | Self::Expired
                | Self::Interrupted
                | Self::RequiresLocalGesture
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentPhase {
    Accepted,
    AwaitingLocalGesture,
    Syncing,
    Reviewing,
    Updating,
    Disconnecting,
    RelaunchPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentTerminalCode {
    Completed,
    RequiresLocalGesture,
    DeviceFrozen,
    PendingDisconnect,
    CandidateRecovery,
    AuthorizationLost,
    StaleTarget,
    CancellationRequested,
    CancelledBeforeStart,
    LeaseExpired,
    CrashUnproven,
    NativeDenied,
    NativeDispatchFailed,
    UpdateAttestationFailed,
    ProtocolViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentResultCode {
    ViewRead,
    SyncCompleted,
    ReviewsRechecked,
    PausePersisted,
    LaunchAtLoginPersisted,
    ReviewPrepared,
    ReviewConfirmed,
    UpdateChecked,
    UpdateInstalled,
    DisconnectCompleted,
    LocalFolderDispatchAttempted,
    DriveDispatchAttempted,
    RootsDiscovered,
    RootsRefreshed,
    PairSelected,
    ServerValidated,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentAcknowledgeRequest {
    pub lease_id: String,
    pub event_sequence: i64,
    pub assertion: DesktopAgentDeviceAssertion,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentProgressRequest {
    pub lease_id: String,
    pub event_sequence: i64,
    pub assertion: DesktopAgentDeviceAssertion,
    pub phase: DesktopAgentPhase,
    #[serde(default)]
    pub progress_basis_points: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentTerminalRequest {
    pub lease_id: String,
    pub event_sequence: i64,
    pub assertion: DesktopAgentDeviceAssertion,
    pub status: DesktopAgentTerminalStatus,
    pub terminal_code: DesktopAgentTerminalCode,
    #[serde(default)]
    pub result_code: Option<DesktopAgentResultCode>,
    #[serde(default)]
    pub result: Option<DesktopAgentResultPayload>,
}

/// The capability is not part of this request. It is delivered only on a
/// Disconnect lease and held outside the desktop state in a private platform
/// credential store until the local cleanup can be truthfully completed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentDisconnectRetirementRequest {
    pub lease_id: String,
    pub assertion: DesktopAgentDeviceAssertion,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentDisconnectCompletionRequest {
    pub lease_id: String,
    pub event_sequence: i64,
    /// A cancellation can arrive after retirement while the device credential
    /// is intentionally gone. This fixed acknowledgment can only persist the
    /// server-requested cancellation terminal, never a cleanup success.
    #[serde(default)]
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentTerminalStatus {
    Succeeded,
    Failed,
    Rejected,
    Interrupted,
}

impl From<DesktopAgentTerminalStatus> for DesktopAgentCommandStatus {
    fn from(value: DesktopAgentTerminalStatus) -> Self {
        match value {
            DesktopAgentTerminalStatus::Succeeded => Self::Succeeded,
            DesktopAgentTerminalStatus::Failed => Self::Failed,
            DesktopAgentTerminalStatus::Rejected => Self::Rejected,
            DesktopAgentTerminalStatus::Interrupted => Self::Interrupted,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DesktopAgentCommandEvent {
    pub sequence: i64,
    pub at: String,
    pub status: DesktopAgentCommandStatus,
    pub phase: Option<DesktopAgentPhase>,
    pub progress_basis_points: Option<u16>,
    pub terminal_code: Option<DesktopAgentTerminalCode>,
    pub result_code: Option<DesktopAgentResultCode>,
    pub result: Option<DesktopAgentResultPayload>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DesktopAgentCommand {
    pub id: String,
    pub device_id: Option<String>,
    pub kind: DesktopAgentCommandKind,
    pub status: DesktopAgentCommandStatus,
    pub created_at: String,
    pub expires_at: String,
    pub lease_expires_at: Option<String>,
    pub events: Vec<DesktopAgentCommandEvent>,
    pub terminal_code: Option<DesktopAgentTerminalCode>,
    pub result_code: Option<DesktopAgentResultCode>,
    pub result: Option<DesktopAgentResultPayload>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DesktopAgentCommandPage {
    pub commands: Vec<DesktopAgentCommand>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct DesktopAgentLease {
    pub command_id: String,
    pub lease_id: String,
    pub lease_expires_at: String,
    pub kind: DesktopAgentCommandKind,
    pub payload: Value,
    /// Present only for an acknowledged Disconnect flow. It is never stored
    /// in command readback, device records, or events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_completion_capability: Option<String>,
    /// The capability's non-secret deadline. It can outlive the regular
    /// device lease because a Disconnect retires that device before local
    /// cleanup and its terminal acknowledgement can finish.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_completion_expires_at: Option<String>,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct DesktopAgentClaimResponse {
    pub claim: Option<DesktopAgentLease>,
}
