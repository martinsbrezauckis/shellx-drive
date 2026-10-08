//! Typed, non-secret contract for the outbound desktop-agent broker.
//!
//! The module deliberately has no transport loop or Tauri dependency. It
//! validates the command vocabulary, persists only a bounded local journal,
//! and makes post-ack restart recovery explicit. Device credentials never
//! enter durable desktop state.

use crate::{DesktopError, Result, ReviewAction};

use super::{
    ensure_fingerprint, ensure_opaque_id, DesktopAgentDesktopViewPageRequest,
    DesktopAgentRootsPageRequest,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod claim;
pub use claim::{validate_disconnect_completion_capability, DesktopAgentClaim};

pub const MAX_DESKTOP_AGENT_JOURNAL_ENTRIES: usize = 128;
const MAX_AGENT_APP_VERSION_BYTES: usize = 128;
const MAX_AGENT_DEVICE_CREDENTIAL_BYTES: usize = 512;
const DISCONNECT_COMPLETION_CREDENTIAL_PREFIX: &str = "sxd_disconnect_";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentPlatform {
    Windows,
    Macos,
    Linux,
}

#[cfg(target_os = "windows")]
pub const CURRENT_DESKTOP_AGENT_PLATFORM: DesktopAgentPlatform = DesktopAgentPlatform::Windows;
#[cfg(target_os = "macos")]
pub const CURRENT_DESKTOP_AGENT_PLATFORM: DesktopAgentPlatform = DesktopAgentPlatform::Macos;
#[cfg(target_os = "linux")]
pub const CURRENT_DESKTOP_AGENT_PLATFORM: DesktopAgentPlatform = DesktopAgentPlatform::Linux;

/// The broker-visible projection of native synchronization state. The broker
/// accepts only this bounded operational vocabulary, never the full UI state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentObservedStatus {
    Ready,
    Paused,
    Error,
    NeedsSetup,
}

/// The complete desktop-action registry. This is shared by the HTTP decoder
/// and the native dispatcher; it is never an arbitrary invoke name.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

/// Commands which a broker may describe but which must continue in the native
/// UI. Their data is checked before this outcome is returned and never becomes
/// an arbitrary native invocation, path, URL, or secret.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentLocalGesture {
    StartPair,
    ContinueLogin,
    ContinueMfa,
}

impl DesktopAgentCommandKind {
    pub fn local_gesture(self) -> Option<DesktopAgentLocalGesture> {
        match self {
            Self::ContinueLogin => Some(DesktopAgentLocalGesture::ContinueLogin),
            Self::ContinueMfa => Some(DesktopAgentLocalGesture::ContinueMfa),
            Self::DesktopView
            | Self::SyncNow
            | Self::RecheckReviews
            | Self::SetPaused
            | Self::SetLaunchAtLogin
            | Self::PrepareReviewAction
            | Self::ConfirmReviewAction
            | Self::CheckDesktopUpdate
            | Self::InstallDesktopUpdate
            | Self::Disconnect
            | Self::OpenLocalFolder
            | Self::OpenDrive
            | Self::DiscoverRoots
            | Self::StartPair
            | Self::SelectPair
            | Self::ValidateServer => None,
        }
    }
}

/// A fully parsed broker command. The wire payload is decoded against its
/// outer kind before it reaches any native action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesktopAgentCommand {
    DesktopView {
        page: DesktopAgentDesktopViewPageRequest,
    },
    SyncNow,
    RecheckReviews,
    SetPaused {
        paused: bool,
    },
    SetLaunchAtLogin {
        enabled: bool,
    },
    PrepareReviewAction {
        pair_id: String,
        review_id: String,
        action: ReviewAction,
    },
    ConfirmReviewAction {
        pair_id: String,
        review_id: String,
        action: ReviewAction,
        prepared_confirmation_id: String,
        fingerprint: String,
    },
    CheckDesktopUpdate,
    InstallDesktopUpdate {
        candidate_id: String,
    },
    Disconnect,
    OpenLocalFolder {
        pair_id: Option<String>,
    },
    OpenDrive {
        pair_id: Option<String>,
    },
    DiscoverRoots {
        page: DesktopAgentRootsPageRequest,
    },
    StartPair {
        workspace_id: String,
    },
    SelectPair {
        pair_id: String,
    },
    ValidateServer,
    RequiresLocalGesture(DesktopAgentLocalGesture),
}

impl DesktopAgentCommand {
    pub fn kind(&self) -> DesktopAgentCommandKind {
        match self {
            Self::DesktopView { .. } => DesktopAgentCommandKind::DesktopView,
            Self::SyncNow => DesktopAgentCommandKind::SyncNow,
            Self::RecheckReviews => DesktopAgentCommandKind::RecheckReviews,
            Self::SetPaused { .. } => DesktopAgentCommandKind::SetPaused,
            Self::SetLaunchAtLogin { .. } => DesktopAgentCommandKind::SetLaunchAtLogin,
            Self::PrepareReviewAction { .. } => DesktopAgentCommandKind::PrepareReviewAction,
            Self::ConfirmReviewAction { .. } => DesktopAgentCommandKind::ConfirmReviewAction,
            Self::CheckDesktopUpdate => DesktopAgentCommandKind::CheckDesktopUpdate,
            Self::InstallDesktopUpdate { .. } => DesktopAgentCommandKind::InstallDesktopUpdate,
            Self::Disconnect => DesktopAgentCommandKind::Disconnect,
            Self::OpenLocalFolder { .. } => DesktopAgentCommandKind::OpenLocalFolder,
            Self::OpenDrive { .. } => DesktopAgentCommandKind::OpenDrive,
            Self::DiscoverRoots { .. } => DesktopAgentCommandKind::DiscoverRoots,
            Self::StartPair { .. } => DesktopAgentCommandKind::StartPair,
            Self::SelectPair { .. } => DesktopAgentCommandKind::SelectPair,
            Self::ValidateServer => DesktopAgentCommandKind::ValidateServer,
            Self::RequiresLocalGesture(DesktopAgentLocalGesture::StartPair) => {
                DesktopAgentCommandKind::StartPair
            }
            Self::RequiresLocalGesture(DesktopAgentLocalGesture::ContinueLogin) => {
                DesktopAgentCommandKind::ContinueLogin
            }
            Self::RequiresLocalGesture(DesktopAgentLocalGesture::ContinueMfa) => {
                DesktopAgentCommandKind::ContinueMfa
            }
        }
    }
}

/// The strict payload supplied beside a broker command kind. It is public so
/// the HTTP adapter can deserialize it, but callers must use its parse method
/// before dispatching it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum DesktopAgentClaimPayload {
    DesktopView {
        page: DesktopAgentDesktopViewPageRequest,
    },
    SetPaused {
        paused: bool,
    },
    SetLaunchAtLogin {
        enabled: bool,
    },
    PrepareReviewAction {
        pair_id: String,
        review_id: String,
        action: ReviewAction,
    },
    ConfirmReviewAction {
        pair_id: String,
        review_id: String,
        action: ReviewAction,
        prepared_confirmation_id: String,
        fingerprint: String,
    },
    InstallDesktopUpdate {
        candidate_id: String,
    },
    OpenLocalFolder {
        pair_id: Option<String>,
    },
    OpenDrive {
        pair_id: Option<String>,
    },
    DiscoverRoots {
        page: DesktopAgentRootsPageRequest,
    },
    StartPair {
        workspace_id: String,
    },
    SelectPair {
        pair_id: String,
    },
    /// Keep this last: untagged deserialization otherwise treats every object
    /// as an empty payload before it reaches the command-specific variant.
    Empty {},
}

/// Registration has the same no-`Debug` rule as a claim because the device
/// credential is returned once and must immediately move to the OS store.
#[derive(Deserialize)]
pub struct DesktopAgentRegistration {
    pub device_id: String,
    pub device_credential: String,
    pub credential_expires_at: Option<DateTime<Utc>>,
}

impl DesktopAgentRegistration {
    pub fn validate(&self) -> Result<()> {
        ensure_opaque_id("desktop-agent device ID", &self.device_id)?;
        if !self.device_credential.starts_with("sxd_device_")
            || self.device_credential.len() > MAX_AGENT_DEVICE_CREDENTIAL_BYTES
            || !self
                .device_credential
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent registration did not return a bounded device credential".to_string(),
            ));
        }
        Ok(())
    }
}

/// The non-secret state assertion sent with every device operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DesktopAgentDeviceAssertion {
    pub app_version: String,
    /// Historical wire name retained for compatibility. New enrollments bind
    /// this digest to the normalized Drive server and account, never a root.
    pub pair_fingerprint: String,
    pub status: DesktopAgentObservedStatus,
    pub pending_disconnect_cleanup: bool,
    pub candidate_recovery: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_terminal_command_id: Option<String>,
}

impl DesktopAgentDeviceAssertion {
    pub fn validate(&self) -> Result<()> {
        if self.app_version.is_empty() || self.app_version.len() > MAX_AGENT_APP_VERSION_BYTES {
            return Err(DesktopError::InvalidState(
                "desktop-agent app version has an invalid length".to_string(),
            ));
        }
        ensure_fingerprint(&self.pair_fingerprint)?;
        if let Some(command_id) = self.last_terminal_command_id.as_deref() {
            ensure_opaque_id("desktop-agent last terminal command ID", command_id)?;
        }
        Ok(())
    }
}

/// Result fields are code-only. The UI maps these stable values to text after
/// the broker has authenticated the requester; no local paths, logs, or
/// opaque remote error messages become command results.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    PairStarted,
    PairSelected,
    ServerValidated,
    LocalGestureCompleted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentTerminalStatus {
    Succeeded,
    Failed,
    Rejected,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentProgressPhase {
    Accepted,
    AwaitingLocalGesture,
    Syncing,
    Reviewing,
    Updating,
    Disconnecting,
    RelaunchPending,
}
