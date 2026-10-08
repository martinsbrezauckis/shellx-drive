use serde::{Deserialize, Serialize};

use super::{
    DesktopAgentCommandKind, DesktopAgentDesktopViewPage, DesktopAgentObservedStatus,
    DesktopAgentReviewAction, DesktopAgentRootsDiscoveredPage,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentUpdateAvailability {
    UpToDate,
    CandidateAvailable,
    Unavailable,
}

/// Bounded, kind-specific readback for a successful desktop command. It never
/// contains a local path, URL, free-form error, log, credential, or file name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopAgentResultPayload {
    DesktopView {
        status: DesktopAgentObservedStatus,
        paused: bool,
        active_pair_count: u8,
        /// Aggregate across every configured location. Individual page rows
        /// remain `u16`, bounded by the per-location review limit.
        pending_review_count: u32,
        #[serde(default)]
        page: Option<DesktopAgentDesktopViewPage>,
        #[serde(default)]
        next_after: Option<String>,
    },
    Sync {
        status: DesktopAgentObservedStatus,
        pending_review_count: u32,
    },
    Pause {
        paused: bool,
    },
    LaunchAtLogin {
        enabled: bool,
    },
    ReviewPrepared {
        /// Historical records predate an exact root binding. They remain
        /// readable, but cannot satisfy a new review terminal proof.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pair_id: Option<String>,
        review_id: String,
        action: DesktopAgentReviewAction,
        prepared_confirmation_id: String,
        fingerprint: String,
    },
    ReviewConfirmed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pair_id: Option<String>,
        review_id: String,
        action: DesktopAgentReviewAction,
        prepared_confirmation_id: String,
        fingerprint: String,
    },
    UpdateCheck {
        availability: DesktopAgentUpdateAvailability,
        candidate_id: Option<String>,
    },
    UpdateInstall {
        candidate_id: String,
        installed_version: String,
    },
    Disconnect {
        cleanup_completed: bool,
    },
    LocalFolderDispatch {
        dispatched: bool,
        pair_id: Option<String>,
    },
    DriveDispatch {
        dispatched: bool,
        pair_id: Option<String>,
    },
    RootsDiscovered {
        workspace_count: u16,
        candidate_count: u16,
        requires_local_selection: bool,
        #[serde(default)]
        page: Option<DesktopAgentRootsDiscoveredPage>,
        #[serde(default)]
        next_after: Option<String>,
    },
    RootsRefreshed {
        workspace_id: String,
        added_root_count: u16,
        existing_root_count: u16,
    },
    PairSelected {
        pair_id: String,
    },
    ServerValidated {
        status: DesktopAgentObservedStatus,
    },
}

impl DesktopAgentResultPayload {
    pub const fn matches_kind(&self, kind: DesktopAgentCommandKind) -> bool {
        matches!(
            (kind, self),
            (
                DesktopAgentCommandKind::DesktopView,
                Self::DesktopView { .. }
            ) | (DesktopAgentCommandKind::SyncNow, Self::Sync { .. })
                | (DesktopAgentCommandKind::RecheckReviews, Self::Sync { .. })
                | (DesktopAgentCommandKind::SetPaused, Self::Pause { .. })
                | (
                    DesktopAgentCommandKind::SetLaunchAtLogin,
                    Self::LaunchAtLogin { .. }
                )
                | (
                    DesktopAgentCommandKind::PrepareReviewAction,
                    Self::ReviewPrepared { .. }
                )
                | (
                    DesktopAgentCommandKind::ConfirmReviewAction,
                    Self::ReviewConfirmed { .. }
                )
                | (
                    DesktopAgentCommandKind::CheckDesktopUpdate,
                    Self::UpdateCheck { .. }
                )
                | (
                    DesktopAgentCommandKind::InstallDesktopUpdate,
                    Self::UpdateInstall { .. }
                )
                | (DesktopAgentCommandKind::Disconnect, Self::Disconnect { .. })
                | (
                    DesktopAgentCommandKind::OpenLocalFolder,
                    Self::LocalFolderDispatch { .. }
                )
                | (
                    DesktopAgentCommandKind::OpenDrive,
                    Self::DriveDispatch { .. }
                )
                | (
                    DesktopAgentCommandKind::DiscoverRoots,
                    Self::RootsDiscovered { .. }
                )
                | (
                    DesktopAgentCommandKind::StartPair,
                    Self::RootsRefreshed { .. }
                )
                | (
                    DesktopAgentCommandKind::SelectPair,
                    Self::PairSelected { .. }
                )
                | (
                    DesktopAgentCommandKind::ValidateServer,
                    Self::ServerValidated { .. }
                )
        )
    }
}
