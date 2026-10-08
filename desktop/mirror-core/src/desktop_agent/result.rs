//! Bounded, successful command readback for the desktop-agent broker.

use serde::{Deserialize, Serialize};

use crate::{DesktopError, Result, ReviewAction};

use super::{
    ensure_fingerprint, ensure_native_review_id, ensure_opaque_id, validate_page_result,
    DesktopAgentCommandKind, DesktopAgentDesktopViewPage, DesktopAgentObservedStatus,
    DesktopAgentResultCode, DesktopAgentRootsPage,
};

mod start_pair;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentUpdateAvailability {
    UpToDate,
    CandidateAvailable,
    Unavailable,
}

/// A successful readback is deliberately compact and has no local paths,
/// URLs, free-form errors, logs, credentials, or file names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopAgentResultPayload {
    DesktopView {
        status: DesktopAgentObservedStatus,
        paused: bool,
        active_pair_count: u8,
        /// Aggregate across every configured location. Individual page rows
        /// remain `u16`, bounded by the 20,000-review per-location limit.
        pending_review_count: u32,
        page: DesktopAgentDesktopViewPage,
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
        pair_id: String,
        review_id: String,
        action: ReviewAction,
        prepared_confirmation_id: String,
        fingerprint: String,
    },
    ReviewConfirmed {
        pair_id: String,
        review_id: String,
        action: ReviewAction,
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
        page: DesktopAgentRootsPage,
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
    pub(crate) fn validate_for(
        &self,
        kind: DesktopAgentCommandKind,
        code: DesktopAgentResultCode,
    ) -> Result<()> {
        let matches_kind = matches!(
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
        );
        let matches_code = matches!(
            (code, self),
            (DesktopAgentResultCode::ViewRead, Self::DesktopView { .. })
                | (DesktopAgentResultCode::SyncCompleted, Self::Sync { .. })
                | (DesktopAgentResultCode::ReviewsRechecked, Self::Sync { .. })
                | (DesktopAgentResultCode::PausePersisted, Self::Pause { .. })
                | (
                    DesktopAgentResultCode::LaunchAtLoginPersisted,
                    Self::LaunchAtLogin { .. }
                )
                | (
                    DesktopAgentResultCode::ReviewPrepared,
                    Self::ReviewPrepared { .. }
                )
                | (
                    DesktopAgentResultCode::ReviewConfirmed,
                    Self::ReviewConfirmed { .. }
                )
                | (
                    DesktopAgentResultCode::UpdateChecked,
                    Self::UpdateCheck { .. }
                )
                | (
                    DesktopAgentResultCode::UpdateInstalled,
                    Self::UpdateInstall { .. }
                )
                | (
                    DesktopAgentResultCode::DisconnectCompleted,
                    Self::Disconnect { .. }
                )
                | (
                    DesktopAgentResultCode::LocalFolderDispatchAttempted,
                    Self::LocalFolderDispatch { .. }
                )
                | (
                    DesktopAgentResultCode::DriveDispatchAttempted,
                    Self::DriveDispatch { .. }
                )
                | (
                    DesktopAgentResultCode::RootsDiscovered,
                    Self::RootsDiscovered { .. }
                )
                | (
                    DesktopAgentResultCode::RootsRefreshed,
                    Self::RootsRefreshed { .. }
                )
                | (
                    DesktopAgentResultCode::PairSelected,
                    Self::PairSelected { .. }
                )
                | (
                    DesktopAgentResultCode::ServerValidated,
                    Self::ServerValidated { .. }
                )
        );
        if !matches_kind || !matches_code {
            return Err(DesktopError::InvalidState(
                "desktop-agent terminal result does not match its command".to_string(),
            ));
        }
        match self {
            Self::ReviewPrepared {
                pair_id,
                review_id,
                prepared_confirmation_id,
                fingerprint,
                ..
            } => {
                ensure_opaque_id("review pair ID", pair_id)?;
                ensure_native_review_id(review_id)?;
                ensure_opaque_id("review confirmation ID", prepared_confirmation_id)?;
                ensure_fingerprint(fingerprint)?;
            }
            Self::ReviewConfirmed {
                pair_id,
                review_id,
                prepared_confirmation_id,
                fingerprint,
                ..
            } => {
                ensure_opaque_id("review pair ID", pair_id)?;
                ensure_native_review_id(review_id)?;
                ensure_opaque_id("review confirmation ID", prepared_confirmation_id)?;
                ensure_fingerprint(fingerprint)?;
            }
            Self::UpdateCheck {
                availability,
                candidate_id,
            } => {
                if matches!(
                    availability,
                    DesktopAgentUpdateAvailability::CandidateAvailable
                ) != candidate_id.is_some()
                {
                    return Err(DesktopError::InvalidState(
                        "desktop-agent update availability and candidate disagree".to_string(),
                    ));
                }
                if let Some(candidate_id) = candidate_id {
                    ensure_opaque_id("desktop update candidate ID", candidate_id)?;
                }
            }
            Self::UpdateInstall {
                candidate_id,
                installed_version,
            } => {
                ensure_opaque_id("desktop update candidate ID", candidate_id)?;
                if installed_version.is_empty()
                    || installed_version.len() > 128
                    || !installed_version.is_ascii()
                {
                    return Err(DesktopError::InvalidState(
                        "desktop-agent installed version is invalid".to_string(),
                    ));
                }
            }
            Self::LocalFolderDispatch { pair_id, .. } | Self::DriveDispatch { pair_id, .. } => {
                if let Some(pair_id) = pair_id {
                    ensure_opaque_id("selected pair ID", pair_id)?;
                }
            }
            Self::DesktopView {
                page, next_after, ..
            } => {
                page.validate(next_after.as_deref())?;
                validate_page_result(self)?;
            }
            Self::RootsDiscovered {
                page, next_after, ..
            } => {
                page.validate(next_after.as_deref())?;
                validate_page_result(self)?;
            }
            Self::RootsRefreshed { .. } => start_pair::validate_roots_refreshed(self)?,
            Self::PairSelected { pair_id } => ensure_opaque_id("selected pair ID", pair_id)?,
            Self::Sync { .. }
            | Self::Pause { .. }
            | Self::LaunchAtLogin { .. }
            | Self::Disconnect { .. }
            | Self::ServerValidated { .. } => {}
        }
        Ok(())
    }
}
