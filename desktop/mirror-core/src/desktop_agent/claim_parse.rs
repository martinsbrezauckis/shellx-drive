//! Command-specific validation after the outer-kind decoder selected a shape.

use crate::{DesktopError, Result};

use super::{
    ensure_fingerprint, ensure_native_review_id, ensure_opaque_id, DesktopAgentClaimPayload,
    DesktopAgentCommand, DesktopAgentCommandKind,
};

impl DesktopAgentClaimPayload {
    pub fn parse(self, kind: DesktopAgentCommandKind) -> Result<DesktopAgentCommand> {
        let command = match (kind, self) {
            (DesktopAgentCommandKind::DesktopView, Self::DesktopView { page }) => {
                DesktopAgentCommand::DesktopView { page }
            }
            (DesktopAgentCommandKind::SyncNow, Self::Empty {}) => DesktopAgentCommand::SyncNow,
            (DesktopAgentCommandKind::RecheckReviews, Self::Empty {}) => {
                DesktopAgentCommand::RecheckReviews
            }
            (DesktopAgentCommandKind::SetPaused, Self::SetPaused { paused }) => {
                DesktopAgentCommand::SetPaused { paused }
            }
            (DesktopAgentCommandKind::SetLaunchAtLogin, Self::SetLaunchAtLogin { enabled }) => {
                DesktopAgentCommand::SetLaunchAtLogin { enabled }
            }
            (
                DesktopAgentCommandKind::PrepareReviewAction,
                Self::PrepareReviewAction {
                    pair_id,
                    review_id,
                    action,
                },
            ) => {
                ensure_opaque_id("review pair ID", &pair_id)?;
                ensure_native_review_id(&review_id)?;
                DesktopAgentCommand::PrepareReviewAction {
                    pair_id,
                    review_id,
                    action,
                }
            }
            (
                DesktopAgentCommandKind::ConfirmReviewAction,
                Self::ConfirmReviewAction {
                    pair_id,
                    review_id,
                    action,
                    prepared_confirmation_id,
                    fingerprint,
                },
            ) => {
                ensure_opaque_id("review pair ID", &pair_id)?;
                ensure_native_review_id(&review_id)?;
                ensure_opaque_id("review confirmation ID", &prepared_confirmation_id)?;
                ensure_fingerprint(&fingerprint)?;
                DesktopAgentCommand::ConfirmReviewAction {
                    pair_id,
                    review_id,
                    action,
                    prepared_confirmation_id,
                    fingerprint,
                }
            }
            (
                DesktopAgentCommandKind::InstallDesktopUpdate,
                Self::InstallDesktopUpdate { candidate_id },
            ) => {
                ensure_opaque_id("desktop update candidate ID", &candidate_id)?;
                DesktopAgentCommand::InstallDesktopUpdate { candidate_id }
            }
            (DesktopAgentCommandKind::OpenLocalFolder, Self::OpenLocalFolder { pair_id }) => {
                if let Some(pair_id) = pair_id.as_deref() {
                    ensure_opaque_id("selected pair ID", pair_id)?;
                }
                DesktopAgentCommand::OpenLocalFolder { pair_id }
            }
            (DesktopAgentCommandKind::OpenDrive, Self::OpenDrive { pair_id }) => {
                if let Some(pair_id) = pair_id.as_deref() {
                    ensure_opaque_id("selected pair ID", pair_id)?;
                }
                DesktopAgentCommand::OpenDrive { pair_id }
            }
            (DesktopAgentCommandKind::StartPair, Self::StartPair { workspace_id }) => {
                ensure_opaque_id("workspace ID", &workspace_id)?;
                DesktopAgentCommand::StartPair { workspace_id }
            }
            (DesktopAgentCommandKind::SelectPair, Self::SelectPair { pair_id }) => {
                ensure_opaque_id("selected pair ID", &pair_id)?;
                DesktopAgentCommand::SelectPair { pair_id }
            }
            (DesktopAgentCommandKind::CheckDesktopUpdate, Self::Empty {}) => {
                DesktopAgentCommand::CheckDesktopUpdate
            }
            (DesktopAgentCommandKind::Disconnect, Self::Empty {}) => {
                DesktopAgentCommand::Disconnect
            }
            (DesktopAgentCommandKind::DiscoverRoots, Self::DiscoverRoots { page }) => {
                DesktopAgentCommand::DiscoverRoots { page }
            }
            (DesktopAgentCommandKind::ValidateServer, Self::Empty {}) => {
                DesktopAgentCommand::ValidateServer
            }
            (kind, Self::Empty {}) if kind.local_gesture().is_some() => {
                DesktopAgentCommand::RequiresLocalGesture(kind.local_gesture().expect("checked"))
            }
            (kind, _) => {
                return Err(DesktopError::InvalidState(format!(
                    "desktop-agent command {kind:?} has an invalid typed payload"
                )));
            }
        };
        Ok(command)
    }
}
