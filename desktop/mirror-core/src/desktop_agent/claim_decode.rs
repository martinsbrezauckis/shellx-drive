//! Claim decoding selects its strict payload shape from the outer command.

use serde::Deserialize;

use crate::{DesktopError, Result, ReviewAction};

use super::{DesktopAgentClaimPayload, DesktopAgentCommandKind};

mod readback;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PausePayload {
    paused: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchAtLoginPayload {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareReviewPayload {
    pair_id: String,
    review_id: String,
    action: ReviewAction,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmReviewPayload {
    pair_id: String,
    review_id: String,
    action: ReviewAction,
    prepared_confirmation_id: String,
    fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidatePayload {
    candidate_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionalPairPayload {
    pair_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspacePayload {
    workspace_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairPayload {
    pair_id: String,
}

impl DesktopAgentClaimPayload {
    pub(crate) fn decode(kind: DesktopAgentCommandKind, value: serde_json::Value) -> Result<Self> {
        let payload = match kind {
            DesktopAgentCommandKind::SyncNow
            | DesktopAgentCommandKind::RecheckReviews
            | DesktopAgentCommandKind::CheckDesktopUpdate
            | DesktopAgentCommandKind::Disconnect
            | DesktopAgentCommandKind::ValidateServer
            | DesktopAgentCommandKind::ContinueLogin
            | DesktopAgentCommandKind::ContinueMfa => {
                decode::<EmptyPayload>(value).map(|_| Self::Empty {})
            }
            DesktopAgentCommandKind::DesktopView => {
                readback::decode_desktop_view(value).map(|page| Self::DesktopView { page })
            }
            DesktopAgentCommandKind::DiscoverRoots => {
                readback::decode_discover_roots(value).map(|page| Self::DiscoverRoots { page })
            }
            DesktopAgentCommandKind::SetPaused => {
                decode::<PausePayload>(value).map(|value| Self::SetPaused {
                    paused: value.paused,
                })
            }
            DesktopAgentCommandKind::SetLaunchAtLogin => {
                decode::<LaunchAtLoginPayload>(value).map(|value| Self::SetLaunchAtLogin {
                    enabled: value.enabled,
                })
            }
            DesktopAgentCommandKind::PrepareReviewAction => decode::<PrepareReviewPayload>(value)
                .map(|value| Self::PrepareReviewAction {
                    pair_id: value.pair_id,
                    review_id: value.review_id,
                    action: value.action,
                }),
            DesktopAgentCommandKind::ConfirmReviewAction => decode::<ConfirmReviewPayload>(value)
                .map(|value| Self::ConfirmReviewAction {
                    pair_id: value.pair_id,
                    review_id: value.review_id,
                    action: value.action,
                    prepared_confirmation_id: value.prepared_confirmation_id,
                    fingerprint: value.fingerprint,
                }),
            DesktopAgentCommandKind::InstallDesktopUpdate => {
                decode::<CandidatePayload>(value).map(|value| Self::InstallDesktopUpdate {
                    candidate_id: value.candidate_id,
                })
            }
            DesktopAgentCommandKind::OpenLocalFolder => {
                decode::<OptionalPairPayload>(value).map(|value| Self::OpenLocalFolder {
                    pair_id: value.pair_id,
                })
            }
            DesktopAgentCommandKind::OpenDrive => {
                decode::<OptionalPairPayload>(value).map(|value| Self::OpenDrive {
                    pair_id: value.pair_id,
                })
            }
            DesktopAgentCommandKind::StartPair => {
                decode::<WorkspacePayload>(value).map(|value| Self::StartPair {
                    workspace_id: value.workspace_id,
                })
            }
            DesktopAgentCommandKind::SelectPair => {
                decode::<PairPayload>(value).map(|value| Self::SelectPair {
                    pair_id: value.pair_id,
                })
            }
        };
        payload.map_err(|_| {
            DesktopError::InvalidState(
                "desktop-agent command payload does not match its declared kind".to_string(),
            )
        })
    }
}

fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> std::result::Result<T, ()> {
    serde_json::from_value(value).map_err(|_| ())
}
