//! Canonical typed payloads persisted by the desktop-agent broker.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    DesktopAgentCommandKind, DesktopAgentReviewAction, DesktopAgentViewSection,
    DEFAULT_DESKTOP_AGENT_READBACK_LIMIT,
};

/// This is parsed from `{ kind, payload }` before persistence, so
/// unrecognised JSON is never a command argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DesktopAgentCommandPayload {
    DesktopView {
        #[serde(default)]
        section: DesktopAgentViewSection,
        #[serde(default)]
        after: Option<String>,
        #[serde(default = "default_desktop_agent_readback_limit")]
        limit: u8,
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
        /// Historical broker rows predate the root binding. They remain
        /// readable, but are never eligible to be claimed for execution.
        #[serde(default)]
        pair_id: Option<String>,
        review_id: String,
        action: DesktopAgentReviewAction,
    },
    ConfirmReviewAction {
        #[serde(default)]
        pair_id: Option<String>,
        review_id: String,
        action: DesktopAgentReviewAction,
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
        #[serde(default)]
        after: Option<String>,
        #[serde(default = "default_desktop_agent_readback_limit")]
        limit: u8,
    },
    StartPair {
        workspace_id: String,
    },
    SelectPair {
        pair_id: String,
    },
    ValidateServer,
    ContinueLogin,
    ContinueMfa,
}

impl DesktopAgentCommandPayload {
    /// A persisted command must retain every authority binding needed by its
    /// current action before a device may receive it. This preserves old
    /// history without inferring a root for a queued review mutation.
    pub(crate) const fn is_claimable(&self) -> bool {
        match self {
            Self::PrepareReviewAction { pair_id, .. }
            | Self::ConfirmReviewAction { pair_id, .. } => pair_id.is_some(),
            _ => true,
        }
    }

    pub const fn kind(&self) -> DesktopAgentCommandKind {
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
            Self::ContinueLogin => DesktopAgentCommandKind::ContinueLogin,
            Self::ContinueMfa => DesktopAgentCommandKind::ContinueMfa,
        }
    }

    pub fn wire_payload(&self) -> Value {
        match self {
            Self::SyncNow
            | Self::RecheckReviews
            | Self::CheckDesktopUpdate
            | Self::Disconnect
            | Self::ValidateServer
            | Self::ContinueLogin
            | Self::ContinueMfa => Value::Object(Default::default()),
            Self::DesktopView {
                section,
                after,
                limit,
            } => serde_json::json!({
                "section": section,
                "after": after,
                "limit": limit,
            }),
            Self::SetPaused { paused } => serde_json::json!({ "paused": paused }),
            Self::SetLaunchAtLogin { enabled } => serde_json::json!({ "enabled": enabled }),
            Self::PrepareReviewAction {
                pair_id,
                review_id,
                action,
            } => {
                serde_json::json!({ "pair_id": pair_id, "review_id": review_id, "action": action })
            }
            Self::ConfirmReviewAction {
                pair_id,
                review_id,
                action,
                prepared_confirmation_id,
                fingerprint,
            } => serde_json::json!({
                "pair_id": pair_id,
                "review_id": review_id,
                "action": action,
                "prepared_confirmation_id": prepared_confirmation_id,
                "fingerprint": fingerprint,
            }),
            Self::InstallDesktopUpdate { candidate_id } => {
                serde_json::json!({ "candidate_id": candidate_id })
            }
            Self::OpenLocalFolder { pair_id } => serde_json::json!({ "pair_id": pair_id }),
            Self::OpenDrive { pair_id } => serde_json::json!({ "pair_id": pair_id }),
            Self::DiscoverRoots { after, limit } => serde_json::json!({
                "after": after,
                "limit": limit,
            }),
            Self::StartPair { workspace_id } => serde_json::json!({ "workspace_id": workspace_id }),
            Self::SelectPair { pair_id } => serde_json::json!({ "pair_id": pair_id }),
        }
    }
}

const fn default_desktop_agent_readback_limit() -> u8 {
    DEFAULT_DESKTOP_AGENT_READBACK_LIMIT
}
