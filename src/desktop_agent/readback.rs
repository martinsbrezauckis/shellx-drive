//! Bounded, actionable desktop-agent readback pages.
//!
//! The broker needs stable identifiers for the actions it already supports,
//! but it never accepts or stores a local path, credential, raw log, or free
//! form error in these projections.

use serde::{Deserialize, Serialize};

use super::DesktopAgentReviewAction;

pub const DEFAULT_DESKTOP_AGENT_READBACK_LIMIT: u8 = 25;
pub const MAX_DESKTOP_AGENT_READBACK_LIMIT: u8 = 50;
pub const MAX_DESKTOP_AGENT_READBACK_LABEL_BYTES: usize = 256;
pub const MAX_DESKTOP_AGENT_RESULT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentViewSection {
    #[default]
    Pairs,
    Reviews,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentPairStatus {
    Ready,
    Paused,
    NeedsReview,
    Error,
    Managed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentReviewKind {
    LocalDeletion,
    RemoteDeletion,
    ContentConflict,
    DeleteEditConflict,
    PathConflict,
    UnsupportedTransfer,
    UnsafePath,
    UnsafeLink,
    ReadOnlyLocalChange,
    AccessRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentSyncRootRole {
    Owner,
    Editor,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentRootSelectionStatus {
    Available,
    Configured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentPairRow {
    pub pair_id: String,
    pub workspace_id: String,
    pub workspace_name: String,
    pub remote_root_id: Option<String>,
    pub remote_root_name: Option<String>,
    pub selected: bool,
    pub status: DesktopAgentPairStatus,
    pub pending_review_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentReviewRow {
    pub review_id: String,
    pub pair_id: String,
    pub item_label: String,
    pub reason: DesktopAgentReviewKind,
    pub actions: Vec<DesktopAgentReviewAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "section", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopAgentDesktopViewPage {
    Pairs {
        after: Option<String>,
        limit: u8,
        rows: Vec<DesktopAgentPairRow>,
    },
    Reviews {
        after: Option<String>,
        limit: u8,
        rows: Vec<DesktopAgentReviewRow>,
    },
}

impl DesktopAgentDesktopViewPage {
    pub const fn section(&self) -> DesktopAgentViewSection {
        match self {
            Self::Pairs { .. } => DesktopAgentViewSection::Pairs,
            Self::Reviews { .. } => DesktopAgentViewSection::Reviews,
        }
    }

    pub fn after(&self) -> Option<&str> {
        match self {
            Self::Pairs { after, .. } | Self::Reviews { after, .. } => after.as_deref(),
        }
    }

    pub const fn limit(&self) -> u8 {
        match self {
            Self::Pairs { limit, .. } | Self::Reviews { limit, .. } => *limit,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentRootRow {
    pub workspace_id: String,
    pub workspace_name: String,
    pub sync_root_id: String,
    pub remote_root_id: Option<String>,
    pub root_name: String,
    pub owner_label: String,
    pub role: DesktopAgentSyncRootRole,
    pub selection_status: DesktopAgentRootSelectionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentRootsDiscoveredPage {
    pub after: Option<String>,
    pub limit: u8,
    pub rows: Vec<DesktopAgentRootRow>,
}
