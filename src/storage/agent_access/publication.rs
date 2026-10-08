use crate::model::{AgentAccess, Receipt};

mod finalization;
mod issuance;
mod limits;
mod rotation;
#[cfg(test)]
mod tests;

/// A route-only issuance intent. Its rows are deliberately inactive until the
/// exact source credential and workspace Write authority succeed again at the
/// final publication boundary.
#[derive(Debug)]
pub(crate) struct PendingAgentAccessPublication {
    pub(crate) access: AgentAccess,
    pub(crate) receipt: Receipt,
    pub(super) kind: PendingAgentAccessPublicationKind,
}

#[derive(Debug)]
pub(super) enum PendingAgentAccessPublicationKind {
    NewPrincipal {
        principal_id: String,
        token_id: String,
        grant_id: String,
        workspace_id: String,
    },
    Grant {
        principal_id: String,
        grant_id: String,
        workspace_id: String,
    },
}

/// A staged principal-wide token replacement. Existing live tokens remain
/// usable until publication atomically activates this token and retires them.
#[derive(Debug)]
pub(crate) struct PendingAgentPrincipalRotation {
    pub(crate) receipt: Receipt,
    pub(super) principal_id: String,
    pub(super) token_id: String,
}
