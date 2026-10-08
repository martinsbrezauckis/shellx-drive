//! Durable, non-secret record of a Disconnect terminal that was not accepted.

use serde::{Deserialize, Serialize};

use crate::{DesktopError, Result};

use super::{
    ensure_opaque_id, DesktopAgentDisconnectBlockedReason, DesktopAgentDisconnectContinuation,
    DesktopAgentDisconnectPhase, MAX_CANONICAL_SERVER_ORIGIN_BYTES,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentDisconnectUnconfirmedDisposition {
    RetirementBlocked,
    CompletionBlocked,
}

/// This historical disposition contains no capability or session locator. It
/// permits later pairing while preserving that the named broker terminal was
/// never accepted as a successful Disconnect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DesktopAgentDisconnectUnconfirmedTerminal {
    pub canonical_server_origin: String,
    pub command_id: String,
    pub disposition: DesktopAgentDisconnectUnconfirmedDisposition,
    pub reason: DesktopAgentDisconnectBlockedReason,
}

impl DesktopAgentDisconnectUnconfirmedTerminal {
    pub fn validate(&self) -> Result<()> {
        if self.canonical_server_origin.is_empty()
            || self.canonical_server_origin.len() > MAX_CANONICAL_SERVER_ORIGIN_BYTES
            || !self.canonical_server_origin.starts_with("https://")
            || self.canonical_server_origin.contains(['?', '#'])
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent unconfirmed Disconnect has no canonical HTTPS origin".to_string(),
            ));
        }
        ensure_opaque_id(
            "desktop-agent unconfirmed Disconnect command ID",
            &self.command_id,
        )
    }
}

impl DesktopAgentDisconnectContinuation {
    pub(crate) fn unconfirmed_terminal(&self) -> Result<DesktopAgentDisconnectUnconfirmedTerminal> {
        let disposition = match self.phase {
            DesktopAgentDisconnectPhase::RetirementBlocked => {
                DesktopAgentDisconnectUnconfirmedDisposition::RetirementBlocked
            }
            DesktopAgentDisconnectPhase::CompletionBlocked => {
                DesktopAgentDisconnectUnconfirmedDisposition::CompletionBlocked
            }
            _ => {
                return Err(DesktopError::InvalidState(
                    "desktop-agent Disconnect has no unconfirmed terminal disposition".to_string(),
                ));
            }
        };
        let unconfirmed = DesktopAgentDisconnectUnconfirmedTerminal {
            canonical_server_origin: self.canonical_server_origin.clone(),
            command_id: self.command_id.clone(),
            disposition,
            reason: self.blocked_reason.ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent unconfirmed Disconnect has no blocked reason".to_string(),
                )
            })?,
        };
        unconfirmed.validate()?;
        Ok(unconfirmed)
    }
}
