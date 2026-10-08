//! Durable, non-secret continuation for an agent-owned Disconnect terminal.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DesktopAgentDeviceAssertion, DesktopError, RemoteSessionRecord, Result};

use super::ensure_opaque_id;

const MAX_CANONICAL_SERVER_ORIGIN_BYTES: usize = 512;

mod unconfirmed;

pub use unconfirmed::{
    DesktopAgentDisconnectUnconfirmedDisposition, DesktopAgentDisconnectUnconfirmedTerminal,
};

/// The durable boundary of an agent-owned Disconnect. The raw capability is
/// always held separately in the platform credential store.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentDisconnectPhase {
    /// The exact assertion is durable before the capability-authenticated
    /// retirement request can revoke the broker device and owner session.
    RetiringRemote,
    /// Remote retirement was accepted; exact marker and credential cleanup is
    /// still required before the terminal receipt may be requested.
    LocalCleanup,
    /// Local cleanup is complete and the capability-authenticated terminal
    /// request can be retried exactly after a response loss.
    Reporting,
    /// The broker accepted the fixed terminal disposition. This receipt is
    /// durable before the raw capability and local control state are removed.
    TerminalAccepted,
    /// Cancellation won before retirement admission. The normal device
    /// bearer remains live, so the exact interruption terminal must be
    /// durably retried before local cleanup and capability removal.
    RetirementCancelled,
    /// The broker rejected retirement before the bound session was retired.
    /// Normal local Disconnect remains available to complete its existing
    /// cleanup intent.
    RetirementBlocked,
    /// The broker rejected a terminal after local cleanup. No success is
    /// claimed and normal pairing is no longer blocked.
    CompletionBlocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentDisconnectTerminalReceipt {
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentDisconnectBlockedReason {
    CancellationRequested,
    AuthorizationLost,
    CapabilityExpired,
    CapabilityUnavailable,
    BrokerConflict,
}

/// The completion capability remains only in the OS credential namespace.
/// This state records the non-secret locator and exact retry witness needed to
/// finish a cleanup after the paired session and broker device are retired.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DesktopAgentDisconnectContinuation {
    pub canonical_server_origin: String,
    pub command_id: String,
    pub lease_id: String,
    /// The ordinary claim lease deadline. Retirement and a cancellation that
    /// races before retirement admission use the normal device bearer and
    /// never outlive this deadline. Older serialized continuations have no
    /// reconstructible value and are recovered conservatively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement_expires_at: Option<DateTime<Utc>>,
    /// The server-bounded command deadline; retry scheduling never keeps the
    /// capability beyond this instant when the network is unavailable.
    pub completion_expires_at: DateTime<Utc>,
    pub completion_event_sequence: u64,
    pub phase: DesktopAgentDisconnectPhase,
    /// Required only while a lost `disconnect-retire` response must be retried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retire_assertion: Option<DesktopAgentDeviceAssertion>,
    /// Required only while a lost retirement response must be retried. It is
    /// the exact non-secret current-session locator to remove after the
    /// capability route has retired it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_owner_session: Option<RemoteSessionRecord>,
    /// Required only after the broker's terminal acceptance, before local
    /// capability/control cleanup is durably finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_receipt: Option<DesktopAgentDisconnectTerminalReceipt>,
    /// Required only when the broker terminal cannot be truthfully completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<DesktopAgentDisconnectBlockedReason>,
}

impl DesktopAgentDisconnectContinuation {
    pub fn validate(&self) -> Result<()> {
        if self.canonical_server_origin.is_empty()
            || self.canonical_server_origin.len() > MAX_CANONICAL_SERVER_ORIGIN_BYTES
            || !self.canonical_server_origin.starts_with("https://")
            || self.canonical_server_origin.contains(['?', '#'])
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent Disconnect continuation has no canonical HTTPS origin".to_string(),
            ));
        }
        ensure_opaque_id("desktop-agent Disconnect command ID", &self.command_id)?;
        ensure_opaque_id("desktop-agent Disconnect lease ID", &self.lease_id)?;
        if self.completion_event_sequence == 0 {
            return Err(DesktopError::InvalidState(
                "desktop-agent Disconnect continuation has no completion sequence".to_string(),
            ));
        }
        match self.phase {
            DesktopAgentDisconnectPhase::RetiringRemote => {
                let assertion = self.retire_assertion.as_ref().ok_or_else(|| {
                    DesktopError::InvalidState(
                        "desktop-agent Disconnect retirement has no exact assertion witness"
                            .to_string(),
                    )
                })?;
                assertion.validate()?;
                self.bound_owner_session
                    .as_ref()
                    .ok_or_else(|| {
                        DesktopError::InvalidState(
                            "desktop-agent Disconnect retirement has no bound session witness"
                                .to_string(),
                        )
                    })?
                    .validate()?;
                if !assertion.pending_disconnect_cleanup
                    || self.terminal_receipt.is_some()
                    || self.blocked_reason.is_some()
                {
                    return Err(DesktopError::InvalidState(
                        "desktop-agent Disconnect retirement has an invalid durable disposition"
                            .to_string(),
                    ));
                }
            }
            DesktopAgentDisconnectPhase::RetirementCancelled => {
                let assertion = self.retire_assertion.as_ref().ok_or_else(|| {
                    DesktopError::InvalidState(
                        "desktop-agent Disconnect cancellation has no exact assertion witness"
                            .to_string(),
                    )
                })?;
                assertion.validate()?;
                if !assertion.pending_disconnect_cleanup
                    || assertion.last_terminal_command_id.as_deref()
                        != Some(self.command_id.as_str())
                    || self.bound_owner_session.is_some()
                    || self.terminal_receipt.is_some()
                    || self.blocked_reason
                        != Some(DesktopAgentDisconnectBlockedReason::CancellationRequested)
                {
                    return Err(DesktopError::InvalidState(
                        "desktop-agent Disconnect cancellation has an invalid durable disposition"
                            .to_string(),
                    ));
                }
            }
            DesktopAgentDisconnectPhase::LocalCleanup | DesktopAgentDisconnectPhase::Reporting => {
                if self.retire_assertion.is_some()
                    || self.bound_owner_session.is_some()
                    || self.terminal_receipt.is_some()
                    || self.blocked_reason.is_some()
                {
                    return Err(DesktopError::InvalidState(
                        "desktop-agent Disconnect cleanup has an invalid durable disposition"
                            .to_string(),
                    ));
                }
            }
            DesktopAgentDisconnectPhase::TerminalAccepted => {
                if self.retire_assertion.is_some()
                    || self.bound_owner_session.is_some()
                    || self.terminal_receipt.is_none()
                    || self.blocked_reason.is_some()
                {
                    return Err(DesktopError::InvalidState(
                        "desktop-agent Disconnect terminal receipt is incomplete".to_string(),
                    ));
                }
            }
            DesktopAgentDisconnectPhase::RetirementBlocked
            | DesktopAgentDisconnectPhase::CompletionBlocked => {
                if self.retire_assertion.is_some()
                    || self.bound_owner_session.is_some()
                    || self.terminal_receipt.is_some()
                    || self.blocked_reason.is_none()
                {
                    return Err(DesktopError::InvalidState(
                        "desktop-agent Disconnect blocked disposition is incomplete".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn requires_capability_retry(&self) -> bool {
        matches!(
            self.phase,
            DesktopAgentDisconnectPhase::RetiringRemote
                | DesktopAgentDisconnectPhase::LocalCleanup
                | DesktopAgentDisconnectPhase::Reporting
                | DesktopAgentDisconnectPhase::TerminalAccepted
                | DesktopAgentDisconnectPhase::RetirementCancelled
                | DesktopAgentDisconnectPhase::RetirementBlocked
                | DesktopAgentDisconnectPhase::CompletionBlocked
        )
    }

    pub fn blocks_new_pairing(&self) -> bool {
        matches!(
            self.phase,
            DesktopAgentDisconnectPhase::RetiringRemote
                | DesktopAgentDisconnectPhase::LocalCleanup
                | DesktopAgentDisconnectPhase::Reporting
                | DesktopAgentDisconnectPhase::RetirementCancelled
                | DesktopAgentDisconnectPhase::RetirementBlocked
        )
    }
}

/// Stable, non-secret OS-store locator for one raw completion capability. The
/// server origin and command ID are domain-separated before hashing so the
/// credential backend never receives a URL-shaped key.
pub fn desktop_agent_disconnect_credential_key(origin: &str, command_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shellx-drive-desktop-agent-disconnect-capability-v1\0");
    hasher.update((origin.len() as u64).to_le_bytes());
    hasher.update(origin.as_bytes());
    hasher.update((command_id.len() as u64).to_le_bytes());
    hasher.update(command_id.as_bytes());
    format!(
        "disconnect-{}",
        crate::hex_digest(hasher.finalize().as_slice())
    )
}
