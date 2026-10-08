//! Raw-credential-safe claim decoding for the one outbound broker lease.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer};

use crate::{DesktopError, Result};

use super::super::ensure_opaque_id;
use super::{
    DesktopAgentClaimPayload, DesktopAgentCommand, DesktopAgentCommandKind,
    DISCONNECT_COMPLETION_CREDENTIAL_PREFIX, MAX_AGENT_DEVICE_CREDENTIAL_BYTES,
};

/// A short-lived, non-secret broker lease. The Disconnect completion
/// capability is the sole raw credential and deliberately has no `Debug`.
pub struct DesktopAgentClaim {
    pub command_id: String,
    pub lease_id: String,
    pub lease_expires_at: DateTime<Utc>,
    pub disconnect_completion_expires_at: Option<DateTime<Utc>>,
    pub kind: DesktopAgentCommandKind,
    pub payload: DesktopAgentClaimPayload,
    pub disconnect_completion_capability: Option<String>,
}

#[derive(Deserialize)]
struct ClaimWire {
    command_id: String,
    lease_id: String,
    lease_expires_at: DateTime<Utc>,
    #[serde(default)]
    disconnect_completion_expires_at: Option<DateTime<Utc>>,
    kind: DesktopAgentCommandKind,
    payload: serde_json::Value,
    #[serde(default)]
    disconnect_completion_capability: Option<String>,
}

impl<'de> Deserialize<'de> for DesktopAgentClaim {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ClaimWire::deserialize(deserializer)?;
        let payload = DesktopAgentClaimPayload::decode(wire.kind, wire.payload)
            .map_err(|error| <D::Error as serde::de::Error>::custom(error.to_string()))?;
        validate_disconnect_completion_capability(
            wire.kind,
            wire.disconnect_completion_capability.as_deref(),
        )
        .map_err(|error| <D::Error as serde::de::Error>::custom(error.to_string()))?;
        validate_disconnect_completion_expiry(wire.kind, wire.disconnect_completion_expires_at)
            .map_err(|error| <D::Error as serde::de::Error>::custom(error.to_string()))?;
        Ok(Self {
            command_id: wire.command_id,
            lease_id: wire.lease_id,
            lease_expires_at: wire.lease_expires_at,
            disconnect_completion_expires_at: wire.disconnect_completion_expires_at,
            kind: wire.kind,
            payload,
            disconnect_completion_capability: wire.disconnect_completion_capability,
        })
    }
}

impl DesktopAgentClaim {
    pub fn parse_command(&self) -> Result<DesktopAgentCommand> {
        ensure_opaque_id("desktop-agent command ID", &self.command_id)?;
        ensure_opaque_id("desktop-agent lease ID", &self.lease_id)?;
        self.payload.clone().parse(self.kind)
    }
}

fn validate_disconnect_completion_expiry(
    kind: DesktopAgentCommandKind,
    expiry: Option<DateTime<Utc>>,
) -> Result<()> {
    match (kind, expiry) {
        (DesktopAgentCommandKind::Disconnect, Some(expiry)) if expiry > Utc::now() => Ok(()),
        (DesktopAgentCommandKind::Disconnect, _) => Err(DesktopError::InvalidState(
            "desktop-agent Disconnect claim has no valid completion deadline".to_string(),
        )),
        (_, None) => Ok(()),
        (_, Some(_)) => Err(DesktopError::InvalidState(
            "desktop-agent claim supplied a Disconnect completion deadline for another command"
                .to_string(),
        )),
    }
}

pub fn validate_disconnect_completion_capability(
    kind: DesktopAgentCommandKind,
    capability: Option<&str>,
) -> Result<()> {
    match (kind, capability) {
        (DesktopAgentCommandKind::Disconnect, Some(value))
            if value.starts_with(DISCONNECT_COMPLETION_CREDENTIAL_PREFIX)
                && value.len() <= MAX_AGENT_DEVICE_CREDENTIAL_BYTES
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) =>
        {
            Ok(())
        }
        (DesktopAgentCommandKind::Disconnect, _) => Err(DesktopError::InvalidState(
            "desktop-agent Disconnect claim has no valid completion capability".to_string(),
        )),
        (_, None) => Ok(()),
        (_, Some(_)) => Err(DesktopError::InvalidState(
            "desktop-agent claim supplied a Disconnect capability for another command".to_string(),
        )),
    }
}
