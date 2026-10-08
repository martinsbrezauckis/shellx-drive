//! Capability-bounded terminal transport for an agent-owned Disconnect.

use reqwest::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{DesktopAgentDeviceAssertion, DesktopError};

use super::super::{CycleBudgetedRequest, DriveHttpClient};

const MAX_DISCONNECT_ERROR_BYTES: usize = 1024;

/// Fixed broker dispositions that may be acted on without exposing an HTTP
/// response body to the application or durable state.
#[derive(Debug)]
pub enum DesktopAgentDisconnectTransportError {
    CancellationRequested,
    CapabilityExpired,
    AuthorizationLost,
    Other(DesktopError),
}

impl DesktopAgentDisconnectTransportError {
    pub fn into_core_error(self) -> DesktopError {
        match self {
            Self::CancellationRequested => DesktopError::InvalidState(
                "desktop-agent Disconnect cancellation was requested".to_string(),
            ),
            Self::CapabilityExpired => DesktopError::InvalidState(
                "desktop-agent Disconnect completion capability expired".to_string(),
            ),
            Self::AuthorizationLost => DesktopError::InvalidState(
                "desktop-agent Disconnect completion authorization was lost".to_string(),
            ),
            Self::Other(error) => error,
        }
    }
}

impl DriveHttpClient {
    /// Retire only the claimed device-owner session after the local cleanup
    /// intent and exact assertion witness are durable. The raw completion
    /// capability authenticates both the first request and an exact retry
    /// after that retirement invalidates the normal device credential.
    pub async fn retire_desktop_agent_disconnect(
        &self,
        completion_capability: &str,
        command_id: &str,
        lease_id: &str,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> std::result::Result<(), DesktopAgentDisconnectTransportError> {
        assertion
            .validate()
            .map_err(DesktopAgentDisconnectTransportError::Other)?;
        let response = self
            .authorized(
                Method::POST,
                &self
                    .desktop_agent_command_path(command_id, "disconnect-retire")
                    .map_err(DesktopAgentDisconnectTransportError::Other)?,
                completion_capability,
            )
            .json(&DisconnectRetireRequest {
                lease_id,
                assertion,
            })
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await
            .map_err(DesktopAgentDisconnectTransportError::Other)?;
        decode_disconnect_response(response).await
    }

    /// Finish only an already-retired Disconnect. The raw completion
    /// capability is distinct from both the device credential and owner
    /// bearer, so this works after the paired session was deliberately
    /// removed. Cancellation is explicit and never aliases a success.
    pub async fn complete_desktop_agent_disconnect(
        &self,
        completion_capability: &str,
        command_id: &str,
        lease_id: &str,
        event_sequence: u64,
        cancelled: bool,
    ) -> std::result::Result<(), DesktopAgentDisconnectTransportError> {
        let response = self
            .authorized(
                Method::POST,
                &self
                    .desktop_agent_command_path(command_id, "disconnect-complete")
                    .map_err(DesktopAgentDisconnectTransportError::Other)?,
                completion_capability,
            )
            .json(&DisconnectCompleteRequest {
                lease_id,
                event_sequence,
                cancelled: cancelled.then_some(true),
            })
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await
            .map_err(DesktopAgentDisconnectTransportError::Other)?;
        decode_disconnect_response(response).await
    }
}

async fn decode_disconnect_response(
    response: Response,
) -> std::result::Result<(), DesktopAgentDisconnectTransportError> {
    if response.status().is_success() {
        return Ok(());
    }
    if response.status() != StatusCode::CONFLICT {
        return Err(DesktopAgentDisconnectTransportError::Other(
            DesktopError::Server {
                status: response.status().as_u16(),
                message: "desktop-agent Disconnect transport was rejected".to_string(),
            },
        ));
    }
    let code = decode_disconnect_error_code(response).await?;
    match code.as_deref() {
        Some("desktop_agent_cancellation_requested") => {
            Err(DesktopAgentDisconnectTransportError::CancellationRequested)
        }
        Some("desktop_agent_disconnect_capability_expired") => {
            Err(DesktopAgentDisconnectTransportError::CapabilityExpired)
        }
        Some("desktop_agent_disconnect_authorization_lost") => {
            Err(DesktopAgentDisconnectTransportError::AuthorizationLost)
        }
        _ => Err(DesktopAgentDisconnectTransportError::Other(
            DesktopError::Server {
                status: StatusCode::CONFLICT.as_u16(),
                message: "desktop-agent Disconnect completion conflicted".to_string(),
            },
        )),
    }
}

async fn decode_disconnect_error_code(
    mut response: Response,
) -> std::result::Result<Option<String>, DesktopAgentDisconnectTransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DISCONNECT_ERROR_BYTES as u64)
    {
        return Err(DesktopAgentDisconnectTransportError::Other(
            DesktopError::InvalidState(
                "desktop-agent Disconnect error response exceeds its bounded decoder".to_string(),
            ),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(DesktopError::from)
        .map_err(DesktopAgentDisconnectTransportError::Other)?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > MAX_DISCONNECT_ERROR_BYTES)
        {
            return Err(DesktopAgentDisconnectTransportError::Other(
                DesktopError::InvalidState(
                    "desktop-agent Disconnect error response exceeds its bounded decoder"
                        .to_string(),
                ),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = serde_json::from_slice::<DisconnectErrorBody>(&bytes)
        .map_err(DesktopError::from)
        .map_err(DesktopAgentDisconnectTransportError::Other)?;
    Ok(Some(body.error))
}

#[derive(Deserialize)]
struct DisconnectErrorBody {
    error: String,
}

#[derive(Serialize)]
struct DisconnectRetireRequest<'a> {
    lease_id: &'a str,
    assertion: &'a DesktopAgentDeviceAssertion,
}

#[derive(Serialize)]
struct DisconnectCompleteRequest<'a> {
    lease_id: &'a str,
    event_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cancelled: Option<bool>,
}
