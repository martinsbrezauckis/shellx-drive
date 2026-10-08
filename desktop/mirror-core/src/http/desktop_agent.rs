//! HTTP adapter for the outbound desktop-agent broker.
//!
//! This is a child of `http.rs` so it reuses its bounded decoder and private
//! request construction. It provides only fixed, device-pulled broker calls;
//! no inbound listener or arbitrary action endpoint is introduced.

use chrono::Utc;
use reqwest::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};

use super::{require_success, CycleBudgetedRequest, DriveHttpClient};
use crate::{
    DesktopAgentClaim, DesktopAgentDeviceAssertion, DesktopAgentPlatform,
    DesktopAgentProgressPhase, DesktopAgentRegistration, DesktopAgentResultCode,
    DesktopAgentResultPayload, DesktopAgentTerminalCode, DesktopAgentTerminalStatus, DesktopError,
    Result,
};

#[path = "desktop_agent/disconnect.rs"]
mod disconnect;
pub use disconnect::DesktopAgentDisconnectTransportError;

/// Fixed normal-device command-event outcomes which may change the durable
/// generic command journal. This is intentionally separate from Disconnect's
/// capability transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopAgentCommandEventDisposition {
    Accepted,
    CancellationRequested,
}

/// One persisted, idempotent progress report. Keeping its authoritative
/// fields together prevents a retry from accidentally combining a new phase
/// or sequence with an older assertion.
pub struct DesktopAgentProgressReport<'a> {
    pub command_id: &'a str,
    pub lease_id: &'a str,
    pub event_sequence: u64,
    pub assertion: &'a DesktopAgentDeviceAssertion,
    pub phase: DesktopAgentProgressPhase,
    pub progress_basis_points: Option<u16>,
}

/// One persisted, idempotent terminal report. Successful results remain
/// attached to their original terminal sequence for response-loss retries.
pub struct DesktopAgentTerminalReport<'a> {
    pub command_id: &'a str,
    pub lease_id: &'a str,
    pub event_sequence: u64,
    pub assertion: &'a DesktopAgentDeviceAssertion,
    pub status: DesktopAgentTerminalStatus,
    pub terminal_code: DesktopAgentTerminalCode,
    pub result_code: Option<DesktopAgentResultCode>,
    pub result: Option<&'a DesktopAgentResultPayload>,
}

impl DriveHttpClient {
    /// Register only after a signed-in person has explicitly enabled device
    /// control in the native UI. The returned secret must be written to the
    /// platform's separate credential service before state records `device_id`.
    pub async fn register_desktop_agent_device(
        &self,
        owner_bearer: &str,
        platform: DesktopAgentPlatform,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> Result<DesktopAgentRegistration> {
        assertion.validate()?;
        let response = self
            .authorized(
                Method::POST,
                "/desktop-agent/devices/register",
                owner_bearer,
            )
            .json(&RegisterDeviceRequest {
                platform,
                assertion,
            })
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let registration: DesktopAgentRegistration = self
            .decode_success_json(response, "desktop-agent registration")
            .await?;
        registration.validate()?;
        Ok(registration)
    }

    /// Claim zero or one typed action through a bounded outbound request.
    /// `None` is an explicit idle poll and never an implicit local success.
    pub async fn claim_desktop_agent_command(
        &self,
        device_id: &str,
        device_credential: &str,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> Result<Option<DesktopAgentClaim>> {
        assertion.validate()?;
        let response = self
            .authorized(
                Method::POST,
                &self.desktop_agent_device_path(device_id, "claim")?,
                device_credential,
            )
            .json(&DeviceAssertionRequest { assertion })
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response: ClaimResponse = self
            .decode_success_json(response, "desktop-agent claim")
            .await?;
        if let Some(claim) = &response.claim {
            claim.parse_command()?;
            if claim.lease_expires_at <= Utc::now() {
                return Err(DesktopError::InvalidState(
                    "desktop-agent claim lease is already expired".to_string(),
                ));
            }
        }
        Ok(response.claim)
    }

    pub async fn heartbeat_desktop_agent_device(
        &self,
        device_id: &str,
        device_credential: &str,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> Result<()> {
        assertion.validate()?;
        self.send_device_assertion(device_id, "heartbeat", device_credential, assertion)
            .await
    }

    pub async fn acknowledge_desktop_agent_command(
        &self,
        device_credential: &str,
        command_id: &str,
        lease_id: &str,
        event_sequence: u64,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> Result<()> {
        assertion.validate()?;
        self.send_command_event(
            device_credential,
            command_id,
            CommandEventRequest::Acknowledgement {
                lease_id,
                event_sequence,
                assertion,
            },
            "acknowledge",
        )
        .await
    }

    pub async fn report_desktop_agent_progress(
        &self,
        device_credential: &str,
        report: DesktopAgentProgressReport<'_>,
    ) -> Result<()> {
        report.assertion.validate()?;
        self.send_command_event(
            device_credential,
            report.command_id,
            CommandEventRequest::from(report),
            "progress",
        )
        .await
    }

    /// Retry a persisted normal-device progress event while recognizing the
    /// one broker disposition that replaces its reserved slot with a
    /// cancellation terminal.
    pub async fn report_desktop_agent_progress_with_disposition(
        &self,
        device_credential: &str,
        report: DesktopAgentProgressReport<'_>,
    ) -> Result<DesktopAgentCommandEventDisposition> {
        report.assertion.validate()?;
        let response = self
            .authorized(
                Method::POST,
                &self.desktop_agent_command_path(report.command_id, "progress")?,
                device_credential,
            )
            .json(&CommandEventRequest::from(report))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        decode_desktop_agent_command_event_response(response).await
    }

    pub async fn report_desktop_agent_terminal(
        &self,
        device_credential: &str,
        report: DesktopAgentTerminalReport<'_>,
    ) -> Result<()> {
        report.assertion.validate()?;
        self.send_command_event(
            device_credential,
            report.command_id,
            CommandEventRequest::from(report),
            "terminal",
        )
        .await
    }

    /// Retry a previously persisted normal-device terminal report while
    /// recognizing the one server disposition that requires replacing a
    /// locally pending result. The response body is never surfaced to the
    /// caller or stored in the journal.
    pub async fn report_desktop_agent_terminal_with_disposition(
        &self,
        device_credential: &str,
        report: DesktopAgentTerminalReport<'_>,
    ) -> Result<DesktopAgentCommandEventDisposition> {
        report.assertion.validate()?;
        let response = self
            .authorized(
                Method::POST,
                &self.desktop_agent_command_path(report.command_id, "terminal")?,
                device_credential,
            )
            .json(&CommandEventRequest::from(report))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        decode_desktop_agent_command_event_response(response).await
    }

    /// A disabled local preference must retire the exact device before the
    /// platform deletes the separate device secret. This endpoint authenticates
    /// as the device itself so owner bearer leakage cannot retire another PC.
    pub async fn retire_desktop_agent_device(
        &self,
        device_id: &str,
        device_credential: &str,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> Result<()> {
        self.send_device_assertion(device_id, "retire", device_credential, assertion)
            .await
    }

    /// Owner-authenticated local disable/recovery path. The server rechecks
    /// same-owner authority and rejects/cancels unstarted work before local
    /// credential removal can continue.
    pub async fn revoke_desktop_agent_device(
        &self,
        device_id: &str,
        owner_bearer: &str,
    ) -> Result<()> {
        let response = self
            .authorized(
                Method::POST,
                &self.desktop_agent_device_path(device_id, "revoke")?,
                owner_bearer,
            )
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        require_success(response).await.map(|_| ())
    }

    /// Confirm an externally revoked exact device with the current owner's
    /// active source credential. A device-bearer authentication failure alone
    /// is not enough to clear local enrollment: it can also mean that the
    /// owner session or connectivity needs attention.
    pub async fn owner_confirms_desktop_agent_device_revoked(
        &self,
        owner_bearer: &str,
        device_id: &str,
    ) -> Result<bool> {
        bounded_route_id("desktop-agent device ID", device_id)?;
        let response = self
            .authorized(Method::GET, "/desktop-agent/devices", owner_bearer)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response: OwnerDeviceListResponse = self
            .decode_success_json(response, "desktop-agent device list")
            .await?;
        exact_device_is_revoked(response, device_id)
    }

    async fn send_device_assertion(
        &self,
        device_id: &str,
        operation: &str,
        device_credential: &str,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> Result<()> {
        assertion.validate()?;
        let response = self
            .authorized(
                Method::POST,
                &self.desktop_agent_device_path(device_id, operation)?,
                device_credential,
            )
            .json(&DeviceAssertionRequest { assertion })
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        require_success(response).await.map(|_| ())
    }

    async fn send_command_event(
        &self,
        device_credential: &str,
        command_id: &str,
        event: CommandEventRequest<'_>,
        endpoint: &str,
    ) -> Result<()> {
        let response = self
            .authorized(
                Method::POST,
                &self.desktop_agent_command_path(command_id, endpoint)?,
                device_credential,
            )
            .json(&event)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        require_success(response).await.map(|_| ())
    }

    fn desktop_agent_device_path(&self, device_id: &str, operation: &str) -> Result<String> {
        bounded_route_id("desktop-agent device ID", device_id)?;
        bounded_route_segment("desktop-agent device operation", operation)?;
        Ok(format!("/desktop-agent/devices/{device_id}/{operation}"))
    }

    fn desktop_agent_command_path(&self, command_id: &str, operation: &str) -> Result<String> {
        bounded_route_id("desktop-agent command ID", command_id)?;
        bounded_route_segment("desktop-agent command operation", operation)?;
        Ok(format!("/desktop-agent/commands/{command_id}/{operation}"))
    }
}

#[derive(Serialize)]
struct RegisterDeviceRequest<'a> {
    platform: DesktopAgentPlatform,
    #[serde(flatten)]
    assertion: &'a DesktopAgentDeviceAssertion,
}

#[derive(Serialize)]
struct DeviceAssertionRequest<'a> {
    #[serde(flatten)]
    assertion: &'a DesktopAgentDeviceAssertion,
}

#[derive(Deserialize)]
struct ClaimResponse {
    claim: Option<DesktopAgentClaim>,
}

const MAX_OWNER_DEVICE_READBACKS: usize = 50;

#[derive(Deserialize)]
struct OwnerDeviceListResponse {
    devices: Vec<OwnerDeviceReadback>,
}

#[derive(Deserialize)]
struct OwnerDeviceReadback {
    id: String,
    state: OwnerDeviceState,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnerDeviceState {
    Active,
    Frozen,
    Retired,
    Revoked,
}

fn exact_device_is_revoked(response: OwnerDeviceListResponse, device_id: &str) -> Result<bool> {
    if response.devices.len() > MAX_OWNER_DEVICE_READBACKS {
        return Err(DesktopError::InvalidState(
            "desktop-agent device list exceeds its bounded limit".to_string(),
        ));
    }
    let mut matching_state = None;
    for device in response.devices {
        bounded_route_id("desktop-agent device readback ID", &device.id)?;
        if device.id == device_id && matching_state.replace(device.state).is_some() {
            return Err(DesktopError::InvalidState(
                "desktop-agent device list contains a duplicate device ID".to_string(),
            ));
        }
    }
    Ok(matches!(matching_state, Some(OwnerDeviceState::Revoked)))
}

#[derive(Serialize)]
#[serde(untagged)]
enum CommandEventRequest<'a> {
    Acknowledgement {
        lease_id: &'a str,
        event_sequence: u64,
        assertion: &'a DesktopAgentDeviceAssertion,
    },
    Progress {
        lease_id: &'a str,
        event_sequence: u64,
        assertion: &'a DesktopAgentDeviceAssertion,
        phase: DesktopAgentProgressPhase,
        #[serde(skip_serializing_if = "Option::is_none")]
        progress_basis_points: Option<u16>,
    },
    Terminal {
        lease_id: &'a str,
        event_sequence: u64,
        assertion: &'a DesktopAgentDeviceAssertion,
        status: DesktopAgentTerminalStatus,
        terminal_code: DesktopAgentTerminalCode,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_code: Option<DesktopAgentResultCode>,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<DesktopAgentResultPayload>,
    },
}

impl<'a> From<DesktopAgentProgressReport<'a>> for CommandEventRequest<'a> {
    fn from(report: DesktopAgentProgressReport<'a>) -> Self {
        Self::Progress {
            lease_id: report.lease_id,
            event_sequence: report.event_sequence,
            assertion: report.assertion,
            phase: report.phase,
            progress_basis_points: report.progress_basis_points,
        }
    }
}

impl<'a> From<DesktopAgentTerminalReport<'a>> for CommandEventRequest<'a> {
    fn from(report: DesktopAgentTerminalReport<'a>) -> Self {
        Self::Terminal {
            lease_id: report.lease_id,
            event_sequence: report.event_sequence,
            assertion: report.assertion,
            status: report.status,
            terminal_code: report.terminal_code,
            result_code: report.result_code,
            result: report.result.cloned(),
        }
    }
}

const MAX_DESKTOP_AGENT_COMMAND_EVENT_ERROR_BYTES: usize = 1024;
const DESKTOP_AGENT_CANCELLATION_REQUESTED: &str = "desktop_agent_cancellation_requested";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopAgentCommandEventConflictBody {
    error: String,
    #[serde(rename = "message", default)]
    _message: Option<String>,
}

async fn decode_desktop_agent_command_event_response(
    mut response: Response,
) -> Result<DesktopAgentCommandEventDisposition> {
    if response.status().is_success() {
        return Ok(DesktopAgentCommandEventDisposition::Accepted);
    }
    if response.status() != StatusCode::CONFLICT {
        return require_success(response)
            .await
            .map(|_| DesktopAgentCommandEventDisposition::Accepted);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DESKTOP_AGENT_COMMAND_EVENT_ERROR_BYTES as u64)
    {
        return Err(generic_command_event_conflict());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > MAX_DESKTOP_AGENT_COMMAND_EVENT_ERROR_BYTES)
        {
            return Err(generic_command_event_conflict());
        }
        bytes.extend_from_slice(&chunk);
    }
    if is_cancellation_command_event_conflict(&bytes) {
        Ok(DesktopAgentCommandEventDisposition::CancellationRequested)
    } else {
        Err(generic_command_event_conflict())
    }
}

fn is_cancellation_command_event_conflict(body: &[u8]) -> bool {
    if body.len() > MAX_DESKTOP_AGENT_COMMAND_EVENT_ERROR_BYTES {
        return false;
    }
    serde_json::from_slice::<DesktopAgentCommandEventConflictBody>(body)
        .map(|body| body.error == DESKTOP_AGENT_CANCELLATION_REQUESTED)
        .unwrap_or(false)
}

fn generic_command_event_conflict() -> DesktopError {
    DesktopError::Server {
        status: StatusCode::CONFLICT.as_u16(),
        message: "desktop-agent command event conflicted".to_string(),
    }
}

fn bounded_route_id(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DesktopError::InvalidState(format!(
            "{label} must be a bounded opaque identifier"
        )));
    }
    Ok(())
}

fn bounded_route_segment(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        return Err(DesktopError::InvalidState(format!(
            "{label} must be a fixed lowercase route segment"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "desktop_agent/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "desktop_agent/cancellation_tests.rs"]
mod cancellation_tests;
