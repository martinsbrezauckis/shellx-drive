use chrono::Duration;
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    auth::token_hash,
    error::{ApiError, ApiResult},
};

use super::readback_validation::{
    parse_desktop_view_payload, parse_roots_payload, validate_result_bounds,
};
use super::{
    DesktopAgentCommandKind, DesktopAgentCommandPayload, DesktopAgentDeviceAssertion,
    DesktopAgentDeviceRegistration, DesktopAgentResultPayload, DesktopAgentSubmitRequest,
    DesktopAgentSubmitWireRequest, DesktopAgentUpdateAvailability,
};

mod disconnect;
pub use disconnect::{
    validate_disconnect_completion_request, validate_disconnect_retirement_request,
};

pub(super) fn validate_lease_id(lease_id: &str) -> ApiResult<()> {
    opaque_id(lease_id, INVALID_DESKTOP_AGENT_REQUEST)
}

pub const MAX_COMMAND_TTL_SECONDS: i64 = 600;
pub const DEFAULT_COMMAND_TTL_SECONDS: i64 = 300;
pub const MAX_DEVICE_APP_VERSION_BYTES: usize = 128;
pub const MAX_OPAQUE_ID_BYTES: usize = 128;
pub(super) const MAX_NATIVE_REVIEW_ID_BYTES: usize = 4 * 1024;
pub const MAX_FINGERPRINT_BYTES: usize = 128;
pub const MAX_EVENT_SEQUENCE: i64 = 1_000_000_000;
pub const DESKTOP_AGENT_LEASE_SECONDS: i64 = 45;
pub const DESKTOP_AGENT_RELAUNCH_GRACE_SECONDS: i64 = 300;

const INVALID_DESKTOP_AGENT_REQUEST: &str = "invalid_desktop_agent_request";
const INVALID_DESKTOP_AGENT_PAYLOAD: &str = "invalid_desktop_agent_payload";

pub fn parse_submit_request(
    request: DesktopAgentSubmitWireRequest,
) -> ApiResult<DesktopAgentSubmitRequest> {
    canonical_uuid(&request.request_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    if let Some(device_id) = request.device_id.as_deref() {
        opaque_id(device_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    }
    let payload = parse_payload(request.kind, request.payload)?;
    let expires_in_seconds = request
        .expires_in_seconds
        .unwrap_or(DEFAULT_COMMAND_TTL_SECONDS);
    if !(1..=MAX_COMMAND_TTL_SECONDS).contains(&expires_in_seconds) {
        return Err(ApiError::Validation(
            INVALID_DESKTOP_AGENT_REQUEST.to_string(),
        ));
    }
    Ok(DesktopAgentSubmitRequest {
        request_id: request.request_id,
        device_id: request.device_id,
        payload,
        expires_in_seconds,
    })
}
pub fn validate_registration(registration: &DesktopAgentDeviceRegistration) -> ApiResult<()> {
    validate_device_assertion(&registration.assertion())
}
pub fn validate_device_assertion(assertion: &DesktopAgentDeviceAssertion) -> ApiResult<()> {
    app_version(&assertion.app_version)?;
    fingerprint(&assertion.pair_fingerprint)?;
    if let Some(command_id) = assertion.last_terminal_command_id.as_deref() {
        opaque_id(command_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    }
    Ok(())
}

pub fn validate_lease_event(lease_id: &str, sequence: i64) -> ApiResult<()> {
    validate_lease_id(lease_id)?;
    if !(1..=MAX_EVENT_SEQUENCE).contains(&sequence) {
        return Err(ApiError::Validation(
            INVALID_DESKTOP_AGENT_REQUEST.to_string(),
        ));
    }
    Ok(())
}

pub fn validate_result_payload(
    payload: &DesktopAgentCommandPayload,
    result: &DesktopAgentResultPayload,
) -> ApiResult<()> {
    if !result.matches_kind(payload.kind()) {
        return Err(ApiError::Validation(
            INVALID_DESKTOP_AGENT_REQUEST.to_string(),
        ));
    }
    match result {
        DesktopAgentResultPayload::ReviewPrepared {
            pair_id,
            review_id,
            action: _,
            prepared_confirmation_id,
            fingerprint: result_fingerprint,
        } => {
            let pair_id = pair_id
                .as_deref()
                .ok_or_else(|| ApiError::Validation(INVALID_DESKTOP_AGENT_REQUEST.to_string()))?;
            opaque_id(pair_id, INVALID_DESKTOP_AGENT_REQUEST)?;
            native_review_id(review_id, INVALID_DESKTOP_AGENT_REQUEST)?;
            opaque_id(prepared_confirmation_id, INVALID_DESKTOP_AGENT_REQUEST)?;
            fingerprint(result_fingerprint)?;
        }
        DesktopAgentResultPayload::ReviewConfirmed {
            pair_id,
            review_id,
            prepared_confirmation_id,
            fingerprint: result_fingerprint,
            ..
        } => {
            let pair_id = pair_id
                .as_deref()
                .ok_or_else(|| ApiError::Validation(INVALID_DESKTOP_AGENT_REQUEST.to_string()))?;
            opaque_id(pair_id, INVALID_DESKTOP_AGENT_REQUEST)?;
            native_review_id(review_id, INVALID_DESKTOP_AGENT_REQUEST)?;
            opaque_id(prepared_confirmation_id, INVALID_DESKTOP_AGENT_REQUEST)?;
            fingerprint(result_fingerprint)?;
        }
        DesktopAgentResultPayload::UpdateCheck {
            availability,
            candidate_id,
        } => {
            if matches!(
                availability,
                DesktopAgentUpdateAvailability::CandidateAvailable
            ) != candidate_id.is_some()
            {
                return Err(ApiError::Validation(
                    INVALID_DESKTOP_AGENT_REQUEST.to_string(),
                ));
            }
            optional_opaque_id(candidate_id.as_deref())?;
        }
        DesktopAgentResultPayload::UpdateInstall {
            candidate_id,
            installed_version,
        } => {
            opaque_id(candidate_id, INVALID_DESKTOP_AGENT_REQUEST)?;
            app_version(installed_version)?;
        }
        DesktopAgentResultPayload::LocalFolderDispatch { pair_id, .. }
        | DesktopAgentResultPayload::DriveDispatch { pair_id, .. } => {
            optional_opaque_id(pair_id.as_deref())?;
        }
        DesktopAgentResultPayload::PairSelected { pair_id } => {
            opaque_id(pair_id, INVALID_DESKTOP_AGENT_REQUEST)?;
        }
        DesktopAgentResultPayload::RootsRefreshed { workspace_id, .. } => {
            opaque_id(workspace_id, INVALID_DESKTOP_AGENT_REQUEST)?;
        }
        DesktopAgentResultPayload::DesktopView { .. }
        | DesktopAgentResultPayload::Sync { .. }
        | DesktopAgentResultPayload::Pause { .. }
        | DesktopAgentResultPayload::LaunchAtLogin { .. }
        | DesktopAgentResultPayload::Disconnect { .. }
        | DesktopAgentResultPayload::RootsDiscovered { .. }
        | DesktopAgentResultPayload::ServerValidated { .. } => {}
    }
    validate_result_bounds(payload, result)
}

/// Hash the canonical server-generated serialization rather than caller JSON,
/// so equivalent idempotency retries compare exactly after strict parsing.
pub fn payload_hash(payload: &DesktopAgentCommandPayload) -> ApiResult<String> {
    let serialized = serde_json::to_string(payload)
        .map_err(|_| ApiError::Validation(INVALID_DESKTOP_AGENT_PAYLOAD.to_string()))?;
    Ok(token_hash(&format!(
        "desktop-agent-payload-v1\0{serialized}"
    )))
}

pub fn command_expires_at(now: chrono::DateTime<chrono::Utc>, ttl_seconds: i64) -> String {
    (now + Duration::seconds(ttl_seconds)).to_rfc3339()
}

fn parse_payload(
    kind: DesktopAgentCommandKind,
    value: Value,
) -> ApiResult<DesktopAgentCommandPayload> {
    let payload = match kind {
        DesktopAgentCommandKind::DesktopView => parse_desktop_view_payload(value),
        DesktopAgentCommandKind::SyncNow => {
            empty::<EmptyPayload>(value).map(|_| DesktopAgentCommandPayload::SyncNow)
        }
        DesktopAgentCommandKind::RecheckReviews => {
            empty::<EmptyPayload>(value).map(|_| DesktopAgentCommandPayload::RecheckReviews)
        }
        DesktopAgentCommandKind::SetPaused => {
            decode::<SetPausedPayload>(value).map(|value| DesktopAgentCommandPayload::SetPaused {
                paused: value.paused,
            })
        }
        DesktopAgentCommandKind::SetLaunchAtLogin => {
            decode::<SetLaunchAtLoginPayload>(value).map(|value| {
                DesktopAgentCommandPayload::SetLaunchAtLogin {
                    enabled: value.enabled,
                }
            })
        }
        DesktopAgentCommandKind::PrepareReviewAction => decode::<PrepareReviewPayload>(value)
            .and_then(|value| {
                native_review_id(&value.review_id, INVALID_DESKTOP_AGENT_PAYLOAD)
                    .map_err(|_| ())?;
                opaque_id(&value.pair_id, INVALID_DESKTOP_AGENT_PAYLOAD).map_err(|_| ())?;
                Ok(DesktopAgentCommandPayload::PrepareReviewAction {
                    pair_id: Some(value.pair_id),
                    review_id: value.review_id,
                    action: value.action,
                })
            }),
        DesktopAgentCommandKind::ConfirmReviewAction => decode::<ConfirmReviewPayload>(value)
            .and_then(|value| {
                native_review_id(&value.review_id, INVALID_DESKTOP_AGENT_PAYLOAD)
                    .map_err(|_| ())?;
                opaque_id(&value.pair_id, INVALID_DESKTOP_AGENT_PAYLOAD).map_err(|_| ())?;
                opaque_id(
                    &value.prepared_confirmation_id,
                    INVALID_DESKTOP_AGENT_PAYLOAD,
                )
                .map_err(|_| ())?;
                fingerprint(&value.fingerprint).map_err(|_| ())?;
                Ok(DesktopAgentCommandPayload::ConfirmReviewAction {
                    pair_id: Some(value.pair_id),
                    review_id: value.review_id,
                    action: value.action,
                    prepared_confirmation_id: value.prepared_confirmation_id,
                    fingerprint: value.fingerprint,
                })
            }),
        DesktopAgentCommandKind::CheckDesktopUpdate => {
            empty::<EmptyPayload>(value).map(|_| DesktopAgentCommandPayload::CheckDesktopUpdate)
        }
        DesktopAgentCommandKind::InstallDesktopUpdate => decode::<InstallUpdatePayload>(value)
            .and_then(|value| {
                opaque_id(&value.candidate_id, INVALID_DESKTOP_AGENT_PAYLOAD).map_err(|_| ())?;
                Ok(DesktopAgentCommandPayload::InstallDesktopUpdate {
                    candidate_id: value.candidate_id,
                })
            }),
        DesktopAgentCommandKind::Disconnect => {
            empty::<EmptyPayload>(value).map(|_| DesktopAgentCommandPayload::Disconnect)
        }
        DesktopAgentCommandKind::OpenLocalFolder => {
            decode::<OptionalPairPayload>(value).and_then(|value| {
                optional_opaque_id(value.pair_id.as_deref()).map_err(|_| ())?;
                Ok(DesktopAgentCommandPayload::OpenLocalFolder {
                    pair_id: value.pair_id,
                })
            })
        }
        DesktopAgentCommandKind::OpenDrive => {
            decode::<OptionalPairPayload>(value).and_then(|value| {
                optional_opaque_id(value.pair_id.as_deref()).map_err(|_| ())?;
                Ok(DesktopAgentCommandPayload::OpenDrive {
                    pair_id: value.pair_id,
                })
            })
        }
        DesktopAgentCommandKind::DiscoverRoots => parse_roots_payload(value),
        DesktopAgentCommandKind::StartPair => decode::<StartPairPayload>(value).and_then(|value| {
            opaque_id(&value.workspace_id, INVALID_DESKTOP_AGENT_PAYLOAD).map_err(|_| ())?;
            Ok(DesktopAgentCommandPayload::StartPair {
                workspace_id: value.workspace_id,
            })
        }),
        DesktopAgentCommandKind::SelectPair => {
            decode::<SelectPairPayload>(value).and_then(|value| {
                opaque_id(&value.pair_id, INVALID_DESKTOP_AGENT_PAYLOAD).map_err(|_| ())?;
                Ok(DesktopAgentCommandPayload::SelectPair {
                    pair_id: value.pair_id,
                })
            })
        }
        DesktopAgentCommandKind::ValidateServer => {
            empty::<EmptyPayload>(value).map(|_| DesktopAgentCommandPayload::ValidateServer)
        }
        DesktopAgentCommandKind::ContinueLogin => {
            empty::<EmptyPayload>(value).map(|_| DesktopAgentCommandPayload::ContinueLogin)
        }
        DesktopAgentCommandKind::ContinueMfa => {
            empty::<EmptyPayload>(value).map(|_| DesktopAgentCommandPayload::ContinueMfa)
        }
    };
    payload.map_err(|_| ApiError::Validation(INVALID_DESKTOP_AGENT_PAYLOAD.to_string()))
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, ()> {
    serde_json::from_value(value).map_err(|_| ())
}

fn empty<T: DeserializeOwned>(value: Value) -> Result<T, ()> {
    decode(value)
}

fn canonical_uuid(value: &str, code: &str) -> ApiResult<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| ApiError::Validation(code.to_string()))?;
    if parsed.hyphenated().to_string() != value {
        return Err(ApiError::Validation(code.to_string()));
    }
    Ok(())
}

fn app_version(value: &str) -> ApiResult<()> {
    if value.is_empty() || value.len() > MAX_DEVICE_APP_VERSION_BYTES || !value.is_ascii() {
        return Err(ApiError::Validation(
            INVALID_DESKTOP_AGENT_REQUEST.to_string(),
        ));
    }
    Ok(())
}

fn fingerprint(value: &str) -> ApiResult<()> {
    if value.len() != 64
        || value.len() > MAX_FINGERPRINT_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ApiError::Validation(
            INVALID_DESKTOP_AGENT_REQUEST.to_string(),
        ));
    }
    Ok(())
}

fn optional_opaque_id(value: Option<&str>) -> ApiResult<()> {
    if let Some(value) = value {
        opaque_id(value, INVALID_DESKTOP_AGENT_PAYLOAD)?;
    }
    Ok(())
}

/// A native planner lookup key, not a path or authority-bearing opaque ID.
pub(super) fn native_review_id(value: &str, code: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > MAX_NATIVE_REVIEW_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ApiError::Validation(code.to_string()));
    }
    Ok(())
}

fn opaque_id(value: &str, code: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(ApiError::Validation(code.to_string()));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPausedPayload {
    paused: bool,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetLaunchAtLoginPayload {
    enabled: bool,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareReviewPayload {
    pair_id: String,
    review_id: String,
    action: super::DesktopAgentReviewAction,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmReviewPayload {
    pair_id: String,
    review_id: String,
    action: super::DesktopAgentReviewAction,
    prepared_confirmation_id: String,
    fingerprint: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallUpdatePayload {
    candidate_id: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionalPairPayload {
    #[serde(default)]
    pair_id: Option<String>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StartPairPayload {
    workspace_id: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectPairPayload {
    pair_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop_agent::{DesktopAgentCommandKind, DesktopAgentSubmitWireRequest};
    use serde_json::json;

    fn request(kind: DesktopAgentCommandKind, payload: Value) -> DesktopAgentSubmitWireRequest {
        DesktopAgentSubmitWireRequest {
            request_id: "9f4f46c9-56af-4e59-8df9-361274a28150".to_string(),
            device_id: Some("device_01".to_string()),
            kind,
            payload,
            expires_in_seconds: Some(60),
        }
    }

    #[test]
    fn strict_payload_parser_rejects_extra_and_path_fields() {
        assert!(parse_submit_request(request(
            DesktopAgentCommandKind::SyncNow,
            json!({"path":"C:/"})
        ))
        .is_err());
        assert!(parse_submit_request(request(
            DesktopAgentCommandKind::PrepareReviewAction,
            json!({"review_id":"review_01"})
        ))
        .is_err());
        assert!(parse_submit_request(request(
            DesktopAgentCommandKind::PrepareReviewAction,
            json!({"review_id":"review_01", "action":"remove_local_copy"})
        ))
        .is_err());
        assert!(parse_submit_request(request(
            DesktopAgentCommandKind::ValidateServer,
            json!({"server_origin":"https://elsewhere.test"})
        ))
        .is_err());
    }

    #[test]
    fn stale_lease_only_replays_observation_actions() {
        assert!(DesktopAgentCommandKind::DesktopView.lease_replay_safe());
        assert!(DesktopAgentCommandKind::CheckDesktopUpdate.lease_replay_safe());
        assert!(!DesktopAgentCommandKind::Disconnect.lease_replay_safe());
        assert!(!DesktopAgentCommandKind::ConfirmReviewAction.lease_replay_safe());
    }

    #[test]
    fn same_typed_payload_has_stable_idempotency_hash() {
        let first = parse_submit_request(request(
            DesktopAgentCommandKind::SetPaused,
            json!({"paused":true}),
        ))
        .unwrap();
        let second = parse_submit_request(request(
            DesktopAgentCommandKind::SetPaused,
            json!({"paused":true}),
        ))
        .unwrap();
        assert_eq!(
            payload_hash(&first.payload).unwrap(),
            payload_hash(&second.payload).unwrap()
        );
    }
}
