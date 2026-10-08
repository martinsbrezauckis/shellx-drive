//! Admission and bounded delivery for bulk authenticated metadata JSON.

use std::{
    io::{self, Write},
    time::Duration,
};

use axum::{
    body::Body,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::{
    error::{ApiError, ApiResult},
    routes::blob_response::guard_bounded_bytes_response_with_total_deadline,
    server::{AppState, PartitionedPermit},
};

const MAX_METADATA_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

struct LimitedJson {
    bytes: Vec<u8>,
    exceeded: bool,
    limit: usize,
}

impl Write for LimitedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("metadata response byte limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_limited<T: Serialize>(value: &T, limit: usize) -> ApiResult<Vec<u8>> {
    let mut writer = LimitedJson {
        bytes: Vec::new(),
        exceeded: false,
        limit,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.exceeded {
            return Err(ApiError::PayloadTooLarge(format!(
                "metadata response exceeds {limit} bytes"
            )));
        }
        return Err(ApiError::Io(io::Error::other(error)));
    }
    Ok(writer.bytes)
}

pub(crate) fn guarded_metadata_json<T: Serialize>(
    state: &AppState,
    actor_email: &str,
    planning_capability: &str,
    value: impl FnOnce() -> T,
) -> ApiResult<Response> {
    // The planning lane also caps the number of encoded bodies held by slow
    // clients. Acquire it before serialization, then move both permits into
    // the bounded producer until delivery or its backpressure deadline.
    let planning_permit = state.try_metadata_planning(planning_capability)?;
    guarded_metadata_json_with_permit(state, actor_email, planning_permit, value, || Ok(()))
}

pub(crate) fn guarded_metadata_json_with_permit<T: Serialize>(
    state: &AppState,
    actor_email: &str,
    planning_permit: PartitionedPermit,
    value: impl FnOnce() -> T,
    terminal_authorization: impl FnOnce() -> ApiResult<()>,
) -> ApiResult<Response> {
    guarded_metadata_json_with_limit_and_permit(
        state,
        actor_email,
        planning_permit,
        MAX_METADATA_RESPONSE_BYTES,
        value,
        terminal_authorization,
    )
}

pub(crate) fn guarded_metadata_json_with_limit_and_permit<T: Serialize>(
    state: &AppState,
    actor_email: &str,
    planning_permit: PartitionedPermit,
    max_encoded_bytes: usize,
    value: impl FnOnce() -> T,
    terminal_authorization: impl FnOnce() -> ApiResult<()>,
) -> ApiResult<Response> {
    let stream_permit = state.try_authenticated_body_stream(actor_email)?;
    let encoded = encode_limited(&value(), max_encoded_bytes)?;
    terminal_authorization()?;
    let mut response = Body::empty().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&encoded.len().to_string())
            .map_err(|error| ApiError::Io(io::Error::other(error)))?,
    );
    Ok(guard_bounded_bytes_response_with_total_deadline(
        response,
        encoded,
        (planning_permit, stream_permit),
        Duration::from_secs(10 * 60),
    ))
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::header};

    use crate::config::{Config, PublicOrigin};

    use super::*;

    fn test_state(data_dir: std::path::PathBuf) -> AppState {
        AppState::open(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir,
            token: "test-token".to_string(),
            bootstrap_token: None,
            e2e_enabled: true,
            email_transport: "capture".to_string(),
            email_from: "ShellX Drive <noreply@example.test>".to_string(),
            public_origin: PublicOrigin::parse("http://127.0.0.1").unwrap(),
            email_smtp_host_source: "not_configured".to_string(),
            email_smtp_port: None,
            email_smtp_user_source: "not_configured".to_string(),
            maintenance_token_source: "not_configured".to_string(),
            maintenance_sudo_source: "not_configured".to_string(),
            local_session_ttl_seconds: 2_592_000,
            office_provider_name: "Office editor".to_string(),
            office_provider_url: None,
            office_session_ttl_seconds: 900,
            hosted_mode: false,
            hosted_billing_provider: "none".to_string(),
            hosted_public_rate_limit_per_minute: 60,
            backup_max_archive_bytes: 9 * 1024 * 1024 * 1024 * 1024,
            secure_cookies: false,
            trust_proxy_headers: false,
            update_repo: None,
        })
        .unwrap()
    }

    #[test]
    fn exact_limit_serializes_and_oversize_fails_without_partial_json() {
        assert_eq!(encode_limited(&"ok", 4).unwrap(), br#""ok""#);
        assert!(matches!(
            encode_limited(&"oversize", 4),
            Err(ApiError::PayloadTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn ordinary_json_delivers_and_oversize_releases_admission() {
        let data = tempfile::tempdir().unwrap();
        let state = test_state(data.path().to_path_buf());
        let actor = "metadata@example.test";
        let response = guarded_metadata_json(
            &state,
            actor,
            actor,
            || serde_json::json!({ "files": ["ordinary"] }),
        )
        .unwrap();
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "22");
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], br#"{"files":["ordinary"]}"#);

        let rejected = guarded_metadata_json(&state, actor, actor, || {
            "x".repeat(MAX_METADATA_RESPONSE_BYTES)
        });
        assert!(matches!(rejected, Err(ApiError::PayloadTooLarge(_))));
        let _first = state.try_metadata_planning(actor).unwrap();
        let _second = state.try_metadata_planning(actor).unwrap();
    }

    #[tokio::test]
    async fn slow_or_abandoned_reader_cannot_keep_unbounded_response_admission() {
        let data = tempfile::tempdir().unwrap();
        let state = test_state(data.path().to_path_buf());
        let actor = "slow@example.test";
        let response =
            guarded_metadata_json(&state, actor, actor, || "x".repeat(1024 * 1024)).unwrap();
        let _other = state.try_metadata_planning(actor).unwrap();
        tokio::task::yield_now().await;
        assert!(matches!(
            state.try_metadata_planning(actor),
            Err(ApiError::TooManyRequests)
        ));
        drop(response);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if state.try_metadata_planning(actor).is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn retained_response_runs_terminal_authorization_after_encoding() {
        let data = tempfile::tempdir().unwrap();
        let state = test_state(data.path().to_path_buf());
        let actor = "terminal@example.test";
        let encoded = std::cell::Cell::new(false);
        let permit = state.try_metadata_planning(actor).unwrap();
        let result = guarded_metadata_json_with_permit(
            &state,
            actor,
            permit,
            || {
                encoded.set(true);
                serde_json::json!({ "files": ["secret"] })
            },
            || {
                assert!(encoded.get());
                Err(ApiError::Forbidden)
            },
        );
        assert!(matches!(result, Err(ApiError::Forbidden)));
        let _first = state.try_metadata_planning(actor).unwrap();
        let _second = state.try_metadata_planning(actor).unwrap();
    }
}
