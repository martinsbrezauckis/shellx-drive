use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("desktop-agent cancellation requested")]
    DesktopAgentCancellationRequested,
    #[error("desktop-agent disconnect capability expired")]
    DesktopAgentDisconnectCapabilityExpired,
    #[error("desktop-agent disconnect authorization lost")]
    DesktopAgentDisconnectAuthorizationLost,
    #[error("locked")]
    Locked,
    #[error("precondition failed")]
    PreconditionFailed,
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("too many requests")]
    TooManyRequests,
    #[error("request body timed out")]
    RequestTimeout,
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    #[error("sync root discovery exceeds its bounded publication limit")]
    SyncRootDiscoveryOverflow,
    #[error("service maintenance in progress: {0}")]
    Maintenance(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("storage error")]
    Storage(#[source] rusqlite::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        let bounded_resource = match &error {
            rusqlite::Error::SqliteFailure(_, Some(message)) => match message.as_str() {
                "file revision limit exceeded" => {
                    Some("file revision history reached its bounded limit")
                }
                "pinned file revision limit exceeded" => {
                    Some("pinned file revision history reached its bounded limit")
                }
                "folder template limit exceeded" => {
                    Some("workspace folder templates reached their bounded limit")
                }
                "folder template item limit exceeded" => {
                    Some("folder template items reached their bounded limit")
                }
                "folder template content limit exceeded" => {
                    Some("folder template embedded content reached its bounded limit")
                }
                "workspace folder template content limit exceeded" => {
                    Some("workspace folder template embedded content reached its bounded limit")
                }
                "workspace auxiliary storage limit exceeded" => {
                    Some("workspace metadata and collaboration storage reached its bounded limit")
                }
                _ => None,
            },
            _ => None,
        };
        bounded_resource
            .map(|message| ApiError::PayloadTooLarge(message.to_string()))
            .unwrap_or(ApiError::Storage(error))
    }
}

impl ApiError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict
            | Self::DesktopAgentCancellationRequested
            | Self::DesktopAgentDisconnectCapabilityExpired
            | Self::DesktopAgentDisconnectAuthorizationLost => StatusCode::CONFLICT,
            Self::Locked => StatusCode::LOCKED,
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::PayloadTooLarge(_) | Self::SyncRootDiscoveryOverflow => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            Self::Maintenance(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Storage(_) | Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error = match status {
            StatusCode::UNAUTHORIZED => "unauthenticated",
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::CONFLICT => match &self {
                Self::DesktopAgentCancellationRequested => "desktop_agent_cancellation_requested",
                Self::DesktopAgentDisconnectCapabilityExpired => {
                    "desktop_agent_disconnect_capability_expired"
                }
                Self::DesktopAgentDisconnectAuthorizationLost => {
                    "desktop_agent_disconnect_authorization_lost"
                }
                _ => "conflict",
            },
            StatusCode::LOCKED => "locked",
            StatusCode::PRECONDITION_FAILED => "precondition_failed",
            StatusCode::NOT_IMPLEMENTED => "not_implemented",
            StatusCode::TOO_MANY_REQUESTS => "too_many_requests",
            StatusCode::REQUEST_TIMEOUT => "request_timeout",
            StatusCode::PAYLOAD_TOO_LARGE => match &self {
                Self::SyncRootDiscoveryOverflow => "sync_root_discovery_overflow",
                _ => "payload_too_large",
            },
            StatusCode::BAD_REQUEST => "validation_error",
            StatusCode::SERVICE_UNAVAILABLE => "maintenance",
            _ => "internal_error",
        };
        (
            status,
            Json(ErrorBody {
                error,
                message: self.to_string(),
            }),
        )
            .into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
