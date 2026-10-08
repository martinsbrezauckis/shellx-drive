use axum::{
    http::{header, HeaderValue},
    response::Response,
};

use crate::{
    error::{ApiError, ApiResult},
    routes::blob_response::guard_bounded_bytes_response_with_total_deadline,
};

use super::MAX_PUBLIC_SHARE_METADATA_BYTES;

pub(super) fn bounded_metadata_response<G>(
    mut response: Response,
    metadata_bytes: Vec<u8>,
    stream_permit: G,
) -> ApiResult<Response>
where
    G: Send + 'static,
{
    if metadata_bytes.len() > MAX_PUBLIC_SHARE_METADATA_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "public share metadata exceeds its {MAX_PUBLIC_SHARE_METADATA_BYTES}-byte response limit"
        )));
    }
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&metadata_bytes.len().to_string()).map_err(|_| {
            ApiError::Maintenance("invalid public share metadata response length".to_string())
        })?,
    );
    Ok(guard_bounded_bytes_response_with_total_deadline(
        response,
        metadata_bytes,
        stream_permit,
        Duration::from_secs(2 * 60),
    ))
}
use std::time::Duration;
