use crate::{
    auth::Actor,
    error::{ApiError, ApiResult},
    model::{UploadChunkRequest, UploadSession},
};

use super::MAX_RESUMABLE_UPLOAD_BYTES;

pub(super) fn validate_declared_upload_size(total_size: i64) -> ApiResult<()> {
    if !(0..=MAX_RESUMABLE_UPLOAD_BYTES).contains(&total_size) {
        return Err(ApiError::Validation(format!(
            "total_size must be between 0 and {MAX_RESUMABLE_UPLOAD_BYTES}"
        )));
    }
    Ok(())
}

pub(super) fn ensure_upload_session_actor(session: &UploadSession, actor: &Actor) -> ApiResult<()> {
    if actor.is_admin || session.actor_email == actor.email {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

pub(super) fn upload_chunk_bytes(request: &UploadChunkRequest) -> ApiResult<Vec<u8>> {
    match (&request.content, &request.content_base64) {
        (Some(_), Some(_)) => Err(ApiError::Validation(
            "upload chunk must contain content or content_base64, not both".to_string(),
        )),
        (Some(content), None) => Ok(content.as_bytes().to_vec()),
        (None, Some(content_base64)) => {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            STANDARD.decode(content_base64).map_err(|error| {
                ApiError::Validation(format!("invalid upload content_base64: {error}"))
            })
        }
        (None, None) => Err(ApiError::Validation(
            "upload chunk must contain content or content_base64".to_string(),
        )),
    }
}
