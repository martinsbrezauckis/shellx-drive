use crate::error::{ApiError, ApiResult};

#[derive(Debug, Clone, Copy, Default)]
pub struct ImportRunTotals {
    pub entries: i64,
    pub files: i64,
    pub folders: i64,
    pub bytes: i64,
}

pub(super) fn bounded_error_code(value: &str) -> ApiResult<String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ApiError::Validation(
            "invalid import/export error code".to_string(),
        ));
    }
    Ok(value.to_string())
}
