use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

const INVALID_UPLOAD_ID: &str = "upload session id must be a canonical UUID";

/// Parse any UUID spelling accepted at a normalization boundary and return the
/// one lowercase, hyphenated representation used by storage and paths.
pub(crate) fn normalize(value: &str) -> ApiResult<String> {
    Uuid::parse_str(value)
        .map(|id| id.hyphenated().to_string())
        .map_err(|_| ApiError::Validation(INVALID_UPLOAD_ID.to_string()))
}

/// Persisted IDs must already use the canonical representation. This keeps a
/// restored database value from becoming an interpreted path component later.
pub(crate) fn require_canonical(value: &str) -> ApiResult<()> {
    if normalize(value)?.as_str() != value {
        return Err(ApiError::Validation(INVALID_UPLOAD_ID.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_safe_aliases_and_rejects_path_components() {
        assert_eq!(
            normalize("550E8400-E29B-41D4-A716-446655440000").unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert!(normalize("../../tmp/target").is_err());
        assert!(normalize("550e8400-e29b-41d4-a716-446655440000/../x").is_err());
        assert!(require_canonical("550E8400-E29B-41D4-A716-446655440000").is_err());
        assert!(require_canonical("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }
}
