use crate::error::{ApiError, ApiResult};

use super::{validate_file_name, MAX_FILE_NAME_BYTES};

/// Append a server-controlled suffix without exceeding the canonical file-name
/// limit. The base is cut only at a UTF-8 boundary so generated names remain
/// valid UTF-8 before the final canonical validation.
pub(super) fn derive_file_name(base: &str, suffix: &str) -> ApiResult<String> {
    let base_budget = MAX_FILE_NAME_BYTES
        .checked_sub(suffix.len())
        .ok_or_else(|| {
            ApiError::Validation("derived file name suffix exceeds the 255-byte limit".to_string())
        })?;
    let mut prefix_end = base.len().min(base_budget);
    while prefix_end > 0 && !base.is_char_boundary(prefix_end) {
        prefix_end -= 1;
    }
    validate_file_name(&format!("{}{}", &base[..prefix_end], suffix))
}

/// Produce the user-visible keep-both name for a copy without turning its
/// extension into part of the basename.  `photo.png` therefore becomes
/// `photo (copy).png`, then `photo (copy2).png`.  The stem alone is shortened
/// when necessary so both the suffix and extension remain intact.
pub(super) fn derive_copy_file_name(base: &str, sequence: usize) -> ApiResult<String> {
    let suffix = if sequence == 1 {
        " (copy)".to_string()
    } else {
        format!(" (copy{sequence})")
    };
    let (stem, extension) = base
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map(|(stem, extension)| (stem, format!(".{extension}")))
        .unwrap_or((base, String::new()));
    let stem_budget = MAX_FILE_NAME_BYTES
        .checked_sub(suffix.len())
        .and_then(|budget| budget.checked_sub(extension.len()))
        .ok_or_else(|| {
            ApiError::Validation(
                "copy name suffix and extension exceed the 255-byte limit".to_string(),
            )
        })?;
    let mut stem_end = stem.len().min(stem_budget);
    while stem_end > 0 && !stem.is_char_boundary(stem_end) {
        stem_end -= 1;
    }
    validate_file_name(&format!("{}{}{}", &stem[..stem_end], suffix, extension))
}

/// Produce a portable stale-write name. RFC 3339 timestamps contain colons,
/// which Windows file names cannot contain, so the derived suffix replaces
/// them with hyphens before reserving space for it.
pub(super) fn derive_conflict_file_name(base: &str, timestamp: &str) -> ApiResult<String> {
    derive_file_name(
        base,
        &format!(" (conflict {})", timestamp.replace(':', "-")),
    )
}

#[cfg(test)]
mod tests;
