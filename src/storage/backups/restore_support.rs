#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use crate::error::{ApiError, ApiResult};

#[cfg(test)]
static FAIL_AFTER_REVERSE_DELETES: std::sync::OnceLock<
    std::sync::Mutex<Option<std::path::PathBuf>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(super) fn fail_next_after_reverse_deletes(data_dir: &Path) {
    *FAIL_AFTER_REVERSE_DELETES
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap() = Some(data_dir.to_path_buf());
}

#[cfg(test)]
pub(super) fn fail_after_reverse_deletes(data_dir: &Path) -> ApiResult<()> {
    let mut fault_data_dir = FAIL_AFTER_REVERSE_DELETES
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap();
    if fault_data_dir.as_deref() == Some(data_dir) {
        *fault_data_dir = None;
        return Err(ApiError::Validation(
            "test fault after backup restore deletes".to_string(),
        ));
    }
    Ok(())
}
