use shellx_drive_desktop_core::{
    BaselineEntry, DesktopError, DesktopState, Result as CoreResult, ReviewItem,
};

pub(super) fn load<'a>(
    state: &'a DesktopState,
    item: &ReviewItem,
) -> CoreResult<(Vec<&'a BaselineEntry>, bool)> {
    let saved = state
        .baseline
        .values()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .collect::<Vec<_>>();
    if saved.is_empty() {
        return Err(DesktopError::InvalidState(
            "the review has no saved Drive subtree to restore locally".to_string(),
        ));
    }
    let directory = saved
        .iter()
        .find(|entry| entry.relative_path == item.relative_path)
        .map(|entry| entry.kind.eq_ignore_ascii_case("folder"))
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "the saved local restore tree has no exact root entry".to_string(),
            )
        })?;
    if directory != item.is_directory || (!directory && saved.len() != 1) {
        return Err(DesktopError::InvalidState(
            "the reviewed local restore root changed kind; no bytes were written".to_string(),
        ));
    }
    Ok((saved, directory))
}
