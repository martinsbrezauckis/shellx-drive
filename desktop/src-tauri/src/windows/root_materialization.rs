//! Checked creation and retained attachment for a new Windows pair root.

use super::{
    transfer_execution::{
        local_target, open_checked_rename_directory, pin_checked_rename_directory_chain,
    },
    *,
};

/// Create one new pair root while retaining every checked directory from the
/// selected base through the final child. The caller keeps these no-delete
/// handles live through identity verification, marker creation, and state
/// publication so the new child cannot be detached from its selected base.
pub(super) fn ensure_local_directory_pinned(
    root: &Path,
    relative_path: &Path,
) -> CoreResult<Vec<fs::File>> {
    if relative_path.as_os_str().is_empty() {
        return pin_checked_rename_directory_chain(root, root);
    }
    let target = local_target(root, relative_path)?;
    let relative = target.strip_prefix(root).map_err(|_| {
        DesktopError::UnsafePath(format!(
            "Drive folder escapes the selected root: {}",
            relative_path.display()
        ))
    })?;
    let mut current = root.to_path_buf();
    let mut pins = pin_checked_rename_directory_chain(root, root)?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(DesktopError::UnsafePath(
                "Drive folder has a non-normal path component".to_string(),
            ));
        };
        let child = current.join(name);
        match fs::create_dir(&child) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(DesktopError::Io(error)),
        }
        pins.push(open_checked_rename_directory(&child)?);
        current = child;
    }
    Ok(pins)
}
