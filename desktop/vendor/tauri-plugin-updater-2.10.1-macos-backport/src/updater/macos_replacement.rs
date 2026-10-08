// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! macOS-only updater replacement safeguards.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::error::{Error, Result};

const MACOS_PRIVILEGED_REPLACEMENT_SHELL: &str = r#"set -eu
umask 077
source_path=$1
archive_path=$2
staging_path=$3
backup_directory=$4
expected_digest=$5

case "$expected_digest" in
    *[!0123456789abcdef]*|'') exit 2 ;;
esac
if [ "${#expected_digest}" -ne 64 ]; then
    exit 2
fi
if [ "${staging_path%/*}" != /private/var/tmp ] ||
   [ "${backup_directory%/*}" != /private/var/tmp ] ||
   [ "$(/usr/bin/stat -f '%u:%Sp' /private/var/tmp)" != '0:drwxrwxrwt' ]; then
    exit 1
fi
if [ -e "$staging_path" ] || [ -L "$staging_path" ]; then
    exit 1
fi
/bin/mkdir -m 700 "$staging_path" || exit 1
cleanup() {
    if [ -e "$backup_directory/current_app" ] && [ ! -e "$source_path" ] && [ ! -L "$source_path" ]; then
        /bin/mv -n "$backup_directory/current_app" "$source_path" || true
    fi
    if [ -d "$staging_path" ] && [ ! -L "$staging_path" ]; then
        /bin/rm -rf "$staging_path"
    fi
}
trap cleanup EXIT
archive_copy="$staging_path/update.tar.gz"
app_stage="$staging_path/${source_path##*/}"
if ! /usr/bin/ditto "$archive_path" "$archive_copy"; then
    /bin/rm -rf "$staging_path"
    exit 1
fi
actual_digest=$(/usr/bin/shasum -a 256 "$archive_copy" | /usr/bin/awk '{print $1}') || {
    /bin/rm -rf "$staging_path"
    exit 1
}
if [ "$actual_digest" != "$expected_digest" ]; then
    /bin/rm -rf "$staging_path"
    exit 1
fi
/bin/mkdir -m 700 "$app_stage" || exit 1
if ! /usr/bin/tar -xzf "$archive_copy" -C "$app_stage" --strip-components 1; then
    /bin/rm -rf "$staging_path"
    exit 1
fi
/bin/rm -f "$archive_copy"
if ! /usr/bin/codesign --verify --deep --strict "$app_stage"; then
    exit 1
fi
if ! /usr/sbin/chown -R -P root:wheel "$app_stage" ||
   ! /usr/bin/find "$app_stage" ! -type l -exec /bin/chmod -N {} + ||
   ! /usr/bin/find "$app_stage" ! -type l -exec /bin/chmod go-w,u-s,g-s {} +; then
    exit 1
fi
if ! /usr/bin/codesign --verify --deep --strict "$app_stage"; then
    /bin/rm -rf "$staging_path"
    exit 1
fi
signature_details=$(/usr/bin/codesign -dv --verbose=4 "$app_stage" 2>&1) || {
    /bin/rm -rf "$staging_path"
    exit 1
}
if ! printf '%s\n' "$signature_details" | /usr/bin/grep -Fxq 'Identifier=com.shellx.drive.desktop' ||
   ! printf '%s\n' "$signature_details" | /usr/bin/grep -Fxq 'TeamIdentifier=4M329JW6R4'; then
    /bin/rm -rf "$staging_path"
    exit 1
fi
source_parent=${source_path%/*}
if [ -z "$source_parent" ] || [ "$source_parent" = "$source_path" ] ||
   [ "$(/bin/realpath "$source_parent")" != "$source_parent" ] ||
   [ -L "$source_path" ]; then
    exit 1
fi
ancestor=$source_parent
while :; do
    ancestor_identity=$(/usr/bin/stat -f '%u:%g:%Sp' "$ancestor") || exit 1
    case "$ancestor_identity" in
        0:*) ;;
        *) exit 1 ;;
    esac
    ancestor_group=${ancestor_identity#*:}
    ancestor_group=${ancestor_group%%:*}
    ancestor_permissions=${ancestor_identity##*:}
    case "$ancestor_permissions" in
        ????????w*) exit 1 ;;
        ?????w*)
            case "$ancestor_group" in
                0|80) ;;
                *) exit 1 ;;
            esac
            ;;
    esac
    ancestor_listing=$(/bin/ls -lde "$ancestor") || exit 1
    case "${ancestor_listing%% *}" in
        *+) exit 1 ;;
    esac
    [ "$ancestor" = / ] && break
    ancestor=${ancestor%/*}
    [ -n "$ancestor" ] || ancestor=/
done
if [ -e "$backup_directory" ] || [ -L "$backup_directory" ]; then
    exit 1
fi
if ! /bin/mkdir "$backup_directory"; then
    exit 1
fi

source_identity=$(/usr/bin/stat -f '%d:%i' "$source_path") || {
    /bin/rmdir "$backup_directory" || true
    exit 1
}
if ! /bin/mv -n "$source_path" "$backup_directory/current_app"; then
    /bin/rmdir "$backup_directory" || true
    exit 1
fi
backup_identity=$(/usr/bin/stat -f '%d:%i' "$backup_directory/current_app") || exit 1
if [ "$source_identity" != "$backup_identity" ] || [ -e "$source_path" ] || [ -L "$source_path" ]; then
    exit 1
fi

staging_identity=$(/usr/bin/stat -f '%d:%i' "$app_stage") || exit 1
if ! /bin/mv -n "$app_stage" "$source_path"; then
    /bin/mv -n "$backup_directory/current_app" "$source_path" || true
    exit 1
fi
source_identity=$(/usr/bin/stat -f '%d:%i' "$source_path") || exit 1
if [ "$staging_identity" != "$source_identity" ] || [ -e "$app_stage" ] || [ -L "$app_stage" ]; then
    exit 1
fi

/bin/rm -rf "$backup_directory"
"#;

const MACOS_PRIVILEGED_REPLACEMENT_APPLESCRIPT: &str =
    include_str!("macos_replacement.applescript");

pub(super) fn macos_validate_path(path: &Path) -> Result<&str> {
    if !path.is_absolute() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "macOS updater path must be absolute",
        )));
    }
    path.to_str().ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "macOS updater path is not valid UTF-8",
        ))
    })
}

// The privileged extractor replays these signed bytes with tar. Validate the
// archive's paths before offering them to a root process.
pub(super) fn macos_validate_archive_entry<R: std::io::Read>(
    entry: &mut tar::Entry<R>,
) -> Result<()> {
    let path = entry.path()?.into_owned();
    let kind = entry.header().entry_type();
    let target = entry.link_name()?;
    macos_validate_archive_path(&path, kind, target.as_deref())
}

fn macos_validate_archive_path(
    path: &Path,
    kind: tar::EntryType,
    target: Option<&Path>,
) -> Result<()> {
    use std::path::Component;

    let mut components = path.components();
    let Some(Component::Normal(bundle_name)) = components.next() else {
        return Err(Error::InvalidUpdaterFormat);
    };
    if !bundle_name.to_string_lossy().ends_with(".app")
        || components.any(|component| !matches!(component, Component::Normal(_)))
        || (path.components().count() == 1 && !kind.is_dir())
    {
        return Err(Error::InvalidUpdaterFormat);
    }
    if kind.is_symlink() {
        let target = target.ok_or(Error::InvalidUpdaterFormat)?;
        let mut depth = path.components().count().saturating_sub(2);
        for component in target.components() {
            match component {
                Component::Normal(_) => depth += 1,
                Component::ParentDir if depth > 0 => depth -= 1,
                Component::CurDir => (),
                _ => return Err(Error::InvalidUpdaterFormat),
            }
        }
    } else if !kind.is_file() && !kind.is_dir() {
        return Err(Error::InvalidUpdaterFormat);
    }
    Ok(())
}

fn macos_path_argument(path: &Path) -> Result<osakit::Value> {
    Ok(osakit::Value::String(
        macos_validate_path(path)?.to_string(),
    ))
}

fn macos_privileged_replacement_arguments(
    source: &Path,
    archive: &Path,
    staging: &Path,
    backup: &Path,
    digest: &str,
) -> Result<[osakit::Value; 6]> {
    Ok([
        macos_path_argument(source)?,
        macos_path_argument(archive)?,
        macos_path_argument(staging)?,
        macos_path_argument(backup)?,
        osakit::Value::String(digest.to_string()),
        osakit::Value::String(MACOS_PRIVILEGED_REPLACEMENT_SHELL.to_string()),
    ])
}

fn macos_sibling_tempdir(source: &Path, prefix: &str) -> Result<tempfile::TempDir> {
    let parent = source.parent().ok_or(Error::FailedToDetermineExtractPath)?;
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(parent)
        .map_err(Into::into)
}

pub(super) fn macos_backup_directory(source: &Path) -> Result<tempfile::TempDir> {
    macos_sibling_tempdir(source, ".tauri-current-app-")
}

fn macos_copy_directory(source: &Path, destination: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("/usr/bin/ditto")
        .args(["--rsrc", "--extattr"])
        .arg(source)
        .arg(destination)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(
            "macOS updater could not stage the verified replacement",
        ));
    }
    std::fs::set_permissions(destination, std::fs::metadata(source)?.permissions())
}

pub(super) fn macos_stage_verified_replacement(
    source: &Path,
    incoming: &Path,
) -> Result<tempfile::TempDir> {
    macos_stage_verified_replacement_with(source, incoming, macos_copy_directory)
}

fn macos_stage_verified_replacement_with(
    source: &Path,
    incoming: &Path,
    copy: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<tempfile::TempDir> {
    macos_validate_path(source)?;
    let staging = macos_sibling_tempdir(source, ".tauri-verified-app-")?;
    copy(incoming, staging.path())?;
    Ok(staging)
}

fn macos_privileged_private_path(
    source: &Path,
    nonce_source: &Path,
    suffix: &str,
) -> Result<PathBuf> {
    macos_validate_path(source)?;
    let nonce = nonce_source
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "macOS updater staging nonce is not valid UTF-8",
            ))
        })?;
    Ok(Path::new("/private/var/tmp").join(format!(".shellx-drive-updater-{suffix}-{nonce}")))
}

pub(super) fn macos_privileged_staging_path(source: &Path, nonce_source: &Path) -> Result<PathBuf> {
    macos_privileged_private_path(source, nonce_source, "staging")
}

pub(super) fn macos_privileged_backup_path(source: &Path, nonce_source: &Path) -> Result<PathBuf> {
    macos_privileged_private_path(source, nonce_source, "backup")
}

pub(super) fn macos_rename_without_replacing(
    source: &Path,
    destination: &Path,
) -> std::io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "macOS updater source path contains a NUL byte",
        )
    })?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "macOS updater destination path contains a NUL byte",
        )
    })?;
    // SAFETY: these NUL-terminated paths remain alive throughout the FFI call.
    // RENAME_EXCL atomically refuses a destination created after preflight.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(super) fn macos_replace_staged_with_rollback(
    staged: &Path,
    source: &Path,
    backup: &Path,
) -> Result<()> {
    match macos_rename_without_replacing(staged, source) {
        Ok(()) => Ok(()),
        Err(replacement_error) => {
            if let Err(restore_error) = macos_rename_without_replacing(backup, source) {
                return Err(Error::Io(std::io::Error::new(
                    restore_error.kind(),
                    format!(
                        "failed to replace the macOS app ({replacement_error}) and restore its backup ({restore_error})"
                    ),
                )));
            }
            Err(replacement_error.into())
        }
    }
}

pub(super) fn macos_replace_with_authorization(
    source: &Path,
    archive: &Path,
    staging: &Path,
    backup: &Path,
    digest: &str,
    run_on_main_thread: &Arc<super::RunOnMainThread>,
) -> Result<()> {
    let arguments =
        macos_privileged_replacement_arguments(source, archive, staging, backup, digest)?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    run_on_main_thread(Box::new(move || {
        let result = (|| {
            let mut script = osakit::Script::new_from_source(
                osakit::Language::AppleScript,
                MACOS_PRIVILEGED_REPLACEMENT_APPLESCRIPT,
            );
            script.compile().map_err(|error| error.to_string())?;
            script
                .execute_function("replace_app", arguments)
                .map(|_| ())
                .map_err(|error| error.to_string())
        })();
        let _ = sender.send(result);
    }))
    .map_err(|_| {
        Error::Io(std::io::Error::other(
            "macOS updater authorization could not be scheduled",
        ))
    })?;
    receiver
        .recv()
        .map_err(|_| {
            Error::Io(std::io::Error::other(
                "macOS updater authorization did not return a result",
            ))
        })?
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Failed to move the new app into place",
            ))
        })
}

#[cfg(test)]
#[path = "macos_replacement_tests.rs"]
mod macos_replacement_tests;
