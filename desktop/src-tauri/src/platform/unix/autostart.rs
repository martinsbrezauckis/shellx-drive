//! Per-user Unix launch-at-login registration.
//!
//! A launch entry is persisted only after its executable is proven stable. In
//! particular, an AppImage's transient FUSE mount is never written to an XDG
//! autostart file.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use directories::BaseDirs;
use shellx_drive_desktop_core::{DesktopError, Result as CoreResult};

#[cfg(target_os = "macos")]
const AUTOSTART_FILE: &str = "com.shellx.drive.desktop.plist";
#[cfg(target_os = "linux")]
const AUTOSTART_FILE: &str = "shellx-drive-desktop.desktop";
#[cfg(target_os = "macos")]
const AUTOSTART_OWNERSHIP_MARKER: &str = "<key>ShellXDriveManaged</key><true/>";
#[cfg(target_os = "linux")]
const AUTOSTART_OWNERSHIP_MARKER: &str = "X-ShellX-Drive-Managed=true";

mod executable;

pub(super) fn set_unix_launch_at_login(enabled: bool) -> CoreResult<()> {
    let (path, legacy_path) = autostart_paths()?;
    if enabled {
        let parent = path.parent().ok_or_else(|| {
            DesktopError::InvalidState("autostart path has no parent directory".to_string())
        })?;
        ensure_owned_directory(parent)?;
        write_private_file(&path, &autostart_contents()?)?;
        // The selected XDG location is now durable. A legacy default-location
        // entry is compatibility cleanup, so a later cleanup failure must not
        // report that enabling launch-at-login failed after it has succeeded.
        cleanup_known_legacy_after_enable(&path, legacy_path);
        Ok(())
    } else {
        remove_owned_autostart_entries(&path, legacy_path)
    }
}

pub(super) fn remove_owned_launch_at_login() -> CoreResult<()> {
    let (path, legacy_path) = autostart_paths()?;
    remove_owned_autostart_entries(&path, legacy_path)
}

#[cfg(test)]
fn autostart_path() -> CoreResult<PathBuf> {
    Ok(autostart_paths()?.0)
}

fn autostart_paths() -> CoreResult<(PathBuf, Option<PathBuf>)> {
    let base = BaseDirs::new().ok_or_else(|| {
        DesktopError::InvalidState("could not determine home directory".to_string())
    })?;
    #[cfg(target_os = "linux")]
    let paths = linux_autostart_paths(base.home_dir(), base.config_dir());
    #[cfg(target_os = "macos")]
    let paths = {
        let directory = base.home_dir().join("Library").join("LaunchAgents");
        (directory.join(AUTOSTART_FILE), None)
    };
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn linux_autostart_paths(home_dir: &Path, config_dir: &Path) -> (PathBuf, Option<PathBuf>) {
    // Before XDG_CONFIG_HOME support, Drive always used the default location.
    // It is the sole known migration candidate: arbitrary earlier custom XDG
    // directories are not recoverable without state and must never be found by
    // scanning the user's home directory.
    let current = config_dir.join("autostart").join(AUTOSTART_FILE);
    let legacy = home_dir
        .join(".config")
        .join("autostart")
        .join(AUTOSTART_FILE);
    let legacy = (legacy != current).then_some(legacy);
    (current, legacy)
}

fn autostart_contents() -> CoreResult<String> {
    let current = std::env::current_exe().map_err(DesktopError::Io)?;
    let executable =
        executable::select_stable_executable(&current, std::env::var_os("APPIMAGE").as_deref())?;
    autostart_contents_for(&executable)
}

fn autostart_contents_for(executable: &Path) -> CoreResult<String> {
    let executable = executable.to_str().ok_or_else(|| {
        DesktopError::InvalidState("autostart requires a UTF-8 executable path".to_string())
    })?;
    if executable.contains(['\n', '\r', '\0']) {
        return Err(DesktopError::InvalidState(
            "desktop executable path cannot be represented safely in autostart configuration"
                .to_string(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        if executable.contains(['=', '%', '\t']) {
            return Err(DesktopError::InvalidState(
                "desktop executable path cannot be represented safely in Linux autostart configuration"
                    .to_string(),
            ));
        }
        // Exec quoting is applied after desktop-entry string unescaping.
        // Escape both layers. Literal percent signs remain rejected: native
        // launchers can resolve the executable before decoding field codes.
        let mut argument = String::new();
        for character in executable.chars() {
            if matches!(character, '"' | '`' | '$' | '\\') {
                argument.push('\\');
            }
            argument.push(character);
        }
        let argument = argument.replace('\\', "\\\\");
        Ok(format!(
            "[Desktop Entry]\nType=Application\nName=ShellX Drive\nExec=\"{argument}\"\nX-GNOME-Autostart-enabled=true\n{AUTOSTART_OWNERSHIP_MARKER}\n"
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let executable = xml_escape(executable);
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>com.shellx.drive.desktop</string><key>ProgramArguments</key><array><string>{executable}</string></array><key>RunAtLoad</key><true/>{AUTOSTART_OWNERSHIP_MARKER}</dict></plist>\n"
        ))
    }
}

fn remove_owned_autostart(path: &Path) -> CoreResult<()> {
    let contents = match read_owned_autostart_file(path) {
        Ok(Some(contents)) => contents,
        Ok(None) => return Ok(()),
        Err(error) => return Err(error),
    };
    if !autostart_contents_are_owned(&contents) {
        return Err(DesktopError::InvalidState(
            "refusing to remove an autostart entry not owned by ShellX Drive".to_string(),
        ));
    }
    fs::remove_file(path)?;
    Ok(())
}

fn remove_owned_autostart_entries(path: &Path, legacy_path: Option<PathBuf>) -> CoreResult<()> {
    let current_result = remove_owned_autostart(path);
    let legacy_result = match legacy_path {
        Some(legacy_path) => remove_known_legacy_autostart(&legacy_path),
        None => Ok(()),
    };
    match (current_result, legacy_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(current_error), Err(legacy_error)) => Err(DesktopError::InvalidState(format!(
            "could not remove current and known legacy autostart entries: {current_error}; {legacy_error}"
        ))),
    }
}

fn cleanup_known_legacy_after_enable(path: &Path, legacy_path: Option<PathBuf>) {
    let Some(legacy_path) = legacy_path else {
        return;
    };
    if paths_refer_to_same_entry(path, &legacy_path) {
        return;
    }
    let _ = remove_known_legacy_autostart(&legacy_path);
}

fn paths_refer_to_same_entry(first: &Path, second: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let (Ok(first), Ok(second)) = (fs::metadata(first), fs::metadata(second)) else {
        return false;
    };
    first.dev() == second.dev() && first.ino() == second.ino()
}

fn remove_known_legacy_autostart(path: &Path) -> CoreResult<()> {
    let contents = match read_owned_autostart_file(path) {
        Ok(Some(contents)) => contents,
        Ok(None) => return Ok(()),
        Err(error) => return Err(error),
    };
    if autostart_contents_are_owned(&contents) {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn read_owned_autostart_file(path: &Path) -> CoreResult<Option<String>> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DesktopError::Io(error)),
    };
    verify_owned_autostart_file(&file)?;
    let mut contents = String::new();
    file.take(64 * 1024).read_to_string(&mut contents)?;
    Ok(Some(contents))
}

fn ensure_owned_directory(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::DirBuilderExt;

    match fs::symlink_metadata(path) {
        Ok(metadata) => verify_owned_directory_metadata(&metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                DesktopError::InvalidState("autostart directory has no parent".to_string())
            })?;
            ensure_owned_directory(parent)?;
            fs::DirBuilder::new().mode(0o700).create(path)?;
            verify_owned_directory_metadata(&fs::symlink_metadata(path)?)
        }
        Err(error) => Err(DesktopError::Io(error)),
    }
}

fn verify_owned_directory_metadata(metadata: &fs::Metadata) -> CoreResult<()> {
    use std::os::unix::fs::MetadataExt;

    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(DesktopError::UnsafePath(
            "autostart directory is not an owner-private real directory".to_string(),
        ));
    }
    Ok(())
}

fn write_private_file(path: &Path, contents: &str) -> CoreResult<()> {
    if let Some(existing) = read_owned_autostart_file(path)? {
        if !autostart_contents_are_owned(&existing) {
            return Err(DesktopError::InvalidState(
                "refusing to replace an autostart entry not owned by ShellX Drive".to_string(),
            ));
        }
    }
    let parent = path.parent().ok_or_else(|| {
        DesktopError::InvalidState("autostart file has no parent directory".to_string())
    })?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".shellx-drive-autostart-")
        .suffix(".next")
        .tempfile_in(parent)?;
    temporary
        .as_file()
        .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    temporary.write_all(contents.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    verify_owned_autostart_file(&fs::File::open(path)?)
}

fn verify_owned_autostart_file(file: &fs::File) -> CoreResult<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(DesktopError::UnsafePath(
            "autostart entry is not a private app-owned regular file".to_string(),
        ));
    }
    Ok(())
}

fn autostart_contents_are_owned(contents: &str) -> bool {
    contents.contains(AUTOSTART_OWNERSHIP_MARKER)
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
#[path = "autostart/tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "autostart/linux_exec_tests.rs"]
mod linux_exec_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "autostart/migration_tests.rs"]
mod migration_tests;
