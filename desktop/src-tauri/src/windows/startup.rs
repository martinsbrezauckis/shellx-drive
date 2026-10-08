//! Durable Windows launch-at-sign-in registration and update recovery.

use super::*;
use winreg::{enums::HKEY_CURRENT_USER, RegKey};

const STARTUP_VALUE: &str = "ShellX Drive Desktop";
const STARTUP_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

pub(crate) fn set_windows_startup(enabled: bool) -> CoreResult<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (run, _) = hkcu
        .create_subkey(STARTUP_KEY)
        .map_err(|error| DesktopError::InvalidState(error.to_string()))?;
    if enabled {
        let executable = std::env::current_exe().map_err(DesktopError::Io)?;
        run.set_value(STARTUP_VALUE, &format!("\"{}\"", executable.display()))
            .map_err(|error| DesktopError::InvalidState(error.to_string()))?;
    } else {
        match run.delete_value(STARTUP_VALUE) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(DesktopError::InvalidState(error.to_string())),
        }
    }
    Ok(())
}
