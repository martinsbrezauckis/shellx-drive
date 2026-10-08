//! macOS and Linux platform services for the shared desktop application.
//!
//! The admitted native sync executors use the real OS credential backend,
//! shell integration, per-user autostart representation, and
//! descriptor-bound filesystem boundary. They never fall back to a text path,
//! plaintext bearer, or process-global state file.

use super::PlatformServices;
use shellx_drive_desktop_core::{CredentialStore, DesktopError, Result as CoreResult};
use std::{ffi::OsStr, path::Path, process::Command};

// These are deliberately Unix-only primitives.  The desktop application
// layers may use them, but no caller receives a path-string mutation escape
// hatch: all root-relative work remains descriptor-bound in `filesystem`.
mod autostart;
pub(crate) mod download_space;
pub(crate) mod filesystem;
pub(crate) mod instance;

#[cfg(target_os = "linux")]
use shellx_drive_desktop_core::{
    LinuxCredentialStore as NativeCredentialStore,
    LinuxDesktopAgentCredentialStore as NativeDesktopAgentCredentialStore,
    LinuxDesktopAgentDisconnectCredentialStore as NativeDesktopAgentDisconnectCredentialStore,
};
#[cfg(target_os = "macos")]
use shellx_drive_desktop_core::{
    MacOsCredentialStore as NativeCredentialStore,
    MacOsDesktopAgentCredentialStore as NativeDesktopAgentCredentialStore,
    MacOsDesktopAgentDisconnectCredentialStore as NativeDesktopAgentDisconnectCredentialStore,
};

/// The real macOS/Linux platform service. It intentionally provides no
/// best-effort filesystem fallback; native executors surface a repairable error
/// whenever the descriptor-bound mutation preconditions cannot be proved.
pub(crate) struct UnixPlatformServices {
    credentials: NativeCredentialStore,
    desktop_agent_credentials: NativeDesktopAgentCredentialStore,
    desktop_agent_disconnect_credentials: NativeDesktopAgentDisconnectCredentialStore,
}

impl Default for UnixPlatformServices {
    fn default() -> Self {
        Self {
            credentials: NativeCredentialStore,
            desktop_agent_credentials: NativeDesktopAgentCredentialStore,
            desktop_agent_disconnect_credentials: NativeDesktopAgentDisconnectCredentialStore,
        }
    }
}

impl PlatformServices for UnixPlatformServices {
    fn credentials(&self) -> &dyn CredentialStore {
        &self.credentials
    }

    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        &self.desktop_agent_credentials
    }

    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        &self.desktop_agent_disconnect_credentials
    }

    fn set_launch_at_login(&self, enabled: bool) -> CoreResult<()> {
        autostart::set_unix_launch_at_login(enabled)
    }

    fn open_local_root(&self, path: &Path) -> CoreResult<()> {
        shell_open(path.as_os_str())
    }

    fn open_drive_url(&self, url: &str) -> CoreResult<()> {
        shell_open(OsStr::new(url))
    }
}

fn shell_open(subject: &OsStr) -> CoreResult<()> {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = Command::new("xdg-open");
    command
        .arg(subject)
        .spawn()
        .map(|_| ())
        .map_err(DesktopError::Io)
}

/// Remove only this user's verified ShellX Drive launch registration. This is
/// used by both Disconnect and the pre-uninstall lifecycle command.
pub(crate) fn remove_owned_launch_at_login() -> CoreResult<()> {
    autostart::remove_owned_launch_at_login()
}
