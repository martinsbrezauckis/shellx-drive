//! Windows implementation of the desktop platform-services boundary.

use std::{path::Path, process::Command};

use super::PlatformServices;
use shellx_drive_desktop_core::{
    CredentialStore, Result as CoreResult, WindowsCredentialStore,
    WindowsDesktopAgentCredentialStore, WindowsDesktopAgentDisconnectCredentialStore,
};

/// Windows platform service backed by Credential Manager, launch-at-login
/// integration, and the Windows shell.
pub(crate) struct WindowsPlatformServices {
    credentials: WindowsCredentialStore,
    desktop_agent_credentials: WindowsDesktopAgentCredentialStore,
    desktop_agent_disconnect_credentials: WindowsDesktopAgentDisconnectCredentialStore,
}

impl Default for WindowsPlatformServices {
    fn default() -> Self {
        Self {
            credentials: WindowsCredentialStore,
            desktop_agent_credentials: WindowsDesktopAgentCredentialStore,
            desktop_agent_disconnect_credentials: WindowsDesktopAgentDisconnectCredentialStore,
        }
    }
}

impl PlatformServices for WindowsPlatformServices {
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
        crate::application::startup::set_windows_startup(enabled)
    }

    fn open_local_root(&self, path: &Path) -> CoreResult<()> {
        Command::new("explorer.exe").arg(path).spawn()?;
        Ok(())
    }

    fn open_drive_url(&self, url: &str) -> CoreResult<()> {
        Command::new("explorer.exe").arg(url).spawn()?;
        Ok(())
    }
}
