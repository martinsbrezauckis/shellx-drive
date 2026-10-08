//! Narrow operating-system services used by the shared desktop application.
//!
//! A platform is admitted only when it can supply these services with the
//! same fail-closed guarantees as the Windows implementation. In particular,
//! a future adapter must not substitute files, environment variables, or a
//! browser profile for protected credentials, and must not emulate native root
//! selection with a caller-controlled path string.

use std::path::Path;

use shellx_drive_desktop_core::{CredentialStore, Result as CoreResult};

/// OS behavior intentionally excluded from application orchestration.
///
/// The platform-owned native filesystem modules retain their independent
/// identity, reparse-link, hard-link, staging, and publication checks. The
/// shared application only obtains credentials and performs lifecycle/UI
/// actions through this interface.
pub(crate) trait PlatformServices: Send + Sync {
    /// Canonical credential namespace for the authenticated Drive session.
    fn credentials(&self) -> &dyn CredentialStore;

    /// Device-control credentials have a separate fixed platform namespace.
    /// They must never share a keyring service with the normal Drive bearer.
    fn desktop_agent_credentials(&self) -> &dyn CredentialStore;

    /// Disconnect completion capabilities survive normal device credential
    /// cleanup until their exact terminal receipt is accepted.
    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore;

    /// Register or remove the current user's launch-at-login integration.
    fn set_launch_at_login(&self, enabled: bool) -> CoreResult<()>;

    /// Open an already-paired local root using the OS shell.
    fn open_local_root(&self, path: &Path) -> CoreResult<()>;

    /// Open the paired Drive URL using the OS shell.
    fn open_drive_url(&self, url: &str) -> CoreResult<()>;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) mod unix;
#[cfg(target_os = "windows")]
pub(crate) mod windows;
