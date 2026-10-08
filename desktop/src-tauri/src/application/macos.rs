//! macOS adapter for the shared ShellX Drive desktop surface.
//!
//! macOS owns Keychain lifecycle, the Unix descriptor-bound local filesystem
//! boundary, LaunchAgent management, the process lease, and Finder/browser
//! opening.  Product state, user-facing views, server validation, root
//! discovery, and confirmation admission remain shared above this module.

mod add_root;
mod auth;
mod candidate_recovery;
pub(crate) mod offboarding;
mod offboarding_resume;
pub(crate) mod pairing;
pub(crate) mod review_execution;
mod shell;
pub(crate) mod sync;
mod updates;

use super::*;
use shellx_drive_desktop_core::{DesktopError, DesktopState, Result as CoreResult, StateStore};

impl Runtime {
    fn load_macos() -> CoreResult<Self> {
        let (store, state) = Self::load_state()?;
        Self::load_connection(store, state)
    }

    pub(crate) fn load_connection(store: StateStore, mut state: DesktopState) -> CoreResult<Self> {
        let platform = Box::new(crate::platform::unix::UnixPlatformServices::default());
        if offboarding_resume::resume_macos_disconnect_cleanup(&store, &mut state).is_err() {
            state.last_error = Some(
                "Disconnect local cleanup remains pending; retry Disconnect to complete it."
                    .to_string(),
            );
            let _ = store.save(&state);
        }
        Ok(Self::from_loaded_state(platform, store, state))
    }
}

pub(crate) fn run_from_args() -> i32 {
    shell::run_from_args()
}

pub(crate) use shell::update_tray;

fn macos_error(error: DesktopError) -> String {
    error.to_string()
}

#[cfg(test)]
#[path = "macos/pairing/tests.rs"]
mod pairing_tests;
