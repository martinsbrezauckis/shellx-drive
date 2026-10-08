//! Serialized terminal-login publication shared by native desktop adapters.
//!
//! A password request is deliberately allowed to run without this mutex. Its
//! terminal result, however, must not repopulate a 2FA continuation after a
//! newer login or Disconnect invalidated that request's generation.

use std::sync::Mutex;

use shellx_drive_desktop_core::{AuthOffboardingGate, DesktopError, Result as CoreResult};

use super::PendingLogin;

pub(crate) const CANCELED_SIGN_IN: &str = "Sign-in was canceled by a newer sign-in or disconnect.";

pub(crate) async fn lock_current<'a>(
    gate: &'a AuthOffboardingGate,
    publication: &'a tokio::sync::Mutex<()>,
    generation: u64,
) -> CoreResult<tokio::sync::MutexGuard<'a, ()>> {
    let guard = publication.lock().await;
    if gate.may_publish(generation) {
        Ok(guard)
    } else {
        Err(canceled_sign_in())
    }
}

/// Store the short-lived 2FA continuation only while its password request is
/// still current. `PendingLogin` intentionally remains memory-only and has
/// no Debug implementation.
pub(crate) async fn publish_second_factor(
    gate: &AuthOffboardingGate,
    publication: &tokio::sync::Mutex<()>,
    pending_login: &Mutex<Option<PendingLogin>>,
    pending: PendingLogin,
) -> CoreResult<()> {
    let _publication = lock_current(gate, publication, pending.generation).await?;
    *pending_login.lock().expect("pending login lock") = Some(pending);
    Ok(())
}

pub(crate) fn canceled_sign_in() -> DesktopError {
    DesktopError::InvalidState(CANCELED_SIGN_IN.to_string())
}

#[cfg(test)]
#[path = "auth_publication/tests.rs"]
mod tests;
