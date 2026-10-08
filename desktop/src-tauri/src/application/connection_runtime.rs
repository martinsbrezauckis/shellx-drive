//! Per-connection credential ownership, state availability and sync deadlines.

use std::time::{Duration, Instant};

use super::{CoreResult, DesktopError, Runtime, SessionIdentity};

impl Runtime {
    pub(crate) fn ensure_state_available(&self) -> CoreResult<()> {
        if self.state_load_unavailable {
            return Err(DesktopError::InvalidState(
                "Restore the retained connection state before saving changes.".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn mark_sync_check_finished(&self) {
        *self
            .last_sync_check_finished
            .lock()
            .expect("sync check deadline lock") = Some(Instant::now());
    }

    pub(crate) fn sync_check_delay(&self, interval: Duration) -> Duration {
        self.last_sync_check_finished
            .lock()
            .expect("sync check deadline lock")
            .map_or(interval, |last| interval.saturating_sub(last.elapsed()))
    }

    pub(crate) fn set_owned_session_identity(&self, identity: SessionIdentity) {
        *self
            .owned_session_identity
            .lock()
            .expect("owned identity lock") = Some(identity);
    }

    pub(crate) fn owns_session_identity(&self, identity: &SessionIdentity) -> bool {
        self.owns_credential_key(&identity.credential_key())
    }

    pub(crate) fn owns_credential_key(&self, key: &str) -> bool {
        if self
            .owned_session_identity
            .lock()
            .expect("owned identity lock")
            .as_ref()
            .is_some_and(|identity| identity.credential_key() == key)
            || self
                .session
                .lock()
                .expect("session lock")
                .as_ref()
                .is_some_and(|identity| identity.credential_key() == key)
        {
            return true;
        }
        let state = self.coordinator.snapshot();
        state
            .pair
            .as_ref()
            .is_some_and(|pair| Self::credential_key(&pair.server_url, &pair.account_email) == key)
            || state.active_remote_session.as_ref().is_some_and(|record| {
                Self::credential_key(&record.server_url, &record.account_email) == key
            })
    }
}
