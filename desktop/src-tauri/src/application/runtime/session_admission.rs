//! Exact-bearer session retirement and pairing-response ownership checks.

use shellx_drive_desktop_core::{
    classify_exact_credential_removal, sync_pair_identity_matches, DesktopError,
    ExactCredentialRemoval, Result as CoreResult,
};

use crate::{application::Runtime, session_identity::SessionIdentity};

impl Runtime {
    /// Pairing rechecks its captured identity while it owns the terminal
    /// publication lock. A retained pair can add roots after restart without
    /// an ephemeral setup session; Disconnect or a newer sign-in must win.
    pub(crate) fn require_captured_setup_session_during_publication(
        &self,
        session: &SessionIdentity,
        captured_bearer: &str,
    ) -> CoreResult<()> {
        let paired = self.coordinator.snapshot().pair;
        let current = self.session.lock().expect("session lock");
        let owns_session = if let Some(pair) = paired.as_ref() {
            sync_pair_identity_matches(pair, &session.server_url, &session.email)
                && current.as_ref().is_none_or(|current| current == session)
        } else {
            current.as_ref() == Some(session)
        };
        drop(current);
        if !owns_session
            || self
                .platform
                .credentials()
                .get(&session.credential_key())?
                .as_deref()
                != Some(captured_bearer)
        {
            return Err(DesktopError::NeedsReconnect);
        }
        Ok(())
    }

    /// Retire only the exact bearer that a Drive 401 rejected. The publication
    /// lock prevents a late response from removing a newer session.
    pub(crate) async fn invalidate_captured_pair_credential(
        &self,
        session: &SessionIdentity,
        captured_bearer: &str,
    ) -> CoreResult<bool> {
        let _publication = self.auth_publication.lock().await;
        self.invalidate_captured_pair_credential_during_publication(session, captured_bearer)
    }

    /// Same exact-bearer admission while pairing already owns
    /// `auth_publication`; awaiting the public method there would deadlock.
    pub(crate) fn invalidate_captured_pair_credential_during_publication(
        &self,
        session: &SessionIdentity,
        captured_bearer: &str,
    ) -> CoreResult<bool> {
        let paired = self.coordinator.snapshot().pair;
        if let Some(pair) = paired.as_ref() {
            if !sync_pair_identity_matches(pair, &session.server_url, &session.email) {
                return Ok(false);
            }
        } else if self.session.lock().expect("session lock").as_ref() != Some(session) {
            return Ok(false);
        }
        let key = session.credential_key();
        if self.platform.credentials().get(&key)?.as_deref() != Some(captured_bearer) {
            return Ok(false);
        }
        let removal = classify_exact_credential_removal(
            self.platform.credentials().delete(&key),
            self.platform.credentials().get(&key),
        );
        match removal {
            ExactCredentialRemoval::Removed => {
                if paired.is_none() {
                    let mut current = self.session.lock().expect("session lock");
                    if current.as_ref() == Some(session) {
                        *current = None;
                    }
                }
                Ok(true)
            }
            ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => {
                Err(DesktopError::Credential(
                    "Drive rejected the saved session, but protected credential removal was not confirmed."
                        .to_string(),
                ))
            }
        }
    }
}
