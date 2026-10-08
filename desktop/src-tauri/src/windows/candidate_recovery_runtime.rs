//! Runtime latch and exact-identity admission for candidate recovery.

use super::*;

impl Runtime {
    /// A stuck candidate cannot be resolved by arbitrary credentials. The
    /// exact recorded server/account may complete password or TOTP login so
    /// that fresh same-identity session can retire the old locator.
    pub(super) fn require_candidate_recovery_login_identity(
        &self,
        normalized_url: &str,
        email: &str,
    ) -> CoreResult<()> {
        if !self.candidate_recovery_pending() {
            return Ok(());
        }
        let requested = SessionIdentity::new(normalized_url, email).credential_key();
        let state_matches =
            candidate_recovery_locator(&self.coordinator.snapshot()).is_some_and(|record| {
                SessionIdentity::new(&record.server_url, &record.account_email).credential_key()
                    == requested
            });
        let remembered_matches = self
            .candidate_recovery_identities
            .lock()
            .expect("candidate recovery identity lock")
            .contains(&requested);
        if state_matches || remembered_matches {
            return Ok(());
        }
        let staged_matches =
            pending_session_retirement::owned_pending_slots(&self.coordinator.snapshot())?
                .iter()
                .any(|slot| slot.identity.credential_key() == requested);
        if state_matches || staged_matches {
            return Ok(());
        }
        Err(DesktopError::Credential(
            "Drive credential recovery permits sign-in only for its retained server and account"
                .to_string(),
        ))
    }

    pub(super) fn refresh_candidate_recovery_pending(&self) {
        let state = self.coordinator.snapshot();
        if let Some(record) = state.pending_candidate_session.as_ref() {
            self.remember_candidate_recovery_record(record);
        }
        let pending = state.pending_candidate_session.is_some()
            || pending_session_retirement::owned_pending_slots(&state)
                .map(|slots| {
                    let mut pending = false;
                    for slot in slots {
                        if PendingWindowsCredentialStore
                            .get(&slot.account_key)
                            .map(|bearer| bearer.is_some())
                            .unwrap_or(true)
                        {
                            self.remember_candidate_recovery_identity(&slot.identity);
                            pending = true;
                        }
                    }
                    pending
                })
                .unwrap_or(true);
        self.set_candidate_recovery_pending(pending);
    }
}
