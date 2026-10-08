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
        let staged_matches = PendingWindowsCredentialStore::service_account_keys()
            .map_err(|_| candidate_recovery_error())?
            .into_iter()
            .map(|account_key| {
                SessionIdentity::parse_pending_service_key(&account_key)
                    .ok_or_else(candidate_recovery_error)
            })
            .collect::<CoreResult<Vec<_>>>()?
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
            || PendingWindowsCredentialStore::service_account_keys()
                .map(|slots| {
                    for account_key in &slots {
                        if let Some(slot) = SessionIdentity::parse_pending_service_key(account_key)
                        {
                            self.remember_candidate_recovery_identity(&slot.identity);
                        }
                    }
                    !slots.is_empty()
                })
                .unwrap_or(true);
        self.set_candidate_recovery_pending(pending);
    }
}

fn candidate_recovery_error() -> DesktopError {
    DesktopError::Credential(
        "Drive credential recovery must finish before sign-in, pairing, or sync".to_string(),
    )
}
