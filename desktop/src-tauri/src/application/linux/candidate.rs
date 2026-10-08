//! Linux Secret Service pending-candidate recovery admission.

mod recovery;

use shellx_drive_desktop_core::{DesktopError, PendingLinuxCredentialStore, Result as CoreResult};

use crate::{application::Runtime, session_identity::SessionIdentity};

impl Runtime {
    /// A staged bearer may be retired only by a fresh login for the exact
    /// retained server/account identity.
    pub(super) fn require_linux_candidate_recovery_identity(
        &self,
        normalized_url: &str,
        email: &str,
    ) -> CoreResult<()> {
        if !self.candidate_recovery_pending() {
            return Ok(());
        }
        let requested = SessionIdentity::new(normalized_url, email).credential_key();
        let recorded = self
            .coordinator
            .snapshot()
            .pending_candidate_session
            .as_ref()
            .is_some_and(|record| {
                SessionIdentity::new(&record.server_url, &record.account_email).credential_key()
                    == requested
            });
        let remembered = self
            .candidate_recovery_identities
            .lock()
            .expect("candidate recovery identity lock")
            .contains(&requested);
        let staged = PendingLinuxCredentialStore::service_account_keys()?
            .iter()
            .filter_map(|key| SessionIdentity::parse_pending_service_key(key))
            .any(|slot| slot.identity.credential_key() == requested);
        if recorded || remembered || staged {
            Ok(())
        } else {
            Err(DesktopError::Credential(
                "Drive credential recovery permits sign-in only for its retained server and account"
                    .to_string(),
            ))
        }
    }

    pub(super) fn refresh_linux_candidate_recovery_pending(&self) {
        let state = self.coordinator.snapshot();
        if let Some(record) = state.pending_candidate_session.as_ref() {
            self.remember_candidate_recovery_record(record);
        }
        let pending = state.pending_candidate_session.is_some()
            || PendingLinuxCredentialStore::service_account_keys()
                .map(|slots| {
                    for key in &slots {
                        if let Some(slot) = SessionIdentity::parse_pending_service_key(key) {
                            self.remember_candidate_recovery_identity(&slot.identity);
                        }
                    }
                    !slots.is_empty()
                })
                .unwrap_or(true);
        self.set_candidate_recovery_pending(pending);
    }
}

pub(super) use recovery::recover_at_startup;
