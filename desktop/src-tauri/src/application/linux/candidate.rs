//! Linux Secret Service pending-candidate recovery admission.

mod recovery;

use std::collections::BTreeSet;

use shellx_drive_desktop_core::{
    DesktopError, DesktopState, PendingLinuxCredentialStore, Result as CoreResult,
};

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
        if recorded || remembered {
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
            || owned_pending_keys(&state)
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

/// Candidates are owned by their durable exact session locator. Another
/// connection, including a rejected duplicate sign-in, may have a pending
/// bearer for the same account; account identity alone does not admit it.
pub(super) fn pending_locator_keys(state: &DesktopState) -> BTreeSet<String> {
    state
        .pending_candidate_session
        .iter()
        .chain(state.active_remote_session.iter())
        .chain(state.pending_remote_revocations.iter())
        .filter_map(|record| {
            SessionIdentity::new(&record.server_url, &record.account_email)
                .pending_service_key(&record.session_id)
                .map(|slot| slot.account_key)
        })
        .chain(
            state
                .pending_disconnect_cleanup()
                .into_iter()
                .flat_map(|cleanup| cleanup.credential_slots.iter())
                .filter(|slot| {
                    slot.namespace
                        == shellx_drive_desktop_core::DisconnectCredentialNamespace::PendingCandidate
                })
                .map(|slot| slot.account_key.clone()),
        )
        .collect()
}

pub(super) fn owned_pending_keys(state: &DesktopState) -> CoreResult<Vec<String>> {
    let owned = pending_locator_keys(state);
    if owned.is_empty() {
        return Ok(Vec::new());
    }
    Ok(filter_owned_pending_keys(
        state,
        PendingLinuxCredentialStore::service_account_keys()?,
    ))
}

fn filter_owned_pending_keys(state: &DesktopState, keys: Vec<String>) -> Vec<String> {
    let owned = pending_locator_keys(state);
    keys.into_iter().filter(|key| owned.contains(key)).collect()
}

pub(super) use recovery::recover_at_startup;

#[cfg(test)]
#[path = "candidate/tests.rs"]
mod tests;
