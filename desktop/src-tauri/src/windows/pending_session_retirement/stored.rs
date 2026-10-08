use super::*;

#[path = "stored/identity.rs"]
mod identity;
#[cfg(test)]
#[path = "stored/tests.rs"]
mod tests;

use identity::{invalid_saved_identity, parse_identity};

#[derive(Clone)]
pub(in crate::application) struct StoredSessionCredential {
    pub(crate) identity: SessionIdentity,
    pub(crate) session_id: Option<String>,
    pub(crate) bearer_token: String,
}

impl StoredSessionCredential {
    pub(in crate::application) fn candidate(
        identity: &SessionIdentity,
        bearer_token: &str,
    ) -> Self {
        Self {
            identity: identity.clone(),
            session_id: None,
            bearer_token: bearer_token.to_string(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CredentialNamespace {
    Canonical,
    PendingCandidate,
}

pub(in crate::application) fn stored_session_credentials(
    runtime: &Runtime,
    state: &DesktopState,
    fallback: Option<&SessionIdentity>,
) -> CoreResult<Vec<StoredSessionCredential>> {
    let canonical = owned_canonical_keys(runtime, state, fallback)
        .into_iter()
        .map(|key| (CredentialNamespace::Canonical, key));
    let pending = owned_pending_slots(state)?
        .into_iter()
        .map(|slot| (CredentialNamespace::PendingCandidate, slot.account_key));
    let mut stored = Vec::new();
    for (namespace, account_key) in canonical.chain(pending) {
        let (identity, session_id) = parse_identity(namespace, &account_key, fallback)?;
        let bearer = match namespace {
            CredentialNamespace::Canonical => runtime.platform.credentials().get(&account_key)?,
            CredentialNamespace::PendingCandidate => {
                PendingWindowsCredentialStore.get(&account_key)?
            }
        };
        if let Some(bearer_token) = bearer {
            stored.push(StoredSessionCredential {
                identity,
                session_id,
                bearer_token,
            });
        }
    }
    Ok(stored)
}

/// Canonical ownership comes from the catalog-bound identity, never from a
/// rejected candidate locator whose identity may belong to another runtime.
pub(in crate::application::windows) fn owned_canonical_keys(
    runtime: &Runtime,
    state: &DesktopState,
    fallback: Option<&SessionIdentity>,
) -> std::collections::BTreeSet<String> {
    state
        .pairs()
        .map(|pair| SessionIdentity::new(&pair.server_url, &pair.account_email))
        .chain(
            state
                .active_remote_session
                .iter()
                .map(|record| SessionIdentity::new(&record.server_url, &record.account_email)),
        )
        .chain(
            state
                .pending_candidate_session
                .iter()
                .chain(state.pending_remote_revocations.iter())
                .map(|record| SessionIdentity::new(&record.server_url, &record.account_email)),
        )
        .chain(fallback.cloned())
        .filter(|identity| runtime.owns_session_identity(identity))
        .map(|identity| identity.credential_key())
        .collect()
}

/// Pending slots are owned by exact durable session locators, including a
/// rejected duplicate's fresh session awaiting retirement. Do not enumerate
/// all slots for the identity or adopt an unattributed provider slot.
pub(in crate::application::windows) fn owned_pending_slots(
    state: &DesktopState,
) -> CoreResult<Vec<ServiceCredentialKey>> {
    let mut slots = std::collections::BTreeMap::new();
    for record in state
        .pending_candidate_session
        .iter()
        .chain(state.active_remote_session.iter())
        .chain(state.pending_remote_revocations.iter())
    {
        let slot = SessionIdentity::new(&record.server_url, &record.account_email)
            .pending_service_key(&record.session_id)
            .ok_or_else(invalid_saved_identity)?;
        slots.insert(slot.account_key.clone(), slot);
    }
    Ok(slots.into_values().collect())
}
