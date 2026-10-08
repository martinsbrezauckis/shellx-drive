//! Resolve legacy credential keys without interpreting them as endpoint data.

use shellx_drive_desktop_core::{DesktopError, DesktopState, RemoteSessionRecord, Result};

use super::{ServiceCredentialKey, SessionIdentity};

/// Durable state supplies the endpoint. Legacy keys can contain `|` in both
/// URL paths and email local parts, so splitting a key cannot recover identity.
pub(crate) fn canonical_credential_identity(
    state: &DesktopState,
    account_key: &str,
) -> Result<SessionIdentity> {
    let identities = state
        .pairs()
        .map(|pair| identity(&pair.server_url, &pair.account_email))
        .chain(records(state).map(|record| identity(&record.server_url, &record.account_email)));
    let mut matched = None;
    for candidate in identities.filter(|candidate| candidate.credential_key() == account_key) {
        if matched.as_ref().is_some_and(|saved| saved != &candidate) {
            return Err(identity_error());
        }
        matched = Some(candidate);
    }
    matched.ok_or_else(identity_error)
}

/// Preserve the exact durable URL, email and session ID, including old keys.
/// Colliding or unattributed keys remain retained without remote/local effects.
pub(crate) fn pending_credential_slot(
    state: &DesktopState,
    account_key: &str,
) -> Result<ServiceCredentialKey> {
    let mut matched = None;
    for record in records(state) {
        let candidate = identity(&record.server_url, &record.account_email)
            .pending_service_key(&record.session_id)
            .ok_or_else(identity_error)?;
        if candidate.account_key != account_key {
            continue;
        }
        if matched.as_ref().is_some_and(|saved| saved != &candidate) {
            return Err(identity_error());
        }
        matched = Some(candidate);
    }
    matched.ok_or_else(identity_error)
}

fn records(state: &DesktopState) -> impl Iterator<Item = &RemoteSessionRecord> {
    state
        .active_remote_session
        .iter()
        .chain(state.pending_candidate_session.iter())
        .chain(state.pending_remote_revocations.iter())
}

fn identity(server_url: &str, email: &str) -> SessionIdentity {
    SessionIdentity::new(
        server_url.trim_end_matches('/'),
        email.trim().to_ascii_lowercase(),
    )
}

fn identity_error() -> DesktopError {
    DesktopError::Credential(
        "The saved Drive credential has no unambiguous durable identity; credentials were kept for recovery."
            .into(),
    )
}

#[cfg(test)]
mod tests;
