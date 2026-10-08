//! Selection rules for fail-closed pending remote-session retirement.

use crate::{DesktopError, LogoutOutcome, RemoteSessionRecord, Result};

/// A pending record that names the session being published is not stale. The
/// caller publishes that exact session after the other pending records have
/// retired, which also removes its duplicate pending locator.
pub fn pending_record_requires_retirement(
    record: &RemoteSessionRecord,
    candidate: Option<&RemoteSessionRecord>,
) -> bool {
    candidate.is_none_or(|candidate| !record.same_remote_session(candidate))
}

/// A record tied to a local bearer is retired by that bearer's logout endpoint,
/// which accepts an already-invalid bearer on retry. Do not instead require
/// that bearer to authorize a second session-revocation request after a save
/// failure has made it invalid.
pub fn pending_record_requires_authorized_retirement(
    record: &RemoteSessionRecord,
    candidate: Option<&RemoteSessionRecord>,
    direct_retirements: &[RemoteSessionRecord],
) -> bool {
    pending_record_requires_retirement(record, candidate)
        && !direct_retirements
            .iter()
            .any(|direct| record.same_remote_session(direct))
}

/// Confirm a direct local-bearer logout before callers remove its locator or
/// replace/delete the credential. A transport failure never becomes a pending
/// success because that could discard the only remaining authorizer.
pub fn confirm_direct_retirement<T>(
    record: Option<T>,
    outcome: Result<LogoutOutcome>,
) -> Result<Option<T>> {
    match outcome {
        Ok(LogoutOutcome::Revoked | LogoutOutcome::AlreadyInvalid) => Ok(record),
        Err(_) => Err(DesktopError::Credential(
            "remote session retirement was not confirmed; credentials were kept for retry"
                .to_string(),
        )),
    }
}

/// Select an authorizer for one pending session. A freshly authenticated
/// same-account candidate takes precedence over retained credentials because
/// callers may already have retired the latter. If the candidate belongs to a
/// different account, retain the ordinary matching-credential fallback.
pub fn select_pending_retirement_authorizer<'a, T>(
    record: &RemoteSessionRecord,
    preferred: Option<&'a T>,
    retained: &'a [T],
    identity_matches: impl Fn(&RemoteSessionRecord, &T) -> bool,
) -> Option<&'a T> {
    preferred
        .filter(|candidate| identity_matches(record, candidate))
        .or_else(|| {
            retained
                .iter()
                .find(|credential| identity_matches(record, credential))
        })
}

#[cfg(test)]
mod tests;
