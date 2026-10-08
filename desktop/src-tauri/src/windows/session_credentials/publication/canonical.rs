//! Exact canonical credential publication and ambiguity classification.

use super::super::super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CanonicalCandidateState {
    Published,
    NotPublished,
    Unknown,
}

pub(super) fn publish_canonical_candidate(
    runtime: &Runtime,
    account_key: &str,
    bearer_token: &str,
) -> CanonicalCandidateState {
    // Always read back the exact canonical destination. In particular, an
    // error from `set` may arrive after Credential Manager accepted the
    // candidate; treating that error as a failed publication would otherwise
    // lead cleanup to revoke the newly canonical bearer.
    let write = runtime
        .platform
        .credentials()
        .set(account_key, bearer_token);
    let readback = runtime.platform.credentials().get(account_key);
    match classify_exact_credential_write(write, readback, bearer_token) {
        ExactCredentialWrite::Written => CanonicalCandidateState::Published,
        ExactCredentialWrite::NotWritten => CanonicalCandidateState::NotPublished,
        ExactCredentialWrite::Unknown => CanonicalCandidateState::Unknown,
    }
}

/// Completes a staged candidate whose active locator was durably published
/// before a crash. The exact readback treats post-write provider errors as a
/// successful promotion only when the canonical destination contains that
/// candidate.
pub(in crate::application) fn complete_staged_candidate_promotion(
    runtime: &Runtime,
    identity: &SessionIdentity,
    bearer_token: &str,
) -> CoreResult<()> {
    match publish_canonical_candidate(runtime, &identity.credential_key(), bearer_token) {
        CanonicalCandidateState::Published => Ok(()),
        CanonicalCandidateState::NotPublished => Err(DesktopError::Credential(
            "Drive credential publication was not confirmed".to_string(),
        )),
        CanonicalCandidateState::Unknown => Err(DesktopError::Credential(
            "Drive credential publication needs recovery; credentials were kept for retry"
                .to_string(),
        )),
    }
}

pub(super) fn canonical_candidate_state(
    runtime: &Runtime,
    record: &RemoteSessionRecord,
    bearer_token: &str,
) -> CanonicalCandidateState {
    let account_key =
        SessionIdentity::new(&record.server_url, &record.account_email).credential_key();
    match runtime.platform.credentials().get(&account_key) {
        Ok(Some(value)) if value == bearer_token => CanonicalCandidateState::Published,
        Ok(_) => CanonicalCandidateState::NotPublished,
        Err(_) => CanonicalCandidateState::Unknown,
    }
}
