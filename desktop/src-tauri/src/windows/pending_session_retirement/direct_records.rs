//! Records whose exact local bearer is retired through direct logout.

use super::*;

pub(in crate::application) fn direct_retirement_records(
    state: &DesktopState,
    credentials: &[StoredSessionCredential],
) -> Vec<Option<RemoteSessionRecord>> {
    credentials
        .iter()
        .map(|credential| {
            credential
                .session_id
                .as_ref()
                .and_then(|session_id| {
                    state
                        .pending_candidate_session
                        .as_ref()
                        .filter(|record| {
                            record.session_id == *session_id
                                && record.identity_matches(
                                    &credential.identity.server_url,
                                    &credential.identity.email,
                                )
                        })
                        .cloned()
                        .or_else(|| {
                            state
                                .pending_remote_revocations
                                .iter()
                                .find(|record| {
                                    record.session_id == *session_id
                                        && record.identity_matches(
                                            &credential.identity.server_url,
                                            &credential.identity.email,
                                        )
                                })
                                .cloned()
                        })
                        .or_else(|| {
                            state
                                .active_remote_session
                                .as_ref()
                                .filter(|record| {
                                    record.session_id == *session_id
                                        && record.identity_matches(
                                            &credential.identity.server_url,
                                            &credential.identity.email,
                                        )
                                })
                                .cloned()
                        })
                })
                .or_else(|| {
                    (credential.session_id.is_none())
                        .then(|| {
                            RemoteSessionRecord::from_local_bearer(
                                &credential.identity.server_url,
                                &credential.identity.email,
                                &credential.bearer_token,
                            )
                        })
                        .flatten()
                })
                .or_else(|| {
                    (credential.session_id.is_none())
                        .then(|| {
                            state
                                .active_remote_session
                                .as_ref()
                                .filter(|record| {
                                    record.identity_matches(
                                        &credential.identity.server_url,
                                        &credential.identity.email,
                                    )
                                })
                                .cloned()
                        })
                        .flatten()
                })
        })
        .collect()
}
