mod credential_keys;

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
pub(crate) use credential_keys::ServiceCredentialKey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionIdentity {
    pub(crate) server_url: String,
    pub(crate) email: String,
}

impl SessionIdentity {
    pub(crate) fn new(server_url: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            email: email.into(),
        }
    }
}

/// A server that reissues the exact same bearer for the same canonical account
/// key must not have that bearer revoked while the local record is replaced.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn stored_credential_needs_remote_retirement(
    stored_identity: &SessionIdentity,
    stored_token: &str,
    candidate: Option<(&SessionIdentity, &str)>,
) -> bool {
    candidate.is_none_or(|(candidate_identity, candidate_token)| {
        stored_identity.credential_key() != candidate_identity.credential_key()
            || stored_token != candidate_token
    })
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn disconnect_identity(
    session: Option<SessionIdentity>,
    retained_pair: Option<SessionIdentity>,
) -> Option<SessionIdentity> {
    session.or(retained_pair)
}

#[cfg(test)]
#[path = "session_identity/tests.rs"]
mod tests;
