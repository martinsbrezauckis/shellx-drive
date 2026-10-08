use super::*;

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
    fallback: Option<&SessionIdentity>,
) -> CoreResult<Vec<StoredSessionCredential>> {
    let canonical = WindowsCredentialStore::service_account_keys()?
        .into_iter()
        .map(|key| (CredentialNamespace::Canonical, key));
    let pending = PendingWindowsCredentialStore::service_account_keys()?
        .into_iter()
        .map(|key| (CredentialNamespace::PendingCandidate, key));
    canonical
        .chain(pending)
        .map(|(namespace, account_key)| {
            let (identity, session_id) = parse_identity(namespace, &account_key, fallback)?;
            let bearer_token = read_bearer(runtime, namespace, &account_key)?;
            Ok(StoredSessionCredential {
                identity,
                session_id,
                bearer_token,
            })
        })
        .collect()
}

fn parse_identity(
    namespace: CredentialNamespace,
    account_key: &str,
    fallback: Option<&SessionIdentity>,
) -> CoreResult<(SessionIdentity, Option<String>)> {
    match namespace {
        CredentialNamespace::Canonical => {
            SessionIdentity::parse_canonical_credential_key(account_key)
                .or_else(|| {
                    fallback
                        .filter(|identity| identity.credential_key() == account_key)
                        .cloned()
                })
                .map(|identity| (identity, None))
                .ok_or_else(invalid_saved_identity)
        }
        CredentialNamespace::PendingCandidate => {
            let pending = SessionIdentity::parse_pending_service_key(account_key)
                .ok_or_else(invalid_saved_identity)?;
            Ok((pending.identity, Some(pending.session_id)))
        }
    }
}

fn read_bearer(
    runtime: &Runtime,
    namespace: CredentialNamespace,
    account_key: &str,
) -> CoreResult<String> {
    let bearer = match namespace {
        CredentialNamespace::Canonical => runtime.platform.credentials().get(account_key)?,
        CredentialNamespace::PendingCandidate => PendingWindowsCredentialStore.get(account_key)?,
    };
    bearer.ok_or_else(missing_saved_credential)
}

fn invalid_saved_identity() -> DesktopError {
    DesktopError::Credential(
        "a saved Drive credential has an invalid identity; credentials were kept for retry"
            .to_string(),
    )
}

fn missing_saved_credential() -> DesktopError {
    DesktopError::Credential(
        "a saved Drive credential could not be read; credentials were kept for retry".to_string(),
    )
}
