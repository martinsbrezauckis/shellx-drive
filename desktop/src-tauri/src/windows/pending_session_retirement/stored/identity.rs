use super::*;

pub(super) fn parse_identity(
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

pub(super) fn invalid_saved_identity() -> DesktopError {
    DesktopError::Credential(
        "a saved Drive credential has an invalid identity; credentials were kept for retry"
            .to_string(),
    )
}
