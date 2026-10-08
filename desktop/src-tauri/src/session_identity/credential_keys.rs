use super::SessionIdentity;

const PENDING_SLOT_SUFFIX: &str = "|shellx-session:";
const MAX_SESSION_ID_BYTES: usize = 128;

/// A bounded, non-secret account key within the dedicated pending-candidate
/// Credential Manager service. It is never stored in the canonical service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceCredentialKey {
    pub(crate) account_key: String,
    pub(crate) identity: SessionIdentity,
    pub(crate) session_id: String,
}

impl SessionIdentity {
    pub(crate) fn credential_key(&self) -> String {
        Self::credential_key_for(&self.server_url, &self.email)
    }

    pub(crate) fn credential_key_for(server_url: &str, email: &str) -> String {
        format!(
            "{}|{}",
            server_url.trim_end_matches('/'),
            email.trim().to_ascii_lowercase()
        )
    }

    pub(crate) fn pending_service_key(&self, session_id: &str) -> Option<ServiceCredentialKey> {
        valid_session_id(session_id).then(|| ServiceCredentialKey {
            account_key: format!(
                "{}{}{}",
                self.credential_key(),
                PENDING_SLOT_SUFFIX,
                session_id
            ),
            identity: self.clone(),
            session_id: session_id.to_string(),
        })
    }

    /// The canonical service accepts only this unadorned key. The first
    /// delimiter is authoritative because a URL cannot contain `|`, while an
    /// email local part may.
    pub(crate) fn parse_canonical_credential_key(account_key: &str) -> Option<Self> {
        let (server_url, email) = account_key.split_once('|')?;
        if server_url.is_empty() || email.is_empty() {
            return None;
        }
        let identity = Self::new(server_url, email);
        (identity.credential_key() == account_key).then_some(identity)
    }

    /// Pending candidates are parsed only from their separate fixed service.
    pub(crate) fn parse_pending_service_key(account_key: &str) -> Option<ServiceCredentialKey> {
        let (identity_key, session_id) = account_key.rsplit_once(PENDING_SLOT_SUFFIX)?;
        let identity = Self::parse_canonical_credential_key(identity_key)?;
        valid_session_id(session_id).then(|| ServiceCredentialKey {
            account_key: account_key.to_string(),
            identity,
            session_id: session_id.to_string(),
        })
    }
}

fn valid_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= MAX_SESSION_ID_BYTES
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
