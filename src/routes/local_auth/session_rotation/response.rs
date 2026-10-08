use crate::model::AuthSessionReplacementResponse;

use super::{super::session_cookie, PreparedLocalSessionRotation};

impl PreparedLocalSessionRotation {
    pub(in crate::routes::local_auth) fn cookie(&self, secure: bool) -> Option<String> {
        self.login
            .as_ref()
            .map(|login| session_cookie(login, secure))
    }

    pub(in crate::routes::local_auth) fn response(
        &self,
        expose_token: bool,
    ) -> AuthSessionReplacementResponse {
        AuthSessionReplacementResponse {
            replacement_token_type: self.login.as_ref().map(|login| login.token_type.clone()),
            replacement_token: expose_token
                .then(|| self.login.as_ref().and_then(|login| login.token.clone()))
                .flatten(),
            replacement_session_id: self
                .storage
                .as_ref()
                .map(|storage| storage.session.id.clone()),
            replacement_expires_at: self
                .storage
                .as_ref()
                .map(|storage| storage.session.expires_at.clone()),
            delegated_credential_revoked: self.delegated_credential_revoked,
        }
    }
}
