use chrono::{Duration, Utc};
use uuid::Uuid;

use super::LOCAL_ISSUER;

mod response;
use crate::{
    auth::{mint_sso_token_with_admin, token_hash, Actor, DriveCredential},
    error::ApiResult,
    model::{AuthAccountSecret, AuthSession, LoginResponse},
    server::{AppState, ClientRequestMetadata},
    storage::{AuthSessionReplacement, AuthSessionRotation},
};

pub(super) struct PreparedLocalSessionRotation {
    pub(super) storage: Option<AuthSessionReplacement>,
    login: Option<LoginResponse>,
    delegated_credential_revoked: bool,
}

impl PreparedLocalSessionRotation {
    pub(super) fn prepare(
        state: &AppState,
        account: &AuthAccountSecret,
        client: &ClientRequestMetadata,
    ) -> ApiResult<Self> {
        let session_id = Uuid::now_v7().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(state.config.local_session_ttl_seconds);
        let token = mint_sso_token_with_admin(
            &session_id,
            &account.email,
            LOCAL_ISSUER,
            &account.user_id,
            expires_at.timestamp(),
            account.is_admin,
            &state.config.token,
        )?;
        let login = LoginResponse {
            token_type: "Bearer".to_string(),
            token: Some(token.clone()),
            session_id: Some(session_id.clone()),
            actor: account.email.clone(),
            is_admin: account.is_admin,
            requires_2fa: false,
            expires_at: Some(expires_at.to_rfc3339()),
        };
        Ok(Self {
            storage: Some(AuthSessionReplacement {
                session: AuthSession {
                    id: session_id,
                    actor_email: account.email.clone(),
                    issuer: LOCAL_ISSUER.to_string(),
                    subject: account.user_id.clone(),
                    expires_at: expires_at.to_rfc3339(),
                    revoked_at: None,
                    created_at: now.to_rfc3339(),
                    revoked: false,
                },
                token_hash: token_hash(&token),
                client_ip: Some(client.client_ip.clone()),
                user_agent: client.user_agent.clone(),
            }),
            login: Some(login),
            delegated_credential_revoked: false,
        })
    }

    pub(super) fn for_source_credential(
        state: &AppState,
        account: &AuthAccountSecret,
        client: &ClientRequestMetadata,
        source_credential: &DriveCredential,
    ) -> ApiResult<Self> {
        match source_credential {
            DriveCredential::UserSession(_) => Self::prepare(state, account, client),
            DriveCredential::DelegatedAgentToken(_) => Ok(Self {
                storage: None,
                login: None,
                delegated_credential_revoked: true,
            }),
            _ => Err(crate::error::ApiError::Forbidden),
        }
    }

    pub(super) fn rotation<'a>(
        &'a self,
        actor: &'a Actor,
        source_credential: &'a DriveCredential,
    ) -> AuthSessionRotation<'a> {
        AuthSessionRotation {
            actor,
            source_credential,
            replacement: self.storage.as_ref(),
        }
    }
}
