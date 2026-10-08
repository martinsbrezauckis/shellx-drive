//! Bounded, non-secret metadata for remote sessions that still need retirement.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{DesktopError, DesktopState, Result};

mod candidate;

pub use candidate::{
    candidate_recovery_locator, compare_staged_candidate_recovery_order,
    staged_candidate_recovery_action, state_after_confirmed_remote_retirement,
    StagedCandidateRecoveryAction,
};

pub const MAX_PENDING_REMOTE_REVOCATIONS: usize = 128;
const MAX_BEARER_BYTES: usize = 16 * 1024;
const MAX_CLAIMS_BYTES: usize = 4 * 1024;
const MAX_SERVER_URL_BYTES: usize = 4 * 1024;
const MAX_ACCOUNT_EMAIL_BYTES: usize = 254;
const MAX_SESSION_ID_BYTES: usize = 128;
const LOCAL_PASSWORD_ISSUER: &str = "local-password";

/// A session locator is not an authentication capability. It is sufficient
/// only for a later authenticated same-account self-revocation request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteSessionRecord {
    pub server_url: String,
    pub account_email: String,
    pub session_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct LocalSessionClaims {
    jti: String,
    email: String,
    issuer: String,
    expires_at: i64,
}

impl RemoteSessionRecord {
    pub fn new(
        server_url: &str,
        account_email: &str,
        session_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let record = Self {
            server_url: canonical_server_url(server_url)?,
            account_email: account_email.trim().to_ascii_lowercase(),
            session_id: session_id.to_string(),
            expires_at,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn from_login_response(
        server_url: &str,
        account_email: &str,
        session_id: &str,
        expires_at: &str,
    ) -> Result<Self> {
        let expires_at = DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| {
                DesktopError::InvalidState(
                    "Drive login returned an invalid session expiry".to_string(),
                )
            })?
            .with_timezone(&Utc);
        Self::new(server_url, account_email, session_id, expires_at)
    }

    /// Recover metadata for credentials issued by an earlier desktop build or
    /// process. Claims are not trusted as authentication: the later revoke is
    /// authorized by a fresh same-account bearer and the server owns the ID.
    pub fn from_local_bearer(
        server_url: &str,
        account_email: &str,
        bearer_token: &str,
    ) -> Option<Self> {
        if bearer_token.len() > MAX_BEARER_BYTES {
            return None;
        }
        let mut parts = bearer_token.split('.');
        if parts.next()? != "sso" || parts.next()? != "v1" {
            return None;
        }
        let encoded_claims = parts.next()?;
        let signature = parts.next()?;
        if parts.next().is_some() || encoded_claims.is_empty() || signature.is_empty() {
            return None;
        }
        let claims_bytes = URL_SAFE_NO_PAD.decode(encoded_claims).ok()?;
        if claims_bytes.len() > MAX_CLAIMS_BYTES {
            return None;
        }
        let claims: LocalSessionClaims = serde_json::from_slice(&claims_bytes).ok()?;
        if claims.issuer != LOCAL_PASSWORD_ISSUER
            || !claims
                .email
                .trim()
                .eq_ignore_ascii_case(account_email.trim())
        {
            return None;
        }
        let expires_at = Utc.timestamp_opt(claims.expires_at, 0).single()?;
        Self::new(server_url, account_email, &claims.jti, expires_at).ok()
    }

    pub fn identity_matches(&self, server_url: &str, account_email: &str) -> bool {
        self.server_url == canonical_server_url(server_url).unwrap_or_default()
            && self
                .account_email
                .eq_ignore_ascii_case(account_email.trim())
    }

    pub fn same_remote_session(&self, other: &Self) -> bool {
        self.server_url == other.server_url
            && self.account_email == other.account_email
            && self.session_id == other.session_id
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !matches!(
            canonical_server_url(&self.server_url),
            Ok(canonical) if canonical == self.server_url
        ) {
            return Err(DesktopError::InvalidState(
                "remote-session server URL is not canonical or bounded".to_string(),
            ));
        }
        if self.account_email.is_empty()
            || self.account_email.len() > MAX_ACCOUNT_EMAIL_BYTES
            || self.account_email != self.account_email.trim().to_ascii_lowercase()
            || self.account_email.chars().any(char::is_whitespace)
        {
            return Err(DesktopError::InvalidState(
                "remote-session account is not canonical or bounded".to_string(),
            ));
        }
        if self.session_id.is_empty()
            || self.session_id.len() > MAX_SESSION_ID_BYTES
            || !self
                .session_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(DesktopError::InvalidState(
                "remote-session ID is not bounded or path-safe".to_string(),
            ));
        }
        Ok(())
    }
}

fn canonical_server_url(input: &str) -> Result<String> {
    if input.len() > MAX_SERVER_URL_BYTES || input.chars().any(char::is_control) {
        return Err(DesktopError::InvalidState(
            "remote-session server URL is not canonical or bounded".to_string(),
        ));
    }
    let mut url = Url::parse(input.trim()).map_err(|_| {
        DesktopError::InvalidState("remote-session server URL is invalid".to_string())
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DesktopError::InvalidState(
            "remote-session server URL violates the desktop transport policy".to_string(),
        ));
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

impl DesktopState {
    pub fn record_pending_remote_revocation(
        &mut self,
        record: RemoteSessionRecord,
        now: DateTime<Utc>,
    ) {
        self.prune_remote_sessions(now);
        if record.expires_at <= now {
            return;
        }
        self.pending_remote_revocations
            .retain(|existing| !existing.same_remote_session(&record));
        self.pending_remote_revocations.push(record);
        self.pending_remote_revocations.sort_by(|left, right| {
            left.expires_at
                .cmp(&right.expires_at)
                .then_with(|| left.server_url.cmp(&right.server_url))
                .then_with(|| left.account_email.cmp(&right.account_email))
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        let excess = self
            .pending_remote_revocations
            .len()
            .saturating_sub(MAX_PENDING_REMOTE_REVOCATIONS);
        self.pending_remote_revocations.drain(0..excess);
    }

    pub fn remove_remote_session_record(&mut self, record: &RemoteSessionRecord) {
        if self
            .active_remote_session
            .as_ref()
            .is_some_and(|active| active.same_remote_session(record))
        {
            self.active_remote_session = None;
        }
        self.pending_remote_revocations
            .retain(|existing| !existing.same_remote_session(record));
        candidate::clear_matching(self, record);
    }

    pub fn publish_active_remote_session(&mut self, record: RemoteSessionRecord) {
        self.pending_remote_revocations
            .retain(|pending| !pending.same_remote_session(&record));
        candidate::clear_matching(self, &record);
        self.active_remote_session = Some(record);
    }

    pub fn prune_remote_sessions(&mut self, now: DateTime<Utc>) {
        if self
            .active_remote_session
            .as_ref()
            .is_some_and(|record| record.expires_at <= now)
        {
            self.active_remote_session = None;
        }
        self.pending_remote_revocations
            .retain(|record| record.expires_at > now);
        candidate::prune_expired(self, now);
    }

    pub fn pending_remote_revocation_count(&self, now: DateTime<Utc>) -> usize {
        self.pending_remote_revocations
            .iter()
            .filter(|record| record.expires_at > now)
            .count()
    }

    pub fn pending_remote_revocations_for_identity(
        &self,
        server_url: &str,
        account_email: &str,
        now: DateTime<Utc>,
    ) -> Vec<RemoteSessionRecord> {
        self.pending_remote_revocations
            .iter()
            .filter(|record| {
                record.expires_at > now && record.identity_matches(server_url, account_email)
            })
            .cloned()
            .collect()
    }

    pub fn into_disconnected(mut self, now: DateTime<Utc>) -> Self {
        self.prune_remote_sessions(now);
        if let Some(active) = self.active_remote_session.take() {
            self.record_pending_remote_revocation(active, now);
        }
        if let Some(candidate) = candidate::take(&mut self) {
            self.record_pending_remote_revocation(candidate, now);
        }
        Self {
            launch_at_login: self.launch_at_login,
            pending_remote_revocations: self.pending_remote_revocations,
            pending_disconnect_cleanup: self.pending_disconnect_cleanup,
            pending_desktop_agent_disconnect: self.pending_desktop_agent_disconnect,
            ..Self::default()
        }
    }
}

#[cfg(test)]
#[path = "session_revocations/tests.rs"]
mod tests;
