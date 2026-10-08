use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, net::IpAddr};

use crate::{
    error::{ApiError, ApiResult},
    server::AppState,
};

const ACTOR_HEADER: &str = "x-shellx-actor";
/// Reserved identity used exclusively by the configured server operator.
///
/// It is not an account or SSO subject. Code that admits a human identity
/// must reject this value rather than treating a matching string as operator
/// authority.
pub(crate) const ADMIN_ACTOR: &str = "system@local";
const SSO_PREFIX: &str = "sso.v1.";
pub const APP_TOKEN_PREFIX: &str = "sxd_app_";
pub const AGENT_TOKEN_PREFIX: &str = "sxd_agent_";
const LOCAL_PASSWORD_ISSUER: &str = "local-password";
const MAX_PASSWORD_BYTES: usize = 1024;
/// Browser-session cookie used when HTTPS session cookies are enabled.
///
/// The `__Host-` prefix makes browsers enforce the properties Drive needs for
/// a production browser session: `Secure`, `Path=/`, and no `Domain`
/// attribute. That prevents a sibling subdomain from setting a competing
/// parent-domain cookie with the same name.
pub const HOST_SESSION_COOKIE_NAME: &str = "__Host-shellx_drive_session";

/// Cookie name used only for intentionally insecure loopback/e2e sessions.
///
/// It must never overlap the production cookie name: browsers may retain an
/// insecure local-test cookie when a user later opens a production Drive host.
pub const DEVELOPMENT_SESSION_COOKIE_NAME: &str = "shellx_drive_session_dev";
const TOTP_PERIOD_SECONDS: i64 = 30;
const TOTP_DIGITS: u32 = 1_000_000;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// Turn a network address into a stable, non-reversible throttle partition.
///
/// This throttle partition stores no raw address. The server token keys the
/// digest, so an exported attempt table cannot enumerate client addresses
/// offline. The separate security ledger and session history retain client
/// IP metadata as documented in SECURITY.md.
pub fn client_fingerprint(client_ip: IpAddr, signing_key: &str) -> String {
    let normalized = match client_ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        value => value,
    };
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .expect("HMAC accepts signing keys of any length");
    mac.update(b"shellx-drive-client-v1\0");
    mac.update(normalized.to_string().as_bytes());
    let digest = mac.finalize().into_bytes();
    format!("client-v1-{}", hex::encode(&digest[..12]))
}

/// Stable, non-secret identity for the configured operator credential.
///
/// Durable work stores this value instead of the bearer itself so rotating the
/// operator token also revokes queued work admitted by the previous token.
pub fn operator_credential_generation(signing_key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .expect("HMAC accepts signing keys of any length");
    mac.update(b"shellx-drive-operator-generation-v1\0");
    format!("operator-v1-{}", hex::encode(mac.finalize().into_bytes()))
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub email: String,
    pub is_admin: bool,
    pub auth_mode: AuthMode,
    /// `Some` permanently constrains this credential to the listed workspaces.
    /// User/admin sessions use `None` and rely on normal membership checks.
    pub allowed_workspace_ids: Option<HashSet<String>>,
}

#[derive(Debug, Clone)]
pub struct AgentActor {
    pub principal_id: String,
    pub name: String,
    pub token_id: String,
}

/// The revocable credential which authenticated a Drive actor. Derived
/// capabilities must retain this identity long enough to revalidate it in the
/// same transaction which publishes the new capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveCredential {
    Operator,
    AppToken(String),
    UserSession(String),
    /// An explicit account-wide delegation. The backing token, principal and
    /// owner are revalidated at each mutation and publication boundary.
    DelegatedAgentToken(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Operator,
    AppToken,
    DelegatedAgent,
    LocalAccount,
    Sso,
    OfficeSession,
}

#[derive(Debug, Clone)]
pub struct RequestAuditIdentity {
    pub actor_email: Option<String>,
    pub credential_kind: &'static str,
    /// A non-secret principal identifier. Middleware converts it to an opaque
    /// security-event reference before durable recording.
    pub delegated_principal_id: Option<String>,
    pub session_id: Option<String>,
    pub is_admin: bool,
}

impl AuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::AppToken => "app_token",
            Self::DelegatedAgent => "delegated_agent",
            Self::LocalAccount => "local_account",
            Self::Sso => "sso",
            Self::OfficeSession => "office_session",
        }
    }

    pub fn account_security_available(self) -> bool {
        matches!(self, Self::LocalAccount | Self::DelegatedAgent)
    }

    pub fn session_management_available(self) -> bool {
        matches!(self, Self::LocalAccount | Self::Sso | Self::DelegatedAgent)
    }

    pub fn notifications_available(self) -> bool {
        matches!(
            self,
            Self::Operator | Self::DelegatedAgent | Self::LocalAccount | Self::Sso
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoClaims {
    pub jti: String,
    pub email: String,
    pub issuer: String,
    pub subject: String,
    pub expires_at: i64,
    #[serde(default)]
    pub admin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRole {
    Viewer,
    Editor,
    Owner,
}

impl WorkspaceRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "viewer" => Some(Self::Viewer),
            "editor" => Some(Self::Editor),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
            Self::Owner => "owner",
        }
    }

    pub fn allows(self, permission: WorkspacePermission) -> bool {
        matches!(
            (self, permission),
            (Self::Owner, _)
                | (
                    Self::Editor,
                    WorkspacePermission::Read | WorkspacePermission::Write
                )
                | (Self::Viewer, WorkspacePermission::Read)
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WorkspacePermission {
    Read,
    Write,
    Manage,
}

pub fn require_drive_actor(state: &AppState, headers: &HeaderMap) -> ApiResult<Actor> {
    require_drive_actor_with_credential(state, headers).map(|(actor, _)| actor)
}

pub fn require_drive_actor_with_credential(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(Actor, DriveCredential)> {
    let token = bearer_token(headers, state.config.secure_cookies)?;
    if constant_time_str_eq(&token, state.config.token.as_str()) {
        return Ok((
            admin_actor_from_headers(headers)?,
            DriveCredential::Operator,
        ));
    }

    if token.starts_with(APP_TOKEN_PREFIX) {
        let app_token = state
            .storage
            .authenticate_app_token(&token_hash(&token), Utc::now().timestamp())?
            .ok_or(ApiError::Unauthenticated)?;
        if state
            .storage
            .get_auth_account(&app_token.actor_email)?
            .is_some_and(|account| account.disabled)
        {
            return Err(ApiError::Unauthenticated);
        }
        return Ok((
            Actor {
                email: app_token.actor_email,
                is_admin: false,
                auth_mode: AuthMode::AppToken,
                allowed_workspace_ids: Some(app_token.workspace_ids.into_iter().collect()),
            },
            DriveCredential::AppToken(app_token.id),
        ));
    }

    if token.starts_with(AGENT_TOKEN_PREFIX) {
        let delegated = state
            .storage
            .authenticate_delegated_agent_token(&token_hash(&token), Utc::now().timestamp())?
            .ok_or(ApiError::Unauthenticated)?;
        return Ok((
            Actor {
                email: delegated.owner_email,
                is_admin: delegated.owner_is_admin,
                auth_mode: AuthMode::DelegatedAgent,
                allowed_workspace_ids: None,
            },
            DriveCredential::DelegatedAgentToken(delegated.token_id),
        ));
    }

    let (actor, session_id) = require_sso_session_actor(state, &token)?;
    Ok((actor, DriveCredential::UserSession(session_id)))
}

pub fn require_admin(state: &AppState, headers: &HeaderMap) -> ApiResult<Actor> {
    require_admin_with_credential(state, headers).map(|(actor, _)| actor)
}

pub fn require_admin_with_credential(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(Actor, DriveCredential)> {
    let token = bearer_token(headers, state.config.secure_cookies)?;
    if constant_time_str_eq(&token, state.config.token.as_str()) {
        return Ok((
            Actor {
                email: ADMIN_ACTOR.to_string(),
                is_admin: true,
                auth_mode: AuthMode::Operator,
                allowed_workspace_ids: None,
            },
            DriveCredential::Operator,
        ));
    }

    let (actor, credential) = require_drive_actor_with_credential(state, headers)?;
    // App tokens are deliberately not an administrator authentication scheme;
    // preserve the authentication boundary rather than reporting them as a
    // valid, merely underprivileged admin identity.
    if matches!(credential, DriveCredential::AppToken(_)) {
        return Err(ApiError::Unauthenticated);
    }
    if !actor.is_admin {
        return Err(ApiError::Forbidden);
    }
    Ok((actor, credential))
}

/// Authenticate an interactive user identity. Application tokens are intended
/// only for workspace-scoped data operations and must not become a substitute
/// for a human session on account-wide inbox or identity-management routes.
pub fn require_user_actor(state: &AppState, headers: &HeaderMap) -> ApiResult<Actor> {
    require_user_actor_with_credential(state, headers).map(|(actor, _)| actor)
}

pub fn require_user_actor_with_credential(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(Actor, DriveCredential)> {
    let (actor, credential) = require_drive_actor_with_credential(state, headers)?;
    if actor.allowed_workspace_ids.is_some() {
        return Err(ApiError::Forbidden);
    }
    Ok((actor, credential))
}

/// Authenticate the distinct no-login credential accepted only by the
/// `/agent/v1` route family. Normal Drive authentication intentionally does
/// not recognize this prefix.
pub fn require_agent_actor(state: &AppState, headers: &HeaderMap) -> ApiResult<AgentActor> {
    let token = bearer_token(headers, state.config.secure_cookies)?;
    if !token.starts_with(AGENT_TOKEN_PREFIX) {
        return Err(ApiError::Unauthenticated);
    }
    let credential = state
        .storage
        .authenticate_agent_token(&token_hash(&token), Utc::now().timestamp())?
        .ok_or(ApiError::Unauthenticated)?;
    Ok(AgentActor {
        principal_id: credential.principal_id,
        name: credential.principal_name,
        token_id: credential.token_id,
    })
}

pub fn require_local_session_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(Actor, String)> {
    let token = bearer_token(headers, state.config.secure_cookies)?;
    if constant_time_str_eq(&token, state.config.token.as_str()) {
        return Err(ApiError::Forbidden);
    }
    require_sso_session_actor(state, &token)
}

/// Best-effort identity for the admin-only security ledger. This never returns
/// or stores credential material, and invalid credentials remain anonymous.
pub fn request_audit_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<RequestAuditIdentity> {
    let token = bearer_token(headers, state.config.secure_cookies).ok()?;
    if constant_time_str_eq(&token, state.config.token.as_str()) {
        return Some(RequestAuditIdentity {
            actor_email: Some(ADMIN_ACTOR.to_string()),
            credential_kind: "operator",
            delegated_principal_id: None,
            session_id: None,
            is_admin: true,
        });
    }
    if token.starts_with(APP_TOKEN_PREFIX) {
        let app_token = state
            .storage
            .authenticate_app_token(&token_hash(&token), Utc::now().timestamp())
            .ok()
            .flatten()?;
        if state
            .storage
            .get_auth_account(&app_token.actor_email)
            .ok()
            .flatten()
            .is_some_and(|account| account.disabled)
        {
            return None;
        }
        return Some(RequestAuditIdentity {
            actor_email: None,
            credential_kind: "app_token",
            delegated_principal_id: None,
            session_id: None,
            is_admin: false,
        });
    }
    if token.starts_with(AGENT_TOKEN_PREFIX) {
        if let Some(delegated) = state
            .storage
            .authenticate_delegated_agent_token(&token_hash(&token), Utc::now().timestamp())
            .ok()
            .flatten()
        {
            return Some(RequestAuditIdentity {
                actor_email: Some(delegated.owner_email),
                credential_kind: "delegated_agent_token",
                delegated_principal_id: Some(delegated.principal_id),
                session_id: None,
                is_admin: delegated.owner_is_admin,
            });
        }
        state
            .storage
            .authenticate_agent_token(&token_hash(&token), Utc::now().timestamp())
            .ok()
            .flatten()?;
        return Some(RequestAuditIdentity {
            actor_email: None,
            credential_kind: "agent_token",
            delegated_principal_id: None,
            session_id: None,
            is_admin: false,
        });
    }
    let (actor, session_id) = require_sso_session_actor(state, &token).ok()?;
    let is_admin = actor.is_admin;
    Some(RequestAuditIdentity {
        actor_email: Some(actor.email),
        credential_kind: if actor.auth_mode == AuthMode::LocalAccount {
            "local_session"
        } else {
            "sso_session"
        },
        delegated_principal_id: None,
        session_id: Some(session_id),
        is_admin,
    })
}

fn require_sso_session_actor(state: &AppState, token: &str) -> ApiResult<(Actor, String)> {
    let Some(claims) = verify_sso_token(token, &state.config.token, Utc::now().timestamp())? else {
        return Err(ApiError::Unauthenticated);
    };
    state.storage.ensure_auth_session_active(
        &claims.jti,
        &token_hash(token),
        Utc::now().timestamp(),
    )?;
    let mut is_admin = claims.admin;
    if claims.issuer == LOCAL_PASSWORD_ISSUER {
        let account = state
            .storage
            .get_auth_account(&claims.email)?
            .ok_or(ApiError::Unauthenticated)?;
        if account.disabled {
            return Err(ApiError::Unauthenticated);
        }
        is_admin = account.is_admin;
    }
    Ok((
        Actor {
            email: claims.email,
            is_admin,
            auth_mode: if claims.issuer == LOCAL_PASSWORD_ISSUER {
                AuthMode::LocalAccount
            } else {
                AuthMode::Sso
            },
            allowed_workspace_ids: None,
        },
        claims.jti,
    ))
}

fn admin_actor_from_headers(headers: &HeaderMap) -> ApiResult<Actor> {
    let Some(value) = headers.get(ACTOR_HEADER) else {
        return Ok(Actor {
            email: ADMIN_ACTOR.to_string(),
            is_admin: true,
            auth_mode: AuthMode::Operator,
            allowed_workspace_ids: None,
        });
    };
    let email = value
        .to_str()
        .map_err(|_| ApiError::Validation("actor header must be valid utf-8".to_string()))?
        .trim();
    if email.is_empty() {
        return Err(ApiError::Validation(
            "actor header must not be empty".to_string(),
        ));
    }
    Ok(Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    })
}

pub fn mint_sso_token(
    jti: &str,
    email: &str,
    issuer: &str,
    subject: &str,
    expires_at: i64,
    signing_secret: &str,
) -> ApiResult<String> {
    mint_sso_token_with_admin(
        jti,
        email,
        issuer,
        subject,
        expires_at,
        false,
        signing_secret,
    )
}

pub fn mint_sso_token_with_admin(
    jti: &str,
    email: &str,
    issuer: &str,
    subject: &str,
    expires_at: i64,
    admin: bool,
    signing_secret: &str,
) -> ApiResult<String> {
    let claims = SsoClaims {
        jti: jti.to_string(),
        email: email.to_string(),
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        expires_at,
        admin,
    };
    let claims_json = serde_json::to_vec(&claims)
        .map_err(|error| ApiError::Validation(format!("failed to encode sso claims: {error}")))?;
    let claims_base64 = URL_SAFE_NO_PAD.encode(claims_json);
    let payload = format!("sso.v1.{claims_base64}");
    let signature = sso_signature(&payload, signing_secret);
    Ok(format!("{payload}.{signature}"))
}

pub fn normalize_email(email: &str) -> ApiResult<String> {
    let normalized = email.trim().to_ascii_lowercase();
    if normalized.len() < 3
        || normalized.len() > 254
        || !normalized.contains('@')
        || normalized.contains(char::is_whitespace)
    {
        return Err(ApiError::Validation("email must be valid".to_string()));
    }
    Ok(normalized)
}

/// Normalize an identity which will be persisted or accepted as a human
/// account/SSO subject. The internal operator marker is deliberately not a
/// human identity, even when it has the same syntactic form as an email.
pub fn normalize_user_email(email: &str) -> ApiResult<String> {
    let normalized = normalize_email(email)?;
    ensure_not_reserved_user_email(&normalized)?;
    Ok(normalized)
}

/// Reject the reserved operator marker while preserving callers that merely
/// need to normalize an existing identity for lookup or audit purposes.
pub fn ensure_not_reserved_user_email(email: &str) -> ApiResult<()> {
    if email.trim().eq_ignore_ascii_case(ADMIN_ACTOR) {
        return Err(ApiError::Validation(
            "email is reserved for the server operator".to_string(),
        ));
    }
    Ok(())
}

pub fn hash_account_password(password: &str) -> ApiResult<String> {
    validate_account_password(password)?;
    let salt = SaltString::generate(&mut OsRng);
    password_argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| ApiError::Validation(format!("failed to hash password: {error}")))
}

pub fn verify_account_password(encoded: &str, password: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    password_argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn validate_account_password(password: &str) -> ApiResult<()> {
    if password.len() < 12 {
        return Err(ApiError::Validation(
            "password must be at least 12 characters".to_string(),
        ));
    }
    validate_password_size(password)?;
    Ok(())
}

fn validate_password_size(password: &str) -> ApiResult<()> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(ApiError::Validation(format!(
            "password must be {MAX_PASSWORD_BYTES} bytes or shorter"
        )));
    }
    Ok(())
}

pub fn generate_totp_secret() -> String {
    let mut bytes = [0_u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

pub fn totp_uri(secret: &str, email: &str) -> String {
    format!(
        "otpauth://totp/ShellX%20Drive:{}?secret={}&issuer=ShellX%20Drive&algorithm=SHA1&digits=6&period=30",
        percent_encode(email),
        secret
    )
}

pub fn matched_totp_counter(secret: &str, code: &str, now_epoch: i64) -> Option<i64> {
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    [-1_i64, 0, 1]
        .into_iter()
        .filter_map(|offset| {
            let step_time = now_epoch + offset * TOTP_PERIOD_SECONDS;
            (step_time >= 0
                && totp_code_at(secret, step_time)
                    .is_some_and(|expected| constant_time_str_eq(&expected, trimmed)))
            .then_some(step_time / TOTP_PERIOD_SECONDS)
        })
        // Adjacent counters can very rarely produce the same six-digit value.
        // Select the greatest accepted counter so the replay ledger remains
        // monotonic and cannot accept that value again through a later window.
        .max()
}

pub fn verify_totp_code(secret: &str, code: &str, now_epoch: i64) -> bool {
    matched_totp_counter(secret, code, now_epoch).is_some()
}

fn totp_code_at(secret: &str, unix_time: i64) -> Option<String> {
    let key = base32_decode(secret)?;
    let counter = (unix_time / TOTP_PERIOD_SECONDS) as u64;
    let mut msg = [0_u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());
    let mut mac = HmacSha1::new_from_slice(&key).ok()?;
    mac.update(&msg);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    Some(format!("{:06}", binary % TOTP_DIGITS))
}

pub fn generate_recovery_codes() -> Vec<String> {
    (0..10)
        .map(|_| {
            let mut bytes = [0_u8; 6];
            rand::thread_rng().fill_bytes(&mut bytes);
            let raw = hex::encode(bytes);
            format!("{}-{}-{}", &raw[0..4], &raw[4..8], &raw[8..12])
        })
        .collect()
}

pub fn random_secret_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn recovery_code_hash(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(normalize_recovery_code(code).as_bytes());
    hex::encode(hasher.finalize())
}

pub fn normalize_recovery_code(code: &str) -> String {
    code.trim()
        .chars()
        .filter(|ch| *ch != '-' && !ch.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect()
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0_u32;
    let mut bits_left = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | (*byte as u32);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            out.push(ALPHABET[((buffer >> bits_left) & 0x1f) as usize] as char);
        }
    }
    if bits_left > 0 {
        out.push(ALPHABET[((buffer << (5 - bits_left)) & 0x1f) as usize] as char);
    }
    out
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut bits = 0_u32;
    let mut bit_count = 0_u8;
    let mut out = Vec::new();
    for ch in input.chars().filter(|ch| *ch != '=') {
        let value = match ch.to_ascii_uppercase() {
            'A'..='Z' => ch.to_ascii_uppercase() as u8 - b'A',
            '2'..='7' => ch as u8 - b'2' + 26,
            _ => return None,
        } as u32;
        bits = (bits << 5) | value;
        bit_count += 5;
        while bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    Some(out)
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => {
                vec![byte as char]
            }
            b' ' => vec!['%', '2', '0'],
            other => format!("%{other:02X}").chars().collect(),
        })
        .collect()
}

fn verify_sso_token(
    token: &str,
    signing_secret: &str,
    now_epoch: i64,
) -> ApiResult<Option<SsoClaims>> {
    let Some(rest) = token.strip_prefix(SSO_PREFIX) else {
        return Ok(None);
    };
    let Some((claims_base64, signature)) = rest.rsplit_once('.') else {
        return Err(ApiError::Unauthenticated);
    };
    let payload = format!("sso.v1.{claims_base64}");
    if !constant_time_str_eq(&sso_signature(&payload, signing_secret), signature) {
        return Err(ApiError::Unauthenticated);
    }
    let claims_json = URL_SAFE_NO_PAD
        .decode(claims_base64)
        .map_err(|_| ApiError::Unauthenticated)?;
    let claims: SsoClaims =
        serde_json::from_slice(&claims_json).map_err(|_| ApiError::Unauthenticated)?;
    if claims.expires_at <= now_epoch
        || claims.jti.trim().is_empty()
        || claims.email.trim().is_empty()
        || claims.issuer.trim().is_empty()
        || claims.subject.trim().is_empty()
    {
        return Err(ApiError::Unauthenticated);
    }
    Ok(Some(claims))
}

pub(crate) fn explicit_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.trim().is_empty())
}

/// Return the cookie name selected by the resolved configuration.
///
/// `secure_cookies=false` is only for loopback/e2e development. It receives a
/// distinct name so an insecure local cookie cannot collide with the
/// production `__Host-` session cookie.
pub(crate) fn session_cookie_name(secure_cookies: bool) -> &'static str {
    if secure_cookies {
        HOST_SESSION_COOKIE_NAME
    } else {
        DEVELOPMENT_SESSION_COOKIE_NAME
    }
}

fn bearer_token(headers: &HeaderMap, secure_cookies: bool) -> ApiResult<String> {
    if let Some(token) = explicit_bearer_token(headers) {
        return Ok(token.to_string());
    }
    session_cookie_token(headers, session_cookie_name(secure_cookies))
}

/// Parse all `Cookie` headers and accept exactly one non-empty selected
/// session cookie. Duplicate selected cookies are ambiguous and are rejected
/// rather than choosing whichever header or pair happens to be read first.
///
/// A malformed selected cookie is also rejected. Other cookies remain opaque
/// to Drive, so unrelated malformed extension cookies do not alter Drive's
/// authentication decision.
fn session_cookie_token(headers: &HeaderMap, selected_name: &str) -> ApiResult<String> {
    let mut selected = None;
    for header_value in headers.get_all(header::COOKIE).iter() {
        let raw_header = header_value
            .to_str()
            .map_err(|_| ApiError::Unauthenticated)?;
        for raw_part in raw_header.split(';') {
            let part = raw_part.trim();
            if part.is_empty() {
                continue;
            }

            let Some((name, value)) = part.split_once('=') else {
                if part == selected_name {
                    return Err(ApiError::Unauthenticated);
                }
                continue;
            };
            if name != selected_name {
                continue;
            }
            if value.is_empty() || selected.replace(value.to_string()).is_some() {
                return Err(ApiError::Unauthenticated);
            }
        }
    }
    selected.ok_or(ApiError::Unauthenticated)
}

/// True only when the request has one valid selected browser-session cookie.
/// The CSRF middleware uses this to decide whether a browser write needs an
/// origin check; the authentication path repeats the same strict parse before
/// accepting a session.
pub(crate) fn has_session_cookie(headers: &HeaderMap, secure_cookies: bool) -> bool {
    session_cookie_token(headers, session_cookie_name(secure_cookies)).is_ok()
}

pub fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Correlate repeated access to a capability or object without persisting its
/// raw URL, id, or token-bearing path.
pub fn opaque_audit_ref(value: &str, signing_key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .expect("HMAC accepts signing keys of any length");
    mac.update(b"shellx-drive-audit-target-v1\0");
    mac.update(value.as_bytes());
    let digest = mac.finalize().into_bytes();
    format!("target-v1-{}", hex::encode(&digest[..12]))
}

fn sso_signature(payload: &str, signing_secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes())
        .expect("hmac accepts signing secrets of any length");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn hash_password(password: &str) -> ApiResult<String> {
    validate_password_size(password)?;
    let salt = SaltString::generate(&mut OsRng);
    password_argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| ApiError::Validation(format!("failed to hash password: {error}")))
}

pub fn verify_password(encoded: &str, password: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    if encoded.starts_with("$argon2") {
        let Ok(parsed) = PasswordHash::new(encoded) else {
            return false;
        };
        return password_argon2()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }

    let mut parts = encoded.split('$');
    let Some("sha256") = parts.next() else {
        return false;
    };
    let Some(salt_hex) = parts.next() else {
        return false;
    };
    let Some(expected) = parts.next() else {
        return false;
    };
    parts.next().is_none() && constant_time_str_eq(&password_digest(salt_hex, password), expected)
}

fn password_digest(salt_hex: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update(b":");
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

fn password_argon2() -> Argon2<'static> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .expect("fixed Argon2id password parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn constant_time_str_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = *left.get(index).unwrap_or(&0);
        let right_byte = *right.get(index).unwrap_or(&0);
        diff |= (left_byte ^ right_byte) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn sso_token_expiry_is_end_exclusive_at_the_exact_epoch() {
        let now_epoch = 1_800_000_000;
        let token = mint_sso_token(
            "expiry-boundary-session",
            "person@example.test",
            "test-issuer",
            "test-subject",
            now_epoch,
            "test-signing-secret",
        )
        .unwrap();

        assert!(
            verify_sso_token(&token, "test-signing-secret", now_epoch - 1)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            verify_sso_token(&token, "test-signing-secret", now_epoch),
            Err(ApiError::Unauthenticated)
        ));
    }

    #[test]
    fn session_cookie_parser_reads_all_headers_and_rejects_ambiguous_selected_pairs() {
        let secure_name = session_cookie_name(true);

        let mut across_headers = HeaderMap::new();
        across_headers.append(header::COOKIE, HeaderValue::from_static("other=ignored"));
        across_headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{secure_name}=accepted-token")).unwrap(),
        );
        assert_eq!(
            session_cookie_token(&across_headers, secure_name).unwrap(),
            "accepted-token"
        );
        assert!(has_session_cookie(&across_headers, true));

        let mut duplicate_across_headers = HeaderMap::new();
        duplicate_across_headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{secure_name}=first")).unwrap(),
        );
        duplicate_across_headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{secure_name}=second")).unwrap(),
        );
        assert!(session_cookie_token(&duplicate_across_headers, secure_name).is_err());
        assert!(!has_session_cookie(&duplicate_across_headers, true));

        let mut malformed_selected = HeaderMap::new();
        malformed_selected.append(header::COOKIE, HeaderValue::from_str(secure_name).unwrap());
        assert!(session_cookie_token(&malformed_selected, secure_name).is_err());

        let mut legacy_production = HeaderMap::new();
        legacy_production.append(
            header::COOKIE,
            HeaderValue::from_static("shellx_drive_session=legacy-token"),
        );
        assert!(session_cookie_token(&legacy_production, secure_name).is_err());
    }

    #[test]
    fn explicit_bearer_precedes_invalid_or_duplicated_session_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer explicit-bearer"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-shellx_drive_session=first"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-shellx_drive_session=second"),
        );

        assert_eq!(
            bearer_token(&headers, true).unwrap(),
            "explicit-bearer",
            "an explicit bearer credential must retain precedence over cookies"
        );
    }
}
