use axum::body::to_bytes;
use hmac::{Hmac, Mac};
use rusqlite::params;
use sha1::Sha1;
use tempfile::TempDir;

use crate::{
    auth::recovery_code_hash,
    config::{Config, PublicOrigin},
};

use super::*;

const EMAIL: &str = "mfa@example.test";
const OLD_PASSWORD: &str = "old-fixture-password";
const NEW_PASSWORD: &str = "new-fixture-password";
const RECOVERY_CODE: &str = "1234-5678-90ab";
// RFC 6238's SHA-1 key, encoded as base32.
const TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

struct Fixture {
    state: AppState,
    _data: TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        let state = AppState::open(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.path().to_path_buf(),
            token: "test-token".to_string(),
            bootstrap_token: None,
            e2e_enabled: true,
            email_transport: "capture".to_string(),
            email_from: "ShellX Drive <noreply@example.test>".to_string(),
            public_origin: PublicOrigin::parse("http://127.0.0.1").unwrap(),
            email_smtp_host_source: "not_configured".to_string(),
            email_smtp_port: None,
            email_smtp_user_source: "not_configured".to_string(),
            maintenance_token_source: "not_configured".to_string(),
            maintenance_sudo_source: "not_configured".to_string(),
            local_session_ttl_seconds: 2_592_000,
            office_provider_name: "Office editor".to_string(),
            office_provider_url: None,
            office_session_ttl_seconds: 900,
            hosted_mode: false,
            hosted_billing_provider: "none".to_string(),
            hosted_public_rate_limit_per_minute: 60,
            backup_max_archive_bytes: 9 * 1024 * 1024 * 1024 * 1024,
            secure_cookies: false,
            trust_proxy_headers: false,
            update_repo: None,
        })
        .unwrap();
        let password_hash = state.hash_account_password(OLD_PASSWORD).await.unwrap();
        state
            .storage
            .bootstrap_auth_account(EMAIL, &password_hash)
            .unwrap();
        // Provision the factor fixture without consuming the login proof.
        rusqlite::Connection::open(data.path().join("drive.db"))
            .unwrap()
            .execute(
                "UPDATE auth_accounts SET totp_secret = ?2, totp_enabled = 1,
                 recovery_code_hashes = ?3, security_version = security_version + 1
                 WHERE email = ?1",
                params![
                    EMAIL,
                    TOTP_SECRET,
                    serde_json::to_string(&[recovery_code_hash(RECOVERY_CODE)]).unwrap()
                ],
            )
            .unwrap();
        Self { state, _data: data }
    }

    fn account(&self) -> AuthAccountSecret {
        self.state
            .storage
            .get_auth_account_secret(EMAIL)
            .unwrap()
            .unwrap()
    }

    async fn verified_password_account(&self) -> AuthAccountSecret {
        let account = self.account();
        assert!(self
            .state
            .verify_untrusted_account_password(&account.password_hash, OLD_PASSWORD)
            .await
            .unwrap());
        account
    }

    async fn reset_password(&self) {
        let password_hash = self
            .state
            .hash_account_password(NEW_PASSWORD)
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer test-token".parse().unwrap());
        let (actor, credential) = require_admin_with_credential(&self.state, &headers).unwrap();
        self.state
            .storage
            .update_auth_account(
                EMAIL,
                None,
                None,
                Some(&password_hash),
                false,
                None,
                &actor,
                &credential,
            )
            .unwrap();
    }
}

fn client() -> ClientRequestMetadata {
    ClientRequestMetadata {
        client_ip: "127.0.0.1".to_string(),
        user_agent: Some("MFA snapshot regression".to_string()),
    }
}

fn login_request(password: &str, recovery: bool) -> LoginRequest {
    let counter = (Utc::now().timestamp() / 30) as u64;
    let mut mac = Hmac::<Sha1>::new_from_slice(b"12345678901234567890").unwrap();
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    LoginRequest {
        email: EMAIL.to_string(),
        password: password.to_string(),
        totp_code: (!recovery).then(|| format!("{:06}", binary % 1_000_000)),
        recovery_code: recovery.then(|| RECOVERY_CODE.to_string()),
        cookie_only: None,
    }
}

async fn assert_success(outcome: LoginOutcome) {
    assert_eq!(outcome.outcome, "success");
    assert!(outcome.session_id.is_some());
    assert_eq!(outcome.response.status(), StatusCode::OK);
    let body = to_bytes(outcome.response.into_body(), 16 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_eq!(body["requires_2fa"], false);
}

async fn password_reset_after_password_proof_rejects_mfa_login(recovery: bool) {
    let fixture = Fixture::new().await;
    let password_verified = fixture.verified_password_account().await;
    fixture.reset_password().await;
    let current = fixture.account();
    assert_ne!(password_verified.password_hash, current.password_hash);
    assert!(current.security_version > password_verified.security_version);
    assert_eq!(password_verified.totp_secret, current.totp_secret);
    assert_eq!(
        password_verified.recovery_code_hashes,
        current.recovery_code_hashes
    );

    // This is the production route's continuation after the awaited password
    // proof, with a completed password reset before its second-factor reread.
    let mut request = login_request(OLD_PASSWORD, recovery);
    let result = finish_password_login(
        &fixture.state,
        &client(),
        password_verified,
        request.clone(),
        "snapshot-test-client",
    );
    assert!(matches!(result, Err(ApiError::Unauthenticated)));
    assert!(fixture
        .state
        .storage
        .list_auth_sessions()
        .unwrap()
        .is_empty());
    assert_eq!(
        fixture.account().recovery_code_hashes,
        current.recovery_code_hashes
    );

    // The denied attempt must not consume the valid factor. The current
    // password can use it once, while replay cannot mint another session.
    request.password = NEW_PASSWORD.to_string();
    assert_success(
        login_inner(
            &fixture.state,
            &client(),
            &HeaderMap::new(),
            request.clone(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert!(matches!(
        login_inner(&fixture.state, &client(), &HeaderMap::new(), request).await,
        Err(ApiError::Unauthenticated)
    ));
    assert_eq!(fixture.state.storage.list_auth_sessions().unwrap().len(), 1);
}

#[tokio::test]
async fn password_reset_between_password_and_totp_rejects_login() {
    password_reset_after_password_proof_rejects_mfa_login(false).await;
}

#[tokio::test]
async fn password_reset_between_password_and_recovery_rejects_login() {
    password_reset_after_password_proof_rejects_mfa_login(true).await;
}

#[tokio::test]
async fn unchanged_mfa_password_login_succeeds_once() {
    for recovery in [false, true] {
        let fixture = Fixture::new().await;
        let request = login_request(OLD_PASSWORD, recovery);
        assert_success(
            login_inner(
                &fixture.state,
                &client(),
                &HeaderMap::new(),
                request.clone(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert!(matches!(
            login_inner(&fixture.state, &client(), &HeaderMap::new(), request).await,
            Err(ApiError::Unauthenticated)
        ));
        assert_eq!(fixture.state.storage.list_auth_sessions().unwrap().len(), 1);
    }
}
