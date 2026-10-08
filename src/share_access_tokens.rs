//! Stateless browser grants for unlimited public shares.
//!
//! Finite-use links keep durable database grants because each visit must be
//! consumed atomically. Unlimited links only need a short-lived proof that the
//! page passed its password check, avoiding repeated Argon2 work and durable
//! grant rows.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    auth::constant_time_str_eq,
    error::{ApiError, ApiResult},
};

const PREFIX: &str = "share-access.v1.";
const MAX_TOKEN_BYTES: usize = 1024;
pub(crate) const TTL_SECONDS: i64 = 3_600;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    share_id: String,
    authorization_fingerprint: String,
    client_fingerprint: String,
    expires_at: i64,
}

pub(crate) fn mint(
    share_id: &str,
    authorization_fingerprint: &str,
    client_fingerprint: &str,
    expires_at: i64,
    signing_secret: &str,
) -> ApiResult<String> {
    let claims = Claims {
        share_id: share_id.to_string(),
        authorization_fingerprint: authorization_fingerprint.to_string(),
        client_fingerprint: client_fingerprint.to_string(),
        expires_at,
    };
    let claims_json = serde_json::to_vec(&claims).map_err(|error| {
        ApiError::Validation(format!(
            "failed to encode unlimited share access claims: {error}"
        ))
    })?;
    let claims_base64 = URL_SAFE_NO_PAD.encode(claims_json);
    let payload = format!("{PREFIX}{claims_base64}");
    let signature = signature(&payload, signing_secret);
    Ok(format!("{payload}.{signature}"))
}

pub(crate) fn verify(
    token: &str,
    share_id: &str,
    authorization_fingerprint: &str,
    client_fingerprint: &str,
    signing_secret: &str,
    now_epoch: i64,
) -> ApiResult<()> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(ApiError::Unauthenticated);
    }
    let Some(rest) = token.strip_prefix(PREFIX) else {
        return Err(ApiError::Unauthenticated);
    };
    let Some((claims_base64, supplied_signature)) = rest.rsplit_once('.') else {
        return Err(ApiError::Unauthenticated);
    };
    if claims_base64.is_empty() || supplied_signature.is_empty() {
        return Err(ApiError::Unauthenticated);
    }
    let payload = format!("{PREFIX}{claims_base64}");
    if !constant_time_str_eq(&signature(&payload, signing_secret), supplied_signature) {
        return Err(ApiError::Unauthenticated);
    }
    let claims_json = URL_SAFE_NO_PAD
        .decode(claims_base64)
        .map_err(|_| ApiError::Unauthenticated)?;
    let claims: Claims =
        serde_json::from_slice(&claims_json).map_err(|_| ApiError::Unauthenticated)?;
    if claims.expires_at <= now_epoch
        || !constant_time_str_eq(&claims.share_id, share_id)
        || !constant_time_str_eq(&claims.authorization_fingerprint, authorization_fingerprint)
        || !constant_time_str_eq(&claims.client_fingerprint, client_fingerprint)
    {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

fn signature(payload: &str, signing_secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes())
        .expect("hmac accepts signing secrets of any length");
    mac.update(b"shellx-drive-unlimited-share-access-v1\0");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_signed_expiring_and_bound() {
        let secret = "test-signing-secret";
        let now = 1_700_000_000;
        let token = mint(
            "share-id",
            "authorization-fingerprint",
            "client-fingerprint",
            now + TTL_SECONDS,
            secret,
        )
        .unwrap();

        assert!(verify(
            &token,
            "share-id",
            "authorization-fingerprint",
            "client-fingerprint",
            secret,
            now,
        )
        .is_ok());
        assert!(verify(
            &token,
            "other-share",
            "authorization-fingerprint",
            "client-fingerprint",
            secret,
            now,
        )
        .is_err());
        assert!(verify(
            &token,
            "share-id",
            "authorization-fingerprint",
            "client-fingerprint",
            "other-secret",
            now,
        )
        .is_err());
        assert!(verify(
            &token,
            "share-id",
            "authorization-fingerprint",
            "other-client",
            secret,
            now,
        )
        .is_err());
        assert!(verify(
            &token,
            "share-id",
            "authorization-fingerprint",
            "client-fingerprint",
            secret,
            now + TTL_SECONDS,
        )
        .is_err());
    }
}
