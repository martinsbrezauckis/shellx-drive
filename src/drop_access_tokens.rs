//! Stateless grants for public Drop upload workflows.
//!
//! A successful password preflight mints a short-lived proof bound to the
//! Drop's current authorization fingerprint and the requesting client. Later
//! session, chunk, and cancellation requests verify this HMAC proof instead of
//! repeating expensive password hashing. Revocation, expiry, password rotation,
//! a different client, or a different server secret invalidates the proof.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    auth::constant_time_str_eq,
    error::{ApiError, ApiResult},
};

const PREFIX: &str = "drop-access.v1.";
const MAX_TOKEN_BYTES: usize = 2_048;
pub(crate) const TTL_SECONDS: i64 = 3_600;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    drop_id: String,
    authorization_fingerprint: String,
    client_fingerprint: String,
    expires_at: i64,
}

pub(crate) fn mint(
    drop_id: &str,
    authorization_fingerprint: &str,
    client_fingerprint: &str,
    expires_at: i64,
    signing_secret: &str,
) -> ApiResult<String> {
    let claims = Claims {
        drop_id: drop_id.to_string(),
        authorization_fingerprint: authorization_fingerprint.to_string(),
        client_fingerprint: client_fingerprint.to_string(),
        expires_at,
    };
    let claims_json = serde_json::to_vec(&claims)
        .map_err(|error| ApiError::Maintenance(format!("could not encode Drop grant: {error}")))?;
    let claims_base64 = URL_SAFE_NO_PAD.encode(claims_json);
    let payload = format!("{PREFIX}{claims_base64}");
    Ok(format!("{payload}.{}", signature(&payload, signing_secret)))
}

pub(crate) fn verify(
    token: &str,
    drop_id: &str,
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
    let payload = format!("{PREFIX}{claims_base64}");
    if claims_base64.is_empty()
        || supplied_signature.is_empty()
        || !constant_time_str_eq(&signature(&payload, signing_secret), supplied_signature)
    {
        return Err(ApiError::Unauthenticated);
    }
    let claims_json = URL_SAFE_NO_PAD
        .decode(claims_base64)
        .map_err(|_| ApiError::Unauthenticated)?;
    let claims: Claims =
        serde_json::from_slice(&claims_json).map_err(|_| ApiError::Unauthenticated)?;
    if claims.expires_at <= now_epoch
        || !constant_time_str_eq(&claims.drop_id, drop_id)
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
    mac.update(b"shellx-drive-drop-access-v1\0");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_signed_expiring_and_bound_to_drop_authorization_and_client() {
        let now = 1_700_000_000;
        let token = mint("drop", "authorization", "client", now + 60, "secret").unwrap();
        assert!(verify(&token, "drop", "authorization", "client", "secret", now).is_ok());
        for candidate in [
            verify(&token, "other", "authorization", "client", "secret", now),
            verify(&token, "drop", "rotated", "client", "secret", now),
            verify(&token, "drop", "authorization", "other", "secret", now),
            verify(&token, "drop", "authorization", "client", "other", now),
            verify(
                &token,
                "drop",
                "authorization",
                "client",
                "secret",
                now + 60,
            ),
        ] {
            assert!(candidate.is_err());
        }
    }
}
