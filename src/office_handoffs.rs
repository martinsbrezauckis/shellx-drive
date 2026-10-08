//! One-time, bounded browser handoffs for external Office providers.
//!
//! The durable Office session bearer never appears in a launch URL. The Drive
//! UI receives only a short-lived one-use handle; redeeming it returns an
//! auto-submitting POST form whose body is delivered directly to the provider.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{
    auth::{random_secret_token, token_hash},
    error::{ApiError, ApiResult},
};

const HANDOFF_TTL: Duration = Duration::from_secs(60);
const MAX_HANDOFFS: usize = 64;
const MAX_HANDOFFS_PER_ACTOR: usize = 4;

#[derive(Clone, Default)]
pub(crate) struct OfficeHandoffs {
    inner: Arc<Mutex<HashMap<String, OfficeHandoff>>>,
}

pub(crate) struct OfficeHandoff {
    pub provider_url: String,
    pub session_token: String,
    pub file_id: String,
    pub save_url: String,
    pub session_url: String,
    pub package_url: String,
    pub commit_url: String,
    partition_key: String,
    expires_at: Instant,
}

pub(crate) struct NewOfficeHandoff {
    pub provider_url: String,
    pub session_token: String,
    pub file_id: String,
    pub save_url: String,
    pub session_url: String,
    pub package_url: String,
    pub commit_url: String,
    pub actor_email: String,
}

impl OfficeHandoffs {
    pub(crate) fn issue(&self, handoff: NewOfficeHandoff) -> ApiResult<String> {
        let partition_key = token_hash(&format!(
            "office-handoff-partition\0{}",
            handoff.actor_email
        ));
        let mut handoffs = self.inner.lock().expect("office handoff lock poisoned");
        let now = Instant::now();
        handoffs.retain(|_, handoff| handoff.expires_at > now);
        let actor_count = handoffs
            .values()
            .filter(|handoff| handoff.partition_key == partition_key)
            .count();
        if handoffs.len() >= MAX_HANDOFFS || actor_count >= MAX_HANDOFFS_PER_ACTOR {
            return Err(ApiError::TooManyRequests);
        }

        let raw = random_secret_token();
        handoffs.insert(
            token_hash(&raw),
            OfficeHandoff {
                provider_url: handoff.provider_url,
                session_token: handoff.session_token,
                file_id: handoff.file_id,
                save_url: handoff.save_url,
                session_url: handoff.session_url,
                package_url: handoff.package_url,
                commit_url: handoff.commit_url,
                partition_key,
                expires_at: now + HANDOFF_TTL,
            },
        );
        Ok(raw)
    }

    pub(crate) fn redeem(&self, raw: &str) -> ApiResult<OfficeHandoff> {
        if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ApiError::NotFound);
        }
        let mut handoffs = self.inner.lock().expect("office handoff lock poisoned");
        let handoff = handoffs
            .remove(&token_hash(raw))
            .ok_or(ApiError::NotFound)?;
        if handoff.expires_at <= Instant::now() {
            return Err(ApiError::NotFound);
        }
        Ok(handoff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handoff(actor_email: &str) -> NewOfficeHandoff {
        NewOfficeHandoff {
            provider_url: "https://office.example.test/edit".to_string(),
            session_token: "session".to_string(),
            file_id: "file".to_string(),
            save_url: "/save".to_string(),
            session_url: "/session".to_string(),
            package_url: "/package".to_string(),
            commit_url: "/commit".to_string(),
            actor_email: actor_email.to_string(),
        }
    }

    #[test]
    fn handoffs_are_one_use_and_partitioned() {
        let registry = OfficeHandoffs::default();
        let first = registry.issue(handoff("actor-a")).unwrap();
        assert_eq!(registry.redeem(&first).unwrap().session_token, "session");
        assert!(matches!(registry.redeem(&first), Err(ApiError::NotFound)));

        for _ in 0..MAX_HANDOFFS_PER_ACTOR {
            registry.issue(handoff("actor-a")).unwrap();
        }
        assert!(matches!(
            registry.issue(handoff("actor-a")),
            Err(ApiError::TooManyRequests)
        ));
        assert!(registry.issue(handoff("actor-b")).is_ok());
    }
}
