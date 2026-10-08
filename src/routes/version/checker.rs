use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::version::{self, UpdateStatus, UpdateStatusKind};

use super::resolve_update;

const UPDATE_CACHE_TTL: Duration = Duration::from_secs(30 * 60);
const UPDATE_ERROR_BACKOFF_BASE: Duration = Duration::from_secs(5);
const UPDATE_ERROR_BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
struct CachedUpdate {
    repo: String,
    fetched: Instant,
    ttl: Duration,
    status: UpdateStatus,
}

#[derive(Default)]
struct UpdateCache {
    entry: Option<CachedUpdate>,
    consecutive_errors: u32,
}

#[derive(Clone)]
pub(crate) struct UpdateChecker {
    client: reqwest::Client,
    cache: Arc<Mutex<UpdateCache>>,
    refresh: Arc<tokio::sync::Semaphore>,
}

impl UpdateChecker {
    pub(crate) fn new() -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(format!("shellx-drive/{}", version::VERSION))
            .timeout(Duration::from_secs(10))
            .https_only(true)
            .redirect(update_redirect_policy())
            .build()?;
        Ok(Self {
            client,
            cache: Arc::new(Mutex::new(UpdateCache::default())),
            refresh: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }

    pub(crate) async fn check(&self, repo: &str, checked_at: String) -> UpdateStatus {
        self.resolve_with(repo, checked_at.clone(), || {
            resolve_update(&self.client, repo, checked_at)
        })
        .await
    }

    async fn resolve_with<F, Fut>(
        &self,
        repo: &str,
        checked_at: String,
        resolver: F,
    ) -> UpdateStatus
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = UpdateStatus>,
    {
        if let Some(status) = self.cached_status(repo, true) {
            return status;
        }
        let Ok(_refresh) = self.refresh.clone().try_acquire_owned() else {
            return self.cached_status(repo, false).unwrap_or_else(|| {
                UpdateStatus::error(
                    Some(repo.to_string()),
                    version::VERSION,
                    checked_at,
                    "An update check is already in progress; retry shortly.",
                )
            });
        };
        // A concurrent refresh can finish between the initial check and permit.
        if let Some(status) = self.cached_status(repo, true) {
            return status;
        }
        let status = resolver().await;
        self.store(repo, status.clone());
        status
    }

    fn cached_status(&self, repo: &str, require_fresh: bool) -> Option<UpdateStatus> {
        let cache = self.cache.lock().unwrap();
        let entry = cache.entry.as_ref().filter(|entry| entry.repo == repo)?;
        if require_fresh && entry.fetched.elapsed() >= entry.ttl {
            return None;
        }
        Some(entry.status.clone())
    }

    fn store(&self, repo: &str, status: UpdateStatus) {
        let mut cache = self.cache.lock().unwrap();
        let ttl = if status.kind == UpdateStatusKind::Error {
            cache.consecutive_errors = cache.consecutive_errors.saturating_add(1);
            negative_cache_ttl(cache.consecutive_errors)
        } else {
            cache.consecutive_errors = 0;
            UPDATE_CACHE_TTL
        };
        cache.entry = Some(CachedUpdate {
            repo: repo.to_string(),
            fetched: Instant::now(),
            ttl,
            status,
        });
    }
}

fn update_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::none()
}

fn negative_cache_ttl(consecutive_errors: u32) -> Duration {
    let exponent = consecutive_errors.saturating_sub(1).min(16);
    UPDATE_ERROR_BACKOFF_BASE
        .checked_mul(1_u32 << exponent)
        .unwrap_or(UPDATE_ERROR_BACKOFF_MAX)
        .min(UPDATE_ERROR_BACKOFF_MAX)
}

#[cfg(test)]
mod tests;
