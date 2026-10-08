use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::error::{ApiError, ApiResult};

const PASSWORD_WORK_CONCURRENCY: usize = 2;
const PUBLIC_PASSWORD_WORK_CONCURRENCY: usize = PASSWORD_WORK_CONCURRENCY - 1;
const PUBLIC_DROP_FINALIZATION_CONCURRENCY: usize = 2;
const AUTHENTICATED_BODY_STREAM_CONCURRENCY: usize = 64;
const AUTHENTICATED_BODY_STREAMS_PER_ACTOR: usize = 16;
const AUTHENTICATED_UPLOAD_INGRESS_CONCURRENCY: usize = 8;
const AUTHENTICATED_UPLOAD_INGRESS_PER_ACTOR: usize = 3;
const METADATA_PLANNING_CONCURRENCY: usize = 16;
const METADATA_PLANNING_PER_CAPABILITY: usize = 2;
const SYNC_COMPUTE_CONCURRENCY: usize = 2;
const SYNC_COMPUTE_PER_ACTOR: usize = 1;
const RCLONE_EXPORT_CONCURRENCY: usize = 2;
const RCLONE_EXPORTS_PER_ACTOR: usize = 1;
mod backup_work;
mod blocking;
mod drop_upload;
mod json_ingress;
mod public_stream;
mod upload_finalization;

pub(super) use backup_work::{BackupWorkGovernor, BackupWorkPermit};
pub(crate) use drop_upload::{PublicDropChunkIngressGovernor, PublicDropChunkIngressPermit};
pub(super) use json_ingress::{JsonIngressClass, JsonIngressGovernor};
pub(crate) use public_stream::{PublicBodyStreamGovernor, PublicBodyStreamPermit};
pub(super) use upload_finalization::authenticated_upload_finalization_governor;

#[derive(Clone)]
pub(crate) struct PartitionedGovernor {
    permits: Arc<tokio::sync::Semaphore>,
    active_partitions: Arc<Mutex<HashMap<String, usize>>>,
    per_partition_limit: usize,
}

pub(crate) struct PartitionedPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    partition: String,
    active_partitions: Arc<Mutex<HashMap<String, usize>>>,
}

impl PartitionedGovernor {
    fn new(global_limit: usize, per_partition_limit: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(global_limit)),
            active_partitions: Arc::new(Mutex::new(HashMap::new())),
            per_partition_limit,
        }
    }

    pub(crate) fn try_acquire(&self, partition: &str) -> ApiResult<PartitionedPermit> {
        let global = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)?;
        let mut active = self.active_partitions.lock().unwrap();
        let count = active.entry(partition.to_string()).or_default();
        if *count >= self.per_partition_limit {
            return Err(ApiError::TooManyRequests);
        }
        *count += 1;
        drop(active);
        Ok(PartitionedPermit {
            _global: global,
            partition: partition.to_string(),
            active_partitions: self.active_partitions.clone(),
        })
    }
}

impl Drop for PartitionedPermit {
    fn drop(&mut self) {
        let mut active = self.active_partitions.lock().unwrap();
        let mut remove_partition = false;
        if let Some(count) = active.get_mut(&self.partition) {
            *count = count.saturating_sub(1);
            remove_partition = *count == 0;
        }
        if remove_partition {
            active.remove(&self.partition);
        }
    }
}

pub(super) fn authenticated_body_stream_governor() -> PartitionedGovernor {
    PartitionedGovernor::new(
        AUTHENTICATED_BODY_STREAM_CONCURRENCY,
        AUTHENTICATED_BODY_STREAMS_PER_ACTOR,
    )
}

pub(super) fn authenticated_upload_ingress_governor() -> PartitionedGovernor {
    PartitionedGovernor::new(
        AUTHENTICATED_UPLOAD_INGRESS_CONCURRENCY,
        AUTHENTICATED_UPLOAD_INGRESS_PER_ACTOR,
    )
}

pub(super) fn metadata_planning_governor() -> PartitionedGovernor {
    PartitionedGovernor::new(
        METADATA_PLANNING_CONCURRENCY,
        METADATA_PLANNING_PER_CAPABILITY,
    )
}

pub(super) fn sync_compute_governor() -> PartitionedGovernor {
    PartitionedGovernor::new(SYNC_COMPUTE_CONCURRENCY, SYNC_COMPUTE_PER_ACTOR)
}

pub(super) fn rclone_export_governor() -> PartitionedGovernor {
    PartitionedGovernor::new(RCLONE_EXPORT_CONCURRENCY, RCLONE_EXPORTS_PER_ACTOR)
}

#[derive(Clone)]
pub(super) struct PasswordWorkGovernor {
    total_permits: Arc<tokio::sync::Semaphore>,
    account_permits: Arc<tokio::sync::Semaphore>,
    public_permits: Arc<tokio::sync::Semaphore>,
}

struct PasswordWorkPermit {
    _total: tokio::sync::OwnedSemaphorePermit,
    _account: Option<tokio::sync::OwnedSemaphorePermit>,
    _public: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Default for PasswordWorkGovernor {
    fn default() -> Self {
        Self::new(PASSWORD_WORK_CONCURRENCY, PUBLIC_PASSWORD_WORK_CONCURRENCY)
    }
}

impl PasswordWorkGovernor {
    fn new(total_limit: usize, public_limit: usize) -> Self {
        assert!(public_limit > 0 && public_limit < total_limit);
        Self {
            total_permits: Arc::new(tokio::sync::Semaphore::new(total_limit)),
            account_permits: Arc::new(tokio::sync::Semaphore::new(total_limit - public_limit)),
            public_permits: Arc::new(tokio::sync::Semaphore::new(public_limit)),
        }
    }

    fn try_acquire_account(&self) -> ApiResult<PasswordWorkPermit> {
        let account = self
            .account_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)?;
        let total = self
            .total_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)?;
        Ok(PasswordWorkPermit {
            _total: total,
            _account: Some(account),
            _public: None,
        })
    }

    fn try_acquire_public(&self) -> ApiResult<PasswordWorkPermit> {
        let public = self
            .public_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)?;
        let total = self
            .total_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)?;
        Ok(PasswordWorkPermit {
            _total: total,
            _account: None,
            _public: Some(public),
        })
    }

    pub(super) async fn verify_public(&self, encoded: &str, password: &str) -> ApiResult<bool> {
        let encoded = encoded.to_owned();
        let password = password.to_owned();
        self.run_blocking_public(move || crate::auth::verify_password(&encoded, &password))
            .await
    }

    pub(super) async fn verify_account(&self, encoded: &str, password: &str) -> ApiResult<bool> {
        let encoded = encoded.to_owned();
        let password = password.to_owned();
        self.run_blocking_account(move || crate::auth::verify_account_password(&encoded, &password))
            .await
    }

    pub(super) async fn verify_untrusted_account(
        &self,
        encoded: &str,
        password: &str,
    ) -> ApiResult<bool> {
        let encoded = encoded.to_owned();
        let password = password.to_owned();
        self.run_blocking_public(move || crate::auth::verify_account_password(&encoded, &password))
            .await
    }

    pub(super) async fn hash_account(&self, password: &str) -> ApiResult<String> {
        let password = password.to_owned();
        self.run_blocking_account(move || crate::auth::hash_account_password(&password))
            .await?
    }

    pub(super) async fn hash_untrusted_account(&self, password: &str) -> ApiResult<String> {
        let password = password.to_owned();
        self.run_blocking_public(move || crate::auth::hash_account_password(&password))
            .await?
    }

    pub(super) async fn hash_public(&self, password: &str) -> ApiResult<String> {
        let password = password.to_owned();
        self.run_blocking_public(move || crate::auth::hash_password(&password))
            .await?
    }

    async fn run_blocking_account<T>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        let permit = self.try_acquire_account()?;
        Self::spawn_blocking(permit, work).await
    }

    async fn run_blocking_public<T>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        let permit = self.try_acquire_public()?;
        Self::spawn_blocking(permit, work).await
    }

    async fn spawn_blocking<T>(
        permit: PasswordWorkPermit,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let result = work();
            drop(permit);
            result
        })
        .await
        .map_err(|_| ApiError::Maintenance("password worker failed".to_string()))
    }
}

#[derive(Clone)]
pub(super) struct PublicDropFinalizationGovernor {
    permits: Arc<tokio::sync::Semaphore>,
}

impl Default for PublicDropFinalizationGovernor {
    fn default() -> Self {
        Self::new(PUBLIC_DROP_FINALIZATION_CONCURRENCY)
    }
}

impl PublicDropFinalizationGovernor {
    fn new(limit: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(limit)),
        }
    }

    pub(super) fn try_acquire(&self) -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)
    }
}

#[cfg(test)]
mod tests;
