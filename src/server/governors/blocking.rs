use super::{PartitionedGovernor, PartitionedPermit};
use crate::error::{ApiError, ApiResult};

mod password;

impl PartitionedGovernor {
    /// Keep the same admission across blocking planning and later response
    /// publication. A cancelled waiter still leaves the permit in the worker
    /// until the blocking work exits.
    pub(crate) async fn run_blocking_retained<T>(
        &self,
        partition: &str,
        work: impl FnOnce() -> ApiResult<T> + Send + 'static,
    ) -> ApiResult<(T, PartitionedPermit)>
    where
        T: Send + 'static,
    {
        let permit = self.try_acquire(partition)?;
        let (result, permit) = tokio::task::spawn_blocking(move || (work(), permit))
            .await
            .map_err(|_| ApiError::Maintenance("bounded blocking worker failed".to_string()))?;
        Ok((result?, permit))
    }

    pub(crate) async fn run_blocking<T>(
        &self,
        partition: &str,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        let permit = self.try_acquire(partition)?;
        tokio::task::spawn_blocking(move || {
            let result = work();
            drop(permit);
            result
        })
        .await
        .map_err(|_| ApiError::Maintenance("bounded blocking worker failed".to_string()))
    }
}
