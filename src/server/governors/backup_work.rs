//! One shared admission lane for attacker-controlled legacy backup parsing and
//! backup catalog inspection. Both operations can read and deserialize sizeable
//! server-side files, so neither may queue unbounded blocking work.

use std::sync::Arc;

use crate::error::{ApiError, ApiResult};

const BACKUP_WORK_CONCURRENCY: usize = 1;

#[derive(Clone)]
pub(crate) struct BackupWorkGovernor {
    permits: Arc<tokio::sync::Semaphore>,
}

pub(crate) struct BackupWorkPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Default for BackupWorkGovernor {
    fn default() -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(BACKUP_WORK_CONCURRENCY)),
        }
    }
}

impl BackupWorkGovernor {
    pub(crate) fn try_acquire(&self) -> ApiResult<BackupWorkPermit> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)?;
        Ok(BackupWorkPermit { _permit: permit })
    }

    pub(crate) async fn run_blocking<T>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        let permit = self.try_acquire()?;
        tokio::task::spawn_blocking(move || {
            let result = work();
            drop(permit);
            result
        })
        .await
        .map_err(|_| ApiError::Maintenance("backup worker failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn saturation_is_rejected_and_capacity_returns_after_work() {
        let governor = BackupWorkGovernor::default();
        let first = governor.try_acquire().expect("first permit");
        assert!(matches!(
            governor.run_blocking(|| ()).await,
            Err(ApiError::TooManyRequests)
        ));
        drop(first);
        governor.run_blocking(|| ()).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_waiter_keeps_capacity_reserved_until_blocking_work_exits() {
        let governor = BackupWorkGovernor::default();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let running_governor = governor.clone();
        let waiter = tokio::spawn(async move {
            running_governor
                .run_blocking(move || {
                    let _ = entered_tx.send(());
                    release_rx.recv().unwrap();
                })
                .await
        });
        entered_rx.await.unwrap();
        waiter.abort();
        assert!(matches!(
            governor.run_blocking(|| ()).await,
            Err(ApiError::TooManyRequests)
        ));

        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match governor.run_blocking(|| ()).await {
                    Ok(()) => break,
                    Err(ApiError::TooManyRequests) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected backup-work error: {error}"),
                }
            }
        })
        .await
        .expect("backup-work capacity did not return after blocking work exited");
    }
}
