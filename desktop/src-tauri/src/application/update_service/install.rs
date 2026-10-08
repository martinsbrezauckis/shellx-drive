use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use shellx_drive_desktop_core::{DesktopState, LifecycleOperation, Result as CoreResult};
use tauri::AppHandle;
use tauri_plugin_updater::Update;

use super::{
    lifecycle::{self, UpdateLifecycle},
    DesktopUpdateEvent, DesktopUpdateService, DesktopUpdateServiceError, Runtime,
};

#[derive(Clone, Copy)]
pub(crate) enum DesktopUpdateLifecycleStage {
    Updating,
    RelaunchPending,
}

pub(crate) trait DesktopUpdateLifecycleHook {
    fn report<'a>(
        &'a mut self,
        stage: DesktopUpdateLifecycleStage,
        state: &'a mut DesktopState,
        operation: &'a mut LifecycleOperation,
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>>;

    fn renewal_interval(&self) -> Duration {
        Duration::from_secs(15)
    }
}

impl DesktopUpdateService {
    pub(crate) async fn install(
        &self,
        app: &AppHandle,
        runtime: &Runtime,
        candidate_id: &str,
        emit: impl Fn(DesktopUpdateEvent) + Send + Sync,
    ) -> Result<(), DesktopUpdateServiceError> {
        let (candidate_id, update, mut lifecycle) =
            self.begin_install(runtime, candidate_id, None)?;
        let bytes = match download(&update, &emit).await {
            Ok(bytes) => bytes,
            Err(error) => return self.abort(runtime, &mut lifecycle, &candidate_id, error),
        };
        emit(DesktopUpdateEvent::Verified);
        emit(DesktopUpdateEvent::Restarting);
        if let Err(error) = update.install(bytes) {
            return self.abort(
                runtime,
                &mut lifecycle,
                &candidate_id,
                DesktopUpdateServiceError::Updater(error.to_string()),
            );
        }
        app.request_restart();
        Ok(())
    }

    pub(crate) async fn install_for_agent<H: DesktopUpdateLifecycleHook + Send>(
        &self,
        app: &AppHandle,
        runtime: &Runtime,
        candidate_id: &str,
        command_id: &str,
        hook: &mut H,
        emit: impl Fn(DesktopUpdateEvent) + Send + Sync,
    ) -> Result<(), DesktopUpdateServiceError> {
        let (candidate_id, update, mut lifecycle) =
            self.begin_install(runtime, candidate_id, Some(command_id))?;
        if let Err(error) = hook
            .report(
                DesktopUpdateLifecycleStage::Updating,
                &mut lifecycle.state,
                &mut lifecycle.operation,
            )
            .await
        {
            return self.abort(runtime, &mut lifecycle, &candidate_id, error.into());
        }
        let bytes = match download_with_renewal(&update, &emit, hook, &mut lifecycle).await {
            Ok(bytes) => bytes,
            Err(error) => return self.abort(runtime, &mut lifecycle, &candidate_id, error),
        };
        emit(DesktopUpdateEvent::Verified);
        if let Err(error) = hook
            .report(
                DesktopUpdateLifecycleStage::RelaunchPending,
                &mut lifecycle.state,
                &mut lifecycle.operation,
            )
            .await
        {
            return self.abort(runtime, &mut lifecycle, &candidate_id, error.into());
        }
        emit(DesktopUpdateEvent::Restarting);
        if let Err(error) = update.install(bytes) {
            return self.abort(
                runtime,
                &mut lifecycle,
                &candidate_id,
                DesktopUpdateServiceError::Updater(error.to_string()),
            );
        }
        app.request_restart();
        Ok(())
    }

    fn begin_install(
        &self,
        runtime: &Runtime,
        candidate_id: &str,
        command_id: Option<&str>,
    ) -> Result<(String, Update, UpdateLifecycle), DesktopUpdateServiceError> {
        let (candidate_id, update) = self.take_ready(candidate_id)?;
        match lifecycle::persist_restart_intent(runtime, &update.version, &candidate_id, command_id)
        {
            Ok(lifecycle) => Ok((candidate_id, update, lifecycle)),
            Err(error) => {
                self.restore_ready(candidate_id, update)?;
                Err(error)
            }
        }
    }

    fn abort(
        &self,
        runtime: &Runtime,
        lifecycle: &mut UpdateLifecycle,
        candidate_id: &str,
        error: DesktopUpdateServiceError,
    ) -> Result<(), DesktopUpdateServiceError> {
        let cancellation = lifecycle.cancel(runtime, candidate_id);
        let release = self.clear_installing();
        cancellation?;
        release?;
        Err(error)
    }
}

#[cfg(test)]
#[path = "install/tests.rs"]
mod tests;

async fn download(
    update: &Update,
    emit: &(impl Fn(DesktopUpdateEvent) + Send + Sync),
) -> Result<Vec<u8>, DesktopUpdateServiceError> {
    let started = AtomicBool::new(false);
    update
        .download(
            |chunk_length, content_length| {
                if !started.swap(true, Ordering::Relaxed) {
                    emit(DesktopUpdateEvent::Started { content_length });
                }
                emit(DesktopUpdateEvent::Progress { chunk_length });
            },
            || emit(DesktopUpdateEvent::Downloaded),
        )
        .await
        .map_err(|error| DesktopUpdateServiceError::Updater(error.to_string()))
}

async fn download_with_renewal<H: DesktopUpdateLifecycleHook + Send>(
    update: &Update,
    emit: &(impl Fn(DesktopUpdateEvent) + Send + Sync),
    hook: &mut H,
    lifecycle: &mut UpdateLifecycle,
) -> Result<Vec<u8>, DesktopUpdateServiceError> {
    let started = AtomicBool::new(false);
    let download = update.download(
        |chunk_length, content_length| {
            if !started.swap(true, Ordering::Relaxed) {
                emit(DesktopUpdateEvent::Started { content_length });
            }
            emit(DesktopUpdateEvent::Progress { chunk_length });
        },
        || emit(DesktopUpdateEvent::Downloaded),
    );
    tokio::pin!(download);
    let interval = hook.renewal_interval().max(Duration::from_secs(1));
    let mut renewals = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    loop {
        tokio::select! {
            result = &mut download => return result.map_err(|error| DesktopUpdateServiceError::Updater(error.to_string())),
            _ = renewals.tick() => hook.report(DesktopUpdateLifecycleStage::Updating, &mut lifecycle.state, &mut lifecycle.operation).await?,
        }
    }
}
