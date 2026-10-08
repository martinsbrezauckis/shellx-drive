//! Captured-runtime automatic checks and conservative offline scheduling.

use std::{sync::atomic::Ordering, time::Duration};

use shellx_drive_desktop_core::SyncStatus;
use tauri::{AppHandle, Manager};

use crate::application::{connections::ConnectionManager, Runtime};

use super::sync_with_schedule;

const OFFLINE_BACKOFF: Duration = Duration::from_secs(60);
const SCHEDULE_RECHECK: Duration = Duration::from_secs(20);

pub(crate) fn start_polling(app: &AppHandle, runtime: &Runtime) {
    let manager = app.state::<ConnectionManager>();
    if !manager.may_sync(runtime) {
        return;
    }
    let Some(id) = manager.id_for_runtime(runtime) else {
        return;
    };
    let Ok(runtime) = manager.resolve(Some(&id)) else {
        return;
    };
    if runtime
        .coordinator
        .snapshot()
        .has_pending_disconnect_cleanup()
        || runtime.polling_enabled.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let generation = runtime.poll_generation.fetch_add(1, Ordering::AcqRel) + 1;
    // Seed a newly armed schedule; immediate startup/manual checks below
    // replace this timestamp with their actual completion time.
    runtime.mark_sync_check_finished();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let manager = app.state::<ConnectionManager>();
            let interval = effective_poll_interval(&manager, &runtime);
            let remaining = runtime.sync_check_delay(interval);
            let delay = if remaining.is_zero() {
                interval.min(SCHEDULE_RECHECK)
            } else {
                remaining.min(SCHEDULE_RECHECK)
            };
            tokio::time::sleep(delay).await;
            if !runtime.polling_enabled.load(Ordering::Acquire)
                || runtime.poll_generation.load(Ordering::Acquire) != generation
            {
                break;
            }
            if !manager.may_sync(&runtime) {
                continue;
            }
            // A manual check or interval edit can move the deadline while
            // this task sleeps. Recheck the current completion time before
            // requesting its fair permit; missed checks never queue a burst.
            if !runtime
                .sync_check_delay(effective_poll_interval(&manager, &runtime))
                .is_zero()
            {
                continue;
            }
            if matches!(
                runtime.status(),
                SyncStatus::NeedsSetup
                    | SyncStatus::NeedsReconnect
                    | SyncStatus::Syncing
                    | SyncStatus::Paused
            ) {
                continue;
            }
            if let Err(error) = sync_with_schedule(&app, &runtime, false, true).await {
                eprintln!("ShellX Drive Linux automatic poll did not complete: {error}");
            }
        }
    });
}

pub(super) fn effective_poll_interval(manager: &ConnectionManager, runtime: &Runtime) -> Duration {
    let interval = manager.effective_interval(runtime);
    if runtime.status() == SyncStatus::Offline {
        interval.max(OFFLINE_BACKOFF)
    } else {
        interval
    }
}

pub(in crate::application::linux) fn stop_polling(runtime: &Runtime) {
    runtime.polling_enabled.store(false, Ordering::Release);
    runtime.poll_generation.fetch_add(1, Ordering::AcqRel);
}
