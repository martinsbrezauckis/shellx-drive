use std::{sync::atomic::Ordering, time::Duration};

use super::*;

const OFFLINE_BACKOFF: Duration = Duration::from_secs(60);

pub(crate) fn start_polling(app: &tauri::AppHandle, runtime: &Runtime) {
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
    {
        return;
    }
    if runtime.polling_enabled.swap(true, Ordering::AcqRel) {
        return;
    }
    let generation = runtime.poll_generation.fetch_add(1, Ordering::AcqRel) + 1;
    runtime.mark_sync_check_finished();
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let manager = handle.state::<ConnectionManager>();
            let interval = manager.effective_interval(&runtime);
            let delay = if runtime.status() == shellx_drive_desktop_core::SyncStatus::Offline {
                interval.max(OFFLINE_BACKOFF)
            } else {
                interval
            };
            tokio::time::sleep(runtime.sync_check_delay(delay).max(Duration::from_secs(1))).await;
            if !runtime.polling_enabled.load(Ordering::Acquire)
                || runtime.poll_generation.load(Ordering::Acquire) != generation
            {
                break;
            }
            let interval = manager.effective_interval(&runtime);
            let interval = if runtime.status() == shellx_drive_desktop_core::SyncStatus::Offline {
                interval.max(OFFLINE_BACKOFF)
            } else {
                interval
            };
            if !runtime.sync_check_delay(interval).is_zero() {
                continue;
            }
            if !manager.may_sync(&runtime) {
                continue;
            }
            if matches!(
                runtime.status(),
                shellx_drive_desktop_core::SyncStatus::NeedsSetup
                    | shellx_drive_desktop_core::SyncStatus::NeedsReconnect
                    | shellx_drive_desktop_core::SyncStatus::Syncing
                    | shellx_drive_desktop_core::SyncStatus::Paused
            ) {
                continue;
            }
            let result = sync_roots_pass(&handle, &runtime, false, Some(generation)).await;
            if runtime.poll_generation.load(Ordering::Acquire) == generation {
                runtime.mark_sync_check_finished();
            }
            if let Err(error) = result {
                eprintln!("ShellX Drive macOS automatic sync did not complete: {error}");
            }
        }
    });
}

pub(in crate::application::macos) fn stop_polling(runtime: &Runtime) {
    runtime.polling_enabled.store(false, Ordering::Release);
    runtime.poll_generation.fetch_add(1, Ordering::AcqRel);
}

pub(super) fn scheduled_check_is_due(
    manager: &ConnectionManager,
    runtime: &Runtime,
    poll_generation: Option<u64>,
) -> Result<bool, String> {
    if poll_generation.is_some_and(|generation| {
        !runtime.polling_enabled.load(Ordering::Acquire)
            || runtime.poll_generation.load(Ordering::Acquire) != generation
    }) {
        return Err(
            "This automatic sync check was canceled by a newer connection operation.".to_string(),
        );
    }
    if poll_generation.is_some() {
        let interval = manager.effective_interval(runtime);
        let interval = if runtime.status() == shellx_drive_desktop_core::SyncStatus::Offline {
            interval.max(OFFLINE_BACKOFF)
        } else {
            interval
        };
        if !runtime.sync_check_delay(interval).is_zero() {
            return Ok(false);
        }
    }
    Ok(true)
}
