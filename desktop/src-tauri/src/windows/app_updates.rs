//! Signed desktop-client updater commands shared by Windows and Linux shells.

use tauri::{ipc::Channel, AppHandle, State};

use crate::application::{
    update_service::{DesktopUpdateEvent, DesktopUpdateInfo},
    Runtime,
};

pub(super) use crate::application::update_service::DesktopUpdateService as PendingDesktopUpdate;

#[tauri::command]
pub(super) async fn check_desktop_update(
    app: AppHandle,
    service: State<'_, PendingDesktopUpdate>,
) -> Result<Option<DesktopUpdateInfo>, String> {
    service.check(&app).await.map_err(|error| error.to_string())
}

#[tauri::command]
pub(super) async fn install_desktop_update(
    app: AppHandle,
    runtime: State<'_, Runtime>,
    service: State<'_, PendingDesktopUpdate>,
    candidate_id: String,
    events: Channel<DesktopUpdateEvent>,
) -> Result<(), String> {
    service
        .install(&app, &runtime, &candidate_id, |event| {
            let _ = events.send(event);
        })
        .await
        .map_err(|error| error.to_string())
}
