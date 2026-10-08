//! Tauri commands that are independent of filesystem publication.
//!
//! These commands compile with every desktop-shell target. They deliberately
//! stop at the platform-services boundary: pairing, sync execution, review
//! execution, and disconnect cleanup remain native-adapter work.

use serde::Serialize;
use shellx_drive_desktop_core::{DesktopError, DriveHttpClient, Result as CoreResult};
use tauri::State;
use tauri_plugin_dialog::DialogExt;

use super::{ConnectionManager, DesktopView, Runtime};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerReply {
    normalized_url: String,
    setup_required: bool,
}

/// Validate the current signed-in server through the same bounded HTTP client
/// used by the Settings screen. It accepts no remote-supplied URL.
pub(crate) async fn validate_current_server(runtime: &Runtime) -> CoreResult<ServerReply> {
    runtime.ensure_disconnect_cleanup_complete()?;
    runtime.require_candidate_recovery_complete()?;
    let session = runtime.current_session()?;
    let client = DriveHttpClient::new(&session.server_url)?;
    let validation = client.validate_server().await?;
    Ok(ServerReply {
        normalized_url: validation.normalized_url,
        setup_required: validation.setup_required,
    })
}

#[tauri::command]
pub(crate) fn get_desktop_view(
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
) -> Result<DesktopView, String> {
    Ok(manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?
        .view())
}

#[tauri::command]
pub(crate) async fn validate_server(
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    server_url: String,
) -> Result<ServerReply, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
    let client = DriveHttpClient::new(&server_url).map_err(present_error)?;
    let validation = client.validate_server().await.map_err(present_error)?;
    Ok(ServerReply {
        normalized_url: validation.normalized_url,
        setup_required: validation.setup_required,
    })
}

#[tauri::command]
pub(crate) async fn pick_local_root(app: tauri::AppHandle) -> Option<String> {
    await_folder_choice(|complete| {
        app.dialog().file().pick_folder(move |folder| {
            complete(
                folder
                    .and_then(|folder| folder.into_path().ok())
                    .map(|folder| folder.display().to_string()),
            );
        });
    })
    .await
}

/// Wait for the dialog plugin's non-blocking completion callback on a worker.
///
/// The plugin schedules its GTK/AppKit/Win32 picker on Tauri's main thread.
/// A synchronous command must not wait there for that callback.
async fn await_folder_choice(
    start: impl FnOnce(Box<dyn FnOnce(Option<String>) + Send>),
) -> Option<String> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    start(Box::new(move |choice| {
        let _ = sender.send(choice);
    }));
    tauri::async_runtime::spawn_blocking(move || receiver.recv().ok().flatten())
        .await
        .ok()
        .flatten()
}

#[tauri::command]
pub(crate) async fn set_launch_at_login(
    manager: State<'_, ConnectionManager>,
    enabled: bool,
) -> Result<DesktopView, String> {
    let runtime = manager.app_service_runtime();
    let saved = super::connection_commands::persist_launch_preference(&manager, enabled)
        .map_err(present_error)?;
    let mut view = runtime.view();
    view.launch_at_login = saved.preferences.launch_at_login;
    Ok(view)
}

#[tauri::command]
pub(crate) fn open_local_folder(
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
) -> Result<DesktopView, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?;
    if let Some(base) = runtime.coordinator.snapshot().sync_root_base {
        runtime
            .platform
            .open_local_root(&base)
            .map_err(present_error)?;
        return Ok(runtime.view());
    }
    let pair = runtime
        .coordinator
        .snapshot()
        .pair
        .ok_or_else(|| "Set up a Drive pair first.".to_string())?;
    runtime
        .platform
        .open_local_root(&pair.local_root)
        .map_err(present_error)?;
    Ok(runtime.view())
}

#[tauri::command]
pub(crate) fn open_drive(
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
) -> Result<DesktopView, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?;
    let pair = runtime
        .coordinator
        .snapshot()
        .pair
        .ok_or_else(|| "Set up a Drive pair first.".to_string())?;
    runtime
        .platform
        .open_drive_url(&pair.server_url)
        .map_err(present_error)?;
    Ok(runtime.view())
}

/// Persist a platform-autostart transition as one lifecycle operation. The
/// rollback is intentionally platform-neutral so a future Unix shell cannot
/// silently retain a registration after durable state rejected the change.
pub(crate) async fn persist_launch_at_login_state(
    runtime: &Runtime,
    enabled: bool,
) -> CoreResult<()> {
    // Startup registration is durable desktop lifecycle state. Keep the
    // pending Disconnect cleanup journal as the only mutation authority until
    // its retained-tree cleanup is complete.
    runtime.ensure_disconnect_cleanup_complete()?;
    let _auth_publication = runtime.auth_publication.lock().await;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let previous = runtime.coordinator.snapshot();
    runtime.platform.set_launch_at_login(enabled)?;
    let mut candidate = previous.clone();
    candidate.launch_at_login = enabled;
    if let Err(error) = runtime.store.save(&candidate) {
        if let Err(rollback_error) = runtime
            .platform
            .set_launch_at_login(previous.launch_at_login)
        {
            return Err(DesktopError::InvalidState(format!(
                "The startup preference was not saved and platform startup rollback also failed: {error}; {rollback_error}"
            )));
        }
        return Err(error);
    }
    operation.finish_state(candidate);
    Ok(())
}

pub(crate) fn present_error(error: DesktopError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::{Arc, Mutex},
    };

    use shellx_drive_desktop_core::{
        CredentialStore, DesktopState, FakeCredentialStore, StateStore,
    };

    use super::*;

    struct TestPlatform {
        credentials: FakeCredentialStore,
        autostart: Arc<Mutex<Vec<bool>>>,
    }

    impl crate::platform::PlatformServices for TestPlatform {
        fn credentials(&self) -> &dyn CredentialStore {
            &self.credentials
        }

        fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
            &self.credentials
        }

        fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
            &self.credentials
        }

        fn set_launch_at_login(&self, enabled: bool) -> CoreResult<()> {
            self.autostart.lock().expect("autostart lock").push(enabled);
            Ok(())
        }

        fn open_local_root(&self, _: &Path) -> CoreResult<()> {
            Ok(())
        }

        fn open_drive_url(&self, _: &str) -> CoreResult<()> {
            Ok(())
        }
    }

    #[test]
    fn launch_preference_uses_the_platform_boundary_and_persists() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let autostart = Arc::new(Mutex::new(Vec::new()));
        let runtime = Runtime::from_loaded_state(
            Box::new(TestPlatform {
                credentials: FakeCredentialStore::default(),
                autostart: Arc::clone(&autostart),
            }),
            StateStore::new(directory.path().join("state.json")),
            DesktopState::default(),
        );

        tauri::async_runtime::block_on(persist_launch_at_login_state(&runtime, false))
            .expect("persist launch preference");

        assert_eq!(*autostart.lock().expect("autostart lock"), vec![false]);
        assert!(!runtime.coordinator.snapshot().launch_at_login);
    }

    #[test]
    fn folder_choice_returns_the_nonblocking_dialog_callback_value() {
        let selected = tauri::async_runtime::block_on(await_folder_choice(|complete| {
            complete(Some("/tmp/shellx-drive-folder".to_string()));
        }));

        assert_eq!(selected.as_deref(), Some("/tmp/shellx-drive-folder"));

        let cancelled = tauri::async_runtime::block_on(await_folder_choice(|complete| {
            complete(None);
        }));

        assert_eq!(cancelled, None);
    }
}
