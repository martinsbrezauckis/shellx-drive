//! macOS Tauri shell and tray projection.

use std::{ffi::OsStr, sync::Arc};

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, State,
};
use tauri_plugin_notification::NotificationExt;

use super::*;

mod navigation;
mod tray_sync;

use navigation::show_main_window;

pub(super) fn run_from_args() -> i32 {
    let mut args = std::env::args_os();
    let _executable = args.next();
    let first_arg = args.next();
    if first_arg.as_deref() == Some(OsStr::new("--uninstall-cleanup")) {
        if args.next().is_some() {
            eprintln!("ShellX Drive Desktop uninstall cleanup accepts no additional arguments.");
            return 2;
        }
        return crate::application::unix_uninstall::run_uninstall_cleanup_with_lease();
    }
    if first_arg.is_some() {
        eprintln!("ShellX Drive Desktop does not accept command-line arguments on macOS.");
        return 2;
    }
    let lease = match crate::platform::unix::instance::UnixDesktopInstanceLease::acquire() {
        Ok(Some(lease)) => lease,
        Ok(None) => return 0,
        Err(error) => {
            eprintln!("ShellX Drive Desktop could not acquire its macOS process lease: {error}");
            return 1;
        }
    };
    run(lease)
}

fn run(_lease: crate::platform::unix::instance::UnixDesktopInstanceLease) -> i32 {
    let runtime = match Runtime::load_macos() {
        Ok(runtime) => Arc::new(runtime),
        Err(error) => {
            eprintln!("ShellX Drive Desktop could not load its non-secret state: {error}");
            return 1;
        }
    };
    let manager = match ConnectionManager::load(Arc::clone(&runtime), Runtime::load_connection) {
        Ok(manager) => manager,
        Err(error) => {
            eprintln!("ShellX Drive Desktop could not load its server connections: {error}");
            return 1;
        }
    };
    if let Err(error) = runtime
        .platform
        .set_launch_at_login(manager.preferences().launch_at_login)
    {
        runtime.coordinator.record_error(format!(
            "Drive could not restore its launch-at-sign-in registration: {error}"
        ));
        let _ = runtime.save();
    }
    for connection in manager.all_runtimes() {
        if let Err(error) =
            crate::application::update_service::reconcile_desktop_update_restart(&connection)
        {
            eprintln!("ShellX Drive Desktop could not reconcile a connection's pending update restart: {error}");
        }
        if !connection
            .coordinator
            .snapshot()
            .has_pending_disconnect_cleanup()
        {
            candidate_recovery::recover_at_startup(&connection);
        }
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(runtime)
        .manage(manager)
        .manage(updates::PendingDesktopUpdate::default())
        .invoke_handler(tauri::generate_handler![
            super::super::commands::get_desktop_view,
            super::super::connection_commands::get_connections_view,
            super::super::connection_commands::begin_connection,
            super::super::connection_commands::complete_connection,
            super::super::connection_commands::save_connection,
            super::super::connection_commands::save_app_preferences,
            super::super::connection_commands::cancel_login,
            super::super::connection_commands::cancel_connection,
            super::super::connection_commands::remove_connection,
            super::super::connection_commands::replace_connection_folder,
            super::super::desktop_agent::set_desktop_agent_control,
            super::super::commands::validate_server,
            auth::login_password,
            auth::continue_login,
            super::super::root_discovery::list_workspaces,
            super::super::root_discovery::list_workspace_page,
            super::super::commands::pick_local_root,
            pairing::start_pair,
            super::add_root::add_root,
            pairing::select_pair,
            sync::sync_now,
            sync::recheck_reviews,
            set_paused,
            super::super::commands::set_launch_at_login,
            super::super::commands::open_local_folder,
            super::super::commands::open_drive,
            offboarding::disconnect,
            super::super::review::prepare_review_action,
            super::super::review::choose_review_action,
            updates::check_desktop_update,
            updates::install_desktop_update,
        ])
        .setup(move |app| {
            let handle = app.handle();
            let manager = handle.state::<ConnectionManager>();
            let menu = build_tray_menu(handle, &manager)?;
            TrayIconBuilder::with_id("drive-tray")
                .menu(&menu)
                .icon(
                    handle
                        .default_window_icon()
                        .cloned()
                        .expect("ShellX Drive tray icon is bundled"),
                )
                .tooltip(tray_tooltip(&manager))
                .show_menu_on_left_click(false)
                .build(app)?;
            for connection in manager.all_runtimes() {
                if connection.coordinator.snapshot().pair.is_some() && manager.may_sync(&connection)
                {
                    super::super::desktop_agent::start_polling(handle, &connection);
                }
                if manager.may_sync(&connection)
                    && !connection.candidate_recovery_pending()
                    && connection.coordinator.snapshot().pair.is_some()
                {
                    sync::start_polling(handle, &connection);
                    let startup = handle.clone();
                    tauri::async_runtime::spawn(async move {
                        let runtime = connection;
                        let _ = sync::sync_now_impl(&startup, &runtime).await;
                    });
                }
            }
            super::super::desktop_agent::resume_agent_disconnect_completion(handle);
            Ok(())
        })
        .on_menu_event(|app, event| {
            let id = event.id().as_ref();
            match id {
                "quit" => app.exit(0),
                "show" => show_main_window(app),
                _ => {
                    if let Some(connection_id) = id.strip_prefix("connection:") {
                        show_main_window(app);
                        let _ = app.emit_to(
                            "main",
                            "shellx-drive-open-connection",
                            connection_id.to_string(),
                        );
                    }
                }
            }
        })
        .on_tray_icon_event(|app, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show_main_window(app);
            }
        })
        .run(tauri::generate_context!())
        .expect("Tauri desktop shell failed");
    0
}

#[tauri::command]
async fn set_paused(
    app: tauri::AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    paused: bool,
) -> Result<DesktopView, String> {
    manager.ensure_mutation_allowed().map_err(macos_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(macos_error)?;
    lifecycle::persist_paused_state(&runtime, paused)
        .await
        .map_err(macos_error)?;
    update_tray(&app, &runtime);
    Ok(runtime.view())
}

pub(crate) fn update_tray(app: &tauri::AppHandle, _runtime: &Runtime) {
    let manager = app.state::<ConnectionManager>();
    if let Some(tray) = app.tray_by_id("drive-tray") {
        let _ = tray.set_tooltip(Some(tray_tooltip(&manager)));
        if let Ok(menu) = build_tray_menu(app, &manager) {
            let _ = tray.set_menu(Some(menu));
        }
    }
}

pub(super) fn notify_actionable(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    error_is_persistent: bool,
) {
    if !runtime.coordinator.should_notify(error_is_persistent) {
        return;
    }
    let view = runtime.view();
    let body = if view.status == "needs_review" {
        format!("{} Drive item(s) need your decision.", view.review_count)
    } else {
        "Drive needs your attention. Open ShellX Drive for the next safe step.".to_string()
    };
    let _ = app
        .notification()
        .builder()
        .title("ShellX Drive")
        .body(&body)
        .show();
}

fn tray_tooltip(manager: &ConnectionManager) -> String {
    let view = manager.view();
    let attention = view
        .connections
        .iter()
        .filter(|connection| {
            matches!(
                connection.view.status,
                "needs_review" | "needs_reconnect" | "offline" | "error"
            )
        })
        .count();
    let syncing = view
        .connections
        .iter()
        .filter(|connection| connection.view.status == "syncing")
        .count();
    format!(
        "ShellX Drive — {} servers · {} syncing · {} need attention",
        view.connections.len(),
        syncing,
        attention
    )
}

fn build_tray_menu<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    manager: &ConnectionManager,
) -> tauri::Result<Menu<R>> {
    let menu = Menu::new(app)?;
    let status = MenuItem::with_id(app, "status", tray_tooltip(manager), false, None::<&str>)?;
    menu.append(&status)?;
    let show = MenuItem::with_id(app, "show", "Open ShellX Drive", true, None::<&str>)?;
    menu.append(&show)?;
    for connection in manager.view().connections {
        let item = MenuItem::with_id(
            app,
            format!("connection:{}", connection.id),
            format!(
                "{} — {}",
                connection.name,
                tray_sync::status_label(connection.view.status)
            ),
            true,
            None::<&str>,
        )?;
        menu.append(&item)?;
    }
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    menu.append(&separator)?;
    menu.append(&quit)?;
    Ok(menu)
}
