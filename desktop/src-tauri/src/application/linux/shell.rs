//! Linux Tauri shell, tray surface, and startup ownership.

use std::{ffi::OsStr, sync::Arc};

use shellx_drive_desktop_core::{DesktopState, Result as CoreResult, StateStore};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
use tauri_plugin_notification::NotificationExt;

use crate::application::{
    commands, connection_commands, connections::ConnectionManager, review, root_discovery, Runtime,
};

use super::{app_updates, auth, candidate, disconnect, roots, sync, tray_policy};

pub(crate) fn run_from_args() -> i32 {
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
        eprintln!("ShellX Drive Desktop does not accept command-line arguments on Linux.");
        return 2;
    }
    let lease = match crate::platform::unix::instance::UnixDesktopInstanceLease::acquire() {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            eprintln!("ShellX Drive Desktop is already running for this Linux user.");
            return 0;
        }
        Err(error) => {
            eprintln!("ShellX Drive Desktop could not acquire its process lease: {error}");
            return 1;
        }
    };
    run(lease)
}

fn run(_lease: crate::platform::unix::instance::UnixDesktopInstanceLease) -> i32 {
    let runtime = match Runtime::new_linux() {
        Ok(runtime) => Arc::new(runtime),
        Err(error) => {
            eprintln!("ShellX Drive Desktop could not load its non-secret state: {error}");
            return 1;
        }
    };
    let manager = match ConnectionManager::load(Arc::clone(&runtime), Runtime::load_connection) {
        Ok(manager) => manager,
        Err(error) => {
            eprintln!("ShellX Drive Desktop could not load its connection catalog: {error}");
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
            eprintln!(
                "ShellX Drive Desktop could not reconcile its pending update restart: {error}"
            );
        }
        candidate::recover_at_startup(&connection);
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(runtime)
        .manage(manager)
        .manage(app_updates::PendingDesktopUpdate::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_desktop_view,
            connection_commands::get_connections_view,
            connection_commands::begin_connection,
            connection_commands::complete_connection,
            connection_commands::save_connection,
            connection_commands::save_app_preferences,
            connection_commands::cancel_login,
            connection_commands::cancel_connection,
            connection_commands::remove_connection,
            connection_commands::replace_connection_folder,
            crate::application::desktop_agent::set_desktop_agent_control,
            commands::validate_server,
            auth::login_password,
            auth::continue_login,
            root_discovery::list_workspaces,
            root_discovery::list_workspace_page,
            commands::pick_local_root,
            roots::start_pair,
            super::add_root::add_root,
            roots::select_pair,
            sync::sync_now,
            sync::recheck_reviews,
            sync::set_paused,
            commands::set_launch_at_login,
            commands::open_local_folder,
            commands::open_drive,
            disconnect::disconnect,
            review::prepare_review_action,
            review::choose_review_action,
            app_updates::check_desktop_update,
            app_updates::install_desktop_update,
        ])
        .setup(move |app| {
            let handle = app.handle();
            let manager = handle.state::<ConnectionManager>();
            let menu = build_tray_menu(handle)?;
            TrayIconBuilder::with_id("drive-tray")
                .menu(&menu)
                .icon(
                    handle
                        .default_window_icon()
                        .cloned()
                        .expect("ShellX Drive tray icon is bundled"),
                )
                .tooltip(tray_tooltip(handle))
                .show_menu_on_left_click(false)
                .build(app)?;
            for connection in manager.all_runtimes() {
                if manager.may_sync(&connection)
                    && !connection.candidate_recovery_pending()
                    && connection.coordinator.snapshot().pair.is_some()
                {
                    sync::start_polling(handle, &connection);
                    let startup = handle.clone();
                    let startup_connection = Arc::clone(&connection);
                    tauri::async_runtime::spawn(async move {
                        if let Err(error) =
                            sync::sync_or_recheck(&startup, &startup_connection, false).await
                        {
                            eprintln!("ShellX Drive Linux startup sync did not complete: {error}");
                        }
                    });
                }
                crate::application::desktop_agent::start_polling(handle, &connection);
            }
            crate::application::desktop_agent::resume_agent_disconnect_completion(handle);
            Ok(())
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "quit" => app.exit(0),
            "show" => show_main_window(app),
            "review" => show_review_window(app),
            id if id.starts_with("connection:") => {
                let id = &id["connection:".len()..];
                let manager = app.state::<ConnectionManager>();
                if manager.resolve(Some(id)).is_ok() {
                    show_main_window(app);
                    let _ = app.emit("shellx-drive-open-connection", id.to_string());
                }
            }
            _ => {}
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

impl Runtime {
    pub(super) fn new_linux() -> CoreResult<Self> {
        let (store, state) = Self::load_state()?;
        Self::load_connection(store, state)
    }

    pub(crate) fn load_connection(store: StateStore, mut state: DesktopState) -> CoreResult<Self> {
        if disconnect::resume_linux_disconnect_cleanup(&store, &mut state).is_err() {
            state.last_error = Some(
                "Disconnect local cleanup remains pending; retry Disconnect to complete it."
                    .to_string(),
            );
            let _ = store.save(&state);
        }
        Ok(Self::from_loaded_state(
            Box::new(crate::platform::unix::UnixPlatformServices::default()),
            store,
            state,
        ))
    }
}

pub(crate) fn update_tray(app: &AppHandle, _runtime: &Runtime) {
    if let Some(tray) = app.tray_by_id("drive-tray") {
        let _ = tray.set_tooltip(Some(tray_tooltip(app)));
        if let Ok(menu) = build_tray_menu(app) {
            let _ = tray.set_menu(Some(menu));
        }
    }
}

pub(super) fn notify_actionable(app: &AppHandle, runtime: &Runtime, error_is_persistent: bool) {
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

fn tray_tooltip<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> String {
    let manager = app.state::<ConnectionManager>();
    let runtimes = manager.all_runtimes();
    let views = runtimes
        .iter()
        .map(|runtime| runtime.view())
        .filter(|view| view.status != "needs_setup" || view.disconnect_available)
        .collect::<Vec<_>>();
    let attention = views
        .iter()
        .filter(|view| {
            matches!(
                view.status,
                "needs_review" | "needs_reconnect" | "offline" | "error"
            ) || view.disconnect_cleanup_pending
        })
        .count();
    let syncing = views.iter().filter(|view| view.status == "syncing").count();
    if attention > 0 {
        format!(
            "ShellX Drive — {attention} of {} servers need attention",
            views.len()
        )
    } else if syncing > 0 {
        format!(
            "ShellX Drive — {syncing} of {} servers syncing",
            views.len()
        )
    } else {
        format!("ShellX Drive — {} servers", views.len())
    }
}

fn build_tray_menu<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<Menu<R>> {
    let manager = app.state::<ConnectionManager>();
    let status = MenuItem::with_id(app, "status", tray_tooltip(app), false, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Open Servers", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&status, &show])?;
    for runtime in manager.all_runtimes() {
        let view = runtime.view();
        if view.status == "needs_setup" && !view.disconnect_available {
            continue;
        }
        let Some(id) = manager.id_for_runtime(&runtime) else {
            continue;
        };
        let item = MenuItem::with_id(
            app,
            format!("connection:{id}"),
            format!(
                "{} · {} — {}",
                view.server_host,
                view.account,
                tray_policy::status_label(view.status)
            ),
            true,
            None::<&str>,
        )?;
        menu.append(&item)?;
    }
    menu.append(&separator)?;
    menu.append(&quit)?;
    Ok(menu)
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn show_review_window(app: &AppHandle) {
    show_main_window(app);
    let _ = app.emit(tray_policy::OPEN_REVIEWS_EVENT, ());
}
