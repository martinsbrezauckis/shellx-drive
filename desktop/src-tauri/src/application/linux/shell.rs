//! Linux Tauri shell, tray surface, and startup ownership.

use std::ffi::OsStr;

use shellx_drive_desktop_core::{DesktopError, Result as CoreResult, SyncStatus};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
use tauri_plugin_notification::NotificationExt;

use crate::application::{commands, lifecycle, review, root_discovery, Runtime};

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
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ShellX Drive Desktop could not load its non-secret state: {error}");
            return 1;
        }
    };
    runtime.reconcile_launch_at_login();
    if let Err(error) =
        crate::application::update_service::reconcile_desktop_update_restart(&runtime)
    {
        eprintln!("ShellX Drive Desktop could not reconcile its pending update restart: {error}");
    }
    candidate::recover_at_startup(&runtime);
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(runtime)
        .manage(app_updates::PendingDesktopUpdate::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_desktop_view,
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
            let runtime = handle.state::<Runtime>();
            let menu = build_tray_menu(handle, &runtime)?;
            TrayIconBuilder::with_id("drive-tray")
                .menu(&menu)
                .icon(
                    handle
                        .default_window_icon()
                        .cloned()
                        .expect("ShellX Drive tray icon is bundled"),
                )
                .tooltip(tray_tooltip(&runtime))
                .show_menu_on_left_click(false)
                .build(app)?;
            if !runtime.candidate_recovery_pending()
                && runtime.coordinator.snapshot().pair.is_some()
            {
                sync::start_polling(handle, &runtime);
                let startup = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = startup.state::<Runtime>();
                    if let Err(error) = sync::sync_or_recheck(&startup, &runtime, false).await {
                        eprintln!("ShellX Drive Linux startup sync did not complete: {error}");
                    }
                });
            }
            crate::application::desktop_agent::start_polling(handle, &runtime);
            crate::application::desktop_agent::resume_agent_disconnect_completion(handle);
            Ok(())
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "quit" => app.exit(0),
            "show" => show_main_window(app),
            "review" => show_review_window(app),
            "open-local" => {
                let _ = open_pair_local_root(app);
            }
            "open-drive" => {
                let _ = open_pair_server(app);
            }
            "pause-resume" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = handle.state::<Runtime>();
                    if let Err(error) = lifecycle::toggle_paused_state(&runtime).await {
                        eprintln!("ShellX Drive tray pause did not complete: {error}");
                    }
                    update_tray(&handle, &runtime);
                });
            }
            "sync-now" | "recheck-reviews" => {
                let recheck = event.id().as_ref() == "recheck-reviews";
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = handle.state::<Runtime>();
                    if let Err(error) = sync::sync_or_recheck(&handle, &runtime, recheck).await {
                        eprintln!("ShellX Drive tray sync did not complete: {error}");
                    }
                });
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
        let (store, mut state) = Self::load_state()?;
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

pub(crate) fn update_tray(app: &AppHandle, runtime: &Runtime) {
    if let Some(tray) = app.tray_by_id("drive-tray") {
        let _ = tray.set_tooltip(Some(tray_tooltip(runtime)));
        if let Ok(menu) = build_tray_menu(app, runtime) {
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

fn tray_tooltip(runtime: &Runtime) -> String {
    let view = runtime.view();
    match view.status {
        "syncing" => "ShellX Drive — Syncing configured locations".to_string(),
        "needs_review" => format!("ShellX Drive — Needs review ({})", view.review_count),
        _ => format!("ShellX Drive — {}", tray_policy::status_label(view.status)),
    }
}

fn build_tray_menu<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    runtime: &Runtime,
) -> tauri::Result<Menu<R>> {
    let state = runtime.coordinator.snapshot();
    let view = runtime.view();
    let paired = state.pair.is_some();
    let review_pending = state.has_any_reviews();
    let cleanup_pending = state.has_pending_disconnect_cleanup();
    let can_sync = tray_policy::can_sync(paired, cleanup_pending, state.paused, runtime.status());
    let can_pause = paired && !cleanup_pending && runtime.status() != SyncStatus::Syncing;
    let status = MenuItem::with_id(
        app,
        "status",
        format!("ShellX Drive — {}", tray_policy::status_label(view.status)),
        false,
        None::<&str>,
    )?;
    let show = MenuItem::with_id(app, "show", "Open ShellX Drive", true, None::<&str>)?;
    let open_local =
        MenuItem::with_id(app, "open-local", "Open local folder", paired, None::<&str>)?;
    let open_drive = MenuItem::with_id(app, "open-drive", "Open Drive", paired, None::<&str>)?;
    let sync = MenuItem::with_id(
        app,
        if review_pending {
            "recheck-reviews"
        } else {
            "sync-now"
        },
        if review_pending {
            "Recheck review"
        } else {
            "Sync now"
        },
        can_sync,
        None::<&str>,
    )?;
    let pause = MenuItem::with_id(
        app,
        "pause-resume",
        if state.paused { "Resume" } else { "Pause" },
        can_pause,
        None::<&str>,
    )?;
    let review = MenuItem::with_id(app, "review", "Review issues", review_pending, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    Menu::with_items(
        app,
        &[
            &status,
            &show,
            &open_local,
            &open_drive,
            &sync,
            &pause,
            &review,
            &separator,
            &quit,
        ],
    )
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

fn open_pair_local_root(app: &AppHandle) -> CoreResult<()> {
    let runtime = app.state::<Runtime>();
    let pair = runtime
        .coordinator
        .snapshot()
        .pair
        .ok_or(DesktopError::NeedsSetup)?;
    runtime.platform.open_local_root(&pair.local_root)
}

fn open_pair_server(app: &AppHandle) -> CoreResult<()> {
    let runtime = app.state::<Runtime>();
    let pair = runtime
        .coordinator
        .snapshot()
        .pair
        .ok_or(DesktopError::NeedsSetup)?;
    runtime.platform.open_drive_url(&pair.server_url)
}
