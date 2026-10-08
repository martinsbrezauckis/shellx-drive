//! macOS Tauri shell and tray projection.

use std::ffi::OsStr;

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State,
};
use tauri_plugin_notification::NotificationExt;

use super::*;

mod navigation;
mod tray_sync;

use navigation::{show_main_window, show_reviews};
use tray_sync::{tray_sync_enabled, tray_sync_request, TraySyncRequest};

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
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(runtime)
        .manage(updates::PendingDesktopUpdate::default())
        .invoke_handler(tauri::generate_handler![
            super::super::commands::get_desktop_view,
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
            if runtime.coordinator.snapshot().pair.is_some()
                && !runtime
                    .coordinator
                    .snapshot()
                    .has_pending_disconnect_cleanup()
            {
                sync::start_polling(handle, &runtime);
                let startup = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = startup.state::<Runtime>();
                    let _ = sync::sync_now_impl(&startup, &runtime).await;
                });
            }
            super::super::desktop_agent::start_polling(handle, &runtime);
            super::super::desktop_agent::resume_agent_disconnect_completion(handle);
            Ok(())
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "quit" => app.exit(0),
            "show" => show_main_window(app),
            "review" => show_reviews(app),
            "open-local" => {
                let runtime = app.state::<Runtime>();
                if let Some(pair) = runtime.coordinator.snapshot().pair {
                    let _ = runtime.platform.open_local_root(&pair.local_root);
                }
            }
            "open-drive" => {
                let runtime = app.state::<Runtime>();
                if let Some(pair) = runtime.coordinator.snapshot().pair {
                    let _ = runtime.platform.open_drive_url(&pair.server_url);
                }
            }
            "pause-resume" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = handle.state::<Runtime>();
                    let paused = !runtime.coordinator.snapshot().paused;
                    let _ = lifecycle::persist_paused_state(&runtime, paused).await;
                    update_tray(&handle, &runtime);
                });
            }
            "sync-now" | "recheck-reviews" => {
                let request = tray_sync_request(event.id().as_ref())
                    .expect("tray event arm accepts only sync request IDs");
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = handle.state::<Runtime>();
                    let _ = match request {
                        TraySyncRequest::SyncNow => sync::sync_now_impl(&handle, &runtime).await,
                        TraySyncRequest::RecheckReviews => {
                            sync::recheck_reviews_impl(&handle, &runtime).await
                        }
                    };
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

#[tauri::command]
async fn set_paused(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
    paused: bool,
) -> Result<DesktopView, String> {
    lifecycle::persist_paused_state(&runtime, paused)
        .await
        .map_err(macos_error)?;
    update_tray(&app, &runtime);
    Ok(runtime.view())
}

pub(crate) fn update_tray(app: &tauri::AppHandle, runtime: &Runtime) {
    if let Some(tray) = app.tray_by_id("drive-tray") {
        let _ = tray.set_tooltip(Some(tray_tooltip(runtime)));
        if let Ok(menu) = build_tray_menu(app, runtime) {
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

fn tray_tooltip(runtime: &Runtime) -> String {
    let view = runtime.view();
    match view.status {
        "syncing" => "ShellX Drive — Syncing configured locations".to_string(),
        "needs_review" => format!("ShellX Drive — Needs review ({})", view.review_count),
        _ => format!("ShellX Drive — {}", tray_sync::status_label(view.status)),
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
    let can_sync = paired && !cleanup_pending && !state.paused && tray_sync_enabled(view.status);
    let can_pause = paired && !cleanup_pending && view.status != "syncing";
    let status = MenuItem::with_id(
        app,
        "status",
        format!("ShellX Drive — {}", tray_sync::status_label(view.status)),
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
