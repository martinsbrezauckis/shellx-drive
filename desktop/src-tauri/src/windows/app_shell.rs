//! Windows startup, tray, notification, and Tauri application shell.

use super::super::lifecycle::toggle_paused_state;
use super::app_updates::PendingDesktopUpdate;
use super::tray_policy::{status_label, tray_sync_is_enabled};
use super::*;
use tauri::Emitter;

fn tray_tooltip(runtime: &Runtime) -> String {
    let view = runtime.view();
    match view.status {
        "syncing" => "ShellX Drive — Syncing configured locations".to_string(),
        "needs_review" => format!("ShellX Drive — Needs review ({})", view.review_count),
        _ => format!("ShellX Drive — {}", status_label(view.status)),
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
    let credential_available = runtime.require_pair_credential().is_ok();
    let can_sync = tray_sync_is_enabled(
        paired,
        credential_available,
        cleanup_pending,
        state.paused,
        view.status,
    );
    let can_pause = paired && !cleanup_pending && view.status != "syncing";
    let status = MenuItem::with_id(
        app,
        "status",
        format!("ShellX Drive — {}", status_label(view.status)),
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

pub(super) fn user_error(error: DesktopError) -> String {
    error.to_string()
}

pub(super) fn run_from_args() -> i32 {
    let mut args = std::env::args_os();
    let _executable = args.next();
    let first_arg = args.next();
    let uninstall_cleanup =
        first_arg.as_deref() == Some(std::ffi::OsStr::new("--uninstall-cleanup"));
    if uninstall_cleanup && args.next().is_some() {
        eprintln!("ShellX Drive Desktop uninstall cleanup accepts no additional arguments.");
        return 2;
    }
    if !uninstall_cleanup && first_arg.is_some() {
        eprintln!("ShellX Drive Desktop does not accept command-line arguments on Windows.");
        return 2;
    }
    let instance_lease = match instance_lock::DesktopInstanceLease::acquire() {
        Ok(Some(lease)) => lease,
        Ok(None) if uninstall_cleanup => {
            eprintln!("ShellX Drive Desktop must be closed before uninstall cleanup.");
            return 1;
        }
        Ok(None) => {
            if instance_lock::focus_existing_main_window() {
                return 0;
            }
            eprintln!(
                "ShellX Drive Desktop is already running in another Windows session. Close it there before continuing."
            );
            return 1;
        }
        Err(error) => {
            eprintln!("ShellX Drive Desktop could not acquire its process lease: {error}");
            return 1;
        }
    };
    if uninstall_cleanup {
        // The NSIS hook can remove the app only after interactive Disconnect
        // has finished. This flag cannot read credentials or retire sessions.
        return if uninstall_offboarding::verify_disconnected_and_remove_startup().is_ok() {
            0
        } else {
            eprintln!("Open ShellX Drive, finish Disconnect and any pending recovery, then retry uninstall. Synced files and saved credentials were kept.");
            1
        };
    }

    run(instance_lease)
}

fn run(_instance_lease: instance_lock::DesktopInstanceLease) -> i32 {
    let runtime = match Runtime::new() {
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
    // A pending-candidate slot can represent a write that completed just
    // before a provider error or process crash. Reconcile it before allowing
    // automatic sync to use any canonical credential.
    runtime.set_candidate_recovery_pending(true);
    // An interrupted Disconnect owns the exact candidate and canonical slots
    // already captured in its durable cleanup journal. Startup recovery must
    // not promote or remove one of those slots outside that journal.
    let disconnect_cleanup_pending = runtime
        .coordinator
        .snapshot()
        .has_pending_disconnect_cleanup();
    if !disconnect_cleanup_pending && recover_staged_candidates_before_polling(&runtime).is_err() {
        runtime
            .coordinator
            .record_error(CANDIDATE_RECOVERY_PAUSED_ERROR);
        let _ = runtime.save();
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(runtime)
        .manage(PendingDesktopUpdate::default())
        .invoke_handler(tauri::generate_handler![
            super::super::commands::get_desktop_view,
            super::super::desktop_agent::set_desktop_agent_control,
            super::super::commands::validate_server,
            login_password,
            continue_login,
            super::super::root_discovery::list_workspaces,
            super::super::root_discovery::list_workspace_page,
            super::super::commands::pick_local_root,
            root_sync::start_pair,
            root_sync::add_root,
            pair_selection::select_pair,
            sync_runtime::sync_now,
            sync_runtime::recheck_reviews,
            set_paused,
            super::super::commands::set_launch_at_login,
            super::super::commands::open_local_folder,
            super::super::commands::open_drive,
            disconnect,
            super::super::review::prepare_review_action,
            super::super::review::choose_review_action,
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
                start_polling(handle, &runtime);
                // Startup is an authority boundary too: refresh roots now
                // rather than leaving a revoked retained tree eligible for
                // the poll interval. The poller remains the periodic path.
                let startup = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = startup.state::<Runtime>();
                    let state = runtime.coordinator.snapshot();
                    let result = if state.reviews.is_empty() {
                        sync_now_impl(&startup, &runtime).await
                    } else {
                        recheck_reviews_impl(&startup, &runtime, false).await
                    };
                    if let Err(error) = result {
                        eprintln!("ShellX Drive startup root refresh did not complete: {error}");
                    }
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
                let _ = open_pair_local_root(app);
            }
            "open-drive" => {
                let _ = open_pair_server(app);
            }
            "pause-resume" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = handle.state::<Runtime>();
                    if let Err(error) = toggle_paused_state(&runtime).await {
                        eprintln!("ShellX Drive tray pause did not complete: {error}");
                    }
                    update_tray(&handle, &runtime);
                });
            }
            "sync-now" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = handle.state::<Runtime>();
                    if let Err(error) = sync_now_impl(&handle, &runtime).await {
                        eprintln!("ShellX Drive tray sync did not complete: {error}");
                    }
                });
            }
            "recheck-reviews" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let runtime = handle.state::<Runtime>();
                    if let Err(error) = recheck_reviews_impl(&handle, &runtime, true).await {
                        eprintln!("ShellX Drive tray review recheck did not complete: {error}");
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

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn show_reviews(app: &tauri::AppHandle) {
    show_main_window(app);
    let _ = app.emit_to("main", "shellx-drive-open-reviews", ());
}

fn open_pair_local_root(app: &tauri::AppHandle) -> CoreResult<()> {
    let runtime = app.state::<Runtime>();
    let pair = runtime
        .coordinator
        .snapshot()
        .pair
        .ok_or(DesktopError::NeedsSetup)?;
    runtime.platform.open_local_root(&pair.local_root)?;
    Ok(())
}

fn open_pair_server(app: &tauri::AppHandle) -> CoreResult<()> {
    let runtime = app.state::<Runtime>();
    let pair = runtime
        .coordinator
        .snapshot()
        .pair
        .ok_or(DesktopError::NeedsSetup)?;
    runtime.platform.open_drive_url(&pair.server_url)?;
    Ok(())
}
