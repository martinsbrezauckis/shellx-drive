//! Bounded readback and platform-handler adapters for broker commands.

use shellx_drive_desktop_core::{DesktopError, Result as CoreResult};
use tauri::{AppHandle, Manager};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::DesktopView;
use super::{current_agent_assertion, Runtime};

mod disconnect_cleanup;
mod disconnect_sessions;
mod readback;

pub(super) use disconnect_cleanup::{
    complete_agent_disconnect_local_cleanup, persist_agent_disconnect_admission,
};
pub(super) use disconnect_sessions::{bound_agent_owner_session, retire_non_bound_agent_sessions};
pub(super) use readback::{agent_view_result, roots_discovered_result};

pub(super) fn agent_sync_result(
    runtime: &Runtime,
) -> CoreResult<shellx_drive_desktop_core::DesktopAgentResultPayload> {
    let view = agent_view_result(runtime, &Default::default())?;
    let shellx_drive_desktop_core::DesktopAgentResultPayload::DesktopView {
        status,
        pending_review_count,
        ..
    } = view
    else {
        unreachable!("agent view helper always constructs its bounded view result");
    };
    Ok(shellx_drive_desktop_core::DesktopAgentResultPayload::Sync {
        status,
        pending_review_count,
    })
}

pub(super) fn refresh_platform_tray(app: &AppHandle, runtime: &Runtime) {
    #[cfg(target_os = "linux")]
    crate::application::linux::update_tray(app, runtime);
    #[cfg(target_os = "macos")]
    crate::application::macos::update_tray(app, runtime);
    #[cfg(target_os = "windows")]
    crate::application::windows::update_tray(app, runtime);
}

pub(super) fn server_validated_result(
    runtime: &Runtime,
) -> CoreResult<shellx_drive_desktop_core::DesktopAgentResultPayload> {
    Ok(
        shellx_drive_desktop_core::DesktopAgentResultPayload::ServerValidated {
            status: current_agent_assertion(runtime)?.status,
        },
    )
}

pub(super) async fn check_update(
    app: &AppHandle,
) -> CoreResult<shellx_drive_desktop_core::DesktopAgentResultPayload> {
    let info = app
        .state::<crate::application::update_service::DesktopUpdateService>()
        .check(app)
        .await
        .map_err(|error| DesktopError::InvalidState(error.to_string()))?;
    Ok(match info {
        Some(info) => shellx_drive_desktop_core::DesktopAgentResultPayload::UpdateCheck {
            availability:
                shellx_drive_desktop_core::DesktopAgentUpdateAvailability::CandidateAvailable,
            candidate_id: Some(info.candidate_id),
        },
        None => shellx_drive_desktop_core::DesktopAgentResultPayload::UpdateCheck {
            availability: shellx_drive_desktop_core::DesktopAgentUpdateAvailability::UpToDate,
            candidate_id: None,
        },
    })
}

pub(super) async fn dispatch_review_confirmation(
    app: &AppHandle,
    runtime: &Runtime,
    review_id: String,
    action: shellx_drive_desktop_core::ReviewAction,
    confirmation_id: String,
) -> CoreResult<()> {
    #[cfg(target_os = "linux")]
    {
        crate::application::linux::sync::reviews::choose_review_action_impl(
            app,
            runtime,
            review_id,
            action,
            confirmation_id,
        )
        .await
        .map(|_| ())
        .map_err(DesktopError::InvalidState)
    }
    #[cfg(target_os = "macos")]
    {
        crate::application::macos::review_execution::choose_review_action_impl(
            app,
            runtime,
            review_id,
            action,
            confirmation_id,
        )
        .await
        .map(|_| ())
        .map_err(DesktopError::InvalidState)
    }
    #[cfg(target_os = "windows")]
    {
        crate::application::windows::choose_review_action_impl(
            app,
            runtime,
            review_id,
            action,
            confirmation_id,
        )
        .await
        .map(|_| ())
        .map_err(DesktopError::InvalidState)
    }
}

pub(super) async fn dispatch_select_pair(
    app: &AppHandle,
    runtime: &Runtime,
    pair_id: String,
) -> CoreResult<()> {
    #[cfg(target_os = "linux")]
    {
        crate::application::linux::roots::select_pair_impl(app, runtime, pair_id)
            .await
            .map(|_| ())
            .map_err(DesktopError::InvalidState)
    }
    #[cfg(target_os = "macos")]
    {
        crate::application::macos::pairing::select_pair_impl(app, runtime, pair_id)
            .await
            .map(|_| ())
            .map_err(DesktopError::InvalidState)
    }
    #[cfg(target_os = "windows")]
    {
        crate::application::windows::pair_selection::select_pair_impl(app, runtime, pair_id)
            .await
            .map(|_| ())
            .map_err(DesktopError::InvalidState)
    }
}

/// Refreshes server-authorized roots only below the already selected native
/// base. The caller decides whether that base exists before reaching this
/// adapter, so no broker payload can select a local path.
pub(super) async fn dispatch_authorized_root_refresh(runtime: &Runtime) -> CoreResult<()> {
    #[cfg(target_os = "linux")]
    {
        crate::application::linux::roots::refresh_authorized_roots(runtime).await
    }
    #[cfg(target_os = "macos")]
    {
        crate::application::macos::pairing::refresh_authorized_roots(runtime).await
    }
    #[cfg(target_os = "windows")]
    {
        crate::application::windows::root_sync::refresh_authorized_roots(runtime).await
    }
}
