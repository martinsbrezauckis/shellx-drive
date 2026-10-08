//! Review confirmation admission shared by every desktop target.
//!
//! The confirmation is deliberately separate from the native executor. It
//! validates a current, allowed recoverable decision and captures its durable
//! fingerprint, but never touches a local root or contacts Drive.

use serde::Serialize;
use shellx_drive_desktop_core::ReviewAction;
use tauri::{AppHandle, State};

use super::{ConnectionManager, DesktopView, Runtime};

mod confirmation;
mod native;

pub(crate) use confirmation::{
    ensure_review_confirmation_pair, prepare_review_confirmation,
    prepare_review_confirmation_for_pair,
};
use native::{execute_after_native_choice, native_review_prompt, show_native_review_dialog};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewConfirmation {
    pub(crate) confirmation_id: String,
    relative_path: std::path::PathBuf,
    descendant_count: usize,
    pub(crate) action: ReviewAction,
    #[serde(skip_serializing)]
    pub(crate) fingerprint: String,
}

#[tauri::command]
pub(crate) fn prepare_review_action(
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    review_id: String,
    action: ReviewAction,
) -> Result<ReviewConfirmation, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(|error| error.to_string())?;
    prepare_review_confirmation(&runtime, review_id, action).map_err(|error| error.to_string())
}

/// The renderer may request a decision, but only the native dialog callback
/// can admit its command to the platform executor. Desktop-agent confirmations
/// use their separately authorized dispatcher and do not call this IPC entry.
#[tauri::command]
pub(crate) async fn choose_review_action(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    review_id: String,
    action: ReviewAction,
    confirmation_id: String,
) -> Result<DesktopView, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(|error| error.to_string())?;
    let prompt = native_review_prompt(&runtime, &review_id, action, &confirmation_id)?;
    execute_after_native_choice(show_native_review_dialog(&app, prompt).await, || async {
        #[cfg(target_os = "windows")]
        {
            return super::windows::choose_review_action_impl(
                &app,
                &runtime,
                review_id,
                action,
                confirmation_id,
            )
            .await;
        }
        #[cfg(target_os = "macos")]
        {
            return super::macos::review_execution::choose_review_action_impl(
                &app,
                &runtime,
                review_id,
                action,
                confirmation_id,
            )
            .await;
        }
        #[cfg(target_os = "linux")]
        {
            return super::linux::sync::reviews::choose_review_action_impl(
                &app,
                &runtime,
                review_id,
                action,
                confirmation_id,
            )
            .await;
        }
    })
    .await
}

#[cfg(test)]
#[path = "review/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "review/agent_confirmation_tests.rs"]
mod agent_confirmation_tests;
