//! Native confirmation binds a current review witness before executor admission.

use std::future::Future;

use shellx_drive_desktop_core::{
    resolve_review_decision, review_confirmation_fingerprint, sync_pair_id, ReviewAction,
    ReviewDecision,
};
use tauri::AppHandle;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use super::{ensure_review_confirmation_pair, Runtime};

pub(super) fn native_review_prompt(
    runtime: &Runtime,
    review_id: &str,
    action: ReviewAction,
    confirmation_id: &str,
) -> Result<String, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(|error| error.to_string())?;
    let (pair_id, fingerprint) = {
        let pending = runtime
            .pending_review_confirmation
            .lock()
            .expect("review confirmation lock");
        let pending = pending
            .as_ref()
            .ok_or_else(|| "That review action is no longer pending confirmation.".to_string())?;
        (pending.pair_id.clone(), pending.fingerprint.clone())
    };
    ensure_review_confirmation_pair(
        runtime,
        &pair_id,
        review_id,
        action,
        confirmation_id,
        &fingerprint,
    )
    .map_err(|error| error.to_string())?;
    let state = runtime.coordinator.snapshot();
    let pair = state
        .pair
        .as_ref()
        .ok_or_else(|| "The selected Drive location changed. Recheck this review.".to_string())?;
    if sync_pair_id(pair) != pair_id {
        return Err("The selected Drive location changed. Recheck this review.".to_string());
    }
    let item = state
        .reviews
        .iter()
        .find(|item| item.id == review_id)
        .ok_or_else(|| "That review item is no longer pending.".to_string())?;
    if review_confirmation_fingerprint(&state, item).map_err(|error| error.to_string())?
        != fingerprint
    {
        return Err("The review changed. Recheck and confirm the current item.".to_string());
    }
    let action_copy =
        match resolve_review_decision(item, action).map_err(|error| error.to_string())? {
            ReviewDecision::TrashRemote => "Move this file to Drive trash",
            ReviewDecision::RestoreLocal => "Restore this file to the local Drive folder",
            ReviewDecision::RecoverLocal => "Move this local copy to recovery",
            ReviewDecision::RestoreRemote => "Restore this file to Drive",
            ReviewDecision::RemoveRetainedRoot => {
                "Move this retained local Drive root to recovery and remove its pairing"
            }
        };
    let root_name = pair
        .remote_root_name
        .as_deref()
        .unwrap_or(&pair.workspace_name);
    Ok(format!(
        "{action_copy}?\n\nDrive location: {root_name:?}\nItem: {:?}\nAffected descendants: {}\n\nThis requires confirmation in the native desktop dialog.",
        item.relative_path, item.descendant_count
    ))
}

pub(super) async fn show_native_review_dialog(app: &AppHandle, prompt: String) -> bool {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog()
        .message(prompt)
        .title("Confirm ShellX Drive review action")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Confirm action".to_string(),
            "Cancel".to_string(),
        ))
        .show(move |confirmed| {
            let _ = sender.send(confirmed);
        });
    receiver.await.unwrap_or(false)
}

pub(super) async fn execute_after_native_choice<T, F, Fut>(
    confirmed: bool,
    execute: F,
) -> Result<T, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    if !confirmed {
        return Err("Native confirmation was cancelled; no review action was applied.".to_string());
    }
    execute().await
}
