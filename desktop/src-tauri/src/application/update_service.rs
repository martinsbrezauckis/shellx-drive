//! Typed, durable desktop-update lifecycle independent of WebView IPC.

use std::{fmt, sync::Mutex};

use serde::Serialize;
use shellx_drive_desktop_core::DesktopError;
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;
use uuid::Uuid;

use super::Runtime;

mod install;
mod lifecycle;
mod slot;

pub(crate) use install::{DesktopUpdateLifecycleHook, DesktopUpdateLifecycleStage};
pub(crate) use lifecycle::reconcile_desktop_update_restart;
use slot::UpdateSlot;

#[derive(Default)]
pub(crate) struct DesktopUpdateService(Mutex<UpdateSlot>);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopUpdateInfo {
    pub(crate) candidate_id: String,
    pub(crate) version: String,
    pub(crate) current_version: String,
    pub(crate) notes: Option<String>,
    pub(crate) published_at: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "event",
    content = "data",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum DesktopUpdateEvent {
    Started { content_length: Option<u64> },
    Progress { chunk_length: usize },
    Downloaded,
    Verified,
    Restarting,
}

#[derive(Debug)]
pub(crate) enum DesktopUpdateServiceError {
    NoCheckedUpdate,
    CandidateMismatch,
    InProgress,
    StateUnavailable,
    Lifecycle(DesktopError),
    Updater(String),
}

impl fmt::Display for DesktopUpdateServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCheckedUpdate => {
                formatter.write_str("Check for an update before installing it.")
            }
            Self::CandidateMismatch => {
                formatter.write_str("Check for this update again before installing it.")
            }
            Self::InProgress => formatter.write_str("A desktop update is already installing."),
            Self::StateUnavailable => formatter.write_str("Desktop update state is unavailable."),
            Self::Lifecycle(error) => error.fmt(formatter),
            Self::Updater(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for DesktopUpdateServiceError {}

impl From<DesktopError> for DesktopUpdateServiceError {
    fn from(error: DesktopError) -> Self {
        Self::Lifecycle(error)
    }
}

impl DesktopUpdateService {
    pub(crate) async fn check(
        &self,
        app: &AppHandle,
    ) -> Result<Option<DesktopUpdateInfo>, DesktopUpdateServiceError> {
        let update = app
            .updater()
            .map_err(|error| DesktopUpdateServiceError::Updater(error.to_string()))?
            .check()
            .await
            .map_err(|error| DesktopUpdateServiceError::Updater(error.to_string()))?;
        let candidate_id = update.as_ref().map(|_| Uuid::new_v4().to_string());
        let info = update
            .as_ref()
            .zip(candidate_id.as_ref())
            .map(|(update, candidate_id)| DesktopUpdateInfo {
                candidate_id: candidate_id.clone(),
                version: update.version.clone(),
                current_version: update.current_version.clone(),
                notes: update.body.clone(),
                published_at: update.date.map(|date| date.to_string()),
            });
        let mut slot = self.lock()?;
        if matches!(*slot, UpdateSlot::Installing) {
            return Err(DesktopUpdateServiceError::InProgress);
        }
        *slot = match (update, candidate_id) {
            (Some(update), Some(candidate_id)) => UpdateSlot::Ready {
                candidate_id,
                update: Box::new(update),
            },
            _ => UpdateSlot::Empty,
        };
        Ok(info)
    }
}
