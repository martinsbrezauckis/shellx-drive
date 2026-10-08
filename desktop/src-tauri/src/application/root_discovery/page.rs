//! Bounded authority-only root browsing for the native picker.

use std::time::Duration;

use serde::Serialize;
use shellx_drive_desktop_core::{DesktopError, DriveHttpClient, Result as CoreResult};

use crate::application::{sync_terminal::session::admit_user_session_response, Runtime};

use super::{workspace_choices, WorkspaceChoice};

const MAX_DESKTOP_DISCOVERY_DURATION: Duration = Duration::from_secs(2 * 60);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkspaceChoicePage {
    pub(crate) workspaces: Vec<WorkspaceChoice>,
    pub(crate) next_cursor: Option<String>,
}

pub(crate) async fn discover_workspace_choice_page(
    runtime: &Runtime,
    cursor: Option<&str>,
    limit: u8,
) -> CoreResult<WorkspaceChoicePage> {
    runtime.ensure_disconnect_cleanup_complete()?;
    runtime.require_candidate_recovery_complete()?;
    let discovery = async {
        let session = runtime.current_session()?;
        let token = runtime.current_token(&session)?;
        let client = DriveHttpClient::new(&session.server_url)?;
        let page = admit_user_session_response(
            runtime,
            &session,
            &token,
            client
                .discover_sync_root_page_limited(&token, cursor, limit)
                .await,
        )
        .await?;
        Ok::<WorkspaceChoicePage, DesktopError>(WorkspaceChoicePage {
            workspaces: workspace_choices(&page.roots),
            next_cursor: page.next_cursor,
        })
    };
    tokio::time::timeout(MAX_DESKTOP_DISCOVERY_DURATION, discovery)
        .await
        .map_err(|_| {
            DesktopError::InvalidState(
                "Drive root discovery took too long; check the server and try again.".to_string(),
            )
        })?
}
