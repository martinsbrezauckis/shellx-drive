//! Refresh only configured pair authority; browsing never admits local roots.

use shellx_drive_desktop_core::{
    DesktopError, DesktopState, DriveHttpClient, Result as CoreResult, SyncRoot, SyncRootKind,
    SyncRootRole,
};

use crate::{
    application::{sync_terminal::session::admit_user_session_response, Runtime},
    session_identity::SessionIdentity,
};

/// Every configured root is revalidated against one authenticated server
/// transaction. Available-root pages never materialize automatically.
pub(crate) async fn discover_for_sync_refresh(
    runtime: &Runtime,
    session: &SessionIdentity,
    token: &str,
    client: &DriveHttpClient,
    state: &DesktopState,
) -> CoreResult<(Vec<SyncRoot>, bool)> {
    let configured = state.pairs().map(|pair| {
        if let Some(metadata) = state.sync_root_for_pair(pair) {
            return Ok(metadata.root.clone());
        }
        // Older whole-workspace pairs predate saved root metadata, but
        // their server subject is deterministic. Never infer an item
        // grant subject from a folder ID.
        if pair.remote_root_id.is_none() {
            return Ok(SyncRoot {
                id: format!("workspace:{}", pair.workspace_id),
                kind: SyncRootKind::Workspace,
                workspace_id: pair.workspace_id.clone(),
                root_file_id: None,
                grant_id: None,
                owner_label: "Existing workspace".to_string(),
                role: SyncRootRole::Viewer,
                access_generation: 1,
                expires_at: None,
                label: "Existing workspace".to_string(),
            });
        }
        Err(DesktopError::InvalidState(
            "an existing shared folder has no saved root identity; refresh cannot safely revalidate it".to_string(),
        ))
    }).collect::<CoreResult<Vec<_>>>()?;
    let roots = admit_user_session_response(
        runtime,
        session,
        token,
        client
            .revalidate_configured_sync_roots(token, &configured)
            .await,
    )
    .await?;
    Ok((roots, false))
}
