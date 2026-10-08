//! Shared root-discovery command and bounded picker presentation.
//!
//! Discovery is authority-only: it does not pick a path, create a marker, or
//! materialize a root. Native adapters own that later publication step.

use serde::Serialize;
use shellx_drive_desktop_core::{Result as CoreResult, SyncRoot, SyncRootKind, SyncRootRole};
use tauri::State;

use super::Runtime;
pub(crate) mod page;
mod refresh;
pub(crate) use refresh::discover_for_sync_refresh;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkspaceChoice {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) locations: Vec<FolderChoice>,
}

/// Broker and native UI share this authority-only discovery path. It returns
/// bounded server subjects and presentation labels, never a local path or a
/// picker result; selecting a first local base remains a local gesture.
pub(crate) async fn discover_workspace_choices(
    runtime: &Runtime,
) -> CoreResult<Vec<WorkspaceChoice>> {
    Ok(page::discover_workspace_choice_page(runtime, None, 50)
        .await?
        .workspaces)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FolderChoice {
    pub(crate) remote_root_id: Option<String>,
    pub(crate) sync_root_id: String,
    pub(crate) owner_label: String,
    pub(crate) role: SyncRootRole,
    pub(crate) label: String,
}

/// Root selectors retain only the opaque server subject. Presentation data is
/// bounded metadata from root discovery, never a workspace-manifest path.
fn root_choice(root: &SyncRoot) -> FolderChoice {
    FolderChoice {
        remote_root_id: root.root_file_id.clone(),
        sync_root_id: root.id.clone(),
        owner_label: root.owner_label.clone(),
        role: root.role,
        label: root.label.clone(),
    }
}

pub(crate) fn workspace_choices(roots: &[SyncRoot]) -> Vec<WorkspaceChoice> {
    roots
        .iter()
        .map(|root| WorkspaceChoice {
            id: root.workspace_id.clone(),
            name: if root.kind == SyncRootKind::Workspace && root.role == SyncRootRole::Owner {
                root.label.clone()
            } else {
                format!("Shared with me / {}", root.owner_label)
            },
            locations: vec![root_choice(root)],
        })
        .collect()
}

pub(crate) fn workspace_choice_counts(choices: &[WorkspaceChoice]) -> (usize, usize) {
    (
        choices.len(),
        choices.iter().map(|choice| choice.locations.len()).sum(),
    )
}

#[tauri::command]
pub(crate) async fn list_workspaces(
    runtime: State<'_, Runtime>,
) -> Result<Vec<WorkspaceChoice>, String> {
    discover_workspace_choices(&runtime)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) async fn list_workspace_page(
    runtime: State<'_, Runtime>,
    cursor: Option<String>,
) -> Result<page::WorkspaceChoicePage, String> {
    page::discover_workspace_choice_page(&runtime, cursor.as_deref(), 50)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use shellx_drive_desktop_core::{SyncRoot, SyncRootKind, SyncRootRole};

    use super::*;

    #[test]
    fn root_picker_names_each_owned_workspace_without_changing_opaque_subjects() {
        let choices = workspace_choices(&[
            SyncRoot {
                id: "workspace:personal".to_string(),
                kind: SyncRootKind::Workspace,
                workspace_id: "personal".to_string(),
                root_file_id: None,
                grant_id: None,
                owner_label: "Me".to_string(),
                role: SyncRootRole::Owner,
                access_generation: 7,
                expires_at: None,
                label: "My files".to_string(),
            },
            SyncRoot {
                id: "workspace:native-sync-acceptance".to_string(),
                kind: SyncRootKind::Workspace,
                workspace_id: "native-sync-acceptance".to_string(),
                root_file_id: None,
                grant_id: None,
                owner_label: "Me".to_string(),
                role: SyncRootRole::Owner,
                access_generation: 7,
                expires_at: None,
                label: "Native sync acceptance".to_string(),
            },
            SyncRoot {
                id: "item-grant:opaque".to_string(),
                kind: SyncRootKind::ItemGrant,
                workspace_id: "shared".to_string(),
                root_file_id: Some("folder".to_string()),
                grant_id: Some("opaque".to_string()),
                owner_label: "Avery".to_string(),
                role: SyncRootRole::Viewer,
                access_generation: 8,
                expires_at: None,
                label: "Reports".to_string(),
            },
        ]);

        assert_eq!(choices[0].name, "My files");
        assert_eq!(choices[0].id, "personal");
        assert_eq!(choices[0].locations[0].sync_root_id, "workspace:personal");
        assert_eq!(choices[1].name, "Native sync acceptance");
        assert_eq!(choices[1].id, "native-sync-acceptance");
        assert_eq!(
            choices[1].locations[0].sync_root_id,
            "workspace:native-sync-acceptance"
        );
        assert_eq!(choices[2].name, "Shared with me / Avery");
        assert_eq!(choices[2].locations[0].sync_root_id, "item-grant:opaque");
        assert_eq!(
            choices[2].locations[0].remote_root_id.as_deref(),
            Some("folder")
        );
    }
}
