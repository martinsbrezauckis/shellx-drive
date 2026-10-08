use crate::{
    DesktopAgentCommandKind, DesktopAgentResultCode, DesktopAgentResultPayload,
    DesktopAgentRootRow, DesktopAgentRootSelectionStatus, DesktopAgentRootsPage, SyncRootRole,
};

fn row(id: &str) -> DesktopAgentRootRow {
    DesktopAgentRootRow {
        workspace_id: "workspace_1".to_string(),
        workspace_name: "Workspace".to_string(),
        sync_root_id: id.to_string(),
        remote_root_id: None,
        root_name: "My files".to_string(),
        owner_label: "Person".to_string(),
        role: SyncRootRole::Owner,
        selection_status: DesktopAgentRootSelectionStatus::Available,
    }
}

fn result(
    rows: Vec<DesktopAgentRootRow>,
    after: Option<&str>,
    next: Option<&str>,
) -> DesktopAgentResultPayload {
    DesktopAgentResultPayload::RootsDiscovered {
        workspace_count: 1,
        candidate_count: rows.len() as u16,
        requires_local_selection: true,
        page: DesktopAgentRootsPage {
            after: after.map(str::to_string),
            limit: 1,
            rows,
        },
        next_after: next.map(str::to_string),
    }
}

#[test]
fn root_readback_accepts_opaque_cursor_and_empty_advancing_page() {
    let previous = "opaque.page_1";
    let next = "opaque.page_2";
    for value in [
        result(vec![row("workspace:private")], None, Some(previous)),
        result(Vec::new(), Some(previous), Some(next)),
    ] {
        value
            .validate_for(
                DesktopAgentCommandKind::DiscoverRoots,
                DesktopAgentResultCode::RootsDiscovered,
            )
            .unwrap();
    }
    assert!(result(Vec::new(), Some(previous), Some(previous))
        .validate_for(
            DesktopAgentCommandKind::DiscoverRoots,
            DesktopAgentResultCode::RootsDiscovered
        )
        .is_err());
    assert!(
        result(vec![row("workspace:one"), row("workspace:one")], None, None)
            .validate_for(
                DesktopAgentCommandKind::DiscoverRoots,
                DesktopAgentResultCode::RootsDiscovered
            )
            .is_err()
    );
}
