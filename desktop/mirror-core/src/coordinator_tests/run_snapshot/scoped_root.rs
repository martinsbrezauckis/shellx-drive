use super::*;

#[test]
fn scoped_manifest_may_refresh_only_the_bound_root_subject() {
    let mut state = DesktopState::default();
    let pair = pair("workspace", "C:/Drive");
    state.configure_pair(pair.clone()).unwrap();
    let root = crate::SyncRoot {
        id: "workspace:workspace".to_string(),
        kind: crate::SyncRootKind::Workspace,
        workspace_id: "workspace".to_string(),
        root_file_id: None,
        grant_id: None,
        owner_label: "Owner".to_string(),
        role: crate::SyncRootRole::Owner,
        access_generation: 1,
        expires_at: None,
        label: "My files".to_string(),
    };
    state.record_sync_root(&pair, root.clone()).unwrap();
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    let mut narrowed = root.clone();
    narrowed.role = crate::SyncRootRole::Viewer;
    narrowed.access_generation = 2;
    run.refresh_active_sync_root(narrowed, chrono::Utc::now())
        .unwrap();
    assert_eq!(
        run.sync_root_for_active_pair().unwrap().root.role,
        crate::SyncRootRole::Viewer
    );
    let mut sibling = root;
    sibling.id = "workspace:other".to_string();
    assert!(run
        .refresh_active_sync_root(sibling, chrono::Utc::now())
        .is_err());
}
