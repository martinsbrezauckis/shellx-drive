use super::*;

#[test]
fn startup_recovers_committed_drop_finalization_residue_without_touching_active_parts() {
    let temp = tempfile::tempdir().unwrap();
    let config = test_config(temp.path().to_path_buf());
    let state = AppState::open(config.clone()).unwrap();
    let (workspace, _, _) = state
        .storage
        .create_workspace("Drop finalization recovery", "owner@example.test")
        .unwrap();
    let operator = crate::auth::Actor {
        email: "system@local".to_string(),
        is_admin: true,
        auth_mode: crate::auth::AuthMode::Operator,
        allowed_workspace_ids: None,
    };
    let (drop_link, _) = state
        .storage
        .create_drop(
            DropCreateFields {
                workspace_id: &workspace.id,
                name: "Finalization recovery inbox",
                password_hash: "drop-password-hash",
                password_required: true,
                expires_in_seconds: 3_600,
            },
            &operator,
            &crate::auth::DriveCredential::Operator,
        )
        .unwrap();
    let authorization_fingerprint = state
        .storage
        .get_drop(&drop_link.id)
        .unwrap()
        .unwrap()
        .authorization_fingerprint();
    let make_session = |name| {
        state
            .storage
            .create_drop_upload_session(DropUploadSessionCreate {
                drop_id: &drop_link.id,
                workspace_id: &workspace.id,
                client_fingerprint: "drop-client",
                transport_fingerprint: "drop-transport",
                expected_authorization_fingerprint: &authorization_fingerprint,
                name,
                path: None,
                content_type: Some("application/octet-stream"),
                total_size: 7,
                policy: DropUploadAdmissionPolicy::default(),
            })
            .unwrap()
            .0
    };
    let committed = make_session("committed-before-unlink.bin");
    state
        .storage
        .update_drop_upload_received(&committed.id, 0, 7)
        .unwrap();
    state
        .storage
        .finalize_drop_upload_file(&committed.id, "committed-before-unlink")
        .unwrap();
    assert_eq!(
        state
            .storage
            .get_drop_upload_session(&committed.id)
            .unwrap()
            .unwrap()
            .status,
        "completed"
    );
    let active = make_session("active-resumption.bin");

    let drop_dir = state.data_dir().join("drop-uploads");
    std::fs::create_dir_all(&drop_dir).unwrap();
    let committed_part = drop_dir.join(format!("{}.part", committed.id));
    let active_part = drop_dir.join(format!("{}.part", active.id));
    let committed_lock = drop_dir.join(format!("{}.lock", committed.id));
    let active_lock = drop_dir.join(format!("{}.lock", active.id));
    std::fs::write(&committed_part, b"post-commit crash residue").unwrap();
    std::fs::write(&active_part, b"active partial body").unwrap();
    std::fs::write(&committed_lock, b"stable committed lock").unwrap();
    std::fs::write(&active_lock, b"stable active lock").unwrap();
    let committed_lock_inode = committed_lock.metadata().unwrap().ino();
    let active_lock_inode = active_lock.metadata().unwrap().ino();
    drop(state);

    let reopened = AppState::open(config).unwrap();
    assert!(!committed_part.exists());
    assert!(active_part.exists());
    assert_eq!(
        reopened
            .storage
            .get_drop_upload_session(&committed.id)
            .unwrap()
            .unwrap()
            .status,
        "completed"
    );
    assert_eq!(
        reopened
            .storage
            .get_drop_upload_session(&active.id)
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    assert_eq!(
        committed_lock.metadata().unwrap().ino(),
        committed_lock_inode
    );
    assert_eq!(active_lock.metadata().unwrap().ino(), active_lock_inode);
}
