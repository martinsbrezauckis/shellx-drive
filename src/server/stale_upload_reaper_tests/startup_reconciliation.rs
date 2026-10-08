use rusqlite::params;

use super::*;

#[test]
fn data_directory_has_one_live_server_owner() {
    let temp = tempfile::tempdir().unwrap();
    let config = test_config(temp.path().to_path_buf());
    let first = AppState::open(config.clone()).unwrap();
    let error = match AppState::open(config.clone()) {
        Ok(_) => panic!("a second live owner unexpectedly acquired the data directory"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("another ShellX Drive process already owns"));
    drop(first);
    AppState::open(config).unwrap();
}

#[test]
fn startup_removes_terminal_parts_and_preserves_active_resumptions() {
    let temp = tempfile::tempdir().unwrap();
    let config = test_config(temp.path().to_path_buf());
    let state = AppState::open(config.clone()).unwrap();
    let (workspace, _, _) = state
        .storage
        .create_workspace("Startup reconciliation", "owner@example.test")
        .unwrap();
    let make_session = |name| {
        state
            .storage
            .create_upload_session(
                UploadSessionCreate {
                    workspace_id: &workspace.id,
                    actor_email: "owner@example.test",
                    parent_id: None,
                    name,
                    total_size: Some(7),
                    path: None,
                    duplicate_policy: "keep_both",
                },
                UploadAdmissionPolicy::default(),
            )
            .unwrap()
    };
    let terminal = make_session("terminal.bin");
    let active = make_session("active.bin");
    rusqlite::Connection::open(temp.path().join("drive.db"))
        .unwrap()
        .execute(
            "UPDATE upload_sessions SET completed = 1 WHERE id = ?1",
            params![&terminal.id],
        )
        .unwrap();
    let upload_dir = state.data_dir().join("uploads");
    let terminal_part = upload_dir.join(format!("{}.part", terminal.id));
    let active_part = upload_dir.join(format!("{}.part", active.id));
    std::fs::write(&terminal_part, b"terminal residue").unwrap();
    std::fs::write(&active_part, b"active partial body").unwrap();
    drop(state);

    let reopened = AppState::open(config).unwrap();
    assert!(!terminal_part.exists());
    assert!(active_part.exists());
    assert!(
        !reopened
            .storage
            .get_upload_session(&active.id)
            .unwrap()
            .unwrap()
            .canceled
    );
}

#[path = "startup_reconciliation/drop_recovery.rs"]
mod drop_recovery;

#[test]
fn terminal_part_reconciliation_is_bounded_and_resumable() {
    let temp = tempfile::tempdir().unwrap();
    let state = AppState::open(test_config(temp.path().to_path_buf())).unwrap();
    let (workspace, _, _) = state
        .storage
        .create_workspace("Batched reconciliation", "owner@example.test")
        .unwrap();
    let terminal = state
        .storage
        .create_upload_session(
            UploadSessionCreate {
                workspace_id: &workspace.id,
                actor_email: "owner@example.test",
                parent_id: None,
                name: "terminal.bin",
                total_size: Some(7),
                path: None,
                duplicate_policy: "keep_both",
            },
            UploadAdmissionPolicy::default(),
        )
        .unwrap();
    rusqlite::Connection::open(temp.path().join("drive.db"))
        .unwrap()
        .execute(
            "UPDATE upload_sessions SET completed = 1 WHERE id = ?1",
            params![&terminal.id],
        )
        .unwrap();
    let upload_dir = state.data_dir().join("uploads");
    for index in 0..600 {
        std::fs::write(upload_dir.join(format!("noise-{index}")), b"noise").unwrap();
    }
    let terminal_part = upload_dir.join(format!("{}.part", terminal.id));
    std::fs::write(&terminal_part, b"terminal residue").unwrap();

    for batch_index in 0..10 {
        let batch = routes::uploads::cleanup::reconcile_terminal_upload_parts_lock_safe(
            &state,
            STALE_UPLOAD_MAX_AGE_SECONDS,
        )
        .unwrap();
        assert!(batch.inspected <= 256);
        if batch.complete {
            assert!(batch_index >= 2);
            assert!(!terminal_part.exists());
            return;
        }
    }
    panic!("upload part reconciliation did not complete in bounded batches");
}
