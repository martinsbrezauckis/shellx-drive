use super::{
    completion::fail_next_new_upload_completion_before_commit, UploadAdmissionPolicy,
    UploadSessionCreate,
};
use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    model::UploadSession,
    storage::{NewUploadCompletion, Storage},
};

fn operator() -> Actor {
    Actor {
        email: "system@local".to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    }
}

fn new_session(storage: &Storage) -> UploadSession {
    let (workspace, _, _) = storage
        .create_workspace("Atomic upload finalization", "owner@example.test")
        .unwrap();
    storage
        .create_upload_session(
            UploadSessionCreate {
                workspace_id: &workspace.id,
                actor_email: "owner@example.test",
                parent_id: None,
                name: "final.bin",
                total_size: Some(3),
                path: None,
                duplicate_policy: "keep_both",
            },
            UploadAdmissionPolicy::default(),
        )
        .unwrap()
}

#[test]
fn new_upload_finalization_commits_file_session_receipts_and_jobs_together() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let session = new_session(&storage);
    let actor = operator();

    let completed = storage
        .complete_new_upload_session(NewUploadCompletion {
            upload_id: &session.id,
            actor: &actor,
            source_credential: &DriveCredential::Operator,
            received_bytes: 3,
            parent_id: None,
            name: session.name.clone(),
            content_hash: "published-hash",
        })
        .unwrap();

    assert!(completed.session.completed);
    assert_eq!(
        completed.session.file_id.as_deref(),
        Some(completed.file.id.as_str())
    );
    assert_eq!(storage.list_files().unwrap().len(), 1);
    assert_eq!(storage.background_job_totals().unwrap().queued, 2);
    assert_eq!(
        storage
            .get_upload_session(&session.id)
            .unwrap()
            .unwrap()
            .completion_receipt_id
            .as_deref(),
        Some(completed.receipt.id.as_str())
    );
}

#[test]
fn new_upload_finalization_crash_boundary_rolls_back_every_durable_reference() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let session = new_session(&storage);
    let actor = operator();
    let receipts_before: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
        .unwrap();

    fail_next_new_upload_completion_before_commit();
    assert!(storage
        .complete_new_upload_session(NewUploadCompletion {
            upload_id: &session.id,
            actor: &actor,
            source_credential: &DriveCredential::Operator,
            received_bytes: 3,
            parent_id: None,
            name: session.name.clone(),
            content_hash: "published-hash",
        })
        .is_err());

    let current = storage.get_upload_session(&session.id).unwrap().unwrap();
    assert!(!current.completed);
    assert!(!current.canceled);
    assert_eq!(current.received_bytes, 0);
    assert!(storage.list_files().unwrap().is_empty());
    assert_eq!(storage.background_job_totals().unwrap().queued, 0);
    let receipts_after: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(receipts_after, receipts_before);
}
