use std::{
    sync::{Arc, Barrier},
    thread,
};

use chrono::{Duration, Utc};
use rusqlite::params;
use uuid::Uuid;

use crate::{
    auth::{token_hash, Actor, AuthMode, DriveCredential, WorkspaceRole},
    error::ApiError,
    model::{
        CreateFileRequest, FileKind, NullableI64Patch, UpdateWorkspacePolicyRequest, Workspace,
    },
    storage::{DropCreateFields, DropUploadAdmissionPolicy, DropUploadSessionCreate},
};

use super::{super::Storage, ShareCreateFields, ShareRecord};

fn owner_with_workspace(storage: &Storage) -> (Actor, DriveCredential, Workspace) {
    let email = "owner@example.test";
    let (account, workspace, _, _) = storage
        .bootstrap_auth_account_with_workspace(email, "stored-password-hash", "Publication", "open")
        .unwrap();
    let session_id = Uuid::now_v7().to_string();
    storage
        .record_auth_session(
            &session_id,
            email,
            "local-password",
            &account.user_id,
            "stored-session-token-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    (
        Actor {
            email: email.to_string(),
            is_admin: true,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        },
        DriveCredential::UserSession(session_id),
        workspace,
    )
}

#[test]
fn pending_public_capabilities_are_hidden_until_terminal_publication() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential, workspace) = owner_with_workspace(&storage);
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "shared.txt".to_string(),
                kind: FileKind::File,
                content: Some("private".to_string()),
                path: None,
            },
            Some("a".repeat(64)),
        )
        .unwrap();

    let password_hash = "share-password-hash";
    let (share, share_receipt) = storage
        .create_pending_share_publication(
            ShareCreateFields {
                file_id: &file.id,
                password_hash,
                password_required: true,
                expires_in_seconds: 3_600,
                target_kind: "file",
                allow_download: true,
                recipient_note: None,
                max_uses: None,
            },
            &actor,
            &credential,
        )
        .unwrap();
    let share_fingerprint = ShareRecord::authorization_fingerprint_for(true, password_hash);
    assert!(storage.get_share(&share.id).unwrap().is_none());
    assert!(storage.list_file_shares(&file.id).unwrap().is_empty());
    assert!(matches!(
        storage.claim_share_access(&share.id, &share_fingerprint, "client-a"),
        Err(ApiError::NotFound)
    ));

    storage
        .publish_pending_share(&share.id, &share_receipt, &actor, &credential)
        .unwrap();
    assert!(storage.get_share(&share.id).unwrap().is_some());
    assert_eq!(storage.list_file_shares(&file.id).unwrap().len(), 1);
    assert!(storage
        .claim_share_access(&share.id, &share_fingerprint, "client-a")
        .is_ok());

    let drop_password_hash = "drop-password-hash";
    let (drop, drop_receipt) = storage
        .create_pending_drop_publication(
            DropCreateFields {
                workspace_id: &workspace.id,
                name: "Inbox",
                password_hash: drop_password_hash,
                password_required: true,
                expires_in_seconds: 3_600,
            },
            &actor,
            &credential,
        )
        .unwrap();
    let drop_fingerprint = token_hash(&format!("drop-authorization-v1\0{drop_password_hash}"));
    assert!(storage.get_drop(&drop.id).unwrap().is_none());
    assert!(storage
        .list_workspace_drops(&workspace.id)
        .unwrap()
        .is_empty());
    assert!(matches!(
        storage.create_drop_upload_session(DropUploadSessionCreate {
            drop_id: &drop.id,
            workspace_id: &workspace.id,
            client_fingerprint: "client-a",
            transport_fingerprint: "transport-a",
            expected_authorization_fingerprint: &drop_fingerprint,
            name: "upload.txt",
            path: None,
            content_type: None,
            total_size: 0,
            policy: DropUploadAdmissionPolicy::default(),
        }),
        Err(ApiError::NotFound)
    ));

    storage
        .publish_pending_drop(&drop.id, &drop_receipt, true, 3_600, &actor, &credential)
        .unwrap();
    assert!(storage.get_drop(&drop.id).unwrap().is_some());
    assert_eq!(
        storage.list_workspace_drops(&workspace.id).unwrap().len(),
        1
    );
    assert!(storage
        .create_drop_upload_session(DropUploadSessionCreate {
            drop_id: &drop.id,
            workspace_id: &workspace.id,
            client_fingerprint: "client-a",
            transport_fingerprint: "transport-a",
            expected_authorization_fingerprint: &drop_fingerprint,
            name: "upload.txt",
            path: None,
            content_type: None,
            total_size: 0,
            policy: DropUploadAdmissionPolicy::default(),
        })
        .is_ok());
}

#[test]
fn pending_share_is_deleted_when_its_source_session_is_revoked_at_publication() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("drive.db");
    let storage = Arc::new(Storage::open(db_path.clone()).unwrap());
    storage.migrate().unwrap();
    let (actor, credential, workspace) = owner_with_workspace(&storage);
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: "shared.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (share, receipt) = storage
        .create_pending_share_publication(
            ShareCreateFields {
                file_id: &file.id,
                password_hash: "share-password-hash",
                password_required: true,
                expires_in_seconds: 3_600,
                target_kind: "file",
                allow_download: true,
                recipient_note: None,
                max_uses: None,
            },
            &actor,
            &credential,
        )
        .unwrap();
    let DriveCredential::UserSession(session_id) = &credential else {
        unreachable!();
    };
    let reached_terminal_boundary = Arc::new(Barrier::new(2));
    let release_terminal_revalidation = Arc::new(Barrier::new(2));
    let worker_storage = Arc::clone(&storage);
    let worker_actor = actor.clone();
    let worker_credential = credential.clone();
    let worker_share_id = share.id.clone();
    let worker_reached = Arc::clone(&reached_terminal_boundary);
    let worker_release = Arc::clone(&release_terminal_revalidation);
    let worker = thread::spawn(move || {
        worker_storage.publish_pending_share_with_test_barrier(
            &worker_share_id,
            &receipt,
            &worker_actor,
            &worker_credential,
            move || {
                worker_reached.wait();
                worker_release.wait();
            },
        )
    });

    reached_terminal_boundary.wait();
    storage
        .revoke_auth_session(session_id, &actor.email)
        .unwrap();
    release_terminal_revalidation.wait();
    assert!(matches!(
        worker.join().unwrap(),
        Err(ApiError::Unauthenticated)
    ));
    assert!(storage.get_share(&share.id).unwrap().is_none());
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM shares WHERE id = ?1",
            params![share.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn pending_drop_is_deleted_when_writer_membership_is_removed_at_publication() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("drive.db");
    let storage = Arc::new(Storage::open(db_path.clone()).unwrap());
    storage.migrate().unwrap();
    let (owner, owner_credential, workspace) = owner_with_workspace(&storage);
    let writer_email = "writer@example.test";
    storage
        .upsert_workspace_member(
            &workspace.id,
            writer_email,
            WorkspaceRole::Editor,
            &owner,
            &owner_credential,
        )
        .unwrap();
    let writer_session_id = Uuid::now_v7().to_string();
    storage
        .record_auth_session(
            &writer_session_id,
            writer_email,
            "test-sso",
            "writer-subject",
            "writer-session-token-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let writer = Actor {
        email: writer_email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::Sso,
        allowed_workspace_ids: None,
    };
    let writer_credential = DriveCredential::UserSession(writer_session_id);
    let (drop, receipt) = storage
        .create_pending_drop_publication(
            DropCreateFields {
                workspace_id: &workspace.id,
                name: "Inbox",
                password_hash: "drop-password-hash",
                password_required: true,
                expires_in_seconds: 3_600,
            },
            &writer,
            &writer_credential,
        )
        .unwrap();
    let reached_terminal_boundary = Arc::new(Barrier::new(2));
    let release_terminal_revalidation = Arc::new(Barrier::new(2));
    let worker_storage = Arc::clone(&storage);
    let worker_writer = writer.clone();
    let worker_credential = writer_credential.clone();
    let worker_drop_id = drop.id.clone();
    let worker_reached = Arc::clone(&reached_terminal_boundary);
    let worker_release = Arc::clone(&release_terminal_revalidation);
    let worker = thread::spawn(move || {
        worker_storage.publish_pending_drop_with_test_barrier(
            &worker_drop_id,
            &receipt,
            true,
            3_600,
            &worker_writer,
            &worker_credential,
            move || {
                worker_reached.wait();
                worker_release.wait();
            },
        )
    });

    reached_terminal_boundary.wait();
    storage
        .remove_workspace_member(&workspace.id, writer_email, &owner, &owner_credential)
        .unwrap();
    release_terminal_revalidation.wait();
    assert!(matches!(worker.join().unwrap(), Err(ApiError::Forbidden)));
    assert!(storage.get_drop(&drop.id).unwrap().is_none());
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM drops WHERE id = ?1",
            params![drop.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn pending_drop_is_deleted_when_workspace_policy_changes_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, credential, workspace) = owner_with_workspace(&storage);
    let (drop, receipt) = storage
        .create_pending_drop_publication(
            DropCreateFields {
                workspace_id: &workspace.id,
                name: "Policy race",
                password_hash: "drop-password-hash",
                password_required: true,
                expires_in_seconds: 3_600,
            },
            &owner,
            &credential,
        )
        .unwrap();
    storage
        .update_workspace_policy(
            &workspace.id,
            UpdateWorkspacePolicyRequest {
                quota_bytes: NullableI64Patch::Missing,
                public_links_enabled: Some(false),
                link_password_required: None,
                allow_never_expire: None,
                max_link_ttl_seconds: None,
                drop_password_required: None,
                max_drop_ttl_seconds: None,
                trash_retention_days: None,
                revision_retention_days: None,
            },
            &owner,
            &credential,
        )
        .unwrap();

    assert!(matches!(
        storage.publish_pending_drop(&drop.id, &receipt, true, 3_600, &owner, &credential),
        Err(ApiError::Validation(_))
    ));
    assert!(storage.get_drop(&drop.id).unwrap().is_none());
    let rows: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM drops WHERE id = ?1",
            [&drop.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}
