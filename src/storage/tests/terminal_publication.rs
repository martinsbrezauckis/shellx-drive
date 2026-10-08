use super::*;
use std::{
    sync::{Arc, Barrier},
    thread,
};

use crate::{
    auth::token_hash,
    download_subjects::{CurrentFileSubject, FileContentSubject},
    model::{CreateFileRequest, FileKind},
};

#[test]
fn terminal_admin_publication_rejects_a_revoked_source_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "terminal-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    assert!(actor.is_admin);
    storage
        .ensure_admin_publication_authorized(&actor, &credential)
        .unwrap();

    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage.revoke_auth_session(session_id, email).unwrap();
    assert!(matches!(
        storage.ensure_admin_publication_authorized(&actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
}

#[test]
fn terminal_source_credential_publication_rejects_a_revoked_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "terminal-account-metadata@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    storage
        .ensure_source_credential_publication_authorized(&actor, &credential)
        .unwrap();

    let DriveCredential::UserSession(session_id) = &credential else {
        unreachable!();
    };
    storage.revoke_auth_session(session_id, email).unwrap();
    assert!(matches!(
        storage.ensure_source_credential_publication_authorized(&actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
}

#[test]
fn workspace_read_publication_rechecks_membership_and_source_session_after_selection() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (operator, operator_credential) = test_operator();
    let email = "usage-reader@example.test";
    storage
        .create_auth_account(
            email,
            "stored-password-hash",
            false,
            &operator,
            &operator_credential,
        )
        .unwrap();
    let (actor, credential, _) = test_session_for_existing_account(&storage, email);
    let (workspace, _, _) = storage
        .create_workspace("Selected workspace metadata", "owner@example.test")
        .unwrap();
    storage
        .upsert_workspace_member(
            &workspace.id,
            email,
            WorkspaceRole::Viewer,
            &operator,
            &operator_credential,
        )
        .unwrap();

    let selected_usage = storage.workspace_usage(&workspace.id).unwrap();
    let selected_policy = storage.get_workspace_policy(&workspace.id).unwrap();
    assert_eq!(selected_usage.workspace_id, workspace.id);
    assert_eq!(selected_policy.workspace_id, workspace.id);
    storage
        .ensure_workspace_publication_authorized(
            &workspace.id,
            &actor,
            &credential,
            WorkspacePermission::Read,
        )
        .unwrap();

    storage
        .remove_workspace_member(&workspace.id, email, &operator, &operator_credential)
        .unwrap();
    assert!(matches!(
        storage.ensure_workspace_publication_authorized(
            &workspace.id,
            &actor,
            &credential,
            WorkspacePermission::Read,
        ),
        Err(ApiError::Forbidden)
    ));

    storage
        .upsert_workspace_member(
            &workspace.id,
            email,
            WorkspaceRole::Viewer,
            &operator,
            &operator_credential,
        )
        .unwrap();
    let DriveCredential::UserSession(session_id) = &credential else {
        unreachable!();
    };
    storage.revoke_auth_session(session_id, email).unwrap();
    assert!(matches!(
        storage.ensure_workspace_publication_authorized(
            &workspace.id,
            &actor,
            &credential,
            WorkspacePermission::Read,
        ),
        Err(ApiError::Unauthenticated)
    ));
}

#[test]
fn e2e_debug_mutations_revalidate_the_admitted_admin_before_commit() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "e2e-terminal-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage
        .create_workspace("E2E terminal fixture", "owner@example.test")
        .unwrap();
    let (operator, operator_credential) = test_operator();
    let invitation = storage
        .create_workspace_invitation(
            &workspace.id,
            "invitee@example.test",
            WorkspaceRole::Viewer,
            None,
            "e2e-terminal-invitation-token-hash",
            "E2E terminal invitation",
            &operator,
            &operator_credential,
        )
        .unwrap()
        .0;
    let reset_token_hash = "e2e-terminal-reset-token-hash";
    storage
        .create_password_reset_token(
            "reset@example.test",
            reset_token_hash,
            &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let workspace_count: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM workspaces", [], |row| row.get(0))
        .unwrap();

    // Model a request admitted at entry, then revoked before its storage
    // transaction reaches the terminal authorization check.
    let DriveCredential::UserSession(session_id) = &credential else {
        unreachable!();
    };
    storage.revoke_auth_session(session_id, email).unwrap();

    assert!(matches!(
        storage.e2e_expire_workspace_invitation_authorized(&invitation.id, &actor, &credential,),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.e2e_expire_password_reset_authorized(reset_token_hash, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.create_workspace_authorized(
            "stale E2E seed workspace",
            "e2e@example.test",
            None,
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.create_file_with_content_bytes_authorized(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "stale-e2e-seed.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
            0,
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));

    assert_eq!(
        storage
            .list_all_workspace_invitations()
            .unwrap()
            .into_iter()
            .find(|item| item.id == invitation.id)
            .unwrap()
            .expires_at,
        invitation.expires_at
    );
    let reset_expiry: String = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT expires_at FROM password_reset_tokens WHERE token_hash = ?1",
            [reset_token_hash],
            |row| row.get(0),
        )
        .unwrap();
    assert_ne!(reset_expiry, "2000-01-01T00:00:00Z");
    assert_eq!(
        storage
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM workspaces", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        workspace_count
    );
    assert!(storage
        .get_root_file_by_name(&workspace.id, "stale-e2e-seed.txt")
        .unwrap()
        .is_none());
}

#[test]
fn app_token_terminal_publication_revokes_an_unpublished_token_after_source_revocation() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(temp.path().join("drive.db")).unwrap());
    storage.migrate().unwrap();
    let email = "terminal-app-token-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let workspace = storage
        .create_workspace("Terminal token publication", email)
        .unwrap()
        .0;
    let plaintext = "sxd_app_terminal-publication-regression";
    let (app_token, creation_receipt) = storage
        .create_pending_app_token_publication(
            "Terminal publication regression",
            email,
            &token_hash(plaintext),
            std::slice::from_ref(&workspace.id),
            &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    assert!(storage
        .authenticate_app_token(&token_hash(plaintext), Utc::now().timestamp())
        .unwrap()
        .is_none());
    let source_session_id = match &credential {
        DriveCredential::UserSession(id) => id.clone(),
        _ => unreachable!(),
    };
    let reached_terminal_boundary = Arc::new(Barrier::new(2));
    let release_terminal_revalidation = Arc::new(Barrier::new(2));
    let worker_storage = Arc::clone(&storage);
    let worker_actor = actor.clone();
    let worker_credential = credential.clone();
    let worker_token_id = app_token.id.clone();
    let worker_reached = Arc::clone(&reached_terminal_boundary);
    let worker_release = Arc::clone(&release_terminal_revalidation);
    let worker = thread::spawn(move || {
        worker_storage.publish_pending_app_token_with_test_barrier(
            &worker_token_id,
            &creation_receipt,
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
        .revoke_auth_session(&source_session_id, email)
        .unwrap();
    release_terminal_revalidation.wait();

    assert!(matches!(
        worker.join().unwrap(),
        Err(ApiError::Unauthenticated)
    ));
    assert!(storage
        .authenticate_app_token(&token_hash(plaintext), Utc::now().timestamp())
        .unwrap()
        .is_none());
    let canceled: (i64, Option<String>) = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT publication_pending, revoked_at FROM app_tokens WHERE id = ?1",
            [&app_token.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(canceled.0, 1);
    assert!(canceled.1.is_some());
    let receipts = storage.list_receipts().unwrap();
    assert!(!receipts.iter().any(|receipt| {
        receipt.kind == "app_token.create" && receipt.target_id.as_deref() == Some(&app_token.id)
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt.kind == "app_token.revoke.stale_publication"
            && receipt.target_id.as_deref() == Some(&app_token.id)
    }));
}

#[test]
fn oidc_terminal_publication_revokes_an_unpublished_session_after_source_revocation() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(temp.path().join("drive.db")).unwrap());
    storage.migrate().unwrap();
    let email = "terminal-oidc-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let source_session_id = match &credential {
        DriveCredential::UserSession(id) => id.clone(),
        _ => unreachable!(),
    };
    let session_id = "terminal-oidc-publication-session";
    let session_token_hash = "terminal-oidc-publication-token-hash";
    let session = storage
        .record_pending_auth_session_publication(
            session_id,
            "delegated@example.test",
            "https://idp.example.test",
            "delegated-subject",
            session_token_hash,
            &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_auth_session_active(&session.id, session_token_hash, Utc::now().timestamp()),
        Err(ApiError::Unauthenticated)
    ));
    let reached_terminal_boundary = Arc::new(Barrier::new(2));
    let release_terminal_revalidation = Arc::new(Barrier::new(2));
    let worker_storage = Arc::clone(&storage);
    let worker_actor = actor.clone();
    let worker_credential = credential.clone();
    let worker_session_id = session.id.clone();
    let worker_reached = Arc::clone(&reached_terminal_boundary);
    let worker_release = Arc::clone(&release_terminal_revalidation);
    let worker = thread::spawn(move || {
        worker_storage.publish_pending_auth_session_with_test_barrier(
            &worker_session_id,
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
        .revoke_auth_session(&source_session_id, email)
        .unwrap();
    release_terminal_revalidation.wait();

    assert!(matches!(
        worker.join().unwrap(),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.ensure_auth_session_active(&session.id, session_token_hash, Utc::now().timestamp()),
        Err(ApiError::Unauthenticated)
    ));
    let canceled: (i64, Option<String>) = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT publication_pending, revoked_at FROM auth_sessions WHERE id = ?1",
            [&session.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(canceled.0, 1);
    assert!(canceled.1.is_some());
    let receipts = storage.list_receipts().unwrap();
    assert!(!receipts.iter().any(|receipt| {
        receipt.kind == "auth.session.sso.create"
            && receipt.target_id.as_deref() == Some(&session.id)
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt.kind == "auth.session.revoke.stale_publication"
            && receipt.target_id.as_deref() == Some(&session.id)
    }));
}

#[test]
fn published_bearers_remain_independent_after_a_later_source_session_revoke() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "published-bearer-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let source_session_id = match &credential {
        DriveCredential::UserSession(id) => id.clone(),
        _ => unreachable!(),
    };
    let workspace = storage
        .create_workspace("Published bearer independence", email)
        .unwrap()
        .0;
    let app_token_plaintext = "sxd_app_published-bearer-regression";
    let (app_token, app_token_receipt) = storage
        .create_pending_app_token_publication(
            "Published bearer regression",
            email,
            &token_hash(app_token_plaintext),
            std::slice::from_ref(&workspace.id),
            &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    storage
        .publish_pending_app_token(&app_token.id, &app_token_receipt, &actor, &credential)
        .unwrap();
    let session_token_hash = "published-oidc-bearer-token-hash";
    let session = storage
        .record_pending_auth_session_publication(
            "published-oidc-bearer-session",
            "delegated@example.test",
            "https://idp.example.test",
            "delegated-subject",
            session_token_hash,
            &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    storage
        .publish_pending_auth_session(&session.id, &actor, &credential)
        .unwrap();

    storage
        .revoke_auth_session(&source_session_id, email)
        .unwrap();

    assert!(storage
        .authenticate_app_token(&token_hash(app_token_plaintext), Utc::now().timestamp())
        .unwrap()
        .is_some());
    storage
        .ensure_auth_session_active(&session.id, session_token_hash, Utc::now().timestamp())
        .unwrap();
}

#[test]
fn oidc_publication_enforces_the_active_session_limit_at_the_linearization_point() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential, _) = test_local_account_session(&storage, "limit-admin@example.test");
    let target_email = "oidc-limit-target@example.test";
    let expires_at = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let mut sessions = Vec::new();
    for sequence in 0..17 {
        let session_id = format!("oidc-publication-limit-{sequence:02}");
        let token_hash = format!("oidc-publication-limit-token-{sequence:02}");
        let session = storage
            .record_pending_auth_session_publication(
                &session_id,
                target_email,
                "https://idp.example.test",
                &format!("subject-{sequence:02}"),
                &token_hash,
                &expires_at,
                &actor,
                &credential,
            )
            .unwrap();
        storage
            .publish_pending_auth_session(&session.id, &actor, &credential)
            .unwrap();
        sessions.push((session, token_hash));
    }

    assert_eq!(
        storage
            .list_active_auth_sessions_for_actor(target_email)
            .unwrap()
            .len(),
        16
    );
    assert!(matches!(
        storage.ensure_auth_session_active(
            &sessions[0].0.id,
            &sessions[0].1,
            Utc::now().timestamp()
        ),
        Err(ApiError::Unauthenticated)
    ));
    storage
        .ensure_auth_session_active(&sessions[16].0.id, &sessions[16].1, Utc::now().timestamp())
        .unwrap();
}

#[test]
fn terminal_file_publication_rejects_a_revoked_source_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "terminal-reader@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage
        .create_workspace("Terminal publication", email)
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "private.txt".to_string(),
                kind: FileKind::File,
                content: Some("private".to_string()),
                path: None,
            },
            Some("a".repeat(64)),
        )
        .unwrap();
    let subject = FileContentSubject::Current(CurrentFileSubject::from_file(&file).unwrap());
    storage
        .ensure_download_ticket_authorized(
            &workspace.id,
            std::slice::from_ref(&file.id),
            std::slice::from_ref(&subject),
            &actor,
            &credential,
        )
        .unwrap();

    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage.revoke_auth_session(session_id, email).unwrap();

    assert!(matches!(
        storage.ensure_download_ticket_authorized(
            &workspace.id,
            std::slice::from_ref(&file.id),
            std::slice::from_ref(&subject),
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
}

#[test]
fn share_metadata_terminal_claim_rejects_a_trashed_planned_descendant_without_consuming_use() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential) = test_operator();
    let (workspace, _, _) = storage
        .create_workspace("Public metadata terminal snapshot", "owner@example.test")
        .unwrap();
    let (root, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "shared".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (child, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: Some(root.id.clone()),
                name: "planned.txt".to_string(),
                kind: FileKind::File,
                content: Some("planned body".to_string()),
                path: None,
            },
            Some("a".repeat(64)),
        )
        .unwrap();
    let (share, _) = storage
        .create_share(
            ShareCreateFields {
                file_id: &root.id,
                password_hash: "not-required",
                password_required: false,
                expires_in_seconds: 3_600,
                target_kind: "folder",
                allow_download: true,
                recipient_note: None,
                max_uses: Some(1),
            },
            &actor,
            &credential,
        )
        .unwrap();
    let fingerprint = storage
        .get_share(&share.id)
        .unwrap()
        .unwrap()
        .authorization_fingerprint();
    let planned_root = storage.get_file_unaggregated(&root.id).unwrap().unwrap();
    let (entries, planned_descendants) = storage
        .share_folder_entries_with_subjects(&root.id)
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(planned_descendants[0].id, child.id);

    // This is the deterministic race boundary: planning completed against a
    // live subtree, then the selected child is trashed before terminal claim.
    storage.set_trashed(&child.id, true).unwrap();
    assert!(matches!(
        storage.claim_share_metadata_access_with(
            &share.id,
            &fingerprint,
            "metadata-client",
            &planned_root,
            &planned_descendants,
            |_| Ok(()),
        ),
        Err(ApiError::NotFound)
    ));
    let after = storage.get_share(&share.id).unwrap().unwrap().share;
    assert_eq!(after.access_count, 0);
    assert_eq!(after.uses_remaining, Some(1));
}
