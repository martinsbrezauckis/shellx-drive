use super::*;
use std::{
    sync::{Arc, Barrier},
    thread,
};

use crate::auth::AuthMode;

fn test_operator() -> (Actor, DriveCredential) {
    (
        Actor {
            email: "system@local".to_string(),
            is_admin: true,
            auth_mode: AuthMode::Operator,
            allowed_workspace_ids: None,
        },
        DriveCredential::Operator,
    )
}

fn test_local_account_session(storage: &Storage, email: &str) -> (Actor, DriveCredential) {
    if storage.get_auth_account_secret(email).unwrap().is_none() {
        if storage.auth_account_count().unwrap() == 0 {
            storage
                .bootstrap_auth_account(email, "stored-password-hash")
                .unwrap();
        } else {
            let (operator, operator_credential) = test_operator();
            storage
                .create_auth_account(
                    email,
                    "stored-password-hash",
                    false,
                    &operator,
                    &operator_credential,
                )
                .unwrap();
        }
    }
    let account = storage.get_auth_account_secret(email).unwrap().unwrap();
    let session_id = Uuid::now_v7().to_string();
    storage
        .record_auth_session(
            &session_id,
            email,
            "local-password",
            &account.user_id,
            &format!("stored-session-token-hash-{session_id}"),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    (
        Actor {
            email: email.to_string(),
            is_admin: account.is_admin,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        },
        DriveCredential::UserSession(session_id),
    )
}

#[test]
fn concurrent_role_replacement_and_resend_commit_one_complete_intent() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(temp.path().join("drive.db")).unwrap());
    storage.migrate().unwrap();
    let (owner_a, credential_a) = test_local_account_session(&storage, "a@example.test");
    let (owner_b, credential_b) = test_local_account_session(&storage, "b@example.test");
    let workspace = storage
        .create_workspace("Atomic invitations", &owner_a.email)
        .unwrap()
        .0;
    let (operator, operator_credential) = test_operator();
    storage
        .upsert_workspace_member(
            &workspace.id,
            &owner_b.email,
            WorkspaceRole::Owner,
            &operator,
            &operator_credential,
        )
        .unwrap();
    let (initial, _) = storage
        .create_workspace_invitation(
            &workspace.id,
            "invitee@example.test",
            WorkspaceRole::Viewer,
            None,
            "initial-token-hash",
            "initial-body",
            &owner_a,
            &credential_a,
        )
        .unwrap();

    let start = Arc::new(Barrier::new(3));
    let create_storage = Arc::clone(&storage);
    let create_start = Arc::clone(&start);
    let create_workspace = workspace.id.clone();
    let create_actor = owner_a.clone();
    let create_credential = credential_a.clone();
    let create = thread::spawn(move || {
        create_start.wait();
        let result = create_storage.create_workspace_invitation(
            &create_workspace,
            "invitee@example.test",
            WorkspaceRole::Owner,
            None,
            "replacement-token-hash",
            "replacement-body",
            &create_actor,
            &create_credential,
        )?;
        create_storage.create_workspace_invitation_notification_if_current(
            &result.0,
            "replacement-token-hash",
            "Replacement notification",
            "replacement-notification",
        )?;
        Ok::<_, ApiError>(result)
    });
    let resend_storage = Arc::clone(&storage);
    let resend_start = Arc::clone(&start);
    let resend_workspace = workspace.id.clone();
    let resend_invitation = initial.id.clone();
    let resend_actor = owner_b.clone();
    let resend_credential = credential_b.clone();
    let resend = thread::spawn(move || {
        resend_start.wait();
        let result = resend_storage.resend_workspace_invitation(
            &resend_workspace,
            &resend_invitation,
            "resend-token-hash",
            "resend-body",
            &resend_actor,
            &resend_credential,
        )?;
        resend_storage.create_workspace_invitation_notification_if_current(
            &result.0,
            "resend-token-hash",
            "Resend notification",
            "resend-notification",
        )?;
        Ok::<_, ApiError>(result)
    });
    start.wait();
    create.join().unwrap().unwrap();
    resend.join().unwrap().unwrap();

    let conn = storage.conn.lock().unwrap();
    let current: (String, String, i64) = conn
        .query_row(
            "SELECT role, token_hash, publication_pending
             FROM workspace_invitations WHERE id = ?1",
            [&initial.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let queued_body: String = conn
        .query_row(
            "SELECT body_text FROM email_outbox
             WHERE related_type = 'workspace_invitation' AND related_id = ?1",
            [&initial.id],
            |row| row.get(0),
        )
        .unwrap();
    let notifications: (i64, String) = conn
        .query_row(
            "SELECT COUNT(*), MAX(body) FROM notifications
             WHERE related_type = 'workspace_invitation' AND related_id = ?1",
            [&initial.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(current.0, "owner");
    assert_eq!(current.2, 0);
    assert!(matches!(
        (current.1.as_str(), queued_body.as_str()),
        ("replacement-token-hash", "replacement-body") | ("resend-token-hash", "resend-body")
    ));
    assert_eq!(notifications.0, 1);
    assert!(matches!(
        (current.1.as_str(), notifications.1.as_str()),
        ("replacement-token-hash", "replacement-notification")
            | ("resend-token-hash", "resend-notification")
    ));
}

#[test]
fn revoked_source_cannot_enter_the_atomic_invitation_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, credential) = test_local_account_session(&storage, "owner@example.test");
    let workspace = storage
        .create_workspace("Revoked invitation", &owner.email)
        .unwrap()
        .0;
    let DriveCredential::UserSession(session_id) = &credential else {
        unreachable!();
    };
    storage
        .revoke_auth_session(session_id, &owner.email)
        .unwrap();

    assert!(matches!(
        storage.create_workspace_invitation(
            &workspace.id,
            "invitee@example.test",
            WorkspaceRole::Owner,
            None,
            "must-not-publish-token-hash",
            "must-not-publish-body",
            &owner,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
    let invitation_rows: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM workspace_invitations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(invitation_rows, 0);
}

#[test]
fn migration_cancels_an_orphaned_two_phase_invitation_and_its_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, credential) = test_local_account_session(&storage, "owner@example.test");
    let workspace = storage
        .create_workspace("Interrupted invitation", &owner.email)
        .unwrap()
        .0;
    let (invitation, _) = storage
        .create_workspace_invitation(
            &workspace.id,
            "invitee@example.test",
            WorkspaceRole::Owner,
            None,
            "orphaned-token-hash",
            "orphaned-body",
            &owner,
            &credential,
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE email_outbox
             SET status = 'sent', sent_at = updated_at
             WHERE related_type = 'workspace_invitation' AND related_id = ?1",
            [&invitation.id],
        )
        .unwrap();
    storage
        .queue_workspace_email(
            &workspace.id,
            "workspace_invitation",
            &invitation.email,
            "ShellX Drive workspace invitation",
            "orphaned queued retry",
            Some("workspace_invitation"),
            Some(&invitation.id),
        )
        .unwrap();
    assert!(storage
        .create_workspace_invitation_notification_if_current(
            &invitation,
            "orphaned-token-hash",
            "Orphaned invitation",
            "orphaned notification",
        )
        .unwrap());
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE workspace_invitations SET publication_pending = 1 WHERE id = ?1",
            [&invitation.id],
        )
        .unwrap();

    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let state: (String, i64) = conn
        .query_row(
            "SELECT status, publication_pending FROM workspace_invitations WHERE id = ?1",
            [&invitation.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, ("canceled".to_string(), 0));
    let deliveries: (i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*),
                    SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END)
             FROM email_outbox
             WHERE related_type = 'workspace_invitation' AND related_id = ?1",
            [&invitation.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(deliveries, (1, 0, 1));
    let notifications: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications
             WHERE related_type = 'workspace_invitation' AND related_id = ?1",
            [&invitation.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(notifications, 0);
    let cancellation_receipts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM receipts
             WHERE kind = 'workspace.invitation.cancel.stale_publication'
               AND target_id = ?1",
            [&invitation.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(cancellation_receipts, 1);
}
