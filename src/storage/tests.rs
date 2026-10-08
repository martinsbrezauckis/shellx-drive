use super::*;
use crate::{
    download_subjects::{CurrentFileSubject, FileContentSubject},
    model::{AuthSession, RcloneFolderCollisionPolicy},
};

mod admin_self_removal;
mod bootstrap_atomicity;
mod file_move_collision_races;
mod file_move_collisions;
mod file_move_replacements;
mod terminal_derived_publication;
mod terminal_publication;
mod workspace_owner_expiry;
mod workspace_owner_transitions;

fn test_operator() -> (Actor, DriveCredential) {
    (
        Actor {
            email: "system@local".to_string(),
            is_admin: true,
            auth_mode: crate::auth::AuthMode::Operator,
            allowed_workspace_ids: None,
        },
        DriveCredential::Operator,
    )
}

fn test_local_account_session(
    storage: &Storage,
    email: &str,
) -> (Actor, DriveCredential, AuthAccountSecret) {
    storage
        .bootstrap_auth_account(email, "stored-password-hash")
        .unwrap();
    test_session_for_existing_account(storage, email)
}

fn test_session_for_existing_account(
    storage: &Storage,
    email: &str,
) -> (Actor, DriveCredential, AuthAccountSecret) {
    let account = storage.get_auth_account_secret(email).unwrap().unwrap();
    let session_id = Uuid::now_v7().to_string();
    let session_token_hash = format!("stored-session-token-hash-{session_id}");
    storage
        .record_auth_session(
            &session_id,
            email,
            "local-password",
            &account.user_id,
            &session_token_hash,
            &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    (
        Actor {
            email: email.to_string(),
            is_admin: account.is_admin,
            auth_mode: crate::auth::AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        },
        DriveCredential::UserSession(session_id),
        account,
    )
}

fn replacement_session_for_account(
    storage: &Storage,
    email: &str,
) -> (AuthSessionReplacement, DriveCredential) {
    let account = storage.get_auth_account_secret(email).unwrap().unwrap();
    let session_id = Uuid::now_v7().to_string();
    let replacement = AuthSessionReplacement {
        session: AuthSession {
            id: session_id.clone(),
            actor_email: email.to_string(),
            issuer: "local-password".to_string(),
            subject: account.user_id,
            expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            revoked_at: None,
            created_at: Utc::now().to_rfc3339(),
            revoked: false,
        },
        token_hash: format!("replacement-token-hash-{session_id}"),
        client_ip: Some("127.0.0.1".to_string()),
        user_agent: Some("storage-test".to_string()),
    };
    (replacement, DriveCredential::UserSession(session_id))
}

#[test]
fn auth_session_expiry_is_end_exclusive_at_the_exact_epoch() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "expiry-boundary@example.test";
    storage
        .bootstrap_auth_account(email, "stored-password-hash")
        .unwrap();
    let account = storage.get_auth_account_secret(email).unwrap().unwrap();
    let session_id = Uuid::now_v7().to_string();
    let token_hash = "expiry-boundary-token-hash";
    let expires_at_epoch = 1_800_000_000;
    let expires_at = chrono::DateTime::from_timestamp(expires_at_epoch, 0)
        .unwrap()
        .to_rfc3339();
    storage
        .record_auth_session(
            &session_id,
            email,
            "local-password",
            &account.user_id,
            token_hash,
            &expires_at,
        )
        .unwrap();

    storage
        .ensure_auth_session_active(&session_id, token_hash, expires_at_epoch - 1)
        .unwrap();
    assert!(matches!(
        storage.ensure_auth_session_active(&session_id, token_hash, expires_at_epoch),
        Err(ApiError::Unauthenticated)
    ));
}

fn test_rotation<'a>(
    replacement: &'a AuthSessionReplacement,
    actor: &'a Actor,
    source_credential: &'a DriveCredential,
) -> AuthSessionRotation<'a> {
    AuthSessionRotation {
        actor,
        source_credential,
        replacement: Some(replacement),
    }
}

fn issue_mfa_lifecycle_derivatives(
    storage: &Storage,
    email: &str,
    source_credential: &DriveCredential,
    file_id: &str,
) -> String {
    let _ = test_session_for_existing_account(storage, email);
    storage
        .create_office_edit_session(file_id, email, source_credential, 1, "test-provider", 900)
        .unwrap()
        .1
}

fn assert_mfa_lifecycle_derivatives_revoked(
    storage: &Storage,
    email: &str,
    replacement: &AuthSessionReplacement,
    office_token: &str,
) {
    let active_sessions = storage.list_active_auth_sessions_for_actor(email).unwrap();
    assert_eq!(active_sessions.len(), 1);
    assert_eq!(active_sessions[0].session.id, replacement.session.id);
    storage
        .ensure_auth_session_active(
            &replacement.session.id,
            &replacement.token_hash,
            Utc::now().timestamp(),
        )
        .unwrap();
    assert!(storage
        .get_office_edit_session_by_token(office_token)
        .unwrap()
        .is_none());
}

#[test]
fn account_security_mutations_compare_version_and_revalidate_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "owner@example.test";
    let (actor, credential, initial) = test_local_account_session(&storage, email);
    let (replacement, replacement_credential) = replacement_session_for_account(&storage, email);

    storage
        .update_totp_secret(
            email,
            "first-secret",
            initial.security_version,
            VerifiedLocalSecondFactor::NotRequired,
            &test_rotation(&replacement, &actor, &credential),
        )
        .unwrap();
    assert!(matches!(
        storage.update_totp_secret(
            email,
            "stale-secret",
            initial.security_version,
            VerifiedLocalSecondFactor::NotRequired,
            &test_rotation(
                &replacement_session_for_account(&storage, email).0,
                &actor,
                &replacement_credential,
            ),
        ),
        Err(ApiError::Conflict)
    ));

    let session_id = match &replacement_credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage.revoke_auth_session(session_id, email).unwrap();
    let current = storage.get_auth_account_secret(email).unwrap().unwrap();
    assert!(matches!(
        storage.disable_totp(
            email,
            current.security_version,
            VerifiedLocalSecondFactor::NotRequired,
            &test_rotation(
                &replacement_session_for_account(&storage, email).0,
                &actor,
                &replacement_credential,
            ),
        ),
        Err(ApiError::Unauthenticated)
    ));
}

#[test]
fn totp_identity_changes_reset_the_login_replay_counter() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "totp-reset@example.test";
    let (actor, mut credential, initial) = test_local_account_session(&storage, email);
    let (replacement, next_credential) = replacement_session_for_account(&storage, email);

    storage
        .update_totp_secret(
            email,
            "first-secret",
            initial.security_version,
            VerifiedLocalSecondFactor::NotRequired,
            &test_rotation(&replacement, &actor, &credential),
        )
        .unwrap();
    credential = next_credential;
    let pending = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .enable_totp(
            email,
            &["recovery-hash".to_string()],
            pending.security_version,
            VerifiedLocalSecondFactor::TotpCounter(1),
            &test_rotation(&replacement, &actor, &credential),
        )
        .unwrap();
    credential = next_credential;
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE auth_accounts SET totp_last_used_counter = 42 WHERE email = ?1",
            params![email],
        )
        .unwrap();

    let enabled = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .update_totp_secret(
            email,
            "replacement-secret",
            enabled.security_version,
            VerifiedLocalSecondFactor::TotpCounter(43),
            &test_rotation(&replacement, &actor, &credential),
        )
        .unwrap();
    credential = next_credential;
    let counter: Option<i64> = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT totp_last_used_counter FROM auth_accounts WHERE email = ?1",
            params![email],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(counter, None);

    let replacement = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement_session, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .enable_totp(
            email,
            &["replacement-recovery-hash".to_string()],
            replacement.security_version,
            VerifiedLocalSecondFactor::TotpCounter(43),
            &test_rotation(&replacement_session, &actor, &credential),
        )
        .unwrap();
    credential = next_credential;
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE auth_accounts SET totp_last_used_counter = 43 WHERE email = ?1",
            params![email],
        )
        .unwrap();
    let replacement_enabled = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement_session, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .disable_totp(
            email,
            replacement_enabled.security_version,
            VerifiedLocalSecondFactor::TotpCounter(44),
            &test_rotation(&replacement_session, &actor, &credential),
        )
        .unwrap();
    credential = next_credential;
    let counter: Option<i64> = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT totp_last_used_counter FROM auth_accounts WHERE email = ?1",
            params![email],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(counter, None);

    let disabled = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .update_totp_secret(
            email,
            "admin-reset-secret",
            disabled.security_version,
            VerifiedLocalSecondFactor::NotRequired,
            &test_rotation(&replacement, &actor, &credential),
        )
        .unwrap();
    credential = next_credential;
    let admin_reset_pending = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .enable_totp(
            email,
            &["admin-reset-recovery-hash".to_string()],
            admin_reset_pending.security_version,
            VerifiedLocalSecondFactor::TotpCounter(44),
            &test_rotation(&replacement, &actor, &credential),
        )
        .unwrap();
    credential = next_credential;
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE auth_accounts SET totp_last_used_counter = 44 WHERE email = ?1",
            params![email],
        )
        .unwrap();
    storage
        .update_auth_account(email, None, None, None, true, None, &actor, &credential)
        .unwrap();
    let counter: Option<i64> = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT totp_last_used_counter FROM auth_accounts WHERE email = ?1",
            params![email],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(counter, None);
}

#[test]
fn totp_lifecycle_changes_revoke_sibling_sessions_and_office_capabilities() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "totp-lifecycle@example.test";
    let (actor, mut source_credential, initial) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage.create_workspace("TOTP lifecycle", email).unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: "lifecycle.docx".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();

    let office_token =
        issue_mfa_lifecycle_derivatives(&storage, email, &source_credential, &file.id);
    let (replacement, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .update_totp_secret(
            email,
            "lifecycle-secret",
            initial.security_version,
            VerifiedLocalSecondFactor::NotRequired,
            &test_rotation(&replacement, &actor, &source_credential),
        )
        .unwrap();
    assert_mfa_lifecycle_derivatives_revoked(&storage, email, &replacement, &office_token);
    source_credential = next_credential;

    let office_token =
        issue_mfa_lifecycle_derivatives(&storage, email, &source_credential, &file.id);
    let pending = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .enable_totp(
            email,
            &["recovery-1".to_string()],
            pending.security_version,
            VerifiedLocalSecondFactor::TotpCounter(10),
            &test_rotation(&replacement, &actor, &source_credential),
        )
        .unwrap();
    assert_mfa_lifecycle_derivatives_revoked(&storage, email, &replacement, &office_token);
    source_credential = next_credential;

    let office_token =
        issue_mfa_lifecycle_derivatives(&storage, email, &source_credential, &file.id);
    let enabled = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement, next_credential) = replacement_session_for_account(&storage, email);
    storage
        .rotate_recovery_code_hashes(
            email,
            &["recovery-2".to_string()],
            enabled.security_version,
            VerifiedLocalSecondFactor::TotpCounter(11),
            &test_rotation(&replacement, &actor, &source_credential),
        )
        .unwrap();
    assert_mfa_lifecycle_derivatives_revoked(&storage, email, &replacement, &office_token);
    source_credential = next_credential;

    let office_token =
        issue_mfa_lifecycle_derivatives(&storage, email, &source_credential, &file.id);
    let rotated = storage.get_auth_account_secret(email).unwrap().unwrap();
    let (replacement, _next_credential) = replacement_session_for_account(&storage, email);
    storage
        .disable_totp(
            email,
            rotated.security_version,
            VerifiedLocalSecondFactor::TotpCounter(12),
            &test_rotation(&replacement, &actor, &source_credential),
        )
        .unwrap();
    assert_mfa_lifecycle_derivatives_revoked(&storage, email, &replacement, &office_token);
}

#[test]
fn totp_login_counter_is_consumed_atomically_with_session_insertion() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "totp-race@example.test";
    storage
        .bootstrap_auth_account(email, "stored-password-hash")
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE auth_accounts
             SET totp_secret = 'race-secret', totp_enabled = 1
             WHERE email = ?1",
            params![email],
        )
        .unwrap();
    let account = storage.get_auth_account_secret(email).unwrap().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let issue = |storage: Storage,
                 barrier: std::sync::Arc<std::sync::Barrier>,
                 account: AuthAccountSecret,
                 suffix: &'static str| {
        std::thread::spawn(move || {
            barrier.wait();
            storage.record_verified_local_auth_session(
                &format!("session-{suffix}"),
                &account,
                VerifiedLocalSecondFactor::TotpCounter(42),
                "local-password",
                &format!("token-hash-{suffix}"),
                &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                Some("127.0.0.1"),
                Some("totp-race-test"),
            )
        })
    };
    let first = issue(
        storage.clone(),
        std::sync::Arc::clone(&barrier),
        account.clone(),
        "first",
    );
    let second = issue(
        storage.clone(),
        std::sync::Arc::clone(&barrier),
        account,
        "second",
    );
    barrier.wait();
    let results = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ApiError::Unauthenticated)))
            .count(),
        1
    );
    assert_eq!(
        storage
            .list_active_auth_sessions_for_actor(email)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn self_session_revoke_revalidates_the_source_session_in_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "session-owner@example.test";
    let (actor, source_credential, account) = test_local_account_session(&storage, email);
    let target_session_id = "second-active-session";
    storage
        .record_auth_session(
            target_session_id,
            email,
            "local-password",
            &account.user_id,
            "second-active-session-hash",
            &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let source_session_id = match &source_credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage
        .revoke_auth_session(source_session_id, "system@local")
        .unwrap();

    assert!(matches!(
        storage.revoke_auth_session_for_actor_authorized(
            target_session_id,
            &actor,
            &source_credential,
            "auth.session.revoke",
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert!(storage
        .list_active_auth_sessions_for_actor(email)
        .unwrap()
        .iter()
        .any(|session| session.session.id == target_session_id));
}

#[test]
fn auth_attempt_unlock_revalidates_the_admin_source_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "unlock-admin@example.test";
    let (actor, source_credential, _) = test_local_account_session(&storage, email);
    let attempt = storage
        .record_auth_attempt_failure(
            Some("target@example.test"),
            "login",
            "test-client",
            AuthThrottlePolicy {
                threshold: 1,
                base_lockout_seconds: 30,
                max_lockout_seconds: 30,
                decay_seconds: 60,
            },
        )
        .unwrap();
    let source_session_id = match &source_credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage
        .revoke_auth_session(source_session_id, "system@local")
        .unwrap();

    assert!(matches!(
        storage.unlock_auth_attempt(&attempt.key, &actor, &source_credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(storage
        .list_auth_attempts_bounded(10)
        .unwrap()
        .iter()
        .any(|row| row.key == attempt.key));
}

#[test]
fn direct_workspace_membership_stops_at_the_durable_limit() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Bounded members", "owner@example.test")
        .unwrap();
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for index in 1..super::collaboration_limits::MAX_WORKSPACE_MEMBERS {
            let user_id = format!("member-{index}");
            let email = format!("member-{index}@example.test");
            tx.execute(
                "INSERT INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
                params![&user_id, &email, Utc::now().to_rfc3339()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_members (workspace_id, user_id, role)
                 VALUES (?1, ?2, 'viewer')",
                params![&workspace.id, &user_id],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let (operator, credential) = test_operator();
    assert_eq!(
        storage.list_workspace_members(&workspace.id).unwrap().len(),
        super::collaboration_limits::MAX_WORKSPACE_MEMBERS as usize
    );
    assert!(matches!(
        storage.upsert_workspace_member(
            &workspace.id,
            "overflow@example.test",
            WorkspaceRole::Viewer,
            &operator,
            &credential,
        ),
        Err(ApiError::PayloadTooLarge(_))
    ));
}

#[test]
fn invitations_deduplicate_and_roll_back_if_email_queueing_fails() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Bounded invitations", "owner@example.test")
        .unwrap();
    let (operator, credential) = test_operator();
    let (first, _) = storage
        .create_workspace_invitation(
            &workspace.id,
            "guest@example.test",
            WorkspaceRole::Viewer,
            None,
            "first-token-hash",
            "First invitation",
            &operator,
            &credential,
        )
        .unwrap();
    let (replacement, _) = storage
        .create_workspace_invitation(
            &workspace.id,
            "GUEST@example.test",
            WorkspaceRole::Editor,
            None,
            "replacement-token-hash",
            "Replacement invitation",
            &operator,
            &credential,
        )
        .unwrap();
    assert_eq!(replacement.id, first.id);
    assert_eq!(replacement.role, "editor");
    assert_eq!(
        storage
            .list_workspace_invitations(&workspace.id)
            .unwrap()
            .len(),
        1
    );
    {
        let conn = storage.conn.lock().unwrap();
        let queued: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM email_outbox
                 WHERE kind = 'workspace_invitation' AND status = 'queued'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(queued, 1);
        conn.execute_batch(
            "CREATE TRIGGER fail_invitation_email
             BEFORE INSERT ON email_outbox
             WHEN NEW.kind = 'workspace_invitation'
             BEGIN
                 SELECT RAISE(ABORT, 'forced invitation email failure');
             END;",
        )
        .unwrap();
    }
    assert!(matches!(
        storage.create_workspace_invitation(
            &workspace.id,
            "rollback@example.test",
            WorkspaceRole::Viewer,
            None,
            "rollback-token-hash",
            "Must roll back",
            &operator,
            &credential,
        ),
        Err(ApiError::Storage(_))
    ));
    assert!(!storage
        .list_workspace_invitations(&workspace.id)
        .unwrap()
        .iter()
        .any(|invitation| invitation.email == "rollback@example.test"));
}

#[test]
fn invitation_acceptance_revalidates_the_exact_source_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Revoked invitation", "owner@example.test")
        .unwrap();
    let (operator, operator_credential) = test_operator();
    let (invitation, _) = storage
        .create_workspace_invitation(
            &workspace.id,
            "invitee@example.test",
            WorkspaceRole::Viewer,
            None,
            "revoked-invitation-token-hash",
            "Invitation",
            &operator,
            &operator_credential,
        )
        .unwrap();
    let (actor, credential, _) = test_local_account_session(&storage, "invitee@example.test");
    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage
        .revoke_auth_session(session_id, "system@local")
        .unwrap();

    assert!(matches!(
        storage.accept_workspace_invitation_for_account(
            "revoked-invitation-token-hash",
            "invitee@example.test",
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert_eq!(
        storage
            .list_workspace_invitations(&workspace.id)
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.id == invitation.id)
            .unwrap()
            .status,
        "pending"
    );
    assert!(!storage
        .list_workspace_members(&workspace.id)
        .unwrap()
        .iter()
        .any(|member| member.email == "invitee@example.test"));
}

#[test]
fn share_and_drop_mutations_revalidate_workspace_policy_in_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (operator, credential) = test_operator();
    let (workspace, _, _) = storage
        .create_workspace("Policy transaction", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "shared.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (share, _) = storage
        .create_share(
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
            &operator,
            &credential,
        )
        .unwrap();
    let (drop, _) = storage
        .create_drop(
            DropCreateFields {
                workspace_id: &workspace.id,
                name: "Inbox",
                password_hash: "drop-password-hash",
                password_required: true,
                expires_in_seconds: 3_600,
            },
            &operator,
            &credential,
        )
        .unwrap();
    storage
        .update_workspace_policy(
            &workspace.id,
            serde_json::from_value(json!({"public_links_enabled": false})).unwrap(),
            &operator,
            &credential,
        )
        .unwrap();

    assert!(matches!(
        storage.create_share(
            ShareCreateFields {
                file_id: &file.id,
                password_hash: "another-share-hash",
                password_required: true,
                expires_in_seconds: 3_600,
                target_kind: "file",
                allow_download: true,
                recipient_note: None,
                max_uses: None,
            },
            &operator,
            &credential,
        ),
        Err(ApiError::Validation(_))
    ));
    assert!(matches!(
        storage.update_share(
            &share.id,
            ShareUpdateFields {
                password_hash: None,
                password_required: None,
                expires_in_seconds: Some(7_200),
                allow_download: None,
                recipient_note: None,
                max_uses: None,
            },
            &operator,
            &credential,
        ),
        Err(ApiError::Validation(_))
    ));
    assert!(matches!(
        storage.create_drop(
            DropCreateFields {
                workspace_id: &workspace.id,
                name: "Blocked",
                password_hash: "drop-password-hash",
                password_required: true,
                expires_in_seconds: 3_600,
            },
            &operator,
            &credential,
        ),
        Err(ApiError::Validation(_))
    ));
    assert!(matches!(
        storage.update_drop(
            &drop.id,
            DropUpdateFields {
                name: Some("Blocked rename"),
                password_hash: None,
                password_required: None,
                expires_in_seconds: None,
            },
            &operator,
            &credential,
        ),
        Err(ApiError::Validation(_))
    ));
}

#[test]
fn password_reset_debug_publication_revalidates_the_admin_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "reset-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    storage
        .create_password_reset_token(
            email,
            "reset-debug-token-hash",
            &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage
        .revoke_auth_session(session_id, "system@local")
        .unwrap();

    assert!(matches!(
        storage.create_password_reset_debug_publication_intent(
            email,
            "reset-debug-token-hash",
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert!(!storage
        .list_receipts()
        .unwrap()
        .iter()
        .any(|receipt| { receipt.kind == "auth.password_reset.debug.publish.intent" }));
}

#[test]
fn pending_workspace_invitation_limit_is_workspace_local_and_durable() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Invitation capacity", "owner@example.test")
        .unwrap();
    let now = Utc::now().to_rfc3339();
    let expires_at = (Utc::now() + chrono::Duration::days(7)).to_rfc3339();
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for index in 0..super::collaboration_limits::MAX_PENDING_WORKSPACE_INVITATIONS {
            tx.execute(
                "INSERT INTO workspace_invitations (
                    id, workspace_id, email, role, token_hash, status, invited_by,
                    expires_at, accepted_at, canceled_at, created_at, updated_at,
                    member_expires_in_seconds
                 ) VALUES (?1, ?2, ?3, 'viewer', ?4, 'pending', 'owner@example.test',
                           ?5, NULL, NULL, ?6, ?6, NULL)",
                params![
                    format!("invite-{index}"),
                    &workspace.id,
                    format!("invite-{index}@example.test"),
                    format!("token-{index}"),
                    &expires_at,
                    &now,
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let (operator, credential) = test_operator();
    assert!(matches!(
        storage.create_workspace_invitation(
            &workspace.id,
            "overflow@example.test",
            WorkspaceRole::Viewer,
            None,
            "overflow-token",
            "Capacity overflow",
            &operator,
            &credential,
        ),
        Err(ApiError::PayloadTooLarge(_))
    ));
    let (deduplicated, _) = storage
        .create_workspace_invitation(
            &workspace.id,
            "INVITE-0@example.test",
            WorkspaceRole::Editor,
            None,
            "replacement-token",
            "Replacement at capacity",
            &operator,
            &credential,
        )
        .unwrap();
    assert_eq!(deduplicated.id, "invite-0");
    assert_eq!(
        storage
            .list_workspace_invitations(&workspace.id)
            .unwrap()
            .len(),
        super::collaboration_limits::MAX_PENDING_WORKSPACE_INVITATIONS as usize
    );
}

#[test]
fn admin_upload_cleanup_revalidates_the_source_session_before_cancellation() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "cleanup-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage
        .create_workspace("Cleanup authorization", email)
        .unwrap();
    let upload = storage
        .create_upload_session(
            UploadSessionCreate {
                workspace_id: &workspace.id,
                actor_email: email,
                parent_id: None,
                name: "in-progress.bin",
                total_size: Some(1),
                path: None,
                duplicate_policy: "keep_both",
            },
            UploadAdmissionPolicy::default(),
        )
        .unwrap();
    // Keep this authorization test independent of backward wall-clock adjustments.
    {
        let conn = storage.conn.lock().unwrap();
        assert_eq!(
            conn.execute(
                "UPDATE upload_sessions
                 SET updated_at = '2000-01-01T00:00:00Z'
                 WHERE id = ?1",
                params![&upload.id],
            )
            .unwrap(),
            1
        );
    }
    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    let (candidates, _) = storage
        .stale_upload_cleanup_candidates_authorized(0, &actor, &credential)
        .unwrap();
    assert!(candidates.contains(&upload.id));
    storage
        .revoke_auth_session(session_id, "system@local")
        .unwrap();

    assert!(matches!(
        storage.stale_upload_cleanup_candidates_authorized(0, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.stale_drop_upload_cleanup_candidates_authorized(0, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.reap_stale_upload_session_authorized(&upload.id, 0, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(
        !storage
            .get_upload_session(&upload.id)
            .unwrap()
            .unwrap()
            .canceled
    );
}

#[test]
fn extreme_upload_cleanup_age_is_rejected_without_poisoning_storage() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential) = test_operator();

    assert!(matches!(
        storage.stale_upload_cleanup_candidates_authorized(i64::MAX, &actor, &credential),
        Err(ApiError::Validation(_))
    ));
    assert!(matches!(
        storage.stale_drop_upload_cleanup_candidates_authorized(i64::MAX, &actor, &credential),
        Err(ApiError::Validation(_))
    ));
    assert!(matches!(
        storage.stale_upload_session_ids(i64::MAX),
        Err(ApiError::Validation(_))
    ));
    assert!(matches!(
        storage.stale_drop_upload_session_ids(i64::MAX),
        Err(ApiError::Validation(_))
    ));
    storage
        .stale_upload_cleanup_candidates_authorized(0, &actor, &credential)
        .unwrap();
}

#[test]
fn mobile_offline_selection_revalidates_workspace_and_source_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "mobile-owner@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage.create_workspace("Mobile authority", email).unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "offline.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage
        .revoke_auth_session(session_id, "system@local")
        .unwrap();

    assert!(matches!(
        storage.set_mobile_offline_file(&actor, &credential, &workspace.id, &file.id, true),
        Err(ApiError::Unauthenticated)
    ));
    assert!(!storage.is_mobile_offline_file(email, &file.id).unwrap());
}

#[test]
fn queued_restore_and_terminal_mutations_revalidate_source_session() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage
        .create_workspace("Authorization boundary", email)
        .unwrap();

    let job = storage
        .enqueue_authorized_backup_restore_job("backup-one", &actor, &credential)
        .unwrap();
    storage
        .ensure_backup_restore_job_authorized(&job.id)
        .unwrap();
    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage.revoke_auth_session(session_id, email).unwrap();

    assert!(matches!(
        storage.ensure_backup_restore_job_authorized(&job.id),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.create_file_with_content_bytes_authorized(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "stale.txt".to_string(),
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
    assert!(matches!(
        storage.apply_rclone_import_atomic(
            &workspace.id,
            &actor,
            &credential,
            Vec::new(),
            RcloneFolderCollisionPolicy::KeepBoth,
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.apply_retention_authorized(&[], &[], &actor, &credential, Some(&workspace.id),),
        Err(ApiError::Unauthenticated)
    ));
}

#[test]
fn queued_backup_jobs_fail_closed_across_generation_and_authority_changes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("drive.db");
    let first = Storage::open_with_operator_credential_generation(
        path.clone(),
        "operator-v1-generation-a".to_string(),
    )
    .unwrap();
    first.migrate().unwrap();
    let (actor, credential) = test_operator();
    let stale = first
        .enqueue_authorized_backup_restore_job("operator-rotation", &actor, &credential)
        .unwrap();
    let (session_actor, session_credential, _) =
        test_local_account_session(&first, "backup-admin@example.test");
    let stale_session = first
        .enqueue_authorized_backup_job(
            "validate",
            "session-rotation",
            &session_actor,
            &session_credential,
        )
        .unwrap();
    let scheduled = first
        .enqueue_scheduled_backup_job("create", "scheduled-across-rotation", "system@local")
        .unwrap();
    let legacy = first
        .enqueue_scheduled_backup_job("validate", "legacy-unbound", "system@local")
        .unwrap();
    first
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE backup_jobs
             SET source_credential_kind = NULL, source_credential_id = NULL,
                 source_credential_generation = NULL
             WHERE id = ?1",
            params![&legacy.id],
        )
        .unwrap();
    first
        .ensure_backup_restore_job_authorized(&stale.id)
        .unwrap();
    drop(first);

    let rotated = Storage::open_with_operator_credential_generation(
        path,
        "operator-v1-generation-b".to_string(),
    )
    .unwrap();
    rotated.migrate().unwrap();
    assert_eq!(rotated.fail_stale_backup_jobs().unwrap(), 3);
    let stale = rotated.get_backup_job(&stale.id).unwrap().unwrap();
    assert_eq!(stale.status, "failed");
    assert_eq!(stale.phase, "credential_rotated");
    assert!(matches!(
        rotated.ensure_backup_restore_job_authorized(&stale.id),
        Err(ApiError::Forbidden)
    ));
    let stale_session = rotated.get_backup_job(&stale_session.id).unwrap().unwrap();
    assert_eq!(stale_session.status, "failed");
    assert_eq!(stale_session.phase, "credential_rotated");
    assert!(matches!(
        rotated.ensure_backup_job_authorized(&stale_session.id),
        Err(ApiError::Forbidden)
    ));
    let legacy = rotated.get_backup_job(&legacy.id).unwrap().unwrap();
    assert_eq!(legacy.status, "failed");
    assert_eq!(legacy.phase, "authority_unbound");
    assert!(matches!(
        rotated.ensure_backup_job_authorized(&legacy.id),
        Err(ApiError::Forbidden)
    ));
    rotated.ensure_backup_job_authorized(&scheduled.id).unwrap();
    let scheduled_claim = rotated.claim_next_backup_job().unwrap().unwrap();
    assert_eq!(scheduled_claim.id, scheduled.id);
    rotated
        .finish_backup_job(&scheduled_claim.id, "succeeded", "complete", None, None)
        .unwrap();

    let current = rotated
        .enqueue_authorized_backup_job("create", "operator-current-generation", &actor, &credential)
        .unwrap();
    rotated.ensure_backup_job_authorized(&current.id).unwrap();
    assert_eq!(
        rotated.claim_next_backup_job().unwrap().unwrap().id,
        current.id
    );
}

#[test]
fn queued_delegated_admin_backup_jobs_revalidate_without_failing_shape_screening() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, owner_credential, _) =
        test_local_account_session(&storage, "delegated-backup-admin@example.test");
    let delegated_actor = Actor {
        email: owner.email.clone(),
        is_admin: true,
        auth_mode: crate::auth::AuthMode::DelegatedAgent,
        allowed_workspace_ids: None,
    };
    let expires_at = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (active_agent, _) = storage
        .create_delegated_agent(
            "Active backup administrator",
            "active-delegated-backup-token-digest",
            &expires_at,
            &owner,
            &owner_credential,
        )
        .unwrap();
    let active_credential = DriveCredential::DelegatedAgentToken(active_agent.token_id.clone());
    let active = storage
        .enqueue_authorized_backup_job(
            "validate",
            "active-delegated-backup",
            &delegated_actor,
            &active_credential,
        )
        .unwrap();
    let active_claim = storage.claim_backup_job(&active.id).unwrap().unwrap();
    assert_eq!(active_claim.id, active.id);
    storage.ensure_backup_job_authorized(&active.id).unwrap();
    storage
        .finish_backup_job(&active.id, "succeeded", "complete", None, None)
        .unwrap();

    let malformed = storage
        .enqueue_authorized_backup_job(
            "validate",
            "malformed-delegated-backup",
            &delegated_actor,
            &active_credential,
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE backup_jobs SET source_credential_id = NULL
             WHERE id = ?1",
            params![&malformed.id],
        )
        .unwrap();
    let malformed_generation = storage
        .enqueue_authorized_backup_job(
            "validate",
            "malformed-delegated-generation",
            &delegated_actor,
            &active_credential,
        )
        .unwrap();
    let malformed = storage.get_backup_job(&malformed.id).unwrap().unwrap();
    assert_eq!(malformed.status, "failed");
    assert_eq!(malformed.phase, "authority_invalid");
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE backup_jobs SET source_credential_generation = 'unexpected-generation'
             WHERE id = ?1",
            params![&malformed_generation.id],
        )
        .unwrap();
    assert_eq!(storage.fail_stale_backup_jobs().unwrap(), 1);
    let malformed_generation = storage
        .get_backup_job(&malformed_generation.id)
        .unwrap()
        .unwrap();
    assert_eq!(malformed_generation.status, "failed");
    assert_eq!(malformed_generation.phase, "authority_invalid");

    let (revoked_agent, _) = storage
        .create_delegated_agent(
            "Revoked backup administrator",
            "revoked-delegated-backup-token-digest",
            &expires_at,
            &owner,
            &owner_credential,
        )
        .unwrap();
    let revoked_credential = DriveCredential::DelegatedAgentToken(revoked_agent.token_id.clone());
    let revoked = storage
        .enqueue_authorized_backup_job(
            "validate",
            "revoked-delegated-backup",
            &delegated_actor,
            &revoked_credential,
        )
        .unwrap();
    storage
        .revoke_delegated_agent(&revoked_agent.principal_id, &owner, &owner_credential)
        .unwrap();
    let revoked_claim = storage.claim_backup_job(&revoked.id).unwrap().unwrap();
    assert_eq!(revoked_claim.id, revoked.id);
    assert!(matches!(
        storage.ensure_backup_job_authorized(&revoked.id),
        Err(ApiError::Unauthenticated)
    ));
    storage
        .finish_backup_job(
            &revoked.id,
            "failed",
            "authority_invalid",
            None,
            Some("delegated authority was revoked"),
        )
        .unwrap();

    let (demoted_agent, _) = storage
        .create_delegated_agent(
            "Demoted backup administrator",
            "demoted-delegated-backup-token-digest",
            &expires_at,
            &owner,
            &owner_credential,
        )
        .unwrap();
    let demoted_credential = DriveCredential::DelegatedAgentToken(demoted_agent.token_id);
    let demoted = storage
        .enqueue_authorized_backup_job(
            "validate",
            "demoted-delegated-backup",
            &delegated_actor,
            &demoted_credential,
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE auth_accounts SET is_admin = 0 WHERE email = ?1",
            params![&owner.email],
        )
        .unwrap();
    let demoted_claim = storage.claim_backup_job(&demoted.id).unwrap().unwrap();
    assert_eq!(demoted_claim.id, demoted.id);
    assert!(matches!(
        storage.ensure_backup_job_authorized(&demoted.id),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn office_capabilities_fail_closed_across_operator_generation_rotation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("drive.db");
    let first = Storage::open_with_operator_credential_generation(
        path.clone(),
        "office-generation-a".to_string(),
    )
    .unwrap();
    first.migrate().unwrap();

    let (operator, operator_credential) = test_operator();
    let (operator_workspace, _, _) = first
        .create_workspace("Operator Office", &operator.email)
        .unwrap();
    let (operator_file, _) = first
        .create_file(
            CreateFileRequest {
                workspace_id: operator_workspace.id,
                parent_id: None,
                name: "operator.docx".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (_, operator_token) = first
        .create_office_edit_session(
            &operator_file.id,
            &operator.email,
            &operator_credential,
            operator_file.revision,
            "test-provider",
            900,
        )
        .unwrap();
    let (_, legacy_token) = first
        .create_office_edit_session(
            &operator_file.id,
            &operator.email,
            &operator_credential,
            operator_file.revision,
            "test-provider",
            900,
        )
        .unwrap();
    first
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE office_edit_sessions
             SET source_credential_generation = NULL
             WHERE token_hash = ?1",
            params![crate::auth::token_hash(&legacy_token)],
        )
        .unwrap();

    let email = "office-generation@example.test";
    let (session_actor, session_credential, _) = test_local_account_session(&first, email);
    let (session_workspace, _, _) = first.create_workspace("Session Office", email).unwrap();
    let (session_file, _) = first
        .create_file(
            CreateFileRequest {
                workspace_id: session_workspace.id,
                parent_id: None,
                name: "session.docx".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (_, session_token) = first
        .create_office_edit_session(
            &session_file.id,
            &session_actor.email,
            &session_credential,
            session_file.revision,
            "test-provider",
            900,
        )
        .unwrap();
    drop(first);

    let rotated =
        Storage::open_with_operator_credential_generation(path, "office-generation-b".to_string())
            .unwrap();
    rotated.migrate().unwrap();
    assert!(rotated
        .get_office_edit_session_by_token(&operator_token)
        .unwrap()
        .is_none());
    assert!(rotated
        .get_office_edit_session_by_token(&session_token)
        .unwrap()
        .is_none());
    assert!(matches!(
        rotated.claim_office_edit_session_authorized(&operator_token),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        rotated.claim_office_edit_session_authorized(&session_token),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        rotated.claim_office_edit_session_authorized(&legacy_token),
        Err(ApiError::NotFound)
    ));
}

#[test]
fn terminal_write_publication_rejects_session_revocation_and_role_downgrade() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "capability-writer@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let workspace = storage
        .create_workspace("Capability listing", email)
        .unwrap()
        .0;

    assert!(storage
        .list_workspace_shares(&workspace.id)
        .unwrap()
        .is_empty());
    assert!(storage
        .list_workspace_drops(&workspace.id)
        .unwrap()
        .is_empty());
    storage
        .ensure_workspace_publication_authorized(
            &workspace.id,
            &actor,
            &credential,
            WorkspacePermission::Write,
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
            WorkspacePermission::Write,
        ),
        Err(ApiError::Unauthenticated)
    ));

    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE auth_accounts SET is_admin = 0 WHERE email = ?1",
            params![email],
        )
        .unwrap();
    let (actor, credential, _) = test_session_for_existing_account(&storage, email);
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE workspace_members SET role = 'viewer'
             WHERE workspace_id = ?1 AND user_id = (
                 SELECT id FROM users WHERE email = ?2
             )",
            params![workspace.id, email],
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_workspace_publication_authorized(
            &workspace.id,
            &actor,
            &credential,
            WorkspacePermission::Write,
        ),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn backup_lifecycle_intents_reject_a_source_session_revoked_before_intent() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "backup-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let job = storage
        .enqueue_authorized_backup_job("create", "backup-intent", &actor, &credential)
        .unwrap();
    storage.claim_next_backup_job().unwrap().unwrap();
    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage.revoke_auth_session(session_id, email).unwrap();
    let receipts_before = storage.list_receipts().unwrap();

    assert!(matches!(
        storage.create_backup_download_publication_intent("backup-intent", &actor, &credential,),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.create_backup_delete_intent("backup-intent", &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.create_backup_v2_publication_intent(&job.id),
        Err(ApiError::Unauthenticated)
    ));

    assert_eq!(
        storage.list_receipts().unwrap().len(),
        receipts_before.len()
    );
    let current = storage.get_backup_job(&job.id).unwrap().unwrap();
    assert_eq!(current.status, "running");
    assert_eq!(current.phase, "starting");
}

#[test]
fn backup_lifecycle_intents_are_distinct_from_completion_receipts() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "backup-intent-admin@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let job = storage
        .enqueue_authorized_backup_job("create", "backup-intent-audit", &actor, &credential)
        .unwrap();
    storage.claim_next_backup_job().unwrap().unwrap();

    let publication = storage
        .create_backup_v2_publication_intent(&job.id)
        .unwrap();
    let deletion = storage
        .create_backup_delete_intent("backup-intent-audit", &actor, &credential)
        .unwrap();
    assert_eq!(publication.kind, "backup.create.intent");
    assert_eq!(deletion.kind, "backup.delete.intent");
    let receipts = storage.list_receipts().unwrap();
    assert!(!receipts
        .iter()
        .any(|receipt| receipt.kind == "backup.create"));
    assert!(!receipts
        .iter()
        .any(|receipt| receipt.kind == "backup.delete"));
}

#[test]
fn backup_v2_publication_intent_allows_scheduled_jobs() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let job = storage
        .enqueue_scheduled_backup_job(
            "create",
            "scheduled-backup-intent",
            "system-backup@shellx.local",
        )
        .unwrap();
    storage.claim_next_backup_job().unwrap().unwrap();

    let intent = storage
        .create_backup_v2_publication_intent(&job.id)
        .unwrap();
    assert_eq!(intent.kind, "backup.create.intent");
    assert_eq!(intent.actor, "system-backup@shellx.local");
    assert_eq!(
        storage.get_backup_job(&job.id).unwrap().unwrap().phase,
        "publishing"
    );
}

#[test]
fn comment_threads_and_replies_have_transactional_hard_caps() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Comment bounds", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: "review.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let now = Utc::now().to_rfc3339();
    let first_comment_id = Uuid::now_v7().to_string();
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for index in 0..500 {
            let id = if index == 0 {
                first_comment_id.clone()
            } else {
                Uuid::now_v7().to_string()
            };
            tx.execute(
                "INSERT INTO comments
                    (id, file_id, author_email, body, resolved, created_at, updated_at)
                 VALUES (?1, ?2, 'owner@example.test', 'bounded', 0, ?3, ?3)",
                params![id, &file.id, &now],
            )
            .unwrap();
        }
        for _ in 0..100 {
            tx.execute(
                "INSERT INTO comment_replies
                    (id, comment_id, author_email, body, created_at, updated_at)
                 VALUES (?1, ?2, 'owner@example.test', 'bounded', ?3, ?3)",
                params![Uuid::now_v7().to_string(), &first_comment_id, &now],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    assert!(matches!(
        storage.create_comment(&file.id, "owner@example.test", "one too many"),
        Err(ApiError::PayloadTooLarge(message)) if message.contains("comment threads")
    ));
    assert!(matches!(
        storage.create_comment_reply(
            &first_comment_id,
            "owner@example.test",
            "one too many",
        ),
        Err(ApiError::PayloadTooLarge(message)) if message.contains("reply limit")
    ));
    let listed = storage.list_comments_for_file(&file.id).unwrap();
    assert_eq!(listed.len(), 500);
    assert_eq!(
        listed
            .iter()
            .find(|comment| comment.id == first_comment_id)
            .unwrap()
            .replies
            .len(),
        100
    );
}

#[test]
fn retained_revision_bodies_are_charged_and_history_is_hard_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Revision quota", "owner@example.test")
        .unwrap();
    let (admin, credential) = test_operator();
    storage
        .update_workspace_policy(
            &workspace.id,
            serde_json::from_value(json!({"quota_bytes": 7})).unwrap(),
            &admin,
            &credential,
        )
        .unwrap();
    let (file, _) = storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "bounded.bin".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some("first-body".to_string()),
            4,
        )
        .unwrap();

    assert!(matches!(
        storage.put_content(&file.id, 1, "second-body", 4),
        Err(ApiError::Validation(message)) if message.contains("quota exceeded")
    ));
    assert_eq!(storage.get_file(&file.id).unwrap().unwrap().revision, 1);

    storage
        .update_workspace_policy(
            &workspace.id,
            serde_json::from_value(json!({"quota_bytes": 8})).unwrap(),
            &admin,
            &credential,
        )
        .unwrap();
    storage.put_content(&file.id, 1, "second-body", 4).unwrap();
    assert_eq!(
        storage
            .workspace_usage(&workspace.id)
            .unwrap()
            .remaining_bytes,
        Some(0)
    );

    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE workspace_policies SET quota_bytes = NULL WHERE workspace_id = ?1",
            params![&workspace.id],
        )
        .unwrap();
    }

    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for revision in 3..=MAX_FILE_REVISIONS as i64 {
            tx.execute(
                "INSERT INTO file_revisions (
                    id, file_id, revision, content_hash, content_bytes, created_at,
                    conflict_of_revision, pinned
                 ) VALUES (?1, ?2, ?3, ?4, 1, ?5, NULL, 0)",
                params![
                    Uuid::now_v7().to_string(),
                    &file.id,
                    revision,
                    format!("history-{revision}"),
                    Utc::now().to_rfc3339(),
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    assert_eq!(
        storage.list_file_revisions(&file.id).unwrap().len(),
        MAX_FILE_REVISIONS
    );
    assert!(matches!(
        storage.put_content(&file.id, 2, "overflow-body", 1),
        Err(ApiError::PayloadTooLarge(message)) if message.contains("bounded limit")
    ));

    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE file_revisions SET pinned = 1
             WHERE id IN (
                 SELECT id FROM file_revisions WHERE file_id = ?1
                 ORDER BY revision ASC LIMIT ?2
             )",
            params![&file.id, MAX_PINNED_FILE_REVISIONS as i64],
        )
        .unwrap();
    }
    assert!(matches!(
        storage.set_revision_pinned(
            &file.id,
            (MAX_PINNED_FILE_REVISIONS + 1) as i64,
            true,
            "owner@example.test"
        ),
        Err(ApiError::PayloadTooLarge(message)) if message.contains("pinned")
    ));
}

#[test]
fn password_reset_tokens_are_invalidated_by_later_security_state() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "reset@example.test";
    let (admin, credential) = test_operator();
    storage
        .create_auth_account(email, "old-hash", false, &admin, &credential)
        .unwrap();
    let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();

    storage
        .create_password_reset_token(email, "first-token", &expires_at)
        .unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO password_reset_tokens (
                id, email, token_hash, expires_at, used_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            params![
                Uuid::now_v7().to_string(),
                email,
                "sibling-token",
                &expires_at,
                Utc::now().to_rfc3339(),
            ],
        )
        .unwrap();
    }
    storage
        .consume_password_reset_token("first-token", "reset-hash")
        .unwrap();
    assert!(matches!(
        storage.consume_password_reset_token("sibling-token", "attacker-hash"),
        Err(ApiError::Validation(_))
    ));

    storage
        .create_password_reset_token(email, "before-password-change", &expires_at)
        .unwrap();
    let (account_actor, account_credential, _) = test_session_for_existing_account(&storage, email);
    storage
        .change_auth_account_password(
            email,
            "owner-changed-hash",
            storage
                .get_auth_account_secret(email)
                .unwrap()
                .unwrap()
                .security_version,
            VerifiedLocalSecondFactor::NotRequired,
            &account_actor,
            &account_credential,
        )
        .unwrap();
    assert!(matches!(
        storage.consume_password_reset_token("before-password-change", "attacker-hash"),
        Err(ApiError::Validation(_))
    ));

    storage
        .create_password_reset_token(email, "before-disable", &expires_at)
        .unwrap();
    storage
        .update_auth_account(
            email,
            Some(true),
            None,
            None,
            false,
            None,
            &admin,
            &credential,
        )
        .unwrap();
    storage
        .update_auth_account(
            email,
            Some(false),
            None,
            None,
            false,
            None,
            &admin,
            &credential,
        )
        .unwrap();
    assert!(matches!(
        storage.consume_password_reset_token("before-disable", "attacker-hash"),
        Err(ApiError::Validation(_))
    ));

    storage
        .create_password_reset_token(email, "before-2fa", &expires_at)
        .unwrap();
    let (account_actor, account_credential, _) = test_session_for_existing_account(&storage, email);
    let (replacement, _) = replacement_session_for_account(&storage, email);
    storage
        .update_totp_secret(
            email,
            "secret",
            storage
                .get_auth_account_secret(email)
                .unwrap()
                .unwrap()
                .security_version,
            VerifiedLocalSecondFactor::NotRequired,
            &test_rotation(&replacement, &account_actor, &account_credential),
        )
        .unwrap();
    assert!(matches!(
        storage.consume_password_reset_token("before-2fa", "attacker-hash"),
        Err(ApiError::Validation(_))
    ));
}

#[test]
fn bounded_subtrees_ignore_unrelated_workspace_rows_and_reject_oversize_trees() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Bounded trees", "owner@example.test")
        .unwrap();
    let (shared, _) = storage
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
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: Some(shared.id.clone()),
                name: "inside.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (oversized, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "oversized".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();

    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        let now = Utc::now().to_rfc3339();
        {
            let mut unrelated_insert = tx
                .prepare(
                    "INSERT INTO files (
                        id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                        content_hash, created_at, updated_at, content_bytes, cover_hash, cover_bytes
                     ) VALUES (?1, ?2, NULL, ?3, 'file', 1, 0, 0, NULL, ?4, ?4, 0, NULL, 0)",
                )
                .unwrap();
            let mut oversized_insert = tx
                .prepare(
                    "INSERT INTO files (
                        id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                        content_hash, created_at, updated_at, content_bytes, cover_hash, cover_bytes
                     ) VALUES (?1, ?2, ?3, ?4, 'file', 1, 0, 0, NULL, ?5, ?5, 0, NULL, 0)",
                )
                .unwrap();
            for index in 0..=MAX_FILE_TREE_NODES {
                unrelated_insert
                    .execute(params![
                        format!("unrelated-{index}"),
                        &workspace.id,
                        format!("u-{index}"),
                        &now
                    ])
                    .unwrap();
                oversized_insert
                    .execute(params![
                        format!("oversized-child-{index}"),
                        &workspace.id,
                        &oversized.id,
                        format!("o-{index}"),
                        &now
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }

    let entries = storage.share_folder_entries(&shared.id).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "inside.txt");
    assert!(matches!(
        storage.share_folder_entries(&oversized.id),
        Err(ApiError::Validation(_))
    ));
}

#[test]
fn compatibility_file_list_scopes_in_sql_and_enforces_its_sentinel() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Compatibility", "owner@example.test")
        .unwrap();
    for name in ["one.txt", "two.txt"] {
        storage
            .create_file(
                CreateFileRequest {
                    workspace_id: workspace.id.clone(),
                    parent_id: None,
                    name: name.to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                None,
            )
            .unwrap();
    }
    let owner = Actor {
        email: "owner@example.test".to_string(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };
    assert!(matches!(
        storage.list_files_for_actor_bounded(&owner, 1, true),
        Err(ApiError::PayloadTooLarge(_))
    ));
    let stranger = Actor {
        email: "stranger@example.test".to_string(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };
    assert!(storage
        .list_files_for_actor_bounded(&stranger, 1, true)
        .unwrap()
        .is_empty());
}

#[test]
fn effective_trash_visibility_precedes_bounded_list_limits() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Legacy bounded visibility", "owner@example.test")
        .unwrap();
    let (ancestor, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "archive".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    for name in ["hidden-first.txt", "hidden-second.txt"] {
        storage
            .create_file(
                CreateFileRequest {
                    workspace_id: workspace.id.clone(),
                    parent_id: Some(ancestor.id.clone()),
                    name: name.to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                None,
            )
            .unwrap();
    }
    let (live, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "live.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (other_workspace, _, _) = storage
        .create_workspace("Other legacy workspace", "other@example.test")
        .unwrap();
    let (foreign_parent, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: other_workspace.id,
                parent_id: None,
                name: "foreign-parent".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (cross_workspace_child, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "cross-workspace-child.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();

    // Reproduce the legacy state directly and make the hidden children sort
    // before the live row. A post-LIMIT filter would return an empty page or
    // incorrectly accept the compatibility sentinel.
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE files SET trashed = 1 WHERE id = ?1",
            params![ancestor.id],
        )
        .unwrap();
        conn.execute(
            "UPDATE files SET updated_at = '9999-01-01T00:00:02Z'
             WHERE name = 'hidden-first.txt'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE files SET updated_at = '9999-01-01T00:00:01Z'
             WHERE name = 'hidden-second.txt'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE files SET updated_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            params![live.id],
        )
        .unwrap();
        conn.execute(
            "UPDATE files
             SET parent_id = ?1, updated_at = '9999-01-01T00:00:03Z'
             WHERE id = ?2",
            params![foreign_parent.id, cross_workspace_child.id],
        )
        .unwrap();
    }

    assert!(storage
        .file_is_effectively_trashed(&cross_workspace_child.id)
        .unwrap());

    for files in [
        storage.list_workspace_files_bounded(&workspace.id, 1, false),
        storage.list_sync_manifest_files(&workspace.id, 1),
        storage.list_active_files_for_workspace_bounded(&workspace.id, 1),
    ] {
        let files = files.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].id, live.id);
    }

    let owner = Actor {
        email: "owner@example.test".to_string(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };
    let files = storage
        .list_files_for_actor_bounded(&owner, 1, false)
        .unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].id, live.id);
    assert!(matches!(
        storage.list_files_for_actor_bounded(&owner, 1, true),
        Err(ApiError::PayloadTooLarge(_))
    ));
}

#[test]
fn parent_validation_stays_inside_the_move_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("drive.db");
    let first = Storage::open(path.clone()).unwrap();
    first.migrate().unwrap();
    let second = Storage::open(path).unwrap();
    second
        .conn
        .lock()
        .unwrap()
        .busy_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let (workspace, _, _) = first
        .create_workspace("Tree", "owner@example.test")
        .unwrap();
    let (left, _) = first
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "left".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (right, _) = first
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: "right".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    first.install_parent_validation_pause(reached_tx, resume_rx);
    let left_id = left.id.clone();
    let right_id = right.id.clone();
    let first_move = {
        let storage = first.clone();
        let target = right_id.clone();
        std::thread::spawn(move || {
            storage.update_file(
                &left_id,
                UpdateFileRequest {
                    base_revision: None,
                    name: None,
                    parent_id: Some(target),
                    move_to_root: None,
                    collision_policy: None,
                    replace_target_id: None,
                    replace_target_revision: None,
                    labels: None,
                    custom_metadata: None,
                },
            )
        })
    };
    reached_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let (second_done_tx, second_done_rx) = std::sync::mpsc::channel();
    let second_move = {
        let storage = second.clone();
        let source = right_id.clone();
        let target = left.id.clone();
        std::thread::spawn(move || {
            let result = storage.update_file(
                &source,
                UpdateFileRequest {
                    base_revision: None,
                    name: None,
                    parent_id: Some(target),
                    move_to_root: None,
                    collision_policy: None,
                    replace_target_id: None,
                    replace_target_revision: None,
                    labels: None,
                    custom_metadata: None,
                },
            );
            second_done_tx.send(()).unwrap();
            result
        })
    };
    assert!(second_done_rx
        .recv_timeout(std::time::Duration::from_millis(100))
        .is_err());
    resume_tx.send(()).unwrap();
    assert!(first_move.join().unwrap().is_ok());
    assert!(second_move.join().unwrap().is_err());
    assert!(first.descendants_inclusive(&left.id).is_ok());
    assert!(first.descendants_inclusive(&right_id).is_ok());
}

#[test]
fn zero_day_retention_is_due_immediately() {
    let cutoff = Utc::now();
    let future_timestamp = (cutoff + Duration::hours(1)).to_rfc3339();

    assert!(retention_timestamp_due(&future_timestamp, &cutoff, 0).unwrap());
}

#[test]
fn retention_preview_returns_a_bounded_repeatable_batch() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Bounded retention", "owner@example.test")
        .unwrap();
    let (actor, credential) = test_operator();
    storage
        .update_workspace_policy(
            &workspace.id,
            serde_json::from_value(json!({"trash_retention_days": 0})).unwrap(),
            &actor,
            &credential,
        )
        .unwrap();
    let now = Utc::now().to_rfc3339();
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        let mut insert = tx
            .prepare(
                "INSERT INTO files (
                    id, workspace_id, parent_id, name, kind, revision, trashed, trashed_at,
                    starred, content_hash, content_bytes, cover_hash, cover_bytes,
                    created_at, updated_at
                 ) VALUES (?1, ?2, NULL, ?3, 'file', 1, 1, ?4, 0, NULL, 0, NULL, 0, ?4, ?4)",
            )
            .unwrap();
        for index in 0..=super::lifecycle::MAX_RETENTION_CANDIDATES {
            insert
                .execute(params![
                    format!("retention-file-{index:05}"),
                    &workspace.id,
                    format!("file-{index:05}.txt"),
                    &now
                ])
                .unwrap();
        }
        drop(insert);
        tx.commit().unwrap();
    }

    let (trash, revisions, totals, more_available) =
        storage.preview_retention(Some(&workspace.id)).unwrap();
    assert_eq!(trash.len(), super::lifecycle::MAX_RETENTION_CANDIDATES);
    assert!(revisions.is_empty());
    assert_eq!(totals.trashed_files, trash.len());
    assert!(more_available);
}

#[test]
fn retention_preview_rechecks_the_source_session_before_disclosing_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "retention-owner@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage
        .create_workspace("Retention preview", email)
        .unwrap();
    storage
        .update_workspace_policy(
            &workspace.id,
            serde_json::from_value(serde_json::json!({"trash_retention_days": 0})).unwrap(),
            &actor,
            &credential,
        )
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "private-candidate.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    storage
        .set_trashed_authorized(&file.id, true, &actor, &credential)
        .unwrap();
    let (trash, _, _, _) = storage
        .preview_retention_authorized(Some(&workspace.id), &actor, &credential)
        .unwrap();
    assert_eq!(trash.len(), 1);

    let DriveCredential::UserSession(session_id) = &credential else {
        panic!("expected local session");
    };
    storage.revoke_auth_session(session_id, email).unwrap();
    assert!(matches!(
        storage.preview_retention_authorized(Some(&workspace.id), &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
}

#[test]
fn retention_preview_rechecks_workspace_manage_after_role_downgrade() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "retention-manager@example.test";
    let actor = Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::Sso,
        allowed_workspace_ids: None,
    };
    let session_id = "retention-manager-session";
    let credential = DriveCredential::UserSession(session_id.to_string());
    storage
        .record_auth_session(
            session_id,
            email,
            "oidc-test",
            "retention-manager-subject",
            "retention-manager-token-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Retention scope", "other-owner@example.test")
        .unwrap();
    let (operator, operator_credential) = test_operator();
    storage
        .upsert_workspace_member(
            &workspace.id,
            email,
            WorkspaceRole::Owner,
            &operator,
            &operator_credential,
        )
        .unwrap();
    storage
        .preview_retention_authorized(Some(&workspace.id), &actor, &credential)
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
    let preview = storage.preview_retention_authorized(Some(&workspace.id), &actor, &credential);
    assert!(matches!(preview, Err(ApiError::Forbidden)), "{preview:?}");
}

#[test]
fn backup_jobs_are_durable_single_lease_and_recover_interrupted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("drive.db");
    let storage = Storage::open(path.clone()).unwrap();
    storage.migrate().unwrap();
    let first = storage
        .enqueue_scheduled_backup_job("create", "backup-one", "admin@example.test")
        .unwrap();
    let second = storage
        .enqueue_scheduled_backup_job("create", "backup-two", "admin@example.test")
        .unwrap();

    let running = storage.claim_next_backup_job().unwrap().unwrap();
    assert_eq!(running.id, first.id);
    assert_eq!(running.status, "running");
    assert!(storage.claim_next_backup_job().unwrap().is_none());
    drop(storage);

    let reopened = Storage::open(path).unwrap();
    reopened.migrate().unwrap();
    assert_eq!(reopened.interrupt_running_backup_jobs().unwrap(), 1);
    let interrupted = reopened.get_backup_job(&first.id).unwrap().unwrap();
    assert_eq!(interrupted.status, "interrupted");
    assert_eq!(interrupted.phase, "interrupted_starting");
    assert!(interrupted.last_error.unwrap().len() <= 2048);
    assert_eq!(
        reopened.claim_next_backup_job().unwrap().unwrap().id,
        second.id
    );
}

#[test]
fn backup_job_admission_has_a_transactional_active_cap() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    for index in 0..32 {
        storage
            .enqueue_scheduled_backup_job(
                "create",
                &format!("bounded-backup-{index}"),
                "system-backup@shellx.local",
            )
            .unwrap();
    }
    assert!(matches!(
        storage.enqueue_scheduled_backup_job(
            "create",
            "bounded-backup-overflow",
            "system-backup@shellx.local",
        ),
        Err(ApiError::TooManyRequests)
    ));
}

#[test]
fn backup_job_errors_are_utf8_safe_and_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let job = storage
        .enqueue_scheduled_backup_job("validate", "backup-error", "admin@example.test")
        .unwrap();
    storage.claim_next_backup_job().unwrap().unwrap();
    let message = "💾".repeat(800);
    let failed = storage
        .finish_backup_job(&job.id, "failed", "failed", None, Some(&message))
        .unwrap();
    let error = failed.last_error.unwrap();
    assert!(error.len() <= 2048);
    assert!(error.is_char_boundary(error.len()));
    assert!(error.chars().all(|character| character == '💾'));
}

#[test]
fn auth_throttle_is_partitioned_bounded_and_decays() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let policy = AuthThrottlePolicy {
        threshold: 5,
        base_lockout_seconds: 30,
        max_lockout_seconds: 300,
        decay_seconds: 900,
    };

    let mut attempt = None;
    for _ in 0..5 {
        attempt = Some(
            storage
                .record_auth_attempt_failure(
                    Some("person@example.test"),
                    "password",
                    "client-v1-a",
                    policy,
                )
                .unwrap(),
        );
    }
    let attempt = attempt.unwrap();
    assert_eq!(attempt.failures, 5);
    let first_lock = DateTime::parse_from_rfc3339(attempt.locked_until.as_ref().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let first_updated = DateTime::parse_from_rfc3339(&attempt.updated_at)
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!((first_lock - first_updated).num_seconds(), 30);

    let other_client = storage
        .record_auth_attempt_failure(
            Some("person@example.test"),
            "password",
            "client-v1-b",
            policy,
        )
        .unwrap();
    assert_eq!(other_client.failures, 1);
    assert_ne!(attempt.key, other_client.key);

    let mut capped = attempt;
    for _ in 0..20 {
        capped = storage
            .record_auth_attempt_failure(
                Some("person@example.test"),
                "password",
                "client-v1-a",
                policy,
            )
            .unwrap();
    }
    let capped_lock = DateTime::parse_from_rfc3339(capped.locked_until.as_ref().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let capped_updated = DateTime::parse_from_rfc3339(&capped.updated_at)
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!((capped_lock - capped_updated).num_seconds(), 300);
    assert_eq!(capped.failures, 21);

    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE auth_attempts SET updated_at = ?1 WHERE key = ?2",
            params![(Utc::now() - Duration::hours(1)).to_rfc3339(), capped.key],
        )
        .unwrap();
    }
    let decayed = storage
        .record_auth_attempt_failure(
            Some("person@example.test"),
            "password",
            "client-v1-a",
            policy,
        )
        .unwrap();
    assert_eq!(decayed.failures, 1);
    assert!(decayed.locked_until.is_none());
}

#[test]
fn shared_auth_recovery_is_single_use_and_never_extends_an_active_penalty() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let policy = AuthThrottlePolicy {
        threshold: 1,
        base_lockout_seconds: 30,
        max_lockout_seconds: 30,
        decay_seconds: 900,
    };
    storage
        .record_auth_attempt_failure(
            Some("person@example.test"),
            "password_login_account",
            "account",
            policy,
        )
        .unwrap();
    let before = storage
        .list_auth_attempts()
        .unwrap()
        .into_iter()
        .find(|attempt| attempt.scope == "password_login_account")
        .unwrap();

    assert_eq!(
        storage
            .admit_auth_attempt_or_reserve_shared_recovery(
                Some("person@example.test"),
                "password_login_account",
                "account",
                "password_login_account_recovery",
                "recovery",
            )
            .unwrap(),
        AuthAttemptAdmission::SharedRecovery
    );
    let after_reservation = storage
        .list_auth_attempts()
        .unwrap()
        .into_iter()
        .find(|attempt| attempt.scope == "password_login_account")
        .unwrap();
    assert_eq!(after_reservation.failures, before.failures);
    assert_eq!(after_reservation.locked_until, before.locked_until);
    assert_eq!(after_reservation.updated_at, before.updated_at);

    assert!(matches!(
        storage.admit_auth_attempt_or_reserve_shared_recovery(
            Some("person@example.test"),
            "password_login_account",
            "account",
            "password_login_account_recovery",
            "recovery",
        ),
        Err(ApiError::TooManyRequests)
    ));
    let after_denial = storage
        .list_auth_attempts()
        .unwrap()
        .into_iter()
        .find(|attempt| attempt.scope == "password_login_account")
        .unwrap();
    assert_eq!(after_denial.failures, before.failures);
    assert_eq!(after_denial.locked_until, before.locked_until);
    assert_eq!(after_denial.updated_at, before.updated_at);

    let expired_at = (Utc::now() - Duration::seconds(1)).to_rfc3339();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE auth_attempts SET locked_until = ?1 WHERE key = ?2",
            params![expired_at, before.key],
        )
        .unwrap();
    }
    assert_eq!(
        storage
            .admit_auth_attempt_or_reserve_shared_recovery(
                Some("person@example.test"),
                "password_login_account",
                "account",
                "password_login_account_recovery",
                "recovery",
            )
            .unwrap(),
        AuthAttemptAdmission::Ordinary
    );
    let expired = storage
        .list_auth_attempts()
        .unwrap()
        .into_iter()
        .find(|attempt| attempt.scope == "password_login_account")
        .unwrap();
    assert_eq!(expired.locked_until.as_deref(), Some(expired_at.as_str()));
    assert_eq!(expired.updated_at, before.updated_at);
}

#[test]
fn public_rate_limit_partitions_drop_uploads_by_drop_and_client() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    for _ in 0..2 {
        storage
            .consume_partitioned_public_rate_limit(
                "drop-a",
                "drop_upload_request",
                "client-a",
                2,
                60,
            )
            .unwrap();
    }
    assert!(matches!(
        storage.consume_partitioned_public_rate_limit(
            "drop-a",
            "drop_upload_request",
            "client-a",
            2,
            60,
        ),
        Err(ApiError::TooManyRequests)
    ));
    storage
        .consume_partitioned_public_rate_limit("drop-a", "drop_upload_request", "client-b", 2, 60)
        .unwrap();
    storage
        .consume_partitioned_public_rate_limit("drop-b", "drop_upload_request", "client-a", 2, 60)
        .unwrap();
}

#[test]
fn denied_public_rate_limits_do_not_prune_or_rewrite_sqlite() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    for _ in 0..2 {
        storage
            .consume_partitioned_public_rate_limit(
                "drop-a",
                "drop_upload_request",
                "client-a",
                2,
                60,
            )
            .unwrap();
    }
    let before = storage
        .list_auth_attempts()
        .unwrap()
        .into_iter()
        .find(|attempt| attempt.scope == "drop_upload_request")
        .unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO auth_attempts
             (key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at)
             VALUES ('stale-denial-probe', NULL, 'probe', 'probe', 1, NULL, ?1)",
            [(Utc::now() - Duration::days(30)).to_rfc3339()],
        )
        .unwrap();
    }
    for _ in 0..2 {
        assert!(matches!(
            storage.consume_partitioned_public_rate_limit(
                "drop-a",
                "drop_upload_request",
                "client-a",
                2,
                60,
            ),
            Err(ApiError::TooManyRequests)
        ));
    }
    let attempts = storage.list_auth_attempts().unwrap();
    let after = attempts
        .iter()
        .find(|attempt| attempt.scope == "drop_upload_request")
        .unwrap();
    assert_eq!(after.failures, before.failures);
    assert_eq!(after.updated_at, before.updated_at);
    assert_eq!(after.locked_until, before.locked_until);
    assert!(attempts
        .iter()
        .any(|attempt| attempt.key == "stale-denial-probe"));
}

#[test]
fn fixed_window_recovery_budget_is_not_extended_by_denied_requests() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    for _ in 0..5 {
        storage
            .consume_partitioned_fixed_window_rate_limit(
                "person@example.test",
                "password_reset_email",
                "all-clients",
                5,
                900,
            )
            .unwrap();
    }
    let before = storage
        .list_auth_attempts()
        .unwrap()
        .into_iter()
        .find(|attempt| attempt.scope == "password_reset_email")
        .unwrap();
    for _ in 0..2 {
        assert!(matches!(
            storage.consume_partitioned_fixed_window_rate_limit(
                "person@example.test",
                "password_reset_email",
                "all-clients",
                5,
                900,
            ),
            Err(ApiError::TooManyRequests)
        ));
    }
    let after = storage
        .list_auth_attempts()
        .unwrap()
        .into_iter()
        .find(|attempt| attempt.scope == "password_reset_email")
        .unwrap();
    assert_eq!(after.updated_at, before.updated_at);
    assert_eq!(after.locked_until, before.locked_until);

    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE auth_attempts SET updated_at = ?1 WHERE key = ?2",
            params![(Utc::now() - Duration::hours(1)).to_rfc3339(), &after.key],
        )
        .unwrap();
    storage.public_rate_limit_denials.clear_for_test(&after.key);
    storage
        .consume_partitioned_fixed_window_rate_limit(
            "person@example.test",
            "password_reset_email",
            "all-clients",
            5,
            900,
        )
        .unwrap();
}

#[test]
fn password_reset_request_queues_atomically_and_keeps_the_active_token() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();
    assert!(storage
        .create_password_reset_token_and_email_if_none_active(
            "person@example.test",
            "first-token",
            &expires_at,
            "Reset password",
            "reset body",
        )
        .unwrap());
    assert!(!storage
        .create_password_reset_token_and_email_if_none_active(
            "person@example.test",
            "replacement-token",
            &expires_at,
            "Reset password",
            "replacement body",
        )
        .unwrap());
    let conn = storage.conn.lock().unwrap();
    let hashes: Vec<String> = conn
        .prepare(
            "SELECT token_hash FROM password_reset_tokens
             WHERE email = 'person@example.test'",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(hashes, vec!["first-token"]);
    drop(conn);
    let emails = storage.list_email_outbox_redacted().unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].kind, "password_reset");
}

#[test]
fn password_reset_email_failure_rolls_back_token_creation() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let result = storage.create_password_reset_token_and_email_if_none_active(
        "person@example.test",
        "stranded-token",
        &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        "",
        "reset body",
    );
    assert!(matches!(result, Err(ApiError::Validation(_))));
    let conn = storage.conn.lock().unwrap();
    let token_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM password_reset_tokens", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(token_count, 0);
}

#[test]
fn legacy_thumbnail_bytes_are_backfilled_and_future_previews_obey_the_budget() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path();
    let storage = Storage::open(data_dir.join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Preview budget", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "preview.png".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let thumbnail = b"legacy-thumbnail";
    let hash = blob::put_blob(data_dir, thumbnail).unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO file_previews (
                file_id, workspace_id, revision, kind, content,
                thumbnail_hash, thumbnail_content_type, thumbnail_bytes,
                width, height, status, updated_at
             ) VALUES (?1, ?2, ?3, 'image_thumbnail', 'ready', ?4, 'image/png', 0,
                       1, 1, 'ready', ?5)",
            params![
                file.id,
                workspace.id,
                file.revision,
                hash,
                Utc::now().to_rfc3339()
            ],
        )
        .unwrap();
    }

    storage.backfill_thumbnail_bytes(data_dir).unwrap();
    let charged: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT thumbnail_bytes FROM file_previews WHERE file_id = ?1",
            params![file.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(charged, thumbnail.len() as i64);

    let oversized = GeneratedPreview {
        kind: "image_thumbnail".to_string(),
        content: "oversized".to_string(),
        thumbnail_hash: None,
        thumbnail_content_type: Some("image/png".to_string()),
        thumbnail_bytes: MAX_WORKSPACE_THUMBNAIL_BYTES + 1,
        width: Some(1),
        height: Some(1),
        status: "ready".to_string(),
        thumbnail_publication: None,
    };
    assert!(matches!(
        storage.upsert_file_preview(&file, oversized),
        Err(ApiError::PayloadTooLarge(message)) if message.contains("derived-data budget")
    ));
}

#[test]
fn background_jobs_deduplicate_queued_work_and_claim_exactly_once() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Job claims", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "job.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();

    storage
        .enqueue_background_job("search_index", &workspace.id, &file.id)
        .unwrap();
    storage
        .enqueue_background_job("search_index", &workspace.id, &file.id)
        .unwrap();
    let queued = storage.queued_background_jobs().unwrap();
    let search_jobs = queued
        .iter()
        .filter(|job| job.kind == "search_index")
        .collect::<Vec<_>>();
    assert_eq!(search_jobs.len(), 1);
    assert!(storage
        .mark_background_job_running(&search_jobs[0].id)
        .unwrap());
    assert!(!storage
        .mark_background_job_running(&search_jobs[0].id)
        .unwrap());
    storage
        .finish_background_job(&search_jobs[0].id, "skipped", Some("test"))
        .unwrap();

    storage
        .enqueue_background_job("search_index", &workspace.id, &file.id)
        .unwrap();
    assert_eq!(
        storage
            .queued_background_jobs()
            .unwrap()
            .iter()
            .filter(|job| job.kind == "search_index")
            .count(),
        1
    );
}

#[test]
fn file_receipt_and_sync_change_commit_with_the_authenticated_actor() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Atomic receipt", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "receipt.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();

    let (_, receipt) = storage
        .set_starred_as(&file.id, true, "owner@example.test")
        .unwrap();
    let stored = storage
        .list_receipts()
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.id == receipt.id)
        .unwrap();
    assert_eq!(stored.actor, "owner@example.test");
    let change = storage
        .list_sync_changes(0, Some(&workspace.id))
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.receipt_id == receipt.id)
        .unwrap();
    assert_eq!(change.actor, "owner@example.test");
    assert_eq!(change.kind, "file.star");

    let (deleted, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "deleted.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (_, delete_receipt) = storage
        .permanently_delete_file(&deleted.id, "owner@example.test")
        .unwrap();
    assert!(storage.get_file(&deleted.id).unwrap().is_none());
    let deletion = storage
        .list_sync_changes(0, Some(&workspace.id))
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.receipt_id == delete_receipt.id)
        .expect("permanent deletion sync tombstone");
    assert_eq!(deletion.kind, "file.delete");
    assert_eq!(deletion.entity_id, deleted.id);
}

#[test]
fn destructive_deletion_batches_emit_one_atomic_workspace_rescan_per_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential) = test_operator();

    let (empty_workspace, _, _) = storage
        .create_workspace("Empty trash sync", "owner@example.test")
        .unwrap();
    storage
        .update_workspace_policy(
            &empty_workspace.id,
            serde_json::from_value(json!({"trash_retention_days": 0})).unwrap(),
            &actor,
            &credential,
        )
        .unwrap();
    let mut empty_file_ids = Vec::new();
    for name in ["empty-one.txt", "empty-two.txt"] {
        let (file, _) = storage
            .create_file(
                CreateFileRequest {
                    workspace_id: empty_workspace.id.clone(),
                    parent_id: None,
                    name: name.to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                None,
            )
            .unwrap();
        storage
            .set_trashed_authorized(&file.id, true, &actor, &credential)
            .unwrap();
        empty_file_ids.push(file.id);
    }
    let (empty_result, empty_receipt) = storage
        .empty_workspace_trash(&empty_workspace.id, &actor, &credential)
        .unwrap();
    assert_eq!(empty_result.deleted, 2);
    assert!(empty_file_ids
        .iter()
        .all(|file_id| storage.get_file(file_id).unwrap().is_none()));
    let empty_rescans = storage
        .list_sync_changes(0, Some(&empty_workspace.id))
        .unwrap()
        .into_iter()
        .filter(|change| change.receipt_id == empty_receipt.id && change.kind == "workspace.rescan")
        .collect::<Vec<_>>();
    assert_eq!(empty_rescans.len(), 1);
    assert_eq!(empty_rescans[0].entity_type, "workspace");
    assert_eq!(empty_rescans[0].entity_id, empty_workspace.id);

    let (scoped_workspace, _, _) = storage
        .create_workspace("Scoped retention sync", "owner@example.test")
        .unwrap();
    storage
        .update_workspace_policy(
            &scoped_workspace.id,
            serde_json::from_value(json!({"trash_retention_days": 0})).unwrap(),
            &actor,
            &credential,
        )
        .unwrap();
    let (scoped_file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: scoped_workspace.id.clone(),
                parent_id: None,
                name: "scoped.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    storage
        .set_trashed_authorized(&scoped_file.id, true, &actor, &credential)
        .unwrap();
    let (scoped_trash, scoped_revisions, _, _) = storage
        .preview_retention(Some(&scoped_workspace.id))
        .unwrap();
    let (scoped_receipt, _, applied_scoped_trash, _) = storage
        .apply_retention_authorized(
            &scoped_trash,
            &scoped_revisions,
            &actor,
            &credential,
            Some(&scoped_workspace.id),
        )
        .unwrap();
    assert_eq!(applied_scoped_trash.len(), 1);
    assert!(storage.get_file(&scoped_file.id).unwrap().is_none());
    let scoped_rescans = storage
        .list_sync_changes(0, Some(&scoped_workspace.id))
        .unwrap()
        .into_iter()
        .filter(|change| {
            change.receipt_id == scoped_receipt.id && change.kind == "workspace.rescan"
        })
        .collect::<Vec<_>>();
    assert_eq!(scoped_rescans.len(), 1);
    assert_eq!(scoped_rescans[0].entity_id, scoped_workspace.id);

    let (global_workspace, _, _) = storage
        .create_workspace("Global retention sync", "owner@example.test")
        .unwrap();
    storage
        .update_workspace_policy(
            &global_workspace.id,
            serde_json::from_value(json!({"trash_retention_days": 0})).unwrap(),
            &actor,
            &credential,
        )
        .unwrap();
    let (global_file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: global_workspace.id.clone(),
                parent_id: None,
                name: "global.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    storage
        .set_trashed_authorized(&global_file.id, true, &actor, &credential)
        .unwrap();
    let (global_trash, global_revisions, _, _) = storage.preview_retention(None).unwrap();
    let (global_receipt, _, applied_global_trash, _) = storage
        .apply_retention_authorized(&global_trash, &global_revisions, &actor, &credential, None)
        .unwrap();
    assert!(global_receipt.target_id.is_none());
    assert_eq!(applied_global_trash.len(), 1);
    assert!(storage.get_file(&global_file.id).unwrap().is_none());
    let global_rescans = storage
        .list_sync_changes(0, Some(&global_workspace.id))
        .unwrap()
        .into_iter()
        .filter(|change| {
            change.receipt_id == global_receipt.id && change.kind == "workspace.rescan"
        })
        .collect::<Vec<_>>();
    assert_eq!(global_rescans.len(), 1);
    assert_eq!(global_rescans[0].entity_id, global_workspace.id);
}

#[test]
fn empty_trash_rolls_back_when_its_rescan_event_cannot_be_persisted() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential) = test_operator();
    let (workspace, _, _) = storage
        .create_workspace("Empty trash rollback", "owner@example.test")
        .unwrap();
    storage
        .update_workspace_policy(
            &workspace.id,
            serde_json::from_value(json!({"trash_retention_days": 0})).unwrap(),
            &actor,
            &credential,
        )
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "must-survive.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    storage
        .set_trashed_authorized(&file.id, true, &actor, &credential)
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_workspace_rescan
             BEFORE INSERT ON sync_changes
             WHEN NEW.kind = 'workspace.rescan'
             BEGIN
                 SELECT RAISE(ABORT, 'forced workspace rescan failure');
             END;",
        )
        .unwrap();

    assert!(storage
        .empty_workspace_trash(&workspace.id, &actor, &credential)
        .is_err());
    assert!(storage.get_file(&file.id).unwrap().is_some());
    assert!(!storage
        .list_receipts()
        .unwrap()
        .iter()
        .any(|receipt| receipt.kind == "file.trash.empty"));
    assert!(storage
        .list_sync_changes(0, Some(&workspace.id))
        .unwrap()
        .iter()
        .all(|change| change.kind != "workspace.rescan"));
}

#[test]
fn empty_trash_revalidates_the_source_credential_in_its_deletion_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "empty-trash-owner@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage
        .create_workspace("Empty trash authorization", email)
        .unwrap();
    let (operator, operator_credential) = test_operator();
    storage
        .update_workspace_policy(
            &workspace.id,
            serde_json::from_value(json!({"trash_retention_days": 0})).unwrap(),
            &operator,
            &operator_credential,
        )
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "revoked.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    storage
        .set_trashed_authorized(&file.id, true, &actor, &credential)
        .unwrap();
    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage.revoke_auth_session(session_id, email).unwrap();

    assert!(matches!(
        storage.empty_workspace_trash(&workspace.id, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(storage.get_file(&file.id).unwrap().is_some());
}

#[test]
fn stale_sync_cursors_fail_after_retained_history_advances() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Sync floor", "owner@example.test")
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO sync_change_floors (workspace_id, floor_cursor) VALUES (?1, 42)",
            params![workspace.id],
        )
        .unwrap();

    assert!(matches!(
        storage.list_sync_changes(41, Some(&workspace.id)),
        Err(ApiError::Conflict)
    ));
    assert!(storage
        .list_sync_changes(42, Some(&workspace.id))
        .unwrap()
        .is_empty());
    assert_eq!(storage.current_sync_cursor(&workspace.id).unwrap(), 42);
}

#[test]
fn sync_history_trigger_caps_each_workspace_and_records_the_resync_floor() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Sync retention", "owner@example.test")
        .unwrap();
    let receipt = storage
        .insert_receipt("test.retention", "owner@example.test", None)
        .unwrap();
    let now = Utc::now().to_rfc3339();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "WITH RECURSIVE seq(value) AS (
               VALUES(1) UNION ALL SELECT value + 1 FROM seq WHERE value < 10001
             )
             INSERT INTO sync_changes (
               workspace_id, kind, entity_type, entity_id, actor, receipt_id, created_at
             )
             SELECT ?1, 'file.star', 'file', printf('file-%05d', value),
                    'owner@example.test', ?2, ?3
             FROM seq",
            params![workspace.id, receipt.id, now],
        )
        .unwrap();

    let conn = storage.conn.lock().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_changes WHERE workspace_id = ?1",
            params![workspace.id],
            |row| row.get(0),
        )
        .unwrap();
    let floor: i64 = conn
        .query_row(
            "SELECT floor_cursor FROM sync_change_floors WHERE workspace_id = ?1",
            params![workspace.id],
            |row| row.get(0),
        )
        .unwrap();
    drop(conn);
    assert_eq!(count, 10_000);
    assert!(floor > 0);
    assert!(matches!(
        storage.list_sync_changes(floor - 1, Some(&workspace.id)),
        Err(ApiError::Conflict)
    ));
}

#[test]
fn office_sessions_are_bounded_per_actor_and_file() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Office bounds", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: "bounded.docx".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    for _ in 0..8 {
        storage
            .create_office_edit_session(
                &file.id,
                "owner@example.test",
                &DriveCredential::Operator,
                file.revision,
                "test-provider",
                3_600,
            )
            .unwrap();
    }
    assert!(matches!(
        storage.create_office_edit_session(
            &file.id,
            "owner@example.test",
            &DriveCredential::Operator,
            file.revision,
            "test-provider",
            3_600,
        ),
        Err(ApiError::TooManyRequests)
    ));
}

#[test]
fn import_runs_are_bounded_per_actor_and_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Import bounds", "owner@example.test")
        .unwrap();
    for _ in 0..4 {
        storage
            .start_import_run("rclone_preview", "owner@example.test", Some(&workspace.id))
            .unwrap();
    }
    assert!(matches!(
        storage.start_import_run("rclone_preview", "owner@example.test", Some(&workspace.id)),
        Err(ApiError::TooManyRequests)
    ));
}

#[test]
fn rclone_preview_completion_rejects_a_revoked_source_session_without_success_or_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Preview credential boundary", "owner@example.test")
        .unwrap();
    let (operator, operator_credential) = test_operator();
    storage
        .upsert_workspace_member(
            &workspace.id,
            "editor@example.test",
            WorkspaceRole::Editor,
            &operator,
            &operator_credential,
        )
        .unwrap();
    let actor = Actor {
        email: "editor@example.test".to_string(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::Sso,
        allowed_workspace_ids: None,
    };
    let session_id = "preview-revoked-session";
    storage
        .record_auth_session(
            session_id,
            &actor.email,
            "oidc-test",
            "preview-revoked-subject",
            "preview-revoked-token-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let credential = DriveCredential::UserSession(session_id.to_string());
    let run_id = storage
        .start_import_run("rclone_preview", &actor.email, Some(&workspace.id))
        .unwrap();

    storage
        .revoke_auth_session(session_id, "system@local")
        .unwrap();

    assert!(matches!(
        storage.complete_rclone_preview_authorized(
            &run_id,
            &workspace.id,
            &actor,
            &credential,
            ImportRunTotals {
                entries: 1,
                files: 1,
                folders: 0,
                bytes: 5,
            },
        ),
        Err(ApiError::Unauthenticated)
    ));
    let status: String = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT status FROM import_runs WHERE id = ?1",
            params![run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "running");
    assert!(storage
        .list_receipts()
        .unwrap()
        .iter()
        .all(|receipt| receipt.kind != "import.preview"));
}

#[test]
fn rclone_export_completion_keeps_authority_tracking_and_statistics_atomic() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "export-owner@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage.create_workspace("Export", email).unwrap();
    let (file, _) = storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "selected.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some("a".repeat(64)),
            4,
        )
        .unwrap();
    let file_ids = vec![file.id.clone()];
    let subjects = vec![FileContentSubject::Current(
        CurrentFileSubject::from_file(&file).unwrap(),
    )];
    let statistics_targets = vec![(file.id.clone(), workspace.id.clone())];
    let totals = ImportRunTotals {
        entries: 1,
        files: 1,
        folders: 0,
        bytes: 4,
    };

    let allowed_run = storage
        .start_import_run("rclone_export", email, Some(&workspace.id))
        .unwrap();
    storage
        .complete_rclone_export_authorized(RcloneExportCompletion {
            run_id: &allowed_run,
            workspace_id: &workspace.id,
            file_ids: &file_ids,
            content_subjects: &subjects,
            actor: &actor,
            source_credential: &credential,
            totals,
            statistics_targets: &statistics_targets,
        })
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_rclone_export_stats BEFORE UPDATE ON file_access_stats
             BEGIN SELECT RAISE(ABORT, 'statistics unavailable'); END;",
        )
        .unwrap();
    let best_effort_run = storage
        .start_import_run("rclone_export", email, Some(&workspace.id))
        .unwrap();
    storage
        .complete_rclone_export_authorized(RcloneExportCompletion {
            run_id: &best_effort_run,
            workspace_id: &workspace.id,
            file_ids: &file_ids,
            content_subjects: &subjects,
            actor: &actor,
            source_credential: &credential,
            totals,
            statistics_targets: &statistics_targets,
        })
        .unwrap();
    let denied_run = storage
        .start_import_run("rclone_export", email, Some(&workspace.id))
        .unwrap();
    let DriveCredential::UserSession(session_id) = &credential else {
        unreachable!();
    };
    storage.revoke_auth_session(session_id, email).unwrap();
    assert!(matches!(
        storage.complete_rclone_export_authorized(RcloneExportCompletion {
            run_id: &denied_run,
            workspace_id: &workspace.id,
            file_ids: &file_ids,
            content_subjects: &subjects,
            actor: &actor,
            source_credential: &credential,
            totals,
            statistics_targets: &statistics_targets,
        }),
        Err(ApiError::Unauthenticated)
    ));

    let conn = storage.conn.lock().unwrap();
    let allowed_status: String = conn
        .query_row(
            "SELECT status FROM import_runs WHERE id = ?1",
            params![allowed_run],
            |row| row.get(0),
        )
        .unwrap();
    let denied_status: String = conn
        .query_row(
            "SELECT status FROM import_runs WHERE id = ?1",
            params![denied_run],
            |row| row.get(0),
        )
        .unwrap();
    let best_effort_status: String = conn
        .query_row(
            "SELECT status FROM import_runs WHERE id = ?1",
            params![best_effort_run],
            |row| row.get(0),
        )
        .unwrap();
    let download_count: i64 = conn
        .query_row(
            "SELECT download_count FROM file_access_stats WHERE file_id = ?1",
            params![file.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(allowed_status, "succeeded");
    assert_eq!(best_effort_status, "succeeded");
    assert_eq!(denied_status, "running");
    assert_eq!(download_count, 1);
}

#[test]
fn rclone_preview_completion_rejects_a_downgraded_member_without_success_or_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Preview membership boundary", "owner@example.test")
        .unwrap();
    let (operator, operator_credential) = test_operator();
    storage
        .upsert_workspace_member(
            &workspace.id,
            "editor@example.test",
            WorkspaceRole::Editor,
            &operator,
            &operator_credential,
        )
        .unwrap();
    let actor = Actor {
        email: "editor@example.test".to_string(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::Sso,
        allowed_workspace_ids: None,
    };
    let credential = DriveCredential::UserSession("preview-downgraded-session".to_string());
    storage
        .record_auth_session(
            "preview-downgraded-session",
            &actor.email,
            "oidc-test",
            "preview-downgraded-subject",
            "preview-downgraded-token-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let run_id = storage
        .start_import_run("rclone_preview", &actor.email, Some(&workspace.id))
        .unwrap();

    storage
        .upsert_workspace_member(
            &workspace.id,
            &actor.email,
            WorkspaceRole::Viewer,
            &operator,
            &operator_credential,
        )
        .unwrap();

    assert!(matches!(
        storage.complete_rclone_preview_authorized(
            &run_id,
            &workspace.id,
            &actor,
            &credential,
            ImportRunTotals {
                entries: 1,
                files: 1,
                folders: 0,
                bytes: 5,
            },
        ),
        Err(ApiError::Forbidden)
    ));
    let status: String = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT status FROM import_runs WHERE id = ?1",
            params![run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "running");
    assert!(storage
        .list_receipts()
        .unwrap()
        .iter()
        .all(|receipt| receipt.kind != "import.preview"));
}

#[test]
fn rclone_preview_completion_commits_run_totals_and_receipt_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "preview-editor@example.test";
    let (workspace, _, _) = storage
        .create_workspace("Preview atomic success", email)
        .unwrap();
    let actor = Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::Sso,
        allowed_workspace_ids: None,
    };
    let credential = DriveCredential::UserSession("preview-valid-session".to_string());
    storage
        .record_auth_session(
            "preview-valid-session",
            email,
            "oidc-test",
            "preview-valid-subject",
            "preview-valid-token-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let run_id = storage
        .start_import_run("rclone_preview", email, Some(&workspace.id))
        .unwrap();
    let totals = ImportRunTotals {
        entries: 3,
        files: 2,
        folders: 1,
        bytes: 42,
    };

    let receipt = storage
        .complete_rclone_preview_authorized(&run_id, &workspace.id, &actor, &credential, totals)
        .unwrap();

    assert_eq!(receipt.kind, "import.preview");
    assert_eq!(receipt.actor, email);
    assert_eq!(receipt.target_id.as_deref(), Some(workspace.id.as_str()));
    let completed: (String, i64, i64, i64, i64, Option<String>) = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT status, entries, files, folders, bytes, completed_at
             FROM import_runs WHERE id = ?1",
            params![run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(completed.0, "succeeded");
    assert_eq!(completed.1, totals.entries);
    assert_eq!(completed.2, totals.files);
    assert_eq!(completed.3, totals.folders);
    assert_eq!(completed.4, totals.bytes);
    assert!(completed.5.is_some());
    assert!(storage
        .list_receipts()
        .unwrap()
        .iter()
        .any(|stored| stored.id == receipt.id));
}

#[test]
fn email_queue_rejects_oversized_content_and_a_saturated_queue() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    assert!(matches!(
        storage.queue_email(
            "test",
            "person@example.test",
            "subject",
            &"x".repeat(super::email_outbox::MAX_EMAIL_BODY_BYTES + 1),
            None,
            None,
        ),
        Err(ApiError::PayloadTooLarge(_))
    ));
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        let mut statement = tx
            .prepare(
                "INSERT INTO email_outbox (
                    id, kind, status, recipient_email, subject, body_text,
                    attempts, created_at, updated_at
                 ) VALUES (?1, 'test', 'queued', 'person@example.test', 'subject',
                           'body', 0, ?2, ?2)",
            )
            .unwrap();
        let now = Utc::now().to_rfc3339();
        for index in 0..super::email_outbox::MAX_QUEUED_EMAIL_ROWS {
            statement
                .execute(params![format!("queued-{index:05}"), &now])
                .unwrap();
        }
        drop(statement);
        tx.commit().unwrap();
    }
    assert!(matches!(
        storage.queue_email("test", "person@example.test", "subject", "body", None, None,),
        Err(ApiError::TooManyRequests)
    ));
}

#[test]
fn finite_share_access_grants_are_bounded_per_public_capability() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Share bounds", "owner@example.test")
        .unwrap();
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
    let (actor, credential) = test_operator();
    let (share, _) = storage
        .create_share(
            ShareCreateFields {
                file_id: &file.id,
                password_hash: "not-required",
                password_required: false,
                expires_in_seconds: 3_600,
                target_kind: "file",
                allow_download: true,
                recipient_note: None,
                max_uses: Some(1_000),
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
    let first = storage
        .claim_share_access(&share.id, &fingerprint, "client-a")
        .unwrap()
        .access_token
        .unwrap();
    assert!(storage
        .validate_share_access_grant(&share.id, Some(&first), "client-a")
        .is_ok());
    assert!(storage
        .validate_share_access_grant(&share.id, Some(&first), "client-b")
        .is_err());
    for _ in 1..128 {
        assert!(storage
            .claim_share_access(&share.id, &fingerprint, "client-a")
            .unwrap()
            .access_token
            .is_some());
    }
    assert!(matches!(
        storage.claim_share_access(&share.id, &fingerprint, "client-a"),
        Err(ApiError::TooManyRequests)
    ));
}

#[test]
fn unlimited_share_access_does_not_mint_bounded_grants() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Unlimited share bounds", "owner@example.test")
        .unwrap();
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
    let (actor, credential) = test_operator();
    let (share, _) = storage
        .create_share(
            ShareCreateFields {
                file_id: &file.id,
                password_hash: "not-required",
                password_required: false,
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
    let fingerprint = storage
        .get_share(&share.id)
        .unwrap()
        .unwrap()
        .authorization_fingerprint();

    for _ in 0..256 {
        let claimed = storage
            .claim_share_access(&share.id, &fingerprint, "client-a")
            .unwrap();
        assert!(claimed.access_token.is_none());
    }
    let conn = rusqlite::Connection::open(temp.path().join("drive.db")).unwrap();
    let active_grants: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM share_access_grants WHERE share_id = ?1",
            params![share.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active_grants, 0);
}

#[test]
fn agent_grants_fail_closed_when_a_legacy_active_root_has_a_trashed_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Agent trash boundary", "owner@example.test")
        .unwrap();
    let (ancestor, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "ancestor".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (root, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: Some(ancestor.id.clone()),
                name: "granted-root".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (actor, credential) = test_operator();
    let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let (access, _) = storage
        .create_agent_access(
            "legacy-root-agent",
            &workspace.id,
            &root.id,
            crate::model::AgentPermission::View,
            "test-token-digest",
            &expires_at,
            &actor,
            &credential,
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE files SET trashed = 1 WHERE id = ?1",
            params![ancestor.id],
        )
        .unwrap();

    assert!(matches!(
        storage.authorize_agent_grant(
            &access.principal_id,
            &access.token_id,
            &access.grant_id,
            false,
        ),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn agent_tree_publication_rejects_a_selected_child_moved_outside_the_grant() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Agent terminal tree", "owner@example.test")
        .unwrap();
    let (root, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "granted".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (outside, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "outside".to_string(),
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
                workspace_id: workspace.id.clone(),
                parent_id: Some(root.id.clone()),
                name: "selected.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (actor, credential) = test_operator();
    let (access, _) = storage
        .create_agent_access(
            "terminal-tree-agent",
            &workspace.id,
            &root.id,
            crate::model::AgentPermission::View,
            "terminal-tree-token-digest",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    let (_, planned_files) = storage
        .agent_tree(&access.principal_id, &access.token_id, &access.grant_id)
        .unwrap();
    assert!(planned_files.iter().any(|file| file.id == child.id));

    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE files SET parent_id = ?2 WHERE id = ?1",
            params![&child.id, &outside.id],
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_agent_tree_publication_authorized(
            &access.principal_id,
            &access.token_id,
            &access.grant_id,
            &planned_files,
        ),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn office_sessions_and_cover_commits_revalidate_membership_and_source_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Transactional Office authority", "owner@example.test")
        .unwrap();
    let (operator, operator_credential) = test_operator();
    storage
        .upsert_workspace_member(
            &workspace.id,
            "editor@example.test",
            WorkspaceRole::Editor,
            &operator,
            &operator_credential,
        )
        .unwrap();
    let editor = Actor {
        email: "editor@example.test".to_string(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::Sso,
        allowed_workspace_ids: None,
    };
    let active_session_id = "office-transactional-session";
    storage
        .record_auth_session(
            active_session_id,
            &editor.email,
            "oidc-test",
            "editor-subject",
            "office-transactional-session-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let active_credential = DriveCredential::UserSession(active_session_id.to_string());
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "office.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (folder, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "covers".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (_, office_token) = storage
        .create_office_edit_session(
            &file.id,
            &editor.email,
            &active_credential,
            file.revision,
            "Office editor",
            900,
        )
        .unwrap();

    storage
        .remove_workspace_member(
            &workspace.id,
            &editor.email,
            &operator,
            &operator_credential,
        )
        .unwrap();

    assert!(matches!(
        storage.claim_office_edit_session_authorized(&office_token),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.set_folder_cover_authorized(
            &folder.id,
            &"a".repeat(64),
            1,
            &editor,
            &active_credential,
        ),
        Err(ApiError::Forbidden)
    ));
    assert_eq!(storage.folder_cover_hash(&folder.id).unwrap(), None);

    let retained_cover_hash = "b".repeat(64);
    storage
        .set_folder_cover_as(&folder.id, &retained_cover_hash, 1, "system")
        .unwrap();
    assert!(matches!(
        storage.clear_folder_cover_authorized(&folder.id, &editor, &active_credential),
        Err(ApiError::Forbidden)
    ));
    assert_eq!(
        storage.folder_cover_hash(&folder.id).unwrap().as_deref(),
        Some(retained_cover_hash.as_str())
    );

    let revoked_session_id = "office-revoked-source-session";
    storage
        .upsert_workspace_member(
            &workspace.id,
            &editor.email,
            WorkspaceRole::Editor,
            &operator,
            &operator_credential,
        )
        .unwrap();
    storage
        .record_auth_session(
            revoked_session_id,
            &editor.email,
            "oidc-test",
            "editor-subject",
            "office-revoked-source-session-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let revoked_credential = DriveCredential::UserSession(revoked_session_id.to_string());
    let (_, revoked_office_token) = storage
        .create_office_edit_session(
            &file.id,
            &editor.email,
            &revoked_credential,
            file.revision,
            "Office editor",
            900,
        )
        .unwrap();
    storage
        .revoke_auth_session(revoked_session_id, "system@local")
        .unwrap();
    assert!(matches!(
        storage.claim_office_edit_session_authorized(&revoked_office_token),
        Err(ApiError::NotFound)
    ));
}

fn search_subject_file(storage: &Storage, workspace_id: &str, name: &str, hash: &str) -> DriveFile {
    storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: None,
                name: name.to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some(hash.to_string()),
            1,
        )
        .unwrap()
        .0
}

fn text_index_row_count(storage: &Storage, file_id: &str) -> i64 {
    storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM file_text_index WHERE file_id = ?1",
            params![file_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn fts_content(storage: &Storage, file_id: &str) -> String {
    storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT content FROM file_search_fts WHERE file_id = ?1",
            params![file_id],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn replacing_content_atomically_removes_the_superseded_search_projection() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Search replacement", "owner@example.test")
        .unwrap();
    let file = search_subject_file(&storage, &workspace.id, "memo.txt", &"a".repeat(64));
    storage
        .index_file_text(&file, "supersededsearchneedle")
        .unwrap();

    storage
        .put_content(&file.id, file.revision, &"b".repeat(64), 1)
        .unwrap();

    assert_eq!(text_index_row_count(&storage, &file.id), 0);
    assert_eq!(fts_content(&storage, &file.id), "");
    assert!(storage
        .search_file_results("supersededsearchneedle")
        .unwrap()
        .is_empty());
}

#[test]
fn stale_index_or_clear_worker_cannot_replace_or_remove_the_current_projection() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Search worker ordering", "owner@example.test")
        .unwrap();
    let stale_file = search_subject_file(&storage, &workspace.id, "memo.txt", &"a".repeat(64));
    storage
        .index_file_text(&stale_file, "oldworkerneedle")
        .unwrap();
    storage
        .put_content(&stale_file.id, stale_file.revision, &"b".repeat(64), 1)
        .unwrap();
    let current_file = storage.get_file(&stale_file.id).unwrap().unwrap();
    storage
        .index_file_text(&current_file, "currentworkerneedle")
        .unwrap();

    assert!(!storage
        .index_file_text(&stale_file, "oldworkerneedle")
        .unwrap());
    storage.clear_file_text_index(&stale_file).unwrap();

    assert_eq!(
        fts_content(&storage, &current_file.id),
        "currentworkerneedle"
    );
    assert!(storage
        .search_file_results("oldworkerneedle")
        .unwrap()
        .is_empty());
    assert_eq!(
        storage
            .search_file_results("currentworkerneedle")
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn deleting_a_superseded_revision_cannot_resurface_its_search_text() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Search revision deletion", "owner@example.test")
        .unwrap();
    let old_file = search_subject_file(&storage, &workspace.id, "memo.txt", &"a".repeat(64));
    storage
        .index_file_text(&old_file, "deletedrevisionneedle")
        .unwrap();
    storage
        .put_content(&old_file.id, old_file.revision, &"b".repeat(64), 1)
        .unwrap();
    let current_file = storage.get_file(&old_file.id).unwrap().unwrap();
    storage
        .index_file_text(&current_file, "currentrevisionneedle")
        .unwrap();

    storage
        .delete_file_revision(&old_file.id, old_file.revision, "system")
        .unwrap();

    assert!(storage
        .search_file_results("deletedrevisionneedle")
        .unwrap()
        .is_empty());
    assert_eq!(
        fts_content(&storage, &current_file.id),
        "currentrevisionneedle"
    );
}

#[test]
fn extreme_workspace_policy_dates_are_rejected_without_poisoning_storage() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Bounded policy dates", "owner@example.test")
        .unwrap();
    let (actor, credential) = test_operator();
    for request in [
        json!({"max_link_ttl_seconds": i64::MAX}),
        json!({"trash_retention_days": i64::MAX}),
        json!({"revision_retention_days": i64::MAX}),
    ] {
        assert!(matches!(
            storage.update_workspace_policy(
                &workspace.id,
                serde_json::from_value(request).unwrap(),
                &actor,
                &credential,
            ),
            Err(ApiError::Validation(_))
        ));
        assert!(storage.get_workspace_policy(&workspace.id).is_ok());
    }
    storage
        .update_workspace_policy(
            &workspace.id,
            serde_json::from_value(json!({"trash_retention_days": 30})).unwrap(),
            &actor,
            &credential,
        )
        .unwrap();

    // Older databases can already contain these values. Every consuming path
    // must return an error while leaving the process-wide connection usable.
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "revision.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (share, _) = storage
        .create_share(
            ShareCreateFields {
                file_id: &file.id,
                password_hash: "not-required",
                password_required: false,
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
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE workspace_policies SET trash_retention_days = ?1 WHERE workspace_id = ?2",
            params![i64::MAX, &workspace.id],
        )
        .unwrap();
    }
    assert!(matches!(
        storage.empty_workspace_trash(&workspace.id, &actor, &credential),
        Err(ApiError::Validation(_))
    ));
    assert!(storage.get_workspace_policy(&workspace.id).is_ok());
    assert!(matches!(
        storage.preview_retention(Some(&workspace.id)),
        Err(ApiError::Validation(_))
    ));
    assert!(storage.get_workspace_policy(&workspace.id).is_ok());
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE workspace_policies SET trash_retention_days = 30, revision_retention_days = ?1, max_link_ttl_seconds = ?1 WHERE workspace_id = ?2",
            params![i64::MAX, &workspace.id],
        )
        .unwrap();
    }
    assert!(matches!(
        storage.prune_file_revisions(&file.id, "owner@example.test"),
        Err(ApiError::Validation(_))
    ));
    assert!(storage.get_workspace_policy(&workspace.id).is_ok());
    assert!(matches!(
        storage.update_share(
            &share.id,
            ShareUpdateFields {
                password_hash: None,
                password_required: None,
                expires_in_seconds: Some(i64::MAX),
                allow_download: None,
                recipient_note: None,
                max_uses: None,
            },
            &actor,
            &credential,
        ),
        Err(ApiError::Validation(_))
    ));
    assert!(storage.get_share(&share.id).unwrap().is_some());
}
