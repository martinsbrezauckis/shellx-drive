use chrono::{Duration, Utc};
use rusqlite::params;
use uuid::Uuid;

use super::*;
use crate::{
    auth::{token_hash, Actor, AuthMode, DriveCredential},
    error::ApiError,
    storage::Storage,
};

fn local_owner(storage: &Storage, email: &str) -> (Actor, DriveCredential) {
    storage
        .bootstrap_auth_account(email, "stored-password-hash")
        .unwrap();
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
            is_admin: false,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        },
        DriveCredential::UserSession(session_id),
    )
}

fn self_actor(owner: &Actor) -> Actor {
    Actor {
        email: owner.email.clone(),
        is_admin: owner.is_admin,
        auth_mode: AuthMode::DelegatedAgent,
        allowed_workspace_ids: None,
    }
}

fn create_delegation(
    storage: &Storage,
    owner: &Actor,
    owner_credential: &DriveCredential,
    name: &str,
    token: &str,
) -> DelegatedAgent {
    storage
        .create_delegated_agent(
            name,
            &token_hash(token),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            owner,
            owner_credential,
        )
        .unwrap()
        .0
}

fn stage_self_rotation(
    storage: &Storage,
    agent: &DelegatedAgent,
    actor: &Actor,
    token: &str,
) -> (PendingDelegatedAgentPublication, DriveCredential) {
    let credential = DriveCredential::DelegatedAgentToken(agent.token_id.clone());
    let pending = storage
        .stage_delegated_agent_rotation(
            &agent.principal_id,
            &token_hash(token),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            actor,
            &credential,
        )
        .unwrap();
    (pending, credential)
}

mod limits;

#[test]
fn self_lifecycle_terminal_checks_bind_source_retirement_and_published_state() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, owner_credential) = local_owner(&storage, "self-lifecycle@example.test");
    let actor = self_actor(&owner);

    let stale_source = create_delegation(
        &storage,
        &owner,
        &owner_credential,
        "Stale staged source",
        "sxd_agent_stale-source",
    );
    let (stale_pending, stale_credential) = stage_self_rotation(
        &storage,
        &stale_source,
        &actor,
        "sxd_agent_stale-replacement",
    );
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE agent_tokens SET revoked_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), &stale_source.token_id],
        )
        .unwrap();
    assert!(matches!(
        storage.publish_pending_delegated_agent(&stale_pending, &actor, &stale_credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(storage
        .authenticate_delegated_agent_token(
            &token_hash("sxd_agent_stale-replacement"),
            Utc::now().timestamp()
        )
        .unwrap()
        .is_none());

    let token_revocation = create_delegation(
        &storage,
        &owner,
        &owner_credential,
        "Replacement token retirement",
        "sxd_agent-token-retirement-source",
    );
    let (pending, credential) = stage_self_rotation(
        &storage,
        &token_revocation,
        &actor,
        "sxd_agent-token-retirement-replacement",
    );
    let completion = storage
        .publish_pending_delegated_agent(&pending, &actor, &credential)
        .unwrap();
    storage
        .ensure_pending_delegated_agent_publication_authorized(
            &pending,
            &completion,
            &actor,
            &credential,
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE agent_tokens SET revoked_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), &pending.token_id],
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_pending_delegated_agent_publication_authorized(
            &pending,
            &completion,
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));

    let principal_retirement = create_delegation(
        &storage,
        &owner,
        &owner_credential,
        "Replacement principal retirement",
        "sxd_agent-principal-retirement-source",
    );
    let (pending, credential) = stage_self_rotation(
        &storage,
        &principal_retirement,
        &actor,
        "sxd_agent-principal-retirement-replacement",
    );
    let completion = storage
        .publish_pending_delegated_agent(&pending, &actor, &credential)
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE agent_principals SET disabled_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), &pending.principal_id],
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_pending_delegated_agent_publication_authorized(
            &pending,
            &completion,
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
}

#[test]
fn nonself_revoke_keeps_postmutation_source_liveness_check() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, owner_credential) = local_owner(&storage, "nonself-revoke@example.test");
    let token = "sxd_agent_nonself-revoke";
    let agent = create_delegation(
        &storage,
        &owner,
        &owner_credential,
        "Nonself liveness target",
        token,
    );
    storage
        .conn
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER revoke_owner_session_after_delegation_retirement
             AFTER UPDATE OF revoked_at ON agent_tokens
             WHEN NEW.delegation_kind = 'delegated'
             BEGIN
               UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
               WHERE actor_email = 'nonself-revoke@example.test';
             END",
        )
        .unwrap();
    assert!(matches!(
        storage.revoke_delegated_agent(&agent.principal_id, &owner, &owner_credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(storage
        .authenticate_delegated_agent_token(&token_hash(token), Utc::now().timestamp())
        .unwrap()
        .is_some());
}
