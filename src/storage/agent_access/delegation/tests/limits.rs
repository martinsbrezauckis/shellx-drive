use super::super::limits::{
    MAX_ACTIVE_DELEGATED_AGENTS_PER_OWNER, MAX_DELEGATED_AGENTS_PER_OWNER,
    MAX_DELEGATED_TOKENS_PER_PRINCIPAL, RETIRED_DELEGATION_RETENTION_DAYS,
};
use super::*;

#[test]
fn delegated_agent_quota_and_page_are_bounded_for_one_owner() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, credential) = local_owner(&storage, "delegation-page@example.test");
    for index in 0..MAX_ACTIVE_DELEGATED_AGENTS_PER_OWNER {
        create_delegation(
            &storage,
            &owner,
            &credential,
            &format!("Agent {index}"),
            &format!("sxd_agent_page-{index}"),
        );
    }
    let first = storage
        .list_delegated_agents_for_owner(&owner, &credential, None, 25)
        .unwrap();
    assert_eq!(first.0.len(), 25);
    let second = storage
        .list_delegated_agents_for_owner(&owner, &credential, first.1.as_deref(), 25)
        .unwrap();
    assert_eq!(second.0.len(), 25);
    assert!(second.1.is_none());
    let ids: std::collections::HashSet<_> = first
        .0
        .iter()
        .chain(&second.0)
        .map(|agent| &agent.principal_id)
        .collect();
    assert_eq!(ids.len(), 50);
    let rejected = storage.create_pending_delegated_agent(
        "One too many",
        &token_hash("sxd_agent_quota-rejected"),
        &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        &owner,
        &credential,
    );
    assert!(matches!(rejected, Err(ApiError::PayloadTooLarge(_))));
    storage
        .revoke_delegated_agent(&first.0[0].principal_id, &owner, &credential)
        .unwrap();
    create_delegation(
        &storage,
        &owner,
        &credential,
        "Replacement",
        "sxd_agent_quota-replacement",
    );
}

#[test]
fn delegated_agent_rotation_preserves_bounded_token_history() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, credential) = local_owner(&storage, "delegation-rotation-limit@example.test");
    let agent = create_delegation(&storage, &owner, &credential, "Agent", "sxd_agent_original");
    {
        let conn = storage.conn.lock().unwrap();
        for index in 1..MAX_DELEGATED_TOKENS_PER_PRINCIPAL {
            conn.execute(
                "INSERT INTO agent_tokens (id, principal_id, token_hash, delegation_kind, expires_at, revoked_at, created_at)
                 VALUES (?1, ?2, ?3, 'delegated', ?4, ?5, ?6)",
                params![
                    Uuid::now_v7().to_string(), &agent.principal_id,
                    token_hash(&format!("sxd_agent_old-{index}")),
                    (Utc::now() + Duration::hours(1)).to_rfc3339(),
                    Utc::now().to_rfc3339(), Utc::now().to_rfc3339()
                ],
            ).unwrap();
        }
    }
    let rejected = storage.stage_delegated_agent_rotation(
        &agent.principal_id,
        &token_hash("sxd_agent_rejected-rotation"),
        &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        &owner,
        &credential,
    );
    assert!(matches!(rejected, Err(ApiError::PayloadTooLarge(_))));
    assert!(storage
        .authenticate_delegated_agent_token(
            &token_hash("sxd_agent_original"),
            Utc::now().timestamp()
        )
        .unwrap()
        .is_some());
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE agent_tokens SET revoked_at = ?1 WHERE token_hash = ?2",
            params![
                (Utc::now() - Duration::days(RETIRED_DELEGATION_RETENTION_DAYS + 1)).to_rfc3339(),
                token_hash("sxd_agent_old-1")
            ],
        )
        .unwrap();
    let pending = storage
        .stage_delegated_agent_rotation(
            &agent.principal_id,
            &token_hash("sxd_agent_allowed-rotation"),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &owner,
            &credential,
        )
        .unwrap();
    storage
        .publish_pending_delegated_agent(&pending, &owner, &credential)
        .unwrap();
    assert!(storage
        .authenticate_delegated_agent_token(
            &token_hash("sxd_agent_allowed-rotation"),
            Utc::now().timestamp()
        )
        .unwrap()
        .is_some());
}

#[test]
fn expired_retired_delegation_history_frees_total_quota() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, credential) = local_owner(&storage, "delegation-history@example.test");
    let old = (Utc::now() - Duration::days(RETIRED_DELEGATION_RETENTION_DAYS + 1)).to_rfc3339();
    {
        let conn = storage.conn.lock().unwrap();
        for index in 0..MAX_DELEGATED_AGENTS_PER_OWNER {
            let principal = Uuid::now_v7().to_string();
            conn.execute(
                "INSERT INTO agent_principals (id, name, created_by, creator_authority_kind, delegation_parent_kind, disabled_at, created_at)
                 VALUES (?1, ?2, ?3, 'user', 'local', ?4, ?4)",
                params![&principal, format!("Retired {index}"), &owner.email, &old],
            ).unwrap();
            conn.execute(
                "INSERT INTO agent_tokens (id, principal_id, token_hash, delegation_kind, expires_at, revoked_at, created_at)
                 VALUES (?1, ?2, ?3, 'delegated', ?4, ?4, ?4)",
                params![Uuid::now_v7().to_string(), &principal, token_hash(&format!("sxd_agent_retired-{index}")), &old],
            ).unwrap();
        }
    }
    create_delegation(
        &storage,
        &owner,
        &credential,
        "New agent",
        "sxd_agent_new-after-retention",
    );
    let agents = storage
        .list_delegated_agents_for_owner(&owner, &credential, None, 25)
        .unwrap();
    assert_eq!(agents.0[0].name, "New agent");
    assert!(agents.1.is_some());
}
