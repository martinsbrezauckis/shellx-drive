use chrono::{Duration, Utc};
use rusqlite::params;

use crate::{
    auth::{token_hash, Actor, DriveCredential},
    error::ApiError,
    model::{AgentAccess, AgentPermission, CreateFileRequest, DriveFile, FileKind},
    storage::Storage,
};

use super::common::test_source;

struct Fixture {
    _directory: tempfile::TempDir,
    storage: Storage,
    actor: Actor,
    credential: DriveCredential,
    workspace_id: String,
    root: DriveFile,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(directory.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let (actor, credential, workspace_id, root) =
            test_source(&storage, "bounded-agent@example.test");
        Self {
            _directory: directory,
            storage,
            actor,
            credential,
            workspace_id,
            root,
        }
    }

    fn create(&self, index: i64) -> Result<AgentAccess, ApiError> {
        let pending = self.storage.create_pending_agent_access_publication(
            &format!("Worker {index}"),
            &self.workspace_id,
            &self.root.id,
            AgentPermission::View,
            &token_hash(&format!("token-{index}")),
            &expiry(),
            &self.actor,
            &self.credential,
        )?;
        self.storage
            .publish_pending_agent_access(&pending, &self.actor, &self.credential)?;
        Ok(pending.access)
    }

    fn fill_retired_principals(&self) -> Vec<AgentAccess> {
        (0..200)
            .map(|index| {
                let access = self.create(index).unwrap();
                self.storage
                    .remove_agent_principal(&access.principal_id, &self.actor, &self.credential)
                    .unwrap();
                access
            })
            .collect()
    }

    fn rotate(&self, principal: &str, index: i64) -> String {
        let hash = token_hash(&format!("rotation-{index}"));
        let pending = self
            .storage
            .stage_pending_agent_principal_rotation(
                principal,
                &hash,
                &expiry(),
                &self.actor,
                &self.credential,
            )
            .unwrap();
        self.storage
            .publish_pending_agent_principal_rotation(&pending, &self.actor, &self.credential)
            .unwrap();
        hash
    }

    fn root(&self, index: i64) -> DriveFile {
        self.storage
            .create_file(
                CreateFileRequest {
                    workspace_id: self.workspace_id.clone(),
                    parent_id: None,
                    name: format!("Folder {index}"),
                    kind: FileKind::Folder,
                    content: None,
                    path: None,
                },
                None,
            )
            .unwrap()
            .0
    }
}

fn expiry() -> String {
    (Utc::now() + Duration::hours(1)).to_rfc3339()
}

fn backup_reference(storage: &Storage, id: &str, source_id: &str) {
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO backup_jobs (id, backup_id, kind, format, status, phase, actor,
            source_credential_kind, source_credential_id, created_at, updated_at)
         VALUES (?1, ?1, 'create', 'v2', 'succeeded', 'complete', 'fixture',
            'delegated_agent', ?2, '2000-01-01T00:00:00Z', '2000-01-01T00:00:00Z')",
            params![id, source_id],
        )
        .unwrap();
}

fn office_reference(fixture: &Fixture, source_id: &str) {
    fixture.storage.conn.lock().unwrap().execute(
        "INSERT INTO office_edit_sessions (id, token_hash, file_id, actor_email, base_revision,
            provider_name, source_credential_kind, source_credential_id, expires_at, used_at, created_at)
         VALUES ('office-reference', 'office-reference-hash', ?1, ?2, 1, 'fixture',
            'delegated_agent', ?3, '2000-01-01T00:00:00Z', '2000-01-01T00:00:00Z', '2000-01-01T00:00:00Z')",
        params![&fixture.root.id, &fixture.actor.email, source_id],
    ).unwrap();
}

fn row_exists(storage: &Storage, table: &str, id: &str) -> bool {
    storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id = ?1)"),
            [id],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn rotations_stop_at_retained_limit_without_revoking_the_live_key() {
    let fixture = Fixture::new();
    let access = fixture.create(0).unwrap();
    let mut current = token_hash("token-0");
    for index in 1..64 {
        current = fixture.rotate(&access.principal_id, index);
    }
    for _ in 0..4 {
        assert!(matches!(
            fixture.storage.stage_pending_agent_principal_rotation(
                &access.principal_id,
                &token_hash("over-limit"),
                &expiry(),
                &fixture.actor,
                &fixture.credential,
            ),
            Err(ApiError::PayloadTooLarge(_))
        ));
    }
    let conn = fixture.storage.conn.lock().unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM agent_tokens", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        64
    );
    drop(conn);
    assert!(fixture
        .storage
        .authenticate_agent_token(&current, Utc::now().timestamp())
        .unwrap()
        .is_some());
}

#[test]
fn pending_rotations_reserve_capacity_and_preserve_the_original_live_key() {
    let fixture = Fixture::new();
    let access = fixture.create(0).unwrap();
    for index in 1..64 {
        fixture
            .storage
            .stage_pending_agent_principal_rotation(
                &access.principal_id,
                &token_hash(&format!("pending-{index}")),
                &expiry(),
                &fixture.actor,
                &fixture.credential,
            )
            .unwrap();
    }
    assert!(matches!(
        fixture.storage.stage_pending_agent_principal_rotation(
            &access.principal_id,
            &token_hash("pending-over-limit"),
            &expiry(),
            &fixture.actor,
            &fixture.credential,
        ),
        Err(ApiError::PayloadTooLarge(_))
    ));
    assert!(fixture
        .storage
        .authenticate_agent_token(&token_hash("token-0"), Utc::now().timestamp())
        .unwrap()
        .is_some());
}

#[test]
fn principal_churn_cannot_reset_retained_capacity_by_replacing_a_session() {
    let mut fixture = Fixture::new();
    fixture.fill_retired_principals();
    let account = fixture
        .storage
        .get_auth_account_secret(&fixture.actor.email)
        .unwrap()
        .unwrap();
    fixture
        .storage
        .record_auth_session(
            "replacement-session",
            &fixture.actor.email,
            "local-password",
            &account.user_id,
            "replacement-session-hash",
            &expiry(),
        )
        .unwrap();
    fixture.credential = DriveCredential::UserSession("replacement-session".to_string());
    for index in 200..204 {
        assert!(matches!(
            fixture.create(index),
            Err(ApiError::PayloadTooLarge(_))
        ));
    }
    let conn = fixture.storage.conn.lock().unwrap();
    for table in ["agent_principals", "agent_tokens", "agent_folder_grants"] {
        assert_eq!(
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            200
        );
    }
}

#[test]
fn active_principal_limit_is_independent_of_retained_history() {
    let fixture = Fixture::new();
    let agents: Vec<_> = (0..50)
        .map(|index| fixture.create(index).unwrap())
        .collect();
    assert!(matches!(
        fixture.create(50),
        Err(ApiError::PayloadTooLarge(_))
    ));
    fixture
        .storage
        .remove_agent_principal(&agents[0].principal_id, &fixture.actor, &fixture.credential)
        .unwrap();
    fixture.create(50).unwrap();
}

#[test]
fn retired_principal_pruning_preserves_all_referenced_or_unsettled_evidence() {
    let fixture = Fixture::new();
    let agents = fixture.fill_retired_principals();
    {
        let conn = fixture.storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE agent_principals SET disabled_at = '2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_tokens SET revoked_at = '2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_folder_grants SET revoked_at = '2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_principals SET publication_pending = 1 WHERE id = ?1",
            [&agents[3].principal_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_tokens SET revoked_at = NULL WHERE id = ?1",
            [&agents[4].token_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE agent_folder_grants SET revoked_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), &agents[5].grant_id],
        )
        .unwrap();
    }
    office_reference(&fixture, &agents[0].token_id);
    backup_reference(&fixture.storage, "grant-reference", &agents[1].grant_id);
    backup_reference(
        &fixture.storage,
        "principal-reference",
        &agents[2].principal_id,
    );
    fixture.create(200).unwrap();
    for agent in &agents[..6] {
        assert!(row_exists(
            &fixture.storage,
            "agent_principals",
            &agent.principal_id
        ));
        assert!(row_exists(
            &fixture.storage,
            "agent_tokens",
            &agent.token_id
        ));
        assert!(row_exists(
            &fixture.storage,
            "agent_folder_grants",
            &agent.grant_id
        ));
    }
    assert!(agents[6..].iter().any(|agent| !row_exists(
        &fixture.storage,
        "agent_principals",
        &agent.principal_id
    )));
}

#[test]
fn retired_token_pruning_keeps_live_pending_and_referenced_tokens() {
    let fixture = Fixture::new();
    let access = fixture.create(0).unwrap();
    let mut current = token_hash("token-0");
    for index in 1..64 {
        current = fixture.rotate(&access.principal_id, index);
    }
    let retired: Vec<String> = {
        let conn = fixture.storage.conn.lock().unwrap();
        conn.execute("UPDATE agent_tokens SET revoked_at = '2000-01-01T00:00:00Z' WHERE revoked_at IS NOT NULL", []).unwrap();
        let mut stmt = conn
            .prepare("SELECT id FROM agent_tokens WHERE revoked_at IS NOT NULL ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        rows
    };
    office_reference(&fixture, &retired[0]);
    backup_reference(&fixture.storage, "token-reference", &retired[1]);
    fixture
        .storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE agent_tokens SET publication_pending = 1 WHERE id = ?1",
            [&retired[2]],
        )
        .unwrap();
    fixture
        .storage
        .stage_pending_agent_principal_rotation(
            &access.principal_id,
            &token_hash("after-safe-prune"),
            &expiry(),
            &fixture.actor,
            &fixture.credential,
        )
        .unwrap();
    for id in &retired[..3] {
        assert!(row_exists(&fixture.storage, "agent_tokens", id));
    }
    assert!(retired[3..]
        .iter()
        .any(|id| !row_exists(&fixture.storage, "agent_tokens", id)));
    assert!(fixture
        .storage
        .authenticate_agent_token(&current, Utc::now().timestamp())
        .unwrap()
        .is_some());
}

#[test]
fn grant_history_is_bounded_and_referenced_regrants_keep_the_original_row() {
    let fixture = Fixture::new();
    let access = fixture.create(0).unwrap();
    for index in 1..64 {
        let root = fixture.root(index);
        let pending = fixture
            .storage
            .grant_pending_agent_access_publication(
                &access.principal_id,
                &fixture.workspace_id,
                &root.id,
                AgentPermission::View,
                &expiry(),
                &fixture.actor,
                &fixture.credential,
            )
            .unwrap();
        fixture
            .storage
            .publish_pending_agent_access(&pending, &fixture.actor, &fixture.credential)
            .unwrap();
    }
    let root = fixture.root(64);
    assert!(matches!(
        fixture.storage.grant_pending_agent_access_publication(
            &access.principal_id,
            &fixture.workspace_id,
            &root.id,
            AgentPermission::View,
            &expiry(),
            &fixture.actor,
            &fixture.credential,
        ),
        Err(ApiError::PayloadTooLarge(_))
    ));
    fixture
        .storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE agent_folder_grants SET revoked_at = '2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
    backup_reference(
        &fixture.storage,
        "retired-grant-reference",
        &access.grant_id,
    );
    let pending = fixture
        .storage
        .grant_pending_agent_access_publication(
            &access.principal_id,
            &fixture.workspace_id,
            &fixture.root.id,
            AgentPermission::View,
            &expiry(),
            &fixture.actor,
            &fixture.credential,
        )
        .unwrap();
    assert_ne!(pending.access.grant_id, access.grant_id);
    fixture
        .storage
        .publish_pending_agent_access(&pending, &fixture.actor, &fixture.credential)
        .unwrap();
    let revoked: String = fixture
        .storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT revoked_at FROM agent_folder_grants WHERE id = ?1",
            [&access.grant_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(revoked, "2000-01-01T00:00:00Z");
    assert!(fixture
        .storage
        .authenticate_agent_token(&token_hash("token-0"), Utc::now().timestamp())
        .unwrap()
        .is_some());
}
