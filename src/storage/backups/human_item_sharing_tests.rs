use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::{
    auth::{Actor, AuthMode, DriveCredential, WorkspacePermission},
    error::ApiError,
    model::{CreateFileRequest, CreateHumanItemGrantRequest, FileKind},
};

mod restore_validation;

const OWNER: &str = "backup-owner@example.test";
const RECIPIENT: &str = "backup-recipient@example.test";
pub(super) fn operator() -> Actor {
    Actor {
        email: "system@local".to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    }
}

pub(super) fn recipient() -> Actor {
    Actor {
        email: RECIPIENT.to_string(),
        is_admin: false,
        auth_mode: AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    }
}

pub(super) fn grant(kind: &str, principal_ref: Option<&str>) -> CreateHumanItemGrantRequest {
    CreateHumanItemGrantRequest {
        principal_kind: kind.to_string(),
        principal_ref: principal_ref.map(str::to_string),
        role: "viewer".to_string(),
        expires_at: None,
    }
}

fn enable_everyone_grants(storage: &Storage) {
    storage
        .update_everyone_grant_policy_authorized(
            crate::model::UpdateEveryoneGrantPolicyRequest {
                everyone_grants_enabled: true,
            },
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
}

pub(super) fn create(
    storage: &Storage,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
) -> String {
    create_kind(storage, workspace_id, parent_id, name, FileKind::File)
}

fn create_kind(
    storage: &Storage,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
    kind: FileKind,
) -> String {
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: parent_id.map(str::to_string),
                name: name.to_string(),
                kind,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0
        .id
}

pub(super) fn table<'a>(tables: &'a [BackupTable], name: &str) -> &'a BackupTable {
    tables.iter().find(|table| table.name == name).unwrap()
}

pub(super) fn storage() -> (TempDir, Storage, String) {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (owner, _) = storage
        .bootstrap_auth_account(OWNER, "owner-password")
        .unwrap();
    storage
        .create_auth_account(
            RECIPIENT,
            "recipient-password",
            false,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    (directory, storage, format!("private-v1:{}", owner.user_id))
}

pub(super) fn access_generation(storage: &Storage) -> i64 {
    storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT generation FROM human_item_access_generation WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

pub(super) fn private_mappings(storage: &Storage) -> Vec<(String, String)> {
    let conn = storage.conn.lock().unwrap();
    let mut statement = conn
        .prepare("SELECT user_id, workspace_id FROM account_private_workspaces ORDER BY user_id")
        .unwrap();
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap();
    rows.collect::<Result<Vec<_>, _>>().unwrap()
}

pub(super) fn assert_private_workspace_invariant(storage: &Storage) {
    let invalid: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM auth_accounts account
         WHERE NOT EXISTS (
           SELECT 1 FROM account_private_workspaces private
           JOIN workspace_members member
             ON member.workspace_id = private.workspace_id
            AND member.user_id = private.user_id AND member.role = 'owner'
           WHERE private.user_id = account.user_id
         )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(invalid, 0);
}

#[test]
fn legacy_restore_keeps_live_grant_authority_and_advances_the_epoch() {
    let (_directory, storage, workspace_id) = storage();
    let archived_root = create(&storage, &workspace_id, None, "Archived grant root");
    let current_root = create(&storage, &workspace_id, None, "Current grant root");
    let missing_account_root = create(&storage, &workspace_id, None, "Missing account root");
    let missing_group_root = create(&storage, &workspace_id, None, "Missing group root");
    let (archived_grant, _) = storage
        .create_human_item_grant(
            &archived_root,
            &grant("account", Some(RECIPIENT)),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let archived = storage.export_backup_tables().unwrap();

    storage
        .revoke_human_item_grant(&archived_grant.id, &operator(), &DriveCredential::Operator)
        .unwrap();
    let (current_grant, _) = storage
        .create_human_item_grant(
            &current_root,
            &grant("account", Some(RECIPIENT)),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "INSERT INTO human_item_grants
           (id, workspace_id, root_file_id, principal_kind, principal_ref, role,
            created_by, created_at, updated_at)
         VALUES
           ('missing-account-grant', ?1, ?2, 'account', 'missing-account', 'viewer',
            'system@local', '2026-09-03T00:00:00Z', '2026-09-03T00:00:00Z'),
           ('missing-group-grant', ?1, ?3, 'group', 'missing-group', 'viewer',
            'system@local', '2026-09-03T00:00:00Z', '2026-09-03T00:00:00Z')",
        rusqlite::params![&workspace_id, &missing_account_root, &missing_group_root],
    )
    .unwrap();
    drop(conn);
    let live_generation = access_generation(&storage);
    let live_mappings = private_mappings(&storage);

    storage.restore_backup_tables(&archived).unwrap();
    assert_eq!(access_generation(&storage), live_generation + 1);
    assert_eq!(private_mappings(&storage), live_mappings);
    assert_private_workspace_invariant(&storage);
    let grants = storage.export_backup_tables().unwrap();
    let rows = &table(&grants, "human_item_grants").rows;
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .any(|row| row[0] == json!(archived_grant.id) && !row[10].is_null()));
    assert!(rows
        .iter()
        .any(|row| row[0] == json!(current_grant.id) && row[10].is_null()));
    assert!(matches!(
        storage.ensure_item_permission(&archived_root, &recipient(), WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));
    assert!(storage
        .ensure_item_permission(&current_root, &recipient(), WorkspacePermission::Read)
        .is_ok());
}

#[test]
fn legacy_restore_on_fresh_target_keeps_target_accounts_private_and_unshared() {
    let (_source_root, source, source_workspace) = storage();
    let archived_root = create(&source, &source_workspace, None, "Archived account grant");
    source
        .create_human_item_grant(
            &archived_root,
            &grant("account", Some(RECIPIENT)),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let archived = source.export_backup_tables().unwrap();
    let (_target_root, target, _) = storage();
    let expected_mappings = private_mappings(&target);

    target.restore_backup_tables(&archived).unwrap();

    assert_eq!(private_mappings(&target), expected_mappings);
    assert_private_workspace_invariant(&target);
    assert!(
        table(&target.export_backup_tables().unwrap(), "human_item_grants")
            .rows
            .is_empty()
    );
    assert!(matches!(
        target.ensure_item_permission(&archived_root, &recipient(), WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn legacy_restore_accepts_only_the_complete_pre_item_sharing_table_pair_omission() {
    let (_directory, storage, _workspace_id) = storage();
    let current = storage.export_backup_tables().unwrap();
    let mut historical = current.clone();
    historical.retain(|table| {
        !crate::backup_schema_compatibility::HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES
            .contains(&table.name.as_str())
    });
    storage.validate_backup_tables(&historical).unwrap();
    let live_generation = access_generation(&storage);
    storage.restore_backup_tables(&historical).unwrap();
    assert_eq!(access_generation(&storage), live_generation + 1);

    let mut truncated = historical;
    truncated.push(table(&current, "human_item_grants").clone());
    assert!(storage.validate_backup_tables(&truncated).is_err());
}
