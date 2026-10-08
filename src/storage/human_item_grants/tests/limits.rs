use rusqlite::{params, Transaction};

use super::*;
use crate::storage::human_item_grants::retention::{
    MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_PRINCIPAL, MAX_RETAINED_HUMAN_ITEM_GRANTS_PER_WORKSPACE,
};

pub(super) const SEEDED_AT: &str = "2025-01-01T00:00:00Z";

pub(super) fn insert_file(tx: &Transaction<'_>, workspace_id: &str, id: &str) {
    tx.execute(
        "INSERT INTO files (
             id, workspace_id, parent_id, name, kind, revision, trashed,
             starred, content_hash, content_bytes, created_at, updated_at
         ) VALUES (?1, ?2, NULL, ?1, 'file', 1, 0, 0, NULL, 0, ?3, ?3)",
        params![id, workspace_id, SEEDED_AT],
    )
    .unwrap();
}

pub(super) fn insert_grant(
    tx: &Transaction<'_>,
    id: &str,
    workspace_id: &str,
    root_file_id: &str,
    principal_ref: &str,
    revoked_at: Option<&str>,
) {
    tx.execute(
        "INSERT INTO human_item_grants (
             id, workspace_id, root_file_id, principal_kind, principal_ref,
             role, created_by, created_at, updated_at, expires_at, revoked_at,
             publication_pending
         ) VALUES (?1, ?2, ?3, 'account', ?4, 'viewer', ?5, ?6, ?6, NULL, ?7, 0)",
        params![
            id,
            workspace_id,
            root_file_id,
            principal_ref,
            OWNER,
            SEEDED_AT,
            revoked_at
        ],
    )
    .unwrap();
}

#[test]
fn principal_cap_allows_replacement_and_legacy_sync_discovery_is_complete() {
    let (_directory, storage, workspace_id) = storage();
    let recipient_id = storage
        .get_auth_account(RECIPIENT)
        .unwrap()
        .unwrap()
        .user_id;
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for index in 0..MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_PRINCIPAL {
            let file_id = format!("bounded-root-{index:04}");
            insert_file(&tx, &workspace_id, &file_id);
            insert_grant(
                &tx,
                &format!("bounded-grant-{index:04}"),
                &workspace_id,
                &file_id,
                &recipient_id,
                None,
            );
        }
        insert_file(&tx, &workspace_id, "bounded-root-overflow");
        tx.commit().unwrap();
    }

    let request = human_grant("account", Some(RECIPIENT), "viewer");
    assert!(matches!(
        storage.create_human_item_grant(
            "bounded-root-overflow",
            &request,
            &operator(),
            &DriveCredential::Operator,
        ),
        Err(ApiError::PayloadTooLarge(_))
    ));
    storage
        .create_human_item_grant(
            "bounded-root-0000",
            &request,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();

    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        insert_grant(
            &tx,
            "legacy-over-cap-grant",
            &workspace_id,
            "bounded-root-overflow",
            &recipient_id,
            None,
        );
        tx.commit().unwrap();
    }
    let item_roots = storage
        .list_sync_roots_for_actor(&human(RECIPIENT))
        .unwrap()
        .into_iter()
        .filter(|root| root.kind == "item_grant")
        .count();
    assert_eq!(item_roots, 1_001);
}

#[test]
fn revocation_prunes_only_old_terminal_history() {
    let (_directory, storage, workspace_id) = storage();
    let recipient_id = storage
        .get_auth_account(RECIPIENT)
        .unwrap()
        .unwrap()
        .user_id;
    let root = create(
        &storage,
        &workspace_id,
        None,
        "retention-root",
        FileKind::File,
    );
    let (current, _) = storage
        .create_human_item_grant(
            &root,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for index in 0..=MAX_RETAINED_HUMAN_ITEM_GRANTS_PER_WORKSPACE {
            insert_grant(
                &tx,
                &format!("history-{index:04}"),
                &workspace_id,
                &root,
                &recipient_id,
                Some(SEEDED_AT),
            );
        }
        tx.commit().unwrap();
    }

    storage
        .revoke_human_item_grant(&current.id, &operator(), &DriveCredential::Operator)
        .unwrap();
    let conn = storage.conn.lock().unwrap();
    let retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM human_item_grants
             WHERE workspace_id = ?1 AND revoked_at IS NOT NULL",
            [&workspace_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, MAX_RETAINED_HUMAN_ITEM_GRANTS_PER_WORKSPACE);
    let current_retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM human_item_grants WHERE id = ?1",
            [&current.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(current_retained, 1);
}
