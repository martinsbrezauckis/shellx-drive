use super::super::*;

#[test]
fn expired_grant_is_denied_by_root_reads_without_global_retention_mutation() {
    let (_directory, storage, workspace_id) = storage();
    let shared = create(&storage, &workspace_id, None, "Shared", FileKind::Folder);
    let (grant, _) = storage
        .create_human_item_grant(
            &shared,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (recipient, credential) = session_for_existing_account(&storage, RECIPIENT);
    let root_id = format!("item-grant:{}", grant.id);
    let generation = storage
        .list_sync_roots_for_actor(&recipient)
        .unwrap()
        .into_iter()
        .find(|root| root.id == root_id)
        .unwrap()
        .access_generation;
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE human_item_grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            [&grant.id],
        )
        .unwrap();

    assert!(storage
        .list_sync_roots_for_actor(&recipient)
        .unwrap()
        .iter()
        .all(|root| root.id != root_id));
    assert!(matches!(
        storage.sync_root_manifest(&root_id, &recipient, generation),
        Err(ApiError::NotFound)
    ));
    let (roots, revoked, replacements) = storage
        .revalidate_configured_sync_roots(std::slice::from_ref(&root_id), &recipient, &credential)
        .unwrap();
    assert!(roots.is_empty() && replacements.is_empty());
    assert_eq!(revoked, vec![root_id]);
    let revoked_at: Option<String> = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT revoked_at FROM human_item_grants WHERE id = ?1",
            [&grant.id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(revoked_at.is_none());
}
