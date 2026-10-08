use std::collections::HashSet;

use super::*;

#[test]
fn sharing_cursor_does_not_expose_roots_after_membership_expiry() {
    let (_directory, storage, workspace_id) = storage();
    let recipient = storage.get_auth_account_secret(RECIPIENT).unwrap().unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO workspace_members (workspace_id, user_id, role, expires_at)
         VALUES (?1, ?2, 'viewer', '2000-01-01T00:00:00Z')",
            rusqlite::params![&workspace_id, recipient.user_id],
        )
        .unwrap();
    // All three roots are created after access expired. Only A and C are
    // subsequently shared through current item grants.
    let mut ids = Vec::new();
    for name in ["A-visible", "B-confidential-after-expiry", "C-visible"] {
        ids.push(create(
            &storage,
            &workspace_id,
            None,
            name,
            FileKind::Folder,
        ));
    }
    for id in [&ids[0], &ids[2]] {
        storage
            .create_human_item_grant(
                id,
                &human_grant("account", Some(RECIPIENT), "viewer"),
                &operator(),
                &DriveCredential::Operator,
            )
            .unwrap();
    }
    let recipient = human(RECIPIENT);
    let (first, cursor) = storage
        .list_shared_item_roots_page_for_actor(&recipient, 1, None)
        .unwrap();
    assert_eq!(first[0].file.id, ids[0]);
    assert_eq!(cursor, Some(("A-visible".into(), ids[0].clone())));
    let (second, terminal) = storage
        .list_shared_item_roots_page_for_actor(&recipient, 1, cursor.as_ref())
        .unwrap();
    assert_eq!(second[0].file.id, ids[2]);
    assert!(terminal.is_none());
}

#[test]
fn both_sharing_lists_page_past_one_hundred_roots_without_duplicates() {
    let (_directory, storage, workspace_id) = storage();
    let mut expected = HashSet::new();
    let mut revocable_grant_id = None;
    let mut revocable_file_id = None;
    for number in 0..102 {
        let file_id = create(
            &storage,
            &workspace_id,
            None,
            &format!("share-{number:03}"),
            FileKind::Folder,
        );
        let (grant, _) = storage
            .create_human_item_grant(
                &file_id,
                &human_grant("account", Some(RECIPIENT), "viewer"),
                &operator(),
                &DriveCredential::Operator,
            )
            .unwrap();
        if number == 101 {
            revocable_grant_id = Some(grant.id);
            revocable_file_id = Some(file_id.clone());
        }
        expected.insert(file_id);
    }

    let recipient = human(RECIPIENT);
    let mut cursor = None;
    let mut received = HashSet::new();
    loop {
        let (roots, next) = storage
            .list_shared_item_roots_page_for_actor(&recipient, 37, cursor.as_ref())
            .unwrap();
        assert!(roots.len() <= 37);
        for root in roots {
            assert!(received.insert(root.file.id));
        }
        cursor = next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(received, expected);

    let owner = human(OWNER);
    let mut cursor = None;
    let mut owned = HashSet::new();
    loop {
        let (roots, next) = storage
            .list_shared_by_me_page_for_actor(&owner, 37, cursor.as_ref())
            .unwrap();
        assert!(roots.len() <= 37);
        for root in roots {
            assert!(owned.insert(root.file.id));
        }
        cursor = next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(owned, expected);

    let (first_page, cursor) = storage
        .list_shared_item_roots_page_for_actor(&recipient, 100, None)
        .unwrap();
    assert_eq!(first_page.len(), 100);
    storage
        .revoke_human_item_grant(
            &revocable_grant_id.unwrap(),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let removed = revocable_file_id.unwrap();
    let (last_page, final_cursor) = storage
        .list_shared_item_roots_page_for_actor(&recipient, 100, cursor.as_ref())
        .unwrap();
    assert_eq!(last_page.len(), 1);
    assert!(final_cursor.is_none());
    assert!(!last_page.iter().any(|root| root.file.id == removed));
}

#[test]
fn sharing_cursor_does_not_expose_roots_outside_actor_scope() {
    let (_directory, storage, workspace_id) = storage();
    let (excluded, _, _) = storage.create_workspace("Excluded", OWNER).unwrap();
    let mut ids = Vec::new();
    for (name, workspace) in [
        ("A-visible", &workspace_id),
        ("B-outside-credential-scope", &excluded.id),
        ("C-visible", &workspace_id),
    ] {
        let id = create(&storage, workspace, None, name, FileKind::Folder);
        storage
            .create_human_item_grant(
                &id,
                &human_grant("account", Some(RECIPIENT), "viewer"),
                &operator(),
                &DriveCredential::Operator,
            )
            .unwrap();
        ids.push(id);
    }
    let mut recipient = human(RECIPIENT);
    recipient.allowed_workspace_ids = Some(HashSet::from([workspace_id]));
    let (first, cursor) = storage
        .list_shared_item_roots_page_for_actor(&recipient, 1, None)
        .unwrap();
    assert_eq!(first[0].file.id, ids[0]);
    assert_eq!(cursor, Some(("A-visible".into(), ids[0].clone())));
    let (second, terminal) = storage
        .list_shared_item_roots_page_for_actor(&recipient, 1, cursor.as_ref())
        .unwrap();
    assert_eq!(second[0].file.id, ids[2]);
    assert!(terminal.is_none());
}
