use std::collections::BTreeSet;

use super::*;

fn ids(files: &[crate::model::DriveFile]) -> BTreeSet<String> {
    files.iter().map(|file| file.id.clone()).collect()
}

fn search_ids(storage: &Storage, actor: &Actor, query: &str) -> BTreeSet<String> {
    storage
        .search_file_results_for_actor(actor, query)
        .unwrap()
        .into_iter()
        .map(|result| result.file.id)
        .collect()
}

#[test]
fn item_grants_scope_search_recent_starred_and_activity_to_one_closure() {
    let (_directory, storage, workspace_id) = storage();
    let parent = create(
        &storage,
        &workspace_id,
        None,
        "scope-parent-hidden",
        FileKind::Folder,
    );
    let root = create(
        &storage,
        &workspace_id,
        Some(&parent),
        "scope-root-visible",
        FileKind::Folder,
    );
    let child = create(
        &storage,
        &workspace_id,
        Some(&root),
        "scope-child-visible",
        FileKind::File,
    );
    let sibling = create(
        &storage,
        &workspace_id,
        Some(&parent),
        "scope-sibling-hidden",
        FileKind::File,
    );
    let outside = create(
        &storage,
        &workspace_id,
        None,
        "scope-outside-hidden",
        FileKind::File,
    );
    for file_id in [&parent, &root, &child, &sibling, &outside] {
        storage.set_starred(file_id, true).unwrap();
    }
    let (grant, _) = storage
        .create_human_item_grant(
            &root,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (recipient, credential) = session_for_existing_account(&storage, RECIPIENT);
    let expected = BTreeSet::from([root.clone(), child.clone()]);

    assert_eq!(search_ids(&storage, &recipient, "scope"), expected);
    assert_eq!(
        ids(&storage.recent_files_for_actor(&recipient).unwrap()),
        expected
    );
    assert_eq!(
        ids(&storage.starred_files_for_actor(&recipient).unwrap()),
        expected
    );
    storage
        .set_mobile_offline_file(&recipient, &credential, &workspace_id, &child, true)
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO mobile_offline_files (actor_email, workspace_id, file_id, marked_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                RECIPIENT,
                &workspace_id,
                &sibling,
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .unwrap();
    assert_eq!(
        storage
            .list_mobile_offline_files_for_actor(&recipient)
            .unwrap()
            .into_iter()
            .map(|file| file.file_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([child.clone()]),
        "a stale mark must not turn a sibling into mobile-readable data"
    );

    let activity = storage.list_activity_for_actor(&recipient).unwrap();
    assert!(!activity.is_empty());
    assert!(activity.iter().all(|entry| {
        entry
            .target_id
            .as_ref()
            .is_some_and(|target_id| expected.contains(target_id))
    }));
    assert!(activity
        .iter()
        .any(|entry| entry.target_id.as_deref() == Some(root.as_str())));
    assert!(activity
        .iter()
        .any(|entry| entry.target_id.as_deref() == Some(child.as_str())));

    storage
        .revoke_human_item_grant(&grant.id, &operator(), &DriveCredential::Operator)
        .unwrap();
    assert!(search_ids(&storage, &recipient, "scope").is_empty());
    assert!(storage
        .list_mobile_offline_files_for_actor(&recipient)
        .unwrap()
        .is_empty());
}

#[test]
fn group_and_everyone_grants_deduplicate_and_change_role_or_revoke_immediately() {
    let (_directory, storage, workspace_id) = storage();
    let root = create(
        &storage,
        &workspace_id,
        None,
        "multi-grant-visible",
        FileKind::Folder,
    );
    let child = create(
        &storage,
        &workspace_id,
        Some(&root),
        "multi-grant-child",
        FileKind::File,
    );
    let (group, _) = storage
        .create_group_authorized(
            "Multi grant reviewers",
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    storage
        .upsert_group_member_authorized(
            &group.id,
            RECIPIENT,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (account_grant, _) = storage
        .create_human_item_grant(
            &root,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (group_grant, _) = storage
        .create_human_item_grant(
            &root,
            &human_grant("group", Some(&group.id), "editor"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    storage
        .update_everyone_grant_policy_authorized(
            crate::model::UpdateEveryoneGrantPolicyRequest {
                everyone_grants_enabled: true,
            },
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (everyone_grant, _) = storage
        .create_human_item_grant(
            &root,
            &human_grant("everyone", None, "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (recipient, credential) = session_for_existing_account(&storage, RECIPIENT);
    let expected = BTreeSet::from([root.clone(), child.clone()]);

    for file_id in [&root, &child] {
        storage.set_starred(file_id, true).unwrap();
    }
    assert_eq!(search_ids(&storage, &recipient, "multi-grant"), expected);
    assert_eq!(
        storage
            .search_file_results_for_actor(&recipient, "multi-grant")
            .unwrap()
            .len(),
        2,
        "multiple principal grants must still produce one canonical file row"
    );
    assert_eq!(
        ids(&storage.recent_files_for_actor(&recipient).unwrap()),
        expected
    );
    assert_eq!(
        ids(&storage.starred_files_for_actor(&recipient).unwrap()),
        expected
    );
    assert!(storage
        .list_activity_for_actor(&recipient)
        .unwrap()
        .iter()
        .all(|entry| {
            entry
                .target_id
                .as_ref()
                .is_some_and(|target_id| expected.contains(target_id))
        }));
    storage
        .set_mobile_offline_file(&recipient, &credential, &workspace_id, &child, true)
        .unwrap();
    assert_eq!(
        storage
            .list_mobile_offline_files_for_actor(&recipient)
            .unwrap()
            .into_iter()
            .map(|file| file.file_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([child.clone()])
    );
    assert_eq!(
        storage
            .ensure_item_permission(&child, &recipient, WorkspacePermission::Write)
            .unwrap()
            .role,
        "editor"
    );

    storage
        .update_human_item_grant(
            &group_grant.id,
            Some("viewer"),
            None,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    assert_eq!(
        storage
            .ensure_item_permission(&child, &recipient, WorkspacePermission::Read)
            .unwrap()
            .role,
        "viewer"
    );
    assert!(matches!(
        storage.ensure_item_permission(&child, &recipient, WorkspacePermission::Write),
        Err(ApiError::Forbidden)
    ));
    assert_eq!(search_ids(&storage, &recipient, "multi-grant"), expected);

    for grant_id in [&account_grant.id, &group_grant.id, &everyone_grant.id] {
        storage
            .revoke_human_item_grant(grant_id, &operator(), &DriveCredential::Operator)
            .unwrap();
    }
    assert!(search_ids(&storage, &recipient, "multi-grant").is_empty());
    assert!(storage
        .recent_files_for_actor(&recipient)
        .unwrap()
        .is_empty());
    assert!(storage
        .starred_files_for_actor(&recipient)
        .unwrap()
        .is_empty());
    assert!(storage
        .list_activity_for_actor(&recipient)
        .unwrap()
        .is_empty());
    assert!(storage
        .list_mobile_offline_files_for_actor(&recipient)
        .unwrap()
        .is_empty());
}
