use crate::storage::ShareCreateFields;

use super::*;

#[test]
fn shared_by_me_retires_expired_human_grants_before_constructing_roots() {
    let (_directory, storage, workspace_id) = storage();
    let file_id = create(
        &storage,
        &workspace_id,
        None,
        "expired-human-share",
        FileKind::File,
    );
    let (grant, _) = storage
        .create_human_item_grant(
            &file_id,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let expired_at = (Utc::now() - Duration::hours(1)).to_rfc3339();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE human_item_grants SET expires_at = ?1 WHERE id = ?2",
            rusqlite::params![&expired_at, &grant.id],
        )
        .unwrap();

    let roots = storage
        .list_shared_by_me_for_actor(&human(OWNER), 100)
        .unwrap();
    assert!(roots.is_empty(), "expired grants must not be published");
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
    assert_eq!(revoked_at.as_deref(), Some(expired_at.as_str()));
}

#[test]
fn shared_by_me_unifies_guest_only_and_human_guest_roots_without_capabilities() {
    let (_directory, storage, workspace_id) = storage();
    let guest_only = create(
        &storage,
        &workspace_id,
        None,
        "guest-only-share",
        FileKind::File,
    );
    let shared_both = create(
        &storage,
        &workspace_id,
        None,
        "human-and-guest-share",
        FileKind::File,
    );
    let (owner, credential) = session_for_existing_account(&storage, OWNER);
    let (guest_only_share, _) = storage
        .create_share(
            ShareCreateFields {
                file_id: &guest_only,
                password_hash: "guest-only-password-hash",
                password_required: true,
                expires_in_seconds: 3_600,
                target_kind: "file",
                allow_download: false,
                recipient_note: Some("private note"),
                max_uses: Some(3),
            },
            &owner,
            &credential,
        )
        .unwrap();
    storage
        .create_share(
            ShareCreateFields {
                file_id: &shared_both,
                password_hash: "human-and-guest-password-hash",
                password_required: true,
                expires_in_seconds: 3_600,
                target_kind: "file",
                allow_download: true,
                recipient_note: Some("private note"),
                max_uses: Some(2),
            },
            &owner,
            &credential,
        )
        .unwrap();
    storage
        .create_human_item_grant(
            &shared_both,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();

    let roots = storage.list_shared_by_me_for_actor(&owner, 100).unwrap();
    assert_eq!(roots.len(), 2, "one canonical row per owned file");
    let guest_only_root = roots
        .iter()
        .find(|root| root.file.id == guest_only)
        .unwrap();
    assert!(guest_only_root.grants.is_empty());
    assert_eq!(guest_only_root.guest_links.len(), 1);
    assert_eq!(guest_only_root.guest_links[0].kind, "file");
    assert_eq!(guest_only_root.guest_links[0].uses_remaining, Some(3));
    assert!(!guest_only_root.guest_links[0].allow_download);
    let shared_both_root = roots
        .iter()
        .find(|root| root.file.id == shared_both)
        .unwrap();
    assert_eq!(shared_both_root.grants.len(), 1);
    assert_eq!(shared_both_root.guest_links.len(), 1);
    assert!(shared_both_root.guest_links[0].allow_download);

    let serialized = serde_json::to_string(&roots).unwrap();
    assert!(!serialized.contains(&guest_only_share.id));
    assert!(!serialized.contains("password-hash"));
    assert!(!serialized.contains("private note"));
}
