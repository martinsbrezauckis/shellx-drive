use super::*;

fn file() -> RemoteFile {
    RemoteFile {
        id: "file-42".to_string(),
        workspace_id: "workspace-1".to_string(),
        parent_id: Some("folder-9".to_string()),
        name: "renamed.pdf".to_string(),
        kind: RemoteFileKind::File,
        revision: 8,
        trashed: false,
        content_hash: Some("same-body".to_string()),
        size_bytes: Some(9),
    }
}

fn source() -> RemoteEntry {
    RemoteEntry {
        id: "file-42".to_string(),
        parent_id: Some("folder-9".to_string()),
        name: "renamed.pdf".to_string(),
        kind: RemoteEntryKind::File,
        revision: 7,
        content_hash: Some("same-body".to_string()),
        size_bytes: Some(9),
        trashed: false,
    }
}

#[test]
fn move_response_requires_exact_identity_revision_and_destination() {
    let moved = file();
    assert!(remote_move_response_matches(
        &moved,
        "file-42",
        "workspace-1",
        7,
        Some("folder-9"),
        "renamed.pdf"
    ));
    assert!(!remote_move_response_matches(
        &moved,
        "other",
        "workspace-1",
        7,
        Some("folder-9"),
        "renamed.pdf"
    ));
}

#[test]
fn created_response_rejects_a_cross_workspace_or_stale_envelope() {
    let mut created = file();
    created.revision = 1;
    assert!(created_remote_response_matches(
        &created,
        "workspace-1",
        Some("folder-9"),
        "renamed.pdf",
        RemoteFileKind::File,
        Some("same-body")
    ));
    created.workspace_id = "other".to_string();
    assert!(!created_remote_response_matches(
        &created,
        "workspace-1",
        Some("folder-9"),
        "renamed.pdf",
        RemoteFileKind::File,
        Some("same-body")
    ));
}

#[test]
fn content_and_trash_mutations_bind_the_prior_object_and_next_revision() {
    let current = source();
    let updated = file();
    assert!(updated_remote_response_matches(
        &updated,
        "file-42",
        "workspace-1",
        7,
        &current,
        Some("same-body"),
        9
    ));
    let mut trashed = updated.clone();
    trashed.trashed = true;
    assert!(trashed_remote_response_matches(
        &trashed,
        "file-42",
        "workspace-1",
        7,
        &current
    ));
    assert!(restored_remote_response_matches(
        &updated,
        "file-42",
        "workspace-1",
        7,
        &current
    ));
    let mut stale = updated;
    stale.revision = 7;
    assert!(!updated_remote_response_matches(
        &stale,
        "file-42",
        "workspace-1",
        7,
        &current,
        Some("same-body"),
        9
    ));
}

#[test]
fn content_replacement_binds_changed_body_and_size_to_the_same_item() {
    let current = source();
    let mut updated = file();
    updated.content_hash = Some("new-longer-body".to_string());
    updated.size_bytes = Some(15);
    assert!(updated_remote_response_matches(
        &updated,
        "file-42",
        "workspace-1",
        7,
        &current,
        Some("new-longer-body"),
        15
    ));
}

#[test]
fn content_replacement_rejects_wrong_body_size_or_response_identity() {
    let current = source();
    let mut valid = file();
    valid.content_hash = Some("new-longer-body".to_string());
    valid.size_bytes = Some(15);
    let matches = |response: &RemoteFile| {
        updated_remote_response_matches(
            response,
            "file-42",
            "workspace-1",
            7,
            &current,
            Some("new-longer-body"),
            15,
        )
    };
    assert!(matches(&valid));
    let mut wrong = valid.clone();
    wrong.content_hash = current.content_hash.clone();
    assert!(!matches(&wrong));
    wrong.content_hash = None;
    assert!(!matches(&wrong));
    wrong = valid.clone();
    wrong.size_bytes = Some(9);
    assert!(!matches(&wrong));
    wrong.size_bytes = None;
    assert!(!matches(&wrong));
    wrong.size_bytes = Some(-1);
    assert!(!matches(&wrong));
    wrong = valid.clone();
    wrong.revision = 7;
    assert!(!matches(&wrong));
    wrong.revision = 9;
    assert!(!matches(&wrong));
    wrong = valid.clone();
    wrong.parent_id = Some("other-parent".to_string());
    assert!(!matches(&wrong));
    wrong = valid.clone();
    wrong.name = "other-name.txt".to_string();
    assert!(!matches(&wrong));
    wrong = valid.clone();
    wrong.id = "other-file".to_string();
    assert!(!matches(&wrong));
    wrong = valid.clone();
    wrong.workspace_id = "other-workspace".to_string();
    assert!(!matches(&wrong));
    wrong = valid.clone();
    wrong.kind = RemoteFileKind::Folder;
    assert!(!matches(&wrong));
    wrong = valid.clone();
    wrong.trashed = true;
    assert!(!matches(&wrong));
    assert!(!updated_remote_response_matches(
        &valid,
        "file-42",
        "workspace-1",
        7,
        &current,
        None,
        15
    ));
    assert!(!updated_remote_response_matches(
        &valid,
        "file-42",
        "workspace-1",
        7,
        &current,
        Some("new-longer-body"),
        u64::MAX
    ));
    wrong = valid;
    wrong.size_bytes = None;
    assert!(!updated_remote_response_matches(
        &wrong,
        "file-42",
        "workspace-1",
        7,
        &current,
        Some("new-longer-body"),
        u64::MAX
    ));
}

#[test]
fn trash_and_restore_responses_preserve_the_prior_content_metadata() {
    let current = source();
    let restored = file();
    let mut trashed = restored.clone();
    trashed.trashed = true;
    assert!(trashed_remote_response_matches(
        &trashed,
        "file-42",
        "workspace-1",
        7,
        &current
    ));
    assert!(restored_remote_response_matches(
        &restored,
        "file-42",
        "workspace-1",
        7,
        &current
    ));
    for mutate_body in [true, false] {
        let mut changed_trash = trashed.clone();
        let mut changed_restore = restored.clone();
        if mutate_body {
            changed_trash.content_hash = Some("unexpected-body".to_string());
            changed_restore.content_hash = Some("unexpected-body".to_string());
        } else {
            changed_trash.size_bytes = Some(15);
            changed_restore.size_bytes = Some(15);
        }
        assert!(!trashed_remote_response_matches(
            &changed_trash,
            "file-42",
            "workspace-1",
            7,
            &current
        ));
        assert!(!restored_remote_response_matches(
            &changed_restore,
            "file-42",
            "workspace-1",
            7,
            &current
        ));
    }
}

#[test]
fn trash_and_restore_sizes_require_lossless_exact_optional_binding() {
    let cases = [
        (Some(9_i64), Some(9_u64), true),
        (Some(15), Some(9), false),
        (None, Some(9), false),
        (Some(9), None, false),
        (Some(-1), Some(9), false),
        (Some(-1), None, false),
        (Some(i64::MAX), Some(i64::MAX as u64), true),
        (Some(i64::MAX), Some(u64::MAX), false),
        (None, Some(u64::MAX), false),
        (None, None, true),
    ];
    for (actual_size, expected_size, accepted) in cases {
        let mut current = source();
        current.size_bytes = expected_size;
        let mut response = file();
        response.size_bytes = actual_size;
        if expected_size.is_none() {
            current.kind = RemoteEntryKind::Folder;
            current.content_hash = None;
            response.kind = RemoteFileKind::Folder;
            response.content_hash = None;
        }
        response.trashed = true;
        assert_eq!(
            trashed_remote_response_matches(&response, "file-42", "workspace-1", 7, &current),
            accepted,
            "trash size binding: {actual_size:?} against {expected_size:?}"
        );
        response.trashed = false;
        assert_eq!(
            restored_remote_response_matches(&response, "file-42", "workspace-1", 7, &current),
            accepted,
            "restore size binding: {actual_size:?} against {expected_size:?}"
        );
    }
}
