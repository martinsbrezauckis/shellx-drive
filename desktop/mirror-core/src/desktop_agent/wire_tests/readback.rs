use crate::{
    DesktopAgentCommand, DesktopAgentCommandKind, DesktopAgentDesktopViewPageRequest,
    DesktopAgentDesktopViewSection, DesktopAgentRootsPageRequest,
};

#[test]
fn native_planner_review_ids_roundtrip_through_commands_results_and_nested_cursors() {
    use crate::{
        plan_reconciliation, BaselineEntry, DesktopAgentDesktopViewPage,
        DesktopAgentObservedStatus, DesktopAgentResultCode, DesktopAgentResultPayload,
        DesktopAgentReviewRow, LocalEntry, RemoteEntry, RemoteEntryKind, ReviewAction,
    };
    use std::{collections::BTreeMap, path::PathBuf};

    let path = PathBuf::from("nested").join("file name.txt");
    let baseline = BTreeMap::from([(
        "file".to_string(),
        BaselineEntry {
            remote_id: "file".to_string(),
            parent_id: Some("folder".to_string()),
            relative_path: path.clone(),
            kind: "file".to_string(),
            content_hash: Some("unchanged".to_string()),
            revision: 1,
            directory_identity: None,
        },
    )]);
    let remote = [
        RemoteEntry {
            id: "folder".to_string(),
            parent_id: None,
            name: "nested".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 1,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
        RemoteEntry {
            id: "file".to_string(),
            parent_id: Some("folder".to_string()),
            name: "file name.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("unchanged".to_string()),
            size_bytes: Some(1),
            trashed: false,
        },
    ];
    let local = [LocalEntry {
        relative_path: PathBuf::from("nested"),
        content_hash: None,
        size_bytes: 0,
        is_directory: true,
        directory_identity: None,
    }];
    let plan = plan_reconciliation(&baseline, None, &remote, &local, chrono::Utc::now()).unwrap();
    let review = plan
        .reviews
        .iter()
        .find(|item| item.relative_path == path)
        .unwrap();
    assert_eq!(review.id, format!("LocalDeletion:{}", path.display()));

    for review_id in [
        review.id.as_str(),
        "LocalDeletion:file.txt",
        "LocalDeletion:nested/file name.txt",
        "LocalDeletion:répertoire/文.txt",
    ] {
        let prepare = super::claim(
            DesktopAgentCommandKind::PrepareReviewAction,
            serde_json::json!({
                "pair_id": "pair_1", "review_id": review_id, "action": "restore_local_copy"
            }),
        )
        .parse_command()
        .unwrap();
        assert_eq!(
            prepare,
            DesktopAgentCommand::PrepareReviewAction {
                pair_id: "pair_1".to_string(),
                review_id: review_id.to_string(),
                action: ReviewAction::RestoreLocalCopy,
            }
        );
        let confirm = super::claim(
            DesktopAgentCommandKind::ConfirmReviewAction,
            serde_json::json!({
                "pair_id": "pair_1", "review_id": review_id, "action": "restore_local_copy",
                "prepared_confirmation_id": "confirm_1", "fingerprint": "a".repeat(64)
            }),
        )
        .parse_command()
        .unwrap();
        assert!(
            matches!(confirm, DesktopAgentCommand::ConfirmReviewAction { review_id: id, .. } if id == review_id)
        );
        DesktopAgentResultPayload::ReviewPrepared {
            pair_id: "pair_1".to_string(),
            review_id: review_id.to_string(),
            action: ReviewAction::RestoreLocalCopy,
            prepared_confirmation_id: "confirm_1".to_string(),
            fingerprint: "a".repeat(64),
        }
        .validate_for(
            DesktopAgentCommandKind::PrepareReviewAction,
            DesktopAgentResultCode::ReviewPrepared,
        )
        .unwrap();
        DesktopAgentResultPayload::ReviewConfirmed {
            pair_id: "pair_1".to_string(),
            review_id: review_id.to_string(),
            action: ReviewAction::RestoreLocalCopy,
            prepared_confirmation_id: "confirm_1".to_string(),
            fingerprint: "a".repeat(64),
        }
        .validate_for(
            DesktopAgentCommandKind::ConfirmReviewAction,
            DesktopAgentResultCode::ReviewConfirmed,
        )
        .unwrap();

        let cursor = format!("pair_1/{review_id}");
        let page = DesktopAgentDesktopViewPage::Reviews {
            after: None,
            limit: 1,
            rows: vec![DesktopAgentReviewRow {
                review_id: review_id.to_string(),
                pair_id: "pair_1".to_string(),
                item_label: "file name.txt".to_string(),
                reason: crate::ReviewKind::LocalDeletion,
                actions: vec![ReviewAction::RestoreLocalCopy],
            }],
        };
        DesktopAgentResultPayload::DesktopView {
            status: DesktopAgentObservedStatus::Ready,
            paused: false,
            active_pair_count: 1,
            pending_review_count: 1,
            page,
            next_after: Some(cursor.clone()),
        }
        .validate_for(
            DesktopAgentCommandKind::DesktopView,
            DesktopAgentResultCode::ViewRead,
        )
        .unwrap();
        let next = super::claim(
            DesktopAgentCommandKind::DesktopView,
            serde_json::json!({
                "section": "reviews", "after": cursor, "limit": 1
            }),
        )
        .parse_command()
        .unwrap();
        assert!(
            matches!(next, DesktopAgentCommand::DesktopView { page } if page.after.as_deref() == Some(cursor.as_str()))
        );
    }
}

#[test]
fn review_ids_are_byte_bounded_noncontrol_text_while_authority_ids_stay_opaque() {
    let max = "é".repeat(2048);
    assert!(super::claim(
        DesktopAgentCommandKind::PrepareReviewAction,
        serde_json::json!({
            "pair_id": "pair_1", "review_id": max, "action": "restore_local_copy"
        })
    )
    .parse_command()
    .is_ok());
    for review_id in [
        String::new(),
        "\n".to_string(),
        "item\0name".to_string(),
        "item\u{85}name".to_string(),
        "é".repeat(2049),
    ] {
        assert!(super::claim(
            DesktopAgentCommandKind::PrepareReviewAction,
            serde_json::json!({
                "pair_id": "pair_1", "review_id": review_id, "action": "restore_local_copy"
            })
        )
        .parse_command()
        .is_err());
        assert!(DesktopAgentDesktopViewPageRequest::new(
            Some(DesktopAgentDesktopViewSection::Reviews),
            Some(format!("pair_1/{review_id}")),
            Some(1)
        )
        .is_err());
    }
    for payload in [
        serde_json::json!({"pair_id": "nested/pair", "review_id": "LocalDeletion:nested/file name.txt", "action": "restore_local_copy", "prepared_confirmation_id": "confirm_1", "fingerprint": "a".repeat(64)}),
        serde_json::json!({"pair_id": "pair_1", "review_id": "LocalDeletion:nested/file name.txt", "action": "restore_local_copy", "prepared_confirmation_id": "nested/confirmation", "fingerprint": "a".repeat(64)}),
    ] {
        assert!(
            super::claim(DesktopAgentCommandKind::ConfirmReviewAction, payload)
                .parse_command()
                .is_err()
        );
    }
    assert!(DesktopAgentDesktopViewPageRequest::new(
        Some(DesktopAgentDesktopViewSection::Reviews),
        Some(format!("{}/{}", "p".repeat(128), "r".repeat(4096))),
        Some(1)
    )
    .is_ok());
    assert!(DesktopAgentDesktopViewPageRequest::new(
        Some(DesktopAgentDesktopViewSection::Reviews),
        Some(format!("{}/{}", "p".repeat(129), "r".repeat(4096))),
        Some(1)
    )
    .is_err());
}

#[test]
fn readback_payloads_decode_default_and_explicit_keyset_pages() {
    assert_eq!(
        super::claim(
            DesktopAgentCommandKind::DesktopView,
            serde_json::json!({"section": "reviews", "after": "pair_1/review_1", "limit": 1})
        )
        .parse_command()
        .unwrap(),
        DesktopAgentCommand::DesktopView {
            page: DesktopAgentDesktopViewPageRequest::new(
                Some(DesktopAgentDesktopViewSection::Reviews),
                Some("pair_1/review_1".to_string()),
                Some(1),
            )
            .unwrap(),
        }
    );
    assert_eq!(
        super::claim(
            DesktopAgentCommandKind::DiscoverRoots,
            serde_json::json!({"after": "root_1", "limit": 50})
        )
        .parse_command()
        .unwrap(),
        DesktopAgentCommand::DiscoverRoots {
            page: DesktopAgentRootsPageRequest::new(Some("root_1".to_string()), Some(50)).unwrap(),
        }
    );
    assert_eq!(
        super::claim(
            DesktopAgentCommandKind::DiscoverRoots,
            serde_json::json!({"after": null})
        )
        .parse_command()
        .unwrap(),
        DesktopAgentCommand::DiscoverRoots {
            page: DesktopAgentRootsPageRequest::default(),
        }
    );
    assert!(
        serde_json::from_value::<crate::DesktopAgentClaim>(serde_json::json!({
            "command_id": "command_1",
            "lease_id": "lease_1",
            "lease_expires_at": "2036-09-07T12:00:00Z",
            "kind": "desktop_view",
            "payload": {"section": "pairs", "limit": 51},
        }))
        .is_err()
    );
}

#[test]
fn readback_payloads_reject_null_for_fields_that_default_only_when_absent() {
    for payload in [
        serde_json::json!({"section": null}),
        serde_json::json!({"limit": null}),
    ] {
        assert!(
            serde_json::from_value::<crate::DesktopAgentClaim>(serde_json::json!({
                "command_id": "command_1",
                "lease_id": "lease_1",
                "lease_expires_at": "2036-09-07T12:00:00Z",
                "kind": "desktop_view",
                "payload": payload,
            }))
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<crate::DesktopAgentClaim>(serde_json::json!({
            "command_id": "command_1",
            "lease_id": "lease_1",
            "lease_expires_at": "2036-09-07T12:00:00Z",
            "kind": "discover_roots",
            "payload": {"limit": null},
        }))
        .is_err()
    );
}
