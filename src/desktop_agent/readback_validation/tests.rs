use serde_json::json;

use crate::desktop_agent::{
    parse_submit_request, validate_result_payload, DesktopAgentCommandKind,
    DesktopAgentCommandPayload, DesktopAgentDesktopViewPage, DesktopAgentObservedStatus,
    DesktopAgentPairRow, DesktopAgentPairStatus, DesktopAgentResultPayload,
    DesktopAgentReviewAction, DesktopAgentReviewKind, DesktopAgentReviewRow,
    DesktopAgentSubmitWireRequest, DesktopAgentViewSection,
};

fn request(
    kind: DesktopAgentCommandKind,
    payload: serde_json::Value,
) -> DesktopAgentSubmitWireRequest {
    DesktopAgentSubmitWireRequest {
        request_id: "9f4f46c9-56af-4e59-8df9-361274a28150".to_string(),
        device_id: Some("device_01".to_string()),
        kind,
        payload,
        expires_in_seconds: Some(60),
    }
}

#[test]
fn native_review_ids_roundtrip_through_broker_commands_and_results() {
    for review_id in [
        "LocalDeletion:file.txt",
        "LocalDeletion:nested/file name.txt",
        "LocalDeletion:nested\\file name.txt",
        "LocalDeletion:répertoire/文.txt",
    ] {
        let prepared = parse_submit_request(request(
            DesktopAgentCommandKind::PrepareReviewAction,
            json!({
                "pair_id": "pair_01", "review_id": review_id, "action": "restore_local_copy"
            }),
        ))
        .unwrap();
        assert_eq!(
            prepared.payload,
            DesktopAgentCommandPayload::PrepareReviewAction {
                pair_id: Some("pair_01".to_string()),
                review_id: review_id.to_string(),
                action: DesktopAgentReviewAction::RestoreLocalCopy,
            }
        );
        let confirmed = parse_submit_request(request(
            DesktopAgentCommandKind::ConfirmReviewAction,
            json!({
                "pair_id": "pair_01", "review_id": review_id, "action": "restore_local_copy",
                "prepared_confirmation_id": "confirm_01", "fingerprint": "a".repeat(64)
            }),
        ))
        .unwrap();
        for (payload, kind) in [
            (&prepared.payload, "review_prepared"),
            (&confirmed.payload, "review_confirmed"),
        ] {
            let result: DesktopAgentResultPayload = serde_json::from_value(json!({
                "kind": kind, "pair_id": "pair_01", "review_id": review_id, "action": "restore_local_copy",
                "prepared_confirmation_id": "confirm_01", "fingerprint": "a".repeat(64)
            })).unwrap();
            validate_result_payload(payload, &result).unwrap();
            let encoded = serde_json::to_value(&result).unwrap();
            assert_eq!(encoded["review_id"], review_id);
        }

        let cursor = format!("pair_01/{review_id}");
        let payload = DesktopAgentCommandPayload::DesktopView {
            section: DesktopAgentViewSection::Reviews,
            after: None,
            limit: 1,
        };
        let result = DesktopAgentResultPayload::DesktopView {
            status: DesktopAgentObservedStatus::Ready,
            paused: false,
            active_pair_count: 1,
            pending_review_count: 1,
            page: Some(DesktopAgentDesktopViewPage::Reviews {
                after: None,
                limit: 1,
                rows: vec![DesktopAgentReviewRow {
                    review_id: review_id.to_string(),
                    pair_id: "pair_01".to_string(),
                    item_label: "file name.txt".to_string(),
                    reason: DesktopAgentReviewKind::LocalDeletion,
                    actions: vec![DesktopAgentReviewAction::RestoreLocalCopy],
                }],
            }),
            next_after: Some(cursor.clone()),
        };
        validate_result_payload(&payload, &result).unwrap();
        let next = parse_submit_request(request(
            DesktopAgentCommandKind::DesktopView,
            json!({
                "section": "reviews", "after": cursor, "limit": 1
            }),
        ))
        .unwrap();
        assert_eq!(
            next.payload,
            DesktopAgentCommandPayload::DesktopView {
                section: DesktopAgentViewSection::Reviews,
                after: Some(cursor),
                limit: 1,
            }
        );
    }
}

#[test]
fn review_ids_keep_byte_control_and_authority_id_bounds() {
    let max = "é".repeat(2048);
    assert!(parse_submit_request(request(
        DesktopAgentCommandKind::PrepareReviewAction,
        json!({
            "pair_id": "pair_01", "review_id": max, "action": "restore_local_copy"
        })
    ))
    .is_ok());
    for review_id in [
        String::new(),
        "\n".to_string(),
        "item\0name".to_string(),
        "item\u{85}name".to_string(),
        "é".repeat(2049),
    ] {
        assert!(parse_submit_request(request(
            DesktopAgentCommandKind::PrepareReviewAction,
            json!({
                "pair_id": "pair_01", "review_id": review_id, "action": "restore_local_copy"
            })
        ))
        .is_err());
        assert!(parse_submit_request(request(
            DesktopAgentCommandKind::DesktopView,
            json!({
                "section": "reviews", "after": format!("pair_01/{review_id}"), "limit": 1
            })
        ))
        .is_err());
        let payload = DesktopAgentCommandPayload::PrepareReviewAction {
            pair_id: Some("pair_01".to_string()),
            review_id: "LocalDeletion:file.txt".to_string(),
            action: DesktopAgentReviewAction::RestoreLocalCopy,
        };
        let result = DesktopAgentResultPayload::ReviewPrepared {
            pair_id: Some("pair_01".to_string()),
            review_id,
            action: DesktopAgentReviewAction::RestoreLocalCopy,
            prepared_confirmation_id: "confirm_01".to_string(),
            fingerprint: "a".repeat(64),
        };
        assert!(validate_result_payload(&payload, &result).is_err());
    }
    for payload in [
        json!({"pair_id": "nested/pair", "review_id": "LocalDeletion:nested/file name.txt", "action": "restore_local_copy", "prepared_confirmation_id": "confirm_01", "fingerprint": "a".repeat(64)}),
        json!({"pair_id": "pair_01", "review_id": "LocalDeletion:nested/file name.txt", "action": "restore_local_copy", "prepared_confirmation_id": "nested/confirmation", "fingerprint": "a".repeat(64)}),
    ] {
        assert!(parse_submit_request(request(
            DesktopAgentCommandKind::ConfirmReviewAction,
            payload
        ))
        .is_err());
    }
    let mut device = request(
        DesktopAgentCommandKind::PrepareReviewAction,
        json!({
            "pair_id": "pair_01", "review_id": "LocalDeletion:nested/file name.txt", "action": "restore_local_copy"
        }),
    );
    device.device_id = Some("nested/device".to_string());
    assert!(parse_submit_request(device).is_err());
    assert!(parse_submit_request(request(DesktopAgentCommandKind::DesktopView, json!({
        "section": "reviews", "after": format!("{}/{}", "p".repeat(128), "r".repeat(4096)), "limit": 1
    }))).is_ok());
    assert!(parse_submit_request(request(DesktopAgentCommandKind::DesktopView, json!({
        "section": "reviews", "after": format!("{}/{}", "p".repeat(129), "r".repeat(4096)), "limit": 1
    }))).is_err());
}

#[test]
fn readback_queries_are_strict_and_default_to_a_bounded_pairs_page() {
    let parsed =
        parse_submit_request(request(DesktopAgentCommandKind::DesktopView, json!({}))).unwrap();
    assert_eq!(
        parsed.payload,
        DesktopAgentCommandPayload::DesktopView {
            section: DesktopAgentViewSection::Pairs,
            after: None,
            limit: 25,
        }
    );
    for payload in [
        json!({"after": "/local/path"}),
        json!({"limit": 51}),
        json!({"section": "reviews", "after": "pair_01/LocalDeletion:control\npath"}),
        json!({"section": "pairs", "unexpected": true}),
    ] {
        assert!(
            parse_submit_request(request(DesktopAgentCommandKind::DesktopView, payload)).is_err()
        );
    }
    assert!(parse_submit_request(request(
        DesktopAgentCommandKind::DiscoverRoots,
        json!({"after": "root_01", "limit": 0}),
    ))
    .is_err());
}

#[test]
fn paged_readback_must_echo_the_query_and_prove_its_cursor() {
    let payload = DesktopAgentCommandPayload::DesktopView {
        section: DesktopAgentViewSection::Reviews,
        after: Some("pair_01/review_01".to_string()),
        limit: 2,
    };
    let result = DesktopAgentResultPayload::DesktopView {
        status: DesktopAgentObservedStatus::Ready,
        paused: false,
        active_pair_count: 1,
        pending_review_count: 3,
        page: Some(DesktopAgentDesktopViewPage::Reviews {
            after: Some("pair_01/review_01".to_string()),
            limit: 2,
            rows: vec![
                DesktopAgentReviewRow {
                    review_id: "review_02".to_string(),
                    pair_id: "pair_01".to_string(),
                    item_label: "document.txt".to_string(),
                    reason: DesktopAgentReviewKind::ContentConflict,
                    actions: vec![DesktopAgentReviewAction::OpenConflictCopies],
                },
                DesktopAgentReviewRow {
                    review_id: "review_03".to_string(),
                    pair_id: "pair_01".to_string(),
                    item_label: "notes.txt".to_string(),
                    reason: DesktopAgentReviewKind::LocalDeletion,
                    actions: vec![DesktopAgentReviewAction::RestoreLocalCopy],
                },
            ],
        }),
        next_after: Some("pair_01/review_03".to_string()),
    };
    assert!(validate_result_payload(&payload, &result).is_ok());

    let mut bad_cursor = result.clone();
    if let DesktopAgentResultPayload::DesktopView { next_after, .. } = &mut bad_cursor {
        *next_after = Some("pair_01/review_02".to_string());
    }
    assert!(validate_result_payload(&payload, &bad_cursor).is_err());

    let pair = DesktopAgentPairRow {
        pair_id: "pair_01".to_string(),
        workspace_id: "workspace_01".to_string(),
        workspace_name: "/local/path".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        selected: true,
        status: DesktopAgentPairStatus::Ready,
        pending_review_count: 0,
    };
    let invalid_label = DesktopAgentResultPayload::DesktopView {
        status: DesktopAgentObservedStatus::Ready,
        paused: false,
        active_pair_count: 1,
        pending_review_count: 0,
        page: Some(DesktopAgentDesktopViewPage::Pairs {
            after: None,
            limit: 1,
            rows: vec![pair],
        }),
        next_after: None,
    };
    let pair_payload = DesktopAgentCommandPayload::DesktopView {
        section: DesktopAgentViewSection::Pairs,
        after: None,
        limit: 1,
    };
    assert!(validate_result_payload(&pair_payload, &invalid_label).is_err());
}

#[test]
fn legacy_count_only_records_stay_readable_but_cannot_complete_new_readback() {
    let payload: DesktopAgentCommandPayload =
        serde_json::from_value(json!({"kind": "desktop_view"})).unwrap();
    assert_eq!(
        payload,
        DesktopAgentCommandPayload::DesktopView {
            section: DesktopAgentViewSection::Pairs,
            after: None,
            limit: 25,
        }
    );
    let legacy: DesktopAgentResultPayload = serde_json::from_value(json!({
        "kind": "desktop_view",
        "status": "ready",
        "paused": false,
        "active_pair_count": 1,
        "pending_review_count": 0,
    }))
    .unwrap();
    assert!(validate_result_payload(&payload, &legacy).is_err());
}

#[test]
fn short_byte_limited_review_pages_preserve_cursor_query_and_result_bounds() {
    let rows = (0..2)
        .map(|index| DesktopAgentReviewRow {
            review_id: format!("local-path:{}/file_{index:02}.txt", "a\\\"".repeat(1_000)),
            pair_id: "pair_01".to_string(),
            item_label: format!("file_{index:02}.txt"),
            reason: DesktopAgentReviewKind::UnsafePath,
            actions: Vec::new(),
        })
        .collect::<Vec<_>>();
    let last_cursor = super::review_row_cursor(rows.last().unwrap());
    let payload = DesktopAgentCommandPayload::DesktopView {
        section: DesktopAgentViewSection::Reviews,
        after: None,
        limit: 25,
    };
    let result = DesktopAgentResultPayload::DesktopView {
        status: DesktopAgentObservedStatus::Ready,
        paused: false,
        active_pair_count: 1,
        pending_review_count: 40,
        page: Some(DesktopAgentDesktopViewPage::Reviews {
            after: None,
            limit: 25,
            rows,
        }),
        next_after: Some(last_cursor),
    };
    validate_result_payload(&payload, &result).unwrap();
    let bytes = serde_json::to_vec(&result).unwrap();
    assert!(bytes.windows(2).any(|window| window == b"\\\\"));
    assert!(bytes.windows(2).any(|window| window == b"\\\""));

    for case in 0..6 {
        let mut altered = result.clone();
        if let DesktopAgentResultPayload::DesktopView {
            page: Some(DesktopAgentDesktopViewPage::Reviews { after, limit, rows }),
            next_after,
            ..
        } = &mut altered
        {
            match case {
                0 => *next_after = Some("pair_01/different-review".to_string()),
                1 => rows.clear(),
                2 => *after = Some(super::review_row_cursor(&rows[0])),
                3 => *limit = 1,
                4 => rows[1] = rows[0].clone(),
                5 => rows[0].pair_id = "unsafe/pair".to_string(),
                _ => unreachable!(),
            }
        }
        assert!(
            validate_result_payload(&payload, &altered).is_err(),
            "case {case}"
        );
    }
    let mut oversized = result;
    if let DesktopAgentResultPayload::DesktopView {
        page: Some(DesktopAgentDesktopViewPage::Reviews { rows, .. }),
        next_after,
        ..
    } = &mut oversized
    {
        let template = rows[0].clone();
        *rows = (0..25)
            .map(|index| {
                let mut row = template.clone();
                row.review_id = format!("local-path:{}/file_{index:02}.txt", "a\\\"".repeat(1_000));
                row
            })
            .collect();
        *next_after = rows.last().map(super::review_row_cursor);
    }
    assert!(serde_json::to_vec(&oversized).unwrap().len() > super::MAX_DESKTOP_AGENT_RESULT_BYTES);
    assert!(validate_result_payload(&payload, &oversized).is_err());
}

#[test]
fn aggregate_review_readback_accepts_a_valid_count_above_u16() {
    let payload = DesktopAgentCommandPayload::DesktopView {
        section: DesktopAgentViewSection::Pairs,
        after: None,
        limit: 1,
    };
    let result: DesktopAgentResultPayload = serde_json::from_value(json!({
        "kind": "desktop_view",
        "status": "ready",
        "paused": false,
        "active_pair_count": 4,
        "pending_review_count": 80_000,
        "page": {"section": "pairs", "after": null, "limit": 1, "rows": []},
        "next_after": null,
    }))
    .unwrap();

    assert!(validate_result_payload(&payload, &result).is_ok());
    assert_eq!(
        serde_json::to_value(result).unwrap()["pending_review_count"],
        80_000
    );
}

#[path = "tests/roots.rs"]
mod roots;
