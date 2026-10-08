use crate::{
    DesktopAgentCommandKind, DesktopAgentDesktopViewPage, DesktopAgentObservedStatus,
    DesktopAgentPairRow, DesktopAgentPairStatus, DesktopAgentResultCode, DesktopAgentResultPayload,
    DesktopAgentReviewRow, ReviewKind,
};

#[test]
fn paginated_readback_requires_stable_rows_and_a_full_page_for_next_cursor() {
    let page = DesktopAgentDesktopViewPage::Pairs {
        after: None,
        limit: 1,
        rows: vec![DesktopAgentPairRow {
            pair_id: "pair_1".to_string(),
            workspace_id: "workspace_1".to_string(),
            workspace_name: "Team files".to_string(),
            remote_root_id: None,
            remote_root_name: None,
            selected: true,
            status: DesktopAgentPairStatus::Ready,
            pending_review_count: 0,
        }],
    };
    let result = DesktopAgentResultPayload::DesktopView {
        status: DesktopAgentObservedStatus::Ready,
        paused: false,
        active_pair_count: 1,
        pending_review_count: 0,
        page,
        next_after: Some("pair_1".to_string()),
    };
    result
        .validate_for(
            DesktopAgentCommandKind::DesktopView,
            DesktopAgentResultCode::ViewRead,
        )
        .unwrap();
    let wire = serde_json::to_value(&result).unwrap();
    assert_eq!(wire["kind"], "desktop_view");
    assert_eq!(wire["page"]["section"], "pairs");
    assert_eq!(wire["page"]["limit"], 1);
    assert_eq!(wire["next_after"], "pair_1");

    let incomplete = DesktopAgentResultPayload::DesktopView {
        status: DesktopAgentObservedStatus::Ready,
        paused: false,
        active_pair_count: 0,
        pending_review_count: 0,
        page: DesktopAgentDesktopViewPage::Pairs {
            after: None,
            limit: 1,
            rows: vec![],
        },
        next_after: Some("pair_1".to_string()),
    };
    assert!(incomplete
        .validate_for(
            DesktopAgentCommandKind::DesktopView,
            DesktopAgentResultCode::ViewRead,
        )
        .is_err());
}

#[test]
fn paginated_readback_rejects_more_rows_than_the_requested_limit() {
    let rows = ["pair_1", "pair_2"]
        .into_iter()
        .map(|pair_id| DesktopAgentPairRow {
            pair_id: pair_id.to_string(),
            workspace_id: "workspace_1".to_string(),
            workspace_name: "Team files".to_string(),
            remote_root_id: None,
            remote_root_name: None,
            selected: pair_id == "pair_1",
            status: DesktopAgentPairStatus::Ready,
            pending_review_count: 0,
        })
        .collect();
    let result = DesktopAgentResultPayload::DesktopView {
        status: DesktopAgentObservedStatus::Ready,
        paused: false,
        active_pair_count: 2,
        pending_review_count: 0,
        page: DesktopAgentDesktopViewPage::Pairs {
            after: None,
            limit: 1,
            rows,
        },
        next_after: None,
    };
    assert!(result
        .validate_for(
            DesktopAgentCommandKind::DesktopView,
            DesktopAgentResultCode::ViewRead,
        )
        .is_err());
}

#[test]
fn aggregate_review_readback_serializes_beyond_the_per_pair_u16_limit() {
    let result = DesktopAgentResultPayload::Sync {
        status: DesktopAgentObservedStatus::Ready,
        pending_review_count: 80_000,
    };
    result
        .validate_for(
            DesktopAgentCommandKind::RecheckReviews,
            DesktopAgentResultCode::ReviewsRechecked,
        )
        .unwrap();

    let wire = serde_json::to_value(&result).unwrap();
    assert_eq!(wire["pending_review_count"], 80_000);
    assert_eq!(
        serde_json::from_value::<DesktopAgentResultPayload>(wire).unwrap(),
        result
    );
}

fn review_result(count: usize, limit: u8) -> DesktopAgentResultPayload {
    let rows = (0..count)
        .map(|index| DesktopAgentReviewRow {
            review_id: format!("local-path:{}/file_{index:02}.txt", "a".repeat(3_000)),
            pair_id: "pair_1".to_string(),
            item_label: format!("file_{index:02}.txt"),
            reason: ReviewKind::UnsafePath,
            actions: Vec::new(),
        })
        .collect::<Vec<_>>();
    let next_after = rows.last().map(crate::review_cursor);
    DesktopAgentResultPayload::DesktopView {
        status: DesktopAgentObservedStatus::Ready,
        paused: false,
        active_pair_count: 1,
        pending_review_count: 40,
        page: DesktopAgentDesktopViewPage::Reviews {
            after: None,
            limit,
            rows,
        },
        next_after,
    }
}

#[test]
fn short_review_page_accepts_only_a_nonempty_exact_advancing_continuation() {
    let result = review_result(2, 25);
    let validate = |result: &DesktopAgentResultPayload| {
        result.validate_for(
            DesktopAgentCommandKind::DesktopView,
            DesktopAgentResultCode::ViewRead,
        )
    };
    validate(&result).unwrap();
    for wrong in [None, Some("pair_1/different-review".to_string())] {
        let mut altered = result.clone();
        if let DesktopAgentResultPayload::DesktopView {
            page: DesktopAgentDesktopViewPage::Reviews { rows, .. },
            next_after,
            ..
        } = &mut altered
        {
            if wrong.is_none() {
                rows.clear();
            } else {
                *next_after = wrong;
            }
        }
        assert!(validate(&altered).is_err());
    }
    let mut unchanged_cursor = result.clone();
    if let DesktopAgentResultPayload::DesktopView {
        page: DesktopAgentDesktopViewPage::Reviews { after, rows, .. },
        ..
    } = &mut unchanged_cursor
    {
        *after = rows.first().map(crate::review_cursor);
    }
    assert!(validate(&unchanged_cursor).is_err());
    assert!(validate(&review_result(2, 1)).is_err());
}

#[test]
fn long_review_page_cannot_exceed_the_whole_result_byte_cap() {
    assert!(review_result(25, 25)
        .validate_for(
            DesktopAgentCommandKind::DesktopView,
            DesktopAgentResultCode::ViewRead,
        )
        .is_err());
}

#[test]
fn short_pair_pages_still_cannot_publish_a_continuation() {
    let result = DesktopAgentResultPayload::DesktopView {
        status: DesktopAgentObservedStatus::Ready,
        paused: false,
        active_pair_count: 2,
        pending_review_count: 0,
        page: DesktopAgentDesktopViewPage::Pairs {
            after: None,
            limit: 25,
            rows: vec![DesktopAgentPairRow {
                pair_id: "pair_1".to_string(),
                workspace_id: "workspace_1".to_string(),
                workspace_name: "Workspace".to_string(),
                remote_root_id: None,
                remote_root_name: None,
                selected: true,
                status: DesktopAgentPairStatus::Ready,
                pending_review_count: 0,
            }],
        },
        next_after: Some("pair_1".to_string()),
    };
    assert!(result
        .validate_for(
            DesktopAgentCommandKind::DesktopView,
            DesktopAgentResultCode::ViewRead,
        )
        .is_err());
}
