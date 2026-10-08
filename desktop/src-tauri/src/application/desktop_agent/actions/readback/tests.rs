use std::{collections::BTreeMap, path::PathBuf};

use shellx_drive_desktop_core::{
    apply_local_path_compatibility_reviews, desktop_agent_enrollment_fingerprint,
    plan_reconciliation, validate_local_relative, validate_page_result, CredentialStore,
    DesktopAgentDesktopViewPage, DesktopAgentDesktopViewPageRequest,
    DesktopAgentDesktopViewSection, DesktopAgentResultPayload, DesktopState, FakeCredentialStore,
    LocalPathIssue, Result as CoreResult, ReviewItem, ReviewKind, StateStore, SyncPair,
    MAX_DESKTOP_AGENT_PAGE_BYTES,
};

use super::{agent_view_result, pair_row, review_cursor, DesktopAgentPairStatus, Runtime};

fn pair() -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "workspace_1".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: Some("root_1".to_string()),
        remote_root_name: Some("Root".to_string()),
        local_root: PathBuf::from("/fixture/root_1"),
        local_root_identity: None,
    }
}

#[test]
fn pair_with_reviews_and_an_error_stays_actionable() {
    let reviews = vec![ReviewItem {
        id: "review_1".to_string(),
        kind: ReviewKind::LocalDeletion,
        relative_path: PathBuf::from("document.txt"),
        descendant_count: 0,
        is_directory: false,
        summary: "review".to_string(),
        actions: Vec::new(),
    }];

    let row = pair_row(&pair(), false, false, &reviews, true).unwrap();
    assert_eq!(row.status, DesktopAgentPairStatus::NeedsReview);
}

struct ReadbackPlatform(FakeCredentialStore);

impl crate::platform::PlatformServices for ReadbackPlatform {
    fn credentials(&self) -> &dyn CredentialStore {
        &self.0
    }
    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        panic!("readback must not access protected credentials")
    }
    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        panic!("readback must not access protected credentials")
    }
    fn set_launch_at_login(&self, _: bool) -> CoreResult<()> {
        panic!("readback must not alter login integration")
    }
    fn open_local_root(&self, _: &std::path::Path) -> CoreResult<()> {
        panic!("readback must not open a local path")
    }
    fn open_drive_url(&self, _: &str) -> CoreResult<()> {
        panic!("readback must not open a URL")
    }
}

fn readback_runtime(reviews: Vec<ReviewItem>) -> (tempfile::TempDir, Runtime) {
    let directory = tempfile::tempdir().unwrap();
    let pair = pair();
    let fingerprint = desktop_agent_enrollment_fingerprint(&pair.server_url, &pair.account_email);
    let mut state = DesktopState {
        pair: Some(pair),
        reviews,
        ..DesktopState::default()
    };
    state
        .desktop_agent_control
        .enroll("device_1".to_string(), None, fingerprint)
        .unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(ReadbackPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    (directory, runtime)
}

fn long_planner_reviews(escaped: bool) -> Vec<ReviewItem> {
    let component = if escaped {
        "a\\\"".repeat(33)
    } else {
        "a".repeat(99)
    };
    let prefix = (0..30).map(|_| component.as_str()).collect::<PathBuf>();
    let issues = (0..40)
        .map(|index| {
            let path = prefix.join(format!("file_{index:02}.txt"));
            let issue = validate_local_relative(&path).unwrap_err();
            LocalPathIssue {
                path,
                reason: issue.reason,
            }
        })
        .collect::<Vec<_>>();
    let plan = plan_reconciliation(&BTreeMap::new(), None, &[], &[], chrono::Utc::now()).unwrap();
    let reviews = apply_local_path_compatibility_reviews(plan, &issues).reviews;
    assert_eq!(reviews.len(), 40);
    assert!(reviews
        .iter()
        .all(|review| (2_900..=4_096).contains(&review.id.len())));
    reviews
}

fn assert_long_reviews_paginate(escaped: bool) {
    let (_directory, runtime) = readback_runtime(long_planner_reviews(escaped));
    let state = runtime.coordinator.snapshot();
    let mut expected = state
        .reviews
        .iter()
        .map(|review| review.id.clone())
        .collect::<Vec<_>>();
    expected.sort();
    let mut observed = Vec::new();
    let mut after = None;
    let mut pages = 0;
    loop {
        let request = DesktopAgentDesktopViewPageRequest::new(
            Some(DesktopAgentDesktopViewSection::Reviews),
            after.clone(),
            Some(25),
        )
        .unwrap();
        let result = agent_view_result(&runtime, &request).unwrap();
        let bytes = serde_json::to_vec(&result).unwrap();
        assert!(bytes.len() <= MAX_DESKTOP_AGENT_PAGE_BYTES);
        validate_page_result(&result).unwrap();
        let decoded: DesktopAgentResultPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, result);
        let DesktopAgentResultPayload::DesktopView {
            page:
                DesktopAgentDesktopViewPage::Reviews {
                    rows,
                    after: echoed_after,
                    limit,
                },
            next_after,
            pending_review_count,
            ..
        } = result
        else {
            panic!("expected a review page")
        };
        assert_eq!(echoed_after, after);
        assert_eq!(limit, 25);
        assert_eq!(pending_review_count, 40);
        assert!(!rows.is_empty());
        if pages == 0 {
            assert!(rows.len() < usize::from(limit));
        }
        if escaped {
            assert!(bytes.windows(2).any(|window| window == b"\\\\"));
            assert!(bytes.windows(2).any(|window| window == b"\\\""));
        }
        if let Some(next) = next_after.as_deref() {
            assert_eq!(Some(next), rows.last().map(review_cursor).as_deref());
            assert!(after.as_deref().is_none_or(|previous| next > previous));
        }
        observed.extend(rows.into_iter().map(|row| row.review_id));
        pages += 1;
        assert!(pages <= expected.len());
        let Some(next) = next_after else { break };
        after = Some(next);
    }
    assert!(pages > 1);
    assert_eq!(observed, expected);
    assert_eq!(runtime.coordinator.snapshot(), state);
}

#[test]
fn long_production_review_ids_fit_whole_result_without_pagination_gaps_or_duplicates() {
    assert_long_reviews_paginate(false);
}

#[test]
fn escaped_production_review_ids_budget_the_encoded_body_and_both_cursors() {
    assert_long_reviews_paginate(true);
}

#[test]
fn a_single_oversize_review_fails_instead_of_returning_an_empty_success() {
    let mut review = long_planner_reviews(false).remove(0);
    review.id = "x".repeat(MAX_DESKTOP_AGENT_PAGE_BYTES);
    let (_directory, runtime) = readback_runtime(vec![review]);
    let request = DesktopAgentDesktopViewPageRequest::new(
        Some(DesktopAgentDesktopViewSection::Reviews),
        None,
        Some(25),
    )
    .unwrap();
    assert!(agent_view_result(&runtime, &request).is_err());
    assert_eq!(runtime.coordinator.snapshot().reviews.len(), 1);
}
