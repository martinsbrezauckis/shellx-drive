//! Shared behavioral corpus for every-root terminal precedence and core planning.
//!
//! The JSON holds scenario inputs and expected user-visible outcomes. These tests
//! execute the production coordinator, terminal policy, and planner rather than
//! reproducing their decision logic in a fixture interpreter.

use std::{collections::BTreeMap, path::PathBuf};

use chrono::Utc;
use serde::Deserialize;
use shellx_drive_desktop_core::{
    plan_reconciliation, sync_pair_id, BaselineEntry, DesktopError, DesktopState, LocalEntry,
    MirrorCoordinator, RemoteEntry, ReviewAction, ReviewItem, ReviewKind, SyncAction, SyncPair,
    SyncStatus,
};

use super::SyncCycleTerminal;

const CORPUS: &str = include_str!("desktop-behavioral-conformance-v1.json");
const WHEN: &str = "2026-09-08T12:00:00Z";

#[derive(Deserialize)]
struct Corpus {
    schema: String,
    terminal_cases: Vec<TerminalCase>,
    planning_cases: Vec<PlanningCase>,
}

#[derive(Deserialize)]
struct TerminalCase {
    id: String,
    selected_workspace: String,
    steps: Vec<TerminalStep>,
    expected_status: SyncStatus,
    expected_pending_reviews: usize,
    expected_terminal: TerminalExpectation,
}

#[derive(Deserialize)]
struct TerminalStep {
    workspace_id: String,
    outcome: TerminalOutcome,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalOutcome {
    Success,
    PermanentLocalIo,
    #[serde(rename = "http_503")]
    Http503,
    RetainedAccessReview,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalExpectation {
    Ok,
    #[serde(rename = "http_503")]
    Http503,
}

#[derive(Deserialize)]
struct PlanningCase {
    id: String,
    baseline: BTreeMap<String, BaselineEntry>,
    remote: Vec<RemoteEntry>,
    local: Vec<FixtureLocalEntry>,
    expected_action_kinds: Vec<ActionKind>,
    expected_review_kinds: Vec<ReviewKind>,
    #[serde(default)]
    expected_first_review_actions: Option<Vec<ReviewAction>>,
}

#[derive(Deserialize)]
struct FixtureLocalEntry {
    relative_path: PathBuf,
    content_hash: Option<String>,
    size_bytes: u64,
    is_directory: bool,
}

impl From<FixtureLocalEntry> for LocalEntry {
    fn from(value: FixtureLocalEntry) -> Self {
        Self {
            relative_path: value.relative_path,
            content_hash: value.content_hash,
            size_bytes: value.size_bytes,
            is_directory: value.is_directory,
            directory_identity: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ActionKind {
    EnsureLocalDirectory,
    Download,
    UploadNew,
    UploadExisting,
    MoveLocal,
    MoveRemote,
    WriteRemoteConflictCopy,
}

fn corpus() -> Corpus {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("desktop behavioral corpus JSON");
    assert_eq!(
        corpus.schema, "shellx-drive.desktop-behavioral-conformance/v1",
        "unexpected behavioral corpus schema"
    );
    corpus
}

fn timestamp() -> chrono::DateTime<Utc> {
    WHEN.parse().expect("fixed corpus timestamp")
}

fn pair(workspace_id: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: workspace_id.to_string(),
        workspace_name: workspace_id.to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from(format!("/tmp/shellx-drive-conformance/{workspace_id}")),
        local_root_identity: None,
    }
}

fn retained_access_review() -> ReviewItem {
    ReviewItem {
        id: "access-removed".to_string(),
        kind: ReviewKind::AccessRemoved,
        relative_path: PathBuf::new(),
        descendant_count: 0,
        is_directory: true,
        summary: "This retained Drive location lost access.".to_string(),
        actions: vec![ReviewAction::RemoveLocalCopy],
    }
}

fn http_503() -> DesktopError {
    DesktopError::Server {
        status: 503,
        message: "temporary upstream failure".to_string(),
    }
}

fn action_kind(action: &SyncAction) -> ActionKind {
    match action {
        SyncAction::EnsureLocalDirectory { .. } => ActionKind::EnsureLocalDirectory,
        SyncAction::Download { .. } => ActionKind::Download,
        SyncAction::UploadNew { .. } => ActionKind::UploadNew,
        SyncAction::UploadExisting { .. } => ActionKind::UploadExisting,
        SyncAction::MoveLocal { .. } => ActionKind::MoveLocal,
        SyncAction::MoveRemote { .. } => ActionKind::MoveRemote,
        SyncAction::WriteRemoteConflictCopy { .. } => ActionKind::WriteRemoteConflictCopy,
    }
}

#[test]
fn corpus_executes_terminal_precedence_through_the_shared_coordinator() {
    for case in corpus().terminal_cases {
        let mut state = DesktopState::default();
        for step in &case.steps {
            state
                .configure_pair(pair(&step.workspace_id))
                .unwrap_or_else(|error| {
                    panic!("{}: configure {}: {error}", case.id, step.workspace_id)
                });
        }
        let selected_pair_id = sync_pair_id(&pair(&case.selected_workspace));
        state
            .activate_pair(&selected_pair_id)
            .unwrap_or_else(|error| panic!("{}: select root: {error}", case.id));
        for step in &case.steps {
            if matches!(step.outcome, TerminalOutcome::RetainedAccessReview) {
                let pair_id = sync_pair_id(&pair(&step.workspace_id));
                state
                    .inactive_pairs
                    .iter_mut()
                    .find(|profile| sync_pair_id(&profile.pair) == pair_id)
                    .unwrap_or_else(|| panic!("{}: retained root must be inactive", case.id))
                    .reviews = vec![retained_access_review()];
            }
        }

        let coordinator = MirrorCoordinator::new(state);
        let mut run = coordinator
            .begin_run()
            .unwrap_or_else(|error| panic!("{}: begin run: {error}", case.id));
        let mut terminal = SyncCycleTerminal::default();
        for step in &case.steps {
            let pair_id = sync_pair_id(&pair(&step.workspace_id));
            run.activate_configured_pair(&pair_id)
                .unwrap_or_else(|error| {
                    panic!("{}: activate {}: {error}", case.id, step.workspace_id)
                });
            match step.outcome {
                TerminalOutcome::Success => run.record_success(BTreeMap::new(), timestamp()),
                TerminalOutcome::PermanentLocalIo => terminal.record_root_failure(
                    &mut run,
                    DesktopError::Io(std::io::Error::other(
                        "fixture local I/O failed for this root",
                    )),
                ),
                TerminalOutcome::Http503 => terminal.record_root_failure(&mut run, http_503()),
                TerminalOutcome::RetainedAccessReview => assert!(
                    run.has_active_reviews(),
                    "{}: retained root review must remain attached to its root",
                    case.id
                ),
            }
        }

        let final_state = run
            .finalize_all_roots_state(&selected_pair_id)
            .unwrap_or_else(|error| panic!("{}: finalize: {error}", case.id));
        match case.expected_terminal {
            TerminalExpectation::Ok => assert!(
                terminal.finish(&final_state).is_ok(),
                "{}: retained permanent/review state must suppress a later 503 terminal error",
                case.id
            ),
            TerminalExpectation::Http503 => assert!(
                matches!(
                    terminal.finish(&final_state),
                    Err(DesktopError::Server { status: 503, .. })
                ),
                "{}: isolated 503 must remain the terminal error",
                case.id
            ),
        }
        run.finish_state(final_state);
        coordinator.set_offline(true);
        let snapshot = coordinator.snapshot();
        assert_eq!(
            snapshot
                .pair
                .as_ref()
                .map(|pair| pair.workspace_id.as_str()),
            Some(case.selected_workspace.as_str()),
            "{}: selected root must be restored before publication",
            case.id
        );
        assert_eq!(
            snapshot.pending_review_count(),
            case.expected_pending_reviews,
            "{}: root-scoped reviews must remain visible in aggregate state",
            case.id
        );
        assert_eq!(
            coordinator.status(true),
            case.expected_status,
            "{}: aggregate status precedence drifted",
            case.id
        );
    }
}

#[test]
fn corpus_executes_collision_conflict_and_restore_plans_through_core() {
    for case in corpus().planning_cases {
        let local = case
            .local
            .into_iter()
            .map(LocalEntry::from)
            .collect::<Vec<_>>();
        let plan = plan_reconciliation(&case.baseline, None, &case.remote, &local, timestamp())
            .unwrap_or_else(|error| panic!("{}: plan reconciliation: {error}", case.id));
        assert_eq!(
            plan.actions.iter().map(action_kind).collect::<Vec<_>>(),
            case.expected_action_kinds,
            "{}: production planner actions drifted",
            case.id
        );
        assert_eq!(
            plan.reviews
                .iter()
                .map(|review| review.kind.clone())
                .collect::<Vec<_>>(),
            case.expected_review_kinds,
            "{}: production planner review classification drifted",
            case.id
        );
        if let Some(expected_actions) = case.expected_first_review_actions {
            assert_eq!(
                plan.reviews.first().map(|review| review.actions.clone()),
                Some(expected_actions),
                "{}: restore decision must stay explicit and non-mutating",
                case.id
            );
        }
    }
}

#[test]
fn every_platform_adapter_delegates_terminal_projection_to_the_shared_policy() {
    for (platform, source) in [
        ("Linux", include_str!("../linux/sync/all_roots.rs")),
        ("macOS", include_str!("../macos/sync/all_roots.rs")),
        ("Windows", include_str!("../../windows/sync_runtime.rs")),
    ] {
        for fragment in [
            "SyncCycleTerminal::default()",
            "terminal.record_root_failure(run, error)",
            "run.finalize_all_roots_state(&selected_pair_id)?",
            "terminal.finish(&final_state)",
        ] {
            assert!(
                source.contains(fragment),
                "{platform} must retain the shared terminal-policy handoff: {fragment}"
            );
        }
    }
}
