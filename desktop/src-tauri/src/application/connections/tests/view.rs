use super::*;

use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{sync_pair_id, ActivityEntry};

use super::super::view::project_connection_snapshot;

fn root_pair(root: std::path::PathBuf, id: &str) -> SyncPair {
    let mut pair = pair(root, "work@example.test");
    pair.remote_root_id = Some(id.to_string());
    pair.remote_root_name = Some("Reports".to_string());
    pair
}

fn activity(at: chrono::DateTime<Utc>, result: &str) -> ActivityEntry {
    ActivityEntry {
        at,
        direction: "download".to_string(),
        relative_path: "report.txt".into(),
        result: result.to_string(),
    }
}

#[test]
fn connection_history_labels_each_root_without_changing_runtime_or_durable_activity() {
    let directory = tempfile::tempdir().unwrap();
    let first = root_pair(directory.path().join("first"), "first");
    let second = root_pair(directory.path().join("second"), "second");
    let now = Utc::now();
    let mut state = DesktopState {
        pair: Some(first.clone()),
        ..DesktopState::default()
    };
    state.append_activity(activity(now, "completed first"));
    state.configure_pair(second.clone()).unwrap();
    state.append_activity(activity(now + Duration::seconds(1), "completed second"));
    let runtime = factory(
        StateStore::new(directory.path().join("state.json")),
        state.clone(),
    )
    .unwrap();

    let (view, _) = project_connection_snapshot(&runtime, runtime.coordinator.view_snapshot());
    assert_eq!(view.activity.len(), 2);
    assert!(view.activity[0].result.contains("Reports"));
    assert!(view.activity[0]
        .result
        .contains(&second.local_root.display().to_string()));
    assert!(view.activity[1]
        .result
        .contains(&first.local_root.display().to_string()));
    assert_eq!(
        view.activity[0].relative_path,
        std::path::PathBuf::from("report.txt")
    );
    assert_eq!(runtime.view().activity, state.activity);
    assert_eq!(runtime.coordinator.snapshot(), state);
}

#[test]
fn connection_history_keeps_the_newest_two_hundred_across_selection_changes() {
    let directory = tempfile::tempdir().unwrap();
    let first = root_pair(directory.path().join("first"), "first");
    let second = root_pair(directory.path().join("second"), "second");
    let now = Utc::now();
    let mut state = DesktopState {
        pair: Some(first.clone()),
        ..DesktopState::default()
    };
    for index in 0..200 {
        state.append_activity(activity(now + Duration::seconds(index * 2), "first"));
    }
    state.configure_pair(second).unwrap();
    for index in 0..200 {
        state.append_activity(activity(now + Duration::seconds(index * 2 + 1), "second"));
    }
    let runtime = factory(
        StateStore::new(directory.path().join("state.json")),
        state.clone(),
    )
    .unwrap();
    let (before, _) = project_connection_snapshot(&runtime, runtime.coordinator.view_snapshot());
    assert_eq!(before.activity.len(), 200);
    assert_eq!(
        before.activity.first().unwrap().at,
        now + Duration::seconds(399)
    );
    assert_eq!(
        before.activity.last().unwrap().at,
        now + Duration::seconds(200)
    );
    assert_eq!(
        before
            .activity
            .iter()
            .filter(|entry| entry.result.ends_with("· first"))
            .count(),
        100
    );
    assert_eq!(
        before
            .activity
            .iter()
            .filter(|entry| entry.result.ends_with("· second"))
            .count(),
        100
    );

    state.activate_pair(&sync_pair_id(&first)).unwrap();
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    operation.finish_state(state);
    let (after, _) = project_connection_snapshot(&runtime, runtime.coordinator.view_snapshot());
    assert_eq!(
        after.activity, before.activity,
        "selection cannot drop another root's history"
    );
}

#[test]
fn captured_connection_view_keeps_folder_history_and_status_from_one_coordinator_image() {
    let directory = tempfile::tempdir().unwrap();
    let old_root = root_pair(directory.path().join("old"), "old");
    let old_base = directory.path().join("old-base");
    let state = DesktopState {
        pair: Some(old_root.clone()),
        sync_root_base: Some(old_base.clone()),
        activity: vec![activity(Utc::now(), "old image")],
        ..DesktopState::default()
    };
    let runtime = factory(StateStore::new(directory.path().join("state.json")), state).unwrap();
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    let captured = runtime.coordinator.view_snapshot();
    operation.finish_state(DesktopState {
        pair: Some(root_pair(directory.path().join("new"), "new")),
        sync_root_base: Some(directory.path().join("new-base")),
        activity: vec![activity(Utc::now(), "new image")],
        ..DesktopState::default()
    });

    let (view, folder) = project_connection_snapshot(&runtime, captured);
    assert_eq!(view.status, "syncing");
    assert_eq!(folder.as_deref(), Some(old_base.to_str().unwrap()));
    assert_eq!(view.local_root, old_root.local_root.display().to_string());
    assert_eq!(view.active_pair_id, Some(sync_pair_id(&old_root)));
    assert!(view.activity[0].result.ends_with("· old image"));
    assert!(!runtime.view().activity[0].result.contains("old image"));
}
