//! Ordinary concurrent revision convergence and bounded retry regressions.

use super::super::baseline_tests::{inbound_entry, paired_root};
use super::*;
use crate::application::{runtime::tests::TestPlatform, Runtime};
use shellx_drive_desktop_core::{DesktopState, FakeCredentialStore, StateStore};

fn fixture() -> (
    tempfile::TempDir,
    SyncPair,
    UnixRootGuard,
    Runtime,
    RemoteEntry,
) {
    let directory = tempfile::tempdir().unwrap();
    let (pair, guard) = paired_root(directory.path(), "Drive", "workspace");
    fs::write(pair.local_root.join("inbound.md"), b"revised body").unwrap();
    let mut remote = inbound_entry(&pair);
    remote.revision = 2;
    fs::write(pair.local_root.join("inbound.md"), b"original body").unwrap();
    let mut state = DesktopState::default();
    state.configure_pair(pair.clone()).unwrap();
    let original = inbound_entry(&pair);
    state.baseline.insert(
        remote.id.clone(),
        BaselineEntry {
            remote_id: remote.id.clone(),
            parent_id: None,
            relative_path: PathBuf::from("inbound.md"),
            kind: "file".to_string(),
            content_hash: original.content_hash,
            revision: 1,
            directory_identity: None,
        },
    );
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    (directory, pair, guard, runtime, remote)
}

#[test]
fn concurrent_revision_retries_then_commits_only_matching_current_bytes() {
    let (_directory, pair, guard, runtime, remote) = fixture();
    let mut run = runtime.coordinator.begin_run().unwrap();
    let prior = run.state().baseline.clone();
    let mut cycle = SyncCycleBudget::new(SyncPassLimits::default());
    let mut reads = ReadBudget::new_cycle(100);
    let mut calls = 0;
    converge_test(&mut run, &mut cycle, &mut reads, |run, cycle, reads| {
        calls += 1;
        cycle.admit(std::slice::from_ref(&remote), &[])?;
        if calls == 2 {
            assert_eq!(run.state().baseline, prior);
            assert!(run.state().last_successful_sync.is_none());
            fs::write(pair.local_root.join("inbound.md"), b"revised body")?;
        }
        finish_baseline(run, reads, &pair, &guard, std::slice::from_ref(&remote))
    })
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(cycle.used().manifest_items, 2);
    assert_eq!(run.state().baseline.len(), 1);
    assert_eq!(run.state().baseline["inbound"].revision, 2);
    assert_eq!(
        run.state().baseline["inbound"].content_hash,
        remote.content_hash
    );
    assert!(run.state().last_successful_sync.is_some());
    assert_eq!(run.state().activity.len(), 1);
    assert!(run.state().last_error.is_none());
}

#[test]
fn continuously_changing_tree_stops_after_three_attempts_without_baseline_commit() {
    let (_directory, pair, guard, runtime, remote) = fixture();
    let mut run = runtime.coordinator.begin_run().unwrap();
    let prior = run.state().baseline.clone();
    let mut cycle = SyncCycleBudget::new(SyncPassLimits::default());
    let mut reads = ReadBudget::new_cycle(100);
    let mut calls = 0;
    let error = converge_test(&mut run, &mut cycle, &mut reads, |run, cycle, reads| {
        calls += 1;
        cycle.admit(std::slice::from_ref(&remote), &[])?;
        finish_baseline(run, reads, &pair, &guard, std::slice::from_ref(&remote))
    })
    .unwrap_err();
    assert!(matches!(error, DesktopError::SyncCycleBudgetExceeded(_)));
    assert_eq!(calls, 3);
    assert_eq!(cycle.used().manifest_items, 3);
    assert_eq!(run.state().baseline, prior);
    assert!(run.state().last_successful_sync.is_none());
    assert!(run.state().activity.is_empty());
}

#[test]
fn retry_keeps_accumulated_cycle_plan_budget() {
    let (_directory, pair, guard, runtime, remote) = fixture();
    let mut run = runtime.coordinator.begin_run().unwrap();
    let prior = run.state().baseline.clone();
    let mut cycle = SyncCycleBudget::new(SyncPassLimits {
        max_manifest_items: 1,
        ..SyncPassLimits::default()
    });
    let mut reads = ReadBudget::new_cycle(100);
    let mut calls = 0;
    let error = converge_test(&mut run, &mut cycle, &mut reads, |run, cycle, reads| {
        calls += 1;
        cycle.admit(std::slice::from_ref(&remote), &[])?;
        finish_baseline(run, reads, &pair, &guard, std::slice::from_ref(&remote))
    })
    .unwrap_err();
    assert!(matches!(error, DesktopError::SyncCycleBudgetExceeded(_)));
    assert_eq!(calls, 2);
    assert_eq!(cycle.used().manifest_items, 1);
    assert_eq!(run.state().baseline, prior);
}

#[test]
fn retry_final_inventory_keeps_accumulated_local_read_budget() {
    let (_directory, pair, guard, runtime, remote) = fixture();
    let mut run = runtime.coordinator.begin_run().unwrap();
    let prior = run.state().baseline.clone();
    let mut cycle = SyncCycleBudget::new(SyncPassLimits::default());
    let mut reads = ReadBudget::new_cycle(b"original body".len() as u64);
    let mut calls = 0;
    let error = converge_test(&mut run, &mut cycle, &mut reads, |run, _, reads| {
        calls += 1;
        finish_baseline(run, reads, &pair, &guard, std::slice::from_ref(&remote))
    })
    .unwrap_err();
    assert!(matches!(error, DesktopError::SyncCycleBudgetExceeded(_)));
    assert_eq!(calls, 2);
    assert_eq!(run.state().baseline, prior);
}

#[test]
fn disconnect_cancellation_stops_before_another_attempt() {
    let (_directory, pair, guard, runtime, remote) = fixture();
    let mut run = runtime.coordinator.begin_run().unwrap();
    let prior = run.state().baseline.clone();
    let mut cycle = SyncCycleBudget::new(SyncPassLimits::default());
    let mut reads = ReadBudget::new_cycle(100);
    let mut calls = 0;
    let mut request = None;
    let error = converge_test(&mut run, &mut cycle, &mut reads, |run, _, reads| {
        calls += 1;
        let result = finish_baseline(run, reads, &pair, &guard, std::slice::from_ref(&remote));
        request = Some(runtime.coordinator.request_disconnect()?);
        result
    })
    .unwrap_err();
    assert!(matches!(error, DesktopError::SyncCancelledForDisconnect));
    assert!(!request.as_ref().unwrap().is_ready().unwrap());
    assert_eq!(calls, 1);
    assert_eq!(run.state().baseline, prior);
}

#[test]
fn unrelated_invalid_state_is_never_retried_as_tree_change() {
    let (_directory, _pair, _guard, runtime, _) = fixture();
    let mut run = runtime.coordinator.begin_run().unwrap();
    let mut cycle = SyncCycleBudget::new(SyncPassLimits::default());
    let mut reads = ReadBudget::new_cycle(100);
    let mut calls = 0;
    let error = converge_test(&mut run, &mut cycle, &mut reads, |_, _, _| {
        calls += 1;
        Err(DesktopError::InvalidState(
            "unrelated state failure".to_string(),
        ))
    })
    .unwrap_err();
    assert!(matches!(error, DesktopError::InvalidState(_)));
    assert_eq!(calls, 1);
}

fn converge_test(
    run: &mut SyncRun,
    cycle: &mut SyncCycleBudget,
    reads: &mut ReadBudget,
    mut attempt: impl FnMut(
        &mut SyncRun,
        &mut SyncCycleBudget,
        &mut ReadBudget,
    ) -> CoreResult<SyncAttemptDisposition>,
) -> CoreResult<()> {
    let mut convergence = Convergence::default();
    loop {
        convergence.begin_attempt(run)?;
        let disposition = attempt(run, cycle, reads)?;
        if convergence.complete_attempt(run, disposition)? {
            return Ok(());
        }
    }
}
