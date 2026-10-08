use super::*;

#[path = "coordinator_tests/run_snapshot.rs"]
mod run_snapshot;

#[path = "coordinator_tests/all_roots.rs"]
mod all_roots;

#[path = "coordinator_tests/disconnect.rs"]
mod disconnect;

#[test]
fn durable_intermediate_state_does_not_release_the_reservation() {
    let coordinator = MirrorCoordinator::new(DesktopState::default());
    let mut operation = coordinator.begin_lifecycle_operation().unwrap();
    let mut journaled = coordinator.snapshot();
    journaled.last_error = Some("durable journal marker".to_string());
    operation
        .publish_persisted_state(journaled.clone())
        .unwrap();
    assert_eq!(
        coordinator.snapshot().last_error,
        Some("durable journal marker".to_string())
    );
    assert!(matches!(
        coordinator.begin_lifecycle_operation(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    operation.finish_state(journaled);
}
