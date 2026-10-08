use super::*;

#[test]
fn same_size_post_plan_replacement_does_not_match_the_upload_witness() {
    let planned = local_at("report.pdf", "snapshot-hash", 128);
    let replacement = local_at("report.pdf", "different-hash", 128);

    assert!(!upload_precondition_matches(&planned, &replacement));
}

#[test]
fn upload_actions_retain_the_exact_plan_time_local_witness() {
    let new_local = local_at("new.txt", "new-hash", 3);
    let new_plan = plan_reconciliation(
        &BTreeMap::new(),
        None,
        &[],
        std::slice::from_ref(&new_local),
        timestamp(),
    )
    .unwrap();
    assert!(matches!(
        new_plan.actions.as_slice(),
        [SyncAction::UploadNew { local, .. }] if local == &new_local
    ));

    let changed_local = local("changed", 7);
    let existing_plan = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "base", 1)],
        std::slice::from_ref(&changed_local),
        timestamp(),
    )
    .unwrap();
    assert!(matches!(
        existing_plan.actions.as_slice(),
        [SyncAction::UploadExisting { local, .. }] if local == &changed_local
    ));
}
