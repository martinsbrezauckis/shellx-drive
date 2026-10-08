use super::policy::sync_location_status;

#[test]
fn retained_review_stays_actionable_when_its_root_also_has_an_error() {
    assert_eq!(
        sync_location_status(1, Some("Drive returned an error"), false, false),
        "needs_review"
    );
}

#[test]
fn root_without_a_review_still_surfaces_its_error() {
    assert_eq!(
        sync_location_status(0, Some("Drive returned an error"), false, false),
        "error"
    );
}
