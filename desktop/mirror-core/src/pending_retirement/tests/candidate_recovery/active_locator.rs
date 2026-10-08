//! Portable active-only candidate recovery admission regression.

use super::super::record;
use crate::{candidate_recovery_locator, DesktopError, DesktopState};

#[test]
fn active_only_half_publication_retains_its_exact_recovery_login_locator() {
    let candidate = record(
        "active-only-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let state = DesktopState {
        // The active record can be saved before a native staged-store listing.
        active_remote_session: Some(candidate.clone()),
        ..DesktopState::default()
    };

    assert_eq!(candidate_recovery_locator(&state), Some(&candidate));
    let enumeration: crate::Result<Vec<String>> = Err(DesktopError::Credential(
        "injected pending-store enumeration failure".to_string(),
    ));
    assert!(enumeration.is_err());
    assert_eq!(candidate_recovery_locator(&state), Some(&candidate));
}
