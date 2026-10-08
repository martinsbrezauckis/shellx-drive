use shellx_drive_desktop_core::{candidate_recovery_locator, DesktopState};

use crate::{application::Runtime, session_identity::SessionIdentity};

pub(super) fn sync_location_status(
    review_count: usize,
    error: Option<&str>,
    paused: bool,
    active: bool,
) -> &'static str {
    if review_count > 0 {
        "needs_review"
    } else if error.is_some() {
        "error"
    } else if paused {
        "paused"
    } else if active {
        "current"
    } else {
        "managed"
    }
}
/// Recovery projection uses only retained non-secret identity metadata. A
/// cached slot identity is usable only when the cache identifies one account.
pub(super) fn unpaired_identity(
    runtime: &Runtime,
    state: &DesktopState,
    recovery_pending: bool,
) -> Option<SessionIdentity> {
    if !recovery_pending {
        return runtime.session.lock().expect("session lock").clone();
    }
    if let Some(record) = candidate_recovery_locator(state) {
        return Some(SessionIdentity::new(
            &record.server_url,
            &record.account_email,
        ));
    }
    let identities = runtime
        .candidate_recovery_identities
        .lock()
        .expect("candidate recovery identity lock");
    (identities.len() == 1)
        .then(|| SessionIdentity::parse_canonical_credential_key(identities.first()?))
        .flatten()
}
