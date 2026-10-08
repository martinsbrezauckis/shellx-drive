use crate::{
    auth::{Actor, AuthMode},
    error::ApiError,
};

use super::Storage;

#[test]
fn actor_workspace_selection_rejects_the_sentinel_before_fanout() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "bounded-workspaces@example.test";
    for index in 0..1_001 {
        storage
            .create_workspace(&format!("Bounded workspace {index:04}"), email)
            .unwrap();
    }
    let actor = Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };

    assert!(matches!(
        storage.list_workspaces_for_actor_bounded(&actor, 1_000),
        Err(ApiError::PayloadTooLarge(_))
    ));
    assert!(matches!(
        storage.list_sync_roots_for_actor(&actor),
        Err(ApiError::SyncRootDiscoveryOverflow)
    ));
}
