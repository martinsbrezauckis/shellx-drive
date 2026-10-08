//! Credential registry lifecycle regression coverage.

use super::*;

#[test]
fn disconnect_service_registry_lifecycle_round_trips_at_a_temp_path() {
    let temporary = tempfile::tempdir().expect("temporary registry directory");
    let path = temporary.path().join(REGISTRY_FILE);
    let account_key = "disconnect-capability-test-key";

    let mut registry = CredentialRegistry::load_from_path(path.clone()).expect("empty registry");
    registry
        .insert(DESKTOP_AGENT_DISCONNECT_SERVICE, account_key)
        .expect("disconnect service is admitted for insert");

    let loaded = CredentialRegistry::load_from_path(path.clone()).expect("persisted registry");
    assert_eq!(
        loaded
            .keys(DESKTOP_AGENT_DISCONNECT_SERVICE)
            .expect("disconnect service is admitted for lookup"),
        vec![account_key.to_string()]
    );
    assert!(loaded
        .keys(CANONICAL_SERVICE)
        .expect("canonical namespace remains separate")
        .is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        assert_eq!(
            fs::metadata(&path)
                .expect("private registry metadata")
                .mode()
                & 0o777,
            0o600
        );
    }

    let bytes_before_unknown_service = fs::read(&path).expect("persisted registry bytes");
    let mut registry = CredentialRegistry::load_from_path(path.clone()).expect("registry reload");
    assert!(registry
        .insert("com.shellx.drive.desktop.other", account_key)
        .is_err());
    assert_eq!(
        fs::read(&path).expect("registry bytes after rejected service"),
        bytes_before_unknown_service
    );

    let mut registry = CredentialRegistry::load_from_path(path.clone()).expect("registry reload");
    registry
        .remove(DESKTOP_AGENT_DISCONNECT_SERVICE, account_key)
        .expect("disconnect service is admitted for removal");

    assert!(CredentialRegistry::load_from_path(path)
        .expect("registry after removal")
        .keys(DESKTOP_AGENT_DISCONNECT_SERVICE)
        .expect("disconnect service is admitted after removal")
        .is_empty());
}
