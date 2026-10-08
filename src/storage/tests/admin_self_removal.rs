use super::*;

#[test]
fn self_removal_proof_is_rejected_after_a_concurrent_security_change() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (operator, credential) = test_operator();
    let target = "self-removal-race@example.test";

    storage
        .create_auth_account(
            target,
            "initial-password-hash",
            true,
            &operator,
            &credential,
        )
        .unwrap();
    storage
        .create_auth_account(
            "remaining-admin@example.test",
            "remaining-password-hash",
            true,
            &operator,
            &credential,
        )
        .unwrap();
    let stale_proof = storage.get_auth_account_secret(target).unwrap().unwrap();

    storage
        .update_auth_account(
            target,
            None,
            None,
            Some("concurrently-replaced-password-hash"),
            false,
            None,
            &operator,
            &credential,
        )
        .unwrap();
    assert!(matches!(
        storage.update_auth_account(
            target,
            None,
            Some(false),
            None,
            false,
            Some(stale_proof.security_version),
            &operator,
            &credential,
        ),
        Err(ApiError::Conflict)
    ));
    assert!(storage.get_auth_account(target).unwrap().unwrap().is_admin);
}

#[test]
fn account_update_cannot_remove_the_last_enabled_administrator() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (operator, credential) = test_operator();
    let target = "only-admin@example.test";
    storage
        .create_auth_account(
            target,
            "only-admin-password-hash",
            true,
            &operator,
            &credential,
        )
        .unwrap();

    assert!(matches!(
        storage.update_auth_account(
            target,
            None,
            Some(false),
            None,
            false,
            None,
            &operator,
            &credential,
        ),
        Err(ApiError::Conflict)
    ));
    assert!(storage.get_auth_account(target).unwrap().unwrap().is_admin);
}
