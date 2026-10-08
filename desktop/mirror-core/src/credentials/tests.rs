use super::*;
use crate::DesktopError;

#[test]
fn fake_store_never_requires_a_file() {
    let store = FakeCredentialStore::default();
    assert_eq!(store.get("account").unwrap(), None);
    store.set("account", "secret").unwrap();
    assert_eq!(store.get("account").unwrap().as_deref(), Some("secret"));
    store.delete("account").unwrap();
    assert_eq!(store.get("account").unwrap(), None);
}

#[test]
fn windows_target_filter_matches_only_this_service_and_its_exact_account_key() {
    let account_key = "https://drive.example|person@example.test";
    let target = format!("{account_key}.{WINDOWS_CREDENTIAL_SERVICE}");
    assert!(is_windows_keyring_target_for_service(&target, account_key));
    assert!(has_windows_keyring_service_suffix(&target));

    assert!(!is_windows_keyring_target_for_service(
        &target,
        "https://drive.example|other@example.test"
    ));
    assert!(!is_windows_keyring_target_for_service(
        "https://drive.example|person@example.test.com.shellx.drive.desktop.extra",
        account_key
    ));
    assert!(!is_windows_keyring_target_for_service(
        "https://drive.example|person@example.test.com.shellx.drive.desktop",
        ""
    ));
    assert!(!has_windows_keyring_service_suffix(
        "https://drive.example|person@example.test.com.shellx.drive.desktop.extra"
    ));
}

#[test]
fn pending_candidate_targets_are_a_distinct_fixed_service() {
    let account_key = "https://drive.example|person@example.test|shellx-session:candidate";
    let service = "com.shellx.drive.desktop.pending-candidate";
    let target = format!("{account_key}.{service}");

    assert!(is_windows_keyring_target_for_named_service(
        &target,
        account_key,
        service
    ));
    assert!(!has_windows_keyring_service_suffix(&target));
    assert!(!is_windows_keyring_target_for_service(&target, account_key));
}

#[test]
fn windows_metadata_reader_stops_at_nul_within_the_documented_bound() {
    let terminated = "person@example.test"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    assert_eq!(
        unsafe { read_wide_metadata(terminated.as_ptr(), terminated.len() + 4) },
        Some("person@example.test".to_string())
    );

    let unterminated = "missing terminator".encode_utf16().collect::<Vec<_>>();
    assert_eq!(
        unsafe { read_wide_metadata(unterminated.as_ptr(), unterminated.len()) },
        None
    );
}

#[test]
fn post_write_failure_uses_exact_readback_not_the_provider_result() {
    let failed_after_write = Err(DesktopError::Credential("injected".to_string()));
    assert_eq!(
        classify_exact_credential_write(
            failed_after_write,
            Ok(Some("candidate".to_string())),
            "candidate",
        ),
        ExactCredentialWrite::Written
    );
    assert_eq!(
        classify_exact_credential_write(
            Err(DesktopError::Credential("injected".to_string())),
            Ok(Some("previous".to_string())),
            "candidate",
        ),
        ExactCredentialWrite::NotWritten
    );
    assert_eq!(
        classify_exact_credential_write(
            Err(DesktopError::Credential("injected".to_string())),
            Err(DesktopError::Credential("injected read".to_string())),
            "candidate",
        ),
        ExactCredentialWrite::Unknown
    );
}

#[test]
fn post_delete_failure_uses_exact_readback_not_the_provider_result() {
    assert_eq!(
        classify_exact_credential_removal(
            Err(DesktopError::Credential("injected".to_string())),
            Ok(None),
        ),
        ExactCredentialRemoval::Removed
    );
    assert_eq!(
        classify_exact_credential_removal(
            Err(DesktopError::Credential("injected".to_string())),
            Ok(Some("candidate".to_string())),
        ),
        ExactCredentialRemoval::Retained
    );
    assert_eq!(
        classify_exact_credential_removal(
            Err(DesktopError::Credential("injected".to_string())),
            Err(DesktopError::Credential("injected read".to_string())),
        ),
        ExactCredentialRemoval::Unknown
    );
}

#[test]
fn staged_candidate_crash_recovery_is_fail_closed_on_read_uncertainty() {
    assert_eq!(
        classify_exact_credential_readback(Ok(Some("candidate".to_string())), "candidate"),
        ExactCredentialRead::Matches
    );
    assert_eq!(
        classify_exact_credential_readback(Ok(Some("previous".to_string())), "candidate"),
        ExactCredentialRead::DifferentOrAbsent
    );
    assert_eq!(
        classify_exact_credential_readback(
            Err(DesktopError::Credential("injected read".to_string())),
            "candidate",
        ),
        ExactCredentialRead::Unknown
    );
}
