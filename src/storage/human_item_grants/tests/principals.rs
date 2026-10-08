use super::*;

fn create_account(storage: &Storage, email: &str) {
    storage
        .create_auth_account(
            email,
            "picker-test-password",
            false,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
}

#[test]
fn account_principal_picker_preserves_exact_email_and_bounds_case_folded_prefixes() {
    let (_directory, storage, _) = storage();
    for email in [
        "marcel@example.test",
        "marcus@example.test",
        "marie@example.test",
        "marie@example.test.example",
    ] {
        create_account(&storage, email);
    }
    for index in 0..=50 {
        create_account(&storage, &format!("limit-{index:02}@example.test"));
    }
    storage
        .update_auth_account(
            "marcus@example.test",
            Some(true),
            None,
            None,
            false,
            None,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();

    let prefix = storage.list_share_principals("account", "MAR", 50).unwrap();
    assert_eq!(
        prefix
            .iter()
            .map(|principal| principal.reference.as_str())
            .collect::<Vec<_>>(),
        vec![
            "marcel@example.test",
            "marie@example.test",
            "marie@example.test.example"
        ]
    );
    assert!(prefix
        .iter()
        .all(|principal| principal.auth_enabled == Some(true)));
    assert!(prefix.iter().all(|principal| principal.can_receive_grant));
    assert!(storage
        .list_share_principals("account", "MARCUS@EXAMPLE.TEST", 50)
        .unwrap()
        .is_empty());

    let exact = storage
        .list_share_principals("account", "MARIE@EXAMPLE.TEST", 50)
        .unwrap();
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].reference, "marie@example.test");

    assert_eq!(
        storage
            .list_share_principals("account", "mar", 1)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        storage
            .list_share_principals("account", "limit-", usize::MAX)
            .unwrap()
            .len(),
        50
    );
}
