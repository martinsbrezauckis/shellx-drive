use super::*;

fn foreign_record() -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://legacy.example.test",
        "legacy@example.test",
        "legacy-staged-session",
        Utc::now() - chrono::Duration::hours(1),
    )
    .unwrap()
}

#[test]
fn uncertain_exact_pending_deletion_retains_foreign_legacy_locator_after_restart() {
    let record = foreign_record();
    let credential = StoredSessionCredential {
        identity: SessionIdentity::new(&record.server_url, &record.account_email),
        session_id: Some(record.session_id.clone()),
        bearer_token: "synthetic-pending-bearer".into(),
    };
    let mut state = DesktopState {
        pending_remote_revocations: vec![record.clone()],
        ..DesktopState::default()
    };
    let original = state.clone();
    let result = finish_direct_retirement(&mut state, &credential, Some(record.clone()), |exact| {
        assert!(exact.same_remote_session(&record));
        let readback = classify_exact_credential_removal(
            Ok(()),
            Err(DesktopError::Credential(
                "synthetic readback failure".into(),
            )),
        );
        assert!(matches!(readback, ExactCredentialRemoval::Unknown));
        Err(DesktopError::Credential(
            "pending deletion needs retry".into(),
        ))
    });
    assert!(result.is_err());
    assert_eq!(
        state.pending_remote_revocations,
        original.pending_remote_revocations
    );
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    store.save(&state).unwrap();
    assert_eq!(
        store.load().unwrap().pending_remote_revocations,
        vec![record]
    );
}

#[test]
fn confirmed_pending_deletion_clears_only_its_exact_locator() {
    let record = foreign_record();
    let other = RemoteSessionRecord::new(
        &record.server_url,
        &record.account_email,
        "another-session",
        record.expires_at,
    )
    .unwrap();
    let credential = StoredSessionCredential {
        identity: SessionIdentity::new(&record.server_url, &record.account_email),
        session_id: Some(record.session_id.clone()),
        bearer_token: "synthetic-pending-bearer".into(),
    };
    let mut state = DesktopState {
        pending_remote_revocations: vec![record.clone(), other.clone()],
        ..DesktopState::default()
    };
    finish_direct_retirement(&mut state, &credential, Some(record.clone()), |exact| {
        assert!(exact.same_remote_session(&record));
        Ok(())
    })
    .unwrap();
    assert_eq!(state.pending_remote_revocations, vec![other]);
}

#[test]
fn canonical_direct_retirement_does_not_delete_a_pending_or_foreign_canonical_slot() {
    let record = foreign_record();
    let credential = StoredSessionCredential {
        identity: SessionIdentity::new(&record.server_url, &record.account_email),
        session_id: None,
        bearer_token: "synthetic-canonical-bearer".into(),
    };
    let mut state = DesktopState {
        active_remote_session: Some(record.clone()),
        ..DesktopState::default()
    };
    finish_direct_retirement(&mut state, &credential, Some(record), |_| {
        panic!("canonical retirement must not delete any pending slot")
    })
    .unwrap();
    assert!(state.active_remote_session.is_none());
}
