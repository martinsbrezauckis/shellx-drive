use super::*;

#[test]
fn legacy_drop_backups_default_to_unbound_inboxes() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    for (table, omissions) in [
        ("files", &["drop_inbox_owner_id"][..]),
        ("files", &["cover_bytes", "drop_inbox_owner_id"][..]),
        ("drops", &["inbox_file_id"][..]),
        ("drops", &["publication_pending", "inbox_file_id"][..]),
    ] {
        let expected = table_columns(&conn, table).unwrap();
        let legacy = expected
            .iter()
            .filter(|column| !omissions.contains(&column.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        assert!(backup_columns_are_compatible(table, &legacy, &expected));
    }
}

#[test]
fn legacy_auth_account_backups_default_the_totp_replay_counter() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let expected = table_columns(&conn, "auth_accounts").unwrap();
    let legacy = expected
        .iter()
        .filter(|column| column.as_str() != "totp_last_used_counter")
        .cloned()
        .collect::<Vec<_>>();
    assert!(backup_columns_are_compatible(
        "auth_accounts",
        &legacy,
        &expected
    ));
}

#[test]
fn legacy_publication_backups_default_to_already_published_resources() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    for table in [
        "auth_sessions",
        "app_tokens",
        "agent_principals",
        "agent_tokens",
        "agent_folder_grants",
        "workspace_invitations",
        "shares",
        "drops",
    ] {
        let expected = table_columns(&conn, table).unwrap();
        let legacy = expected
            .iter()
            .filter(|column| column.as_str() != "publication_pending")
            .cloned()
            .collect::<Vec<_>>();
        assert!(backup_columns_are_compatible(table, &legacy, &expected));
    }
}

#[test]
fn legacy_agent_backups_accept_missing_creator_authority_provenance() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    for table in ["agent_principals", "agent_folder_grants"] {
        let expected = table_columns(&conn, table).unwrap();
        let legacy = expected
            .iter()
            .filter(|column| column.as_str() != "creator_authority_kind")
            .cloned()
            .collect::<Vec<_>>();
        assert!(backup_columns_are_compatible(table, &legacy, &expected));
    }
}

#[test]
fn oldest_agent_backups_accept_both_historical_omissions() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    for table in ["agent_principals", "agent_folder_grants"] {
        let expected = table_columns(&conn, table).unwrap();
        let legacy = expected
            .iter()
            .filter(|column| {
                !matches!(
                    column.as_str(),
                    "creator_authority_kind" | "publication_pending"
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        assert!(backup_columns_are_compatible(table, &legacy, &expected));
    }
}

#[test]
fn legacy_email_backups_default_workspace_attribution() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let expected = table_columns(&conn, "email_outbox").unwrap();
    let legacy = expected
        .iter()
        .filter(|column| column.as_str() != "workspace_id")
        .cloned()
        .collect::<Vec<_>>();
    assert!(backup_columns_are_compatible(
        "email_outbox",
        &legacy,
        &expected
    ));
}

#[test]
fn legacy_office_backups_default_to_retired_generationless_capabilities() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let expected = table_columns(&conn, "office_edit_sessions").unwrap();
    let legacy = expected
        .iter()
        .filter(|column| column.as_str() != "source_credential_generation")
        .cloned()
        .collect::<Vec<_>>();
    assert!(backup_columns_are_compatible(
        "office_edit_sessions",
        &legacy,
        &expected
    ));
}
