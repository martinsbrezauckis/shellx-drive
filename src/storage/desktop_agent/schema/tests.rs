use chrono::{Duration, Utc};

use crate::storage::{Storage, VerifiedLocalSecondFactor};

#[test]
fn legacy_command_schema_upgrades_before_auth_session_pruning() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    {
        let storage = Storage::open(path.clone()).unwrap();
        storage.migrate().unwrap();
        let conn = storage.conn.lock().unwrap();
        conn.execute_batch(
            "DROP TRIGGER desktop_agent_revoke_session_on_revocation;
             DROP TRIGGER desktop_agent_revoke_session_on_deletion;
             DROP TRIGGER desktop_agent_revoke_owner_on_security_change;
             DROP TABLE desktop_agent_disconnect_completions;
             CREATE TABLE desktop_agent_disconnect_completions (
               command_id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
               owner_session_id TEXT NOT NULL, owner_security_version INTEGER NOT NULL,
               lease_id TEXT NOT NULL, pair_fingerprint TEXT NOT NULL,
               capability_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
               retirement_authorized_at TEXT, completed_at TEXT
             );
             ALTER TABLE desktop_agent_commands DROP COLUMN terminal_event_sequence;
             -- An interrupted historical upgrade could leave this new trigger
             -- beside the old command table. SQLite does not reject its
             -- missing column until an auth-session mutation prepares it.
             CREATE TRIGGER desktop_agent_revoke_session_on_deletion
             AFTER DELETE ON auth_sessions BEGIN
               UPDATE desktop_agent_commands
                  SET terminal_event_sequence = -1 WHERE 0;
             END;",
        )
        .unwrap();
    }

    let storage = Storage::open(path).unwrap();
    storage.migrate().unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        let has_terminal_sequence: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('desktop_agent_commands')
                     WHERE name = 'terminal_event_sequence'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_terminal_sequence);
        let has_disconnect_completion: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table'
                   AND name = 'desktop_agent_disconnect_completions')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_disconnect_completion);
        let has_retirement_witness: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('desktop_agent_disconnect_completions')
                     WHERE name = 'retirement_assertion_hash'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_retirement_witness);
    }

    storage
        .bootstrap_auth_account("migration-login@example.test", "password-hash")
        .unwrap();
    let account = storage
        .get_auth_account_secret("migration-login@example.test")
        .unwrap()
        .unwrap();
    let session = storage
        .record_verified_local_auth_session(
            "migration-login-session",
            &account,
            VerifiedLocalSecondFactor::NotRequired,
            "local-password",
            "migration-login-token-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            None,
            None,
        )
        .unwrap();
    assert_eq!(session.actor_email, account.email);
}
