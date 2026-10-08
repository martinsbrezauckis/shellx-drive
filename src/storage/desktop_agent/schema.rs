use rusqlite::Connection;

mod compatibility;

#[cfg(test)]
mod tests;
use compatibility::install_compatibility_columns;
/// Called from the normal schema migration. These tables are intentionally
/// absent from `BACKUP_TABLES`; restore purges them as ephemeral controls.
pub(in crate::storage) fn install_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS desktop_agent_devices (
             id TEXT PRIMARY KEY,
             owner_account_id TEXT NOT NULL,
             owner_session_id TEXT NOT NULL,
             owner_security_version INTEGER NOT NULL,
             pair_fingerprint TEXT NOT NULL,
             credential_hash TEXT NOT NULL,
             platform TEXT NOT NULL CHECK (platform IN ('windows', 'macos', 'linux')),
             app_version TEXT NOT NULL,
             state TEXT NOT NULL CHECK (state IN ('active', 'frozen', 'retired', 'revoked')),
             candidate_recovery INTEGER NOT NULL DEFAULT 0 CHECK (candidate_recovery IN (0, 1)),
             created_at TEXT NOT NULL,
             last_seen_at TEXT,
             last_ready_at TEXT,
             frozen_at TEXT,
             retired_at TEXT,
             revoked_at TEXT
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_desktop_agent_devices_credential
             ON desktop_agent_devices(credential_hash);
         CREATE INDEX IF NOT EXISTS idx_desktop_agent_devices_owner_active
             ON desktop_agent_devices(owner_account_id, state, created_at DESC);

         CREATE TABLE IF NOT EXISTS desktop_agent_commands (
             id TEXT PRIMARY KEY,
             owner_account_id TEXT NOT NULL,
             device_id TEXT,
             target_key TEXT NOT NULL,
             requester_kind TEXT NOT NULL CHECK (requester_kind IN ('user_session', 'delegated_agent')),
             requester_id TEXT NOT NULL,
             requester_principal_id TEXT NOT NULL,
             owner_is_admin_at_enqueue INTEGER NOT NULL CHECK (owner_is_admin_at_enqueue IN (0, 1)),
             owner_security_version INTEGER NOT NULL,
             kind TEXT NOT NULL,
             payload_json TEXT NOT NULL,
             payload_hash TEXT NOT NULL,
             request_id TEXT NOT NULL,
             expires_at TEXT NOT NULL,
             status TEXT NOT NULL,
             lease_id TEXT,
             lease_expires_at TEXT,
             lease_event_sequence INTEGER,
             lease_phase TEXT,
             lease_progress_basis_points INTEGER,
             created_at TEXT NOT NULL,
             accepted_at TEXT,
             started_at TEXT,
             finished_at TEXT,
             terminal_code TEXT,
             result_code TEXT,
             result_json TEXT,
             terminal_event_sequence INTEGER,
             FOREIGN KEY (device_id) REFERENCES desktop_agent_devices(id) ON DELETE SET NULL,
             UNIQUE(owner_account_id, requester_principal_id, target_key, request_id)
         );
         CREATE INDEX IF NOT EXISTS idx_desktop_agent_commands_device_queue
             ON desktop_agent_commands(device_id, status, expires_at, created_at);
         CREATE INDEX IF NOT EXISTS idx_desktop_agent_commands_owner_page
             ON desktop_agent_commands(owner_account_id, created_at DESC, id DESC);

         CREATE TABLE IF NOT EXISTS desktop_agent_command_events (
             command_id TEXT NOT NULL,
             sequence INTEGER NOT NULL,
             at TEXT NOT NULL,
             status TEXT NOT NULL,
             phase TEXT,
             progress_basis_points INTEGER,
             terminal_code TEXT,
             result_code TEXT,
             result_json TEXT,
             PRIMARY KEY (command_id, sequence),
             FOREIGN KEY (command_id) REFERENCES desktop_agent_commands(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_desktop_agent_events_command
             ON desktop_agent_command_events(command_id, sequence DESC);

         -- Stores only a one-time Disconnect completion hash, never restored authority.
         CREATE TABLE IF NOT EXISTS desktop_agent_disconnect_completions (
             command_id TEXT PRIMARY KEY,
             device_id TEXT NOT NULL,
             owner_session_id TEXT NOT NULL,
             owner_security_version INTEGER NOT NULL,
             lease_id TEXT NOT NULL,
             pair_fingerprint TEXT NOT NULL,
             capability_hash TEXT NOT NULL UNIQUE,
             retirement_assertion_hash TEXT,
             expires_at TEXT NOT NULL,
             retirement_authorized_at TEXT,
             completed_at TEXT,
             FOREIGN KEY (command_id) REFERENCES desktop_agent_commands(id) ON DELETE CASCADE,
             FOREIGN KEY (device_id) REFERENCES desktop_agent_devices(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_desktop_agent_disconnect_completion_device
             ON desktop_agent_disconnect_completions(device_id, completed_at);",
    )?;
    install_compatibility_columns(conn)?;
    install_parent_invalidation_triggers(conn)
}

fn install_parent_invalidation_triggers(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS desktop_agent_revoke_session_on_revocation;
         DROP TRIGGER IF EXISTS desktop_agent_revoke_session_on_deletion;
         DROP TRIGGER IF EXISTS desktop_agent_revoke_owner_on_security_change;
         CREATE TRIGGER desktop_agent_revoke_session_on_revocation
         AFTER UPDATE OF revoked_at ON auth_sessions
         WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
         BEGIN
           UPDATE desktop_agent_devices
              SET state = 'revoked', credential_hash = 'revoked:' || id,
                  candidate_recovery = 0, revoked_at = COALESCE(revoked_at, NEW.revoked_at)
            WHERE owner_session_id = NEW.id AND state IN ('active', 'frozen')
              AND NOT EXISTS (
                  SELECT 1 FROM desktop_agent_disconnect_completions c
                   WHERE c.device_id = desktop_agent_devices.id
                     AND c.owner_session_id = NEW.id
                     AND c.retirement_authorized_at IS NOT NULL AND c.completed_at IS NULL
              );
           UPDATE desktop_agent_commands
              SET status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE 'interrupted' END,
                  finished_at = NEW.revoked_at,
                  terminal_code = CASE WHEN status = 'queued'
                                       THEN 'cancelled_before_start' ELSE 'authorization_lost' END,
                  result_code = NULL, result_json = NULL, lease_id = NULL, lease_expires_at = NULL,
                  lease_event_sequence = NULL, lease_phase = NULL,
                  lease_progress_basis_points = NULL, terminal_event_sequence = -1
            WHERE device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_session_id = NEW.id)
              AND status IN ('queued', 'leased', 'acknowledged', 'running', 'relaunch_pending', 'cancel_requested')
              AND NOT EXISTS (
                  SELECT 1 FROM desktop_agent_disconnect_completions c
                   WHERE c.command_id = desktop_agent_commands.id
                     AND c.owner_session_id = NEW.id
                     AND c.retirement_authorized_at IS NOT NULL AND c.completed_at IS NULL
              );
           INSERT INTO desktop_agent_command_events
             (command_id, sequence, at, status, terminal_code)
           SELECT c.id, COALESCE((SELECT MAX(e.sequence) + 1
                                   FROM desktop_agent_command_events e WHERE e.command_id = c.id), 1),
                  NEW.revoked_at, c.status, c.terminal_code
             FROM desktop_agent_commands c
            WHERE c.device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_session_id = NEW.id)
              AND c.terminal_event_sequence = -1
              AND c.status IN ('cancelled', 'interrupted');
           UPDATE desktop_agent_commands SET terminal_event_sequence = NULL
            WHERE device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_session_id = NEW.id)
              AND terminal_event_sequence = -1;
         END;

         CREATE TRIGGER desktop_agent_revoke_session_on_deletion
         AFTER DELETE ON auth_sessions
         BEGIN
           UPDATE desktop_agent_devices
              SET state = 'revoked', credential_hash = 'revoked:' || id,
                  candidate_recovery = 0,
                  revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            WHERE owner_session_id = OLD.id AND state IN ('active', 'frozen')
              AND NOT EXISTS (
                  SELECT 1 FROM desktop_agent_disconnect_completions c
                   WHERE c.device_id = desktop_agent_devices.id
                     AND c.owner_session_id = OLD.id
                     AND c.retirement_authorized_at IS NOT NULL AND c.completed_at IS NULL
              );
           UPDATE desktop_agent_commands
              SET status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE 'interrupted' END,
                  finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                  terminal_code = CASE WHEN status = 'queued'
                                       THEN 'cancelled_before_start' ELSE 'authorization_lost' END,
                  result_code = NULL, result_json = NULL, lease_id = NULL, lease_expires_at = NULL,
                  lease_event_sequence = NULL, lease_phase = NULL,
                  lease_progress_basis_points = NULL, terminal_event_sequence = -1
            WHERE device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_session_id = OLD.id)
              AND status IN ('queued', 'leased', 'acknowledged', 'running', 'relaunch_pending', 'cancel_requested')
              AND NOT EXISTS (
                  SELECT 1 FROM desktop_agent_disconnect_completions c
                   WHERE c.command_id = desktop_agent_commands.id
                     AND c.owner_session_id = OLD.id
                     AND c.retirement_authorized_at IS NOT NULL AND c.completed_at IS NULL
              );
           INSERT INTO desktop_agent_command_events
             (command_id, sequence, at, status, terminal_code)
           SELECT c.id, COALESCE((SELECT MAX(e.sequence) + 1
                                   FROM desktop_agent_command_events e WHERE e.command_id = c.id), 1),
                  c.finished_at, c.status, c.terminal_code
             FROM desktop_agent_commands c
            WHERE c.device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_session_id = OLD.id)
              AND c.terminal_event_sequence = -1
              AND c.status IN ('cancelled', 'interrupted');
           UPDATE desktop_agent_commands SET terminal_event_sequence = NULL
            WHERE device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_session_id = OLD.id)
              AND terminal_event_sequence = -1;
         END;

         CREATE TRIGGER desktop_agent_revoke_owner_on_security_change
         AFTER UPDATE OF security_version, disabled_at ON auth_accounts
         WHEN NEW.security_version <> OLD.security_version
              OR (OLD.disabled_at IS NULL AND NEW.disabled_at IS NOT NULL)
         BEGIN
           UPDATE desktop_agent_devices
              SET state = 'revoked', credential_hash = 'revoked:' || id,
                  candidate_recovery = 0,
                  revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            WHERE owner_account_id = NEW.user_id AND state IN ('active', 'frozen');
           UPDATE desktop_agent_commands
              SET status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE 'interrupted' END,
                  finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                  terminal_code = CASE WHEN status = 'queued'
                                       THEN 'cancelled_before_start' ELSE 'authorization_lost' END,
                  result_code = NULL, result_json = NULL, lease_id = NULL, lease_expires_at = NULL,
                  lease_event_sequence = NULL, lease_phase = NULL,
                  lease_progress_basis_points = NULL, terminal_event_sequence = -1
            WHERE device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_account_id = NEW.user_id)
              AND status IN ('queued', 'leased', 'acknowledged', 'running', 'relaunch_pending', 'cancel_requested');
           INSERT INTO desktop_agent_command_events
             (command_id, sequence, at, status, terminal_code)
           SELECT c.id, COALESCE((SELECT MAX(e.sequence) + 1
                                   FROM desktop_agent_command_events e WHERE e.command_id = c.id), 1),
                  c.finished_at, c.status, c.terminal_code
             FROM desktop_agent_commands c
            WHERE c.device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_account_id = NEW.user_id)
              AND c.terminal_event_sequence = -1
              AND c.status IN ('cancelled', 'interrupted');
           UPDATE desktop_agent_commands SET terminal_event_sequence = NULL
            WHERE device_id IN (SELECT id FROM desktop_agent_devices WHERE owner_account_id = NEW.user_id)
              AND terminal_event_sequence = -1;
         END;",
    )
}
