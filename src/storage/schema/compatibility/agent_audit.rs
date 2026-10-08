use rusqlite::Connection;

use super::super::super::ensure_column;

pub(super) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    // Existing bearers retain their narrow folder scope; only newly issued
    // `delegated` tokens may enter ordinary Drive routes.
    ensure_column(
        conn,
        "agent_tokens",
        "delegation_kind",
        "delegation_kind TEXT NOT NULL DEFAULT 'folder' CHECK (delegation_kind IN ('folder', 'delegated'))",
    )?;
    ensure_column(
        conn,
        "security_events",
        "credential_ref",
        "credential_ref TEXT",
    )?;
    // A missing parent binding must never turn an external delegation into a
    // local-account delegation after restore or a partial upgrade.
    ensure_column(
        conn,
        "agent_principals",
        "delegation_parent_kind",
        "delegation_parent_kind TEXT NOT NULL DEFAULT 'local' \
         CHECK (delegation_parent_kind IN ('local', 'external_sso'))",
    )?;
    ensure_column(
        conn,
        "delegated_agent_parent_sessions",
        "parent_token_hash",
        "parent_token_hash TEXT NOT NULL DEFAULT ''",
    )
}
