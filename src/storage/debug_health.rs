use chrono::Utc;
use rusqlite::params;
use serde::Serialize;

use super::{agent_access::ACTIVE_GRANT_CREATOR_PREDICATE, debug::opaque_ref, Storage};
use crate::error::ApiResult;

#[derive(Debug, Clone, Serialize)]
pub struct DebugAgentHealthSummary {
    pub principal_ref: String,
    pub name_present: bool,
    pub creator_ref: String,
    pub created_at: String,
    pub disabled: bool,
    pub token_present: bool,
    pub token_ref: Option<String>,
    pub token_active: bool,
    pub token_expires_at: Option<String>,
    pub token_last_used_at: Option<String>,
    pub token_revoked: bool,
    pub grants: i64,
    pub active_grants: i64,
    pub revoked_grants: i64,
    pub expired_grants: i64,
    pub creator_unauthorized_grants: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugFileAccessSummary {
    pub workspace_ref: String,
    pub tracked_files: i64,
    pub access_count: i64,
    pub download_count: i64,
    pub last_accessed_at: Option<String>,
    pub last_downloaded_at: Option<String>,
}

impl Storage {
    pub fn debug_agent_health_summaries(
        &self,
        limit: i64,
    ) -> ApiResult<(i64, Vec<DebugAgentHealthSummary>)> {
        let conn = self.conn.lock().unwrap();
        let total = conn.query_row("SELECT COUNT(*) FROM agent_principals", [], |row| {
            row.get(0)
        })?;
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT p.id, LENGTH(TRIM(p.name)) > 0, p.created_by, p.created_at,
                    p.disabled_at IS NOT NULL,
                    token.id, token.expires_at, token.last_used_at,
                    token.revoked_at IS NOT NULL,
                    token.id IS NOT NULL AND p.disabled_at IS NULL
                        AND token.revoked_at IS NULL
                        AND julianday(token.expires_at) > julianday(?1),
                    (SELECT COUNT(*) FROM agent_folder_grants all_grants
                     WHERE all_grants.principal_id = p.id),
                    (SELECT COUNT(*) FROM agent_folder_grants g
                     WHERE g.principal_id = p.id AND g.revoked_at IS NULL
                       AND julianday(g.expires_at) > julianday(?1)
                       AND {ACTIVE_GRANT_CREATOR_PREDICATE}),
                    (SELECT COUNT(*) FROM agent_folder_grants revoked_grants
                     WHERE revoked_grants.principal_id = p.id
                       AND revoked_grants.revoked_at IS NOT NULL),
                    (SELECT COUNT(*) FROM agent_folder_grants expired_grants
                     WHERE expired_grants.principal_id = p.id
                       AND expired_grants.revoked_at IS NULL
                       AND julianday(expired_grants.expires_at) <= julianday(?1)),
                    (SELECT COUNT(*) FROM agent_folder_grants g
                     WHERE g.principal_id = p.id AND g.revoked_at IS NULL
                       AND julianday(g.expires_at) > julianday(?1)
                       AND NOT {ACTIVE_GRANT_CREATOR_PREDICATE})
             FROM agent_principals p
             LEFT JOIN agent_tokens token ON token.id = (
                 SELECT current_token.id FROM agent_tokens current_token
                 WHERE current_token.principal_id = p.id
                 ORDER BY current_token.created_at DESC, current_token.id DESC LIMIT 1
             )
             ORDER BY p.created_at DESC, p.id DESC LIMIT ?2"
        );
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params![now, limit], |row| {
            let principal_id: String = row.get(0)?;
            let creator: String = row.get(2)?;
            let token_id: Option<String> = row.get(5)?;
            Ok(DebugAgentHealthSummary {
                principal_ref: opaque_ref("agent-principal", &principal_id),
                name_present: row.get(1)?,
                creator_ref: opaque_ref("actor", &creator),
                created_at: row.get(3)?,
                disabled: row.get(4)?,
                token_present: token_id.is_some(),
                token_ref: token_id
                    .as_deref()
                    .map(|value| opaque_ref("agent-token", value)),
                token_expires_at: row.get(6)?,
                token_last_used_at: row.get(7)?,
                token_revoked: row.get(8)?,
                token_active: row.get(9)?,
                grants: row.get(10)?,
                active_grants: row.get(11)?,
                revoked_grants: row.get(12)?,
                expired_grants: row.get(13)?,
                creator_unauthorized_grants: row.get(14)?,
            })
        })?;
        Ok((total, rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    pub fn debug_file_access_summaries(
        &self,
        limit: i64,
    ) -> ApiResult<(i64, Vec<DebugFileAccessSummary>)> {
        let conn = self.conn.lock().unwrap();
        let total = conn.query_row(
            "SELECT COUNT(*) FROM (
                 SELECT workspace_id FROM file_access_stats GROUP BY workspace_id
             )",
            [],
            |row| row.get(0),
        )?;
        let mut statement = conn.prepare(
            "SELECT workspace_id, COUNT(*),
                    COALESCE(SUM(access_count), 0),
                    COALESCE(SUM(download_count), 0),
                    MAX(last_accessed_at), MAX(last_downloaded_at)
             FROM file_access_stats
             GROUP BY workspace_id
             ORDER BY (SUM(access_count) + SUM(download_count)) DESC,
                      workspace_id ASC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], |row| {
            let workspace_id: String = row.get(0)?;
            Ok(DebugFileAccessSummary {
                workspace_ref: opaque_ref("workspace", &workspace_id),
                tracked_files: row.get(1)?,
                access_count: row.get(2)?,
                download_count: row.get(3)?,
                last_accessed_at: row.get(4)?,
                last_downloaded_at: row.get(5)?,
            })
        })?;
        Ok((total, rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }
}
