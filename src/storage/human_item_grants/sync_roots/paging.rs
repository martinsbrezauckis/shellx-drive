use rusqlite::{params, Transaction};

use crate::error::ApiResult;

const SYNC_ROOT_GRANT_SCAN_PAGE: i64 = 128;

type GrantScanRow = (String, String, String, String);

pub(super) fn next_grant_page_in_tx(
    tx: &Transaction<'_>,
    actor_email: &str,
    after_file_id: Option<&str>,
    after_grant_id: Option<&str>,
) -> ApiResult<Vec<GrantScanRow>> {
    let mut statement = tx.prepare(
        "SELECT g.id, g.workspace_id, g.root_file_id, g.role
         FROM human_item_grants g JOIN files f ON f.id = g.root_file_id
         WHERE g.revoked_at IS NULL AND g.publication_pending = 0 AND f.trashed = 0
           AND EXISTS (SELECT 1 FROM auth_accounts a WHERE a.email = ?1 AND a.disabled_at IS NULL)
           AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
           AND (g.principal_kind = 'everyone' OR (g.principal_kind = 'account' AND EXISTS (SELECT 1 FROM users u JOIN auth_accounts a ON a.user_id = u.id WHERE u.id = g.principal_ref AND u.email = ?1 AND a.disabled_at IS NULL)) OR (g.principal_kind = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN users u ON u.id = gm.user_id JOIN auth_accounts a ON a.user_id = u.id WHERE gm.group_id = g.principal_ref AND u.email = ?1 AND a.disabled_at IS NULL)))
           AND (?2 IS NULL OR f.id > ?2 OR (f.id = ?2 AND g.id > ?3))
         ORDER BY f.id ASC, g.id ASC LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            actor_email,
            after_file_id,
            after_grant_id,
            SYNC_ROOT_GRANT_SCAN_PAGE
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
