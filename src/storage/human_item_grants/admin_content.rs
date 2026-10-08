//! Admin-only canonical-content projections.  These queries read `files`
//! directly, so a canonical item is never duplicated for every recipient.

mod details;

use rusqlite::{params, OptionalExtension, Transaction};
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    model::{
        CanonicalContentItem, CanonicalContentResponse, CanonicalShareSummary, DriveFile,
        ItemActionCapabilities,
    },
};

use super::{
    super::{row_to_file, Storage, MAX_FILE_TREE_DEPTH},
    access::{live_ancestry_in_tx, retire_expired_grants_in_tx},
    sync_roots::access_generation_in_tx,
};

const MAX_ADMIN_CONTENT_PAGE: usize = 100;
pub(super) const MAX_ADMIN_SHARE_DETAILS_PAGE: usize = 50;
const FILE_COLUMNS: &str = "f.id, f.workspace_id, f.parent_id, f.name, f.kind, f.revision, \
     f.trashed, f.starred, f.content_hash, f.created_at, f.updated_at, f.content_bytes, f.cover_hash";

impl Storage {
    pub fn list_canonical_content(
        &self,
        limit: usize,
        cursor: Option<&str>,
        query: Option<&str>,
    ) -> ApiResult<CanonicalContentResponse> {
        let limit = validated_page_limit(limit, MAX_ADMIN_CONTENT_PAGE, "content")?;
        let cursor = normalized_cursor(cursor)?;
        let query = normalized_query(query)?;
        self.retire_expired_human_item_grants()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        let sql = format!(
            "SELECT {FILE_COLUMNS}, private.user_id, accounts.email
             FROM files f
             LEFT JOIN account_private_workspaces private ON private.workspace_id = f.workspace_id
             LEFT JOIN auth_accounts accounts ON accounts.user_id = private.user_id
             WHERE f.trashed = 0 AND (?1 IS NULL OR f.id > ?1)
               AND (?2 = '' OR instr(lower(f.name), lower(?2)) > 0)
             ORDER BY f.id ASC LIMIT ?3"
        );
        let mut statement = tx.prepare(&sql)?;
        let mut rows = statement
            .query_map(
                params![cursor, query, i64::try_from(limit + 1).unwrap_or(i64::MAX)],
                |row| Ok((row_to_file(row)?, row.get(13)?, row.get(14)?)),
            )?
            .collect::<rusqlite::Result<Vec<(DriveFile, Option<String>, Option<String>)>>>()?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let items = rows
            .iter()
            .map(|(file, owner_user_id, owner_label)| {
                canonical_content_item_in_tx(
                    &tx,
                    file.clone(),
                    owner_user_id.clone(),
                    owner_label.clone(),
                )
            })
            .collect::<ApiResult<Vec<_>>>()?;
        drop(statement);
        let next_cursor = has_more
            .then(|| items.last().map(|item| item.file.id.clone()))
            .flatten();
        let access_generation = access_generation_in_tx(&tx)?;
        tx.commit()?;
        Ok(CanonicalContentResponse {
            items,
            next_cursor,
            access_generation,
        })
    }
}

pub(super) fn canonical_content_item_in_tx(
    tx: &Transaction<'_>,
    file: DriveFile,
    owner_user_id: Option<String>,
    owner_label: Option<String>,
) -> ApiResult<CanonicalContentItem> {
    let canonical_path = canonical_path_in_tx(tx, &file.id)?;
    let share_summary = share_summary_in_tx(tx, &file)?;
    Ok(CanonicalContentItem {
        file,
        owner_user_id,
        owner_label: owner_label.unwrap_or_else(|| "Unassigned workspace".to_string()),
        canonical_path,
        share_summary,
        action_capabilities: ItemActionCapabilities {
            manage_human_sharing: true,
            manage_guest_links: true,
            manage_ai_access: true,
        },
    })
}

pub(super) fn canonical_content_item_by_id_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
) -> ApiResult<CanonicalContentItem> {
    let sql = format!(
        "SELECT {FILE_COLUMNS}, private.user_id, accounts.email
         FROM files f
         LEFT JOIN account_private_workspaces private ON private.workspace_id = f.workspace_id
         LEFT JOIN auth_accounts accounts ON accounts.user_id = private.user_id
         WHERE f.id = ?1 AND f.trashed = 0"
    );
    let (file, owner_user_id, owner_label) = tx
        .query_row(&sql, [file_id], |row| {
            Ok((row_to_file(row)?, row.get(13)?, row.get(14)?))
        })
        .optional()?
        .ok_or(ApiError::NotFound)?;
    canonical_content_item_in_tx(tx, file, owner_user_id, owner_label)
}

fn canonical_path_in_tx(tx: &Transaction<'_>, file_id: &str) -> ApiResult<Vec<String>> {
    let ancestry = live_ancestry_in_tx(tx, file_id)?;
    if ancestry.len() > MAX_FILE_TREE_DEPTH + 1 {
        return Err(ApiError::NotFound);
    }
    ancestry
        .iter()
        .rev()
        .map(|ancestor| {
            tx.query_row(
                "SELECT name FROM files WHERE id = ?1",
                [&ancestor.id],
                |row| row.get(0),
            )
            .map_err(ApiError::from)
        })
        .collect()
}

fn share_summary_in_tx(tx: &Transaction<'_>, file: &DriveFile) -> ApiResult<CanonicalShareSummary> {
    let (human_grant_count, inherited_human_grant_count) = human_grant_counts_in_tx(tx, file)?;
    let guest_link_count = count_in_tx(
        tx,
        "SELECT COUNT(*) FROM shares
         WHERE file_id = ?1 AND publication_pending = 0 AND revoked = 0
           AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
           AND (max_uses IS NULL OR access_count < max_uses)",
        &file.id,
    )?;
    let ai_sql = format!(
        "SELECT COUNT(*) FROM agent_folder_grants g
         JOIN agent_principals p ON p.id = g.principal_id
         JOIN agent_tokens t ON t.id = (
            SELECT current_token.id FROM agent_tokens current_token
            WHERE current_token.principal_id = p.id AND current_token.publication_pending = 0
            ORDER BY current_token.created_at DESC, current_token.id DESC LIMIT 1
         )
         WHERE g.root_file_id = ?1 AND g.revoked_at IS NULL
           AND g.publication_pending = 0 AND p.publication_pending = 0
           AND p.disabled_at IS NULL AND t.revoked_at IS NULL
           AND julianday(g.expires_at) > julianday('now')
           AND julianday(t.expires_at) > julianday('now')
           AND {}",
        super::super::agent_access::ACTIVE_GRANT_CREATOR_PREDICATE
    );
    Ok(CanonicalShareSummary {
        human_grant_count,
        inherited_human_grant_count,
        guest_link_count,
        ai_grant_count: count_in_tx(tx, &ai_sql, &file.id)?,
    })
}

fn human_grant_counts_in_tx(tx: &Transaction<'_>, file: &DriveFile) -> ApiResult<(u64, u64)> {
    let ancestry = live_ancestry_in_tx(tx, &file.id)?;
    let placeholders = placeholders(ancestry.len())?;
    let sql = format!(
        "SELECT root_file_id, COUNT(*) FROM human_item_grants
         WHERE root_file_id IN ({placeholders}) AND revoked_at IS NULL
           AND publication_pending = 0 AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
         GROUP BY root_file_id"
    );
    let mut statement = tx.prepare(&sql)?;
    let values = ancestry
        .iter()
        .map(|ancestor| ancestor.id.clone())
        .collect::<Vec<_>>();
    let rows = statement.query_map(rusqlite::params_from_iter(values), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut direct = 0_u64;
    let mut inherited = 0_u64;
    for row in rows {
        let (root_file_id, count) = row?;
        let count = u64::try_from(count).map_err(|_| ApiError::NotFound)?;
        if root_file_id == file.id {
            direct += count;
        } else {
            inherited += count;
        }
    }
    Ok((direct + inherited, inherited))
}

fn count_in_tx(tx: &Transaction<'_>, sql: &str, file_id: &str) -> ApiResult<u64> {
    let count: i64 = tx.query_row(sql, [file_id], |row| row.get(0))?;
    u64::try_from(count).map_err(|_| ApiError::NotFound)
}

pub(super) fn validated_page_limit(
    limit: usize,
    maximum: usize,
    subject: &str,
) -> ApiResult<usize> {
    if !(1..=maximum).contains(&limit) {
        return Err(ApiError::Validation(format!(
            "{subject} limit must be a whole number from 1 to {maximum}"
        )));
    }
    Ok(limit)
}

pub(super) fn normalized_cursor(cursor: Option<&str>) -> ApiResult<Option<String>> {
    cursor
        .map(|value| {
            let parsed = Uuid::parse_str(value)
                .map_err(|_| ApiError::Validation("cursor must be a canonical UUID".to_string()))?;
            let canonical = parsed.hyphenated().to_string();
            (canonical == value)
                .then_some(canonical)
                .ok_or_else(|| ApiError::Validation("cursor must be a canonical UUID".to_string()))
        })
        .transpose()
}

fn normalized_query(query: Option<&str>) -> ApiResult<String> {
    let query = query.unwrap_or_default().trim();
    if query.len() > 120 {
        return Err(ApiError::Validation(
            "content query must be 120 bytes or shorter".to_string(),
        ));
    }
    Ok(query.to_string())
}

pub(super) fn placeholders(count: usize) -> ApiResult<String> {
    if count == 0 || count > MAX_FILE_TREE_DEPTH + 1 {
        return Err(ApiError::NotFound);
    }
    Ok((1..=count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", "))
}
