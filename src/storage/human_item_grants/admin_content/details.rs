use rusqlite::{params, types::Value, Transaction};

use crate::{
    error::{ApiError, ApiResult},
    model::{
        CanonicalHumanGrantDetail, CanonicalShareDetails, CanonicalShareDetailsResponse,
        HumanItemGrant,
    },
};

use super::super::super::{
    agent_access::{row_to_agent_access, ACCESS_SELECT, ACTIVE_GRANT_CREATOR_PREDICATE},
    shares::{row_to_share_record, SHARE_SELECT},
    Storage,
};
use super::super::{
    access::{live_ancestry_in_tx, retire_expired_grants_in_tx},
    mutations::row_to_human_item_grant,
    sync_roots::access_generation_in_tx,
};
use super::{
    canonical_content_item_by_id_in_tx, normalized_cursor, placeholders, validated_page_limit,
    MAX_ADMIN_SHARE_DETAILS_PAGE,
};

impl Storage {
    pub fn canonical_share_details(
        &self,
        file_id: &str,
        kind: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> ApiResult<CanonicalShareDetailsResponse> {
        let limit = validated_page_limit(limit, MAX_ADMIN_SHARE_DETAILS_PAGE, "share detail")?;
        let cursor = normalized_cursor(cursor)?;
        self.retire_expired_human_item_grants()?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        let item = canonical_content_item_by_id_in_tx(&tx, file_id)?;
        let (details, next_cursor) = match kind {
            "human" => human_details_in_tx(&tx, file_id, limit, cursor.as_deref())?,
            "guest" => guest_details_in_tx(&tx, file_id, limit, cursor.as_deref())?,
            "ai" => ai_details_in_tx(&tx, file_id, limit, cursor.as_deref())?,
            _ => {
                return Err(ApiError::Validation(
                    "share detail kind must be human, guest, or ai".to_string(),
                ));
            }
        };
        let access_generation = access_generation_in_tx(&tx)?;
        tx.commit()?;
        Ok(CanonicalShareDetailsResponse {
            item,
            details,
            next_cursor,
            access_generation,
        })
    }
}

fn human_details_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    limit: usize,
    cursor: Option<&str>,
) -> ApiResult<(CanonicalShareDetails, Option<String>)> {
    let ancestry = live_ancestry_in_tx(tx, file_id)?;
    let placeholders = placeholders(ancestry.len())?;
    let cursor_index = ancestry.len() + 1;
    let limit_index = cursor_index + 1;
    let sql = format!(
        "SELECT g.id, g.workspace_id, g.root_file_id, g.principal_kind, g.principal_ref,
                COALESCE(account.email, groups.name, 'Everyone in this Drive'),
                g.role, g.created_by, g.created_at, g.updated_at, g.expires_at, g.revoked_at
         FROM human_item_grants g
         LEFT JOIN users account ON g.principal_kind = 'account' AND account.id = g.principal_ref
         LEFT JOIN \"groups\" groups ON g.principal_kind = 'group' AND groups.id = g.principal_ref
         WHERE g.root_file_id IN ({placeholders}) AND g.revoked_at IS NULL
           AND g.publication_pending = 0
           AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
           AND g.id > ?{cursor_index}
         ORDER BY g.id ASC LIMIT ?{limit_index}"
    );
    let mut values = ancestry
        .iter()
        .map(|ancestor| Value::Text(ancestor.id.clone()))
        .collect::<Vec<_>>();
    values.push(Value::Text(cursor.unwrap_or_default().to_string()));
    values.push(Value::Integer(i64::try_from(limit + 1).unwrap_or(i64::MAX)));
    let mut statement = tx.prepare(&sql)?;
    let mut grants = statement
        .query_map(rusqlite::params_from_iter(values), row_to_human_item_grant)?
        .collect::<rusqlite::Result<Vec<HumanItemGrant>>>()?;
    let has_more = grants.len() > limit;
    grants.truncate(limit);
    let next_cursor = has_more
        .then(|| grants.last().map(|grant| grant.id.clone()))
        .flatten();
    let entries = grants
        .into_iter()
        .map(|grant| CanonicalHumanGrantDetail {
            inherited: grant.root_file_id != file_id,
            grant,
        })
        .collect();
    Ok((CanonicalShareDetails::Human(entries), next_cursor))
}

fn guest_details_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    limit: usize,
    cursor: Option<&str>,
) -> ApiResult<(CanonicalShareDetails, Option<String>)> {
    let sql = format!(
        "{SHARE_SELECT} WHERE file_id = ?1 AND publication_pending = 0
         AND revoked = 0 AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
         AND (max_uses IS NULL OR access_count < max_uses) AND id > ?2
         ORDER BY id ASC LIMIT ?3"
    );
    let mut statement = tx.prepare(&sql)?;
    let mut shares = statement
        .query_map(
            params![
                file_id,
                cursor.unwrap_or_default(),
                i64::try_from(limit + 1).unwrap_or(i64::MAX)
            ],
            row_to_share_record,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(|record| record.share)
        .collect::<Vec<_>>();
    let has_more = shares.len() > limit;
    shares.truncate(limit);
    let next_cursor = has_more
        .then(|| shares.last().map(|share| share.id.clone()))
        .flatten();
    Ok((CanonicalShareDetails::Guest(shares), next_cursor))
}

fn ai_details_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    limit: usize,
    cursor: Option<&str>,
) -> ApiResult<(CanonicalShareDetails, Option<String>)> {
    let sql = format!(
        "{ACCESS_SELECT} WHERE g.root_file_id = ?1 AND g.id > ?2
         AND g.revoked_at IS NULL AND g.publication_pending = 0
         AND p.publication_pending = 0 AND p.disabled_at IS NULL
         AND t.revoked_at IS NULL AND julianday(g.expires_at) > julianday('now')
         AND julianday(t.expires_at) > julianday('now')
         AND {ACTIVE_GRANT_CREATOR_PREDICATE}
         ORDER BY g.id ASC LIMIT ?3"
    );
    let mut statement = tx.prepare(&sql)?;
    let mut access = statement
        .query_map(
            params![
                file_id,
                cursor.unwrap_or_default(),
                i64::try_from(limit + 1).unwrap_or(i64::MAX)
            ],
            row_to_agent_access,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_more = access.len() > limit;
    access.truncate(limit);
    let next_cursor = has_more
        .then(|| access.last().map(|grant| grant.grant_id.clone()))
        .flatten();
    Ok((CanonicalShareDetails::Ai(access), next_cursor))
}
