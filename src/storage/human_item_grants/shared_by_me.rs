//! Owner-facing canonical projection for active human and guest sharing.

use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    auth::{Actor, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DriveFile, GuestLinkStatus, SharedByMeRoot},
};

use super::{
    super::{row_to_file, Storage},
    access::{resolve_item_access_in_tx, retire_expired_grants_in_tx},
    capabilities::item_action_capabilities_in_tx,
    mutations::list_current_human_item_grants_in_tx,
    shared_roots::{SharedRootPage, FILE_COLUMNS, MAX_SHARED_ROOTS},
};

const MAX_GUEST_LINK_STATUSES: usize = 32;

impl Storage {
    /// Return each canonical owned item once when it has an active human grant
    /// or guest link. The complete projection is built after expiry retirement
    /// in one transaction, so a just-expired human grant cannot leak into it.
    pub fn list_shared_by_me_for_actor(
        &self,
        actor: &Actor,
        requested_limit: usize,
    ) -> ApiResult<Vec<SharedByMeRoot>> {
        Ok(self
            .list_shared_by_me_page_for_actor(actor, requested_limit, None)?
            .0)
    }

    pub fn list_shared_by_me_page_for_actor(
        &self,
        actor: &Actor,
        requested_limit: usize,
        cursor: Option<&(String, String)>,
    ) -> ApiResult<SharedRootPage<SharedByMeRoot>> {
        let limit = requested_limit.clamp(1, MAX_SHARED_ROOTS);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        retire_expired_grants_in_tx(&tx)?;
        let files = shared_by_me_files_in_tx(&tx, actor, cursor, limit)?;
        let mut roots = Vec::with_capacity(files.len());
        let mut next_cursor = None;
        for file in files {
            if roots.len() == limit {
                next_cursor = roots
                    .last()
                    .map(|root: &SharedByMeRoot| (root.file.name.clone(), root.file.id.clone()));
                break;
            }
            if let Some(root) = shared_by_me_root_in_tx(&tx, &file.id, actor)? {
                roots.push(root);
            }
        }
        tx.commit()?;
        Ok((roots, next_cursor))
    }
}

pub(super) fn shared_by_me_root_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    actor: &Actor,
) -> ApiResult<Option<SharedByMeRoot>> {
    let Some(file) = owned_live_file_in_tx(tx, file_id, actor)? else {
        return Ok(None);
    };
    let grants = list_current_human_item_grants_in_tx(tx, file_id)?;
    let guest_links = active_guest_link_statuses_in_tx(tx, file_id)?;
    if grants.is_empty() && guest_links.is_empty() {
        return Ok(None);
    }
    resolve_item_access_in_tx(tx, file_id, actor, WorkspacePermission::Manage)?;
    let (_, action_capabilities) = item_action_capabilities_in_tx(tx, file_id, actor)?;
    Ok(Some(SharedByMeRoot {
        file,
        grants,
        guest_links,
        action_capabilities,
    }))
}

fn shared_by_me_files_in_tx(
    tx: &Transaction<'_>,
    actor: &Actor,
    cursor: Option<&(String, String)>,
    limit: usize,
) -> ApiResult<Vec<DriveFile>> {
    let mut statement = tx.prepare(&format!(
        "SELECT {FILE_COLUMNS} FROM files f
         WHERE f.trashed = 0
           AND (?2 IS NULL OR f.name > ?2 OR (f.name = ?2 AND f.id > ?3))
           AND EXISTS (
             SELECT 1 FROM workspace_members wm JOIN users u ON u.id = wm.user_id
             WHERE wm.workspace_id = f.workspace_id AND wm.role = 'owner' AND u.email = ?1
           )
           AND (EXISTS (
             SELECT 1 FROM human_item_grants g
             WHERE g.root_file_id = f.id AND g.revoked_at IS NULL AND g.publication_pending = 0
               AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
           ) OR EXISTS (
             SELECT 1 FROM shares s
             WHERE s.file_id = f.id AND s.publication_pending = 0 AND s.revoked = 0
               AND (s.expires_at IS NULL OR julianday(s.expires_at) > julianday('now'))
               AND (s.max_uses IS NULL OR s.access_count < s.max_uses)
           ))
         ORDER BY f.name ASC, f.id ASC LIMIT ?4"
    ))?;
    let files = statement
        .query_map(
            params![
                &actor.email,
                cursor.map(|v| &v.0),
                cursor.map(|v| &v.1),
                i64::try_from(limit + 1).unwrap_or(i64::MAX)
            ],
            row_to_file,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(files)
}

fn owned_live_file_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    actor: &Actor,
) -> ApiResult<Option<DriveFile>> {
    tx.query_row(
        &format!(
            "SELECT {FILE_COLUMNS} FROM files f
             WHERE f.id = ?1 AND f.trashed = 0 AND EXISTS (
               SELECT 1 FROM workspace_members wm JOIN users u ON u.id = wm.user_id
               WHERE wm.workspace_id = f.workspace_id AND wm.role = 'owner' AND u.email = ?2
             )"
        ),
        params![file_id, &actor.email],
        row_to_file,
    )
    .optional()
    .map_err(ApiError::from)
}

fn active_guest_link_statuses_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
) -> ApiResult<Vec<GuestLinkStatus>> {
    let mut statement = tx.prepare(
        "SELECT target_kind, expires_at, allow_download,
                CASE WHEN max_uses IS NULL THEN NULL ELSE MAX(max_uses - access_count, 0) END
         FROM shares WHERE file_id = ?1 AND publication_pending = 0 AND revoked = 0
           AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
           AND (max_uses IS NULL OR access_count < max_uses)
         ORDER BY created_at ASC, id ASC LIMIT ?2",
    )?;
    let statuses = statement
        .query_map(
            params![
                file_id,
                i64::try_from(MAX_GUEST_LINK_STATUSES + 1).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok(GuestLinkStatus {
                    kind: row.get(0)?,
                    expires_at: row.get(1)?,
                    allow_download: row.get::<_, i64>(2)? != 0,
                    uses_remaining: row.get(3)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if statuses.len() > MAX_GUEST_LINK_STATUSES {
        return Err(ApiError::PayloadTooLarge(
            "guest-link status listing exceeds item limit".to_string(),
        ));
    }
    Ok(statuses)
}
