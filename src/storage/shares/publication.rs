use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{random_secret_token, Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{Receipt, ShareLink},
    workspace_policy::validate_share_policy,
};

use super::{
    super::{
        authorization::ensure_workspace_authorized, insert_receipt_rows, new_receipt, Storage,
    },
    expires_at_from_seconds, normalize_recipient_note, prune_terminal_workspace_shares,
    validate_max_uses, ShareCreateFields, MAX_ACTIVE_SHARES_PER_FILE,
    MAX_ACTIVE_SHARES_PER_WORKSPACE,
};

impl Storage {
    /// Store an inactive public Share intent for the HTTP create route. The
    /// random capability identifier stays unresolvable until the route wins
    /// the terminal source-credential and workspace-permission recheck.
    pub(crate) fn create_pending_share_publication(
        &self,
        fields: ShareCreateFields<'_>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(ShareLink, Receipt)> {
        let share = new_share(&fields)?;
        self.insert_share_with_publication_state(&share, &fields, true, actor, source_credential)?;
        let receipt = new_receipt("share.create", &actor.email, Some(&share.id));
        Ok((share, receipt))
    }

    pub(super) fn insert_share_with_publication_state(
        &self,
        share: &ShareLink,
        fields: &ShareCreateFields<'_>,
        publication_pending: bool,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (workspace_id, kind): (String, String) = tx
            .query_row(
                "SELECT workspace_id, kind FROM files WHERE id = ?1",
                params![fields.file_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if kind != fields.target_kind {
            return Err(ApiError::Conflict);
        }
        ensure_workspace_authorized(
            &tx,
            &workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )?;
        let policy = super::super::workspace_policy_in_transaction(&tx, &workspace_id)?;
        validate_share_policy(&policy, fields.password_required, fields.expires_in_seconds)?;
        if !publication_pending {
            ensure_active_share_capacity(&tx, share, &workspace_id)?;
        }
        tx.execute(
            "INSERT INTO shares
                (id, file_id, password_hash, password_required, expires_at, expires_in_seconds,
                 revoked, created_at, target_kind, allow_download, recipient_note, max_uses,
                 publication_pending)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                &share.id,
                &share.file_id,
                fields.password_hash,
                fields.password_required as i64,
                share.expires_at.as_deref(),
                share.expires_in_seconds,
                &share.created_at,
                &share.kind,
                if share.allow_download { 1 } else { 0 },
                share.recipient_note.as_deref(),
                share.max_uses,
                publication_pending as i64,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Linearize public Share publication. Its capability identifier becomes
    /// resolvable only in the transaction that rechecks the exact issuing
    /// credential and current Write permission.
    pub(crate) fn publish_pending_share(
        &self,
        share_id: &str,
        creation_receipt: &Receipt,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        self.publish_pending_share_with(share_id, creation_receipt, actor, source_credential, || {})
    }

    fn publish_pending_share_with<F>(
        &self,
        share_id: &str,
        creation_receipt: &Receipt,
        actor: &Actor,
        source_credential: &DriveCredential,
        before_publication: F,
    ) -> ApiResult<()>
    where
        F: FnOnce(),
    {
        before_publication();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending = tx
            .query_row(
                "SELECT f.workspace_id, s.password_required, s.expires_in_seconds
                 FROM shares s
                 JOIN files f ON f.id = s.file_id
                 WHERE s.id = ?1 AND s.publication_pending = 1",
                params![share_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::Conflict)?;
        let result = (|| {
            ensure_workspace_authorized(
                &tx,
                &pending.0,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            let policy = super::super::workspace_policy_in_transaction(&tx, &pending.0)?;
            validate_share_policy(&policy, pending.1, pending.2.unwrap_or(0))?;
            let share = pending_share_link(&tx, share_id)?;
            ensure_active_share_capacity(&tx, &share, &pending.0)?;
            let published = tx.execute(
                "UPDATE shares
                 SET publication_pending = 0
                 WHERE id = ?1 AND publication_pending = 1 AND revoked = 0",
                params![share_id],
            )?;
            if published != 1 {
                return Err(ApiError::Conflict);
            }
            insert_receipt_rows(&tx, creation_receipt)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                tx.commit()?;
                Ok(())
            }
            Err(error) => {
                cancel_pending_share_in_tx(&tx, share_id)?;
                tx.commit()?;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn publish_pending_share_with_test_barrier<F>(
        &self,
        share_id: &str,
        creation_receipt: &Receipt,
        actor: &Actor,
        source_credential: &DriveCredential,
        before_publication: F,
    ) -> ApiResult<()>
    where
        F: FnOnce(),
    {
        self.publish_pending_share_with(
            share_id,
            creation_receipt,
            actor,
            source_credential,
            before_publication,
        )
    }
}

pub(super) fn new_share(fields: &ShareCreateFields<'_>) -> ApiResult<ShareLink> {
    let recipient_note = normalize_recipient_note(fields.recipient_note)?;
    let max_uses = validate_max_uses(fields.max_uses)?;
    let now = Utc::now();
    Ok(ShareLink {
        id: random_secret_token(),
        file_id: fields.file_id.to_string(),
        kind: fields.target_kind.to_string(),
        expires_at: expires_at_from_seconds(now, fields.expires_in_seconds)?,
        expires_in_seconds: Some(fields.expires_in_seconds.max(0)),
        revoked: false,
        created_at: now.to_rfc3339(),
        access_count: 0,
        last_accessed_at: None,
        allow_download: fields.allow_download,
        recipient_note,
        max_uses,
        uses_remaining: max_uses,
    })
}

fn pending_share_link(tx: &rusqlite::Transaction<'_>, share_id: &str) -> ApiResult<ShareLink> {
    tx.query_row(
        "SELECT id, file_id, expires_at, expires_in_seconds, created_at, access_count,
                last_accessed_at, target_kind, allow_download, recipient_note, max_uses
         FROM shares WHERE id = ?1 AND publication_pending = 1",
        params![share_id],
        |row| {
            let max_uses: Option<i64> = row.get(10)?;
            let access_count: i64 = row.get(5)?;
            Ok(ShareLink {
                id: row.get(0)?,
                file_id: row.get(1)?,
                kind: row.get(7)?,
                expires_at: row.get(2)?,
                expires_in_seconds: row.get(3)?,
                revoked: false,
                created_at: row.get(4)?,
                access_count,
                last_accessed_at: row.get(6)?,
                allow_download: row.get::<_, i64>(8)? != 0,
                recipient_note: row.get(9)?,
                max_uses,
                uses_remaining: max_uses.map(|limit| (limit - access_count).max(0)),
            })
        },
    )
    .map_err(Into::into)
}

fn ensure_active_share_capacity(
    tx: &rusqlite::Transaction<'_>,
    share: &ShareLink,
    workspace_id: &str,
) -> ApiResult<()> {
    prune_terminal_workspace_shares(tx, workspace_id, &share.created_at)?;
    let active_file_shares: i64 = tx.query_row(
        "SELECT COUNT(*) FROM shares
         WHERE file_id = ?1 AND publication_pending = 0 AND revoked = 0
           AND (expires_at IS NULL OR expires_at > ?2)
           AND (max_uses IS NULL OR access_count < max_uses)",
        params![&share.file_id, &share.created_at],
        |row| row.get(0),
    )?;
    let active_workspace_shares: i64 = tx.query_row(
        "SELECT COUNT(*) FROM shares s
         JOIN files f ON f.id = s.file_id
         WHERE f.workspace_id = ?1 AND s.publication_pending = 0 AND s.revoked = 0
           AND (s.expires_at IS NULL OR s.expires_at > ?2)
           AND (s.max_uses IS NULL OR s.access_count < s.max_uses)",
        params![workspace_id, &share.created_at],
        |row| row.get(0),
    )?;
    if active_file_shares >= MAX_ACTIVE_SHARES_PER_FILE
        || active_workspace_shares >= MAX_ACTIVE_SHARES_PER_WORKSPACE
    {
        Err(ApiError::TooManyRequests)
    } else {
        Ok(())
    }
}

fn cancel_pending_share_in_tx(tx: &rusqlite::Transaction<'_>, share_id: &str) -> ApiResult<()> {
    if tx.execute(
        "DELETE FROM shares WHERE id = ?1 AND publication_pending = 1",
        params![share_id],
    )? != 1
    {
        return Err(ApiError::Conflict);
    }
    Ok(())
}
