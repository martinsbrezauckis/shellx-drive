use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{random_secret_token, Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DropLink, Receipt},
    workspace_policy::validate_drop_policy,
};

use super::{
    super::{
        authorization::ensure_workspace_authorized, insert_receipt_rows, new_receipt, Storage,
    },
    prune_terminal_workspace_drops, DropCreateFields, MAX_ACTIVE_DROPS_PER_WORKSPACE,
};

impl Storage {
    /// Store an inactive public Drop intent for the HTTP create route. The
    /// identifier cannot start a public upload until terminal publication.
    pub(crate) fn create_pending_drop_publication(
        &self,
        fields: DropCreateFields<'_>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DropLink, Receipt)> {
        let drop = new_drop(&fields)?;
        self.insert_drop_with_publication_state(&drop, &fields, true, actor, source_credential)?;
        let receipt = new_receipt("drop.create", &actor.email, Some(&drop.id));
        Ok((drop, receipt))
    }

    pub(super) fn insert_drop_with_publication_state(
        &self,
        drop: &DropLink,
        fields: &DropCreateFields<'_>,
        publication_pending: bool,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_workspace_authorized(
            &tx,
            fields.workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )?;
        let policy = super::super::workspace_policy_in_transaction(&tx, fields.workspace_id)?;
        validate_drop_policy(&policy, fields.password_required, fields.expires_in_seconds)?;
        if !publication_pending {
            ensure_active_drop_capacity(&tx, drop)?;
        }
        tx.execute(
            "INSERT INTO drops
                (id, workspace_id, name, password_hash, password_required, expires_at, revoked, created_at,
                 publication_pending)
             VALUES (?1, ?2, ?3, ?4, ?8, ?5, 0, ?6, ?7)",
            params![
                &drop.id,
                &drop.workspace_id,
                &drop.name,
                fields.password_hash,
                &drop.expires_at,
                &drop.created_at,
                publication_pending as i64,
                fields.password_required as i64,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Linearize public Drop publication with the same source credential and
    /// workspace Write proof that admitted the original request.
    pub(crate) fn publish_pending_drop(
        &self,
        drop_id: &str,
        creation_receipt: &Receipt,
        password_required: bool,
        expires_in_seconds: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        self.publish_pending_drop_with(
            drop_id,
            creation_receipt,
            password_required,
            expires_in_seconds,
            actor,
            source_credential,
            || {},
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_pending_drop_with<F>(
        &self,
        drop_id: &str,
        creation_receipt: &Receipt,
        password_required: bool,
        expires_in_seconds: i64,
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
        let workspace_id = tx
            .query_row(
                "SELECT workspace_id FROM drops
                 WHERE id = ?1 AND publication_pending = 1",
                params![drop_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(ApiError::Conflict)?;
        let result = (|| {
            ensure_workspace_authorized(
                &tx,
                &workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            let policy = super::super::workspace_policy_in_transaction(&tx, &workspace_id)?;
            validate_drop_policy(&policy, password_required, expires_in_seconds)?;
            let drop = pending_drop_link(&tx, drop_id)?;
            ensure_active_drop_capacity(&tx, &drop)?;
            let published = tx.execute(
                "UPDATE drops
                 SET publication_pending = 0
                 WHERE id = ?1 AND publication_pending = 1 AND revoked = 0",
                params![drop_id],
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
                cancel_pending_drop_in_tx(&tx, drop_id)?;
                tx.commit()?;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_pending_drop_with_test_barrier<F>(
        &self,
        drop_id: &str,
        creation_receipt: &Receipt,
        password_required: bool,
        expires_in_seconds: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
        before_publication: F,
    ) -> ApiResult<()>
    where
        F: FnOnce(),
    {
        self.publish_pending_drop_with(
            drop_id,
            creation_receipt,
            password_required,
            expires_in_seconds,
            actor,
            source_credential,
            before_publication,
        )
    }
}

pub(super) fn new_drop(fields: &DropCreateFields<'_>) -> ApiResult<DropLink> {
    let now = Utc::now();
    Ok(DropLink {
        // Public capability identifier: a 256-bit CSPRNG token (64 hex chars),
        // NOT a `Uuid::now_v7()` — same rationale as `create_share`. A Drop link
        // is an unauthenticated write capability, so a guessable id is worse.
        id: random_secret_token(),
        workspace_id: fields.workspace_id.to_string(),
        name: fields.name.to_string(),
        inbox_file_id: None,
        expires_at: super::drop_expiry_from_ttl(fields.expires_in_seconds)?,
        revoked: false,
        created_at: now.to_rfc3339(),
        upload_count: 0,
        last_uploaded_at: None,
    })
}

fn pending_drop_link(tx: &rusqlite::Transaction<'_>, drop_id: &str) -> ApiResult<DropLink> {
    tx.query_row(
        "SELECT id, workspace_id, name, expires_at, created_at, upload_count, last_uploaded_at, inbox_file_id
         FROM drops WHERE id = ?1 AND publication_pending = 1",
        params![drop_id],
        |row| {
            Ok(DropLink {
                id: row.get(0)?,
                workspace_id: row.get(1)?,
                name: row.get(2)?,
                inbox_file_id: row.get(7)?,
                expires_at: row.get(3)?,
                revoked: false,
                created_at: row.get(4)?,
                upload_count: row.get(5)?,
                last_uploaded_at: row.get(6)?,
            })
        },
    )
    .map_err(Into::into)
}

fn ensure_active_drop_capacity(tx: &rusqlite::Transaction<'_>, drop: &DropLink) -> ApiResult<()> {
    prune_terminal_workspace_drops(tx, &drop.workspace_id, &drop.created_at)?;
    let active_drops: i64 = tx.query_row(
        "SELECT COUNT(*) FROM drops
         WHERE workspace_id = ?1 AND publication_pending = 0
           AND revoked = 0 AND expires_at > ?2",
        params![&drop.workspace_id, &drop.created_at],
        |row| row.get(0),
    )?;
    if active_drops >= MAX_ACTIVE_DROPS_PER_WORKSPACE {
        Err(ApiError::TooManyRequests)
    } else {
        Ok(())
    }
}

fn cancel_pending_drop_in_tx(tx: &rusqlite::Transaction<'_>, drop_id: &str) -> ApiResult<()> {
    if tx.execute(
        "DELETE FROM drops WHERE id = ?1 AND publication_pending = 1",
        params![drop_id],
    )? != 1
    {
        return Err(ApiError::Conflict);
    }
    Ok(())
}
