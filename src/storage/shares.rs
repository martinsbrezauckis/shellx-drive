use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, Row, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{Receipt, ShareLink},
    workspace_policy::{checked_share_expiry, validate_share_update_policy},
};

mod capabilities;
#[cfg(test)]
mod public_capability_publication_tests;
mod publication;

use super::{
    auth_throttle::clear_public_capability_password_budget_in_tx,
    authorization::ensure_workspace_authorized, email_outbox::purge_inactive_delivery_rows_locked,
    workspace_policy_in_transaction, PublicCapabilityKind, ShareRecord, Storage,
};

const MAX_SHARE_USES: i64 = 1_000_000;
const SHARE_GRANT_TTL_SECONDS: i64 = 3_600;
const MAX_ACTIVE_SHARE_GRANTS_PER_SHARE: i64 = 128;
const MAX_ACTIVE_SHARES_PER_FILE: i64 = 32;
const MAX_ACTIVE_SHARES_PER_WORKSPACE: i64 = 512;
const MAX_TERMINAL_SHARES_PER_WORKSPACE: i64 = 1_000;
const MAX_SHARE_LIST_ROWS: i64 =
    MAX_ACTIVE_SHARES_PER_WORKSPACE + MAX_TERMINAL_SHARES_PER_WORKSPACE;

pub struct ClaimedShareAccess {
    pub share: ShareLink,
    pub access_token: Option<String>,
}

pub struct ShareCreateFields<'a> {
    pub file_id: &'a str,
    pub password_hash: &'a str,
    pub password_required: bool,
    pub expires_in_seconds: i64,
    pub target_kind: &'a str,
    pub allow_download: bool,
    pub recipient_note: Option<&'a str>,
    pub max_uses: Option<i64>,
}

pub struct ShareUpdateFields<'a> {
    pub password_hash: Option<&'a str>,
    pub password_required: Option<bool>,
    pub expires_in_seconds: Option<i64>,
    pub allow_download: Option<bool>,
    pub recipient_note: Option<Option<&'a str>>,
    pub max_uses: Option<Option<i64>>,
}

impl Storage {
    pub fn create_share(
        &self,
        fields: ShareCreateFields<'_>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(ShareLink, Receipt)> {
        let share = publication::new_share(&fields)?;
        self.insert_share_with_publication_state(&share, &fields, false, actor, source_credential)?;
        let receipt = self.insert_receipt("share.create", &actor.email, Some(&share.id))?;
        Ok((share, receipt))
    }

    pub fn get_share(&self, share_id: &str) -> ApiResult<Option<ShareRecord>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                &format!("{SHARE_SELECT} WHERE publication_pending = 0 AND id = ?1"),
                params![share_id],
                row_to_share_record,
            )
            .optional()?)
    }

    pub fn list_file_shares(&self, file_id: &str) -> ApiResult<Vec<ShareLink>> {
        self.get_file(file_id)?.ok_or(ApiError::NotFound)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&format!(
            "{SHARE_SELECT} WHERE publication_pending = 0 AND file_id = ?1
             ORDER BY created_at DESC, id DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![file_id, MAX_SHARE_LIST_ROWS], row_to_share_record)?;
        Ok(rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|record| record.share)
            .collect())
    }

    pub fn list_workspace_shares(&self, workspace_id: &str) -> ApiResult<Vec<ShareLink>> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT s.id, s.file_id, s.password_hash, s.expires_at, s.revoked,
                    s.created_at, s.access_count, s.last_accessed_at, s.target_kind,
                    s.expires_in_seconds, s.allow_download, s.recipient_note, s.max_uses,
                    s.password_required
             FROM shares s
             JOIN files f ON f.id = s.file_id
             WHERE f.workspace_id = ?1 AND s.publication_pending = 0
             ORDER BY s.created_at DESC, s.id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![workspace_id, MAX_SHARE_LIST_ROWS],
            row_to_share_record,
        )?;
        Ok(rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|record| record.share)
            .collect())
    }

    pub fn list_all_shares(&self) -> ApiResult<Vec<ShareLink>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&format!(
            "{SHARE_SELECT} WHERE publication_pending = 0 ORDER BY created_at DESC, id DESC LIMIT 1000"
        ))?;
        let rows = stmt.query_map([], row_to_share_record)?;
        Ok(rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|record| record.share)
            .collect())
    }

    pub fn update_share(
        &self,
        share_id: &str,
        fields: ShareUpdateFields<'_>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(ShareLink, Receipt)> {
        self.get_share(share_id)?.ok_or(ApiError::NotFound)?;
        let recipient_note = fields
            .recipient_note
            .map(|value| normalize_recipient_note(value))
            .transpose()?;
        let max_uses = fields.max_uses.map(validate_max_uses).transpose()?;
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let workspace_id = tx
                .query_row(
                    "SELECT f.workspace_id FROM shares s
                     JOIN files f ON f.id = s.file_id WHERE s.id = ?1",
                    params![share_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            ensure_workspace_authorized(
                &tx,
                &workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            let policy = workspace_policy_in_transaction(&tx, &workspace_id)?;
            validate_share_update_policy(
                &policy,
                fields.password_required,
                fields.expires_in_seconds,
            )?;
            if let Some(password_hash) = fields.password_hash {
                let password_required = fields.password_required.ok_or_else(|| {
                    ApiError::Validation(
                        "share password requirement must accompany a password update".to_string(),
                    )
                })?;
                tx.execute(
                    "UPDATE shares
                     SET password_hash = ?1, password_required = ?2
                     WHERE id = ?3",
                    params![password_hash, password_required as i64, share_id],
                )?;
                tx.execute(
                    "DELETE FROM share_access_grants WHERE share_id = ?1",
                    params![share_id],
                )?;
                clear_public_capability_password_budget_in_tx(
                    &tx,
                    PublicCapabilityKind::Share,
                    share_id,
                )?;
            }
            if let Some(seconds) = fields.expires_in_seconds {
                let expires_at = expires_at_from_seconds(Utc::now(), seconds)?;
                tx.execute(
                    "UPDATE shares SET expires_at = ?1, expires_in_seconds = ?2 WHERE id = ?3",
                    params![expires_at.as_deref(), seconds.max(0), share_id],
                )?;
            }
            if let Some(allow_download) = fields.allow_download {
                tx.execute(
                    "UPDATE shares SET allow_download = ?1 WHERE id = ?2",
                    params![if allow_download { 1 } else { 0 }, share_id],
                )?;
            }
            if let Some(recipient_note) = recipient_note {
                tx.execute(
                    "UPDATE shares SET recipient_note = ?1 WHERE id = ?2",
                    params![recipient_note.as_deref(), share_id],
                )?;
            }
            if let Some(max_uses) = max_uses {
                tx.execute(
                    "UPDATE shares SET max_uses = ?1 WHERE id = ?2",
                    params![max_uses, share_id],
                )?;
                if max_uses.is_none() {
                    // An unlimited link uses direct authorization rather than
                    // an expiring access grant. Remove finite-use grants when
                    // the policy changes so they cannot consume slots.
                    tx.execute(
                        "DELETE FROM share_access_grants WHERE share_id = ?1",
                        params![share_id],
                    )?;
                }
            }
            purge_inactive_delivery_rows_locked(&tx, &Utc::now().to_rfc3339())?;
            tx.commit()?;
        }
        let share = self.get_share(share_id)?.ok_or(ApiError::NotFound)?.share;
        let receipt = self.insert_receipt("share.update", &actor.email, Some(share_id))?;
        Ok((share, receipt))
    }

    pub fn revoke_share(
        &self,
        share_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(ShareLink, Receipt)> {
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let workspace_id = tx
                .query_row(
                    "SELECT f.workspace_id FROM shares s
                     JOIN files f ON f.id = s.file_id WHERE s.id = ?1",
                    params![share_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            ensure_workspace_authorized(
                &tx,
                &workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            tx.execute(
                "UPDATE shares SET revoked = 1 WHERE id = ?1",
                params![share_id],
            )?;
            tx.execute(
                "DELETE FROM share_access_grants WHERE share_id = ?1",
                params![share_id],
            )?;
            purge_inactive_delivery_rows_locked(&tx, &Utc::now().to_rfc3339())?;
            tx.commit()?;
        }
        let share = self.get_share(share_id)?.ok_or(ApiError::NotFound)?.share;
        let receipt = self.insert_receipt("share.revoke", &actor.email, Some(share_id))?;
        Ok((share, receipt))
    }
}

fn prune_terminal_workspace_shares(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    now: &str,
) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM shares WHERE id IN (
             SELECT s.id FROM shares s
             JOIN files f ON f.id = s.file_id
             WHERE f.workspace_id = ?1
               AND s.publication_pending = 0
               AND (s.revoked != 0
                    OR (s.expires_at IS NOT NULL AND s.expires_at <= ?2)
                    OR (s.max_uses IS NOT NULL AND s.access_count >= s.max_uses))
             ORDER BY s.created_at DESC, s.id DESC
             LIMIT -1 OFFSET ?3
         )",
        params![workspace_id, now, MAX_TERMINAL_SHARES_PER_WORKSPACE],
    )?;
    purge_inactive_delivery_rows_locked(tx, now)?;
    Ok(())
}

pub(super) const SHARE_SELECT: &str =
    "SELECT id, file_id, password_hash, expires_at, revoked, created_at,
            access_count, last_accessed_at, target_kind, expires_in_seconds,
            allow_download, recipient_note, max_uses, password_required
     FROM shares";

pub(super) fn row_to_share_record(row: &Row<'_>) -> rusqlite::Result<ShareRecord> {
    let revoked: i64 = row.get(4)?;
    let allow_download: i64 = row.get(10)?;
    let max_uses: Option<i64> = row.get(12)?;
    let access_count: i64 = row.get(6)?;
    Ok(ShareRecord {
        share: ShareLink {
            id: row.get(0)?,
            file_id: row.get(1)?,
            kind: row.get(8)?,
            expires_at: row.get(3)?,
            expires_in_seconds: row.get(9)?,
            revoked: revoked != 0,
            created_at: row.get(5)?,
            access_count,
            last_accessed_at: row.get(7)?,
            allow_download: allow_download != 0,
            recipient_note: row.get(11)?,
            max_uses,
            uses_remaining: max_uses.map(|limit| (limit - access_count).max(0)),
        },
        password_hash: row.get(2)?,
        password_required: row.get::<_, i64>(13)? != 0,
    })
}

fn expires_at_from_seconds(created_at: DateTime<Utc>, seconds: i64) -> ApiResult<Option<String>> {
    checked_share_expiry(created_at, seconds)
}

fn normalize_recipient_note(note: Option<&str>) -> ApiResult<Option<String>> {
    let note = note.map(str::trim).filter(|value| !value.is_empty());
    if note.is_some_and(|value| value.chars().count() > 500) {
        return Err(ApiError::Validation(
            "recipient note must be 500 characters or shorter".to_string(),
        ));
    }
    Ok(note.map(str::to_string))
}

fn validate_max_uses(max_uses: Option<i64>) -> ApiResult<Option<i64>> {
    if max_uses.is_some_and(|value| !(1..=MAX_SHARE_USES).contains(&value)) {
        return Err(ApiError::Validation(format!(
            "max_uses must be between 1 and {MAX_SHARE_USES}"
        )));
    }
    Ok(max_uses)
}

fn bounded_grant_expiry(now: DateTime<Utc>, share_expiry: Option<&str>) -> String {
    let default = now + Duration::seconds(SHARE_GRANT_TTL_SECONDS);
    let bounded = share_expiry
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .filter(|value| *value < default)
        .unwrap_or(default);
    bounded.to_rfc3339()
}
