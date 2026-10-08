//! Deduplicated public-share access accounting.

use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{auth::token_hash, error::ApiResult};

use super::{record_one, FileAccessKind};
use crate::storage::{
    auth_attempt_key, enforce_auth_attempt_row_cap_locked, insert_receipt_rows, new_receipt,
    prune_auth_attempts_locked, Storage,
};

const PUBLIC_SHARE_ACCESS_DEDUP_SECONDS: i64 = 300;

impl Storage {
    /// Record at most one public content event for the same share, file,
    /// client, and access kind during a short media-seek window.
    pub fn record_public_share_file_access_once(
        &self,
        share_id: &str,
        file_id: &str,
        workspace_id: &str,
        client_fingerprint: &str,
        kind: FileAccessKind,
    ) -> ApiResult<bool> {
        let scope = match kind {
            FileAccessKind::Access => "share_content_access",
            FileAccessKind::Download => "share_content_download",
        };
        let resource_ref = token_hash(&format!(
            "public-share-content-event-v1\0{share_id}\0{file_id}"
        ));
        let key = auth_attempt_key(Some(&resource_ref), scope, Some(client_fingerprint));
        let now = Utc::now();
        let window_start = now - Duration::seconds(PUBLIC_SHARE_ACCESS_DEDUP_SECONDS);

        // Keep repeated range requests read-only after the first event. The
        // transactional recheck below closes races between simultaneous seeks.
        {
            let conn = self.conn.lock().unwrap();
            if has_recent_event(&conn, &key, window_start)? {
                return Ok(false);
            }
        }

        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if has_recent_event(&tx, &key, window_start)? {
            tx.commit()?;
            return Ok(false);
        }
        prune_auth_attempts_locked(&tx, &now_text)?;
        tx.execute(
            "INSERT INTO auth_attempts (
                key, actor_email, client_fingerprint, scope, failures, locked_until, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 1, NULL, ?5)
             ON CONFLICT(key) DO UPDATE SET
                actor_email = excluded.actor_email,
                client_fingerprint = excluded.client_fingerprint,
                scope = excluded.scope,
                failures = 1,
                locked_until = NULL,
                updated_at = excluded.updated_at",
            params![&key, &resource_ref, client_fingerprint, scope, &now_text],
        )?;
        record_one(&tx, file_id, workspace_id, kind, &now_text)?;
        tx.execute(
            "UPDATE shares
             SET access_count = access_count + 1, last_accessed_at = ?1
             WHERE id = ?2 AND publication_pending = 0 AND max_uses IS NULL",
            params![&now_text, share_id],
        )?;
        let receipt = new_receipt("share.access", "public", Some(share_id));
        insert_receipt_rows(&tx, &receipt)?;
        enforce_auth_attempt_row_cap_locked(&tx)?;
        tx.commit()?;
        Ok(true)
    }
}

fn has_recent_event(
    conn: &rusqlite::Connection,
    key: &str,
    window_start: DateTime<Utc>,
) -> ApiResult<bool> {
    let updated_at = conn
        .query_row(
            "SELECT updated_at FROM auth_attempts WHERE key = ?1",
            [key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(updated_at.is_some_and(|updated_at| {
        DateTime::parse_from_rfc3339(&updated_at)
            .map(|value| value.with_timezone(&Utc) > window_start)
            // Corrupt timestamps fail closed instead of enabling write churn.
            .unwrap_or(true)
    }))
}
