use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{constant_time_str_eq, random_secret_token, token_hash},
    error::{ApiError, ApiResult},
    model::{DriveFile, ShareLink},
};

use super::{
    bounded_grant_expiry, row_to_share_record, ClaimedShareAccess, ShareRecord, Storage,
    MAX_ACTIVE_SHARE_GRANTS_PER_SHARE, SHARE_SELECT,
};

mod snapshot;
use snapshot::ensure_share_metadata_snapshot_current;

impl Storage {
    pub fn claim_share_access(
        &self,
        share_id: &str,
        expected_authorization_fingerprint: &str,
        client_fingerprint: &str,
    ) -> ApiResult<ClaimedShareAccess> {
        self.claim_share_access_inner(
            share_id,
            expected_authorization_fingerprint,
            client_fingerprint,
            None,
            |_| Ok(()),
        )
        .map(|(claim, ())| claim)
    }

    /// Atomically prove the planned root/subtree is current, then prepare the
    /// exact response before committing a finite-use visit or its grant.
    pub(crate) fn claim_share_metadata_access_with<T, F>(
        &self,
        share_id: &str,
        expected_authorization_fingerprint: &str,
        client_fingerprint: &str,
        expected_root: &DriveFile,
        expected_descendants: &[DriveFile],
        prepare: F,
    ) -> ApiResult<(ClaimedShareAccess, T)>
    where
        F: FnOnce(&ClaimedShareAccess) -> ApiResult<T>,
    {
        self.claim_share_access_inner(
            share_id,
            expected_authorization_fingerprint,
            client_fingerprint,
            Some((expected_root, expected_descendants)),
            prepare,
        )
    }

    fn claim_share_access_inner<T, F>(
        &self,
        share_id: &str,
        expected_authorization_fingerprint: &str,
        client_fingerprint: &str,
        metadata_snapshot: Option<(&DriveFile, &[DriveFile])>,
        prepare: F,
    ) -> ApiResult<(ClaimedShareAccess, T)>
    where
        F: FnOnce(&ClaimedShareAccess) -> ApiResult<T>,
    {
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (password_hash, password_required, share_expiry, max_uses, share_file_id) = tx
            .query_row(
                "SELECT password_hash, password_required, expires_at, max_uses, file_id
                     FROM shares WHERE id = ?1 AND publication_pending = 0",
                params![share_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        let current_authorization_fingerprint =
            ShareRecord::authorization_fingerprint_for(password_required, &password_hash);
        if !constant_time_str_eq(
            expected_authorization_fingerprint,
            &current_authorization_fingerprint,
        ) {
            return Err(ApiError::Unauthenticated);
        }
        if let Some((expected_root, expected_descendants)) = metadata_snapshot {
            ensure_share_metadata_snapshot_current(
                &tx,
                &share_file_id,
                expected_root,
                expected_descendants,
            )?;
        }
        if max_uses.is_none() {
            // Remove grants that may have been minted while this link was
            // finite-use before it became unlimited. Unlimited links use
            // direct authorization and must not retain slot-consuming
            // state.
            tx.execute(
                "DELETE FROM share_access_grants WHERE share_id = ?1",
                params![share_id],
            )?;
        } else {
            tx.execute(
                "DELETE FROM share_access_grants
                     WHERE share_id = ?1 AND expires_at <= ?2",
                params![share_id, &now_text],
            )?;
            let active_grants: i64 = tx.query_row(
                "SELECT COUNT(*) FROM share_access_grants WHERE share_id = ?1",
                params![share_id],
                |row| row.get(0),
            )?;
            if active_grants >= MAX_ACTIVE_SHARE_GRANTS_PER_SHARE {
                return Err(ApiError::TooManyRequests);
            }
        }
        let changed = tx.execute(
            "UPDATE shares
                 SET access_count = access_count + 1, last_accessed_at = ?1
                 WHERE id = ?2 AND publication_pending = 0 AND revoked = 0
                   AND (expires_at IS NULL OR julianday(expires_at) > julianday(?1))
                   AND (max_uses IS NULL OR access_count < max_uses)",
            params![&now_text, share_id],
        )?;
        if changed == 0 {
            return Err(ApiError::NotFound);
        }

        // Unlimited shares authenticate each body request directly and do
        // not need a durable page grant. Persisting one for every metadata
        // visit let one public capability fill its finite grant table and
        // deny later recipients for the full grant TTL. Finite-use shares
        // retain the existing one-visit grant semantics unchanged.
        let access_token = if max_uses.is_none() {
            None
        } else {
            let raw_token = random_secret_token();
            let grant_expiry = bounded_grant_expiry(now, share_expiry.as_deref());
            tx.execute(
                    "INSERT INTO share_access_grants
                        (token_hash, share_id, authorization_fingerprint, client_fingerprint, expires_at, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        token_hash(&raw_token),
                        share_id,
                        &current_authorization_fingerprint,
                        client_fingerprint,
                        grant_expiry,
                        &now_text
                    ],
                )?;
            Some(raw_token)
        };
        let share = tx
            .query_row(
                &format!("{SHARE_SELECT} WHERE publication_pending = 0 AND id = ?1"),
                params![share_id],
                row_to_share_record,
            )?
            .share;
        let claim = ClaimedShareAccess {
            share,
            access_token,
        };
        let prepared = prepare(&claim)?;
        tx.commit()?;
        Ok((claim, prepared))
    }

    pub fn validate_share_access_grant(
        &self,
        share_id: &str,
        access_token: Option<&str>,
        client_fingerprint: &str,
    ) -> ApiResult<()> {
        let share = self.get_share(share_id)?.ok_or(ApiError::NotFound)?.share;
        if share.revoked
            || share
                .expires_at
                .as_deref()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|value| value.with_timezone(&Utc) <= Utc::now())
        {
            return Err(ApiError::Unauthenticated);
        }
        let raw = match access_token.filter(|value| !value.is_empty()) {
            Some(raw) => raw,
            None if share.max_uses.is_none() => return Ok(()),
            None => return Err(ApiError::Unauthenticated),
        };
        let conn = self.conn.lock().unwrap();
        let (expires_at, grant_fingerprint, grant_client, password_hash, password_required) = conn
            .query_row(
                "SELECT g.expires_at, g.authorization_fingerprint, g.client_fingerprint,
                        s.password_hash, s.password_required
                 FROM share_access_grants g
                 JOIN shares s ON s.id = g.share_id
                 WHERE g.token_hash = ?1 AND g.share_id = ?2
                   AND s.publication_pending = 0 AND s.revoked = 0
                   AND (s.expires_at IS NULL OR julianday(s.expires_at) > julianday('now'))",
                params![token_hash(raw), share_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)? != 0,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::Unauthenticated)?;
        let current_fingerprint =
            ShareRecord::authorization_fingerprint_for(password_required, &password_hash);
        if !grant_fingerprint
            .as_deref()
            .is_some_and(|value| constant_time_str_eq(value, &current_fingerprint))
        {
            return Err(ApiError::Unauthenticated);
        }
        if !grant_client
            .as_deref()
            .is_some_and(|value| constant_time_str_eq(value, client_fingerprint))
        {
            return Err(ApiError::Unauthenticated);
        }
        let expiry = DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|_| ApiError::Unauthenticated)?
            .with_timezone(&Utc);
        if expiry <= Utc::now() {
            return Err(ApiError::Unauthenticated);
        }
        Ok(())
    }

    pub fn validate_unlimited_share_authorization(
        &self,
        share_id: &str,
        expected_authorization_fingerprint: &str,
    ) -> ApiResult<()> {
        let conn = self.conn.lock().unwrap();
        let (password_hash, password_required, max_uses) = conn
            .query_row(
                "SELECT password_hash, password_required, max_uses
                 FROM shares
                 WHERE id = ?1 AND publication_pending = 0 AND revoked = 0
                   AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))",
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
            .ok_or(ApiError::Unauthenticated)?;
        if max_uses.is_some() {
            return Err(ApiError::Unauthenticated);
        }
        let current = ShareRecord::authorization_fingerprint_for(password_required, &password_hash);
        if !constant_time_str_eq(expected_authorization_fingerprint, &current) {
            return Err(ApiError::Unauthenticated);
        }
        Ok(())
    }

    pub fn record_unlimited_share_access(&self, share_id: &str) -> ApiResult<ShareLink> {
        let now = Utc::now().to_rfc3339();
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "UPDATE shares
                 SET access_count = access_count + 1, last_accessed_at = ?1
                 WHERE id = ?2 AND publication_pending = 0 AND max_uses IS NULL",
                params![now, share_id],
            )?;
        }
        Ok(self.get_share(share_id)?.ok_or(ApiError::NotFound)?.share)
    }
}
