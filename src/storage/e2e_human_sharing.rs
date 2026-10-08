//! Exact-identity cleanup primitives for the loopback-only human-sharing E2E
//! harness.  These are deliberately storage-private: normal product routes
//! never expose account or group deletion.

use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
};

use super::{authorization, insert_receipt_rows, new_receipt, Storage};

#[derive(Debug, Clone, Copy)]
pub(crate) struct E2eHumanSharingCleanup {
    pub clean: bool,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct E2eHumanSharingCleanupProbe<'a> {
    pub run_id: &'a str,
    pub actor_ids: &'a [String],
    pub actor_emails: &'a [String],
    pub root_file_id: Option<&'a str>,
    pub group_id: Option<&'a str>,
    pub actor_cleanup: bool,
}
impl Storage {
    pub(crate) fn delete_e2e_human_sharing_group(
        &self,
        group_id: &str,
        run_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        ensure_run_id(run_id)?;
        let receipt = new_receipt(
            "debug.e2e.human_sharing.group.delete",
            &actor.email,
            Some(group_id),
        );
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let name = tx
            .query_row(
                r#"SELECT name FROM "groups" WHERE id = ?1"#,
                [group_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if name != format!("{run_id}-group") {
            return Err(ApiError::Forbidden);
        }
        let references: i64 = tx.query_row(
            "SELECT (SELECT COUNT(*) FROM group_members WHERE group_id = ?1)
                + (SELECT COUNT(*) FROM workspace_group_grants WHERE group_id = ?1)
                + (SELECT COUNT(*) FROM human_item_grants
                   WHERE principal_kind = 'group' AND principal_ref = ?1 AND revoked_at IS NULL)",
            [group_id],
            |row| row.get(0),
        )?;
        if references != 0 {
            return Err(ApiError::Validation(
                "disposable group still has active memberships or grants".to_string(),
            ));
        }
        if tx.execute(
            r#"DELETE FROM "groups" WHERE id = ?1 AND name = ?2"#,
            params![group_id, name],
        )? != 1
        {
            return Err(ApiError::NotFound);
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn delete_e2e_human_sharing_actor(
        &self,
        actor_id: &str,
        run_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        ensure_run_id(run_id)?;
        let (email, workspace_id) =
            self.e2e_human_sharing_actor_preflight(actor_id, run_id, actor, source_credential)?;
        // The existing permanent-workspace path retains its own admin and
        // emptiness checks.  Archive first so no account deletion can erase a
        // populated private workspace.
        self.set_workspace_archived(&workspace_id, true, actor, source_credential)?;
        self.delete_empty_archived_workspace_authorized(&workspace_id, actor, source_credential)?;

        let receipt = new_receipt(
            "debug.e2e.human_sharing.actor.delete",
            &actor.email,
            Some(actor_id),
        );
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let current_email = e2e_account_email_in_tx(&tx, actor_id, run_id)?;
        if current_email != email {
            return Err(ApiError::Conflict);
        }
        ensure_actor_has_no_fixture_authority_in_tx(&tx, actor_id, &email)?;
        tx.execute("DELETE FROM auth_sessions WHERE actor_email = ?1", [&email])?;
        tx.execute(
            "DELETE FROM password_reset_tokens WHERE email = ?1",
            [&email],
        )?;
        tx.execute("DELETE FROM auth_attempts WHERE actor_email = ?1", [&email])?;
        tx.execute(
            "DELETE FROM notifications WHERE recipient_email = ?1",
            [&email],
        )?;
        tx.execute(
            "DELETE FROM email_outbox WHERE recipient_email = ?1",
            [&email],
        )?;
        if tx.execute(
            "DELETE FROM users WHERE id = ?1 AND email = ?2",
            params![actor_id, &email],
        )? != 1
        {
            return Err(ApiError::NotFound);
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn e2e_human_sharing_cleanup_probe(
        &self,
        cleanup: E2eHumanSharingCleanupProbe<'_>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<E2eHumanSharingCleanup> {
        ensure_run_id(cleanup.run_id)?;
        if cleanup.actor_ids.is_empty()
            || cleanup.actor_ids.len() > 6
            || cleanup.actor_ids.iter().any(|id| id.trim().is_empty())
            || cleanup.actor_ids.len() != cleanup.actor_emails.len()
            || cleanup
                .actor_emails
                .iter()
                .any(|email| !is_disposable_email(email, cleanup.run_id))
        {
            return Err(ApiError::Validation(
                "cleanup probe requires matching exact disposable actor ids and emails".to_string(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let mut clean = true;
        if let Some(root_file_id) = cleanup.root_file_id {
            clean &= tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM files WHERE id = ?1)",
                [root_file_id],
                |row| row.get::<_, i64>(0),
            )? == 0;
        }
        if let Some(group_id) = cleanup.group_id {
            let name = tx
                .query_row(
                    r#"SELECT name FROM "groups" WHERE id = ?1"#,
                    [group_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            clean &= name.is_none();
        }
        for (actor_id, actor_email) in cleanup.actor_ids.iter().zip(cleanup.actor_emails) {
            let account = tx
                .query_row(
                    "SELECT email FROM auth_accounts WHERE user_id = ?1",
                    [actor_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(email) = account {
                if email != *actor_email {
                    return Err(ApiError::Forbidden);
                }
                clean &= !cleanup.actor_cleanup;
            } else if !cleanup.actor_cleanup {
                clean = false;
            }
            let active_grants: i64 = tx.query_row(
                "SELECT COUNT(*) FROM human_item_grants
                 WHERE principal_kind = 'account' AND principal_ref = ?1 AND revoked_at IS NULL",
                [actor_id],
                |row| row.get(0),
            )?;
            clean &= active_grants == 0;
        }
        // Browser terminal upload recovery names its one resumable session from
        // the exact generated run id. Match that full name only: no prefix
        // query may inspect or classify another run's upload history.
        let active_browser_uploads: i64 = tx.query_row(
            "SELECT COUNT(*) FROM upload_sessions
             WHERE name = ?1 AND completed = 0 AND canceled = 0",
            [format!("{}-browser-upload.txt", cleanup.run_id)],
            |row| row.get(0),
        )?;
        clean &= active_browser_uploads == 0;
        // Probe only the supplied fixture emails. No wildcard or prefix scan
        // is used for sessions, so a malformed request cannot inspect a
        // neighboring run's identities.
        if cleanup.actor_cleanup {
            for email in cleanup.actor_emails {
                let sessions: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM auth_sessions WHERE actor_email = ?1",
                    [email],
                    |row| row.get(0),
                )?;
                clean &= sessions == 0;
            }
        }
        tx.commit()?;
        Ok(E2eHumanSharingCleanup { clean })
    }

    fn e2e_human_sharing_actor_preflight(
        &self,
        actor_id: &str,
        run_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(String, String)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let email = e2e_account_email_in_tx(&tx, actor_id, run_id)?;
        ensure_actor_has_no_fixture_authority_in_tx(&tx, actor_id, &email)?;
        let workspace_id = tx
            .query_row(
                "SELECT workspace_id FROM account_private_workspaces WHERE user_id = ?1",
                [actor_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        let files: i64 = tx.query_row(
            "SELECT COUNT(*) FROM files WHERE workspace_id = ?1",
            [&workspace_id],
            |row| row.get(0),
        )?;
        let memberships: i64 = tx.query_row(
            "SELECT COUNT(*) FROM workspace_members WHERE user_id = ?1",
            [actor_id],
            |row| row.get(0),
        )?;
        if files != 0 || memberships != 1 {
            return Err(ApiError::Validation(
                "disposable actor still owns fixture content or has non-private workspace membership".to_string(),
            ));
        }
        tx.commit()?;
        Ok((email, workspace_id))
    }
}
fn ensure_run_id(run_id: &str) -> ApiResult<()> {
    if !run_id.starts_with("human-share-")
        || !(12..=92).contains(&run_id.len())
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ApiError::Validation(
            "invalid human-sharing e2e run id".to_string(),
        ));
    }
    Ok(())
}

fn is_disposable_email(email: &str, run_id: &str) -> bool {
    email.starts_with(&format!("{run_id}-")) && email.ends_with("@e2e.invalid")
}

fn e2e_account_email_in_tx(
    tx: &rusqlite::Transaction<'_>,
    actor_id: &str,
    run_id: &str,
) -> ApiResult<String> {
    let email = tx
        .query_row(
            "SELECT email FROM auth_accounts WHERE user_id = ?1",
            [actor_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(ApiError::NotFound)?;
    if !is_disposable_email(&email, run_id) {
        return Err(ApiError::Forbidden);
    }
    Ok(email)
}

fn ensure_actor_has_no_fixture_authority_in_tx(
    tx: &rusqlite::Transaction<'_>,
    actor_id: &str,
    email: &str,
) -> ApiResult<()> {
    let active_grants: i64 = tx.query_row(
        "SELECT COUNT(*) FROM human_item_grants
         WHERE revoked_at IS NULL AND (created_by = ?1 OR (principal_kind = 'account' AND principal_ref = ?2))",
        params![email, actor_id],
        |row| row.get(0),
    )?;
    let memberships: i64 = tx.query_row(
        "SELECT COUNT(*) FROM group_members WHERE user_id = ?1",
        [actor_id],
        |row| row.get(0),
    )?;
    if active_grants != 0 || memberships != 0 {
        return Err(ApiError::Validation(
            "disposable actor still owns or receives fixture authority".to_string(),
        ));
    }
    Ok(())
}
