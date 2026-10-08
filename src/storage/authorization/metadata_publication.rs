use std::collections::{BTreeSet, HashSet};

use rusqlite::{
    params, params_from_iter, types::Value as SqlValue, OptionalExtension, Transaction,
};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    storage::MAX_COMPATIBILITY_FILE_LIST,
};

/// A terminal metadata response may contain many workspace subjects, but never
/// more than the largest compatibility metadata page. Authorization checks
/// batch subjects below SQLite's parameter ceiling.
const MAX_METADATA_PUBLICATION_WORKSPACE_SUBJECTS: usize = MAX_COMPATIBILITY_FILE_LIST;
const WORKSPACE_AUTHORIZATION_BATCH_SIZE: usize = 128;

pub(super) fn ensure_workspace_metadata_subjects_authorized(
    tx: &Transaction<'_>,
    workspace_ids: &[String],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    let workspace_ids = normalize_workspace_subjects(workspace_ids)?;

    if let DriveCredential::AppToken(token_id) = source_credential {
        ensure_app_token_scope_contains_subjects(tx, token_id, &actor.email, &workspace_ids)?;
    }

    ensure_workspace_subjects_exist(tx, &workspace_ids)?;
    if actor.is_admin {
        return Ok(());
    }
    let now = chrono::Utc::now().to_rfc3339();
    ensure_actor_can_read_workspace_subjects(tx, &workspace_ids, &actor.email, &now)
}

fn normalize_workspace_subjects(workspace_ids: &[String]) -> ApiResult<Vec<String>> {
    let workspace_ids = workspace_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if workspace_ids.len() > MAX_METADATA_PUBLICATION_WORKSPACE_SUBJECTS {
        return Err(ApiError::PayloadTooLarge(format!(
            "metadata publication selects more than {MAX_METADATA_PUBLICATION_WORKSPACE_SUBJECTS} workspace subjects"
        )));
    }
    Ok(workspace_ids)
}

fn ensure_app_token_scope_contains_subjects(
    tx: &Transaction<'_>,
    token_id: &str,
    actor_email: &str,
    workspace_ids: &[String],
) -> ApiResult<()> {
    let scope_json = tx
        .query_row(
            "SELECT workspace_ids_json FROM app_tokens
             WHERE id = ?1 AND actor_email = ?2",
            params![token_id, actor_email],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(ApiError::Unauthenticated)?;
    let scope =
        serde_json::from_str::<Vec<String>>(&scope_json).map_err(|_| ApiError::Unauthenticated)?;
    if scope.is_empty() {
        return Err(ApiError::Unauthenticated);
    }

    for workspace_batch in workspace_ids.chunks(WORKSPACE_AUTHORIZATION_BATCH_SIZE) {
        let placeholders = sql_placeholders(workspace_batch.len());
        let sql = format!(
            "SELECT DISTINCT value
             FROM json_each(?1)
             WHERE type = 'text' AND value IN ({placeholders})"
        );
        let mut parameters = Vec::with_capacity(workspace_batch.len() + 1);
        parameters.push(SqlValue::Text(scope_json.clone()));
        parameters.extend(workspace_batch.iter().cloned().map(SqlValue::Text));
        let mut statement = tx.prepare(&sql)?;
        let scoped_ids = statement
            .query_map(params_from_iter(parameters.iter()), |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        if scoped_ids.len() != workspace_batch.len() {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

fn ensure_workspace_subjects_exist(
    tx: &Transaction<'_>,
    workspace_ids: &[String],
) -> ApiResult<()> {
    for workspace_batch in workspace_ids.chunks(WORKSPACE_AUTHORIZATION_BATCH_SIZE) {
        let placeholders = sql_placeholders(workspace_batch.len());
        let sql = format!("SELECT id FROM workspaces WHERE id IN ({placeholders})");
        let mut statement = tx.prepare(&sql)?;
        let present_ids = statement
            .query_map(params_from_iter(workspace_batch.iter()), |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        if present_ids.len() != workspace_batch.len() {
            return Err(ApiError::NotFound);
        }
    }
    Ok(())
}

fn ensure_actor_can_read_workspace_subjects(
    tx: &Transaction<'_>,
    workspace_ids: &[String],
    actor_email: &str,
    now: &str,
) -> ApiResult<()> {
    for workspace_batch in workspace_ids.chunks(WORKSPACE_AUTHORIZATION_BATCH_SIZE) {
        let placeholders = sql_placeholders(workspace_batch.len());
        let sql = format!(
            "SELECT DISTINCT workspace_id FROM (
                 SELECT wm.workspace_id
                 FROM workspace_members wm
                 JOIN users u ON u.id = wm.user_id
                 WHERE u.email = ?1
                   AND (wm.expires_at IS NULL OR wm.expires_at > ?2)
                   AND wm.role IN ('owner', 'editor', 'viewer')
                   AND wm.workspace_id IN ({placeholders})
                 UNION
                 SELECT wgg.workspace_id
                 FROM workspace_group_grants wgg
                 JOIN group_members gm ON gm.group_id = wgg.group_id
                 JOIN users u ON u.id = gm.user_id
                 WHERE u.email = ?1
                   AND wgg.role IN ('owner', 'editor', 'viewer')
                   AND wgg.workspace_id IN ({placeholders})
             )"
        );
        let mut parameters = Vec::with_capacity(workspace_batch.len() * 2 + 2);
        parameters.push(SqlValue::Text(actor_email.to_string()));
        parameters.push(SqlValue::Text(now.to_string()));
        parameters.extend(workspace_batch.iter().cloned().map(SqlValue::Text));
        parameters.extend(workspace_batch.iter().cloned().map(SqlValue::Text));
        let mut statement = tx.prepare(&sql)?;
        let authorized_ids = statement
            .query_map(params_from_iter(parameters.iter()), |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        if authorized_ids.len() != workspace_batch.len() {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

fn sql_placeholders(count: usize) -> String {
    debug_assert!(count > 0);
    (0..count).map(|_| "?").collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chrono::Utc;
    use rusqlite::params;

    use super::*;
    use crate::{auth::AuthMode, storage::Storage};

    fn actor(email: &str) -> Actor {
        Actor {
            email: email.to_string(),
            is_admin: false,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        }
    }

    fn session_for_existing_account(storage: &Storage, email: &str) -> DriveCredential {
        let account = storage.get_auth_account_secret(email).unwrap().unwrap();
        let session_id = uuid::Uuid::now_v7().to_string();
        storage
            .record_auth_session(
                &session_id,
                email,
                "local-password",
                &account.user_id,
                &format!("stored-session-token-hash-{session_id}"),
                &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            )
            .unwrap();
        DriveCredential::UserSession(session_id)
    }

    #[test]
    fn terminal_metadata_publication_rejects_revocation_and_membership_loss() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let email = "metadata-reader@example.test";
        storage
            .bootstrap_auth_account(email, "stored-password-hash")
            .unwrap();
        let credential = session_for_existing_account(&storage, email);
        let workspace = storage.create_workspace("Metadata", email).unwrap().0;
        let workspace_ids = vec![workspace.id.clone()];

        storage
            .ensure_workspace_metadata_publication_authorized(
                &workspace_ids,
                &actor(email),
                &credential,
            )
            .unwrap();

        let DriveCredential::UserSession(session_id) = &credential else {
            unreachable!();
        };
        storage.revoke_auth_session(session_id, email).unwrap();
        assert!(matches!(
            storage.ensure_workspace_metadata_publication_authorized(
                &workspace_ids,
                &actor(email),
                &credential,
            ),
            Err(ApiError::Unauthenticated)
        ));

        let credential = session_for_existing_account(&storage, email);
        storage
            .conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM workspace_members
                 WHERE workspace_id = ?1 AND user_id = (
                     SELECT id FROM users WHERE email = ?2
                 )",
                params![workspace.id, email],
            )
            .unwrap();
        assert!(matches!(
            storage.ensure_workspace_metadata_publication_authorized(
                &workspace_ids,
                &actor(email),
                &credential,
            ),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn terminal_metadata_publication_batches_and_rechecks_current_app_token_scope() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let email = "metadata-app-token@example.test";
        storage
            .bootstrap_auth_account(email, "stored-password-hash")
            .unwrap();
        let workspace_ids = (0..(WORKSPACE_AUTHORIZATION_BATCH_SIZE + 1))
            .map(|index| {
                storage
                    .create_workspace(&format!("Metadata {index}"), email)
                    .unwrap()
                    .0
                    .id
            })
            .collect::<Vec<_>>();
        let operator = Actor {
            email: "system@local".to_string(),
            is_admin: true,
            auth_mode: AuthMode::Operator,
            allowed_workspace_ids: None,
        };
        let token = storage
            .create_app_token(
                "metadata publication",
                email,
                "stored-app-token-hash",
                &workspace_ids,
                &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                &operator,
                &DriveCredential::Operator,
            )
            .unwrap()
            .0;
        let app_actor = Actor {
            email: email.to_string(),
            is_admin: false,
            auth_mode: AuthMode::AppToken,
            allowed_workspace_ids: Some(workspace_ids.iter().cloned().collect::<HashSet<_>>()),
        };
        let credential = DriveCredential::AppToken(token.id.clone());

        storage
            .ensure_workspace_metadata_publication_authorized(
                &workspace_ids,
                &app_actor,
                &credential,
            )
            .unwrap();

        let narrowed_scope = serde_json::to_string(&workspace_ids[..1]).unwrap();
        storage
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE app_tokens SET workspace_ids_json = ?1 WHERE id = ?2",
                params![narrowed_scope, token.id],
            )
            .unwrap();
        assert!(matches!(
            storage.ensure_workspace_metadata_publication_authorized(
                &workspace_ids,
                &app_actor,
                &credential,
            ),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn metadata_publication_subject_bound_matches_compatibility_file_lists() {
        let subjects = (0..MAX_COMPATIBILITY_FILE_LIST)
            .map(|index| format!("workspace-{index}"))
            .collect::<Vec<_>>();
        assert_eq!(
            normalize_workspace_subjects(&subjects).unwrap().len(),
            MAX_COMPATIBILITY_FILE_LIST
        );
    }
}
