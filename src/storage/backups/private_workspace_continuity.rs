use rusqlite::{params, Transaction};
use uuid::Uuid;

use crate::error::ApiResult;

/// Complete the live account-to-private-workspace relation after the archived
/// product graph and current authority have been reconciled. Existing valid
/// mappings win; an extant owner workspace is the next choice, otherwise a new
/// empty private workspace is created without claiming an archived id.
pub(super) fn reconcile(tx: &Transaction<'_>) -> ApiResult<()> {
    tx.execute_batch(
        "DELETE FROM account_private_workspaces
         WHERE NOT EXISTS (
             SELECT 1 FROM workspace_members member
             WHERE member.workspace_id = account_private_workspaces.workspace_id
               AND member.user_id = account_private_workspaces.user_id
               AND member.role = 'owner'
         );
         INSERT OR IGNORE INTO account_private_workspaces (user_id, workspace_id, created_at)
         WITH direct_owners AS (
           SELECT account.user_id, account.created_at AS account_created_at,
                  workspace.id AS workspace_id, workspace.created_at AS workspace_created_at,
                  workspace.archived_at,
                  ROW_NUMBER() OVER (
                    PARTITION BY workspace.id
                    ORDER BY account.created_at ASC, account.user_id ASC
                  ) AS workspace_owner_rank
           FROM auth_accounts account
           JOIN workspace_members member ON member.user_id = account.user_id
           JOIN workspaces workspace ON workspace.id = member.workspace_id
           WHERE member.role = 'owner'
             AND NOT EXISTS (SELECT 1 FROM account_private_workspaces current
                             WHERE current.user_id = account.user_id)
             AND NOT EXISTS (SELECT 1 FROM account_private_workspaces current
                             WHERE current.workspace_id = workspace.id)
         ), ranked_owned AS (
           SELECT user_id, workspace_id, account_created_at,
                  ROW_NUMBER() OVER (
                    PARTITION BY user_id
                    ORDER BY (archived_at IS NULL) DESC,
                             workspace_created_at ASC, workspace_id ASC
                  ) AS owner_rank
           FROM direct_owners WHERE workspace_owner_rank = 1
         )
         SELECT user_id, workspace_id, account_created_at
         FROM ranked_owned WHERE owner_rank = 1;",
    )?;

    let missing = {
        let mut statement = tx.prepare(
            "SELECT account.user_id, account.created_at, account.updated_at
             FROM auth_accounts account
             WHERE NOT EXISTS (SELECT 1 FROM account_private_workspaces current
                               WHERE current.user_id = account.user_id)
             ORDER BY account.created_at, account.user_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (user_id, created_at, updated_at) in missing {
        let preferred = format!("private-v1:{user_id}");
        let occupied = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = ?1)",
            [&preferred],
            |row| row.get::<_, bool>(0),
        )?;
        let workspace_id = if occupied {
            format!("private-restore-v1:{}", Uuid::now_v7())
        } else {
            preferred
        };
        tx.execute(
            "INSERT INTO workspaces
                (id, tenant_id, name, storage_mode, created_at, updated_at)
             VALUES (?1, NULL, 'My files', 'open', ?2, ?3)",
            params![&workspace_id, &created_at, &updated_at],
        )?;
        tx.execute(
            "INSERT INTO workspace_members (workspace_id, user_id, role)
             VALUES (?1, ?2, 'owner')",
            params![&workspace_id, &user_id],
        )?;
        tx.execute(
            "INSERT INTO account_private_workspaces (user_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3)",
            params![&user_id, &workspace_id, &created_at],
        )?;
    }
    Ok(())
}
