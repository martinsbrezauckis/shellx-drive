use rusqlite::Transaction;

use crate::error::ApiResult;

use super::quote_identifier;

/// Online restore snapshots monotonic live security authority, replaces the
/// product graph, then reinstates rows still bound to restored subjects. An old
/// backup therefore cannot revive revoked authority or replace host policy.
struct ContinuityTable {
    name: &'static str,
    predicate: Option<&'static str>,
}

// Insertion follows foreign-key dependencies; deletion uses reverse order.
// Predicates fail closed when a referenced live or restored subject is gone.
const CONTINUITY_TABLES: &[ContinuityTable] = &[
    ContinuityTable {
        name: "server_settings",
        predicate: None,
    },
    ContinuityTable {
        name: "backup_policy",
        predicate: None,
    },
    ContinuityTable {
        name: "sandbox_profiles",
        predicate: None,
    },
    ContinuityTable {
        name: "users",
        predicate: None,
    },
    ContinuityTable {
        name: "auth_accounts",
        predicate: Some("EXISTS (SELECT 1 FROM users u WHERE u.id = live.user_id)"),
    },
    ContinuityTable {
        name: "auth_sessions",
        predicate: None,
    },
    ContinuityTable {
        name: "app_tokens",
        predicate: None,
    },
    ContinuityTable {
        name: "agent_principals",
        predicate: None,
    },
    ContinuityTable {
        name: "agent_tokens",
        predicate: Some("EXISTS (SELECT 1 FROM agent_principals p WHERE p.id = live.principal_id)"),
    },
    ContinuityTable {
        name: "auth_attempts",
        predicate: None,
    },
    ContinuityTable {
        name: "password_reset_tokens",
        predicate: None,
    },
    // Preserve current delivery state so an old backup cannot replay messages.
    ContinuityTable {
        name: "email_outbox",
        predicate: None,
    },
    ContinuityTable {
        name: "groups",
        predicate: None,
    },
    ContinuityTable {
        name: "workspace_members",
        predicate: Some(
            "EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id) \
             AND EXISTS (SELECT 1 FROM users u WHERE u.id = live.user_id)",
        ),
    },
    ContinuityTable {
        name: "account_private_workspaces",
        predicate: Some(
            "EXISTS (SELECT 1 FROM auth_accounts a WHERE a.user_id = live.user_id) \
             AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id) \
             AND EXISTS (SELECT 1 FROM workspace_members m WHERE m.workspace_id = live.workspace_id \
                         AND m.user_id = live.user_id AND m.role = 'owner')",
        ),
    },
    ContinuityTable {
        name: "workspace_invitations",
        predicate: Some("EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id)"),
    },
    ContinuityTable {
        name: "group_members",
        predicate: Some(
            "EXISTS (SELECT 1 FROM \"groups\" g WHERE g.id = live.group_id) \
             AND EXISTS (SELECT 1 FROM users u WHERE u.id = live.user_id)",
        ),
    },
    ContinuityTable {
        name: "workspace_group_grants",
        predicate: Some(
            "EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id) \
             AND EXISTS (SELECT 1 FROM \"groups\" g WHERE g.id = live.group_id)",
        ),
    },
    ContinuityTable {
        name: "human_item_grants",
        predicate: Some(
            "EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id) \
             AND EXISTS (SELECT 1 FROM files f WHERE f.id = live.root_file_id \
                         AND f.workspace_id = live.workspace_id) \
             AND (live.principal_kind = 'everyone' \
                  OR (live.principal_kind = 'account' AND EXISTS \
                      (SELECT 1 FROM auth_accounts a WHERE a.user_id = live.principal_ref)) \
                  OR (live.principal_kind = 'group' AND EXISTS \
                      (SELECT 1 FROM \"groups\" g WHERE g.id = live.principal_ref)))",
        ),
    },
    ContinuityTable {
        name: "workspace_policies",
        predicate: Some("EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id)"),
    },
    ContinuityTable {
        name: "agent_folder_grants",
        predicate: Some(
            "EXISTS (SELECT 1 FROM agent_principals p WHERE p.id = live.principal_id) \
             AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id) \
             AND EXISTS (SELECT 1 FROM files f WHERE f.id = live.root_file_id)",
        ),
    },
    ContinuityTable {
        name: "office_edit_sessions",
        predicate: Some("EXISTS (SELECT 1 FROM files f WHERE f.id = live.file_id)"),
    },
    ContinuityTable {
        name: "shares",
        predicate: Some("EXISTS (SELECT 1 FROM files f WHERE f.id = live.file_id)"),
    },
    ContinuityTable {
        name: "share_access_grants",
        predicate: Some("EXISTS (SELECT 1 FROM shares s WHERE s.id = live.share_id)"),
    },
    ContinuityTable {
        name: "drops",
        predicate: Some("EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id)"),
    },
    ContinuityTable {
        name: "drop_upload_sessions",
        predicate: Some(
            "EXISTS (SELECT 1 FROM drops d WHERE d.id = live.drop_id) \
             AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = live.workspace_id) \
             AND (live.file_id IS NULL OR EXISTS (SELECT 1 FROM files f WHERE f.id = live.file_id))",
        ),
    },
];

fn temporary_table_name(table: &str) -> String {
    format!("shellx_restore_live_{table}")
}

pub(super) fn capture(tx: &Transaction<'_>) -> ApiResult<()> {
    for table in CONTINUITY_TABLES {
        let source = quote_identifier(table.name);
        let temporary = quote_identifier(&temporary_table_name(table.name));
        tx.execute_batch(&format!(
            "DROP TABLE IF EXISTS temp.{temporary};\n\
             CREATE TEMP TABLE {temporary} AS SELECT * FROM {source};"
        ))?;
    }
    Ok(())
}

pub(super) fn restore(tx: &Transaction<'_>) -> ApiResult<()> {
    for table in CONTINUITY_TABLES.iter().rev() {
        tx.execute(&format!("DELETE FROM {}", quote_identifier(table.name)), [])?;
    }

    for table in CONTINUITY_TABLES {
        let destination = quote_identifier(table.name);
        let temporary = quote_identifier(&temporary_table_name(table.name));
        let predicate = table
            .predicate
            .map(|value| format!(" WHERE {value}"))
            .unwrap_or_default();
        tx.execute(
            &format!(
                "INSERT INTO {destination} SELECT live.* FROM temp.{temporary} AS live{predicate}"
            ),
            [],
        )?;
    }

    for table in CONTINUITY_TABLES.iter().rev() {
        let temporary = quote_identifier(&temporary_table_name(table.name));
        tx.execute_batch(&format!("DROP TABLE temp.{temporary};"))?;
    }
    Ok(())
}
