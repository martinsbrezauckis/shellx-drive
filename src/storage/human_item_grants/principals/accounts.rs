use rusqlite::{params, Connection, OptionalExtension};

use crate::{error::ApiResult, model::SharePrincipal};

use super::escape_like;

pub(super) fn list_enabled_accounts(
    conn: &Connection,
    query: &str,
    limit: i64,
) -> ApiResult<Vec<SharePrincipal>> {
    // Email is the canonical account identity and current user-facing account
    // label. Preserve an exact address match before offering the bounded prefix
    // picker for that same label.
    let normalized_query = query.to_ascii_lowercase();
    let exact = conn
        .query_row(
            "SELECT email, disabled_at IS NULL FROM auth_accounts
             WHERE email = ?1 COLLATE NOCASE",
            [&normalized_query],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
        )
        .optional()?;
    if let Some((email, enabled)) = exact {
        return Ok(if enabled {
            vec![account_principal(email)]
        } else {
            Vec::new()
        });
    }
    let mut statement = conn.prepare(
        "SELECT email FROM auth_accounts
         WHERE email LIKE ?1 ESCAPE '\\' COLLATE NOCASE AND disabled_at IS NULL
         ORDER BY email ASC LIMIT ?2",
    )?;
    let pattern = format!("{}%", escape_like(&normalized_query));
    let rows = statement.query_map(params![pattern, limit], |row| {
        Ok(account_principal(row.get(0)?))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn account_principal(email: String) -> SharePrincipal {
    SharePrincipal {
        kind: "account".to_string(),
        reference: email.clone(),
        label: email,
        auth_enabled: Some(true),
        can_receive_grant: true,
    }
}
