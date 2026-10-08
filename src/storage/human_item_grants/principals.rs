use rusqlite::params;

use crate::{
    error::{ApiError, ApiResult},
    model::SharePrincipal,
};

use super::super::Storage;

mod accounts;

impl Storage {
    pub fn list_share_principals(
        &self,
        kind: &str,
        query: &str,
        limit: usize,
    ) -> ApiResult<Vec<SharePrincipal>> {
        let query = query.trim();
        if query.is_empty() {
            return Err(ApiError::Validation(
                "principal query is required".to_string(),
            ));
        }
        let limit = limit.clamp(1, 50) as i64;
        let conn = self.conn.lock().unwrap();
        if kind == "account" {
            return accounts::list_enabled_accounts(&conn, query, limit);
        }
        if kind != "group" {
            return Err(ApiError::Validation(
                "principal kind must be account or group".to_string(),
            ));
        }
        let mut statement = conn.prepare(
            "SELECT id, name FROM \"groups\" WHERE name LIKE ?1 ESCAPE '\\' ORDER BY name ASC LIMIT ?2",
        )?;
        let pattern = format!("{}%", escape_like(query));
        let rows = statement.query_map(params![pattern, limit], |row| {
            Ok(SharePrincipal {
                kind: "group".to_string(),
                reference: row.get(0)?,
                label: row.get(1)?,
                auth_enabled: None,
                can_receive_grant: true,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
