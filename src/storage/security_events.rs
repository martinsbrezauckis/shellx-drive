use chrono::Utc;
use rusqlite::{params, Row};
use uuid::Uuid;

use crate::{error::ApiResult, model::SecurityEvent};

use super::Storage;

pub const SECURITY_EVENT_RETENTION_DAYS: i64 = 90;
pub const MAX_SECURITY_EVENTS: i64 = 100_000;
pub const MAX_SECURITY_EVENT_PAGE: usize = 500;

mod pruning;

#[derive(Debug, Clone)]
pub struct NewSecurityEvent<'a> {
    pub category: &'a str,
    pub action: &'a str,
    pub route: &'a str,
    pub outcome: &'a str,
    pub status_code: u16,
    pub actor_email: Option<&'a str>,
    pub credential_kind: &'a str,
    pub credential_ref: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub client_ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub target_ref: Option<&'a str>,
    pub low_authority: bool,
}

impl Storage {
    pub fn record_security_event(&self, event: NewSecurityEvent<'_>) -> ApiResult<()> {
        let created_at = Utc::now().to_rfc3339();
        let id = Uuid::now_v7().to_string();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO security_events (
                id, category, action, route, outcome, status_code,
                actor_email, credential_kind, credential_ref, session_id, client_ip,
                user_agent, target_ref, created_at, low_authority
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                id,
                bounded(event.category, 32),
                bounded(event.action, 64),
                bounded(event.route, 256),
                bounded(event.outcome, 32),
                i64::from(event.status_code),
                event.actor_email.map(|value| bounded(value, 320)),
                bounded(event.credential_kind, 32),
                event.credential_ref.map(|value| bounded(value, 64)),
                event.session_id.map(|value| bounded(value, 128)),
                event.client_ip.map(|value| bounded(value, 64)),
                event.user_agent.map(|value| bounded(value, 512)),
                event.target_ref.map(|value| bounded(value, 64)),
                created_at,
                i64::from(event.low_authority),
            ],
        )?;
        pruning::maybe_prune_security_metadata(&conn, &self.security_event_prune_countdown)?;
        Ok(())
    }

    pub fn list_security_events(
        &self,
        category: Option<&str>,
        outcome: Option<&str>,
        query: Option<&str>,
        before: Option<&str>,
        before_id: Option<&str>,
        limit: usize,
    ) -> ApiResult<Vec<SecurityEvent>> {
        let category = nonempty_bounded(category, 32);
        let outcome = nonempty_bounded(outcome, 32);
        let search =
            nonempty_bounded(query, 128).map(|value| format!("%{}%", value.to_lowercase()));
        let before = nonempty_bounded(before, 64);
        let before_id = nonempty_bounded(before_id, 64);
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT id, category, action, route, outcome, status_code,
                    actor_email, credential_kind, credential_ref, session_id, client_ip,
                    user_agent, target_ref, created_at
             FROM security_events
             WHERE (?1 IS NULL OR category = ?1)
               AND (?2 IS NULL OR outcome = ?2)
               AND (?3 IS NULL OR lower(
                    category || ' ' || action || ' ' || route || ' ' || outcome || ' ' ||
                    COALESCE(actor_email, '') || ' ' || credential_kind || ' ' ||
                    COALESCE(credential_ref, '') || ' ' ||
                    COALESCE(client_ip, '') || ' ' || COALESCE(user_agent, '') || ' ' ||
                    COALESCE(target_ref, '')
               ) LIKE ?3)
               AND (?4 IS NULL OR created_at < ?4
                    OR (created_at = ?4 AND ?5 IS NOT NULL AND id < ?5))
             ORDER BY created_at DESC, id DESC
             LIMIT ?6",
        )?;
        let rows = statement.query_map(
            params![
                category,
                outcome,
                search,
                before,
                before_id,
                i64::try_from(limit.min(MAX_SECURITY_EVENT_PAGE)).unwrap_or(500),
            ],
            row_to_security_event,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_login_security_events_for_actor(
        &self,
        actor_email: &str,
        limit: usize,
    ) -> ApiResult<Vec<SecurityEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT id, category, action, route, outcome, status_code,
                    actor_email, credential_kind, credential_ref, session_id, client_ip,
                    user_agent, target_ref, created_at
             FROM security_events
             WHERE category = 'login' AND actor_email = ?1
             ORDER BY created_at DESC, id DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![
                actor_email,
                i64::try_from(limit.min(MAX_SECURITY_EVENT_PAGE)).unwrap_or(100),
            ],
            row_to_security_event,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn row_to_security_event(row: &Row<'_>) -> rusqlite::Result<SecurityEvent> {
    Ok(SecurityEvent {
        id: row.get(0)?,
        category: row.get(1)?,
        action: row.get(2)?,
        route: row.get(3)?,
        outcome: row.get(4)?,
        status_code: row.get(5)?,
        actor_email: row.get(6)?,
        credential_kind: row.get(7)?,
        credential_ref: row.get(8)?,
        session_id: row.get(9)?,
        client_ip: row.get(10)?,
        user_agent: row.get(11)?,
        target_ref: row.get(12)?,
        created_at: row.get(13)?,
    })
}

fn nonempty_bounded(value: Option<&str>, maximum: usize) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| bounded(value, maximum))
}

fn bounded(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod pagination_tests {
    use super::{NewSecurityEvent, Storage};

    #[test]
    fn tied_timestamps_remain_reachable_across_pages() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        for _ in 0..3 {
            storage
                .record_security_event(NewSecurityEvent {
                    category: "command",
                    action: "GET",
                    route: "/test",
                    outcome: "success",
                    status_code: 200,
                    actor_email: None,
                    credential_kind: "operator",
                    credential_ref: None,
                    session_id: None,
                    client_ip: None,
                    user_agent: None,
                    target_ref: None,
                    low_authority: false,
                })
                .unwrap();
        }
        storage
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE security_events SET created_at = '2026-09-23T12:00:00Z'",
                [],
            )
            .unwrap();
        let mut seen = Vec::new();
        let mut before = None;
        let mut before_id = None;
        for _ in 0..3 {
            let page = storage
                .list_security_events(None, None, None, before, before_id.as_deref(), 1)
                .unwrap();
            assert_eq!(page.len(), 1);
            seen.push(page[0].id.clone());
            before = Some("2026-09-23T12:00:00Z");
            before_id = seen.last().cloned();
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 3);
    }
}
