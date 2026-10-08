use super::{MAX_SECURITY_EVENTS, SECURITY_EVENT_RETENTION_DAYS};
use std::sync::atomic::{AtomicUsize, Ordering};

mod low_authority;
mod priority;

const MAX_ACTORLESS_FAILED_SECURITY_EVENTS: i64 = 10_000;
const MAX_LOW_AUTHORITY_SECURITY_EVENTS: i64 = 20_000;
const SECURITY_EVENT_PRUNE_INTERVAL: usize = 256;

pub(super) fn maybe_prune_security_metadata(
    conn: &rusqlite::Connection,
    countdown: &AtomicUsize,
) -> rusqlite::Result<()> {
    maybe_prune_with_limits(
        conn,
        countdown,
        SECURITY_EVENT_RETENTION_DAYS,
        MAX_SECURITY_EVENTS,
        MAX_ACTORLESS_FAILED_SECURITY_EVENTS,
        MAX_LOW_AUTHORITY_SECURITY_EVENTS,
        SECURITY_EVENT_PRUNE_INTERVAL,
    )
}

fn maybe_prune_with_limits(
    conn: &rusqlite::Connection,
    countdown: &AtomicUsize,
    retention_days: i64,
    maximum_events: i64,
    maximum_actorless_failed: i64,
    maximum_low_authority: i64,
    interval: usize,
) -> rusqlite::Result<()> {
    if !prune_is_due(countdown) {
        return Ok(());
    }
    // Sweep to cap-minus-one-batch. The next sweep runs on the batch's final
    // successful insert under the same SQLite mutex, so neither hard cap is
    // observable above its documented value between sweeps.
    let batch = i64::try_from(interval).unwrap_or(i64::MAX);
    let result = prune_with_limits(
        conn,
        retention_days,
        maximum_events.saturating_sub(batch).max(0),
        maximum_actorless_failed.saturating_sub(batch).max(0),
        maximum_low_authority.saturating_sub(batch).max(0),
    );
    countdown.store(if result.is_ok() { interval } else { 0 }, Ordering::Relaxed);
    result
}

fn prune_is_due(countdown: &AtomicUsize) -> bool {
    let mut remaining = countdown.load(Ordering::Relaxed);
    loop {
        match countdown.compare_exchange_weak(
            remaining,
            remaining.saturating_sub(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(previous) => return previous <= 1,
            Err(actual) => remaining = actual,
        }
    }
}

fn prune_with_limits(
    conn: &rusqlite::Connection,
    retention_days: i64,
    maximum_events: i64,
    maximum_unattributed_events: i64,
    maximum_low_authority_events: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM security_events
         WHERE julianday(created_at) < julianday('now', ?1)",
        [format!("-{retention_days} days")],
    )?;
    // Delete only the actual overflow count. Rowids are monotonic but not
    // contiguous after retention/pruning, so subtracting a cap from MAX(rowid)
    // can remove protected rows even when the surviving count is below cap.
    let actorless_failed: i64 = conn.query_row(
        "SELECT COUNT(*) FROM security_events
         WHERE actor_email IS NULL AND outcome != 'success'",
        [],
        |row| row.get(0),
    )?;
    let actorless_overflow = actorless_failed.saturating_sub(maximum_unattributed_events.max(0));
    if actorless_overflow > 0 {
        conn.execute(
            "DELETE FROM security_events WHERE rowid IN (
                SELECT rowid FROM security_events
                WHERE actor_email IS NULL AND outcome != 'success'
                ORDER BY rowid ASC LIMIT ?1
             )",
            [actorless_overflow],
        )?;
    }
    low_authority::prune(conn, maximum_low_authority_events)?;
    priority::prune(conn, maximum_events)?;
    conn.execute(
        "UPDATE auth_sessions SET client_ip = NULL, user_agent = NULL
         WHERE (revoked_at IS NOT NULL OR julianday(expires_at) <= julianday('now'))
           AND julianday(COALESCE(last_seen_at, created_at)) < julianday('now', ?1)",
        [format!("-{retention_days} days")],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
