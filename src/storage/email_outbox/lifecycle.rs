use rusqlite::{params, Connection};

/// Remove queued capability-bearing delivery that can no longer be redeemed.
/// Sent mail is retained as audit history; inbox notices are removed because
/// their displayed capability state has become stale.
pub(in super::super) fn purge_inactive_delivery_rows_locked(
    conn: &Connection,
    now: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM email_outbox
         WHERE status = 'queued' AND (
             (related_type = 'share' AND NOT EXISTS (
                 SELECT 1 FROM shares
                 WHERE shares.id = email_outbox.related_id
                   AND shares.publication_pending = 0
                   AND shares.revoked = 0
                   AND (shares.expires_at IS NULL
                        OR julianday(shares.expires_at) > julianday(?1))
                   AND (shares.max_uses IS NULL OR shares.access_count < shares.max_uses)
             )) OR
             (related_type = 'workspace_invitation' AND NOT EXISTS (
                 SELECT 1 FROM workspace_invitations
                 WHERE workspace_invitations.id = email_outbox.related_id
                   AND workspace_invitations.publication_pending = 0
                   AND workspace_invitations.status = 'pending'
                   AND julianday(workspace_invitations.expires_at) > julianday(?1)
             ))
         )",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM notifications
         WHERE (related_type = 'share' AND NOT EXISTS (
                    SELECT 1 FROM shares
                    WHERE shares.id = notifications.related_id
                      AND shares.publication_pending = 0
                      AND shares.revoked = 0
                      AND (shares.expires_at IS NULL
                           OR julianday(shares.expires_at) > julianday(?1))
                      AND (shares.max_uses IS NULL OR shares.access_count < shares.max_uses)
                )) OR
               (related_type = 'workspace_invitation' AND NOT EXISTS (
                    SELECT 1 FROM workspace_invitations
                    WHERE workspace_invitations.id = notifications.related_id
                      AND workspace_invitations.publication_pending = 0
                      AND workspace_invitations.status = 'pending'
                      AND julianday(workspace_invitations.expires_at) > julianday(?1)
                ))",
        params![now],
    )?;
    Ok(())
}

pub(in super::super) fn purge_related_delivery_rows_locked(
    conn: &Connection,
    related_type: &str,
    related_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM email_outbox
         WHERE status = 'queued' AND related_type = ?1 AND related_id = ?2",
        params![related_type, related_id],
    )?;
    conn.execute(
        "DELETE FROM notifications WHERE related_type = ?1 AND related_id = ?2",
        params![related_type, related_id],
    )?;
    Ok(())
}
