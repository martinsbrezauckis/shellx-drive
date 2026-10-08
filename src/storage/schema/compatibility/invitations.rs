use rusqlite::Connection;

use super::super::super::{insert_receipt_rows, new_receipt};

/// The route no longer creates two-phase invitation rows. Any pending
/// publication left by an interrupted pre-upgrade process has no safe active
/// snapshot to resume, so fail it closed and remove its delivery state.
pub(super) fn cancel_orphaned_publications(conn: &Connection) -> rusqlite::Result<()> {
    let orphaned = {
        let mut stmt = conn.prepare(
            "SELECT id, invited_by FROM workspace_invitations
             WHERE publication_pending = 1",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (invitation_id, actor) in &orphaned {
        let receipt = new_receipt(
            "workspace.invitation.cancel.stale_publication",
            actor,
            Some(invitation_id),
        );
        insert_receipt_rows(conn, &receipt)?;
    }
    conn.execute_batch(
        "DELETE FROM email_outbox
         WHERE status = 'queued' AND related_type = 'workspace_invitation'
           AND EXISTS (
             SELECT 1 FROM workspace_invitations invitation
             WHERE invitation.id = email_outbox.related_id
               AND invitation.publication_pending = 1
           );
         DELETE FROM notifications
         WHERE related_type = 'workspace_invitation'
           AND EXISTS (
             SELECT 1 FROM workspace_invitations invitation
             WHERE invitation.id = notifications.related_id
               AND invitation.publication_pending = 1
           );
         UPDATE workspace_invitations
         SET status = 'canceled', canceled_at = COALESCE(canceled_at, updated_at),
             publication_pending = 0
         WHERE publication_pending = 1;",
    )
}
