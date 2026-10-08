use rusqlite::Connection;

pub(super) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let legacy_share_grants = {
        let mut statement = conn.prepare(
            "SELECT g.token_hash, s.password_required, s.password_hash
             FROM share_access_grants g
             JOIN shares s ON s.id = g.share_id
             WHERE g.authorization_fingerprint IS NULL",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (grant_hash, password_required, password_hash) in legacy_share_grants {
        let fingerprint = super::super::super::ShareRecord::authorization_fingerprint_for(
            password_required,
            &password_hash,
        );
        conn.execute(
            "UPDATE share_access_grants
             SET authorization_fingerprint = ?2
             WHERE token_hash = ?1 AND authorization_fingerprint IS NULL",
            rusqlite::params![grant_hash, fingerprint],
        )?;
    }
    // A client binding cannot be reconstructed for capabilities issued by an
    // older binary. Fail closed by retiring those short-lived grants.
    conn.execute(
        "DELETE FROM share_access_grants WHERE client_fingerprint IS NULL",
        [],
    )?;
    conn.execute(
        "UPDATE shares
         SET expires_in_seconds = CASE
             WHEN expires_at IS NULL THEN 0
             WHEN (julianday(expires_at) - julianday('now')) * 86400 <= 45000 THEN 3600
             WHEN (julianday(expires_at) - julianday('now')) * 86400 <= 345600 THEN 86400
             WHEN (julianday(expires_at) - julianday('now')) * 86400 <= 1598400 THEN 604800
             ELSE 2592000
         END
         WHERE expires_in_seconds IS NULL",
        [],
    )?;
    Ok(())
}
