use std::collections::{HashMap, HashSet};

use rusqlite::params;

use crate::{
    error::{ApiError, ApiResult},
    storage::Storage,
};

const MAX_MANAGED_BACKUP_PUBLICATIONS: usize = 10_000;
pub(super) const MAX_MANAGED_BACKUP_TOMBSTONES: i64 = 10_000;

impl Storage {
    pub(crate) fn managed_backup_publication_digests(&self) -> ApiResult<HashMap<String, String>> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT backup_id, archive_sha256 FROM managed_backup_publications LIMIT ?1",
        )?;
        let rows = statement.query_map(
            params![(MAX_MANAGED_BACKUP_PUBLICATIONS + 1) as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let publications = rows.collect::<rusqlite::Result<HashMap<_, _>>>()?;
        if publications.len() > MAX_MANAGED_BACKUP_PUBLICATIONS {
            return Err(ApiError::PayloadTooLarge(format!(
                "managed backup registry exceeds {MAX_MANAGED_BACKUP_PUBLICATIONS} entries"
            )));
        }
        Ok(publications)
    }

    pub(crate) fn managed_backup_tombstoned_ids(&self) -> ApiResult<HashSet<String>> {
        let conn = self.conn.lock().unwrap();
        let mut statement =
            conn.prepare("SELECT backup_id FROM managed_backup_tombstones LIMIT ?1")?;
        let rows =
            statement.query_map(params![MAX_MANAGED_BACKUP_TOMBSTONES + 1], |row| row.get(0))?;
        let tombstones = rows.collect::<rusqlite::Result<HashSet<_>>>()?;
        if tombstones.len() > MAX_MANAGED_BACKUP_TOMBSTONES as usize {
            return Err(ApiError::PayloadTooLarge(format!(
                "managed backup tombstone registry exceeds {MAX_MANAGED_BACKUP_TOMBSTONES} entries"
            )));
        }
        Ok(tombstones)
    }
}
