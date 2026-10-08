use rusqlite::{params, OptionalExtension};

use crate::{
    error::{ApiError, ApiResult},
    storage::{ManagedBackupGeneration, Storage},
};

impl Storage {
    /// Classify a backup ID from local durable state before consulting an
    /// archive directory. This is intentionally registry-first: an archive
    /// provider must not turn a managed or retired ID into a legacy/portable
    /// generation by removing or replacing adjacent files.
    pub(crate) fn managed_backup_generation(
        &self,
        backup_id: &str,
    ) -> ApiResult<ManagedBackupGeneration> {
        let conn = self.conn.lock().unwrap();
        if let Some(archive_sha256) = conn
            .query_row(
                "SELECT archive_sha256 FROM managed_backup_publications WHERE backup_id = ?1",
                params![backup_id],
                |row| row.get(0),
            )
            .optional()?
        {
            return Ok(ManagedBackupGeneration::Active { archive_sha256 });
        }
        let tombstoned = conn
            .query_row(
                "SELECT 1 FROM managed_backup_tombstones WHERE backup_id = ?1",
                params![backup_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(if tombstoned {
            ManagedBackupGeneration::Tombstoned
        } else {
            ManagedBackupGeneration::Unmanaged
        })
    }

    /// Return the protected digest recorded when this instance durably
    /// published a managed backup generation. The registry is outside backup
    /// authority, so restore cannot silently reclassify this ID as portable.
    pub(crate) fn managed_backup_archive_sha256(
        &self,
        backup_id: &str,
    ) -> ApiResult<Option<String>> {
        match self.managed_backup_generation(backup_id)? {
            ManagedBackupGeneration::Active { archive_sha256 } => Ok(Some(archive_sha256)),
            ManagedBackupGeneration::Tombstoned => Err(ApiError::NotFound),
            ManagedBackupGeneration::Unmanaged => Ok(None),
        }
    }
}
