use std::collections::HashSet;

use chrono::Utc;
use rusqlite::{params, Transaction};

use crate::{
    error::ApiResult,
    model::{FileAccessStatistics, WorkspaceFileStatisticsResponse},
};

use super::Storage;

mod public_share;

const FILE_STATISTICS_LIMIT: i64 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccessKind {
    Access,
    Download,
}

impl Storage {
    pub fn record_file_access_best_effort(
        &self,
        file_id: &str,
        workspace_id: &str,
        kind: FileAccessKind,
    ) {
        if let Err(error) = self.record_file_access(file_id, workspace_id, kind) {
            tracing::warn!(%error, ?kind, "file activity counter update failed");
        }
    }

    pub fn record_file_accesses_best_effort(
        &self,
        files: &[(String, String)],
        kind: FileAccessKind,
    ) {
        if let Err(error) = self.record_file_accesses(files, kind) {
            tracing::warn!(%error, ?kind, "file activity counter batch update failed");
        }
    }

    pub fn record_file_access(
        &self,
        file_id: &str,
        workspace_id: &str,
        kind: FileAccessKind,
    ) -> ApiResult<()> {
        self.record_file_accesses(&[(file_id.to_string(), workspace_id.to_string())], kind)
    }

    pub fn record_file_accesses(
        &self,
        files: &[(String, String)],
        kind: FileAccessKind,
    ) -> ApiResult<()> {
        if files.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        let mut unique = HashSet::with_capacity(files.len());
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        for (file_id, workspace_id) in files {
            if unique.insert(file_id.as_str()) {
                record_one(&tx, file_id, workspace_id, kind, &now)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn workspace_file_statistics(
        &self,
        workspace_id: &str,
    ) -> ApiResult<WorkspaceFileStatisticsResponse> {
        let conn = self.conn.lock().unwrap();
        let (access_count, download_count) = conn.query_row(
            "SELECT COALESCE(SUM(access_count), 0), COALESCE(SUM(download_count), 0)
             FROM file_access_stats WHERE workspace_id = ?1",
            [workspace_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let mut statement = conn.prepare(
            "SELECT files.id, files.name, files.parent_id,
                    stats.access_count, stats.download_count,
                    stats.last_accessed_at, stats.last_downloaded_at
             FROM file_access_stats stats
             JOIN files ON files.id = stats.file_id
             WHERE stats.workspace_id = ?1
               AND files.workspace_id = ?1
               AND files.kind = 'file'
               AND files.trashed = 0
             ORDER BY (stats.access_count + stats.download_count) DESC,
                      COALESCE(stats.last_downloaded_at, stats.last_accessed_at) DESC,
                      files.name COLLATE NOCASE
             LIMIT ?2",
        )?;
        let files = statement
            .query_map(params![workspace_id, FILE_STATISTICS_LIMIT], |row| {
                Ok(FileAccessStatistics {
                    file_id: row.get(0)?,
                    name: row.get(1)?,
                    parent_id: row.get(2)?,
                    access_count: row.get(3)?,
                    download_count: row.get(4)?,
                    last_accessed_at: row.get(5)?,
                    last_downloaded_at: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(WorkspaceFileStatisticsResponse {
            workspace_id: workspace_id.to_string(),
            access_count,
            download_count,
            files,
        })
    }
}

pub(super) fn record_one(
    tx: &Transaction<'_>,
    file_id: &str,
    workspace_id: &str,
    kind: FileAccessKind,
    now: &str,
) -> rusqlite::Result<()> {
    match kind {
        FileAccessKind::Access => tx.execute(
            "INSERT INTO file_access_stats
                 (file_id, workspace_id, access_count, download_count, last_accessed_at)
             VALUES (?1, ?2, 1, 0, ?3)
             ON CONFLICT(file_id) DO UPDATE SET
                 access_count = file_access_stats.access_count + 1,
                 last_accessed_at = excluded.last_accessed_at",
            params![file_id, workspace_id, now],
        )?,
        FileAccessKind::Download => tx.execute(
            "INSERT INTO file_access_stats
                 (file_id, workspace_id, access_count, download_count, last_downloaded_at)
             VALUES (?1, ?2, 0, 1, ?3)
             ON CONFLICT(file_id) DO UPDATE SET
                 download_count = file_access_stats.download_count + 1,
                 last_downloaded_at = excluded.last_downloaded_at",
            params![file_id, workspace_id, now],
        )?,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::model::{CreateFileRequest, FileKind};

    use super::*;

    #[test]
    fn aggregates_accesses_downloads_and_deduplicates_archives() {
        let data = tempdir().unwrap();
        let storage = Storage::open(data.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let (workspace, _, _) = storage
            .create_workspace("Stats", "owner@example.test")
            .unwrap();
        let (file, _) = storage
            .create_file(
                CreateFileRequest {
                    workspace_id: workspace.id.clone(),
                    parent_id: None,
                    name: "report.txt".to_string(),
                    kind: FileKind::File,
                    path: None,
                    content: None,
                },
                None,
            )
            .unwrap();

        storage
            .record_file_access(&file.id, &workspace.id, FileAccessKind::Access)
            .unwrap();
        storage
            .record_file_accesses(
                &[
                    (file.id.clone(), workspace.id.clone()),
                    (file.id.clone(), workspace.id.clone()),
                ],
                FileAccessKind::Download,
            )
            .unwrap();

        let statistics = storage.workspace_file_statistics(&workspace.id).unwrap();
        assert_eq!(statistics.access_count, 1);
        assert_eq!(statistics.download_count, 1);
        assert_eq!(statistics.files.len(), 1);
        assert_eq!(statistics.files[0].name, "report.txt");
    }
}
