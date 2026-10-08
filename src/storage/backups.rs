use std::{collections::HashSet, fs::File, io::BufReader, path::Path};

use chrono::Utc;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    backup_v2::{
        self, V2ArchiveIdentity, V2BlobSource, V2CreatedArchive, V2ExtractedSnapshot, V2Limits,
        V2StagedSnapshot, V2TableSchema, V2TableStageWriter,
    },
    blob,
    error::{ApiError, ApiResult},
    model::{BackupJob, BackupTable, Receipt},
};

use super::{
    authorization, auxiliary_storage, bounded_backup_job_error, insert_receipt_rows,
    json_to_sql_value, new_receipt, query_backup_job, quote_identifier, read_backup_v2_line,
    row_to_backup_job, sql_value_to_json, table_columns, table_primary_key_columns,
    BackupV2TableHeader, Storage, BACKUP_TABLES,
};
const MAX_ACTIVE_BACKUP_JOBS: i64 = 32;
const MAX_TERMINAL_BACKUP_JOBS: i64 = 500;
mod file_names;
mod job_authorization;
mod private_workspace_continuity;
pub(crate) mod publication;
mod restore_accounting;
mod restore_delegated_agent;
mod restore_desktop_agent;
mod restore_file_metadata;
mod restore_human_item_sharing;
mod restore_jobs;
mod restore_legacy;
mod restore_support;
mod restore_topology;
mod restore_validation;
mod security_continuity;
struct BackupBlobInstallGuard {
    storage: Storage,
    data_dir: std::path::PathBuf,
    shared_lock: Option<blob::BlobLifecycleLock>,
    publications: Vec<blob::BlobFilePublication>,
}

impl BackupBlobInstallGuard {
    fn acquire(storage: &Storage, data_dir: &Path) -> ApiResult<Self> {
        Ok(Self {
            storage: storage.clone(),
            data_dir: data_dir.to_path_buf(),
            shared_lock: Some(blob::BlobLifecycleLock::acquire_shared(data_dir)?),
            publications: Vec::new(),
        })
    }

    fn put_file(&mut self, path: &Path) -> ApiResult<blob::BlobFilePublication> {
        let publication = blob::put_blob_file_with_outcome(&self.data_dir, path)?;
        self.publications.push(publication.clone());
        Ok(publication)
    }

    fn disarm(mut self) {
        self.publications.clear();
        drop(self.shared_lock.take());
    }

    fn cleanup(&mut self) -> ApiResult<()> {
        let created = std::mem::take(&mut self.publications)
            .into_iter()
            .filter(|item| item.created)
            .map(|item| item.hash)
            .collect::<std::collections::BTreeSet<_>>();
        drop(self.shared_lock.take());
        if created.is_empty() {
            return Ok(());
        }
        let _exclusive = blob::BlobLifecycleLock::acquire_exclusive(&self.data_dir)?;
        for hash in created {
            if !self.storage.content_hash_is_referenced(&hash)? {
                blob::remove_blob(&self.data_dir, &hash)?;
            }
        }
        Ok(())
    }
}

impl Drop for BackupBlobInstallGuard {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::error!(%error, "failed to compensate rejected backup blob installation");
        }
    }
}

fn validate_backup_job_id(kind: &str, backup_id: &str) -> ApiResult<()> {
    if !matches!(kind, "create" | "validate" | "restore") {
        return Err(ApiError::Validation(
            "unsupported backup job kind".to_string(),
        ));
    }
    if backup_id.is_empty()
        || backup_id.len() > 128
        || !backup_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ApiError::Validation("invalid backup job id".to_string()));
    }
    Ok(())
}

fn prune_terminal_backup_jobs_in_tx(tx: &rusqlite::Transaction<'_>) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM backup_jobs WHERE id IN (
             SELECT id FROM backup_jobs
             WHERE status IN ('succeeded', 'failed', 'interrupted')
             ORDER BY updated_at DESC, id DESC
             LIMIT -1 OFFSET ?1
         )",
        params![MAX_TERMINAL_BACKUP_JOBS],
    )?;
    Ok(())
}

impl Storage {
    /// Enqueue trusted internal scheduler work under the explicit
    /// `system_scheduled` authority class.
    pub(crate) fn enqueue_scheduled_backup_job(
        &self,
        kind: &str,
        backup_id: &str,
        actor: &str,
    ) -> ApiResult<BackupJob> {
        self.enqueue_backup_job_inner(kind, backup_id, actor, None)
    }

    pub(crate) fn enqueue_authorized_backup_job(
        &self,
        kind: &str,
        backup_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<BackupJob> {
        self.enqueue_backup_job_inner(
            kind,
            backup_id,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    pub(crate) fn enqueue_authorized_backup_restore_job(
        &self,
        backup_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<BackupJob> {
        self.enqueue_authorized_backup_job("restore", backup_id, actor, source_credential)
    }

    fn enqueue_backup_job_inner(
        &self,
        kind: &str,
        backup_id: &str,
        actor_email: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<BackupJob> {
        validate_backup_job_id(kind, backup_id)?;
        let id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        let (credential_kind, credential_id, credential_generation) =
            job_authorization::queued_authority_metadata(
                authorization_context,
                self.operator_credential_generation.as_ref(),
            )?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some((actor, source_credential)) = authorization_context {
            authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        }
        job_authorization::fail_stale_jobs(&tx, self.operator_credential_generation.as_ref())?;
        prune_terminal_backup_jobs_in_tx(&tx)?;
        let active_jobs: i64 = tx.query_row(
            "SELECT COUNT(*) FROM backup_jobs WHERE status IN ('queued', 'running')",
            [],
            |row| row.get(0),
        )?;
        if active_jobs >= MAX_ACTIVE_BACKUP_JOBS {
            return Err(ApiError::TooManyRequests);
        }
        let duplicate: i64 = tx.query_row(
            "SELECT COUNT(*) FROM backup_jobs
             WHERE backup_id = ?1 AND kind = ?2 AND status IN ('queued', 'running')",
            params![backup_id, kind],
            |row| row.get(0),
        )?;
        if duplicate != 0 {
            return Err(ApiError::Conflict);
        }
        tx.execute(
            "INSERT INTO backup_jobs
                (id, backup_id, kind, format, status, phase, actor,
                 source_credential_kind, source_credential_id,
                 source_credential_generation,
                 archive_sha256, last_error, created_at, updated_at,
                 started_at, finished_at)
             VALUES (?1, ?2, ?3, 'shellx-drive-backup-v2', 'queued', 'queued',
                     ?4, ?5, ?6, ?7, NULL, NULL, ?8, ?8, NULL, NULL)",
            params![
                &id,
                backup_id,
                kind,
                actor_email,
                credential_kind,
                credential_id,
                credential_generation,
                &now,
            ],
        )?;
        let job = query_backup_job(&tx, &id)?.ok_or(ApiError::NotFound)?;
        tx.commit()?;
        Ok(job)
    }

    pub(crate) fn ensure_backup_job_authorized(&self, job_id: &str) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        job_authorization::ensure_job_authorized(
            &tx,
            job_id,
            self.operator_credential_generation.as_ref(),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn ensure_backup_restore_job_authorized(&self, job_id: &str) -> ApiResult<()> {
        self.ensure_backup_job_authorized(job_id)
    }

    /// Commit the authorization decision that permits a backup response body to
    /// be published. The receipt is deliberately written in the same immediate
    /// transaction as current credential and administrator revalidation: a
    /// revocation that commits first prevents response publication, while a
    /// later revocation observes an already-authorized durable intent.
    pub(crate) fn create_backup_download_publication_intent(
        &self,
        backup_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        self.create_backup_lifecycle_intent("backup.download", backup_id, actor, source_credential)
    }

    /// Commit the authorization decision that permits irreversible backup
    /// removal. Callers must create this intent immediately before the first
    /// filesystem mutation, not at request authentication time.
    pub(crate) fn create_backup_delete_intent(
        &self,
        backup_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        self.create_backup_lifecycle_intent(
            "backup.delete.intent",
            backup_id,
            actor,
            source_credential,
        )
    }

    fn create_backup_lifecycle_intent(
        &self,
        kind: &str,
        backup_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let receipt = new_receipt(kind, &actor.email, Some(backup_id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn get_backup_job(&self, job_id: &str) -> ApiResult<Option<BackupJob>> {
        let conn = self.conn.lock().unwrap();
        query_backup_job(&conn, job_id)
    }

    pub fn latest_backup_job(&self, backup_id: &str) -> ApiResult<Option<BackupJob>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, backup_id, kind, format, status, phase, actor,
                    archive_sha256, last_error, created_at, updated_at,
                    started_at, finished_at
             FROM backup_jobs
             WHERE backup_id = ?1
             ORDER BY created_at DESC
             LIMIT 1",
            params![backup_id],
            row_to_backup_job,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn list_backup_jobs(&self) -> ApiResult<Vec<BackupJob>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, backup_id, kind, format, status, phase, actor,
                    archive_sha256, last_error, created_at, updated_at,
                    started_at, finished_at
             FROM backup_jobs
             ORDER BY created_at DESC
             LIMIT 500",
        )?;
        let rows = stmt.query_map([], row_to_backup_job)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn claim_next_backup_job(&self) -> ApiResult<Option<BackupJob>> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        job_authorization::fail_stale_jobs(&tx, self.operator_credential_generation.as_ref())?;
        let id: Option<String> = tx
            .query_row(
                "SELECT id FROM backup_jobs
                 WHERE status = 'queued'
                   AND NOT EXISTS (
                       SELECT 1 FROM backup_jobs active WHERE active.status = 'running'
                   )
                 ORDER BY created_at ASC
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            tx.commit()?;
            return Ok(None);
        };
        let changed = tx.execute(
            "UPDATE backup_jobs
             SET status = 'running', phase = 'starting', last_error = NULL,
                 started_at = ?1, finished_at = NULL, updated_at = ?1
             WHERE id = ?2 AND status = 'queued'",
            params![now, id],
        )?;
        let job = if changed == 1 {
            query_backup_job(&tx, &id)?
        } else {
            None
        };
        tx.commit()?;
        Ok(job)
    }

    pub fn claim_backup_job(&self, job_id: &str) -> ApiResult<Option<BackupJob>> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        job_authorization::fail_stale_jobs(&tx, self.operator_credential_generation.as_ref())?;
        let changed = tx.execute(
            "UPDATE backup_jobs
             SET status = 'running', phase = 'starting', last_error = NULL,
                 started_at = ?1, finished_at = NULL, updated_at = ?1
             WHERE id = ?2 AND status = 'queued'
               AND NOT EXISTS (
                   SELECT 1 FROM backup_jobs active WHERE active.status = 'running'
               )",
            params![now, job_id],
        )?;
        let job = if changed == 1 {
            query_backup_job(&tx, job_id)?
        } else {
            None
        };
        tx.commit()?;
        Ok(job)
    }

    pub fn update_backup_job_phase(&self, job_id: &str, phase: &str) -> ApiResult<()> {
        if phase.is_empty() || phase.len() > 64 || !phase.is_ascii() {
            return Err(ApiError::Validation("invalid backup job phase".to_string()));
        }
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE backup_jobs SET phase = ?1, updated_at = ?2
             WHERE id = ?3 AND status = 'running'",
            params![phase, now, job_id],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(ApiError::Conflict)
        }
    }

    pub fn finish_backup_job(
        &self,
        job_id: &str,
        status: &str,
        phase: &str,
        archive_sha256: Option<&str>,
        error: Option<&str>,
    ) -> ApiResult<BackupJob> {
        if !matches!(status, "succeeded" | "failed" | "interrupted") {
            return Err(ApiError::Validation(
                "invalid terminal backup job status".to_string(),
            ));
        }
        let error = error.map(|value| bounded_backup_job_error(value, 2048));
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE backup_jobs
             SET status = ?1, phase = ?2, archive_sha256 = ?3,
                 last_error = ?4, updated_at = ?5, finished_at = ?5
             WHERE id = ?6 AND status = 'running'",
            params![status, phase, archive_sha256, error, now, job_id],
        )?;
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        query_backup_job(&conn, job_id)?.ok_or(ApiError::NotFound)
    }

    pub fn interrupt_running_backup_jobs(&self) -> ApiResult<usize> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(
            "UPDATE backup_jobs
             SET status = 'interrupted', phase = 'interrupted_' || substr(phase, 1, 48),
                 last_error = 'service restarted before the operation completed',
                 updated_at = ?1, finished_at = ?1
             WHERE status = 'running'",
            params![now],
        )?)
    }

    pub(crate) fn fail_stale_backup_jobs(&self) -> ApiResult<usize> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let failed =
            job_authorization::fail_stale_jobs(&tx, self.operator_credential_generation.as_ref())?;
        tx.commit()?;
        Ok(failed)
    }

    pub fn interrupt_backup_job(&self, job_id: &str) -> ApiResult<BackupJob> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE backup_jobs
             SET status = 'interrupted', phase = 'interrupted_' || substr(phase, 1, 48),
                 last_error = 'service twin interrupted its own backup job',
                 updated_at = ?1, finished_at = ?1
             WHERE id = ?2 AND status = 'running'",
            params![now, job_id],
        )?;
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        query_backup_job(&conn, job_id)?.ok_or(ApiError::NotFound)
    }

    pub fn export_backup_tables(&self) -> ApiResult<Vec<BackupTable>> {
        let conn = self.conn.lock().unwrap();
        let mut tables = Vec::new();
        for table in BACKUP_TABLES {
            let quoted_table = quote_identifier(table);
            let columns = table_columns(&conn, table)?;
            let mut stmt = conn.prepare(&format!("SELECT * FROM {quoted_table}"))?;
            let mut rows = stmt.query([])?;
            let mut exported_rows = Vec::new();
            while let Some(row) = rows.next()? {
                let mut values = Vec::new();
                for index in 0..columns.len() {
                    values.push(sql_value_to_json(row.get_ref(index)?));
                }
                exported_rows.push(values);
            }
            tables.push(BackupTable {
                name: (*table).to_string(),
                columns,
                rows: exported_rows,
            });
        }
        Ok(tables)
    }

    /// Return the exact ordered database shape accepted by backup v2.
    pub fn backup_v2_schema(&self) -> ApiResult<Vec<V2TableSchema>> {
        let conn = self.conn.lock().unwrap();
        BACKUP_TABLES
            .iter()
            .map(|table| {
                Ok(V2TableSchema {
                    name: (*table).to_string(),
                    columns: table_columns(&conn, table)?,
                })
            })
            .collect()
    }

    /// Export one transactionally consistent snapshot directly into v2 JSONL
    /// staging files without accumulating rows or blobs in memory. The SQLite
    /// read transaction stays open so a generation cannot mix revisions.
    pub(crate) fn create_backup_v2_archive(
        &self,
        data_dir: &Path,
        archive_path: &Path,
        staging_root: &Path,
        identity: V2ArchiveIdentity<'_>,
        limits: V2Limits,
    ) -> ApiResult<V2CreatedArchive> {
        backup_v2::create_archive_atomic_streaming(
            archive_path,
            staging_root,
            identity,
            limits,
            |stage_dir, limits| {
                let mut conn = self.conn.lock().unwrap();
                let tx = conn.transaction()?;
                file_names::validate_canonical_file_names_in_tx(&tx)?;
                let database_pages: u64 =
                    tx.query_row("PRAGMA page_count", [], |row| row.get(0))?;
                let database_page_bytes: u64 =
                    tx.query_row("PRAGMA page_size", [], |row| row.get(0))?;
                // SQLite pages include indexes and free space. Eight times the
                // database footprint also covers worst-case JSON string
                // escaping plus JSONL structure, without trusting row content
                // before the staging admission check.
                let estimated_table_bytes = database_pages
                    .checked_mul(database_page_bytes)
                    .and_then(|bytes| bytes.checked_mul(8))
                    .ok_or_else(|| {
                        ApiError::PayloadTooLarge(
                            "backup generation staging estimate overflow".to_string(),
                        )
                    })?;
                if estimated_table_bytes > limits.max_archive_bytes {
                    return Err(ApiError::PayloadTooLarge(format!(
                        "backup generation staging estimate is {estimated_table_bytes} bytes; archive limit is {} bytes",
                        limits.max_archive_bytes
                    )));
                }
                backup_v2::ensure_generation_staging_free_space(stage_dir, estimated_table_bytes)?;
                let mut staged_tables = Vec::with_capacity(BACKUP_TABLES.len());
                let mut referenced_hashes = HashSet::new();
                let mut total_rows = 0u64;
                let mut total_table_bytes = 0u64;

                for (order, table) in BACKUP_TABLES.iter().enumerate() {
                    let columns = table_columns(&tx, table)?;
                    let ordering = table_primary_key_columns(&tx, table)?;
                    let ordering = if ordering.is_empty() {
                        columns.clone()
                    } else {
                        ordering
                    };
                    let order_sql = ordering
                        .iter()
                        .map(|column| quote_identifier(column))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let sql = format!(
                        "SELECT * FROM {} ORDER BY {order_sql}",
                        quote_identifier(table)
                    );
                    let mut statement = tx.prepare(&sql)?;
                    let mut rows = statement.query([])?;
                    let mut writer = V2TableStageWriter::new(
                        stage_dir,
                        order as u64,
                        table,
                        columns.clone(),
                        limits,
                        total_table_bytes,
                    )?;
                    while let Some(row) = rows.next()? {
                        let values = (0..columns.len())
                            .map(|index| Ok(sql_value_to_json(row.get_ref(index)?)))
                            .collect::<rusqlite::Result<Vec<_>>>()?;
                        writer.write_row(&values)?;
                        total_rows = total_rows.checked_add(1).ok_or_else(|| {
                            ApiError::PayloadTooLarge(
                                "backup v2 total row count overflow".to_string(),
                            )
                        })?;
                        if total_rows > limits.max_rows {
                            return Err(ApiError::PayloadTooLarge(format!(
                                "backup v2 has more than {} rows",
                                limits.max_rows
                            )));
                        }
                    }
                    let (staged, hashes) = writer.finish()?;
                    total_table_bytes = total_table_bytes
                        .checked_add(staged.descriptor.byte_length)
                        .ok_or_else(|| {
                            ApiError::PayloadTooLarge(
                                "backup v2 aggregate table byte count overflow".to_string(),
                            )
                        })?;
                    referenced_hashes.extend(hashes);
                    staged_tables.push(staged);
                }

                tx.commit()?;
                let blobs = referenced_hashes
                    .iter()
                    .map(|hash| {
                        Ok(V2BlobSource {
                            hash: hash.clone(),
                            path: blob::blob_file_path(data_dir, hash)?,
                        })
                    })
                    .collect::<ApiResult<Vec<_>>>()?;
                Ok(V2StagedSnapshot {
                    tables: staged_tables,
                    referenced_hashes,
                    blobs,
                })
            },
        )
    }

    /// Count the complete legacy export before allocating its row graph. The
    /// exact snapshot is counted again after export because ordinary writes may
    /// land between these two separately locked reads.
    pub fn backup_row_count(&self) -> ApiResult<u64> {
        let conn = self.conn.lock().unwrap();
        BACKUP_TABLES.iter().try_fold(0u64, |total, table| {
            let count: i64 = conn.query_row(
                &format!("SELECT COUNT(*) FROM {}", quote_identifier(table)),
                [],
                |row| row.get(0),
            )?;
            let count = u64::try_from(count).map_err(|_| {
                ApiError::Validation(format!("backup table {table} has a negative row count"))
            })?;
            total
                .checked_add(count)
                .ok_or_else(|| ApiError::Validation("backup row count overflow".to_string()))
        })
    }

    /// Validate a backup's database shape before any restore mutates live state.
    pub fn validate_backup_tables(&self, tables: &[BackupTable]) -> ApiResult<()> {
        restore_desktop_agent::reject_backup_table_names(
            tables.iter().map(|table| table.name.as_str()),
        )?;
        let current_count = BACKUP_TABLES.len();
        let legacy_item_sharing_count =
            crate::backup_schema_compatibility::HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES
                .len();
        if tables.len() != current_count
            && tables.len().saturating_add(legacy_item_sharing_count) != current_count
        {
            return Err(ApiError::Validation(format!(
                "backup contains {} tables; expected {}",
                tables.len(),
                current_count
            )));
        }

        let conn = self.conn.lock().unwrap();
        let mut seen = HashSet::new();
        for table in tables {
            if !BACKUP_TABLES.contains(&table.name.as_str()) {
                return Err(ApiError::Validation(format!(
                    "backup contains unknown table {}",
                    table.name
                )));
            }
            if !seen.insert(table.name.as_str()) {
                return Err(ApiError::Validation(format!(
                    "backup contains duplicate table {}",
                    table.name
                )));
            }

            let expected_columns = table_columns(&conn, &table.name)?;
            if !backup_columns_are_compatible(&table.name, &table.columns, &expected_columns) {
                return Err(ApiError::Validation(format!(
                    "backup table {} columns do not match current schema",
                    table.name
                )));
            }
            for row in &table.rows {
                if row.len() != table.columns.len() {
                    return Err(ApiError::Validation(format!(
                        "backup table {} row has wrong column count",
                        table.name
                    )));
                }
                for value in row {
                    json_to_sql_value(value)?;
                }
            }
        }

        let missing = BACKUP_TABLES
            .iter()
            .copied()
            .filter(|table| !seen.contains(*table))
            .collect::<Vec<_>>();
        match missing.as_slice() {
            [] => Ok(()),
            missing
                if missing
                    == crate::backup_schema_compatibility::HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES =>
            {
                Ok(())
            }
            [missing, ..] => Err(ApiError::Validation(format!(
                "backup is missing table {missing}"
            ))),
        }
    }

    /// Restore a previously validated and digest-checked v2 extraction without
    /// loading its table graph or blob bodies into memory.
    pub(crate) fn restore_backup_v2_extracted(
        &self,
        data_dir: &Path,
        snapshot: &V2ExtractedSnapshot,
        limits: V2Limits,
        job_id: &str,
    ) -> ApiResult<()> {
        let archived_table_names = snapshot
            .manifest
            .tables
            .iter()
            .map(|table| table.name.as_str())
            .collect::<Vec<_>>();
        restore_desktop_agent::reject_backup_table_names(archived_table_names.iter().copied())?;
        let sharing_tables_omitted =
            crate::backup_schema_compatibility::omits_historical_human_item_sharing_tables(
                &archived_table_names,
                BACKUP_TABLES,
            );
        if (!sharing_tables_omitted && snapshot.manifest.tables.len() != BACKUP_TABLES.len())
            || snapshot.table_paths.len() != snapshot.manifest.tables.len()
            || snapshot.blob_paths.len() != snapshot.manifest.blobs.len()
        {
            return Err(ApiError::Validation(
                "backup v2 extracted snapshot shape is incomplete".to_string(),
            ));
        }
        let expected_tables = BACKUP_TABLES
            .iter()
            .copied()
            .filter(|table| {
                !sharing_tables_omitted
                    || !crate::backup_schema_compatibility::HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES
                        .contains(table)
            })
            .collect::<Vec<_>>();

        backup_v2::ensure_restore_free_space(
            data_dir,
            backup_v2::restore_payload_bytes(&snapshot.manifest)?,
        )?;
        let mut installed_blobs = BackupBlobInstallGuard::acquire(self, data_dir)?;
        // Install immutable content first, but retain request-local ownership
        // until every relational constraint and the database commit succeeds.
        for ((expected_hash, path), descriptor) in snapshot
            .blob_paths
            .iter()
            .zip(snapshot.manifest.blobs.iter())
        {
            if expected_hash != &descriptor.hash {
                return Err(ApiError::Validation(
                    "backup v2 extracted blob order is invalid".to_string(),
                ));
            }
            let publication = installed_blobs.put_file(path)?;
            if publication.hash != descriptor.hash || publication.size != descriptor.byte_length {
                return Err(ApiError::Validation(
                    "backup v2 blob changed during installation".to_string(),
                ));
            }
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        job_authorization::ensure_job_authorized(
            &tx,
            job_id,
            self.operator_credential_generation.as_ref(),
        )?;
        let live_access_generation = restore_human_item_sharing::current_access_generation(&tx)?;
        security_continuity::capture(&tx)?;
        for table in BACKUP_TABLES.iter().rev() {
            tx.execute(&format!("DELETE FROM {}", quote_identifier(table)), [])?;
        }
        restore_delegated_agent::purge_sso_parent_bindings_in_tx(&tx)?;
        restore_desktop_agent::purge_local_state_in_tx(&tx)?;
        #[cfg(test)]
        restore_support::fail_after_reverse_deletes(data_dir)?;

        let mut total_rows = 0u64;
        let mut archived_access_generation = None;
        for (index, ((expected_name, descriptor), path)) in expected_tables
            .iter()
            .zip(snapshot.manifest.tables.iter())
            .zip(snapshot.table_paths.iter())
            .enumerate()
        {
            let expected_columns = table_columns(&tx, expected_name)?;
            if descriptor.order != index as u64
                || descriptor.name != *expected_name
                || !backup_columns_are_compatible(
                    expected_name,
                    &descriptor.columns,
                    &expected_columns,
                )
            {
                return Err(ApiError::Validation(format!(
                    "backup v2 table {} no longer matches the running schema",
                    descriptor.name
                )));
            }
            let mut reader = BufReader::with_capacity(16 * 1024, File::open(path)?);
            let header = read_backup_v2_line(&mut reader, limits.max_line_bytes)?
                .ok_or_else(|| ApiError::Validation("backup v2 table is empty".to_string()))?;
            let header: BackupV2TableHeader = serde_json::from_slice(&header).map_err(|error| {
                ApiError::Validation(format!(
                    "backup v2 table {} has an invalid header: {error}",
                    descriptor.name
                ))
            })?;
            if header.columns != descriptor.columns {
                return Err(ApiError::Validation(format!(
                    "backup v2 table {} header columns do not match manifest",
                    descriptor.name
                )));
            }

            let columns = descriptor
                .columns
                .iter()
                .map(|column| quote_identifier(column))
                .collect::<Vec<_>>()
                .join(", ");
            let placeholders = std::iter::repeat_n("?", descriptor.columns.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO {} ({columns}) VALUES ({placeholders})",
                quote_identifier(&descriptor.name)
            );
            // Never import extracted text without a current revision/hash subject.
            let mut statement = (descriptor.name != "background_jobs"
                && (descriptor.name != "file_text_index"
                    || file_text_index_has_current_subject_columns(&descriptor.columns)))
            .then(|| tx.prepare(&sql))
            .transpose()?;
            let mut table_rows = 0u64;
            while let Some(line) = read_backup_v2_line(&mut reader, limits.max_line_bytes)? {
                if line.is_empty() {
                    return Err(ApiError::Validation(format!(
                        "backup v2 table {} contains an empty row",
                        descriptor.name
                    )));
                }
                let row: Vec<Value> = serde_json::from_slice(&line).map_err(|error| {
                    ApiError::Validation(format!(
                        "backup v2 table {} contains invalid JSONL: {error}",
                        descriptor.name
                    ))
                })?;
                if row.len() != descriptor.columns.len() {
                    return Err(ApiError::Validation(format!(
                        "backup v2 table {} row has wrong column count",
                        descriptor.name
                    )));
                }
                let values = row
                    .iter()
                    .map(json_to_sql_value)
                    .collect::<ApiResult<Vec<_>>>()?;
                if descriptor.name == "human_item_access_generation" {
                    restore_human_item_sharing::record_v2_access_generation(
                        &descriptor.columns,
                        &row,
                        &mut archived_access_generation,
                    )?;
                }
                if let Some(statement) = statement.as_mut() {
                    statement.execute(params_from_iter(values))?;
                } else if descriptor.name == "background_jobs" {
                    restore_jobs::admit_row(&tx, &descriptor.columns, &row)?;
                }
                table_rows = table_rows.checked_add(1).ok_or_else(|| {
                    ApiError::PayloadTooLarge("backup v2 row count overflow".to_string())
                })?;
                total_rows = total_rows.checked_add(1).ok_or_else(|| {
                    ApiError::PayloadTooLarge("backup v2 total row count overflow".to_string())
                })?;
                if table_rows > descriptor.row_count || total_rows > limits.max_rows {
                    return Err(ApiError::PayloadTooLarge(
                        "backup v2 restore exceeded its row limit".to_string(),
                    ));
                }
            }
            if table_rows != descriptor.row_count {
                return Err(ApiError::Validation(format!(
                    "backup v2 table {} restored {table_rows} rows; manifest declares {}",
                    descriptor.name, descriptor.row_count
                )));
            }
        }
        security_continuity::restore(&tx)?;
        private_workspace_continuity::reconcile(&tx)?;
        restore_human_item_sharing::finalize_access_generation(
            &tx,
            live_access_generation,
            archived_access_generation,
            sharing_tables_omitted,
        )?;
        let reconcile_legacy_cover_bytes = snapshot
            .manifest
            .tables
            .iter()
            .find(|table| table.name == "files")
            .is_some_and(|table| !table.columns.iter().any(|column| column == "cover_bytes"));
        restore_validation::validate_in_tx(
            &tx,
            &snapshot.manifest.blobs,
            reconcile_legacy_cover_bytes,
        )?;
        let now = Utc::now().to_rfc3339();
        let changed = tx.execute(
            "UPDATE backup_jobs SET phase = 'committed', updated_at = ?1
             WHERE id = ?2 AND status = 'running'",
            params![now, job_id],
        )?;
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        Storage::backfill_upload_session_quota_reservations_in_tx(&tx)?;
        restore_validation::validate_upload_session_reservations_in_tx(&tx)?;
        rebuild_file_search_fts_in_tx(&tx)?;
        auxiliary_storage::rebuild_workspace_auxiliary_storage_usage_in_tx(&tx)?;
        tx.commit()?;
        drop(conn);
        installed_blobs.disarm();
        Ok(())
    }
}

/// `file_search_fts` is derived data, not backup authority. Recreate it from
/// the restored source rows before committing either backup format so search is
/// immediately correct after recovery even when the prior process had cleared
/// or stale FTS contents.
fn rebuild_file_search_fts_in_tx(conn: &Connection) -> ApiResult<()> {
    conn.execute("DELETE FROM file_search_fts", [])?;
    let rows = {
        let mut statement = conn.prepare(
            "SELECT files.id,
                    files.workspace_id,
                    files.name,
                    COALESCE(file_metadata.labels_json, '[]'),
                    COALESCE(file_metadata.custom_json, '{}'),
                    COALESCE(file_text_index.content_text, '')
             FROM files
             LEFT JOIN file_metadata ON file_metadata.file_id = files.id
             LEFT JOIN file_text_index
               ON file_text_index.file_id = files.id
              AND file_text_index.workspace_id = files.workspace_id
              AND file_text_index.source_revision = files.revision
              AND file_text_index.source_content_hash IS files.content_hash",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (file_id, workspace_id, name, labels_json, custom_json, content) in rows {
        let metadata =
            auxiliary_storage::project_persisted_file_metadata_storage(&labels_json, &custom_json)?;
        conn.execute(
            "INSERT INTO file_search_fts (file_id, workspace_id, name, labels, metadata, content)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                file_id,
                workspace_id,
                name,
                metadata.labels_json,
                metadata.custom_json,
                content,
            ],
        )?;
    }
    Ok(())
}

/// Backups from before TOTP replay tracking, cover quota accounting, resumable
/// replacement, and workspace-attributed comment email have the exact current
/// database shape except for explicitly enumerated, defaultable additions.
/// SQLite supplies their defaults on restore; storage then backfills cover
/// accounting and active new-file reservations. No other schema drift is accepted.
fn backup_columns_are_compatible(table: &str, incoming: &[String], expected: &[String]) -> bool {
    crate::backup_schema_compatibility::columns_are_compatible(table, incoming, expected)
}

fn file_text_index_has_current_subject_columns(columns: &[String]) -> bool {
    columns.iter().any(|column| column == "source_revision")
        && columns.iter().any(|column| column == "source_content_hash")
}

#[cfg(test)]
mod auth_compatibility_tests;
#[cfg(test)]
mod human_item_sharing_tests;
#[cfg(test)]
mod human_item_sharing_v2_tests;
#[cfg(test)]
mod instance_policy_tests;
#[cfg(test)]
mod publication_tests;
#[cfg(test)]
mod restore_accounting_tests;
#[cfg(test)]
mod restore_desktop_agent_tests;
#[cfg(test)]
mod restore_topology_tests;
#[cfg(test)]
mod tests;
