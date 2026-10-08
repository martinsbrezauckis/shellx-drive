use rusqlite::params_from_iter;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::BackupTable,
    storage::{authorization, json_to_sql_value, quote_identifier, Storage, BACKUP_TABLES},
};

use super::{
    auxiliary_storage, file_text_index_has_current_subject_columns, private_workspace_continuity,
    rebuild_file_search_fts_in_tx, restore_human_item_sharing, restore_validation,
    security_continuity,
};

impl Storage {
    /// Restore bodyless legacy tables. Content-bearing publication must use the
    /// authorized path so accounting is bound to its digest-verified catalog.
    pub fn restore_backup_tables(&self, tables: &[BackupTable]) -> ApiResult<()> {
        self.restore_backup_tables_inner(tables, &[], None)
    }

    pub(crate) fn restore_backup_tables_authorized(
        &self,
        tables: &[BackupTable],
        verified_blobs: &[(String, u64)],
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        self.restore_backup_tables_inner(tables, verified_blobs, Some((actor, source_credential)))
    }

    fn restore_backup_tables_inner(
        &self,
        tables: &[BackupTable],
        verified_blobs: &[(String, u64)],
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<()> {
        self.validate_backup_tables(tables)?;
        let sharing_tables_omitted = tables.iter().all(|table| {
            !crate::backup_schema_compatibility::HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES
                .contains(&table.name.as_str())
        });
        let archived_access_generation =
            restore_human_item_sharing::legacy_access_generation(tables)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some((actor, source_credential)) = authorization_context {
            authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        }
        let live_access_generation = restore_human_item_sharing::current_access_generation(&tx)?;
        security_continuity::capture(&tx)?;
        for table in BACKUP_TABLES.iter().rev() {
            tx.execute(&format!("DELETE FROM {}", quote_identifier(table)), [])?;
        }
        super::restore_delegated_agent::purge_sso_parent_bindings_in_tx(&tx)?;
        super::restore_desktop_agent::purge_local_state_in_tx(&tx)?;
        for table_name in BACKUP_TABLES {
            let Some(table) = tables.iter().find(|table| table.name == *table_name) else {
                continue;
            };
            if table.columns.is_empty() {
                continue;
            }
            // Older archives cannot bind extracted text to a content subject.
            // Leave that derived table empty rather than importing text that
            // might describe a superseded blob; FTS rebuilds from only trusted
            // current-subject rows below.
            if table.name == "file_text_index"
                && !file_text_index_has_current_subject_columns(&table.columns)
            {
                continue;
            }
            if table.name == "background_jobs" {
                for row in &table.rows {
                    super::restore_jobs::admit_row(&tx, &table.columns, row)?;
                }
                continue;
            }
            let quoted_table = quote_identifier(&table.name);
            let columns = table
                .columns
                .iter()
                .map(|column| quote_identifier(column))
                .collect::<Vec<_>>()
                .join(", ");
            let placeholders = std::iter::repeat_n("?", table.columns.len())
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!("INSERT INTO {quoted_table} ({columns}) VALUES ({placeholders})");
            let mut statement = tx.prepare(&sql)?;
            for row in &table.rows {
                if row.len() != table.columns.len() {
                    return Err(ApiError::Validation(format!(
                        "backup table {} row has wrong column count",
                        table.name
                    )));
                }
                let values = row
                    .iter()
                    .map(json_to_sql_value)
                    .collect::<ApiResult<Vec<_>>>()?;
                statement.execute(params_from_iter(values))?;
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
        restore_validation::validate_legacy_in_tx(&tx, tables, verified_blobs)?;
        Storage::backfill_upload_session_quota_reservations_in_tx(&tx)?;
        restore_validation::validate_upload_session_reservations_in_tx(&tx)?;
        rebuild_file_search_fts_in_tx(&tx)?;
        auxiliary_storage::rebuild_workspace_auxiliary_storage_usage_in_tx(&tx)?;
        tx.commit()?;
        Ok(())
    }
}
