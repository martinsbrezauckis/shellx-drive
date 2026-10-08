mod accounting;
mod ledger;
#[cfg(test)]
mod legacy_metadata_tests;
#[cfg(test)]
mod metadata_label_tests;
#[cfg(test)]
mod metadata_tests;
mod reconciliation;
#[cfg(test)]
mod tests;
mod triggers;
mod validation;

pub(crate) use ledger::ensure_workspace_auxiliary_storage_delta_fits_in_tx;
pub(crate) use reconciliation::rebuild_workspace_auxiliary_storage_usage_in_tx;
pub(crate) use triggers::install_workspace_auxiliary_storage_triggers;
#[cfg(test)]
use validation::validate_auxiliary_metadata_json;
pub(crate) use validation::{
    bounded_notice_snippet, bounded_notice_snippet_with_limit, project_comment_reply_body_storage,
    project_file_metadata_storage, project_notification_storage,
    project_persisted_file_metadata_storage, project_raw_file_metadata_storage_usage,
    project_workspace_email_outbox_storage, validate_comment_body_utf8,
};

/// This budget intentionally does not share the file-body quota. Auxiliary
/// rows can grow through fanout and derived indexing even when no blob changes.
pub const DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES: i64 = 64 * 1024 * 1024;

pub(crate) const MAX_FILE_METADATA_LABELS: usize = 64;
pub(crate) const MAX_FILE_METADATA_LABEL_BYTES: usize = 64;
pub(crate) const MAX_FILE_METADATA_LABELS_SERIALIZED_BYTES: usize = 8 * 1024;
pub(crate) const MAX_FILE_METADATA_JSON_SERIALIZED_BYTES: usize = 64 * 1024;
pub(crate) const MAX_FILE_METADATA_JSON_DEPTH: usize = 16;
pub(crate) const MAX_FILE_METADATA_JSON_NODES: usize = 4_096;
pub(crate) const MAX_FILE_METADATA_JSON_KEYS: usize = 2_048;
pub(crate) const MAX_FILE_METADATA_JSON_ARRAYS: usize = 512;
pub(crate) const MAX_FILE_METADATA_JSON_SCALARS: usize = 4_096;
pub(crate) const MAX_COMMENT_BODY_UTF8_BYTES: usize = 32 * 1024;
pub(crate) const MAX_NOTICE_SNIPPET_UTF8_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WorkspaceAuxiliaryStorageDelta {
    pub file_metadata_bytes: i64,
    pub metadata_fts_projection_bytes: i64,
    pub comment_reply_body_bytes: i64,
    pub notification_bytes: i64,
    pub email_outbox_bytes: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct JsonStorageShape {
    pub serialized_bytes: usize,
    pub depth: usize,
    pub nodes: usize,
    pub keys: usize,
    pub arrays: usize,
    pub scalars: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileMetadataStorageProjection {
    pub labels: Vec<String>,
    pub labels_json: String,
    pub custom_json: String,
    pub usage: WorkspaceAuxiliaryStorageDelta,
}
