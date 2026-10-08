//! Deterministic, bounded, streaming primitives for ShellX Drive backup v2.
//!
//! This module intentionally has no HTTP exposure yet. Durable backup jobs can
//! build on these primitives after the archive format and hostile-input corpus
//! are proven independently of request handling.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    error::{ApiError, ApiResult},
    fs_private,
    model::BackupTable,
};

pub const FORMAT: &str = "shellx-drive-backup-v2";
pub const ARCHIVE_EXTENSION: &str = "sxdbackup";
pub const MANIFEST_PATH: &str = "manifest.json";
pub const PORTABLE_INTEGRITY_PATH: &str = "private/restore-integrity-v1.json";

const TAR_BLOCK_BYTES: u64 = 512;
const TAR_TRAILER_BYTES: u64 = TAR_BLOCK_BYTES * 2;
const TAR_MAX_ENTRY_BYTES: u64 = 0o77_777_777_777;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_SOURCE_BUILD_BYTES: usize = 256;
const FREE_SPACE_RESERVE_BYTES: u64 = 16 * 1024 * 1024;
const PORTABLE_INTEGRITY_FORMAT: &str = "shellx-drive-backup-restore-integrity-v1";
const PORTABLE_INTEGRITY_VERSION: u8 = 1;
const MAX_PORTABLE_INTEGRITY_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct V2Limits {
    pub max_manifest_bytes: u64,
    pub max_line_bytes: u64,
    pub max_tables: u64,
    pub max_rows: u64,
    pub max_blobs: u64,
    pub max_content_bytes: u64,
    pub max_archive_bytes: u64,
}

impl Default for V2Limits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 1024 * 1024,
            max_line_bytes: 8 * 1024 * 1024,
            max_tables: 64,
            max_rows: 5_000_000,
            max_blobs: 1_000_000,
            max_content_bytes: 8 * 1024 * 1024 * 1024 * 1024,
            max_archive_bytes: 9 * 1024 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2Manifest {
    pub format: String,
    pub backup_id: String,
    pub created_at: String,
    pub source_build: String,
    pub schema_fingerprint: String,
    pub totals: V2Totals,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable_integrity: Option<V2PortableIntegrityDescriptor>,
    pub tables: Vec<V2TableDescriptor>,
    pub blobs: Vec<V2BlobDescriptor>,
}

/// Declares the private, self-contained verification envelope carried by new
/// v2 archives. Older v2 archives omit this field and remain restorable only
/// through their already-authenticated local sidecar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2PortableIntegrityDescriptor {
    pub format: String,
    pub version: u8,
    pub entry_path: String,
}

/// Archive identity copied into the self-contained integrity envelope. The
/// envelope makes one `.sxdbackup` portable and detects ordinary corruption,
/// but is not an externally trusted signature or attacker-resistant provenance
/// proof: a modifier can rewrite a wholly self-contained artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V2PortableMetadata {
    pub backup_id: String,
    pub format: String,
    pub created_at: String,
    pub table_count: u64,
    pub row_count: u64,
    pub blob_count: u64,
    pub content_bytes: u64,
    pub archive_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct V2PortableIntegrityPayload {
    backup_id: String,
    format: String,
    created_at: String,
    manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct V2PortableIntegrityEnvelope {
    payload: V2PortableIntegrityPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2Totals {
    pub table_count: u64,
    pub row_count: u64,
    pub table_bytes: u64,
    pub blob_count: u64,
    pub content_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2TableDescriptor {
    pub order: u64,
    pub name: String,
    pub entry_path: String,
    pub columns: Vec<String>,
    pub row_count: u64,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2BlobDescriptor {
    pub hash: String,
    pub entry_path: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2TableSchema {
    pub name: String,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct V2BlobSource {
    pub hash: String,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct V2BuildInput<'a> {
    pub backup_id: &'a str,
    pub created_at: &'a str,
    pub source_build: &'a str,
    pub tables: &'a [BackupTable],
    pub blobs: &'a [V2BlobSource],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct V2ArchiveIdentity<'a> {
    pub backup_id: &'a str,
    pub created_at: &'a str,
    pub source_build: &'a str,
}

#[derive(Debug)]
pub(crate) struct V2CreatedArchive {
    pub manifest: V2Manifest,
    pub archive_bytes: u64,
    pub archive_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ValidationSummary {
    pub manifest: V2Manifest,
    pub archive_bytes: u64,
    pub(crate) archive_sha256: String,
    pub(crate) portable_metadata: Option<V2PortableMetadata>,
}

#[derive(Debug)]
pub(crate) struct V2ExtractedSnapshot {
    pub manifest: V2Manifest,
    pub table_paths: Vec<PathBuf>,
    pub blob_paths: Vec<(String, PathBuf)>,
    pub archive_sha256: String,
    pub portable_metadata: Option<V2PortableMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct V2TableHeader {
    columns: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct V2StagedTable {
    pub descriptor: V2TableDescriptor,
    pub path: PathBuf,
}

#[derive(Debug)]
pub(crate) struct V2StagedSnapshot {
    pub tables: Vec<V2StagedTable>,
    pub referenced_hashes: HashSet<String>,
    pub blobs: Vec<V2BlobSource>,
}

#[derive(Debug)]
struct PreparedBlob {
    descriptor: V2BlobDescriptor,
    path: PathBuf,
}

#[derive(Debug)]
struct TarHeader {
    path: String,
    size: u64,
    entry_type: u8,
}

pub(crate) struct V2TableStageWriter {
    descriptor: V2TableDescriptor,
    path: PathBuf,
    file: File,
    hasher: Sha256,
    limits: V2Limits,
    prior_table_bytes: u64,
    referenced_hashes: HashSet<String>,
}

impl V2TableStageWriter {
    pub(crate) fn new(
        stage_dir: &Path,
        order: u64,
        name: &str,
        columns: Vec<String>,
        limits: V2Limits,
        prior_table_bytes: u64,
    ) -> ApiResult<Self> {
        validate_schema(&[V2TableSchema {
            name: name.to_string(),
            columns: columns.clone(),
        }])?;
        let entry_path = table_entry_path(order, name)?;
        let path = stage_dir.join(format!("{order:02}.jsonl"));
        let mut file = create_private_file_new(&path)?;
        let mut hasher = Sha256::new();
        let mut byte_length = 0u64;
        write_json_line(
            &mut file,
            &mut hasher,
            &mut byte_length,
            &V2TableHeader {
                columns: columns.clone(),
            },
            limits,
            prior_table_bytes,
        )?;
        Ok(Self {
            descriptor: V2TableDescriptor {
                order,
                name: name.to_string(),
                entry_path,
                columns,
                row_count: 0,
                byte_length,
                sha256: String::new(),
            },
            path,
            file,
            hasher,
            limits,
            prior_table_bytes,
            referenced_hashes: HashSet::new(),
        })
    }

    pub(crate) fn write_row(&mut self, row: &[Value]) -> ApiResult<()> {
        if row.len() != self.descriptor.columns.len() {
            return Err(ApiError::Validation(format!(
                "backup v2 table {} row has wrong column count",
                self.descriptor.name
            )));
        }
        validate_row_values(row, &self.descriptor.name)?;
        collect_referenced_hashes(&self.descriptor.columns, row, &mut self.referenced_hashes)?;
        self.descriptor.row_count =
            self.descriptor.row_count.checked_add(1).ok_or_else(|| {
                ApiError::PayloadTooLarge("backup v2 row count overflow".to_string())
            })?;
        write_json_line(
            &mut self.file,
            &mut self.hasher,
            &mut self.descriptor.byte_length,
            row,
            self.limits,
            self.prior_table_bytes,
        )
    }

    pub(crate) fn finish(mut self) -> ApiResult<(V2StagedTable, HashSet<String>)> {
        self.file.sync_all()?;
        self.descriptor.sha256 = hex::encode(self.hasher.finalize());
        Ok((
            V2StagedTable {
                descriptor: self.descriptor,
                path: self.path,
            },
            self.referenced_hashes,
        ))
    }
}

/// Build the exact schema definition recorded by v2 from ordered backup tables.
pub fn schema_from_tables(tables: &[BackupTable]) -> Vec<V2TableSchema> {
    tables
        .iter()
        .map(|table| V2TableSchema {
            name: table.name.clone(),
            columns: table.columns.clone(),
        })
        .collect()
}

pub fn schema_fingerprint(schema: &[V2TableSchema]) -> ApiResult<String> {
    validate_schema(schema)?;
    let encoded = serde_json::to_vec(schema).map_err(|error| {
        ApiError::Validation(format!("could not serialize backup v2 schema: {error}"))
    })?;
    Ok(sha256_bytes(&encoded))
}

/// Create one complete v2 archive through a private sibling partial file.
///
/// Table JSONL is staged so its exact length and hash can appear in the first
/// archive entry. Blob bodies are read twice (preflight and archive copy), but
/// are never retained in memory.
pub fn create_archive_atomic(
    archive_path: &Path,
    staging_root: &Path,
    input: V2BuildInput<'_>,
    limits: V2Limits,
) -> ApiResult<V2Manifest> {
    validate_build_identity(&input, limits)?;
    let identity = V2ArchiveIdentity {
        backup_id: input.backup_id,
        created_at: input.created_at,
        source_build: input.source_build,
    };
    create_archive_atomic_streaming(
        archive_path,
        staging_root,
        identity,
        limits,
        |stage_dir, limits| {
            let (tables, referenced_hashes) = stage_tables(stage_dir, input.tables, limits)?;
            Ok(V2StagedSnapshot {
                tables,
                referenced_hashes,
                blobs: input.blobs.to_vec(),
            })
        },
    )
    .map(|created| created.manifest)
}

pub(crate) fn create_archive_atomic_streaming<F>(
    archive_path: &Path,
    staging_root: &Path,
    identity: V2ArchiveIdentity<'_>,
    limits: V2Limits,
    stage_snapshot: F,
) -> ApiResult<V2CreatedArchive>
where
    F: FnOnce(&Path, V2Limits) -> ApiResult<V2StagedSnapshot>,
{
    validate_identity(identity)?;
    validate_archive_target(archive_path, identity.backup_id)?;
    if archive_path.exists() {
        return Err(ApiError::Conflict);
    }
    fs_private::create_dir_all_private(staging_root)?;

    let stage_dir = staging_root.join(format!(".{}.v2-stage", identity.backup_id));
    if stage_dir.exists() {
        return Err(ApiError::Conflict);
    }
    fs::create_dir(&stage_dir)?;
    fs_private::set_dir_private(&stage_dir)?;

    let partial_path = archive_partial_path(archive_path)?;
    if partial_path.exists() {
        let _ = fs::remove_dir(&stage_dir);
        return Err(ApiError::Conflict);
    }

    let result = (|| {
        let snapshot = stage_snapshot(&stage_dir, limits)?;
        if snapshot.tables.is_empty() || snapshot.tables.len() as u64 > limits.max_tables {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 has {} tables; limit is {}",
                snapshot.tables.len(),
                limits.max_tables
            )));
        }
        let prepared_blobs = prepare_blobs(&snapshot.blobs, limits)?;
        validate_build_blob_catalog(&snapshot.referenced_hashes, &prepared_blobs)?;
        let manifest = build_manifest(identity, &snapshot.tables, &prepared_blobs, limits)?;
        let manifest_bytes = encode_manifest(&manifest, limits)?;
        let integrity_bytes = encode_portable_integrity_envelope(&manifest, &manifest_bytes)?;
        let expected_archive_bytes = expected_archive_size(
            &manifest,
            manifest_bytes.len() as u64,
            Some(integrity_bytes.len() as u64),
        )?;
        if expected_archive_bytes > limits.max_archive_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 archive would be {expected_archive_bytes} bytes; limit is {} bytes",
                limits.max_archive_bytes
            )));
        }
        let archive_parent = archive_path.parent().ok_or_else(|| {
            ApiError::Validation("backup v2 archive has no parent directory".to_string())
        })?;
        if let Some(available) = available_space_bytes(archive_parent)? {
            let required = expected_archive_bytes
                .checked_add(FREE_SPACE_RESERVE_BYTES)
                .ok_or_else(|| {
                    ApiError::PayloadTooLarge(
                        "backup v2 free-space requirement overflow".to_string(),
                    )
                })?;
            if available < required {
                return Err(ApiError::PayloadTooLarge(format!(
                    "backup v2 requires {required} free bytes including reserve; only {available} are available"
                )));
            }
        }

        let mut archive = ArchiveHashWriter::new(create_private_file_new(&partial_path)?);
        append_bytes_entry(&mut archive, MANIFEST_PATH, &manifest_bytes)?;
        append_bytes_entry(&mut archive, PORTABLE_INTEGRITY_PATH, &integrity_bytes)?;
        for table in &snapshot.tables {
            append_verified_file_entry(
                &mut archive,
                &table.descriptor.entry_path,
                &table.path,
                table.descriptor.byte_length,
                &table.descriptor.sha256,
            )?;
        }
        for blob in &prepared_blobs {
            append_verified_file_entry(
                &mut archive,
                &blob.descriptor.entry_path,
                &blob.path,
                blob.descriptor.byte_length,
                &blob.descriptor.hash,
            )?;
        }
        write_archive_all(&mut archive, &[0u8; TAR_TRAILER_BYTES as usize])?;
        archive.inner.sync_all()?;
        if archive.inner.metadata()?.len() != expected_archive_bytes {
            return Err(ApiError::Validation(
                "backup v2 writer produced an unexpected archive length".to_string(),
            ));
        }
        let archive_sha256 = archive.finish_hash();
        fs::rename(&partial_path, archive_path)?;
        sync_directory(archive_path.parent().ok_or_else(|| {
            ApiError::Validation("backup v2 archive has no parent directory".to_string())
        })?)?;
        Ok(V2CreatedArchive {
            manifest,
            archive_bytes: expected_archive_bytes,
            archive_sha256,
        })
    })();

    cleanup_stage_dir(&stage_dir);
    if result.is_err() {
        let _ = fs::remove_file(&partial_path);
    }
    result
}

#[cfg(unix)]
fn available_space_bytes(path: &Path) -> io::Result<Option<u64>> {
    #[cfg(test)]
    if let Some(available) = test_faults::available_space_override() {
        return Ok(Some(available));
    }

    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stats` points to writable storage.
    let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a zero return from statvfs initializes the full structure.
    let stats = unsafe { stats.assume_init() };
    #[cfg(target_vendor = "apple")]
    let available_blocks = u64::from(stats.f_bavail);
    #[cfg(not(target_vendor = "apple"))]
    let available_blocks = stats.f_bavail;
    Ok(Some(available_blocks.saturating_mul(stats.f_frsize)))
}

#[cfg(not(unix))]
fn available_space_bytes(_path: &Path) -> io::Result<Option<u64>> {
    #[cfg(test)]
    if let Some(available) = test_faults::available_space_override() {
        return Ok(Some(available));
    }

    Ok(None)
}

pub(crate) fn ensure_restore_free_space(path: &Path, payload_bytes: u64) -> ApiResult<()> {
    let required = payload_bytes
        .checked_add(FREE_SPACE_RESERVE_BYTES)
        .ok_or_else(|| {
            ApiError::PayloadTooLarge("backup restore free-space requirement overflow".to_string())
        })?;
    if let Some(available) = available_space_bytes(path)? {
        if available < required {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup restore requires {required} free bytes including reserve; only {available} are available"
            )));
        }
    }
    Ok(())
}

pub(crate) fn ensure_generation_staging_free_space(
    path: &Path,
    estimated_table_bytes: u64,
) -> ApiResult<()> {
    let required = estimated_table_bytes
        .checked_add(FREE_SPACE_RESERVE_BYTES)
        .ok_or_else(|| {
            ApiError::PayloadTooLarge(
                "backup generation staging free-space requirement overflow".to_string(),
            )
        })?;
    if let Some(available) = available_space_bytes(path)? {
        if available < required {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup generation staging requires {required} free bytes including reserve; only {available} are available"
            )));
        }
    }
    Ok(())
}

pub(crate) fn restore_payload_bytes(manifest: &V2Manifest) -> ApiResult<u64> {
    manifest
        .totals
        .content_bytes
        .checked_add(manifest.totals.table_bytes)
        .ok_or_else(|| {
            ApiError::PayloadTooLarge("backup v2 restore size requirement overflow".to_string())
        })
}

/// Read only the bounded manifest and private integrity envelope needed to
/// identify a portable archive in a fresh data directory. Restore still calls
/// [`validate_archive`] and validates every table and blob before installation.
pub(crate) fn read_portable_metadata(
    archive_path: &Path,
    limits: V2Limits,
) -> ApiResult<Option<V2PortableMetadata>> {
    let metadata = fs::symlink_metadata(archive_path)?;
    if !metadata.file_type().is_file() {
        return Err(ApiError::Validation(
            "backup v2 archive is not a regular file".to_string(),
        ));
    }
    if metadata.len() > limits.max_archive_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 archive is {} bytes; limit is {} bytes",
            metadata.len(),
            limits.max_archive_bytes
        )));
    }
    let mut archive = File::open(archive_path)?;
    let manifest_header = read_tar_header(&mut archive, "manifest header")?;
    validate_regular_header(&manifest_header)?;
    if manifest_header.path != MANIFEST_PATH || manifest_header.size > limits.max_manifest_bytes {
        return Err(ApiError::Validation(
            "backup v2 manifest is missing or exceeds its fixed limit".to_string(),
        ));
    }
    let manifest_len = usize::try_from(manifest_header.size).map_err(|_| {
        ApiError::PayloadTooLarge("backup v2 manifest does not fit in memory".to_string())
    })?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    read_exact_validated(&mut archive, &mut manifest_bytes, "manifest body")?;
    skip_tar_padding(&mut archive, manifest_header.size, "manifest padding")?;
    if !manifest_bytes.ends_with(b"\n") {
        return Err(ApiError::Validation(
            "backup v2 manifest must end with a newline".to_string(),
        ));
    }
    let manifest: V2Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ApiError::Validation(format!("invalid backup v2 manifest: {error}")))?;
    let archive_schema = manifest
        .tables
        .iter()
        .map(|table| V2TableSchema {
            name: table.name.clone(),
            columns: table.columns.clone(),
        })
        .collect::<Vec<_>>();
    validate_manifest(&manifest, &archive_schema, limits)?;
    if manifest.portable_integrity.is_none() {
        return Ok(None);
    }
    let (mut portable_metadata, portable_integrity_bytes) =
        read_portable_integrity_entry(&mut archive, &manifest, &manifest_bytes)?;
    let expected_bytes = expected_archive_size(
        &manifest,
        manifest_header.size,
        Some(portable_integrity_bytes),
    )?;
    if expected_bytes != metadata.len() {
        return Err(ApiError::Validation(format!(
            "backup v2 archive length is {}; manifest requires {expected_bytes}",
            metadata.len()
        )));
    }
    portable_metadata.archive_bytes = metadata.len();
    Ok(Some(portable_metadata))
}

/// Stream and validate a complete v2 archive without materializing table sets
/// or blob bodies. Only the bounded manifest, one bounded JSONL line, and the
/// bounded set of declared content hashes are retained.
pub fn validate_archive(
    archive_path: &Path,
    expected_schema: &[V2TableSchema],
    limits: V2Limits,
) -> ApiResult<V2ValidationSummary> {
    validate_schema(expected_schema)?;
    let metadata = fs::symlink_metadata(archive_path)?;
    if !metadata.file_type().is_file() {
        return Err(ApiError::Validation(
            "backup v2 archive is not a regular file".to_string(),
        ));
    }
    if metadata.len() > limits.max_archive_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 archive is {} bytes; limit is {} bytes",
            metadata.len(),
            limits.max_archive_bytes
        )));
    }

    let mut archive = ArchiveHashReader::new(File::open(archive_path)?);
    let manifest_header = read_tar_header(&mut archive, "manifest header")?;
    validate_regular_header(&manifest_header)?;
    if manifest_header.path != MANIFEST_PATH {
        return Err(ApiError::Validation(
            "backup v2 manifest must be the first archive entry".to_string(),
        ));
    }
    if manifest_header.size > limits.max_manifest_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 manifest is {} bytes; limit is {} bytes",
            manifest_header.size, limits.max_manifest_bytes
        )));
    }
    let manifest_len = usize::try_from(manifest_header.size).map_err(|_| {
        ApiError::PayloadTooLarge("backup v2 manifest does not fit in memory".to_string())
    })?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    read_exact_validated(&mut archive, &mut manifest_bytes, "manifest body")?;
    skip_tar_padding(&mut archive, manifest_header.size, "manifest padding")?;
    if !manifest_bytes.ends_with(b"\n") {
        return Err(ApiError::Validation(
            "backup v2 manifest must end with a newline".to_string(),
        ));
    }
    let manifest: V2Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ApiError::Validation(format!("invalid backup v2 manifest: {error}")))?;
    validate_manifest(&manifest, expected_schema, limits)?;

    let (portable_metadata, portable_integrity_bytes) = if manifest.portable_integrity.is_some() {
        let (metadata, bytes) =
            read_portable_integrity_entry(&mut archive, &manifest, &manifest_bytes)?;
        (Some(metadata), Some(bytes))
    } else {
        (None, None)
    };
    let expected_bytes =
        expected_archive_size(&manifest, manifest_header.size, portable_integrity_bytes)?;
    if expected_bytes != metadata.len() {
        return Err(ApiError::Validation(format!(
            "backup v2 archive length is {}; manifest requires {expected_bytes}",
            metadata.len()
        )));
    }

    let mut referenced_hashes = HashSet::new();
    for descriptor in &manifest.tables {
        let header = read_tar_header(&mut archive, "table header")?;
        validate_regular_header(&header)?;
        validate_expected_entry(&header, &descriptor.entry_path, descriptor.byte_length)?;
        validate_table_entry(&mut archive, descriptor, limits, &mut referenced_hashes)?;
        skip_tar_padding(&mut archive, header.size, "table padding")?;
    }

    let declared_hashes = manifest
        .blobs
        .iter()
        .map(|blob| blob.hash.as_str())
        .collect::<HashSet<_>>();
    let referenced = referenced_hashes
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if referenced != declared_hashes {
        let missing = referenced.difference(&declared_hashes).count();
        let extra = declared_hashes.difference(&referenced).count();
        return Err(ApiError::Validation(format!(
            "backup v2 blob catalog is not an exact reference match ({missing} missing, {extra} extra)"
        )));
    }

    for descriptor in &manifest.blobs {
        let header = read_tar_header(&mut archive, "blob header")?;
        validate_regular_header(&header)?;
        validate_expected_entry(&header, &descriptor.entry_path, descriptor.byte_length)?;
        let actual = stream_entry_hash(&mut archive, header.size, "blob body")?;
        if actual != descriptor.hash {
            return Err(ApiError::Validation(format!(
                "backup v2 blob {} content hash does not match bytes",
                descriptor.hash
            )));
        }
        skip_tar_padding(&mut archive, header.size, "blob padding")?;
    }

    let mut trailer = [0u8; TAR_TRAILER_BYTES as usize];
    read_exact_validated(&mut archive, &mut trailer, "tar trailer")?;
    if trailer.iter().any(|byte| *byte != 0) {
        return Err(ApiError::Validation(
            "backup v2 archive has an extra entry or invalid tar trailer".to_string(),
        ));
    }
    let mut extra = [0u8; 1];
    if archive.read(&mut extra)? != 0 {
        return Err(ApiError::Validation(
            "backup v2 archive contains trailing bytes".to_string(),
        ));
    }

    let portable_metadata = portable_metadata.map(|mut portable_metadata| {
        portable_metadata.archive_bytes = metadata.len();
        portable_metadata
    });
    Ok(V2ValidationSummary {
        manifest,
        archive_bytes: metadata.len(),
        archive_sha256: archive.finish_hash(),
        portable_metadata,
    })
}

/// Validate and stream one archive into a new private disposable directory.
///
/// The first pass validates the full hostile-input grammar. The extraction
/// pass then rechecks every declared length and digest, so an archive changed
/// between the two passes cannot feed unverified bytes to restore.
pub(crate) fn extract_archive_validated(
    archive_path: &Path,
    expected_schema: &[V2TableSchema],
    destination: &Path,
    limits: V2Limits,
) -> ApiResult<V2ExtractedSnapshot> {
    let summary = validate_archive(archive_path, expected_schema, limits)?;
    if destination.exists() {
        return Err(ApiError::Conflict);
    }
    let staging_parent = destination.parent().ok_or_else(|| {
        ApiError::Validation("backup v2 extraction destination has no parent".to_string())
    })?;
    ensure_restore_free_space(staging_parent, restore_payload_bytes(&summary.manifest)?)?;
    fs::create_dir(destination)?;
    fs_private::set_dir_private(destination)?;
    let table_dir = destination.join("tables");
    let blob_dir = destination.join("blobs");
    fs::create_dir(&table_dir)?;
    fs::create_dir(&blob_dir)?;
    fs_private::set_dir_private(&table_dir)?;
    fs_private::set_dir_private(&blob_dir)?;

    let result = (|| {
        let mut archive = ArchiveHashReader::new(File::open(archive_path)?);
        let manifest_header = read_tar_header(&mut archive, "manifest header")?;
        validate_regular_header(&manifest_header)?;
        if manifest_header.path != MANIFEST_PATH || manifest_header.size > limits.max_manifest_bytes
        {
            return Err(ApiError::Validation(
                "backup v2 manifest changed before extraction".to_string(),
            ));
        }
        let mut manifest_bytes = vec![0u8; manifest_header.size as usize];
        read_exact_validated(&mut archive, &mut manifest_bytes, "manifest body")?;
        skip_tar_padding(&mut archive, manifest_header.size, "manifest padding")?;
        let manifest: V2Manifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
            ApiError::Validation(format!("invalid backup v2 manifest: {error}"))
        })?;
        if manifest != summary.manifest {
            return Err(ApiError::Validation(
                "backup v2 manifest changed before extraction".to_string(),
            ));
        }
        let portable_metadata = if manifest.portable_integrity.is_some() {
            let (mut metadata, _) =
                read_portable_integrity_entry(&mut archive, &manifest, &manifest_bytes)?;
            metadata.archive_bytes = summary.archive_bytes;
            if summary.portable_metadata.as_ref() != Some(&metadata) {
                return Err(ApiError::Validation(
                    "backup v2 portable integrity metadata changed before extraction".to_string(),
                ));
            }
            Some(metadata)
        } else {
            None
        };

        let mut table_paths = Vec::with_capacity(manifest.tables.len());
        for descriptor in &manifest.tables {
            let header = read_tar_header(&mut archive, "table header")?;
            validate_regular_header(&header)?;
            validate_expected_entry(&header, &descriptor.entry_path, descriptor.byte_length)?;
            let path = table_dir.join(format!("{:02}.jsonl", descriptor.order));
            copy_entry_to_private_file_verified(
                &mut archive,
                &path,
                descriptor.byte_length,
                &descriptor.sha256,
                "table body",
            )?;
            skip_tar_padding(&mut archive, header.size, "table padding")?;
            table_paths.push(path);
        }

        let mut blob_paths = Vec::with_capacity(manifest.blobs.len());
        for descriptor in &manifest.blobs {
            let header = read_tar_header(&mut archive, "blob header")?;
            validate_regular_header(&header)?;
            validate_expected_entry(&header, &descriptor.entry_path, descriptor.byte_length)?;
            let path = blob_dir.join(&descriptor.hash);
            copy_entry_to_private_file_verified(
                &mut archive,
                &path,
                descriptor.byte_length,
                &descriptor.hash,
                "blob body",
            )?;
            skip_tar_padding(&mut archive, header.size, "blob padding")?;
            blob_paths.push((descriptor.hash.clone(), path));
        }

        let mut trailer = [0u8; TAR_TRAILER_BYTES as usize];
        read_exact_validated(&mut archive, &mut trailer, "tar trailer")?;
        if trailer.iter().any(|byte| *byte != 0) {
            return Err(ApiError::Validation(
                "backup v2 archive trailer changed before extraction".to_string(),
            ));
        }
        let mut extra = [0u8; 1];
        if archive.read(&mut extra)? != 0 {
            return Err(ApiError::Validation(
                "backup v2 archive contains trailing bytes".to_string(),
            ));
        }

        Ok(V2ExtractedSnapshot {
            manifest,
            table_paths,
            blob_paths,
            archive_sha256: archive.finish_hash(),
            portable_metadata,
        })
    })();
    if result.is_err() {
        cleanup_stage_dir(destination);
    }
    result
}

fn copy_entry_to_private_file_verified(
    archive: &mut impl Read,
    destination: &Path,
    expected_len: u64,
    expected_hash: &str,
    label: &str,
) -> ApiResult<()> {
    let mut output = create_private_file_new(destination)?;
    let mut hasher = Sha256::new();
    let mut remaining = expected_len;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let allowed = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = archive
            .read(&mut buffer[..allowed])
            .map_err(|error| archive_read_error(error, label))?;
        if read == 0 {
            return Err(ApiError::Validation(format!(
                "backup v2 {label} ended early"
            )));
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    output.sync_all()?;
    if hex::encode(hasher.finalize()) != expected_hash {
        return Err(ApiError::Validation(format!(
            "backup v2 {label} digest changed before extraction"
        )));
    }
    Ok(())
}

fn validate_build_identity(input: &V2BuildInput<'_>, limits: V2Limits) -> ApiResult<()> {
    validate_identity(V2ArchiveIdentity {
        backup_id: input.backup_id,
        created_at: input.created_at,
        source_build: input.source_build,
    })?;
    let table_count = input.tables.len() as u64;
    if table_count == 0 || table_count > limits.max_tables {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 has {table_count} tables; limit is {}",
            limits.max_tables
        )));
    }
    Ok(())
}

fn validate_identity(identity: V2ArchiveIdentity<'_>) -> ApiResult<()> {
    if !valid_backup_id(identity.backup_id) {
        return Err(ApiError::Validation("invalid backup v2 id".to_string()));
    }
    chrono::DateTime::parse_from_rfc3339(identity.created_at)
        .map_err(|_| ApiError::Validation("backup v2 creation time is not RFC3339".to_string()))?;
    if identity.source_build.is_empty() || identity.source_build.len() > MAX_SOURCE_BUILD_BYTES {
        return Err(ApiError::Validation(
            "backup v2 source build is empty or too long".to_string(),
        ));
    }
    Ok(())
}

fn stage_tables(
    stage_dir: &Path,
    tables: &[BackupTable],
    limits: V2Limits,
) -> ApiResult<(Vec<V2StagedTable>, HashSet<String>)> {
    let schema = schema_from_tables(tables);
    validate_schema(&schema)?;
    let mut total_rows = 0u64;
    let mut total_table_bytes = 0u64;
    let mut staged = Vec::with_capacity(tables.len());
    let mut referenced_hashes = HashSet::new();
    for (order, table) in tables.iter().enumerate() {
        let mut writer = V2TableStageWriter::new(
            stage_dir,
            order as u64,
            &table.name,
            table.columns.clone(),
            limits,
            total_table_bytes,
        )?;
        for row in &table.rows {
            writer.write_row(row)?;
        }
        let (table, table_hashes) = writer.finish()?;
        total_rows = total_rows
            .checked_add(table.descriptor.row_count)
            .ok_or_else(|| ApiError::PayloadTooLarge("backup v2 row count overflow".to_string()))?;
        if total_rows > limits.max_rows {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 has more than {} rows",
                limits.max_rows
            )));
        }
        total_table_bytes = total_table_bytes
            .checked_add(table.descriptor.byte_length)
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("backup v2 table byte count overflow".to_string())
            })?;
        referenced_hashes.extend(table_hashes);
        staged.push(table);
    }
    Ok((staged, referenced_hashes))
}

fn prepare_blobs(sources: &[V2BlobSource], limits: V2Limits) -> ApiResult<Vec<PreparedBlob>> {
    if sources.len() as u64 > limits.max_blobs {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 has {} blobs; limit is {}",
            sources.len(),
            limits.max_blobs
        )));
    }
    let mut sorted = sources.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.hash.cmp(&right.hash));
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut prepared = Vec::with_capacity(sorted.len());
    for source in sorted {
        if !is_sha256(&source.hash) || !seen.insert(source.hash.as_str()) {
            return Err(ApiError::Validation(
                "backup v2 blob hash is invalid or duplicated".to_string(),
            ));
        }
        let metadata = fs::symlink_metadata(&source.path)?;
        if !metadata.file_type().is_file() {
            return Err(ApiError::Validation(format!(
                "backup v2 blob {} is not a regular file",
                source.hash
            )));
        }
        if metadata.len() > TAR_MAX_ENTRY_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 blob {} is {} bytes; canonical ustar entry limit is {TAR_MAX_ENTRY_BYTES} bytes",
                source.hash,
                metadata.len()
            )));
        }
        total = total.checked_add(metadata.len()).ok_or_else(|| {
            ApiError::PayloadTooLarge("backup v2 content size overflow".to_string())
        })?;
        if total > limits.max_content_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 references {total} content bytes; limit is {}",
                limits.max_content_bytes
            )));
        }
        let (actual_len, actual_hash) = hash_file_exact(&source.path, metadata.len())?;
        if actual_len != metadata.len() || actual_hash != source.hash {
            return Err(ApiError::Validation(format!(
                "backup v2 blob {} changed or does not match its content hash",
                source.hash
            )));
        }
        prepared.push(PreparedBlob {
            descriptor: V2BlobDescriptor {
                hash: source.hash.clone(),
                entry_path: blob_entry_path(&source.hash)?,
                byte_length: actual_len,
            },
            path: source.path.clone(),
        });
    }
    Ok(prepared)
}

fn build_manifest(
    identity: V2ArchiveIdentity<'_>,
    tables: &[V2StagedTable],
    blobs: &[PreparedBlob],
    limits: V2Limits,
) -> ApiResult<V2Manifest> {
    let table_descriptors = tables
        .iter()
        .map(|table| table.descriptor.clone())
        .collect::<Vec<_>>();
    let blob_descriptors = blobs
        .iter()
        .map(|blob| blob.descriptor.clone())
        .collect::<Vec<_>>();
    let totals = V2Totals {
        table_count: table_descriptors.len() as u64,
        row_count: checked_sum(
            table_descriptors.iter().map(|table| table.row_count),
            "row count",
        )?,
        table_bytes: checked_sum(
            table_descriptors.iter().map(|table| table.byte_length),
            "table bytes",
        )?,
        blob_count: blob_descriptors.len() as u64,
        content_bytes: checked_sum(
            blob_descriptors.iter().map(|blob| blob.byte_length),
            "content bytes",
        )?,
    };
    let schema = table_descriptors
        .iter()
        .map(|table| V2TableSchema {
            name: table.name.clone(),
            columns: table.columns.clone(),
        })
        .collect::<Vec<_>>();
    let manifest = V2Manifest {
        format: FORMAT.to_string(),
        backup_id: identity.backup_id.to_string(),
        created_at: identity.created_at.to_string(),
        source_build: identity.source_build.to_string(),
        schema_fingerprint: schema_fingerprint(&schema)?,
        totals,
        portable_integrity: Some(V2PortableIntegrityDescriptor {
            format: PORTABLE_INTEGRITY_FORMAT.to_string(),
            version: PORTABLE_INTEGRITY_VERSION,
            entry_path: PORTABLE_INTEGRITY_PATH.to_string(),
        }),
        tables: table_descriptors,
        blobs: blob_descriptors,
    };
    validate_manifest(&manifest, &schema, limits)?;
    Ok(manifest)
}

fn encode_manifest(manifest: &V2Manifest, limits: V2Limits) -> ApiResult<Vec<u8>> {
    let mut encoded = serde_json::to_vec(manifest).map_err(|error| {
        ApiError::Validation(format!("could not serialize backup v2 manifest: {error}"))
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > limits.max_manifest_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 manifest is {} bytes; limit is {} bytes",
            encoded.len(),
            limits.max_manifest_bytes
        )));
    }
    Ok(encoded)
}

/// Encode the versioned portable-integrity envelope for a newly-created v2
/// archive. It intentionally carries no confidentiality or attacker-resistant
/// authenticity claim: an externally trusted signature/checksum or protected
/// storage is required for provenance against an archive modifier.
fn encode_portable_integrity_envelope(
    manifest: &V2Manifest,
    manifest_bytes: &[u8],
) -> ApiResult<Vec<u8>> {
    let descriptor = manifest.portable_integrity.as_ref().ok_or_else(|| {
        ApiError::Validation(
            "new backup v2 archive is missing portable integrity metadata".to_string(),
        )
    })?;
    validate_portable_integrity_descriptor(descriptor)?;
    let payload = V2PortableIntegrityPayload {
        backup_id: manifest.backup_id.clone(),
        format: manifest.format.clone(),
        created_at: manifest.created_at.clone(),
        manifest_sha256: sha256_bytes(manifest_bytes),
    };
    let envelope = V2PortableIntegrityEnvelope { payload };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| {
        ApiError::Validation(format!(
            "could not encode backup v2 portable integrity envelope: {error}"
        ))
    })?;
    if bytes.len() as u64 > MAX_PORTABLE_INTEGRITY_BYTES {
        return Err(ApiError::PayloadTooLarge(
            "backup v2 portable integrity envelope exceeds its fixed limit".to_string(),
        ));
    }
    Ok(bytes)
}

fn read_portable_integrity_entry(
    archive: &mut impl Read,
    manifest: &V2Manifest,
    manifest_bytes: &[u8],
) -> ApiResult<(V2PortableMetadata, u64)> {
    let descriptor = manifest.portable_integrity.as_ref().ok_or_else(|| {
        ApiError::Validation("backup v2 portable integrity descriptor is missing".to_string())
    })?;
    validate_portable_integrity_descriptor(descriptor)?;
    let header = read_tar_header(archive, "portable integrity header")?;
    validate_regular_header(&header)?;
    validate_expected_entry(&header, &descriptor.entry_path, header.size)?;
    if header.size > MAX_PORTABLE_INTEGRITY_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 portable integrity envelope is {} bytes; limit is {MAX_PORTABLE_INTEGRITY_BYTES}",
            header.size
        )));
    }
    let length = usize::try_from(header.size).map_err(|_| {
        ApiError::PayloadTooLarge(
            "backup v2 portable integrity envelope does not fit in memory".to_string(),
        )
    })?;
    let mut bytes = vec![0u8; length];
    read_exact_validated(archive, &mut bytes, "portable integrity body")?;
    skip_tar_padding(archive, header.size, "portable integrity padding")?;
    let envelope: V2PortableIntegrityEnvelope =
        serde_json::from_slice(&bytes).map_err(|error| {
            ApiError::Validation(format!(
                "invalid backup v2 portable integrity envelope: {error}"
            ))
        })?;
    if envelope.payload.backup_id != manifest.backup_id
        || envelope.payload.format != manifest.format
        || envelope.payload.created_at != manifest.created_at
        || envelope.payload.manifest_sha256 != sha256_bytes(manifest_bytes)
        || !is_sha256(&envelope.payload.manifest_sha256)
    {
        return Err(ApiError::Validation(
            "backup v2 portable integrity envelope does not match its manifest".to_string(),
        ));
    }
    Ok((
        V2PortableMetadata {
            backup_id: manifest.backup_id.clone(),
            format: manifest.format.clone(),
            created_at: manifest.created_at.clone(),
            table_count: manifest.totals.table_count,
            row_count: manifest.totals.row_count,
            blob_count: manifest.totals.blob_count,
            content_bytes: manifest.totals.content_bytes,
            archive_bytes: 0,
        },
        header.size,
    ))
}

fn validate_portable_integrity_descriptor(
    descriptor: &V2PortableIntegrityDescriptor,
) -> ApiResult<()> {
    if descriptor.format != PORTABLE_INTEGRITY_FORMAT
        || descriptor.version != PORTABLE_INTEGRITY_VERSION
        || descriptor.entry_path != PORTABLE_INTEGRITY_PATH
    {
        return Err(ApiError::Validation(
            "backup v2 portable integrity descriptor is unsupported".to_string(),
        ));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &V2Manifest,
    expected_schema: &[V2TableSchema],
    limits: V2Limits,
) -> ApiResult<()> {
    if manifest.format != FORMAT {
        return Err(ApiError::Validation(format!(
            "unsupported backup v2 format: {}",
            manifest.format
        )));
    }
    if !valid_backup_id(&manifest.backup_id) {
        return Err(ApiError::Validation("invalid backup v2 id".to_string()));
    }
    chrono::DateTime::parse_from_rfc3339(&manifest.created_at)
        .map_err(|_| ApiError::Validation("backup v2 creation time is not RFC3339".to_string()))?;
    if manifest.source_build.is_empty() || manifest.source_build.len() > MAX_SOURCE_BUILD_BYTES {
        return Err(ApiError::Validation(
            "backup v2 source build is empty or too long".to_string(),
        ));
    }
    if let Some(portable_integrity) = &manifest.portable_integrity {
        if portable_integrity.format != PORTABLE_INTEGRITY_FORMAT
            || portable_integrity.version != PORTABLE_INTEGRITY_VERSION
            || portable_integrity.entry_path != PORTABLE_INTEGRITY_PATH
        {
            return Err(ApiError::Validation(
                "backup v2 portable integrity descriptor is unsupported".to_string(),
            ));
        }
    }
    if manifest.tables.len() as u64 > limits.max_tables {
        return Err(ApiError::Validation(format!(
            "backup v2 contains {} tables; expected {}",
            manifest.tables.len(),
            expected_schema.len()
        )));
    }
    if manifest.blobs.len() as u64 > limits.max_blobs {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 contains {} blobs; limit is {}",
            manifest.blobs.len(),
            limits.max_blobs
        )));
    }
    let manifest_schema = manifest
        .tables
        .iter()
        .map(|table| V2TableSchema {
            name: table.name.clone(),
            columns: table.columns.clone(),
        })
        .collect::<Vec<_>>();
    validate_schema(&manifest_schema)?;
    if manifest.schema_fingerprint != schema_fingerprint(&manifest_schema)? {
        return Err(ApiError::Validation(
            "backup v2 schema fingerprint does not match its manifest tables or expected schema order or columns"
                .to_string(),
        ));
    }
    let expected_tables = expected_schema_for_manifest(&manifest_schema, expected_schema)
        .ok_or_else(|| {
            ApiError::Validation(format!(
                "backup v2 contains {} tables; expected {}",
                manifest.tables.len(),
                expected_schema.len()
            ))
        })?;

    let mut paths = HashSet::new();
    if let Some(portable_integrity) = &manifest.portable_integrity {
        paths.insert(portable_integrity.entry_path.as_str());
    }
    let mut table_names = HashSet::new();
    for (index, (table, expected)) in manifest
        .tables
        .iter()
        .zip(expected_tables.iter())
        .enumerate()
    {
        let order = index as u64;
        if table.order != order
            || table.name != expected.name
            || !backup_columns_are_compatible(&table.name, &table.columns, &expected.columns)
            || table.entry_path != table_entry_path(order, &expected.name)?
        {
            return Err(ApiError::Validation(format!(
                "backup v2 table {} does not match expected schema order or columns (schema fingerprint differs)",
                table.name
            )));
        }
        if !table_names.insert(table.name.as_str()) || !paths.insert(table.entry_path.as_str()) {
            return Err(ApiError::Validation(
                "backup v2 contains duplicate table names or entry paths".to_string(),
            ));
        }
        if !is_sha256(&table.sha256) {
            return Err(ApiError::Validation(format!(
                "backup v2 table {} has an invalid hash",
                table.name
            )));
        }
        if table.byte_length > TAR_MAX_ENTRY_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 table {} exceeds the canonical ustar entry limit",
                table.name
            )));
        }
    }

    let mut previous_hash: Option<&str> = None;
    let mut blob_hashes = HashSet::new();
    for blob in &manifest.blobs {
        if !is_sha256(&blob.hash)
            || previous_hash.is_some_and(|previous| previous >= blob.hash.as_str())
            || !blob_hashes.insert(blob.hash.as_str())
            || !paths.insert(blob.entry_path.as_str())
            || blob.entry_path != blob_entry_path(&blob.hash)?
        {
            return Err(ApiError::Validation(
                "backup v2 blob catalog is invalid, duplicated, or unsorted".to_string(),
            ));
        }
        if blob.byte_length > TAR_MAX_ENTRY_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 blob {} exceeds the canonical ustar entry limit",
                blob.hash
            )));
        }
        previous_hash = Some(&blob.hash);
    }

    let computed = V2Totals {
        table_count: manifest.tables.len() as u64,
        row_count: checked_sum(
            manifest.tables.iter().map(|table| table.row_count),
            "row count",
        )?,
        table_bytes: checked_sum(
            manifest.tables.iter().map(|table| table.byte_length),
            "table bytes",
        )?,
        blob_count: manifest.blobs.len() as u64,
        content_bytes: checked_sum(
            manifest.blobs.iter().map(|blob| blob.byte_length),
            "content bytes",
        )?,
    };
    if computed != manifest.totals {
        return Err(ApiError::Validation(
            "backup v2 manifest totals do not match its catalog".to_string(),
        ));
    }
    if computed.row_count > limits.max_rows {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 has {} rows; limit is {}",
            computed.row_count, limits.max_rows
        )));
    }
    if computed.content_bytes > limits.max_content_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 has {} content bytes; limit is {}",
            computed.content_bytes, limits.max_content_bytes
        )));
    }
    Ok(())
}

/// Archive admission and transactional restore share one exact compatibility
/// allowlist so an older archive cannot pass one layer and fail the next.
fn backup_columns_are_compatible(table: &str, incoming: &[String], expected: &[String]) -> bool {
    crate::backup_schema_compatibility::columns_are_compatible(table, incoming, expected)
}

fn expected_schema_for_manifest<'a>(
    incoming: &[V2TableSchema],
    expected: &'a [V2TableSchema],
) -> Option<Vec<&'a V2TableSchema>> {
    if incoming.len() == expected.len() {
        return Some(expected.iter().collect());
    }
    let incoming_names = incoming
        .iter()
        .map(|table| table.name.as_str())
        .collect::<Vec<_>>();
    let expected_names = expected
        .iter()
        .map(|table| table.name.as_str())
        .collect::<Vec<_>>();
    crate::backup_schema_compatibility::omits_historical_human_item_sharing_tables(
        &incoming_names,
        &expected_names,
    )
    .then(|| {
        expected
            .iter()
            .filter(|table| {
                !crate::backup_schema_compatibility::HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES
                    .contains(&table.name.as_str())
            })
            .collect()
    })
}

fn validate_schema(schema: &[V2TableSchema]) -> ApiResult<()> {
    if schema.is_empty() {
        return Err(ApiError::Validation(
            "backup v2 schema must contain at least one table".to_string(),
        ));
    }
    let mut names = HashSet::new();
    for table in schema {
        if !valid_identifier(&table.name) || !names.insert(table.name.as_str()) {
            return Err(ApiError::Validation(
                "backup v2 schema contains an invalid or duplicate table".to_string(),
            ));
        }
        if table.columns.is_empty() {
            return Err(ApiError::Validation(format!(
                "backup v2 table {} has no columns",
                table.name
            )));
        }
        let mut columns = HashSet::new();
        for column in &table.columns {
            if !valid_identifier(column) || !columns.insert(column.as_str()) {
                return Err(ApiError::Validation(format!(
                    "backup v2 table {} has an invalid or duplicate column",
                    table.name
                )));
            }
        }
    }
    Ok(())
}

fn validate_build_blob_catalog(
    referenced: &HashSet<String>,
    blobs: &[PreparedBlob],
) -> ApiResult<()> {
    let declared = blobs
        .iter()
        .map(|blob| blob.descriptor.hash.as_str())
        .collect::<HashSet<_>>();
    let referenced = referenced
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if referenced != declared {
        let missing = referenced.difference(&declared).count();
        let extra = declared.difference(&referenced).count();
        return Err(ApiError::Validation(format!(
            "backup v2 blob sources are not an exact reference match ({missing} missing, {extra} extra)"
        )));
    }
    Ok(())
}

fn validate_table_entry(
    archive: &mut impl Read,
    descriptor: &V2TableDescriptor,
    limits: V2Limits,
    referenced_hashes: &mut HashSet<String>,
) -> ApiResult<()> {
    let mut reader = EntryHashReader::new(archive, descriptor.byte_length);
    let mut buffered = BufReader::with_capacity(16 * 1024, &mut reader);
    let header_line = read_bounded_line(&mut buffered, limits.max_line_bytes)?
        .ok_or_else(|| ApiError::Validation("backup v2 table is empty".to_string()))?;
    let header: V2TableHeader = serde_json::from_slice(&header_line).map_err(|error| {
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

    let mut row_count = 0u64;
    while let Some(line) = read_bounded_line(&mut buffered, limits.max_line_bytes)? {
        if line.is_empty() {
            return Err(ApiError::Validation(format!(
                "backup v2 table {} contains an empty JSONL row",
                descriptor.name
            )));
        }
        row_count = row_count
            .checked_add(1)
            .ok_or_else(|| ApiError::PayloadTooLarge("backup v2 row count overflow".to_string()))?;
        if row_count > descriptor.row_count || row_count > limits.max_rows {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 table {} contains too many rows",
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
        validate_row_values(&row, &descriptor.name)?;
        collect_referenced_hashes(&descriptor.columns, &row, referenced_hashes)?;
    }
    drop(buffered);
    if reader.remaining != 0 {
        return Err(ApiError::Validation(format!(
            "backup v2 table {} ended before its declared length",
            descriptor.name
        )));
    }
    if row_count != descriptor.row_count {
        return Err(ApiError::Validation(format!(
            "backup v2 table {} row count is {row_count}; manifest declares {}",
            descriptor.name, descriptor.row_count
        )));
    }
    let actual_hash = reader.finish_hash();
    if actual_hash != descriptor.sha256 {
        return Err(ApiError::Validation(format!(
            "backup v2 table {} hash does not match manifest",
            descriptor.name
        )));
    }
    Ok(())
}

fn collect_referenced_hashes(
    columns: &[String],
    row: &[Value],
    hashes: &mut HashSet<String>,
) -> ApiResult<()> {
    for (index, column) in columns.iter().enumerate() {
        if column != "content_hash" && column != "thumbnail_hash" && column != "cover_hash" {
            continue;
        }
        match row.get(index) {
            Some(Value::Null) => {}
            Some(Value::String(hash)) if is_sha256(hash) => {
                hashes.insert(hash.clone());
            }
            Some(_) => {
                return Err(ApiError::Validation(format!(
                    "backup v2 row contains an invalid {column}"
                )))
            }
            None => {
                return Err(ApiError::Validation(
                    "backup v2 row is missing a hash column".to_string(),
                ))
            }
        }
    }
    Ok(())
}

fn validate_row_values(row: &[Value], table: &str) -> ApiResult<()> {
    for value in row {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            Value::Object(object)
                if object.len() == 1
                    && object
                        .get("__blob_base64")
                        .and_then(Value::as_str)
                        .is_some_and(|encoded| {
                            base64::engine::general_purpose::STANDARD
                                .decode(encoded)
                                .is_ok()
                        }) => {}
            _ => {
                return Err(ApiError::Validation(format!(
                    "backup v2 table {table} contains an unsupported row value"
                )))
            }
        }
    }
    Ok(())
}

fn write_json_line<T: Serialize + ?Sized>(
    file: &mut File,
    hasher: &mut Sha256,
    byte_length: &mut u64,
    value: &T,
    limits: V2Limits,
    prior_table_bytes: u64,
) -> ApiResult<()> {
    let mut line = serde_json::to_vec(value).map_err(|error| {
        ApiError::Validation(format!("could not serialize backup v2 JSONL: {error}"))
    })?;
    line.push(b'\n');
    if line.len() as u64 > limits.max_line_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 JSONL line is {} bytes; limit is {} bytes",
            line.len(),
            limits.max_line_bytes
        )));
    }
    *byte_length = byte_length.checked_add(line.len() as u64).ok_or_else(|| {
        ApiError::PayloadTooLarge("backup v2 table byte count overflow".to_string())
    })?;
    if *byte_length > TAR_MAX_ENTRY_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 table exceeds the canonical ustar entry limit of {TAR_MAX_ENTRY_BYTES} bytes"
        )));
    }
    let aggregate_table_bytes = prior_table_bytes.checked_add(*byte_length).ok_or_else(|| {
        ApiError::PayloadTooLarge("backup v2 aggregate table byte count overflow".to_string())
    })?;
    if aggregate_table_bytes > limits.max_archive_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 staged tables exceed the {}-byte archive limit",
            limits.max_archive_bytes
        )));
    }
    file.write_all(&line)?;
    hasher.update(&line);
    Ok(())
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: u64) -> ApiResult<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader
            .fill_buf()
            .map_err(|error| archive_read_error(error, "JSONL body"))?;
        if buffer.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(ApiError::Validation(
                "backup v2 JSONL line is not newline terminated".to_string(),
            ));
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        let next_len = (line.len() as u64)
            .checked_add(consumed as u64)
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("backup v2 JSONL line overflow".to_string())
            })?;
        if next_len > max_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 JSONL line exceeds {max_bytes} bytes"
            )));
        }
        line.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            line.pop();
            return Ok(Some(line));
        }
    }
}

/// Bind publication to every successfully written archive byte.
struct ArchiveHashWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W> ArchiveHashWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish_hash(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl<W: Write> Write for ArchiveHashWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Hash exactly the stream consumed by validation or extraction, including
/// headers, padding and trailer. Provenance must never reopen the source path
/// to authenticate an independently extracted snapshot.
struct ArchiveHashReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> ArchiveHashReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish_hash(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl<R: Read> Read for ArchiveHashReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

struct EntryHashReader<'a> {
    inner: &'a mut dyn Read,
    remaining: u64,
    hasher: Sha256,
}

impl<'a> EntryHashReader<'a> {
    fn new(inner: &'a mut dyn Read, remaining: u64) -> Self {
        Self {
            inner,
            remaining,
            hasher: Sha256::new(),
        }
    }

    fn finish_hash(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl Read for EntryHashReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let allowed =
            usize::try_from(self.remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = self.inner.read(&mut buffer[..allowed])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backup v2 entry ended early",
            ));
        }
        self.remaining -= read as u64;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

fn append_bytes_entry(archive: &mut impl Write, path: &str, bytes: &[u8]) -> ApiResult<()> {
    write_tar_header(archive, path, bytes.len() as u64, b'0')?;
    write_archive_all(archive, bytes)?;
    write_tar_padding(archive, bytes.len() as u64)?;
    Ok(())
}

fn append_verified_file_entry(
    archive: &mut impl Write,
    entry_path: &str,
    source_path: &Path,
    expected_len: u64,
    expected_hash: &str,
) -> ApiResult<()> {
    write_tar_header(archive, entry_path, expected_len, b'0')?;
    let mut source = File::open(source_path)?;
    let mut hasher = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read as u64).ok_or_else(|| {
            ApiError::PayloadTooLarge("backup v2 entry size overflow".to_string())
        })?;
        if copied > expected_len {
            return Err(ApiError::Validation(format!(
                "backup v2 source for {entry_path} grew during archive creation"
            )));
        }
        write_archive_all(archive, &buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    let actual_hash = hex::encode(hasher.finalize());
    if copied != expected_len || actual_hash != expected_hash {
        return Err(ApiError::Validation(format!(
            "backup v2 source for {entry_path} changed during archive creation"
        )));
    }
    write_tar_padding(archive, expected_len)?;
    Ok(())
}

fn write_tar_header(
    archive: &mut impl Write,
    path: &str,
    size: u64,
    entry_type: u8,
) -> ApiResult<()> {
    validate_generated_archive_path(path)?;
    if path.len() > 100 {
        return Err(ApiError::Validation(
            "backup v2 tar path exceeds the canonical header limit".to_string(),
        ));
    }
    let mut header = [0u8; TAR_BLOCK_BYTES as usize];
    header[..path.len()].copy_from_slice(path.as_bytes());
    write_octal_field(&mut header[100..108], 0o600, "mode")?;
    write_octal_field(&mut header[108..116], 0, "uid")?;
    write_octal_field(&mut header[116..124], 0, "gid")?;
    write_octal_field(&mut header[124..136], size, "size")?;
    write_octal_field(&mut header[136..148], 0, "mtime")?;
    header[148..156].fill(b' ');
    header[156] = entry_type;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let encoded = format!("{checksum:06o}\0 ");
    if encoded.len() != 8 {
        return Err(ApiError::PayloadTooLarge(
            "backup v2 tar checksum overflow".to_string(),
        ));
    }
    header[148..156].copy_from_slice(encoded.as_bytes());
    write_archive_all(archive, &header)?;
    Ok(())
}

fn read_tar_header(archive: &mut impl Read, label: &str) -> ApiResult<TarHeader> {
    let mut header = [0u8; TAR_BLOCK_BYTES as usize];
    read_exact_validated(archive, &mut header, label)?;
    if header.iter().all(|byte| *byte == 0) {
        return Err(ApiError::Validation(format!(
            "backup v2 reached the tar trailer before {label}"
        )));
    }
    let recorded_checksum = parse_octal_field(&header[148..156], "checksum")?;
    let mut checksum_header = header;
    checksum_header[148..156].fill(b' ');
    let actual_checksum: u64 = checksum_header.iter().map(|byte| u64::from(*byte)).sum();
    if recorded_checksum != actual_checksum {
        return Err(ApiError::Validation(
            "backup v2 tar header checksum is invalid".to_string(),
        ));
    }
    if &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
        return Err(ApiError::Validation(
            "backup v2 archive is not canonical POSIX ustar".to_string(),
        ));
    }
    if header[265..500].iter().any(|byte| *byte != 0) {
        return Err(ApiError::Validation(
            "backup v2 tar header uses unsupported owner, device, prefix, or extension fields"
                .to_string(),
        ));
    }
    let name_end = header[..100]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    if header[name_end..100].iter().any(|byte| *byte != 0) {
        return Err(ApiError::Validation(
            "backup v2 tar path has non-zero padding".to_string(),
        ));
    }
    let path = std::str::from_utf8(&header[..name_end])
        .map_err(|_| ApiError::Validation("backup v2 tar path is not UTF-8".to_string()))?
        .to_string();
    validate_archive_entry_path(&path)?;
    let mode = parse_octal_field(&header[100..108], "mode")?;
    let uid = parse_octal_field(&header[108..116], "uid")?;
    let gid = parse_octal_field(&header[116..124], "gid")?;
    let size = parse_octal_field(&header[124..136], "size")?;
    let mtime = parse_octal_field(&header[136..148], "mtime")?;
    if mode != 0o600 || uid != 0 || gid != 0 || mtime != 0 {
        return Err(ApiError::Validation(
            "backup v2 tar metadata is not canonical".to_string(),
        ));
    }
    Ok(TarHeader {
        path,
        size,
        entry_type: header[156],
    })
}

fn validate_regular_header(header: &TarHeader) -> ApiResult<()> {
    if header.entry_type != b'0' {
        return Err(ApiError::Validation(format!(
            "backup v2 archive entry {} is not a regular file",
            header.path
        )));
    }
    Ok(())
}

fn validate_expected_entry(header: &TarHeader, path: &str, size: u64) -> ApiResult<()> {
    if header.path != path {
        return Err(ApiError::Validation(format!(
            "backup v2 archive entry {} is duplicate, unknown, or out of order; expected {path}",
            header.path
        )));
    }
    if header.size != size {
        return Err(ApiError::Validation(format!(
            "backup v2 archive entry {path} is {} bytes; manifest declares {size}",
            header.size
        )));
    }
    Ok(())
}

fn stream_entry_hash(archive: &mut impl Read, size: u64, label: &str) -> ApiResult<String> {
    let mut remaining = size;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let allowed = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = archive.read(&mut buffer[..allowed])?;
        if read == 0 {
            return Err(ApiError::Validation(format!(
                "backup v2 {label} ended before its declared length"
            )));
        }
        remaining -= read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn write_tar_padding(archive: &mut impl Write, size: u64) -> ApiResult<()> {
    let padding = tar_padding(size);
    if padding > 0 {
        write_archive_all(
            archive,
            &[0u8; TAR_BLOCK_BYTES as usize][..padding as usize],
        )?;
    }
    Ok(())
}

/// Write archive output while allowing deterministic, per-test ENOSPC injection.
///
/// Outside tests this delegates directly to `Write::write_all`, so production
/// archive creation has no fault-injection state or alternate behavior.
fn write_archive_all(archive: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    {
        let mut written = 0usize;
        while written < bytes.len() {
            let allowed = test_faults::next_archive_write_len(bytes.len() - written)?;
            archive.write_all(&bytes[written..written + allowed])?;
            test_faults::record_archive_write(allowed);
            written += allowed;
        }
        Ok(())
    }

    #[cfg(not(test))]
    archive.write_all(bytes)
}

fn skip_tar_padding(archive: &mut impl Read, size: u64, label: &str) -> ApiResult<()> {
    let padding = tar_padding(size);
    if padding == 0 {
        return Ok(());
    }
    let mut bytes = [0u8; TAR_BLOCK_BYTES as usize];
    read_exact_validated(archive, &mut bytes[..padding as usize], label)?;
    if bytes[..padding as usize].iter().any(|byte| *byte != 0) {
        return Err(ApiError::Validation(format!(
            "backup v2 {label} is not zero-filled"
        )));
    }
    Ok(())
}

fn write_octal_field(field: &mut [u8], value: u64, label: &str) -> ApiResult<()> {
    let width = field.len();
    let encoded = format!("{value:0digits$o}\0", digits = width - 1);
    if encoded.len() != width {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup v2 tar {label} does not fit its header field"
        )));
    }
    field.copy_from_slice(encoded.as_bytes());
    Ok(())
}

fn parse_octal_field(field: &[u8], label: &str) -> ApiResult<u64> {
    let trimmed_end = field
        .iter()
        .rposition(|byte| *byte != 0 && *byte != b' ')
        .map_or(0, |index| index + 1);
    let trimmed_start = field[..trimmed_end]
        .iter()
        .position(|byte| *byte != b' ')
        .unwrap_or(trimmed_end);
    let digits = &field[trimmed_start..trimmed_end];
    if digits.is_empty() || digits.iter().any(|byte| !(b'0'..=b'7').contains(byte)) {
        return Err(ApiError::Validation(format!(
            "backup v2 tar {label} is not an octal number"
        )));
    }
    let text = std::str::from_utf8(digits)
        .map_err(|_| ApiError::Validation(format!("backup v2 tar {label} is invalid")))?;
    u64::from_str_radix(text, 8)
        .map_err(|_| ApiError::PayloadTooLarge(format!("backup v2 tar {label} overflows u64")))
}

fn expected_archive_size(
    manifest: &V2Manifest,
    manifest_bytes: u64,
    portable_integrity_bytes: Option<u64>,
) -> ApiResult<u64> {
    let mut total = tar_entry_size(manifest_bytes)?;
    if let Some(portable_integrity_bytes) = portable_integrity_bytes {
        total = total
            .checked_add(tar_entry_size(portable_integrity_bytes)?)
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("backup v2 archive size overflow".to_string())
            })?;
    }
    for bytes in manifest
        .tables
        .iter()
        .map(|table| table.byte_length)
        .chain(manifest.blobs.iter().map(|blob| blob.byte_length))
    {
        total = total.checked_add(tar_entry_size(bytes)?).ok_or_else(|| {
            ApiError::PayloadTooLarge("backup v2 archive size overflow".to_string())
        })?;
    }
    total
        .checked_add(TAR_TRAILER_BYTES)
        .ok_or_else(|| ApiError::PayloadTooLarge("backup v2 archive size overflow".to_string()))
}

fn tar_entry_size(bytes: u64) -> ApiResult<u64> {
    TAR_BLOCK_BYTES
        .checked_add(bytes)
        .and_then(|value| value.checked_add(tar_padding(bytes)))
        .ok_or_else(|| ApiError::PayloadTooLarge("backup v2 tar size overflow".to_string()))
}

fn tar_padding(bytes: u64) -> u64 {
    (TAR_BLOCK_BYTES - (bytes % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES
}

fn table_entry_path(order: u64, name: &str) -> ApiResult<String> {
    if !valid_identifier(name) || order > 99 {
        return Err(ApiError::Validation(
            "backup v2 table name or order is invalid".to_string(),
        ));
    }
    Ok(format!("tables/{order:02}-{name}.jsonl"))
}

fn blob_entry_path(hash: &str) -> ApiResult<String> {
    if !is_sha256(hash) {
        return Err(ApiError::Validation(
            "backup v2 blob hash is invalid".to_string(),
        ));
    }
    Ok(format!("blobs/{}/{}", &hash[..2], hash))
}

fn validate_archive_target(path: &Path, backup_id: &str) -> ApiResult<()> {
    let expected_name = format!("{backup_id}.{ARCHIVE_EXTENSION}");
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(ApiError::Validation(
            "backup v2 archive filename does not match its id".to_string(),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        ApiError::Validation("backup v2 archive has no parent directory".to_string())
    })?;
    fs_private::create_dir_all_private(parent)?;
    Ok(())
}

fn archive_partial_path(path: &Path) -> ApiResult<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Validation("backup v2 archive name is not UTF-8".to_string()))?;
    Ok(path.with_file_name(format!("{name}.partial")))
}

fn validate_generated_archive_path(path: &str) -> ApiResult<()> {
    if !path.is_ascii() {
        return Err(ApiError::Validation(
            "backup v2 generated tar path is not ASCII".to_string(),
        ));
    }
    validate_archive_entry_path(path)
}

fn validate_archive_entry_path(path: &str) -> ApiResult<()> {
    if path.is_empty() || path.contains('\\') || path.contains('\0') {
        return Err(ApiError::Validation(
            "backup v2 archive path is empty or malformed".to_string(),
        ));
    }
    let has_drive_prefix = path.as_bytes().get(1) == Some(&b':');
    if path.starts_with('/')
        || has_drive_prefix
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ApiError::Validation(
            "backup v2 archive path is absolute or traverses directories".to_string(),
        ));
    }
    Ok(())
}

fn valid_backup_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn checked_sum(mut values: impl Iterator<Item = u64>, label: &str) -> ApiResult<u64> {
    values.try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| ApiError::PayloadTooLarge(format!("backup v2 {label} overflow")))
    })
}

fn hash_file_exact(path: &Path, expected_bytes: u64) -> ApiResult<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    while bytes < expected_bytes {
        let remaining = expected_bytes - bytes;
        let allowed = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = file.read(&mut buffer[..allowed])?;
        if read == 0 {
            return Err(ApiError::Validation(
                "backup v2 source ended before its declared length".to_string(),
            ));
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| ApiError::PayloadTooLarge("backup v2 file size overflow".to_string()))?;
        hasher.update(&buffer[..read]);
    }
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(ApiError::Validation(
            "backup v2 source grew beyond its declared length".to_string(),
        ));
    }
    Ok((bytes, hex::encode(hasher.finalize())))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn create_private_file_new(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        fs_private::create_dir_all_private(parent)?;
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    fs_private::set_file_private(path)?;
    Ok(file)
}

fn read_exact_validated(reader: &mut impl Read, buffer: &mut [u8], label: &str) -> ApiResult<()> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            ApiError::Validation(format!("backup v2 {label} is truncated"))
        } else {
            error.into()
        }
    })
}

fn archive_read_error(error: io::Error, label: &str) -> ApiError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        ApiError::Validation(format!("backup v2 {label} is truncated"))
    } else {
        error.into()
    }
}

fn cleanup_stage_dir(stage_dir: &Path) {
    if let Ok(entries) = fs::read_dir(stage_dir) {
        for entry in entries.flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }
    let _ = fs::remove_dir(stage_dir);
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod fault_tests;
#[cfg(test)]
mod test_faults;
#[cfg(test)]
mod tests;
