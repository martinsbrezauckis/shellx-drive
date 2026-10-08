use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::Digest;
use sha2::Sha256;

use crate::{
    backup_v2::{self, V2Manifest},
    error::{ApiError, ApiResult},
    fs_private,
    model::BackupMetadata,
    server::AppState,
};

mod bounds;
mod provenance;
pub(super) use bounds::bounded_backup_catalog_paths;
#[cfg(test)]
use provenance::read_v2_backup_metadata;
pub(super) use provenance::read_v2_backup_metadata_for_state;

const V2_SIDECAR_LIMIT: u64 = 64 * 1024;
const V2_SIDECAR_KEY_BYTES: usize = 32;
const V2_INCOMPLETE_MARKER_SUFFIX: &str = ".v2-incomplete";
/// Per-request metadata budget, charged before each candidate file open.
const MAX_BACKUP_CATALOG_METADATA_BYTES: u64 = 16 * 1024 * 1024;
/// Conservative manifest, integrity-envelope, and framing charge for a
/// sidecar-less portable archive.
const V2_PORTABLE_METADATA_WORK_BYTES: u64 = 2 * 1024 * 1024;
/// The single retention worker can scan the full documented item ceiling.
const MAX_RETENTION_CATALOG_METADATA_BYTES: u64 =
    V2_PORTABLE_METADATA_WORK_BYTES * super::MAX_BACKUP_CATALOG_ENTRIES as u64;

type HmacSha256 = Hmac<Sha256>;

pub(super) struct CatalogMetadataBudget {
    limit: u64,
    remaining: u64,
}

impl Default for CatalogMetadataBudget {
    fn default() -> Self {
        Self {
            limit: MAX_BACKUP_CATALOG_METADATA_BYTES,
            remaining: MAX_BACKUP_CATALOG_METADATA_BYTES,
        }
    }
}

impl CatalogMetadataBudget {
    pub(super) fn reserve(&mut self, bytes: u64) -> ApiResult<()> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(|| {
            ApiError::PayloadTooLarge(format!(
                "backup catalog metadata scan exceeds its {}-byte work limit",
                self.limit
            ))
        })?;
        Ok(())
    }

    fn for_retention() -> Self {
        Self {
            limit: MAX_RETENTION_CATALOG_METADATA_BYTES,
            remaining: MAX_RETENTION_CATALOG_METADATA_BYTES,
        }
    }

    #[cfg(test)]
    fn with_limit(limit: u64) -> Self {
        Self {
            limit,
            remaining: limit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct V2SidecarPayload {
    pub(super) metadata: BackupMetadata,
    pub(super) archive_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2SidecarEnvelope {
    payload: V2SidecarPayload,
    hmac_sha256: String,
}

#[cfg(test)]
pub(super) fn list_v2_backup_metadata(data_dir: &Path) -> ApiResult<Vec<BackupMetadata>> {
    let paths = bounded_backup_catalog_paths(data_dir)?;
    let mut budget = CatalogMetadataBudget::for_retention();
    list_v2_backup_metadata_from_paths(
        data_dir,
        &paths,
        &mut budget,
        &HashMap::new(),
        &HashSet::new(),
    )
}

pub(super) fn list_v2_backup_metadata_from_paths(
    data_dir: &Path,
    paths: &[PathBuf],
    budget: &mut CatalogMetadataBudget,
    managed_digests: &HashMap<String, String>,
    tombstoned_ids: &HashSet<String>,
) -> ApiResult<Vec<BackupMetadata>> {
    let mut backups = Vec::new();
    let mut sidecar_ids = HashSet::new();
    let mut incomplete_ids = HashSet::new();
    for path in paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(backup_id) = name.strip_suffix(".meta.json") else {
            continue;
        };
        if tombstoned_ids.contains(backup_id) {
            continue;
        }
        match v2_incomplete_marker_present(data_dir, backup_id) {
            Ok(true) => {
                incomplete_ids.insert(backup_id.to_string());
                continue;
            }
            Ok(false) => {}
            Err(error) => {
                incomplete_ids.insert(backup_id.to_string());
                tracing::warn!(%error, backup_id, "ignoring backup v2 generation with an invalid incomplete marker");
                continue;
            }
        }
        sidecar_ids.insert(backup_id.to_string());
        reserve_catalog_file_bytes(budget, path, V2_SIDECAR_LIMIT)?;
        match read_v2_sidecar(data_dir, backup_id) {
            Ok(sidecar)
                if managed_digests
                    .get(backup_id)
                    .is_none_or(|expected| expected == &sidecar.archive_sha256) =>
            {
                backups.push(sidecar.metadata)
            }
            Ok(_) => tracing::warn!(
                backup_id,
                "ignoring managed backup whose sidecar conflicts with durable provenance"
            ),
            Err(error) => tracing::warn!(%error, backup_id, "ignoring invalid backup v2 sidecar"),
        }
    }
    for path in paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(backup_id) = name.strip_suffix(&format!(".{}", backup_v2::ARCHIVE_EXTENSION))
        else {
            continue;
        };
        if tombstoned_ids.contains(backup_id) {
            continue;
        }
        // A present local sidecar is authoritative for the old local-v2
        // compatibility lane. Do not silently downgrade an invalid sidecar to
        // the embedded portable envelope.
        if incomplete_ids.contains(backup_id) || sidecar_ids.contains(backup_id) {
            continue;
        }
        if managed_digests.contains_key(backup_id) {
            tracing::warn!(
                backup_id,
                "ignoring managed backup whose authenticated sidecar is missing"
            );
            continue;
        }
        match v2_incomplete_marker_present(data_dir, backup_id) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, backup_id, "ignoring backup v2 generation with an invalid incomplete marker");
                continue;
            }
        }
        budget.reserve(V2_PORTABLE_METADATA_WORK_BYTES)?;
        match read_portable_metadata(path) {
            Ok(Some(metadata)) if metadata.backup_id == backup_id => backups.push(metadata),
            Ok(Some(_)) => tracing::warn!(
                backup_id,
                "ignoring portable backup with mismatched filename"
            ),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, backup_id, "ignoring invalid portable backup archive")
            }
        }
    }
    Ok(backups)
}

fn reserve_catalog_file_bytes(
    budget: &mut CatalogMetadataBudget,
    path: &Path,
    per_file_limit: u64,
) -> ApiResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    budget.reserve(metadata.len().min(per_file_limit))
}

fn read_portable_metadata(path: &Path) -> ApiResult<Option<BackupMetadata>> {
    backup_v2::read_portable_metadata(path, backup_v2::V2Limits::default()).map(|metadata| {
        metadata.map(|metadata| BackupMetadata {
            backup_id: metadata.backup_id,
            format: metadata.format,
            created_at: metadata.created_at,
            table_count: metadata.table_count,
            row_count: metadata.row_count,
            blob_count: metadata.blob_count,
            content_bytes: metadata.content_bytes,
            archive_bytes: Some(metadata.archive_bytes),
            job_id: None,
            status: Some("succeeded".to_string()),
            phase: Some("complete".to_string()),
            last_error: None,
        })
    })
}

pub(super) fn metadata_from_v2_manifest(
    manifest: &V2Manifest,
    archive_bytes: u64,
    job_id: &str,
) -> BackupMetadata {
    BackupMetadata {
        backup_id: manifest.backup_id.clone(),
        format: manifest.format.clone(),
        created_at: manifest.created_at.clone(),
        table_count: manifest.totals.table_count,
        row_count: manifest.totals.row_count,
        blob_count: manifest.totals.blob_count,
        content_bytes: manifest.totals.content_bytes,
        archive_bytes: Some(archive_bytes),
        job_id: Some(job_id.to_string()),
        status: Some("succeeded".to_string()),
        phase: Some("complete".to_string()),
        last_error: None,
    }
}

pub(super) fn apply_v2_retention(state: &AppState) -> ApiResult<()> {
    let policy = state.storage.get_backup_policy()?;
    let retention_count = crate::storage::validate_backup_retention_count(policy.retention_count)?;
    let retention = usize::try_from(retention_count)
        .map_err(|_| ApiError::Validation("invalid backup retention count".to_string()))?;
    let mut sidecars = list_retention_managed_v2_metadata(&state.data_dir())?;
    sidecars.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    for backup in sidecars.into_iter().skip(retention) {
        let archive = v2_backup_path(&state.data_dir(), &backup.backup_id)?;
        let sidecar = v2_sidecar_path(&state.data_dir(), &backup.backup_id)?;
        // Persist the classification before deleting either file. If the
        // process stops or an archive-directory attacker races this sequence,
        // the old authenticated pair remains unusable rather than replayable.
        state
            .storage
            .retire_managed_backup_publication(&backup.backup_id)?;
        if archive.exists() {
            fs::remove_file(archive)?;
        }
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    Ok(())
}

/// Upgrade/backfill bridge: authenticated sidecars predate the durable local
/// publication registry. Register them at startup so later sidecar deletion
/// cannot downgrade an existing managed generation into the portable lane.
pub(super) fn reconcile_managed_v2_publications(state: &AppState) -> ApiResult<()> {
    let tombstoned_ids = state.storage.managed_backup_tombstoned_ids()?;
    for path in bounded_backup_catalog_paths(&state.data_dir())? {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(backup_id) = name.strip_suffix(".meta.json") else {
            continue;
        };
        if tombstoned_ids.contains(backup_id) {
            tracing::warn!(
                backup_id,
                "ignoring retired managed backup replay during reconciliation"
            );
            continue;
        }
        if v2_incomplete_marker_present(&state.data_dir(), backup_id)? {
            continue;
        }
        match read_v2_sidecar(&state.data_dir(), backup_id) {
            Ok(sidecar) => {
                if let Err(error) = state.storage.record_managed_backup_publication(
                    backup_id,
                    &sidecar.archive_sha256,
                    &sidecar.metadata.created_at,
                ) {
                    tracing::warn!(%error, backup_id, "could not backfill managed backup provenance");
                }
            }
            Err(error) => {
                tracing::warn!(%error, backup_id, "could not backfill managed backup provenance")
            }
        }
    }
    Ok(())
}

/// Automatic deletion owns only generations authenticated by this instance's
/// sidecar key. Sidecar-less portable archives remain listable/restorable, but
/// their self-asserted timestamps cannot influence destructive retention.
fn list_retention_managed_v2_metadata(data_dir: &Path) -> ApiResult<Vec<BackupMetadata>> {
    let paths = bounded_backup_catalog_paths(data_dir)?;
    let mut budget = CatalogMetadataBudget::for_retention();
    let mut managed = Vec::new();
    for path in paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(backup_id) = name.strip_suffix(".meta.json") else {
            continue;
        };
        if v2_incomplete_marker_present(data_dir, backup_id).unwrap_or(true) {
            continue;
        }
        reserve_catalog_file_bytes(&mut budget, &path, V2_SIDECAR_LIMIT)?;
        match read_v2_sidecar(data_dir, backup_id) {
            Ok(sidecar) => managed.push(sidecar.metadata),
            Err(error) => {
                tracing::warn!(%error, backup_id, "ignoring unmanaged backup retention candidate")
            }
        }
    }
    Ok(managed)
}

#[cfg(test)]
pub(super) fn hash_file_streaming(path: &Path, max_bytes: u64) -> ApiResult<String> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size > max_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup archive is {size} bytes; limit is {max_bytes} bytes"
        )));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut read_bytes = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        read_bytes = read_bytes.checked_add(read as u64).ok_or_else(|| {
            ApiError::PayloadTooLarge("backup archive length overflow".to_string())
        })?;
        if read_bytes > max_bytes {
            return Err(ApiError::PayloadTooLarge(
                "backup archive grew beyond its configured limit".to_string(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if read_bytes != size {
        return Err(ApiError::Validation(
            "backup archive changed while being hashed".to_string(),
        ));
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn read_or_create_v2_sidecar_key(data_dir: &Path) -> ApiResult<Vec<u8>> {
    let path = backup_dir(data_dir).join(".metadata-key");
    if path.exists() {
        let key = read_file_bounded(&path, V2_SIDECAR_KEY_BYTES as u64, "backup metadata key")?;
        if key.len() != V2_SIDECAR_KEY_BYTES {
            return Err(ApiError::Validation(
                "backup metadata key has an invalid length".to_string(),
            ));
        }
        fs_private::set_file_private(&path)?;
        return Ok(key);
    }
    fs_private::create_dir_all_private(&backup_dir(data_dir))?;
    let has_sidecars = bounded_backup_catalog_paths(data_dir)?.iter().any(|path| {
        path.file_name()
            .and_then(|name| name.to_str().map(str::to_string))
            .is_some_and(|name| name.ends_with(".meta.json"))
    });
    if has_sidecars {
        return Err(ApiError::Validation(
            "backup metadata key is missing while authenticated sidecars exist".to_string(),
        ));
    }
    let mut key = vec![0u8; V2_SIDECAR_KEY_BYTES];
    rand::thread_rng().fill_bytes(&mut key);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    file.write_all(&key)?;
    file.sync_all()?;
    fs_private::set_file_private(&path)?;
    sync_directory(&backup_dir(data_dir))?;
    Ok(key)
}

fn sign_v2_sidecar(key: &[u8], payload: &V2SidecarPayload) -> ApiResult<String> {
    let bytes = serde_json::to_vec(payload).map_err(|error| {
        ApiError::Validation(format!("could not encode backup v2 sidecar: {error}"))
    })?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| ApiError::Validation("invalid backup metadata key".to_string()))?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub(super) fn write_v2_sidecar(data_dir: &Path, payload: V2SidecarPayload) -> ApiResult<()> {
    let key = read_or_create_v2_sidecar_key(data_dir)?;
    let path = v2_sidecar_path(data_dir, &payload.metadata.backup_id)?;
    let partial = v2_sidecar_partial_path(data_dir, &payload.metadata.backup_id)?;
    let envelope = V2SidecarEnvelope {
        hmac_sha256: sign_v2_sidecar(&key, &payload)?,
        payload,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| {
        ApiError::Validation(format!("could not encode backup v2 sidecar: {error}"))
    })?;
    if bytes.len() as u64 > V2_SIDECAR_LIMIT {
        return Err(ApiError::PayloadTooLarge(
            "backup v2 sidecar exceeds its fixed limit".to_string(),
        ));
    }
    fs_private::write_file_private(&partial, &bytes)?;
    fs::rename(&partial, &path)?;
    sync_directory(&backup_dir(data_dir))?;
    Ok(())
}

pub(super) fn read_v2_sidecar(data_dir: &Path, backup_id: &str) -> ApiResult<V2SidecarPayload> {
    let path = v2_sidecar_path(data_dir, backup_id)?;
    let bytes = read_file_bounded(&path, V2_SIDECAR_LIMIT, "backup v2 sidecar")?;
    let envelope: V2SidecarEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| ApiError::Validation(format!("invalid backup v2 sidecar: {error}")))?;
    if envelope.payload.metadata.backup_id != backup_id
        || envelope.payload.metadata.format != backup_v2::FORMAT
        || envelope.payload.archive_sha256.len() != 64
        || !envelope
            .payload
            .archive_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ApiError::Validation(
            "backup v2 sidecar identity is invalid".to_string(),
        ));
    }
    let key = read_or_create_v2_sidecar_key(data_dir)?;
    let signature = hex::decode(&envelope.hmac_sha256)
        .map_err(|_| ApiError::Validation("backup v2 sidecar signature is invalid".to_string()))?;
    let payload = serde_json::to_vec(&envelope.payload).map_err(|error| {
        ApiError::Validation(format!("could not verify backup v2 sidecar: {error}"))
    })?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| ApiError::Validation("invalid backup metadata key".to_string()))?;
    mac.update(&payload);
    mac.verify_slice(&signature)
        .map_err(|_| ApiError::Validation("backup v2 sidecar authentication failed".to_string()))?;
    let archive = v2_backup_path(data_dir, backup_id)?;
    let metadata = fs::symlink_metadata(&archive)?;
    if !metadata.file_type().is_file()
        || envelope.payload.metadata.archive_bytes != Some(metadata.len())
    {
        return Err(ApiError::Validation(
            "backup v2 archive does not match its authenticated sidecar".to_string(),
        ));
    }
    Ok(envelope.payload)
}

pub(super) fn read_file_bounded(path: &Path, max_bytes: u64, label: &str) -> ApiResult<Vec<u8>> {
    let mut file = File::open(path)?;
    let declared = file.metadata()?.len();
    if declared > max_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "{label} is {declared} bytes; limit is {max_bytes} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(declared as usize);
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "{label} grew beyond the limit of {max_bytes} bytes while being read"
        )));
    }
    Ok(bytes)
}

pub(super) fn backup_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("backups")
}

pub(super) fn v2_staging_root(data_dir: &Path) -> PathBuf {
    backup_dir(data_dir).join(".staging")
}

pub(super) fn v2_backup_path(data_dir: &Path, backup_id: &str) -> ApiResult<PathBuf> {
    validate_backup_id(backup_id)?;
    Ok(backup_dir(data_dir).join(format!("{backup_id}.{}", backup_v2::ARCHIVE_EXTENSION)))
}

pub(super) fn v2_sidecar_path(data_dir: &Path, backup_id: &str) -> ApiResult<PathBuf> {
    validate_backup_id(backup_id)?;
    Ok(backup_dir(data_dir).join(format!("{backup_id}.meta.json")))
}

pub(super) fn v2_sidecar_partial_path(data_dir: &Path, backup_id: &str) -> ApiResult<PathBuf> {
    Ok(v2_sidecar_path(data_dir, backup_id)?.with_extension("json.partial"))
}

/// A create job owns this private, empty marker from before it starts archive
/// generation until its successful durable terminal state. It keeps a complete
/// archive fail-closed if the process stops after the archive rename but before
/// sidecar/catalog/job publication has finished.
pub(super) fn create_v2_incomplete_marker(data_dir: &Path, backup_id: &str) -> ApiResult<()> {
    let path = v2_incomplete_marker_path(data_dir, backup_id)?;
    let parent = path.parent().ok_or_else(|| {
        ApiError::Validation("backup v2 incomplete marker has no parent".to_string())
    })?;
    fs_private::create_dir_all_private(parent)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ApiError::Conflict)
        }
        Err(error) => return Err(error.into()),
    };
    file.sync_all()?;
    fs_private::set_file_private(&path)?;
    sync_directory(parent)?;
    Ok(())
}

pub(super) fn ensure_v2_generation_complete(data_dir: &Path, backup_id: &str) -> ApiResult<()> {
    if v2_incomplete_marker_present(data_dir, backup_id)? {
        return Err(ApiError::Conflict);
    }
    Ok(())
}

pub(super) fn remove_v2_incomplete_marker(data_dir: &Path, backup_id: &str) -> ApiResult<bool> {
    let path = v2_incomplete_marker_path(data_dir, backup_id)?;
    if !v2_incomplete_marker_present(data_dir, backup_id)? {
        return Ok(false);
    }
    fs::remove_file(&path)?;
    let parent = path.parent().ok_or_else(|| {
        ApiError::Validation("backup v2 incomplete marker has no parent".to_string())
    })?;
    sync_directory(parent)?;
    Ok(true)
}

pub(super) fn v2_incomplete_marker_present(data_dir: &Path, backup_id: &str) -> ApiResult<bool> {
    let path = v2_incomplete_marker_path(data_dir, backup_id)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.len() != 0 {
        return Err(ApiError::Validation(
            "backup v2 incomplete marker is malformed".to_string(),
        ));
    }
    Ok(true)
}

fn v2_incomplete_marker_path(data_dir: &Path, backup_id: &str) -> ApiResult<PathBuf> {
    validate_backup_id(backup_id)?;
    Ok(v2_staging_root(data_dir).join(format!(".{backup_id}{V2_INCOMPLETE_MARKER_SUFFIX}")))
}

pub(super) fn validate_backup_id(backup_id: &str) -> ApiResult<()> {
    if backup_id.is_empty()
        || backup_id.len() > 128
        || !backup_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ApiError::Validation("invalid backup id".to_string()));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn portable_archive_catalog_budget_stops_before_the_next_archive_open() {
        let data_dir = tempfile::tempdir().unwrap();
        let backups = backup_dir(data_dir.path());
        fs_private::create_dir_all_private(&backups).unwrap();
        fs_private::write_file_private(&backups.join("first.sxdbackup"), b"invalid").unwrap();
        fs_private::write_file_private(&backups.join("second.sxdbackup"), b"invalid").unwrap();
        let paths = bounded_backup_catalog_paths(data_dir.path()).unwrap();
        let mut budget = CatalogMetadataBudget::with_limit(V2_PORTABLE_METADATA_WORK_BYTES);

        let error = list_v2_backup_metadata_from_paths(
            data_dir.path(),
            &paths,
            &mut budget,
            &HashMap::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ApiError::PayloadTooLarge(message) if message.contains("metadata scan")
        ));
    }

    #[test]
    fn retention_budget_covers_the_documented_catalog_ceiling() {
        let mut budget = CatalogMetadataBudget::for_retention();
        for _ in 0..super::super::MAX_BACKUP_CATALOG_ENTRIES {
            budget.reserve(V2_PORTABLE_METADATA_WORK_BYTES).unwrap();
        }
        assert!(matches!(
            budget.reserve(1),
            Err(ApiError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn v2_sidecars_are_authenticated_and_orphans_never_list() {
        let data_dir = tempfile::tempdir().unwrap();
        let backups = backup_dir(data_dir.path());
        fs_private::create_dir_all_private(&backups).unwrap();
        let backup_id = "authenticated-sidecar";
        let archive = v2_backup_path(data_dir.path(), backup_id).unwrap();
        fs_private::write_file_private(&archive, b"fixture archive").unwrap();
        let payload = V2SidecarPayload {
            metadata: BackupMetadata {
                backup_id: backup_id.to_string(),
                format: backup_v2::FORMAT.to_string(),
                created_at: "2026-07-16T00:00:00Z".to_string(),
                table_count: 39,
                row_count: 100,
                blob_count: 1,
                content_bytes: 15,
                archive_bytes: Some(15),
                job_id: Some("job-one".to_string()),
                status: Some("succeeded".to_string()),
                phase: Some("complete".to_string()),
                last_error: None,
            },
            archive_sha256: sha256_hex(b"fixture archive"),
        };
        write_v2_sidecar(data_dir.path(), payload.clone()).unwrap();
        assert_eq!(
            read_v2_sidecar(data_dir.path(), backup_id).unwrap(),
            payload
        );
        assert_eq!(list_v2_backup_metadata(data_dir.path()).unwrap().len(), 1);

        let sidecar = v2_sidecar_path(data_dir.path(), backup_id).unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&sidecar).unwrap()).unwrap();
        envelope["payload"]["metadata"]["row_count"] = serde_json::json!(101);
        fs::write(&sidecar, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(read_v2_sidecar(data_dir.path(), backup_id).is_err());
        assert!(list_v2_backup_metadata(data_dir.path()).unwrap().is_empty());

        write_v2_sidecar(data_dir.path(), payload).unwrap();
        fs::remove_file(archive).unwrap();
        assert!(list_v2_backup_metadata(data_dir.path()).unwrap().is_empty());
    }

    #[test]
    fn incomplete_marker_hides_and_rejects_a_locally_published_generation() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_id = "incomplete-generation";
        let archive = v2_backup_path(data_dir.path(), backup_id).unwrap();
        fs_private::write_file_private(&archive, b"fixture archive").unwrap();
        let payload = V2SidecarPayload {
            metadata: BackupMetadata {
                backup_id: backup_id.to_string(),
                format: backup_v2::FORMAT.to_string(),
                created_at: "2026-07-16T00:00:00Z".to_string(),
                table_count: 1,
                row_count: 1,
                blob_count: 0,
                content_bytes: 0,
                archive_bytes: Some(15),
                job_id: Some("job-incomplete".to_string()),
                status: Some("succeeded".to_string()),
                phase: Some("complete".to_string()),
                last_error: None,
            },
            archive_sha256: sha256_hex(b"fixture archive"),
        };
        write_v2_sidecar(data_dir.path(), payload.clone()).unwrap();

        create_v2_incomplete_marker(data_dir.path(), backup_id).unwrap();
        assert!(v2_incomplete_marker_present(data_dir.path(), backup_id).unwrap());
        assert!(matches!(
            ensure_v2_generation_complete(data_dir.path(), backup_id),
            Err(ApiError::Conflict)
        ));
        assert!(matches!(
            read_v2_backup_metadata(data_dir.path(), backup_id, None),
            Err(ApiError::Conflict)
        ));
        assert!(list_v2_backup_metadata(data_dir.path()).unwrap().is_empty());

        assert!(remove_v2_incomplete_marker(data_dir.path(), backup_id).unwrap());
        assert!(!v2_incomplete_marker_present(data_dir.path(), backup_id).unwrap());
        assert_eq!(
            read_v2_backup_metadata(data_dir.path(), backup_id, None).unwrap(),
            payload.metadata
        );
        assert_eq!(list_v2_backup_metadata(data_dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn incomplete_marker_must_be_an_empty_regular_file_for_a_valid_backup_id() {
        let data_dir = tempfile::tempdir().unwrap();
        assert!(create_v2_incomplete_marker(data_dir.path(), "not/a-backup-id").is_err());

        let backup_id = "malformed-marker";
        create_v2_incomplete_marker(data_dir.path(), backup_id).unwrap();
        let marker = v2_incomplete_marker_path(data_dir.path(), backup_id).unwrap();
        fs_private::write_file_private(&marker, b"not empty").unwrap();
        assert!(v2_incomplete_marker_present(data_dir.path(), backup_id).is_err());
        assert!(remove_v2_incomplete_marker(data_dir.path(), backup_id).is_err());
    }
}
