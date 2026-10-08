use std::{
    fs,
    io::{Read, Result as IoResult},
    path::Path,
};

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    auth::{require_admin, token_hash},
    blob,
    error::{ApiError, ApiResult},
    server::AppState,
};

const DEFAULT_SCAN_LIMIT: usize = 2_000;
const MAX_SCAN_LIMIT: usize = 10_000;
const DEFAULT_HASH_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_ISSUE_LIMIT: usize = 50;
const MAX_ISSUE_LIMIT: usize = 200;

#[derive(Deserialize)]
struct IntegrityQuery {
    scan_limit: Option<usize>,
    hash_bytes: Option<u64>,
    issue_limit: Option<usize>,
}

#[derive(Serialize)]
struct DebugStorageIntegrityResponse {
    service: &'static str,
    read_only: bool,
    referenced_total: i64,
    referenced_scanned: usize,
    stored_scanned: usize,
    bytes_hashed: u64,
    missing_count: usize,
    orphan_count: usize,
    corrupt_count: usize,
    ignored_count: usize,
    scan_truncated: bool,
    hash_budget_exhausted: bool,
    issues_truncated: bool,
    missing_refs: Vec<String>,
    orphan_refs: Vec<String>,
    corrupt_refs: Vec<String>,
    limits: IntegrityLimits,
}

#[derive(Serialize)]
struct IntegrityLimits {
    scan: usize,
    hash_bytes: u64,
    issues: usize,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/storage-integrity", get(debug_storage_integrity))
}

async fn debug_storage_integrity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IntegrityQuery>,
) -> ApiResult<Json<DebugStorageIntegrityResponse>> {
    require_admin(&state, &headers)?;
    let limits = checked_limits(query)?;
    let (referenced_total, referenced) = state
        .storage
        .debug_referenced_blob_hashes(limits.scan as i64)?;
    let mut missing_refs = Vec::new();
    let mut corrupt_refs = Vec::new();
    let mut missing_count = 0usize;
    let mut corrupt_count = 0usize;
    let mut bytes_hashed = 0u64;
    let mut hash_budget_exhausted = false;

    for hash in &referenced {
        let path = blob::blob_file_path(&state.data_dir(), hash)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) | Err(_) => {
                missing_count += 1;
                push_ref(&mut missing_refs, limits.issues, "blob", hash);
                continue;
            }
        };
        if metadata.len() > limits.hash_bytes.saturating_sub(bytes_hashed) {
            hash_budget_exhausted = true;
            continue;
        }
        let (actual, read) = hash_file(&path)?;
        bytes_hashed = bytes_hashed.saturating_add(read);
        if actual != *hash {
            corrupt_count += 1;
            push_ref(&mut corrupt_refs, limits.issues, "blob", hash);
        }
    }

    let mut orphan_refs = Vec::new();
    let mut orphan_count = 0usize;
    let mut ignored_count = 0usize;
    let stored = stored_blob_names(&state.data_dir(), limits.scan, &mut ignored_count)?;
    for hash in &stored {
        if !state.storage.content_hash_is_referenced(hash)? {
            orphan_count += 1;
            push_ref(&mut orphan_refs, limits.issues, "blob", hash);
        }
    }
    let issue_count = missing_count + orphan_count + corrupt_count;
    Ok(Json(DebugStorageIntegrityResponse {
        service: "shellx-drive",
        read_only: true,
        referenced_total,
        referenced_scanned: referenced.len(),
        stored_scanned: stored.len(),
        bytes_hashed,
        missing_count,
        orphan_count,
        corrupt_count,
        ignored_count,
        scan_truncated: referenced_total > referenced.len() as i64 || stored.len() == limits.scan,
        hash_budget_exhausted,
        issues_truncated: issue_count > limits.issues,
        missing_refs,
        orphan_refs,
        corrupt_refs,
        limits,
    }))
}

fn checked_limits(query: IntegrityQuery) -> ApiResult<IntegrityLimits> {
    let scan = query.scan_limit.unwrap_or(DEFAULT_SCAN_LIMIT);
    let hash_bytes = query.hash_bytes.unwrap_or(DEFAULT_HASH_BYTES);
    let issues = query.issue_limit.unwrap_or(DEFAULT_ISSUE_LIMIT);
    if !(1..=MAX_SCAN_LIMIT).contains(&scan)
        || !(1..=MAX_HASH_BYTES).contains(&hash_bytes)
        || !(1..=MAX_ISSUE_LIMIT).contains(&issues)
    {
        return Err(ApiError::Validation(
            "integrity limits are outside their supported bounds".to_string(),
        ));
    }
    Ok(IntegrityLimits {
        scan,
        hash_bytes,
        issues,
    })
}

fn stored_blob_names(root: &Path, limit: usize, ignored: &mut usize) -> IoResult<Vec<String>> {
    let mut names = Vec::new();
    let shards = match fs::read_dir(root.join("blobs")) {
        Ok(rows) => rows,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(names),
        Err(error) => return Err(error),
    };
    'outer: for shard in shards {
        let shard = shard?;
        if !shard.file_type()?.is_dir() {
            *ignored += 1;
            continue;
        }
        for entry in fs::read_dir(shard.path())? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !entry.file_type()?.is_file()
                || name.len() != 64
                || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                *ignored += 1;
                continue;
            }
            names.push(name);
            if names.len() == limit {
                break 'outer;
            }
        }
    }
    Ok(names)
}

fn hash_file(path: &Path) -> IoResult<(String, u64)> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes.saturating_add(read as u64);
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn push_ref(target: &mut Vec<String>, limit: usize, prefix: &str, value: &str) {
    if target.len() < limit {
        target.push(format!("{prefix}-{}", &token_hash(value)[..12]));
    }
}
