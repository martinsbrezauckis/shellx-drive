use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(test)]
use std::fs;

#[cfg(test)]
use crate::blob;
#[cfg(test)]
use crate::model::BackupBlob;
use crate::{
    backup_v2,
    error::{ApiError, ApiResult},
    model::{BackupBundle, BackupMetadata, BackupTable},
    server::AppState,
};

#[cfg(test)]
use crate::fs_private;

use super::catalog::{backup_dir, validate_backup_id, CatalogMetadataBudget};

pub(super) const BACKUP_FORMAT: &str = "shellx-drive-backup-v1";
/// `BackupBundle` serializes its small metadata object before tables and blobs.
/// Listing backups must never read the potentially multi-gigabyte base64 body.
const BACKUP_METADATA_PREFIX_LIMIT: u64 = 256 * 1024;
/// V1 retains several simultaneous copies of the JSON/base64 body. Keep its
/// compatibility lane deliberately below the service memory envelope while V2
/// moves large generations to streamed raw entries.
const MAX_LEGACY_BUNDLE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_LEGACY_CONTENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEGACY_BLOBS: usize = 50_000;
const MAX_LEGACY_TABLES: usize = 64;
const MAX_LEGACY_ROWS: usize = 250_000;
const MAX_LEGACY_ISSUES: usize = 64;
const MAX_LEGACY_ISSUE_BYTES: usize = 512;

#[cfg(test)]
pub(super) fn list_legacy_backup_metadata(data_dir: &Path) -> ApiResult<Vec<BackupMetadata>> {
    let paths = super::catalog::bounded_backup_catalog_paths(data_dir)?;
    let mut budget = CatalogMetadataBudget::default();
    list_legacy_backup_metadata_from_paths(&paths, &mut budget, &HashSet::new())
}

pub(super) fn list_legacy_backup_metadata_from_paths(
    paths: &[PathBuf],
    budget: &mut CatalogMetadataBudget,
    blocked_backup_ids: &HashSet<String>,
) -> ApiResult<Vec<BackupMetadata>> {
    let mut backups = Vec::new();
    for path in paths {
        if path.extension().and_then(|extension| extension.to_str()) != Some("json")
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".meta.json"))
        {
            continue;
        }
        let file_backup_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"));
        if file_backup_id.is_some_and(|backup_id| blocked_backup_ids.contains(backup_id)) {
            continue;
        }
        budget.reserve(BACKUP_METADATA_PREFIX_LIMIT)?;
        let prefix = read_backup_metadata_prefix_bytes(path)?;
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<unknown>".to_string());
        if !is_legacy_backup_prefix(&prefix) {
            tracing::warn!(
                file_name = %file_name,
                "ignoring unrecognized JSON file in backup directory"
            );
            continue;
        }
        let metadata = parse_backup_metadata_prefix(&prefix).map_err(|error| {
            ApiError::Validation(format!(
                "invalid legacy backup metadata in {}: {error}",
                file_name
            ))
        })?;
        if blocked_backup_ids.contains(&metadata.backup_id) {
            continue;
        }
        backups.push(metadata);
    }
    Ok(backups)
}

/// Read only the bounded JSON header written before `tables` and `blobs` and
/// extract its top-level `metadata` object. Full bundle integrity remains the
/// responsibility of the explicit validate/restore paths; a metadata listing
/// must stay constant-memory regardless of retained blob bytes.
fn read_backup_metadata_prefix(path: &Path) -> ApiResult<BackupMetadata> {
    parse_backup_metadata_prefix(&read_backup_metadata_prefix_bytes(path)?)
}

fn read_backup_metadata_prefix_bytes(path: &Path) -> ApiResult<Vec<u8>> {
    let mut prefix = Vec::with_capacity(BACKUP_METADATA_PREFIX_LIMIT as usize);
    File::open(path)?
        .take(BACKUP_METADATA_PREFIX_LIMIT)
        .read_to_end(&mut prefix)?;
    Ok(prefix)
}

fn parse_backup_metadata_prefix(prefix: &[u8]) -> ApiResult<BackupMetadata> {
    let metadata = top_level_object_for_key(prefix, b"metadata").ok_or_else(|| {
        ApiError::Validation(format!(
            "backup metadata is missing from the first {} bytes",
            BACKUP_METADATA_PREFIX_LIMIT
        ))
    })?;
    serde_json::from_slice(metadata)
        .map_err(|error| ApiError::Validation(format!("invalid backup metadata: {error}")))
}

/// A legacy backup is positively identified by the top-level format tag that
/// every v1 bundle writes before its metadata. JSON files without that marker
/// are unrelated directory debris and must not poison the backup catalog.
fn is_legacy_backup_prefix(prefix: &[u8]) -> bool {
    top_level_string_for_key(prefix, b"format") == Some(BACKUP_FORMAT.as_bytes())
}

pub(super) fn read_backup_metadata_for_id(
    data_dir: &Path,
    backup_id: &str,
) -> ApiResult<BackupMetadata> {
    let path = backup_path(data_dir, backup_id)?;
    if !path.exists() {
        return Err(ApiError::NotFound);
    }
    let metadata = read_backup_metadata_prefix(&path)?;
    if metadata.backup_id != backup_id {
        return Err(ApiError::Validation(
            "backup metadata id does not match requested backup".to_string(),
        ));
    }
    Ok(metadata)
}

/// Return the byte slice for an object-valued key directly inside the root JSON
/// object. Strings and escapes are skipped so braces or key-like text inside a
/// JSON string cannot affect the boundary calculation.
fn top_level_object_for_key<'a>(input: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    let mut index = 0;
    let mut container_depth = 0usize;
    while index < input.len() {
        match input[index] {
            b'{' | b'[' => {
                container_depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                container_depth = container_depth.checked_sub(1)?;
                index += 1;
            }
            b'"' => {
                let end = json_string_end(input, index)?;
                if container_depth == 1 && &input[index + 1..end] == wanted {
                    let mut value_start = end + 1;
                    while input.get(value_start).is_some_and(u8::is_ascii_whitespace) {
                        value_start += 1;
                    }
                    if input.get(value_start) != Some(&b':') {
                        index = end + 1;
                        continue;
                    }
                    value_start += 1;
                    while input.get(value_start).is_some_and(u8::is_ascii_whitespace) {
                        value_start += 1;
                    }
                    if input.get(value_start) != Some(&b'{') {
                        return None;
                    }
                    let value_end = json_object_end(input, value_start)?;
                    return Some(&input[value_start..value_end]);
                }
                index = end + 1;
            }
            _ => index += 1,
        }
    }
    None
}

fn top_level_string_for_key<'a>(input: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    let mut index = 0;
    let mut container_depth = 0usize;
    while index < input.len() {
        match input[index] {
            b'{' | b'[' => {
                container_depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                container_depth = container_depth.checked_sub(1)?;
                index += 1;
            }
            b'"' => {
                let end = json_string_end(input, index)?;
                if container_depth == 1 && &input[index + 1..end] == wanted {
                    let mut value_start = end + 1;
                    while input.get(value_start).is_some_and(u8::is_ascii_whitespace) {
                        value_start += 1;
                    }
                    if input.get(value_start) != Some(&b':') {
                        index = end + 1;
                        continue;
                    }
                    value_start += 1;
                    while input.get(value_start).is_some_and(u8::is_ascii_whitespace) {
                        value_start += 1;
                    }
                    if input.get(value_start) != Some(&b'"') {
                        return None;
                    }
                    let value_end = json_string_end(input, value_start)?;
                    return Some(&input[value_start + 1..value_end]);
                }
                index = end + 1;
            }
            _ => index += 1,
        }
    }
    None
}

fn json_string_end(input: &[u8], start: usize) -> Option<usize> {
    let mut escaped = false;
    for (index, byte) in input.iter().enumerate().skip(start + 1) {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            return Some(index);
        }
    }
    None
}

fn json_object_end(input: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    let mut depth = 0usize;
    while index < input.len() {
        match input[index] {
            b'"' => index = json_string_end(input, index)? + 1,
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth = depth.checked_sub(1)?;
                index += 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => index += 1,
        }
    }
    None
}

fn top_level_array_for_key<'a>(input: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    object_value_for_key(input, wanted).filter(|value| value.first() == Some(&b'['))
}

fn object_array_for_key<'a>(input: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    top_level_array_for_key(input, wanted)
}

fn object_string_for_key<'a>(input: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    let value = object_value_for_key(input, wanted)?;
    if value.first() != Some(&b'"') {
        return None;
    }
    let end = json_string_end(value, 0)?;
    Some(&value[1..end])
}

fn object_value_for_key<'a>(input: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    let mut index = 0usize;
    let mut depth = 0usize;
    while index < input.len() {
        match input[index] {
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                index += 1;
            }
            b'"' => {
                let end = json_string_end(input, index)?;
                if depth == 1 && &input[index + 1..end] == wanted {
                    let mut value_start = end + 1;
                    while input.get(value_start).is_some_and(u8::is_ascii_whitespace) {
                        value_start += 1;
                    }
                    if input.get(value_start) != Some(&b':') {
                        index = end + 1;
                        continue;
                    }
                    value_start += 1;
                    while input.get(value_start).is_some_and(u8::is_ascii_whitespace) {
                        value_start += 1;
                    }
                    let value_end = json_value_end(input, value_start)?;
                    return Some(&input[value_start..value_end]);
                }
                index = end + 1;
            }
            _ => index += 1,
        }
    }
    None
}

fn json_value_end(input: &[u8], start: usize) -> Option<usize> {
    match *input.get(start)? {
        b'"' => json_string_end(input, start).map(|end| end + 1),
        b'{' | b'[' => {
            let mut index = start;
            let mut depth = 0usize;
            while index < input.len() {
                match input[index] {
                    b'"' => index = json_string_end(input, index)? + 1,
                    b'{' | b'[' => {
                        depth += 1;
                        index += 1;
                    }
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        index += 1;
                        if depth == 0 {
                            return Some(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            None
        }
        _ => {
            let mut index = start;
            while let Some(byte) = input.get(index) {
                if matches!(*byte, b',' | b'}' | b']') || byte.is_ascii_whitespace() {
                    break;
                }
                index += 1;
            }
            (index > start).then_some(index)
        }
    }
}

fn json_array_items_bounded<'a>(
    input: &'a [u8],
    max_items: usize,
    label: &str,
) -> ApiResult<Vec<&'a [u8]>> {
    let mut items = Vec::new();
    visit_json_array_items(input, max_items, label, |item| items.push(item))?;
    Ok(items)
}

fn json_array_item_count_bounded(input: &[u8], max_items: usize, label: &str) -> ApiResult<usize> {
    let mut count = 0usize;
    visit_json_array_items(input, max_items, label, |_| count += 1)?;
    Ok(count)
}

fn visit_json_array_items<'a>(
    input: &'a [u8],
    max_items: usize,
    label: &str,
    mut visit: impl FnMut(&'a [u8]),
) -> ApiResult<()> {
    if input.first() != Some(&b'[') {
        return Err(ApiError::Validation(format!(
            "legacy backup {label} must be a JSON array"
        )));
    }
    let mut index = 1usize;
    let mut count = 0usize;
    loop {
        while input.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if input.get(index) == Some(&b']') {
            return Ok(());
        }
        let end = json_value_end(input, index).ok_or_else(|| {
            ApiError::Validation(format!("legacy backup {label} contains invalid JSON"))
        })?;
        count = count.checked_add(1).ok_or_else(|| {
            ApiError::PayloadTooLarge(format!("legacy backup {label} count overflow"))
        })?;
        if count > max_items {
            return Err(ApiError::PayloadTooLarge(format!(
                "legacy backup has more than {max_items} {label}"
            )));
        }
        visit(&input[index..end]);
        index = end;
        while input.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        match input.get(index) {
            Some(b',') => index += 1,
            Some(b']') => return Ok(()),
            _ => {
                return Err(ApiError::Validation(format!(
                    "legacy backup {label} contains invalid JSON"
                )))
            }
        }
    }
}

pub(super) fn read_backup_bundle(data_dir: &Path, backup_id: &str) -> ApiResult<BackupBundle> {
    let path = backup_path(data_dir, backup_id)?;
    if !path.exists() {
        return Err(ApiError::NotFound);
    }
    let encoded = read_file_bounded(&path, MAX_LEGACY_BUNDLE_BYTES, "legacy backup bundle")?;
    preflight_legacy_bundle(&encoded)?;
    let bundle: BackupBundle = serde_json::from_slice(&encoded)
        .map_err(|error| ApiError::Validation(format!("invalid backup bundle: {error}")))?;
    if bundle.format != BACKUP_FORMAT {
        return Err(ApiError::Validation(format!(
            "unsupported backup format: {}",
            bundle.format
        )));
    }
    if bundle.backup_id != backup_id {
        return Err(ApiError::Validation(
            "backup id does not match requested backup".to_string(),
        ));
    }
    Ok(bundle)
}

/// Inspect attacker-controlled collection sizes before Serde allocates the
/// legacy object graph. V1 is a compatibility format, so its compact JSON must
/// stay inside a much smaller in-memory envelope than streamed V2 archives.
fn preflight_legacy_bundle(encoded: &[u8]) -> ApiResult<()> {
    let tables = top_level_array_for_key(encoded, b"tables").ok_or_else(|| {
        ApiError::Validation("legacy backup tables must be a JSON array".to_string())
    })?;
    let table_items = json_array_items_bounded(tables, MAX_LEGACY_TABLES, "tables")?;
    let mut total_rows = 0usize;
    for table in table_items {
        let rows = object_array_for_key(table, b"rows").ok_or_else(|| {
            ApiError::Validation("legacy backup table rows must be a JSON array".to_string())
        })?;
        let remaining = MAX_LEGACY_ROWS.saturating_sub(total_rows);
        let rows = json_array_item_count_bounded(rows, remaining, "rows")?;
        total_rows = total_rows.checked_add(rows).ok_or_else(|| {
            ApiError::PayloadTooLarge("legacy backup row count overflow".to_string())
        })?;
    }

    let blobs = top_level_array_for_key(encoded, b"blobs").ok_or_else(|| {
        ApiError::Validation("legacy backup blobs must be a JSON array".to_string())
    })?;
    let blob_items = json_array_items_bounded(blobs, MAX_LEGACY_BLOBS, "blobs")?;
    let max_encoded_bytes = MAX_LEGACY_CONTENT_BYTES
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(4)
        .saturating_add(4);
    let mut encoded_body_bytes = 0u64;
    for blob in blob_items {
        let body = object_string_for_key(blob, b"base64").ok_or_else(|| {
            ApiError::Validation("legacy backup blob base64 must be a string".to_string())
        })?;
        encoded_body_bytes = encoded_body_bytes
            .checked_add(body.len() as u64)
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("legacy backup encoded content overflow".to_string())
            })?;
        if encoded_body_bytes > max_encoded_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "legacy backup encoded content exceeds the {MAX_LEGACY_CONTENT_BYTES}-byte decoded limit"
            )));
        }
    }
    Ok(())
}

fn read_file_bounded(path: &Path, max_bytes: u64, label: &str) -> ApiResult<Vec<u8>> {
    let mut file = File::open(path)?;
    let declared = file.metadata()?.len();
    if declared > max_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "{label} is {declared} bytes; v1 limit is {max_bytes} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(declared as usize);
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "{label} grew beyond the v1 limit of {max_bytes} bytes while being read"
        )));
    }
    Ok(bytes)
}

pub(super) fn backup_validation_issues(state: &AppState, bundle: &BackupBundle) -> Vec<String> {
    validate_backup_bundle_once(state, bundle).issues
}

struct LegacyValidation {
    issues: Vec<String>,
    decoded_blobs: Vec<(String, Vec<u8>)>,
}

fn validate_backup_bundle_once(state: &AppState, bundle: &BackupBundle) -> LegacyValidation {
    let mut issues = Vec::new();
    if let Err(error) = state.storage.validate_backup_tables(&bundle.tables) {
        push_legacy_issue(&mut issues, error.to_string());
    }
    for table in &bundle.tables {
        for (column_index, column) in table.columns.iter().enumerate() {
            if column != "content_hash" && column != "thumbnail_hash" && column != "cover_hash" {
                continue;
            }
            for row in &table.rows {
                match row.get(column_index) {
                    Some(serde_json::Value::Null) => {}
                    Some(serde_json::Value::String(hash)) if is_valid_blob_hash(hash) => {}
                    Some(_) => push_legacy_issue(
                        &mut issues,
                        format!(
                            "backup table {} contains an invalid {}",
                            bounded_legacy_label(&table.name),
                            bounded_legacy_label(column)
                        ),
                    ),
                    None => {}
                }
            }
        }
    }

    let mut blob_hashes = HashSet::new();
    let mut decoded_blobs = Vec::with_capacity(bundle.blobs.len());
    let mut content_bytes = 0u64;
    for backup_blob in &bundle.blobs {
        if !is_valid_blob_hash(&backup_blob.hash) {
            push_legacy_issue(
                &mut issues,
                format!(
                    "blob {} is not a valid content hash",
                    bounded_legacy_label(&backup_blob.hash)
                ),
            );
        }
        if !blob_hashes.insert(backup_blob.hash.clone()) {
            push_legacy_issue(
                &mut issues,
                format!(
                    "blob {} appears more than once",
                    bounded_legacy_label(&backup_blob.hash)
                ),
            );
        }
        let Ok(bytes) = base64_decode(&backup_blob.base64) else {
            push_legacy_issue(
                &mut issues,
                format!(
                    "blob {} is not valid base64",
                    bounded_legacy_label(&backup_blob.hash)
                ),
            );
            continue;
        };
        let Some(next_content_bytes) = content_bytes.checked_add(bytes.len() as u64) else {
            push_legacy_issue(
                &mut issues,
                "legacy backup content size overflow".to_string(),
            );
            break;
        };
        if next_content_bytes > MAX_LEGACY_CONTENT_BYTES {
            push_legacy_issue(
                &mut issues,
                format!("legacy backup decoded content exceeds {MAX_LEGACY_CONTENT_BYTES} bytes"),
            );
            break;
        }
        content_bytes = next_content_bytes;
        if sha256_hex(&bytes) != backup_blob.hash {
            push_legacy_issue(
                &mut issues,
                format!(
                    "blob {} content hash does not match bytes",
                    bounded_legacy_label(&backup_blob.hash)
                ),
            );
        }
        decoded_blobs.push((backup_blob.hash.clone(), bytes));
    }

    let referenced_hashes = referenced_content_hashes(&bundle.tables);
    for hash in referenced_hashes.difference(&blob_hashes) {
        push_legacy_issue(
            &mut issues,
            format!(
                "backup referenced blob {} is missing",
                bounded_legacy_label(hash)
            ),
        );
    }
    for hash in blob_hashes.difference(&referenced_hashes) {
        push_legacy_issue(
            &mut issues,
            format!(
                "backup contains unreferenced blob {}",
                bounded_legacy_label(hash)
            ),
        );
    }

    let expected = backup_metadata_from_totals(
        &bundle.backup_id,
        &bundle.created_at,
        &bundle.tables,
        bundle.blobs.len() as u64,
        content_bytes,
    );
    if expected != bundle.metadata {
        push_legacy_issue(
            &mut issues,
            "metadata does not match bundle tables or blobs".to_string(),
        );
    }
    LegacyValidation {
        issues,
        decoded_blobs,
    }
}

pub(super) fn validated_backup_blobs(
    state: &AppState,
    bundle: &BackupBundle,
) -> ApiResult<Vec<(String, Vec<u8>)>> {
    let validation = validate_backup_bundle_once(state, bundle);
    if !validation.issues.is_empty() {
        return Err(ApiError::Validation(validation.issues.join("; ")));
    }
    Ok(validation.decoded_blobs)
}

pub(super) struct LegacyRestorePreparation {
    pub(super) bundle: BackupBundle,
    pub(super) blobs: Vec<(String, Vec<u8>)>,
    pub(super) verified_blobs: Vec<(String, u64)>,
}

/// Complete every hostile legacy bundle read, decode, and size calculation in
/// the backup worker before any blob publication or database replacement.
pub(super) fn prepare_legacy_restore(
    state: &AppState,
    data_dir: &Path,
    backup_id: &str,
) -> ApiResult<LegacyRestorePreparation> {
    let bundle = read_backup_bundle(data_dir, backup_id)?;
    let blobs = validated_backup_blobs(state, &bundle)?;
    let mut verified_blobs = blobs
        .iter()
        .map(|(hash, bytes)| (hash.clone(), bytes.len() as u64))
        .collect::<Vec<_>>();
    verified_blobs.sort_by(|left, right| left.0.cmp(&right.0));
    let table_bytes = serde_json::to_vec(&bundle.tables)
        .map_err(|error| {
            ApiError::Validation(format!("failed to size legacy restore tables: {error}"))
        })?
        .len() as u64;
    let blob_bytes = blobs.iter().try_fold(0_u64, |total, (_, bytes)| {
        total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| ApiError::PayloadTooLarge("legacy restore size overflow".to_string()))
    })?;
    backup_v2::ensure_restore_free_space(
        data_dir,
        table_bytes
            .checked_add(blob_bytes)
            .ok_or_else(|| ApiError::PayloadTooLarge("legacy restore size overflow".to_string()))?,
    )?;
    Ok(LegacyRestorePreparation {
        bundle,
        blobs,
        verified_blobs,
    })
}

fn backup_metadata_from_totals(
    backup_id: &str,
    created_at: &str,
    tables: &[BackupTable],
    blob_count: u64,
    content_bytes: u64,
) -> BackupMetadata {
    BackupMetadata {
        backup_id: backup_id.to_string(),
        format: BACKUP_FORMAT.to_string(),
        created_at: created_at.to_string(),
        table_count: tables.len() as u64,
        row_count: tables.iter().map(|table| table.rows.len() as u64).sum(),
        blob_count,
        content_bytes,
        archive_bytes: None,
        job_id: None,
        status: Some("succeeded".to_string()),
        phase: Some("complete".to_string()),
        last_error: None,
    }
}

fn push_legacy_issue(issues: &mut Vec<String>, issue: String) {
    if issues.len() >= MAX_LEGACY_ISSUES {
        return;
    }
    let mut bounded = issue;
    if bounded.len() > MAX_LEGACY_ISSUE_BYTES {
        let mut end = MAX_LEGACY_ISSUE_BYTES;
        while !bounded.is_char_boundary(end) {
            end -= 1;
        }
        bounded.truncate(end);
        bounded.push_str("...");
    }
    issues.push(bounded);
}

fn bounded_legacy_label(value: &str) -> String {
    value.chars().take(128).collect()
}

#[cfg(test)]
fn read_backup_blobs(
    data_dir: &Path,
    referenced_hashes: &HashSet<String>,
) -> ApiResult<Vec<BackupBlob>> {
    if referenced_hashes.is_empty() {
        return Ok(Vec::new());
    }
    if referenced_hashes.len() > MAX_LEGACY_BLOBS {
        return Err(ApiError::PayloadTooLarge(format!(
            "legacy backup has {} blobs; v1 limit is {MAX_LEGACY_BLOBS} blobs",
            referenced_hashes.len()
        )));
    }
    let mut hashes = referenced_hashes.iter().cloned().collect::<Vec<_>>();
    hashes.sort();
    let mut sources = Vec::with_capacity(hashes.len());
    let mut content_bytes = 0u64;
    for hash in hashes {
        let path = blob::blob_file_path(data_dir, &hash)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ApiError::Validation(format!(
                    "backup referenced blob {hash} is missing"
                )));
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() {
            return Err(ApiError::Validation(format!(
                "backup referenced blob {hash} is not a regular file"
            )));
        }
        content_bytes = content_bytes.checked_add(metadata.len()).ok_or_else(|| {
            ApiError::PayloadTooLarge("legacy backup content size overflow".to_string())
        })?;
        sources.push((hash, path, metadata.len()));
    }

    if content_bytes > MAX_LEGACY_CONTENT_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "legacy backup references {content_bytes} content bytes; v1 limit is {MAX_LEGACY_CONTENT_BYTES} bytes"
        )));
    }

    let mut blobs = Vec::with_capacity(sources.len());
    for (hash, path, declared_bytes) in sources {
        let bytes = read_file_bounded(&path, declared_bytes, "content-addressed blob")?;
        if sha256_hex(&bytes) != hash {
            return Err(ApiError::Validation(format!(
                "backup referenced blob {hash} does not match its content hash"
            )));
        }
        blobs.push(BackupBlob {
            hash,
            base64: base64_encode(&bytes),
        });
    }
    Ok(blobs)
}

fn referenced_content_hashes(tables: &[BackupTable]) -> HashSet<String> {
    let mut hashes = HashSet::new();
    for table in tables {
        for (column_index, column) in table.columns.iter().enumerate() {
            if column != "content_hash" && column != "thumbnail_hash" && column != "cover_hash" {
                continue;
            }
            for row in &table.rows {
                let Some(hash) = row.get(column_index).and_then(serde_json::Value::as_str) else {
                    continue;
                };
                if is_valid_blob_hash(hash) {
                    hashes.insert(hash.to_string());
                }
            }
        }
    }
    hashes
}

pub(super) fn backup_path(data_dir: &Path, backup_id: &str) -> ApiResult<PathBuf> {
    validate_backup_id(backup_id)?;
    Ok(backup_dir(data_dir).join(format!("{backup_id}.json")))
}

#[cfg(test)]
fn backup_partial_path(data_dir: &Path, backup_id: &str) -> ApiResult<PathBuf> {
    backup_path(data_dir, backup_id).map(|path| path.with_extension("json.partial"))
}

#[cfg(test)]
fn write_backup_bundle_atomic(data_dir: &Path, backup_id: &str, encoded: &[u8]) -> ApiResult<()> {
    let dir = backup_dir(data_dir);
    fs_private::create_dir_all_private(&dir)?;
    let path = backup_path(data_dir, backup_id)?;
    let partial = backup_partial_path(data_dir, backup_id)?;
    if let Err(error) = fs_private::write_file_private(&partial, encoded) {
        let _ = fs::remove_file(&partial);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&partial, &path) {
        let _ = fs::remove_file(&partial);
        return Err(error.into());
    }
    if let Err(error) = sync_directory(&dir) {
        let _ = fs::remove_file(&path);
        let _ = sync_directory(&dir);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(all(test, unix))]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(all(test, not(unix)))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
fn base64_encode(value: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(value)
}

fn base64_decode(value: &str) -> ApiResult<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD
        .decode(value)
        .map_err(|error| ApiError::Validation(format!("invalid backup blob: {error}")))
}

fn is_valid_blob_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn legacy_metadata(backup_id: &str) -> BackupMetadata {
        BackupMetadata {
            backup_id: backup_id.to_string(),
            format: BACKUP_FORMAT.to_string(),
            created_at: "2026-07-16T00:00:00Z".to_string(),
            table_count: 0,
            row_count: 0,
            blob_count: 0,
            content_bytes: 0,
            archive_bytes: None,
            job_id: None,
            status: Some("succeeded".to_string()),
            phase: Some("complete".to_string()),
            last_error: None,
        }
    }

    #[test]
    fn metadata_listing_skips_unrecognized_json_files() {
        let data_dir = tempfile::tempdir().unwrap();
        let backups = backup_dir(data_dir.path());
        fs::create_dir(&backups).unwrap();
        let metadata = legacy_metadata("known-backup");
        let bundle = BackupBundle {
            format: BACKUP_FORMAT.to_string(),
            backup_id: metadata.backup_id.clone(),
            created_at: metadata.created_at.clone(),
            metadata: metadata.clone(),
            tables: Vec::new(),
            blobs: Vec::new(),
        };
        fs::write(
            backups.join("known-backup.json"),
            serde_json::to_vec(&bundle).unwrap(),
        )
        .unwrap();
        fs::write(
            backups.join("inventory.json"),
            br#"{"note":"not a Drive backup"}"#,
        )
        .unwrap();

        assert_eq!(
            list_legacy_backup_metadata(data_dir.path()).unwrap(),
            [metadata]
        );
    }

    #[test]
    fn metadata_listing_reports_recognizable_corrupt_backup() {
        let data_dir = tempfile::tempdir().unwrap();
        let backups = backup_dir(data_dir.path());
        fs::create_dir(&backups).unwrap();
        fs::write(
            backups.join("corrupt-backup.json"),
            format!(r#"{{"format":"{BACKUP_FORMAT}","backup_id":"corrupt-backup","metadata":{{"#),
        )
        .unwrap();

        let error = list_legacy_backup_metadata(data_dir.path()).unwrap_err();
        assert!(matches!(
            error,
            ApiError::Validation(message)
                if message.contains("corrupt-backup.json")
                    && message.contains("backup metadata is missing")
        ));
    }

    #[test]
    fn metadata_listing_does_not_parse_the_backup_blob_body() {
        let data_dir = tempfile::tempdir().unwrap();
        let backups = data_dir.path().join("backups");
        fs::create_dir(&backups).unwrap();
        let metadata = BackupMetadata {
            backup_id: "bounded-listing".to_string(),
            format: BACKUP_FORMAT.to_string(),
            created_at: "2026-07-16T00:00:00Z".to_string(),
            table_count: 39,
            row_count: 900,
            blob_count: 97,
            content_bytes: 5_000_000_000,
            archive_bytes: None,
            job_id: None,
            status: Some("succeeded".to_string()),
            phase: Some("complete".to_string()),
            last_error: None,
        };
        let mut file = File::create(backups.join("bounded-listing.json")).unwrap();
        write!(
            file,
            "{{\n  \"format\": \"{BACKUP_FORMAT}\",\n  \"backup_id\": \"bounded-listing\",\n  \"created_at\": \"2026-07-16T00:00:00Z\",\n  \"metadata\": {},\n  \"tables\": [],\n  \"blobs\": [{{\"base64\": \"",
            serde_json::to_string(&metadata).unwrap()
        )
        .unwrap();
        file.set_len(32 * 1024 * 1024).unwrap();

        assert_eq!(
            list_legacy_backup_metadata(data_dir.path()).unwrap(),
            [metadata]
        );
    }

    #[test]
    fn oversized_legacy_bundle_is_rejected_from_file_metadata() {
        let data_dir = tempfile::tempdir().unwrap();
        let backups = data_dir.path().join("backups");
        fs::create_dir(&backups).unwrap();
        let path = backups.join("oversized.json");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_LEGACY_BUNDLE_BYTES + 1).unwrap();

        let error = read_backup_bundle(data_dir.path(), "oversized").unwrap_err();
        assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    }

    #[test]
    fn legacy_collection_preflight_rejects_counts_before_typed_materialization() {
        let error = json_array_item_count_bounded(b"[{},{}]", 1, "rows").unwrap_err();
        assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    }

    #[test]
    fn oversized_referenced_blob_is_rejected_before_body_read() {
        let data_dir = tempfile::tempdir().unwrap();
        let hash = "a".repeat(64);
        let path = blob::blob_file_path(data_dir.path(), &hash).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = File::create(path).unwrap();
        file.set_len(MAX_LEGACY_CONTENT_BYTES + 1).unwrap();
        let hashes = HashSet::from([hash]);

        let error = read_backup_blobs(data_dir.path(), &hashes).unwrap_err();
        assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    }

    #[test]
    fn partial_generation_is_not_listed_and_atomic_publish_removes_staging_name() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_id = "atomic-generation";
        let metadata = BackupMetadata {
            backup_id: backup_id.to_string(),
            format: BACKUP_FORMAT.to_string(),
            created_at: "2026-07-16T00:00:00Z".to_string(),
            table_count: 0,
            row_count: 0,
            blob_count: 0,
            content_bytes: 0,
            archive_bytes: None,
            job_id: None,
            status: Some("succeeded".to_string()),
            phase: Some("complete".to_string()),
            last_error: None,
        };
        let bundle = BackupBundle {
            format: BACKUP_FORMAT.to_string(),
            backup_id: backup_id.to_string(),
            created_at: metadata.created_at.clone(),
            metadata: metadata.clone(),
            tables: Vec::new(),
            blobs: Vec::new(),
        };
        let encoded = serde_json::to_vec_pretty(&bundle).unwrap();
        let backups = backup_dir(data_dir.path());
        fs::create_dir(&backups).unwrap();
        fs::write(backups.join("orphan.json.partial"), &encoded).unwrap();

        assert!(list_legacy_backup_metadata(data_dir.path())
            .unwrap()
            .is_empty());
        write_backup_bundle_atomic(data_dir.path(), backup_id, &encoded).unwrap();
        assert_eq!(
            list_legacy_backup_metadata(data_dir.path()).unwrap(),
            [metadata]
        );
        assert!(!backup_partial_path(data_dir.path(), backup_id)
            .unwrap()
            .exists());
    }
}
