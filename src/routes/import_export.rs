use std::{collections::HashMap, time::Duration};

mod tracking;

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use crate::{
    auth::{require_drive_actor_with_credential, Actor, DriveCredential, WorkspacePermission},
    blob,
    error::{ApiError, ApiResult},
    model::{
        DriveFile, FileKind, RcloneBundle, RcloneEntry, RcloneImportPreviewAction,
        RcloneImportPreviewResponse, RcloneImportResponse, RcloneImportSummary,
    },
    routes::{
        blob_publication::PendingBlobPublications,
        blob_response::guard_bounded_bytes_response_with_total_deadline,
        content_revalidation::AuthenticatedWorkspacePublication,
    },
    server::AppState,
    storage::{PreparedRcloneContent, PreparedRcloneEntry},
};

/// rclone-v1 serializes whole text bodies into one JSON response. Keep the
/// compatibility endpoint deliberately small; native download APIs stream the
/// real file path for all larger exports.
const RCLONE_V1_MAX_RAW_BODY_BYTES: u64 = 8 * 1024 * 1024;
const RCLONE_V1_MAX_EXPORT_PATH_BYTES: usize = 4 * 1024 * 1024;
const RCLONE_V1_MAX_SERIALIZED_BYTES: usize = 16 * 1024 * 1024;
const RCLONE_V1_MAX_IMPORT_ENTRIES: usize = 1_000;
const RCLONE_V1_MAX_IMPORT_METADATA_BYTES: usize = 8 * 1024 * 1024;
const RCLONE_V1_MAX_PATH_BYTES: usize = 1_024;
const RCLONE_V1_MAX_COMPONENT_BYTES: usize = 255;
const RCLONE_V1_EXPORT_REQUESTS_PER_MINUTE: i64 = 60;
const RCLONE_V1_NATIVE_STREAMED_API_GUIDANCE: &str =
    "use native streamed file APIs for binary or larger exports";

struct BuiltRcloneExport {
    bundle: RcloneBundle,
    statistics_targets: Vec<(String, String)>,
    publication: AuthenticatedWorkspacePublication,
}

struct BuiltRcloneImportPreview {
    summary: RcloneImportSummary,
    actions: Vec<RcloneImportPreviewAction>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/workspaces/{workspace_id}/export/rclone",
            get(export_rclone),
        )
        .route(
            "/workspaces/{workspace_id}/import/rclone",
            post(import_rclone),
        )
        .route(
            "/workspaces/{workspace_id}/import/rclone/preview",
            post(preview_import_rclone),
        )
}

async fn import_rclone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(bundle): Json<RcloneBundle>,
) -> ApiResult<Json<RcloneImportResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Write)?;
    validate_rclone_import_apply(&bundle)?;

    let tracker =
        tracking::ImportRunTracker::start(&state, "rclone_apply", &actor.email, &workspace_id)?;
    let import_state = state.clone();
    state
        .run_detached_mutation(async move {
            let pending_publications = PendingBlobPublications::acquire(&import_state).await?;
            let worker_state = import_state.clone();
            let (pending_publications, result) = tokio::task::spawn_blocking(move || {
                let mut pending_publications = pending_publications;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    apply_import_rclone(
                        &mut pending_publications,
                        &worker_state,
                        &workspace_id,
                        &actor,
                        &source_credential,
                        bundle,
                    )
                }));
                (pending_publications, result)
            })
            .await
            .map_err(|_| ApiError::Maintenance("rclone import worker failed".to_string()))?;
            let result = match result {
                Ok(result) => result,
                Err(_) => Err(ApiError::Maintenance(
                    "rclone import worker panicked".to_string(),
                )),
            };
            match pending_publications.finish(result).await {
                Ok(response) => {
                    tracker.succeed(tracking::summary_totals(&response.summary))?;
                    Ok(Json(response))
                }
                Err(error) => {
                    tracker.fail(&error);
                    Err(error)
                }
            }
        })
        .await
}

fn apply_import_rclone(
    publications: &mut PendingBlobPublications,
    state: &AppState,
    workspace_id: &str,
    actor: &Actor,
    source_credential: &DriveCredential,
    bundle: RcloneBundle,
) -> ApiResult<RcloneImportResponse> {
    let folder_collision_policy = bundle.folder_collision_policy.unwrap_or_default();
    let mut prepared = Vec::with_capacity(bundle.entries.len());
    for entry in bundle.entries {
        let parts = validate_path(&entry.path)?;
        let content = if let Some(text) = entry.content {
            let bytes = i64::try_from(text.len()).map_err(|_| {
                ApiError::PayloadTooLarge(
                    "rclone import content length cannot be represented".to_string(),
                )
            })?;
            let hash = publications.put_bytes(text.as_bytes())?.hash;
            Some(PreparedRcloneContent { hash, text, bytes })
        } else {
            None
        };
        prepared.push(PreparedRcloneEntry {
            parts,
            kind: entry.kind,
            content,
        });
    }
    let result = state.storage.apply_rclone_import_atomic(
        workspace_id,
        actor,
        source_credential,
        prepared,
        folder_collision_policy,
    )?;
    Ok(RcloneImportResponse {
        imported: result.imported,
        summary: result.summary,
        actions: result.actions,
        receipt: result.receipt,
    })
}

async fn preview_import_rclone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(bundle): Json<RcloneBundle>,
) -> ApiResult<Json<RcloneImportPreviewResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Write)?;
    validate_rclone_import_apply(&bundle)?;
    let mut tracker =
        tracking::ImportRunTracker::start(&state, "rclone_preview", &actor.email, &workspace_id)?;
    let result = build_import_preview(&state, &workspace_id, &bundle);
    match result {
        Ok(BuiltRcloneImportPreview { summary, actions }) => {
            let completion = tracker.succeed_rclone_preview_authorized(
                &workspace_id,
                &actor,
                &source_credential,
                tracking::summary_totals(&summary),
            );
            let receipt = match completion {
                Ok(receipt) => receipt,
                Err(error) => {
                    tracker.fail(&error);
                    return Err(error);
                }
            };
            Ok(Json(RcloneImportPreviewResponse {
                dry_run: true,
                summary,
                actions,
                receipt,
            }))
        }
        Err(error) => {
            tracker.fail(&error);
            Err(error)
        }
    }
}

fn build_import_preview(
    state: &AppState,
    workspace_id: &str,
    bundle: &RcloneBundle,
) -> ApiResult<BuiltRcloneImportPreview> {
    let prepared = bundle
        .entries
        .iter()
        .map(|entry| {
            let content = entry
                .content
                .as_ref()
                .map(|text| {
                    Ok::<_, ApiError>(PreparedRcloneContent {
                        // The common planner validates the same content contract
                        // for preview and apply. Preview does not publish a blob,
                        // so a syntactically valid placeholder hash is sufficient.
                        hash: "0".repeat(64),
                        text: text.clone(),
                        bytes: i64::try_from(text.len()).map_err(|_| {
                            ApiError::PayloadTooLarge(
                                "rclone import content length cannot be represented".to_string(),
                            )
                        })?,
                    })
                })
                .transpose()?;
            Ok(PreparedRcloneEntry {
                parts: validate_path(&entry.path)?,
                kind: entry.kind.clone(),
                content,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let preview = state.storage.preview_rclone_import(
        workspace_id,
        prepared,
        bundle.folder_collision_policy.unwrap_or_default(),
    )?;
    Ok(BuiltRcloneImportPreview {
        summary: preview.summary,
        actions: preview.actions,
    })
}

async fn export_rclone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Response> {
    let admission_permit = state.try_rclone_export_admission()?;
    let worker_state = state.clone();
    let (result, admission_permit) = tokio::task::spawn_blocking(move || {
        let result = (|| {
            let (actor, source_credential) =
                require_drive_actor_with_credential(&worker_state, &headers)?;
            worker_state.storage.ensure_workspace_permission(
                &workspace_id,
                &actor,
                WorkspacePermission::Read,
            )?;
            worker_state
                .storage
                .consume_partitioned_fixed_window_rate_limit(
                    &actor.email,
                    "rclone_export",
                    "actor",
                    RCLONE_V1_EXPORT_REQUESTS_PER_MINUTE,
                    60,
                )?;
            let export_permit = worker_state.try_rclone_export(&actor.email)?;
            let body_permit = worker_state.try_authenticated_body_stream(&actor.email)?;
            let mut tracker = tracking::ImportRunTracker::start(
                &worker_state,
                "rclone_export",
                &actor.email,
                &workspace_id,
            )?;
            let encoded = (|| {
                let BuiltRcloneExport {
                    bundle,
                    statistics_targets,
                    publication,
                } = build_export_rclone(&worker_state, &workspace_id, &actor, &source_credential)?;
                let encoded = serde_json::to_vec(&bundle).map_err(|error| {
                    ApiError::Maintenance(format!("could not encode rclone export: {error}"))
                })?;
                if encoded.len() > RCLONE_V1_MAX_SERIALIZED_BYTES {
                    return Err(ApiError::PayloadTooLarge(format!(
                        "rclone v1 legacy export exceeds its {RCLONE_V1_MAX_SERIALIZED_BYTES}-byte response limit"
                    )));
                }
                tracker.succeed_rclone_export_authorized(
                    &publication,
                    tracking::bundle_totals(&bundle),
                    &statistics_targets,
                )?;
                Ok::<_, ApiError>(encoded)
            })();
            if let Err(error) = &encoded {
                tracker.fail(error);
            }
            Ok::<_, ApiError>((encoded?, export_permit, body_permit))
        })();
        // The admission permit stays with the worker if the request is
        // cancelled before construction finishes.
        (result, admission_permit)
    })
    .await
    .map_err(|_| ApiError::Maintenance("rclone export worker failed".to_string()))?;
    let (encoded, export_permit, body_permit) = result?;
    let mut response = axum::body::Body::empty().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&encoded.len().to_string())
            .map_err(|_| ApiError::Maintenance("invalid rclone response length".to_string()))?,
    );
    Ok(guard_bounded_bytes_response_with_total_deadline(
        response,
        encoded,
        (admission_permit, export_permit, body_permit),
        Duration::from_secs(10 * 60),
    ))
}

fn build_export_rclone(
    state: &AppState,
    workspace_id: &str,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<BuiltRcloneExport> {
    state.storage.workspace_storage_mode(workspace_id)?;
    let files = state
        .storage
        .list_active_files_for_rclone_v1_export(workspace_id)?;
    let publication = AuthenticatedWorkspacePublication::new(
        &state.storage,
        workspace_id,
        &files,
        actor,
        source_credential,
    )?;
    ensure_rclone_v1_metadata_body_budget(&files)?;
    let mut entries = Vec::new();
    let mut statistics_targets = Vec::new();
    let mut actual_raw_body_bytes = 0_u64;
    let mut projected_paths = crate::path_projection::project_file_paths(
        &files,
        None,
        RCLONE_V1_MAX_EXPORT_PATH_BYTES,
        "rclone v1 export",
    )?;
    let mut serialized_entry_bytes = 0usize;

    for file in &files {
        let path = projected_paths.remove(&file.id).ok_or_else(|| {
            rclone_v1_validation("path projection is incomplete for an active file")
        })?;
        let mut entry = RcloneEntry {
            path,
            kind: file.kind.clone(),
            mime_type: Some(mime_type_for(file).to_string()),
            content: None,
            size: None,
        };
        if matches!(file.kind, FileKind::File) {
            if let Some(hash) = &file.content_hash {
                let declared_bytes = rclone_v1_declared_body_bytes(file)?;
                let remaining_bytes = RCLONE_V1_MAX_RAW_BODY_BYTES
                    .checked_sub(actual_raw_body_bytes)
                    .ok_or_else(|| {
                        rclone_v1_validation(
                            "physical bodies exceeded the 8 MiB aggregate raw-body maximum",
                        )
                    })?;
                let bytes = blob::get_blob_limited(&state.data_dir(), hash, remaining_bytes)?
                    .ok_or_else(|| {
                        rclone_v1_validation(format!(
                            "a physical blob exceeds the remaining {remaining_bytes}-byte raw-body budget or differs from its metadata"
                        ))
                    })?;
                let actual_bytes = u64::try_from(bytes.len()).map_err(|_| {
                    rclone_v1_validation("a physical blob length cannot be represented safely")
                })?;
                if actual_bytes != declared_bytes {
                    return Err(rclone_v1_validation(format!(
                        "physical blob size ({actual_bytes} bytes) does not match its {declared_bytes}-byte metadata"
                    )));
                }
                actual_raw_body_bytes = actual_raw_body_bytes
                    .checked_add(actual_bytes)
                    .ok_or_else(|| {
                        rclone_v1_validation(
                            "physical bodies overflowed the aggregate raw-body counter",
                        )
                    })?;
                entry.size = Some(bytes.len());
                entry.content = Some(String::from_utf8(bytes).map_err(|_| {
                    rclone_v1_validation("exports UTF-8 text only; binary file bodies are refused")
                })?);
                statistics_targets.push((file.id.clone(), file.workspace_id.clone()));
            }
        }
        serialized_entry_bytes = serialized_entry_bytes
            .checked_add(
                serde_json::to_vec(&entry)
                    .map_err(|_| rclone_v1_validation("could not size serialized entry"))?
                    .len(),
            )
            .ok_or_else(|| rclone_v1_validation("serialized metadata size overflow"))?;
        if serialized_entry_bytes > RCLONE_V1_MAX_SERIALIZED_BYTES {
            return Err(rclone_v1_validation(format!(
                "serialized entries exceed the {RCLONE_V1_MAX_SERIALIZED_BYTES}-byte response limit"
            )));
        }
        entries.push(entry);
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(BuiltRcloneExport {
        bundle: RcloneBundle {
            format: "shellx-rclone-v1".to_string(),
            workspace_id: Some(workspace_id.to_string()),
            entries,
            folder_collision_policy: None,
        },
        statistics_targets,
        publication,
    })
}

/// Validate the aggregate byte contract strictly from SQLite metadata before
/// the exporter opens a single blob body. Physical reads repeat the remaining
/// cap below because old/corrupt rows cannot be trusted as an allocation bound.
fn ensure_rclone_v1_metadata_body_budget(files: &[DriveFile]) -> ApiResult<()> {
    let mut declared_total = 0_u64;
    for file in files {
        if !matches!(file.kind, FileKind::File) {
            continue;
        }
        let declared_bytes = rclone_v1_declared_body_bytes(file)?;
        declared_total = declared_total.checked_add(declared_bytes).ok_or_else(|| {
            rclone_v1_validation("metadata body sizes overflow the aggregate raw-body counter")
        })?;
        if declared_total > RCLONE_V1_MAX_RAW_BODY_BYTES {
            return Err(rclone_v1_validation(format!(
                "metadata declares {declared_total} raw body bytes, exceeding the 8 MiB aggregate raw-body maximum"
            )));
        }
    }
    Ok(())
}

fn rclone_v1_declared_body_bytes(file: &DriveFile) -> ApiResult<u64> {
    let declared = file.size_bytes.ok_or_else(|| {
        rclone_v1_validation(format!(
            "file {} is missing its raw body size metadata",
            file.id
        ))
    })?;
    let declared = u64::try_from(declared).map_err(|_| {
        rclone_v1_validation(format!(
            "file {} has negative raw body size metadata",
            file.id
        ))
    })?;
    if file.content_hash.is_none() && declared != 0 {
        return Err(rclone_v1_validation(format!(
            "file {} declares {declared} body bytes without a blob",
            file.id
        )));
    }
    Ok(declared)
}

fn rclone_v1_validation(detail: impl std::fmt::Display) -> ApiError {
    ApiError::Validation(format!(
        "rclone v1 legacy export {detail}; {RCLONE_V1_NATIVE_STREAMED_API_GUIDANCE}"
    ))
}

fn validate_path(path: &str) -> ApiResult<Vec<String>> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed.len() > RCLONE_V1_MAX_PATH_BYTES
        || trimmed.starts_with('/')
        || trimmed.ends_with('/')
    {
        return Err(ApiError::Validation(format!(
            "path must be relative, non-empty, and at most {RCLONE_V1_MAX_PATH_BYTES} bytes"
        )));
    }
    let mut parts = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.len() > RCLONE_V1_MAX_COMPONENT_BYTES
        {
            return Err(ApiError::Validation(
                format!(
                    "path must not contain empty, dot, dot-dot, or over-{RCLONE_V1_MAX_COMPONENT_BYTES}-byte segments"
                ),
            ));
        }
        parts.push(crate::storage::validate_file_name(part)?);
        if parts.len() > crate::storage::MAX_FILE_TREE_DEPTH + 1 {
            return Err(ApiError::Validation(format!(
                "path exceeds the {}-level depth limit",
                crate::storage::MAX_FILE_TREE_DEPTH
            )));
        }
    }
    Ok(parts)
}

fn enforce_rclone_import_budget(bundle: &RcloneBundle) -> ApiResult<()> {
    if bundle.entries.len() > RCLONE_V1_MAX_IMPORT_ENTRIES {
        return Err(ApiError::PayloadTooLarge(format!(
            "rclone v1 import accepts at most {RCLONE_V1_MAX_IMPORT_ENTRIES} entries"
        )));
    }
    let mut metadata_bytes = bundle
        .format
        .len()
        .checked_add(bundle.workspace_id.as_deref().map(str::len).unwrap_or(0))
        .ok_or_else(|| ApiError::PayloadTooLarge("rclone import metadata overflow".to_string()))?;
    let mut content_bytes = 0usize;
    for entry in &bundle.entries {
        metadata_bytes = metadata_bytes
            .checked_add(entry.path.len())
            .and_then(|value| {
                value.checked_add(entry.mime_type.as_deref().map(str::len).unwrap_or(0))
            })
            .and_then(|value| value.checked_add(std::mem::size_of::<usize>()))
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("rclone import metadata overflow".to_string())
            })?;
        content_bytes = content_bytes
            .checked_add(entry.content.as_deref().map(str::len).unwrap_or(0))
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("rclone import content overflow".to_string())
            })?;
        if entry.size.is_some_and(|size| {
            u64::try_from(size).unwrap_or(u64::MAX) > RCLONE_V1_MAX_RAW_BODY_BYTES
        }) {
            return Err(ApiError::PayloadTooLarge(
                "rclone v1 entry size exceeds the 8 MiB legacy body limit".to_string(),
            ));
        }
        if metadata_bytes > RCLONE_V1_MAX_IMPORT_METADATA_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "rclone v1 import metadata exceeds {RCLONE_V1_MAX_IMPORT_METADATA_BYTES} bytes"
            )));
        }
        if u64::try_from(content_bytes).unwrap_or(u64::MAX) > RCLONE_V1_MAX_RAW_BODY_BYTES {
            return Err(ApiError::PayloadTooLarge(
                "rclone v1 import content exceeds the 8 MiB aggregate legacy body limit"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_rclone_import_apply(bundle: &RcloneBundle) -> ApiResult<()> {
    enforce_rclone_import_budget(bundle)?;
    let mut kinds = HashMap::<String, FileKind>::new();
    for entry in &bundle.entries {
        if matches!(entry.kind, FileKind::Folder) && entry.content.is_some() {
            return Err(ApiError::Validation(
                "rclone folders cannot contain file content".to_string(),
            ));
        }
        let parts = validate_path(&entry.path)?;
        let canonical_path = parts.join("/");
        if kinds.contains_key(&canonical_path) {
            return Err(ApiError::Validation(format!(
                "rclone import contains a duplicate path: {}",
                canonical_path
            )));
        }
        for depth in 0..parts.len().saturating_sub(1) {
            let prefix = parts[..=depth].join("/");
            if kinds
                .get(&prefix)
                .is_some_and(|kind| matches!(kind, FileKind::File))
            {
                return Err(ApiError::Validation(format!(
                    "rclone file path cannot contain descendants: {prefix}"
                )));
            }
        }
        if matches!(entry.kind, FileKind::File) {
            let descendant_prefix = format!("{canonical_path}/");
            if kinds
                .keys()
                .any(|path| path.starts_with(&descendant_prefix))
            {
                return Err(ApiError::Validation(format!(
                    "rclone file path cannot replace a planned folder: {}",
                    canonical_path
                )));
            }
        }
        kinds.insert(canonical_path, entry.kind.clone());
    }
    Ok(())
}

fn mime_type_for(file: &DriveFile) -> &'static str {
    match file.kind {
        FileKind::Folder => "application/vnd.google-apps.folder",
        FileKind::File => "text/plain",
    }
}
