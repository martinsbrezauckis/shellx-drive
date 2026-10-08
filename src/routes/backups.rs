mod catalog;
mod download;
mod legacy;
mod worker;

use std::{collections::HashSet, fs};

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::routes::blob_publication::PendingBlobPublications;
use crate::{
    auth::{require_admin, require_admin_with_credential},
    error::{ApiError, ApiResult},
    model::{
        BackupJobResponse, BackupListResponse, BackupMetadata, BackupMutationResponse,
        BackupPolicyMutationResponse, BackupPolicyResponse, BackupValidationResponse,
        UpdateBackupPolicyRequest,
    },
    server::AppState,
    storage::ManagedBackupGeneration,
};

use catalog::{
    backup_dir, bounded_backup_catalog_paths, list_v2_backup_metadata_from_paths,
    read_v2_backup_metadata_for_state, v2_backup_path, v2_sidecar_path,
};
use legacy::{
    backup_path, backup_validation_issues, list_legacy_backup_metadata_from_paths,
    prepare_legacy_restore, read_backup_metadata_for_id,
};

pub use worker::{recover_backup_state, spawn_backup_worker};

const MAX_BACKUP_CATALOG_ENTRIES: usize = 10_000;

/// Decide the format lane from durable local provenance before inspecting a
/// directory controlled by backup media. An active managed ID must only use
/// its V2 generation; a retired ID has no readable/deletable fallback.
pub(super) fn select_backup_v2_lane(state: &AppState, backup_id: &str) -> ApiResult<bool> {
    let v2_path = v2_backup_path(&state.data_dir(), backup_id)?;
    match state.storage.managed_backup_generation(backup_id)? {
        ManagedBackupGeneration::Tombstoned => Err(ApiError::NotFound),
        ManagedBackupGeneration::Active { .. } if !v2_path.exists() => Err(ApiError::Validation(
            "managed backup v2 archive is missing".to_string(),
        )),
        ManagedBackupGeneration::Active { .. } => Ok(true),
        ManagedBackupGeneration::Unmanaged => Ok(v2_path.exists()),
    }
}

#[derive(Debug, Default, Deserialize)]
struct BackupListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct CreateBackupQuery {
    format: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/backups", get(list_backups).post(create_backup))
        .route("/admin/backup-jobs/{job_id}", get(get_backup_job))
        .route(
            "/admin/backup-policy",
            get(get_backup_policy).patch(update_backup_policy),
        )
        .route(
            "/admin/backups/{backup_id}/download",
            get(download::download_backup),
        )
        .route("/admin/backups/{backup_id}/validate", post(validate_backup))
        .route(
            "/admin/backups/{backup_id}",
            get(get_backup).delete(delete_backup),
        )
        .route("/admin/backups/{backup_id}/restore", post(restore_backup))
}

async fn list_backups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BackupListQuery>,
) -> ApiResult<Json<BackupListResponse>> {
    require_admin(&state, &headers)?;
    let catalog_state = state.clone();
    let mut backups = state
        .run_backup_work(move || list_backup_metadata(&catalog_state))
        .await??;
    let completed = backups
        .iter()
        .map(|backup| backup.backup_id.clone())
        .collect::<HashSet<_>>();
    for job in state.storage.list_backup_jobs()? {
        if job.kind != "create" || completed.contains(&job.backup_id) || job.status == "succeeded" {
            continue;
        }
        backups.push(BackupMetadata {
            backup_id: job.backup_id,
            format: job.format,
            created_at: job.created_at,
            table_count: 0,
            row_count: 0,
            blob_count: 0,
            content_bytes: 0,
            archive_bytes: None,
            job_id: Some(job.id),
            status: Some(job.status),
            phase: Some(job.phase),
            last_error: job.last_error,
        });
    }
    backups.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    if backups.len() > MAX_BACKUP_CATALOG_ENTRIES {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup catalog has more than {MAX_BACKUP_CATALOG_ENTRIES} entries"
        )));
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let start = match query.cursor {
        Some(cursor) => backups
            .iter()
            .position(|backup| backup.backup_id == cursor)
            .map(|index| index + 1)
            .ok_or_else(|| ApiError::Validation("invalid backup cursor".to_string()))?,
        None => 0,
    };
    let end = start.saturating_add(limit).min(backups.len());
    let next_cursor =
        (end < backups.len()).then(|| backups[end.saturating_sub(1)].backup_id.clone());
    Ok(Json(BackupListResponse {
        backups: backups[start..end].to_vec(),
        next_cursor,
    }))
}

async fn create_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CreateBackupQuery>,
) -> ApiResult<(StatusCode, Json<BackupJobResponse>)> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    if query.format.as_deref().is_some_and(|format| format != "v2") {
        return Err(ApiError::Validation(
            "v1 backup creation is disabled; use format=v2".to_string(),
        ));
    }
    let backup_id = uuid::Uuid::now_v7().to_string();
    let job = state.storage.enqueue_authorized_backup_job(
        "create",
        &backup_id,
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::ACCEPTED,
        Json(BackupJobResponse { job, backup: None }),
    ))
}

async fn get_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(backup_id): AxumPath<String>,
) -> ApiResult<Json<BackupJobResponse>> {
    require_admin(&state, &headers)?;
    if matches!(
        state.storage.managed_backup_generation(&backup_id)?,
        ManagedBackupGeneration::Tombstoned
    ) {
        return Err(ApiError::NotFound);
    }
    let job = state
        .storage
        .latest_backup_job(&backup_id)?
        .ok_or(ApiError::NotFound)?;
    let backup = read_v2_backup_metadata_for_state(&state, &backup_id).ok();
    if backup.is_none() && job.status == "succeeded" {
        return Err(ApiError::NotFound);
    }
    Ok(Json(BackupJobResponse { job, backup }))
}

async fn get_backup_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(job_id): AxumPath<String>,
) -> ApiResult<Json<BackupJobResponse>> {
    require_admin(&state, &headers)?;
    let job = state
        .storage
        .get_backup_job(&job_id)?
        .ok_or(ApiError::NotFound)?;
    if matches!(
        state.storage.managed_backup_generation(&job.backup_id)?,
        ManagedBackupGeneration::Tombstoned
    ) {
        return Err(ApiError::NotFound);
    }
    let backup = read_v2_backup_metadata_for_state(&state, &job.backup_id).ok();
    Ok(Json(BackupJobResponse { job, backup }))
}

async fn get_backup_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<BackupPolicyResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(BackupPolicyResponse {
        policy: state.storage.get_backup_policy()?,
    }))
}

async fn update_backup_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateBackupPolicyRequest>,
) -> ApiResult<Json<BackupPolicyMutationResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (policy, receipt) =
        state
            .storage
            .update_backup_policy_authorized(request, &actor, &source_credential)?;
    Ok(Json(BackupPolicyMutationResponse { policy, receipt }))
}

async fn validate_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(backup_id): AxumPath<String>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    if select_backup_v2_lane(&state, &backup_id)? {
        let job = state.storage.enqueue_authorized_backup_job(
            "validate",
            &backup_id,
            &actor,
            &source_credential,
        )?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(BackupJobResponse {
                job,
                backup: read_v2_backup_metadata_for_state(&state, &backup_id).ok(),
            }),
        )
            .into_response());
    }
    let validation_state = state.clone();
    let data_dir = state.data_dir();
    let (bundle, issues) = state
        .run_backup_work(move || -> ApiResult<_> {
            let bundle = legacy::read_backup_bundle(&data_dir, &backup_id)?;
            let issues = backup_validation_issues(&validation_state, &bundle);
            Ok((bundle, issues))
        })
        .await??;
    let receipt =
        state
            .storage
            .insert_receipt("backup.validate", &actor.email, Some(&bundle.backup_id))?;
    Ok(Json(BackupValidationResponse {
        valid: issues.is_empty(),
        backup: bundle.metadata,
        issues,
        receipt,
    })
    .into_response())
}

async fn delete_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(backup_id): AxumPath<String>,
) -> ApiResult<Json<BackupMutationResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let v2_path = v2_backup_path(&state.data_dir(), &backup_id)?;
    if select_backup_v2_lane(&state, &backup_id)? {
        let backup = read_v2_backup_metadata_for_state(&state, &backup_id)?;
        let sidecar_path = v2_sidecar_path(&state.data_dir(), &backup_id)?;
        let _intent =
            state
                .storage
                .create_backup_delete_intent(&backup_id, &actor, &source_credential)?;
        // Once the delete is authorized, make replay impossible before any
        // filesystem operation. A deletion I/O failure can leave bytes behind,
        // but they stay retired rather than silently becoming portable/V1.
        state
            .storage
            .retire_managed_backup_publication(&backup_id)?;
        if sidecar_path.exists() {
            let deleting = sidecar_path.with_extension("json.deleting");
            fs::rename(&sidecar_path, &deleting)?;
            if let Err(error) = fs::remove_file(&v2_path) {
                let _ = fs::rename(&deleting, &sidecar_path);
                return Err(error.into());
            }
            fs::remove_file(deleting)?;
        } else {
            fs::remove_file(&v2_path)?;
        }
        let receipt =
            state
                .storage
                .insert_receipt("backup.delete", &actor.email, Some(&backup_id))?;
        return Ok(Json(BackupMutationResponse { backup, receipt }));
    }
    let backup = read_backup_metadata_for_id(&state.data_dir(), &backup_id)?;
    let path = backup_path(&state.data_dir(), &backup_id)?;
    let _intent =
        state
            .storage
            .create_backup_delete_intent(&backup_id, &actor, &source_credential)?;
    fs::remove_file(path)?;
    let receipt = state
        .storage
        .insert_receipt("backup.delete", &actor.email, Some(&backup_id))?;
    Ok(Json(BackupMutationResponse { backup, receipt }))
}

async fn restore_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(backup_id): AxumPath<String>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    if select_backup_v2_lane(&state, &backup_id)? {
        let job = state
            .enqueue_backup_restore_job(&backup_id, &actor, &source_credential)
            .await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(BackupJobResponse {
                job,
                backup: read_v2_backup_metadata_for_state(&state, &backup_id).ok(),
            }),
        )
            .into_response());
    }
    let restore_id = format!("legacy-{backup_id}");
    state.begin_legacy_backup_restore(&restore_id).await?;
    let worker_state = state.clone();
    tokio::spawn(async move {
        run_legacy_restore(
            worker_state,
            restore_id,
            backup_id,
            actor,
            source_credential,
        )
        .await
    })
    .await
    .map_err(|_| ApiError::Maintenance("legacy restore coordinator failed".to_string()))?
}

async fn run_legacy_restore(
    state: AppState,
    restore_id: String,
    backup_id: String,
    actor: crate::auth::Actor,
    source_credential: crate::auth::DriveCredential,
) -> ApiResult<Response> {
    let _restore_maintenance = LegacyRestoreMaintenanceGuard {
        state: state.clone(),
        restore_id,
    };
    let preparation_state = state.clone();
    let data_dir = state.data_dir();
    let preparation = state
        .run_backup_work(move || prepare_legacy_restore(&preparation_state, &data_dir, &backup_id))
        .await??;
    let backup = preparation.bundle.metadata.clone();
    let tables = preparation.bundle.tables;
    let blobs = preparation.blobs;
    let verified_blobs = preparation.verified_blobs;
    let publications = PendingBlobPublications::acquire(&state).await?;
    let restore_storage = state.storage.clone();
    let restore_actor = actor.clone();
    let restore_credential = source_credential.clone();
    let (publications, restore_result) = tokio::task::spawn_blocking(move || {
        let mut publications = publications;
        let result = (|| {
            for (expected_hash, bytes) in &blobs {
                let publication = publications.put_bytes(bytes)?;
                if publication.hash != *expected_hash {
                    return Err(ApiError::Validation(
                        "validated backup blob changed during installation".to_string(),
                    ));
                }
            }
            restore_storage.restore_backup_tables_authorized(
                &tables,
                &verified_blobs,
                &restore_actor,
                &restore_credential,
            )
        })();
        (publications, result)
    })
    .await
    .map_err(|_| ApiError::Maintenance("legacy backup restore worker failed".to_string()))?;
    publications.finish(restore_result).await?;
    let receipt =
        state
            .storage
            .insert_receipt("backup.restore", &actor.email, Some(&backup.backup_id))?;
    Ok(Json(BackupMutationResponse { backup, receipt }).into_response())
}

struct LegacyRestoreMaintenanceGuard {
    state: AppState,
    restore_id: String,
}

impl Drop for LegacyRestoreMaintenanceGuard {
    fn drop(&mut self) {
        self.state.end_backup_restore(&self.restore_id);
    }
}

pub fn list_backup_metadata(state: &AppState) -> ApiResult<Vec<BackupMetadata>> {
    let data_dir = state.data_dir();
    let dir = backup_dir(&data_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let paths = bounded_backup_catalog_paths(&data_dir)?;
    let managed_digests = state.storage.managed_backup_publication_digests()?;
    let tombstoned_ids = state.storage.managed_backup_tombstoned_ids()?;
    let blocked_ids = managed_digests
        .keys()
        .chain(tombstoned_ids.iter())
        .cloned()
        .collect::<HashSet<_>>();
    let mut budget = catalog::CatalogMetadataBudget::default();
    let mut backups = list_legacy_backup_metadata_from_paths(&paths, &mut budget, &blocked_ids)?;
    backups.extend(list_v2_backup_metadata_from_paths(
        &data_dir,
        &paths,
        &mut budget,
        &managed_digests,
        &tombstoned_ids,
    )?);
    backups.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    Ok(backups)
}
