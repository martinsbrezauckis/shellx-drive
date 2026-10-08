use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    backup_v2::{self, V2Limits},
    blob,
    error::{ApiError, ApiResult},
    fs_private,
    io_advice::FileCacheDropGuard,
    model::BackupJob,
    server::AppState,
    version,
};

use super::catalog::{
    apply_v2_retention, backup_dir, create_v2_incomplete_marker, ensure_v2_generation_complete,
    metadata_from_v2_manifest, read_or_create_v2_sidecar_key, reconcile_managed_v2_publications,
    remove_v2_incomplete_marker, v2_backup_path, v2_sidecar_partial_path, v2_sidecar_path,
    v2_staging_root, write_v2_sidecar, V2SidecarPayload,
};

const BACKUP_WORKER_INTERVAL_SECS: u64 = 1;
const SCHEDULED_BACKUP_ACTOR: &str = "system-backup@shellx.local";

mod provenance;

/// Recover durable backup-job state and remove only server-owned artifacts left
/// by a process interruption. A create marker prevents a complete archive from
/// being exposed between its atomic rename and durable job completion.
pub fn recover_backup_state(state: &AppState) -> ApiResult<()> {
    let dir = backup_dir(&state.data_dir());
    fs_private::create_dir_all_private(&dir)?;
    super::download::cleanup_download_snapshots(&state.data_dir())?;
    let _ = read_or_create_v2_sidecar_key(&state.data_dir())?;
    reconcile_managed_v2_publications(state)?;
    let interrupted = state.storage.interrupt_running_backup_jobs()?;
    if interrupted > 0 {
        tracing::warn!(
            interrupted,
            "marked interrupted backup jobs during startup recovery"
        );
    }
    reconcile_v2_create_publications(state)?;
    let staging = v2_staging_root(&state.data_dir());
    if staging.exists() {
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let file_type = entry.file_type()?;
            if name.ends_with(".v2-stage") || name.ends_with(".restore-stage") {
                if file_type.is_dir() && !file_type.is_symlink() {
                    fs::remove_dir_all(path)?;
                }
            } else if name.ends_with(".partial") && file_type.is_file() {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

fn reconcile_v2_create_publications(state: &AppState) -> ApiResult<()> {
    let data_dir = state.data_dir();
    for job in state.storage.list_backup_jobs()? {
        if job.kind != "create" {
            continue;
        }
        match job.status.as_str() {
            "failed" | "interrupted" => {
                if cleanup_incomplete_v2_create_publication(&data_dir, &job.backup_id) {
                    remove_incomplete_marker_after_cleanup(&data_dir, &job.backup_id);
                }
            }
            "succeeded" => reconcile_succeeded_v2_create_publication(state, &job),
            _ => {}
        }
    }
    Ok(())
}

fn reconcile_succeeded_v2_create_publication(state: &AppState, job: &BackupJob) {
    match remove_v2_incomplete_marker(&state.data_dir(), &job.backup_id) {
        // `false` means publication already cleared the marker before a
        // restart. Retention is idempotent post-publication housekeeping, so
        // retry it in both cases.
        Ok(_) => {
            apply_v2_retention_after_publication(state);
            if job.actor == SCHEDULED_BACKUP_ACTOR {
                enqueue_scheduled_validation_if_missing(state, &job.backup_id);
            }
        }
        Err(error) => {
            // An invalid marker or an unconfirmed removal remains fail-closed.
            tracing::warn!(
                %error,
                backup_id = %job.backup_id,
                "could not reconcile completed backup v2 incomplete marker"
            );
        }
    }
}

struct V2CreatePublicationGuard {
    data_dir: PathBuf,
    backup_id: String,
    active: bool,
}

impl V2CreatePublicationGuard {
    fn begin(data_dir: &Path, backup_id: &str) -> ApiResult<Self> {
        create_v2_incomplete_marker(data_dir, backup_id)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            backup_id: backup_id.to_string(),
            active: true,
        })
    }

    fn mark_succeeded(mut self) -> bool {
        self.active = false;
        match remove_v2_incomplete_marker(&self.data_dir, &self.backup_id) {
            Ok(removed) => removed,
            Err(error) => {
                // The durable job is already successful. Keep the marker in
                // place rather than expose an archive whose final visibility
                // cleanup was not confirmed; startup retries this removal.
                tracing::warn!(
                    %error,
                    backup_id = %self.backup_id,
                    "could not clear completed backup v2 incomplete marker"
                );
                false
            }
        }
    }
}

impl Drop for V2CreatePublicationGuard {
    fn drop(&mut self) {
        if self.active && cleanup_incomplete_v2_create_publication(&self.data_dir, &self.backup_id)
        {
            remove_incomplete_marker_after_cleanup(&self.data_dir, &self.backup_id);
        }
    }
}

fn remove_incomplete_marker_after_cleanup(data_dir: &Path, backup_id: &str) -> bool {
    match remove_v2_incomplete_marker(data_dir, backup_id) {
        Ok(removed) => removed,
        Err(error) => {
            // The marker remains fail-closed when its removal cannot be
            // confirmed. Startup retries it for successful, interrupted, and
            // failed creates.
            tracing::warn!(
                %error,
                backup_id,
                "could not clear backup v2 incomplete marker after publication cleanup"
            );
            false
        }
    }
}

fn apply_v2_retention_after_publication(state: &AppState) {
    // Retention only observes a generation after its success row and marker
    // removal are both durable. A failure before that point cleans only the
    // unpublished generation, so it cannot erase an older usable backup.
    // Retention is post-publication housekeeping: a failure must not turn a
    // completed create back into a failed publication.
    if let Err(error) = apply_v2_retention(state) {
        tracing::warn!(%error, "backup v2 post-publication retention failed");
    }
}

fn enqueue_scheduled_validation_if_missing(state: &AppState, backup_id: &str) {
    let outcome = (|| {
        if state
            .storage
            .list_backup_jobs()?
            .iter()
            .any(|job| job.kind == "validate" && job.backup_id == backup_id)
        {
            return Ok(());
        }
        state.storage.enqueue_scheduled_backup_job(
            "validate",
            backup_id,
            SCHEDULED_BACKUP_ACTOR,
        )?;
        Ok::<(), ApiError>(())
    })();
    if let Err(error) = outcome {
        tracing::warn!(%error, backup_id, "could not enqueue post-publication backup validation");
    }
}

fn cleanup_incomplete_v2_create_publication(data_dir: &Path, backup_id: &str) -> bool {
    let mut complete = true;
    let paths = [
        ("archive", v2_backup_path(data_dir, backup_id)),
        ("sidecar", v2_sidecar_path(data_dir, backup_id)),
        (
            "sidecar partial",
            v2_sidecar_partial_path(data_dir, backup_id),
        ),
    ];
    for (kind, path) in paths {
        let path = match path {
            Ok(path) => path,
            Err(error) => {
                complete = false;
                tracing::warn!(%error, backup_id, "could not resolve incomplete backup v2 publication artifact");
                continue;
            }
        };
        match fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(backup_id, kind, path = %path.display(), "removed incomplete backup v2 publication artifact")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                complete = false;
                tracing::warn!(%error, backup_id, kind, path = %path.display(), "could not remove incomplete backup v2 publication artifact");
            }
        }
    }
    complete
}

pub fn spawn_backup_worker(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(BACKUP_WORKER_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            run_backup_job_once(&state).await;
        }
    })
}

async fn run_backup_job_once(state: &AppState) {
    let state = state.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        enqueue_scheduled_backup_if_due(&state)?;
        process_backup_job_once(&state)
    })
    .await;
    match outcome {
        Ok(Ok(Some(job_id))) => tracing::info!(job_id, "backup worker completed a job"),
        Ok(Ok(None)) => {}
        Ok(Err(error)) => tracing::warn!(%error, "backup worker pass failed"),
        Err(error) => tracing::warn!(%error, "backup worker task panicked"),
    }
}

fn enqueue_scheduled_backup_if_due(state: &AppState) -> ApiResult<()> {
    let policy = state.storage.get_backup_policy()?;
    if !policy.enabled || policy.schedule == "manual" {
        return Ok(());
    }
    let due_after = match policy.schedule.as_str() {
        "hourly" => chrono::Duration::hours(1),
        "daily" => chrono::Duration::days(1),
        "weekly" => chrono::Duration::weeks(1),
        _ => {
            return Err(ApiError::Validation(
                "backup policy contains an unsupported schedule".to_string(),
            ))
        }
    };
    let latest = state
        .storage
        .list_backup_jobs()?
        .into_iter()
        .find(|job| job.kind == "create");
    let due = latest
        .and_then(|job| chrono::DateTime::parse_from_rfc3339(&job.created_at).ok())
        .is_none_or(|created| {
            chrono::Utc::now() - created.with_timezone(&chrono::Utc) >= due_after
        });
    if due {
        state.storage.enqueue_scheduled_backup_job(
            "create",
            &uuid::Uuid::now_v7().to_string(),
            SCHEDULED_BACKUP_ACTOR,
        )?;
    }
    Ok(())
}

fn process_backup_job_once(state: &AppState) -> ApiResult<Option<String>> {
    let Some(job) = state.storage.claim_next_backup_job()? else {
        return Ok(None);
    };
    let job_id = job.id.clone();
    let restore_job = job.kind == "restore";
    let result = match job.kind.as_str() {
        "create" => process_v2_create_job(state, &job),
        "validate" => process_v2_validate_job(state, &job),
        "restore" => process_v2_restore_job(state, &job),
        _ => Err(ApiError::Validation(
            "unsupported durable backup job kind".to_string(),
        )),
    };
    if let Err(error) = result {
        let current = state.storage.get_backup_job(&job.id)?;
        let committed = current
            .as_ref()
            .is_some_and(|current| current.phase == "committed");
        state.storage.finish_backup_job(
            &job.id,
            if committed { "interrupted" } else { "failed" },
            if committed {
                "interrupted_committed"
            } else {
                "failed"
            },
            None,
            Some(&error.to_string()),
        )?;
    }
    if restore_job {
        // The route reserved this drain permit before returning 202. Release it
        // only after the terminal job row has been recorded on either path.
        state.end_backup_restore(&job.id);
    }
    Ok(Some(job_id))
}

fn process_v2_create_job(state: &AppState, job: &BackupJob) -> ApiResult<()> {
    state.storage.ensure_backup_job_authorized(&job.id)?;
    state.storage.update_backup_job_phase(&job.id, "snapshot")?;
    let data_dir = state.data_dir();
    let publication = V2CreatePublicationGuard::begin(&data_dir, &job.backup_id)?;
    let archive_path = v2_backup_path(&data_dir, &job.backup_id)?;
    let staging_root = v2_staging_root(&data_dir);
    let limits = v2_limits(state);
    fs_private::create_dir_all_private(&staging_root)?;
    // Keep every blob selected by the consistent database snapshot alive until
    // the archive has consumed its bytes. Cleanup holds the opposite exclusive
    // lifecycle lock, so it cannot unlink a just-snapshotted reference midway
    // through this streaming export.
    let created = {
        let _blob_lifecycle_lock = blob::BlobLifecycleLock::acquire_shared(&data_dir)?;
        state.storage.create_backup_v2_archive(
            &data_dir,
            &archive_path,
            &staging_root,
            backup_v2::V2ArchiveIdentity {
                backup_id: &job.backup_id,
                created_at: &job.created_at,
                source_build: &version::build_id(),
            },
            limits,
        )?
    };
    let _cache_drop = FileCacheDropGuard::for_path(&archive_path);
    state.storage.ensure_backup_job_authorized(&job.id)?;
    let archive_sha256 = created.archive_sha256;
    // This is the authorization linearization point for publication. It runs
    // after the potentially long archive write, so revocation that wins before this
    // intent prevents all subsequent durable publication work.
    state.storage.create_backup_v2_publication_intent(&job.id)?;
    let metadata = metadata_from_v2_manifest(&created.manifest, created.archive_bytes, &job.id);
    write_v2_sidecar(
        &data_dir,
        V2SidecarPayload {
            metadata,
            archive_sha256: archive_sha256.clone(),
        },
    )?;
    state
        .storage
        .finalize_v2_backup_create_publication(&job.id, &archive_sha256)?;
    if publication.mark_succeeded() {
        apply_v2_retention_after_publication(state);
        if job.actor == SCHEDULED_BACKUP_ACTOR {
            enqueue_scheduled_validation_if_missing(state, &job.backup_id);
        }
    }
    Ok(())
}

fn process_v2_validate_job(state: &AppState, job: &BackupJob) -> ApiResult<()> {
    ensure_v2_generation_complete(&state.data_dir(), &job.backup_id)?;
    state.storage.ensure_backup_job_authorized(&job.id)?;
    state
        .storage
        .update_backup_job_phase(&job.id, "validating")?;
    let data_dir = state.data_dir();
    let archive = v2_backup_path(&data_dir, &job.backup_id)?;
    let _cache_drop = FileCacheDropGuard::for_path(&archive);
    let schema = state.storage.backup_v2_schema()?;
    let limits = v2_limits(state);
    let summary = backup_v2::validate_archive(&archive, &schema, limits)?;
    let sidecar = provenance::verify_v2_archive(
        state,
        &job.backup_id,
        &summary.archive_sha256,
        summary.portable_metadata.is_some(),
    )?;
    if let Some(sidecar) = sidecar {
        if summary.archive_bytes != sidecar.metadata.archive_bytes.unwrap_or_default() {
            return Err(ApiError::Validation(
                "backup v2 archive size does not match authenticated sidecar".to_string(),
            ));
        }
    }
    state.storage.ensure_backup_job_authorized(&job.id)?;
    state
        .storage
        .insert_receipt("backup.validate", &job.actor, Some(&job.backup_id))?;
    state.storage.finish_backup_job(
        &job.id,
        "succeeded",
        "complete",
        Some(&summary.archive_sha256),
        None,
    )?;
    Ok(())
}

fn process_v2_restore_job(state: &AppState, job: &BackupJob) -> ApiResult<()> {
    ensure_v2_generation_complete(&state.data_dir(), &job.backup_id)?;
    state.begin_backup_restore(&job.id)?;
    state
        .storage
        .ensure_backup_restore_job_authorized(&job.id)?;
    let data_dir = state.data_dir();
    let stage = v2_staging_root(&data_dir).join(format!(".{}.restore-stage", job.id));
    let limits = v2_limits(state);
    let result: ApiResult<String> = (|| {
        state
            .storage
            .update_backup_job_phase(&job.id, "validating")?;
        let archive = v2_backup_path(&data_dir, &job.backup_id)?;
        let _cache_drop = FileCacheDropGuard::for_path(&archive);
        state
            .storage
            .update_backup_job_phase(&job.id, "extracting")?;
        fs_private::create_dir_all_private(&v2_staging_root(&data_dir))?;
        let schema = state.storage.backup_v2_schema()?;
        let snapshot = backup_v2::extract_archive_validated(&archive, &schema, &stage, limits)?;
        provenance::verify_v2_archive(
            state,
            &job.backup_id,
            &snapshot.archive_sha256,
            snapshot.portable_metadata.is_some(),
        )?;
        state
            .storage
            .update_backup_job_phase(&job.id, "restoring")?;
        state
            .storage
            .ensure_backup_restore_job_authorized(&job.id)?;
        state
            .storage
            .restore_backup_v2_extracted(&data_dir, &snapshot, limits, &job.id)?;
        state
            .storage
            .insert_receipt("backup.restore", &job.actor, Some(&job.backup_id))?;
        Ok(snapshot.archive_sha256)
    })();
    if stage.exists() {
        if let Err(error) = fs::remove_dir_all(&stage) {
            tracing::warn!(%error, path = %stage.display(), "could not remove restore staging directory");
        }
    }
    let archive_sha256 = result?;
    state.storage.finish_backup_job(
        &job.id,
        "succeeded",
        "complete",
        Some(&archive_sha256),
        None,
    )?;
    Ok(())
}

fn v2_limits(state: &AppState) -> V2Limits {
    let mut limits = V2Limits::default();
    limits.max_archive_bytes = state.config.backup_max_archive_bytes;
    limits.max_content_bytes = limits
        .max_content_bytes
        .min(state.config.backup_max_archive_bytes);
    limits
}

#[cfg(test)]
mod tests;
