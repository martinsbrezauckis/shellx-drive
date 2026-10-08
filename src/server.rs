use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Router,
};
use tokio::time::MissedTickBehavior;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

use crate::{
    auth::{
        client_fingerprint, explicit_bearer_token, has_session_cookie, require_admin,
        require_drive_actor, Actor, DriveCredential,
    },
    config::Config,
    error::{ApiError, ApiResult},
    fs_private, routes,
    storage::{PublicCapabilityKind, PublicPasswordAttemptResult, Storage},
};

pub(crate) mod admin_response_guard;
mod governors;
mod instance_lock;
mod request_trace;
mod security_audit;
mod upload_cleanup;
mod workspace_usage;
use governors::{
    authenticated_body_stream_governor, authenticated_upload_finalization_governor,
    authenticated_upload_ingress_governor, metadata_planning_governor, rclone_export_governor,
    sync_compute_governor, BackupWorkGovernor, BackupWorkPermit, JsonIngressClass,
    JsonIngressGovernor, PartitionedGovernor, PasswordWorkGovernor, PublicBodyStreamGovernor,
    PublicBodyStreamPermit, PublicDropChunkIngressGovernor, PublicDropFinalizationGovernor,
};
pub(crate) use governors::{PartitionedPermit, PublicDropChunkIngressPermit};

/// How often the background worker drains the job queue in production.
///
/// Short enough that a freshly uploaded image gets its thumbnail / search index
/// within a few seconds; long enough that an idle server does almost no work
/// (each empty tick is a single `COUNT(*)`).
const BACKGROUND_WORKER_INTERVAL_SECS: u64 = 4;
const STALE_UPLOAD_REAPER_INTERVAL_TICKS: u64 = 225;
const STALE_UPLOAD_MAX_AGE_SECONDS: i64 = 86_400;
const REQUEST_TIMEOUT_SECONDS: u64 = 300;
const UNTRUSTED_JSON_TIMEOUT_SECONDS: u64 = 30;
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
const STRICT_TRANSPORT_SECURITY: HeaderName = HeaderName::from_static("strict-transport-security");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
pub const CLIENT_FINGERPRINT_HEADER: &str = "x-shellx-client-fingerprint";

#[derive(Debug, Clone)]
pub struct ClientRequestMetadata {
    pub client_ip: String,
    pub user_agent: Option<String>,
}
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub storage: Storage,
    _instance_lock: Arc<instance_lock::InstanceLock>,
    pub(crate) archive_tickets: crate::streaming_zip::ArchiveTickets,
    pub(crate) file_download_tickets: crate::download_tickets::FileDownloadTickets,
    pub(crate) office_handoffs: crate::office_handoffs::OfficeHandoffs,
    backup_maintenance: Arc<RwLock<Option<BackupMaintenance>>>,
    mutation_gate: Arc<tokio::sync::RwLock<()>>,
    backup_restore_permit: Arc<Mutex<Option<BackupRestorePermit>>>,
    pub(crate) upload_part_reconcile_cursor: Arc<Mutex<Option<std::fs::ReadDir>>>,
    pub(crate) drop_upload_part_reconcile_cursor: Arc<Mutex<Option<std::fs::ReadDir>>>,
    password_work: PasswordWorkGovernor,
    public_body_streams: PublicBodyStreamGovernor,
    authenticated_body_streams: PartitionedGovernor,
    authenticated_upload_ingress: PartitionedGovernor,
    authenticated_upload_finalization: PartitionedGovernor,
    json_ingress: JsonIngressGovernor,
    metadata_planning: PartitionedGovernor,
    sync_compute: PartitionedGovernor,
    rclone_export_admission: Arc<tokio::sync::Semaphore>,
    rclone_export: PartitionedGovernor,
    backup_work: BackupWorkGovernor,
    webdav_operations: Arc<tokio::sync::Mutex<()>>,
    public_drop_chunk_ingress: PublicDropChunkIngressGovernor,
    public_drop_finalization: PublicDropFinalizationGovernor,
    security_audit_admission: security_audit::SecurityAuditAdmission,
    pub(crate) update_checker: routes::version::UpdateChecker,
}

#[derive(Debug, Clone)]
pub struct BackupMaintenance {
    pub job_id: String,
    pub started_at: String,
}

struct BackupRestorePermit {
    job_id: String,
    _permit: tokio::sync::OwnedRwLockWriteGuard<()>,
}

struct PendingBackupRestoreIntent {
    state: AppState,
    job_id: String,
    active: bool,
}

impl PendingBackupRestoreIntent {
    fn publish(state: AppState, job_id: &str) -> ApiResult<Self> {
        let mut maintenance = state.backup_maintenance.write().unwrap();
        if maintenance.is_some() {
            return Err(ApiError::Conflict);
        }
        *maintenance = Some(BackupMaintenance {
            job_id: job_id.to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
        });
        drop(maintenance);
        Ok(Self {
            state,
            job_id: job_id.to_string(),
            active: true,
        })
    }

    fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for PendingBackupRestoreIntent {
    fn drop(&mut self) {
        if self.active {
            self.state.clear_backup_restore_intent(&self.job_id);
        }
    }
}

impl AppState {
    pub(crate) fn admit_low_authority_security_event(&self, partition: &str) -> bool {
        self.security_audit_admission.admit_low_authority(partition)
    }

    pub fn open(mut config: Config) -> anyhow::Result<Self> {
        if let Some(provider_url) = config.office_provider_url.take() {
            config.office_provider_url =
                Some(crate::config::validate_office_provider_url(provider_url)?);
        }
        fs_private::create_dir_all_private(&config.data_dir)?;
        let instance_lock = Arc::new(instance_lock::acquire(&config.data_dir)?);
        let operator_credential_generation =
            crate::auth::operator_credential_generation(&config.token);
        let storage = Storage::open_with_operator_credential_generation(
            config.data_dir.join("drive.db"),
            operator_credential_generation,
        )?;
        storage.ping()?;
        storage.migrate()?;
        let stale_backup_jobs = storage.fail_stale_backup_jobs()?;
        if stale_backup_jobs > 0 {
            tracing::warn!(
                failed = stale_backup_jobs,
                "failed queued backup jobs with stale or invalid authority"
            );
        }
        storage.backfill_cover_bytes(&config.data_dir)?;
        storage.backfill_thumbnail_bytes(&config.data_dir)?;
        storage.interrupt_running_import_runs()?;
        let (requeued_background_jobs, failed_background_jobs) =
            storage.recover_running_background_jobs()?;
        if requeued_background_jobs + failed_background_jobs > 0 {
            tracing::warn!(
                requeued = requeued_background_jobs,
                failed = failed_background_jobs,
                "recovered interrupted background jobs during startup"
            );
        }
        let state = Self {
            config: Arc::new(config),
            storage,
            _instance_lock: instance_lock,
            archive_tickets: crate::streaming_zip::ArchiveTickets::default(),
            file_download_tickets: crate::download_tickets::FileDownloadTickets::default(),
            office_handoffs: crate::office_handoffs::OfficeHandoffs::default(),
            backup_maintenance: Arc::new(RwLock::new(None)),
            mutation_gate: Arc::new(tokio::sync::RwLock::new(())),
            backup_restore_permit: Arc::new(Mutex::new(None)),
            upload_part_reconcile_cursor: Arc::new(Mutex::new(None)),
            drop_upload_part_reconcile_cursor: Arc::new(Mutex::new(None)),
            password_work: PasswordWorkGovernor::default(),
            public_body_streams: PublicBodyStreamGovernor::default(),
            authenticated_body_streams: authenticated_body_stream_governor(),
            authenticated_upload_ingress: authenticated_upload_ingress_governor(),
            authenticated_upload_finalization: authenticated_upload_finalization_governor(),
            json_ingress: JsonIngressGovernor::default(),
            metadata_planning: metadata_planning_governor(),
            sync_compute: sync_compute_governor(),
            rclone_export_admission: Arc::new(tokio::sync::Semaphore::new(2)),
            rclone_export: rclone_export_governor(),
            backup_work: BackupWorkGovernor::default(),
            webdav_operations: Arc::new(tokio::sync::Mutex::new(())),
            public_drop_chunk_ingress: PublicDropChunkIngressGovernor::default(),
            public_drop_finalization: PublicDropFinalizationGovernor::default(),
            security_audit_admission: security_audit::SecurityAuditAdmission::default(),
            update_checker: routes::version::UpdateChecker::new()?,
        };
        routes::backups::recover_backup_state(&state)?;
        state.reserve_queued_backup_restore()?;
        let reconciled_upload_parts =
            routes::uploads::cleanup::reconcile_terminal_upload_parts_lock_safe(
                &state,
                STALE_UPLOAD_MAX_AGE_SECONDS,
            )?;
        if reconciled_upload_parts.cleaned > 0 {
            tracing::warn!(
                cleaned = reconciled_upload_parts.cleaned,
                inspected = reconciled_upload_parts.inspected,
                "reconciled terminal upload parts during startup"
            );
        }
        let reconciled_drop_upload_parts =
            routes::drop_uploads::cleanup::reconcile_terminal_drop_upload_parts_lock_safe(
                &state,
                STALE_UPLOAD_MAX_AGE_SECONDS,
            )?;
        if reconciled_drop_upload_parts.cleaned > 0 {
            tracing::warn!(
                cleaned = reconciled_drop_upload_parts.cleaned,
                inspected = reconciled_drop_upload_parts.inspected,
                "reconciled terminal Drop upload parts during startup"
            );
        }
        Ok(state)
    }

    pub fn data_dir(&self) -> PathBuf {
        self.config.data_dir.clone()
    }

    /// Run a public share/drop password check within the one-process Argon2
    /// concurrency bound. Saturation is deliberately a prompt `429`, not a
    /// queue that lets an attacker accumulate expensive work.
    pub async fn verify_public_password(&self, encoded: &str, password: &str) -> ApiResult<bool> {
        self.password_work.verify_public(encoded, password).await
    }

    /// Reserve success-independent work first, then serialize failure-budget
    /// admission, Argon2 verification, and durable result accounting under the
    /// public verifier permit. Valid-password traffic therefore cannot clear
    /// its expensive-work allowance or monopolize the verifier indefinitely.
    pub(crate) async fn verify_public_capability_password(
        &self,
        kind: PublicCapabilityKind,
        capability_id: &str,
        encoded: &str,
        password: Option<&str>,
        client_fingerprint: &str,
    ) -> ApiResult<(bool, PublicPasswordAttemptResult)> {
        self.storage.reserve_public_capability_password_work(
            kind,
            capability_id,
            client_fingerprint,
        )?;
        let admission_storage = self.storage.clone();
        let completion_storage = self.storage.clone();
        let admission_id = capability_id.to_string();
        let completion_id = admission_id.clone();
        let admission_client = client_fingerprint.to_string();
        let completion_client = admission_client.clone();
        let verify_supplied = password.is_some();
        self.password_work
            .verify_public_with_budget(
                encoded,
                password.unwrap_or_default(),
                verify_supplied,
                move || {
                    admission_storage.admit_public_capability_password_attempt(
                        kind,
                        &admission_id,
                        &admission_client,
                    )
                },
                move |verified, admission| {
                    completion_storage.complete_public_capability_password_attempt(
                        kind,
                        &completion_id,
                        &completion_client,
                        admission,
                        verified,
                    )
                },
            )
            .await
    }

    /// Run account-password verification outside async workers and reject new
    /// work immediately when the process-wide memory-hard budget is saturated.
    pub async fn verify_account_password(&self, encoded: &str, password: &str) -> ApiResult<bool> {
        self.password_work.verify_account(encoded, password).await
    }

    /// Run password verification for an unauthenticated account endpoint in
    /// the restricted public lane, preserving capacity for signed-in work.
    pub async fn verify_untrusted_account_password(
        &self,
        encoded: &str,
        password: &str,
    ) -> ApiResult<bool> {
        self.password_work
            .verify_untrusted_account(encoded, password)
            .await
    }

    /// Hash a new account password under the same process-wide Argon2 budget.
    pub async fn hash_account_password(&self, password: &str) -> ApiResult<String> {
        self.password_work.hash_account(password).await
    }

    /// Hash an unauthenticated account password without consuming the lane
    /// reserved for authenticated security and administrator operations.
    pub async fn hash_untrusted_account_password(&self, password: &str) -> ApiResult<String> {
        self.password_work.hash_untrusted_account(password).await
    }

    /// Hash a share or Drop password under the same bounded Argon2 budget.
    pub async fn hash_public_password(&self, password: &str) -> ApiResult<String> {
        self.password_work.hash_public(password).await
    }

    /// Reserve one non-queueing public Drop finalizer. The route moves this
    /// permit into its blocking closure so cancellation cannot release capacity
    /// while hashing or copying is still running.
    pub(crate) fn try_public_drop_finalization(
        &self,
    ) -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
        self.public_drop_finalization.try_acquire()
    }

    /// Bound aggregate Drop request bodies before they are collected into heap
    /// buffers. One permit represents at most one MAX_DROP_CHUNK_BYTES body.
    pub(crate) fn try_public_drop_chunk_ingress(
        &self,
        drop_id: &str,
        transport_fingerprint: &str,
    ) -> ApiResult<PublicDropChunkIngressPermit> {
        self.public_drop_chunk_ingress
            .try_acquire(drop_id, transport_fingerprint)
    }

    /// Hold one process-wide and one per-share reservation for the complete
    /// lifetime of a public file or thumbnail response body.
    pub(crate) fn try_public_body_stream(
        &self,
        share_id: &str,
        client_fingerprint: &str,
    ) -> ApiResult<PublicBodyStreamPermit> {
        self.public_body_streams
            .try_acquire(share_id, client_fingerprint)
    }

    /// Hold one process-wide and one per-principal reservation until an
    /// authenticated response body reaches EOF or is cancelled.
    pub(crate) fn try_authenticated_body_stream(
        &self,
        principal: &str,
    ) -> ApiResult<PartitionedPermit> {
        self.authenticated_body_streams.try_acquire(principal)
    }

    /// Reject excess legacy rclone requests before authentication and SQLite
    /// work, which run in a bounded blocking worker.
    pub(crate) fn try_rclone_export_admission(
        &self,
    ) -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
        self.rclone_export_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)
    }

    /// Hold a per-actor legacy rclone reservation through response delivery.
    pub(crate) fn try_rclone_export(&self, principal: &str) -> ApiResult<PartitionedPermit> {
        self.rclone_export.try_acquire(principal)
    }

    /// Bound authenticated binary chunk buffers globally and per account.
    /// The permit is acquired before Axum collects the request body.
    pub(crate) fn try_authenticated_upload_ingress(
        &self,
        actor_email: &str,
    ) -> ApiResult<PartitionedPermit> {
        self.authenticated_upload_ingress.try_acquire(actor_email)
    }

    /// Run an authenticated resumable-upload terminal transition in its own
    /// bounded lane. The permit moves into the blocking worker so cancellation
    /// cannot admit another full blob publication before that worker exits.
    pub(crate) async fn run_authenticated_upload_finalization<T>(
        &self,
        actor_email: &str,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        self.authenticated_upload_finalization
            .run_blocking(actor_email, work)
            .await
    }

    /// Bound JSON collection/deserialization in separate authority lanes and
    /// per actor or transport client. Middleware acquires this before Axum's
    /// `Json` extractor reads the body.
    fn try_json_ingress(
        &self,
        class: JsonIngressClass,
        partition: &str,
    ) -> ApiResult<PartitionedPermit> {
        self.json_ingress.try_acquire(class, partition)
    }

    /// Bound expensive tree and catalog materialization globally and by the
    /// capability that authorized it. Saturation is rejected instead of queued.
    pub(crate) fn try_metadata_planning(&self, capability: &str) -> ApiResult<PartitionedPermit> {
        self.metadata_planning.try_acquire(capability)
    }

    /// Bound synchronous sync work globally and per actor, and hold capacity
    /// until the blocking read/compute/response work exits even if its caller is
    /// cancelled.
    pub(crate) async fn run_sync_compute<T>(
        &self,
        actor_email: &str,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        self.sync_compute.run_blocking(actor_email, work).await
    }

    /// Run a mutation-capable async coordinator independently of the request
    /// future while retaining a restore-drain reader for its complete
    /// lifetime. Dropping the request only detaches the join handle; restore
    /// cannot acquire its writer until the worker and compensation finish.
    pub(crate) async fn run_detached_mutation<T, F>(&self, work: F) -> ApiResult<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = ApiResult<T>> + Send + 'static,
    {
        let mutation_permit = self.try_mutation_permit()?;
        tokio::spawn(async move {
            let _mutation_permit = mutation_permit;
            work.await
        })
        .await
        .map_err(|_| ApiError::Maintenance("detached mutation worker failed".to_string()))?
    }

    /// Legacy backup parsing and backup catalog inspection process hostile
    /// retained files. Keep that synchronous work in one fail-fast blocking
    /// lane so requests cannot queue large deserializations on async workers.
    pub(crate) async fn run_backup_work<T>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T>
    where
        T: Send + 'static,
    {
        self.backup_work.run_blocking(work).await
    }

    /// Reserve the backup worker lane when another bounded blocking operation
    /// must include backup catalog inspection as one part of its work.
    pub(crate) fn try_backup_work(&self) -> ApiResult<BackupWorkPermit> {
        self.backup_work.try_acquire()
    }

    /// Serialize WebDAV lock publication and mutations in the supported
    /// single-process topology so a lock cannot appear between validation and
    /// the corresponding file commit.
    pub(crate) async fn lock_webdav_operation(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.webdav_operations.clone().lock_owned().await
    }

    pub fn begin_backup_restore(&self, job_id: &str) -> ApiResult<()> {
        if let Some(active) = self.backup_maintenance.read().unwrap().as_ref() {
            return if active.job_id == job_id {
                if self
                    .backup_restore_permit
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|permit| permit.job_id == job_id)
                {
                    Ok(())
                } else {
                    Err(ApiError::Conflict)
                }
            } else {
                Err(ApiError::Conflict)
            };
        }
        let permit = self
            .mutation_gate
            .clone()
            .try_write_owned()
            .map_err(|_| ApiError::Conflict)?;
        self.install_backup_restore_permit(job_id, permit)?;
        Ok(())
    }

    pub(crate) async fn begin_legacy_backup_restore(&self, job_id: &str) -> ApiResult<()> {
        self.reserve_backup_restore_permit(job_id).await
    }

    async fn reserve_backup_restore_permit(&self, job_id: &str) -> ApiResult<()> {
        let intent = PendingBackupRestoreIntent::publish(self.clone(), job_id)?;
        let permit = self.mutation_gate.clone().write_owned().await;
        self.install_backup_restore_permit(job_id, permit)?;
        intent.disarm();
        Ok(())
    }

    fn install_backup_restore_permit(
        &self,
        job_id: &str,
        permit: tokio::sync::OwnedRwLockWriteGuard<()>,
    ) -> ApiResult<()> {
        let mut maintenance = self.backup_maintenance.write().unwrap();
        if maintenance
            .as_ref()
            .is_some_and(|active| active.job_id != job_id)
        {
            return Err(ApiError::Conflict);
        }
        *maintenance = Some(BackupMaintenance {
            job_id: job_id.to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
        });
        *self.backup_restore_permit.lock().unwrap() = Some(BackupRestorePermit {
            job_id: job_id.to_string(),
            _permit: permit,
        });
        Ok(())
    }

    /// Reserve write maintenance before publishing a durable restore job. This
    /// deliberately holds the in-process admission mutex through enqueue so no
    /// ordinary mutation can slip between the HTTP 202 response and worker
    /// adoption of the restore.
    pub async fn enqueue_backup_restore_job(
        &self,
        backup_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<crate::model::BackupJob> {
        let pending_id = format!("restore-pending-{backup_id}");
        self.reserve_backup_restore_permit(&pending_id).await?;
        let job = match self.storage.enqueue_authorized_backup_restore_job(
            backup_id,
            actor,
            source_credential,
        ) {
            Ok(job) => job,
            Err(error) => {
                self.end_backup_restore(&pending_id);
                return Err(error);
            }
        };
        {
            let mut maintenance = self.backup_maintenance.write().unwrap();
            *maintenance = Some(BackupMaintenance {
                job_id: job.id.clone(),
                started_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        self.backup_restore_permit
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .job_id = job.id.clone();
        Ok(job)
    }

    pub fn end_backup_restore(&self, job_id: &str) {
        if self
            .backup_maintenance
            .read()
            .unwrap()
            .as_ref()
            .is_none_or(|active| active.job_id != job_id)
        {
            return;
        }
        // Keep the already-drained write permit while handing off to a queued
        // restore. Releasing then re-acquiring would admit a mutation between
        // two durable restore jobs.
        match oldest_queued_restore_job(&self.storage) {
            Ok(Some(next)) => {
                *self.backup_maintenance.write().unwrap() = Some(BackupMaintenance {
                    job_id: next.id.clone(),
                    started_at: chrono::Utc::now().to_rfc3339(),
                });
                if let Some(permit) = self.backup_restore_permit.lock().unwrap().as_mut() {
                    permit.job_id = next.id;
                } else {
                    tracing::error!(
                        "backup restore maintenance lost its drain permit during handoff"
                    );
                }
            }
            Ok(None) => {
                *self.backup_maintenance.write().unwrap() = None;
                let permit = self.backup_restore_permit.lock().unwrap().take();
                drop(permit);
            }
            Err(error) => {
                tracing::error!(%error, "could not inspect queued backup restores during handoff");
                *self.backup_maintenance.write().unwrap() = None;
                let permit = self.backup_restore_permit.lock().unwrap().take();
                drop(permit);
            }
        }
    }

    pub fn backup_maintenance(&self) -> Option<BackupMaintenance> {
        self.backup_maintenance.read().unwrap().clone()
    }

    fn clear_backup_restore_intent(&self, job_id: &str) {
        let has_permit = self
            .backup_restore_permit
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|permit| permit.job_id == job_id);
        if !has_permit
            && self
                .backup_maintenance
                .read()
                .unwrap()
                .as_ref()
                .is_some_and(|active| active.job_id == job_id)
        {
            *self.backup_maintenance.write().unwrap() = None;
        }
    }

    fn try_mutation_permit(&self) -> ApiResult<tokio::sync::OwnedRwLockReadGuard<()>> {
        if self.backup_maintenance().is_some() {
            return Err(ApiError::Maintenance(
                "backup restore is draining mutations".to_string(),
            ));
        }
        let permit = self.mutation_gate.clone().try_read_owned().map_err(|_| {
            ApiError::Maintenance("backup restore is draining mutations".to_string())
        })?;
        if self.backup_maintenance().is_some() {
            drop(permit);
            return Err(ApiError::Maintenance(
                "backup restore is draining mutations".to_string(),
            ));
        }
        Ok(permit)
    }

    fn reserve_queued_backup_restore(&self) -> ApiResult<()> {
        if self.backup_maintenance.read().unwrap().is_none() {
            if let Some(job) = oldest_queued_restore_job(&self.storage)? {
                self.begin_backup_restore(&job.id)?;
            }
        }
        Ok(())
    }
}

fn oldest_queued_restore_job(storage: &Storage) -> ApiResult<Option<crate::model::BackupJob>> {
    Ok(storage
        .list_backup_jobs()?
        .into_iter()
        .filter(|job| job.kind == "restore" && job.status == "queued")
        .min_by(|left, right| left.created_at.cmp(&right.created_at)))
}

pub fn router(state: AppState) -> Router {
    let terminal_admin_response_state = state.clone();
    let client_identity_state = state.clone();
    let security_audit_state = state.clone();
    let browser_origin_state = state.clone();
    let maintenance_state = state.clone();
    Router::new()
        .route("/health", get(routes::health::health))
        .merge(routes::admin::router())
        .merge(routes::admin_canonical_content::router())
        .merge(routes::agent_access::router())
        .merge(routes::app_tokens::router())
        .merge(routes::backups::router())
        .merge(routes::comments::router())
        .merge(routes::debug::router())
        .merge(routes::desktop_agent::router())
        .merge(routes::drop_uploads::router())
        .merge(routes::drops::router())
        .merge(routes::downloads::router())
        .merge(routes::files::router())
        .merge(routes::folder_templates::router())
        .merge(routes::google_drive::router())
        .merge(routes::groups::router())
        .merge(routes::human_sharing::router())
        .merge(routes::hosted::router())
        .merge(routes::import_export::router())
        .merge(routes::local_auth::router())
        .merge(routes::maintenance::router())
        .merge(routes::notifications::router())
        .merge(routes::office::router())
        .merge(routes::oidc::router())
        .merge(routes::policies::router())
        .merge(routes::retention::router())
        .merge(routes::sandboxes::router())
        .merge(routes::security_events::router())
        .merge(routes::service_twin::router())
        .merge(routes::sessions::router())
        .merge(routes::shares::router())
        .merge(routes::sync::router())
        .merge(routes::sync_roots::router())
        .merge(routes::ui::router())
        .merge(routes::uploads::router())
        .merge(routes::version::router())
        .merge(routes::webdav::router())
        .merge(routes::workspace_statistics::router())
        .merge(routes::workspaces::router())
        // This is innermost so outer request-audit middleware observes a
        // terminal authorization failure rather than the handler's provisional
        // successful response.
        .layer(middleware::from_fn_with_state(
            terminal_admin_response_state,
            admin_response_guard::revalidate_buffered_admin_response,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_trace::SafeMakeSpan))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(REQUEST_TIMEOUT_SECONDS),
        ))
        .layer(middleware::from_fn(response_policy))
        .layer(middleware::from_fn_with_state(
            maintenance_state,
            reject_writes_during_restore,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admit_json_ingress,
        ))
        .layer(middleware::from_fn_with_state(
            browser_origin_state,
            require_browser_mutation_origin,
        ))
        .layer(middleware::from_fn_with_state(
            security_audit_state,
            security_audit::record_request_security_event,
        ))
        .layer(middleware::from_fn_with_state(
            client_identity_state,
            attach_client_fingerprint,
        ))
        .with_state(state)
}

/// Ambient session cookies may mutate state only from the configured Drive
/// origin. Browsers omit `Origin` for some ordinary same-origin `fetch`
/// mutations, so an exact configured-origin Referer is the bounded fallback.
/// Explicit bearer clients and capability-only public routes are not
/// CSRF-capable and keep their existing non-browser contracts.
async fn require_browser_mutation_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) || explicit_bearer_token(request.headers()).is_some()
        || !has_session_cookie(request.headers(), state.config.secure_cookies)
    {
        return Ok(next.run(request).await);
    }
    if !browser_mutation_is_same_origin(request.headers(), state.config.public_origin.as_str()) {
        return Err(ApiError::Forbidden);
    }
    Ok(next.run(request).await)
}

fn browser_mutation_is_same_origin(headers: &axum::http::HeaderMap, public_origin: &str) -> bool {
    match headers.get(header::ORIGIN) {
        Some(origin) => origin
            .to_str()
            .ok()
            .map(str::trim)
            .is_some_and(|origin| !origin.is_empty() && origin == public_origin),
        None => headers
            .get(header::REFERER)
            .and_then(|value| value.to_str().ok())
            .and_then(|referer| reqwest::Url::parse(referer).ok())
            .is_some_and(|referer| {
                referer.username().is_empty()
                    && referer.password().is_none()
                    && referer.origin().ascii_serialization() == public_origin
            }),
    }
}

async fn admit_json_ingress(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_json = content_type == "application/json"
        || content_type
            .strip_prefix("application/")
            .is_some_and(|subtype| subtype.ends_with("+json"));
    if !is_json {
        return Ok(next.run(request).await);
    }

    let (class, partition, untrusted) = if let Ok(actor) = require_admin(&state, request.headers())
    {
        (JsonIngressClass::Admin, actor.email, false)
    } else if let Ok(actor) = require_drive_actor(&state, request.headers()) {
        (JsonIngressClass::User, actor.email, false)
    } else {
        let class = if request.uri().path().starts_with("/auth/") {
            JsonIngressClass::Account
        } else {
            JsonIngressClass::Public
        };
        (
            class,
            request_client_fingerprint(request.headers()).to_string(),
            true,
        )
    };
    let permit = state.try_json_ingress(class, &partition)?;
    let response = if untrusted {
        tokio::time::timeout(
            Duration::from_secs(UNTRUSTED_JSON_TIMEOUT_SECONDS),
            next.run(request),
        )
        .await
        .map_err(|_| ApiError::RequestTimeout)?
    } else {
        next.run(request).await
    };
    drop(permit);
    Ok(response)
}

async fn reject_writes_during_restore(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // The restore endpoint itself establishes the write permit below. Letting
    // middleware take a read permit for it would self-deadlock while upgrading
    // to the drain barrier.
    let restore_endpoint = request.method() == Method::POST
        && request.uri().path().starts_with("/admin/backups/")
        && request.uri().path().ends_with("/restore");
    let observability_endpoint = matches!(request.uri().path(), "/health" | "/ready" | "/version")
        && matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        );
    if !restore_endpoint && !observability_endpoint {
        let mutation_permit = state.try_mutation_permit()?;
        let response = next.run(request).await;
        drop(mutation_permit);
        return Ok(response);
    }
    Ok(next.run(request).await)
}

/// Replace any caller-supplied internal identity header with a keyed digest of
/// the transport client. Forwarding headers are trusted only from a loopback
/// peer (the supported local reverse-proxy topology), and the right-most valid
/// X-Forwarded-For address is used so a caller cannot select an arbitrary
/// left-most value by prepending to the header.
async fn attach_client_fingerprint(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| peer.ip());
    let client_ip =
        resolved_client_ip(peer_ip, request.headers(), state.config.trust_proxy_headers);
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(512).collect());
    let fingerprint = client_fingerprint(client_ip, &state.config.token);
    request.headers_mut().remove(CLIENT_FINGERPRINT_HEADER);
    request.headers_mut().insert(
        HeaderName::from_static(CLIENT_FINGERPRINT_HEADER),
        HeaderValue::from_str(&fingerprint).expect("fingerprint is a valid header value"),
    );
    request.extensions_mut().insert(ClientRequestMetadata {
        client_ip: client_ip.to_string(),
        user_agent,
    });
    next.run(request).await
}

fn resolved_client_ip(
    peer_ip: Option<std::net::IpAddr>,
    headers: &axum::http::HeaderMap,
    trust_proxy_headers: bool,
) -> std::net::IpAddr {
    match peer_ip {
        Some(peer) if trust_proxy_headers && peer.is_loopback() => {
            forwarded_client_ip(headers).unwrap_or(peer)
        }
        Some(peer) => peer,
        None => "0.0.0.0".parse().expect("static IP is valid"),
    }
}

fn forwarded_client_ip(headers: &axum::http::HeaderMap) -> Option<std::net::IpAddr> {
    headers
        .get(header::HeaderName::from_static("x-forwarded-for"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .rev()
                .find_map(|candidate| candidate.trim().parse().ok())
        })
        .or_else(|| {
            headers
                .get(HeaderName::from_static("cf-connecting-ip"))
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse().ok())
        })
        .or_else(|| {
            headers
                .get(HeaderName::from_static("x-real-ip"))
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse().ok())
        })
}

pub fn request_client_fingerprint(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get(CLIENT_FINGERPRINT_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("client-v1-unknown")
}

/// Apply browser/security headers consistently across API, error, content, and
/// static responses. Route handlers may set a more specific content cache
/// policy (for example private thumbnails); JSON and capability-bearing public
/// pages always win with `no-store`.
async fn response_policy(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.starts_with("application/json"))
        .unwrap_or(false);
    let is_static_asset = path.starts_with("/assets/") || path == "/favicon.ico";
    let is_capability_page = path.starts_with("/pub/shares/")
        || path.starts_with("/pub/drops/")
        || path.starts_with("/pub/invitations/")
        || path == "/reset-password";

    let headers = response.headers_mut();
    headers
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("same-origin"));
    headers
        .entry(X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        PERMISSIONS_POLICY,
        HeaderValue::from_static(
            "camera=(self), microphone=(), geolocation=(), payment=(), usb=()",
        ),
    );

    if is_json || is_capability_page {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    } else if is_static_asset || path == "/" || path == "/manifest.webmanifest" || path == "/sw.js"
    {
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-cache"));
    } else if !is_static_asset && !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }

    response
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let bind: SocketAddr = config.bind;
    let state = AppState::open(config)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("shellx-drive listening on {}", listener.local_addr()?);
    // Drain background jobs (thumbnails, previews, search indexing) continuously.
    // `router(state)` moves `state`, so clone the handle for the worker first —
    // `AppState`/`Storage` are `Arc`-backed, so the clone shares the same DB.
    let _worker = spawn_background_worker(state.clone());
    let _backup_worker = routes::backups::spawn_backup_worker(state.clone());
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Spawn the background job worker that drains the queued-jobs table on a fixed
/// interval, and return its join handle.
///
/// WHY THIS EXISTS: uploads/writes call
/// [`Storage::enqueue_file_background_jobs`], but the queue was only ever drained
/// by the admin-only `POST /debug/jobs/run` route and the service-twin route. In
/// production nothing drained it, so uploaded images never got thumbnails, file
/// content was never search-indexed, and previews never generated. This worker
/// runs the exact same drain the debug route runs, on a timer, for the life of
/// the process.
///
/// Design:
/// - [`Storage::run_queued_background_jobs`] is a synchronous rusqlite call, so
///   it runs inside [`tokio::task::spawn_blocking`] to never block the async
///   runtime.
/// - The loop never panics: a drain error (or a worker-task panic) is logged and
///   the loop keeps ticking, so one bad file cannot wedge the pipeline.
/// - Each tick first checks the queued count (a cheap `COUNT(*)`) and skips the
///   full drain when nothing is queued, so an idle server does almost no work.
/// - The interval's first tick fires immediately, so any backlog left by a prior
///   run clears shortly after boot rather than after a full interval.
///
/// The returned handle is detached by [`serve`]; tests hold it so they can abort
/// the worker when the test server is torn down.
pub fn spawn_background_worker(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let data_dir = state.data_dir();
        let mut ticker =
            tokio::time::interval(Duration::from_secs(BACKGROUND_WORKER_INTERVAL_SECS));
        let mut ticks_until_reap = 0_u64;
        // If a drain ever overruns the interval, don't stack up bursts of ticks.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            // First tick is immediate → drains any boot-time backlog promptly.
            ticker.tick().await;
            drain_background_jobs_once(&state, &data_dir).await;
            upload_cleanup::reconcile_upload_parts_once(&state).await;
            if ticks_until_reap == 0 {
                reap_stale_uploads_once(&state, &data_dir).await;
                ticks_until_reap = STALE_UPLOAD_REAPER_INTERVAL_TICKS;
            }
            ticks_until_reap = ticks_until_reap.saturating_sub(1);
        }
    })
}

async fn reap_stale_uploads_once(state: &AppState, _data_dir: &Path) {
    let Ok(mutation_permit) = state.try_mutation_permit() else {
        return;
    };
    let storage = state.storage.clone();
    let reaper_state = state.clone();
    let outcome = tokio::task::spawn_blocking(move || -> ApiResult<(usize, usize)> {
        let _mutation_permit = mutation_permit;
        let upload_ids = storage.stale_upload_session_ids(STALE_UPLOAD_MAX_AGE_SECONDS)?;
        let uploads = crate::routes::uploads::cleanup::reap_upload_candidates_lock_safe(
            &reaper_state,
            upload_ids,
            STALE_UPLOAD_MAX_AGE_SECONDS,
        )?;
        let drop_session_ids =
            storage.stale_drop_upload_session_ids(STALE_UPLOAD_MAX_AGE_SECONDS)?;
        let drops = crate::routes::drop_uploads::reap_stale_drop_upload_candidates_lock_safe(
            &reaper_state,
            drop_session_ids,
            STALE_UPLOAD_MAX_AGE_SECONDS,
        )?;
        Ok((uploads.len(), drops.len()))
    })
    .await;
    match outcome {
        Ok(Ok((uploads, drops))) if uploads + drops > 0 => {
            tracing::info!(
                uploads,
                drops,
                "stale upload reaper canceled abandoned sessions"
            );
        }
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::warn!(%error, "stale upload reaper failed"),
        Err(join_error) => tracing::warn!(%join_error, "stale upload reaper task panicked"),
    }
}

/// Run one drain pass entirely off the async runtime. Errors are logged, never
/// propagated, so the worker loop survives transient failures. A no-op when the
/// queue is empty.
async fn drain_background_jobs_once(state: &AppState, data_dir: &Path) {
    let Ok(mutation_permit) = state.try_mutation_permit() else {
        return;
    };
    let storage = state.storage.clone();
    let data_dir = data_dir.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        let _mutation_permit = mutation_permit;
        // Cheap guard: skip the drain (and the full job-list scan it performs)
        // when nothing is queued.
        match storage.background_job_totals() {
            Ok(totals) if totals.queued == 0 => Ok(None),
            Ok(_) => storage.run_queued_background_jobs(&data_dir).map(Some),
            Err(error) => Err(error),
        }
    })
    .await;
    match outcome {
        Ok(Ok(Some(summary))) if summary.processed > 0 => {
            tracing::info!(
                processed = summary.processed,
                succeeded = summary.succeeded,
                failed = summary.failed,
                skipped = summary.skipped,
                "background worker drained job queue"
            );
        }
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::warn!(%error, "background worker drain failed"),
        Err(join_error) => tracing::warn!(%join_error, "background worker task panicked"),
    }
}

#[cfg(test)]
mod client_identity_tests {
    use super::*;

    #[test]
    fn forwarding_headers_require_an_explicit_loopback_proxy_trust_boundary() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("198.51.100.23"),
        );
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let remote: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let forwarded: std::net::IpAddr = "198.51.100.23".parse().unwrap();

        assert_eq!(
            resolved_client_ip(Some(loopback), &headers, false),
            loopback
        );
        assert_eq!(
            resolved_client_ip(Some(loopback), &headers, true),
            forwarded
        );
        assert_eq!(resolved_client_ip(Some(remote), &headers, true), remote);
    }

    #[test]
    fn cookie_mutation_origin_accepts_only_the_configured_origin_or_referer() {
        let configured = "https://drive.example.test";
        let mut exact_origin = axum::http::HeaderMap::new();
        exact_origin.insert(header::ORIGIN, configured.parse().unwrap());
        assert!(browser_mutation_is_same_origin(&exact_origin, configured));

        let mut same_origin_referer = axum::http::HeaderMap::new();
        same_origin_referer.insert(
            header::REFERER,
            HeaderValue::from_static("https://drive.example.test/files?selected=one"),
        );
        assert!(browser_mutation_is_same_origin(
            &same_origin_referer,
            configured
        ));

        let mut foreign_origin = axum::http::HeaderMap::new();
        foreign_origin.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        foreign_origin.insert(
            header::REFERER,
            HeaderValue::from_static("https://drive.example.test/"),
        );
        assert!(!browser_mutation_is_same_origin(
            &foreign_origin,
            configured
        ));

        for origin in [
            "",
            "   ",
            "null",
            "https://drive.example.test/",
            "not-an-origin",
        ] {
            let mut invalid_origin = axum::http::HeaderMap::new();
            invalid_origin.insert(header::ORIGIN, origin.parse().unwrap());
            invalid_origin.insert(
                header::REFERER,
                HeaderValue::from_static("https://drive.example.test/"),
            );
            assert!(!browser_mutation_is_same_origin(
                &invalid_origin,
                configured
            ));
        }

        let mut non_utf8_origin = axum::http::HeaderMap::new();
        non_utf8_origin.insert(
            header::ORIGIN,
            HeaderValue::from_bytes(&[0xFF]).expect("valid opaque header bytes"),
        );
        non_utf8_origin.insert(
            header::REFERER,
            HeaderValue::from_static("https://drive.example.test/"),
        );
        assert!(!browser_mutation_is_same_origin(
            &non_utf8_origin,
            configured
        ));

        for referer in [
            "https://evil.example/attack",
            "http://drive.example.test/",
            "https://drive.example.test:444/",
            "https://drive.example.test.evil.example/",
            "https://attacker@drive.example.test/",
            "not-a-url",
        ] {
            let mut foreign_referer = axum::http::HeaderMap::new();
            foreign_referer.insert(header::REFERER, referer.parse().unwrap());
            assert!(!browser_mutation_is_same_origin(
                &foreign_referer,
                configured
            ));
        }
        assert!(!browser_mutation_is_same_origin(
            &axum::http::HeaderMap::new(),
            configured
        ));
    }
}

#[cfg(test)]
mod detached_mutation_tests;

#[cfg(all(test, unix))]
mod stale_upload_reaper_tests {
    use std::os::{fd::AsRawFd as _, unix::fs::MetadataExt as _};

    use rusqlite::params;

    use super::*;
    use crate::{
        config::Config,
        storage::{
            DropCreateFields, DropUploadAdmissionPolicy, DropUploadSessionCreate,
            UploadAdmissionPolicy, UploadSessionCreate,
        },
    };

    fn test_config(data_dir: std::path::PathBuf) -> Config {
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir,
            token: "test-token".to_string(),
            bootstrap_token: None,
            e2e_enabled: true,
            email_transport: "capture".to_string(),
            email_from: "ShellX Drive <noreply@example.test>".to_string(),
            public_origin: crate::config::PublicOrigin::parse("http://127.0.0.1:5758").unwrap(),
            email_smtp_host_source: "not_configured".to_string(),
            email_smtp_port: None,
            email_smtp_user_source: "not_configured".to_string(),
            maintenance_token_source: "not_configured".to_string(),
            maintenance_sudo_source: "not_configured".to_string(),
            local_session_ttl_seconds: 2_592_000,
            office_provider_name: "Office editor".to_string(),
            office_provider_url: None,
            office_session_ttl_seconds: 900,
            hosted_mode: false,
            hosted_billing_provider: "none".to_string(),
            hosted_public_rate_limit_per_minute: 60,
            backup_max_archive_bytes: 9 * 1024 * 1024 * 1024 * 1024,
            secure_cookies: false,
            trust_proxy_headers: false,
            update_repo: None,
        }
    }

    mod startup_reconciliation;

    #[tokio::test]
    async fn automatic_reaper_skips_a_locked_session_and_preserves_its_lock_inode() {
        let temp = tempfile::tempdir().unwrap();
        let state = AppState::open(test_config(temp.path().to_path_buf())).unwrap();
        let (workspace, _, _) = state
            .storage
            .create_workspace("Automatic cleanup", "owner@example.test")
            .unwrap();
        let session = state
            .storage
            .create_upload_session(
                UploadSessionCreate {
                    workspace_id: &workspace.id,
                    actor_email: "owner@example.test",
                    parent_id: None,
                    name: "automatic-reaper.bin",
                    total_size: Some(7),
                    path: None,
                    duplicate_policy: "keep_both",
                },
                UploadAdmissionPolicy::default(),
            )
            .unwrap();
        rusqlite::Connection::open(temp.path().join("drive.db"))
            .unwrap()
            .execute(
                "UPDATE upload_sessions SET updated_at = ?1 WHERE id = ?2",
                params!["2000-01-01T00:00:00+00:00", &session.id],
            )
            .unwrap();

        let upload_dir = state.data_dir().join("uploads");
        std::fs::create_dir_all(&upload_dir).unwrap();
        let part_path = upload_dir.join(format!("{}.part", session.id));
        let lock_path = upload_dir.join(format!("{}.lock", session.id));
        std::fs::write(&part_path, b"partial").unwrap();
        std::fs::write(&lock_path, b"stable lock").unwrap();
        let lock_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let lock_inode = lock_file.metadata().unwrap().ino();

        reap_stale_uploads_once(&state, temp.path()).await;
        assert!(part_path.exists());
        assert!(
            !state
                .storage
                .get_upload_session(&session.id)
                .unwrap()
                .unwrap()
                .canceled
        );
        assert_eq!(lock_path.metadata().unwrap().ino(), lock_inode);

        assert_eq!(
            unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) },
            0
        );
        drop(lock_file);

        reap_stale_uploads_once(&state, temp.path()).await;
        assert!(!part_path.exists());
        assert!(
            state
                .storage
                .get_upload_session(&session.id)
                .unwrap()
                .unwrap()
                .canceled
        );
        assert_eq!(lock_path.metadata().unwrap().ino(), lock_inode);
    }

    #[tokio::test]
    async fn automatic_reaper_skips_a_locked_drop_session_and_preserves_its_lock_inode() {
        let temp = tempfile::tempdir().unwrap();
        let state = AppState::open(test_config(temp.path().to_path_buf())).unwrap();
        let (workspace, _, _) = state
            .storage
            .create_workspace("Drop cleanup", "owner@example.test")
            .unwrap();
        let operator = crate::auth::Actor {
            email: "system@local".to_string(),
            is_admin: true,
            auth_mode: crate::auth::AuthMode::Operator,
            allowed_workspace_ids: None,
        };
        let (drop_link, _) = state
            .storage
            .create_drop(
                DropCreateFields {
                    workspace_id: &workspace.id,
                    name: "Stale drop inbox",
                    password_hash: "drop-password-hash",
                    password_required: true,
                    expires_in_seconds: 3_600,
                },
                &operator,
                &crate::auth::DriveCredential::Operator,
            )
            .unwrap();
        let authorization_fingerprint = state
            .storage
            .get_drop(&drop_link.id)
            .unwrap()
            .unwrap()
            .authorization_fingerprint();
        let session = state
            .storage
            .create_drop_upload_session(DropUploadSessionCreate {
                drop_id: &drop_link.id,
                workspace_id: &workspace.id,
                client_fingerprint: "drop-client",
                transport_fingerprint: "drop-transport",
                expected_authorization_fingerprint: &authorization_fingerprint,
                name: "automatic-reaper.bin",
                path: None,
                content_type: Some("application/octet-stream"),
                total_size: 7,
                policy: DropUploadAdmissionPolicy::default(),
            })
            .unwrap()
            .0;
        rusqlite::Connection::open(temp.path().join("drive.db"))
            .unwrap()
            .execute(
                "UPDATE drop_upload_sessions SET updated_at = ?1 WHERE id = ?2",
                params!["2000-01-01T00:00:00+00:00", &session.id],
            )
            .unwrap();

        let drop_dir = state.data_dir().join("drop-uploads");
        std::fs::create_dir_all(&drop_dir).unwrap();
        let part_path = drop_dir.join(format!("{}.part", session.id));
        let lock_path = drop_dir.join(format!("{}.lock", session.id));
        std::fs::write(&part_path, b"partial").unwrap();
        std::fs::write(&lock_path, b"stable lock").unwrap();
        let lock_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let lock_inode = lock_file.metadata().unwrap().ino();

        reap_stale_uploads_once(&state, temp.path()).await;
        assert!(part_path.exists());
        assert_eq!(
            state
                .storage
                .get_drop_upload_session(&session.id)
                .unwrap()
                .unwrap()
                .status,
            "active"
        );
        assert_eq!(lock_path.metadata().unwrap().ino(), lock_inode);

        assert_eq!(
            unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) },
            0
        );
        drop(lock_file);

        reap_stale_uploads_once(&state, temp.path()).await;
        assert!(!part_path.exists());
        assert_eq!(
            state
                .storage
                .get_drop_upload_session(&session.id)
                .unwrap()
                .unwrap()
                .status,
            "canceled"
        );
        assert_eq!(lock_path.metadata().unwrap().ino(), lock_inode);
    }
}
