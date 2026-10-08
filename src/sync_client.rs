//! Reference two-way desktop sync client for ShellX Drive.
//!
//! This is the Drive-side implementation of the contract in
//! `docs/public/DESKTOP_SYNC_CONTRACT.md`. It is a thin `reqwest` consumer of
//! the server's `/sync/*`, `/files/*`, and `/uploads/*` routes; it holds no
//! database and no server state.
//!
//! Responsibilities per `sync_once()`:
//! - **Download** (pre-existing): list actor-visible workspaces, write manifest
//!   snapshots, download file bodies, record safe-space metadata, and snapshot
//!   conflicts plus receipts.
//! - **Upload** (this module's two-way extension): detect NEW and CHANGED local
//!   files under each workspace's `content/` directory and push them to
//!   Drive (create via `POST /files` or the resumable session; update via
//!   `PUT /files/{id}/content` or the delta route), using the SHA-256 hex
//!   `content_hash` as the change-detection primitive and a per-workspace
//!   `sync-state.json` baseline to classify local vs remote change.
//!
//! Conservative v1 semantics (see the contract doc, §9): no delete propagation
//! in either direction (report-only); a both-changed conflict never overwrites
//! either side — the local file is kept, the remote bytes are written alongside
//! with a `.remote-conflict` suffix, and the conflict is counted; a second
//! `sync_once()` with no changes is a no-op (idempotent, so it can run on a
//! timer without re-upload loops).
//!
//! Primary callers: `src/bin/shellx-drive-sync.rs` (the `sync-once` CLI) and
//! `tests/desktop_sync_client.rs` (in-process integration tests).

use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::model::{DriveFile, FileKind, UploadSession, Workspace};
use crate::sync_client_fs::{
    ensure_cache_directory, ensure_cache_root, SafeCacheRoot, SafeDownloadTarget, SafeLocalSnapshot,
};

mod budget;
mod download_publication;
mod profile;
mod response_binding;
mod tls;

use budget::SyncPassBudget;
pub use budget::SyncPassLimits;
use download_publication::{DownloadPublication, DownloadPublicationOutcome};

/// Largest content the client sends through the simple, single-request routes
/// (`POST /files`, `PUT /files/{id}/content`). Above this — or for any non-UTF-8
/// bytes — it switches to the chunked resumable/delta paths. Kept well under the
/// server's 2 MiB request body limit so the JSON envelope always fits.
const SIMPLE_UPLOAD_MAX_BYTES: usize = 1024 * 1024;

/// Raw bytes per resumable chunk. Base64 inflates ~1.37×, so 512 KiB stays under
/// the 2 MiB body limit with margin.
const RESUMABLE_CHUNK_SIZE: usize = 512 * 1024;

/// Chunk size used for delta updates. The client slices the new content by this
/// size and aligns it against the server's chunk manifest of the same size, so
/// unchanged aligned chunks are reused via `copy` and only changed chunks are
/// sent as `data`.
/// A single remote body may never consume more local disk than the server's
/// corresponding upload/session ceiling. The expected manifest size is also
/// enforced while streaming so a lying or corrupted response is rejected
/// before it can grow without bound.
const MAX_SYNC_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_SYNC_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_SYNC_RESPONSE_ITEMS: usize = 10_000;
const MAX_SYNC_LOCAL_FILE_CANDIDATES: usize = 10_000;
const MAX_SYNC_LOCAL_FILENAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_SYNC_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SYNC_STATE_BYTES: u64 = 16 * 1024 * 1024;
/// Reserved suffix for preserved conflict bodies. Remote conflicts use a
/// revision-and-hash-bound filename; a local leaf that changes during a remote
/// replacement uses a random recovery filename. Neither path is replaced.
const REMOTE_CONFLICT_SUFFIX: &str = ".remote-conflict";

/// Immutable client configuration. Backward compatible with the download-only
/// client: all fields are unchanged; upload is enabled automatically for open
/// workspaces.
#[derive(Clone)]
pub struct SyncClientConfig {
    /// Base URL of the Drive server, e.g. `https://drive.example.test`.
    pub base_url: String,
    /// Bearer token (server token or `sso.v1` session token).
    pub token: String,
    /// Local sync root. Manifests, bodies, and `sync-state.json` live here.
    pub cache_dir: PathBuf,
    /// Optional `x-shellx-actor` identity for multi-user, actor-scoped sync.
    pub actor_email: Option<String>,
    /// When non-empty, only these workspace ids are synced.
    pub selected_workspace_ids: Vec<String>,
    /// Workspace ids for which a local `safe-space.json` marker is written.
    pub safe_space_workspace_ids: Vec<String>,
}

/// A stateless HTTP consumer of the Drive sync/upload API. Cheap to clone.
#[derive(Clone)]
pub struct SyncClient {
    config: SyncClientConfig,
    http: reqwest::Client,
    additional_ca_sha256: Option<String>,
    pass_limits: SyncPassLimits,
    adopt_existing_cache: bool,
}

/// Result of one full `sync_once()` pass.
#[derive(Debug)]
pub struct SyncReport {
    pub workspaces: Vec<WorkspaceSyncReport>,
    pub conflicts: SyncConflictSummary,
    pub receipts: Option<ReceiptSummary>,
}

/// Per-workspace outcome. The first six fields are the pre-existing
/// download-only report; the rest describe the two-way upload pass.
#[derive(Debug)]
pub struct WorkspaceSyncReport {
    pub workspace_id: String,
    pub name: String,
    pub storage_mode: String,
    /// Number of active files/folders in the bounded remote manifest.
    pub file_count: usize,
    /// Bodies written to the local cache this pass (fresh pulls + remote-changed
    /// updates + re-pulls of locally-deleted tracked files).
    pub downloaded_files: usize,
    pub safe_space: bool,
    /// New local files created on the server this pass.
    pub uploaded_new: usize,
    /// Existing files whose changed local content was pushed as a new revision.
    pub uploaded_updated: usize,
    /// Subset of uploads (new or update) that used the chunked resumable/delta
    /// transport rather than a single simple request.
    pub resumable_uploads: usize,
    /// Both-changed conflicts detected this pass (remote saved as
    /// `.remote-conflict`, nothing overwritten), plus any server-side `409`
    /// races encountered while uploading.
    pub skipped_conflicts: usize,
}

impl WorkspaceSyncReport {
    /// Total files pushed to the server this pass (new + updated).
    pub fn uploaded_files(&self) -> usize {
        self.uploaded_new + self.uploaded_updated
    }
}

#[derive(Debug)]
pub struct SyncConflictSummary {
    pub total: usize,
}

#[derive(Debug)]
pub struct ReceiptSummary {
    pub count: usize,
    pub newest_kind: Option<String>,
}

// --- Response envelopes (server model types are serialize-only, so the client
// declares its own deserialize views over the JSON it needs) ---------------

#[derive(Deserialize)]
struct WorkspaceListResponse {
    workspaces: Vec<Workspace>,
}

#[derive(Deserialize)]
struct MeResponseView {
    actor: String,
}

#[derive(Deserialize)]
struct WorkspaceManifestResponse {
    files: Vec<DriveFile>,
}

#[derive(Deserialize)]
struct SyncConflictsResponse {
    conflicts: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct ReceiptsResponse {
    receipts: Vec<DebugReceiptView>,
}

#[derive(Deserialize)]
struct DebugReceiptView {
    kind: String,
}

/// Minimal view of the `{ "file": DriveFile, ... }` envelope returned by
/// `POST /files`, `PUT /files/{id}/content`, and the delta route.
#[derive(Deserialize)]
struct FileEnvelope {
    file: DriveFile,
}

/// Minimal view of an upload session envelope (`{ "session": {...} }`).
#[derive(Deserialize)]
struct UploadSessionEnvelope {
    session: UploadSession,
}

#[derive(Deserialize)]
struct UploadSessionView {
    id: String,
}

/// Minimal view of an upload-chunk response; the finishing chunk carries `file`.
#[derive(Deserialize)]
struct UploadChunkEnvelope {
    session: UploadSessionView,
    file: Option<DriveFile>,
    /// Replacement completion can preserve uploaded bytes as a server-side
    /// conflict file while returning HTTP 200 for resumable terminal retries.
    #[serde(default)]
    conflict: Option<serde_json::Value>,
}

// --- Local persisted state -------------------------------------------------

/// Per-file baseline recorded at the last successful sync. `content_hash` +
/// `revision` are the "common ancestor" used to classify local vs remote change.
#[derive(Clone, Serialize, Deserialize)]
struct FileSyncState {
    content_hash: String,
    revision: i64,
}

/// Per-workspace sync state, persisted as `workspaces/<id>/sync-state.json`.
#[derive(Default, Serialize, Deserialize)]
struct WorkspaceSyncState {
    /// file id → last-synced baseline.
    files: HashMap<String, FileSyncState>,
}

#[derive(Serialize)]
struct SafeSpaceMetadata<'a> {
    workspace_id: &'a str,
    storage_mode: &'a str,
    local_agent_visible: bool,
}

/// Outcome of a content-update write (`PUT content` or delta).
enum ContentWriteOutcome {
    /// The server accepted the write and advanced the file to `revision`.
    Updated { revision: i64, content_hash: String },
    /// The server rejected the base revision and forked a conflict copy (409).
    Conflict,
}

/// Whether a create/update went over the chunked transport (for reporting).
enum UploadTransport {
    Simple,
    Chunked,
}

const SYNC_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

impl SyncClient {
    pub fn new(mut config: SyncClientConfig) -> anyhow::Result<Self> {
        config.base_url = profile::validate_base_url(&config.base_url)?;
        Ok(Self {
            config,
            http: tls::build_http_client(None)?,
            additional_ca_sha256: None,
            pass_limits: SyncPassLimits::default(),
            adopt_existing_cache: false,
        })
    }

    /// Select an isolated cache profile and, only when explicitly requested,
    /// adopt a non-empty cache created before profile markers existed. Keeping
    /// this policy on the client preserves the v0.1 `SyncClientConfig` struct-
    /// literal API for existing embedders.
    pub fn with_profile(
        mut self,
        profile_name: Option<&str>,
        adopt_existing_cache: bool,
    ) -> anyhow::Result<Self> {
        if let Some(profile_name) = profile_name {
            profile::validate_name(profile_name)?;
            self.config.cache_dir = self.config.cache_dir.join("profiles").join(profile_name);
        }
        self.adopt_existing_cache = adopt_existing_cache;
        Ok(self)
    }

    /// Add a private Drive certificate authority to this client's trust roots.
    /// This never changes the operating-system trust store and never disables
    /// normal TLS certificate or hostname verification.
    pub fn with_additional_ca_file(mut self, path: &Path) -> anyhow::Result<Self> {
        let additional_ca = tls::read_additional_ca(path)?;
        self.http = tls::build_http_client(Some(&additional_ca))?;
        self.additional_ca_sha256 = Some(additional_ca.sha256);
        Ok(self)
    }

    pub fn with_pass_limits(mut self, limits: SyncPassLimits) -> Self {
        self.pass_limits = limits;
        self
    }

    /// Run one full reconcile pass: download remote state, then upload new and
    /// changed local files, for every selected (or all visible) workspace.
    ///
    /// Workspaces are synced two-way. Returns a per-workspace report plus
    /// conflict/receipt snapshots. Idempotent: a second call with no
    /// local or remote change performs no network writes.
    pub async fn sync_once(&self) -> anyhow::Result<SyncReport> {
        tokio::time::timeout(self.pass_limits.max_elapsed, self.sync_once_bounded())
            .await
            .context("sync pass exceeded its elapsed-time budget")?
    }

    async fn sync_once_bounded(&self) -> anyhow::Result<SyncReport> {
        let mut budget = SyncPassBudget::new(self.pass_limits);
        let cache_root = ensure_cache_root(&self.config.cache_dir)
            .context("sync cache root is not a safe real directory")?;
        profile::preflight(
            &cache_root,
            &self.config.base_url,
            self.additional_ca_sha256.as_deref(),
            self.adopt_existing_cache,
        )?;
        budget.add_requests(1)?;
        let actor = self.resolved_actor().await?;
        profile::bind(
            &cache_root,
            &self.config.base_url,
            &actor,
            self.additional_ca_sha256.as_deref(),
            self.adopt_existing_cache,
        )?;
        let selected_workspace_ids = self
            .config
            .selected_workspace_ids
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let safe_space_workspace_ids = self
            .config
            .safe_space_workspace_ids
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        budget.add_requests(1)?;
        let workspaces = self
            .list_workspaces()
            .await?
            .into_iter()
            .filter(|workspace| {
                selected_workspace_ids.is_empty() || selected_workspace_ids.contains(&workspace.id)
            })
            .collect::<Vec<_>>();
        budget.admit_workspaces(workspaces.len())?;
        budget.add_requests(2)?;
        let conflicts = self
            .sync_conflicts()
            .await
            .unwrap_or(SyncConflictSummary { total: 0 });
        let receipts = self.receipt_summary().await.ok();
        let mut reports = Vec::with_capacity(workspaces.len());

        for workspace in workspaces {
            budget.check_elapsed()?;
            validate_remote_cache_id("workspace", &workspace.id)?;
            budget.add_requests(1)?;
            let manifest = self.workspace_manifest(&workspace.id).await?;
            budget.add_manifest_items(manifest.files.len())?;
            validate_workspace_manifest_ids(&workspace.id, &manifest.files)?;
            let workspace_dir =
                ensure_cache_directory(&cache_root, &Path::new("workspaces").join(&workspace.id))?;
            write_json(
                &cache_root,
                workspace_dir.join("workspace.json"),
                &workspace,
            )?;
            write_json(
                &cache_root,
                workspace_dir.join("files.json"),
                &manifest.files,
            )?;
            let safe_space = safe_space_workspace_ids.contains(&workspace.id);
            if safe_space {
                write_json(
                    &cache_root,
                    workspace_dir.join("safe-space.json"),
                    &SafeSpaceMetadata {
                        workspace_id: &workspace.id,
                        storage_mode: &workspace.storage_mode,
                        local_agent_visible: false,
                    },
                )?;
            }

            let mut report = WorkspaceSyncReport {
                workspace_id: workspace.id.clone(),
                name: workspace.name.clone(),
                storage_mode: workspace.storage_mode.clone(),
                file_count: manifest.files.len(),
                downloaded_files: 0,
                safe_space,
                uploaded_new: 0,
                uploaded_updated: 0,
                resumable_uploads: 0,
                skipped_conflicts: 0,
            };
            self.sync_open_workspace(
                &cache_root,
                &workspace.id,
                &workspace_dir,
                &manifest.files,
                &mut report,
                &mut budget,
            )
            .await?;

            reports.push(report);
        }

        Ok(SyncReport {
            workspaces: reports,
            conflicts,
            receipts,
        })
    }

    /// Reconcile one open workspace's `content/` directory against the remote
    /// manifest and the recorded baseline, downloading remote changes and
    /// uploading local ones. Mutates `report`'s counters.
    async fn sync_open_workspace(
        &self,
        cache_root: &SafeCacheRoot,
        workspace_id: &str,
        workspace_dir: &Path,
        manifest_files: &[DriveFile],
        report: &mut WorkspaceSyncReport,
        budget: &mut SyncPassBudget,
    ) -> anyhow::Result<()> {
        let workspace_relative = workspace_dir
            .strip_prefix(cache_root.path())
            .map_err(|_| anyhow::anyhow!("workspace cache path escaped its configured root"))?;
        let content_dir = ensure_cache_directory(cache_root, &workspace_relative.join("content"))?;
        let state_path = workspace_dir.join("sync-state.json");
        let mut state = load_state(cache_root, &state_path)?;

        // Every id present in the manifest (any kind) — used to tell a genuinely
        // new local file (human name) from a tracked body (id-named).
        let known_ids = manifest_files
            .iter()
            .map(|file| file.id.clone())
            .collect::<HashSet<_>>();

        // Downloadable remote files: real files, not trashed, with content.
        let remote_files = manifest_files
            .iter()
            .filter(|file| matches!(file.kind, FileKind::File) && !file.trashed)
            .filter(|file| file.content_hash.is_some())
            .collect::<Vec<_>>();

        // Files whose changed local content must be pushed (collected in the
        // reconcile pass, uploaded in the next pass so a borrow of `state` is not
        // held across the await).
        let mut pending_updates: Vec<PendingUpdate> = Vec::new();

        // --- Pass 1: reconcile each remote file against local + baseline ------
        for file in &remote_files {
            let remote_hash = file.content_hash.clone().expect("filtered to Some");
            let local_path = content_dir.join(&file.id);
            let local = open_local_snapshot_if_exists(cache_root, &local_path)?;
            let baseline = state.files.get(&file.id).cloned();

            match (local, baseline) {
                // No local copy: fresh download, or a re-pull of a tracked file
                // the user deleted locally (v1 does not propagate deletes).
                (None, _) => {
                    self.download_file_content_to_path(
                        cache_root,
                        file,
                        &local_path,
                        DownloadPublication::New,
                        budget,
                    )
                    .await?;
                    state.files.insert(
                        file.id.clone(),
                        FileSyncState {
                            content_hash: remote_hash,
                            revision: file.revision,
                        },
                    );
                    report.downloaded_files += 1;
                }
                // Local body present but never tracked (e.g. a cache produced by
                // the old download-only client). Adopt if identical; otherwise
                // preserve both and adopt the remote as the new baseline.
                (Some(local), None) => {
                    if local.hash() == remote_hash {
                        state.files.insert(
                            file.id.clone(),
                            FileSyncState {
                                content_hash: remote_hash,
                                revision: file.revision,
                            },
                        );
                    } else {
                        self.write_remote_conflict(cache_root, &content_dir, file, budget)
                            .await?;
                        state.files.insert(
                            file.id.clone(),
                            FileSyncState {
                                content_hash: remote_hash,
                                revision: file.revision,
                            },
                        );
                        report.skipped_conflicts += 1;
                    }
                }
                // Tracked: classify by comparing both sides to the baseline.
                (Some(local), Some(baseline)) => {
                    let local_changed = local.hash() != baseline.content_hash;
                    let remote_changed = remote_hash != baseline.content_hash;
                    match (local_changed, remote_changed) {
                        (false, false) => {}
                        (false, true) => {
                            let expected_local_hash = baseline.content_hash.clone();
                            let retained_local_bytes = local.length();
                            drop(local);
                            let publication = self
                                .download_file_content_to_path(
                                    cache_root,
                                    file,
                                    &local_path,
                                    DownloadPublication::TrackedReplacement {
                                        expected_local_hash,
                                        retained_local_bytes,
                                    },
                                    budget,
                                )
                                .await?;
                            state.files.insert(
                                file.id.clone(),
                                FileSyncState {
                                    content_hash: remote_hash,
                                    revision: file.revision,
                                },
                            );
                            report.downloaded_files += 1;
                            if matches!(
                                publication,
                                DownloadPublicationOutcome::PreservedChangedLocal
                            ) {
                                report.skipped_conflicts += 1;
                            }
                        }
                        (true, false) => {
                            pending_updates.push(PendingUpdate {
                                file_id: file.id.clone(),
                                base_revision: file.revision,
                                local,
                            });
                        }
                        (true, true) => {
                            if local.hash() == remote_hash {
                                // Both sides converged on the same bytes.
                                state.files.insert(
                                    file.id.clone(),
                                    FileSyncState {
                                        content_hash: remote_hash,
                                        revision: file.revision,
                                    },
                                );
                            } else {
                                // True conflict: keep local, save remote alongside,
                                // touch nothing on the server, keep the baseline so
                                // the state stays classified as conflicting until a
                                // human resolves it.
                                self.write_remote_conflict(cache_root, &content_dir, file, budget)
                                    .await?;
                                report.skipped_conflicts += 1;
                            }
                        }
                    }
                }
            }
        }

        // --- Pass 2: upload changed local content ----------------------------
        for mut update in pending_updates {
            budget.reserve_upload(update.local.length())?;
            let (outcome, transport) = self
                .upload_content_update(
                    workspace_id,
                    &update.file_id,
                    &mut update.local,
                    update.base_revision,
                )
                .await?;
            match outcome {
                ContentWriteOutcome::Updated {
                    revision,
                    content_hash,
                } => {
                    if content_hash != update.local.hash() {
                        bail!("remote update response did not match the uploaded snapshot hash");
                    }
                    state.files.insert(
                        update.file_id.clone(),
                        FileSyncState {
                            content_hash: update.local.hash().to_string(),
                            revision,
                        },
                    );
                    report.uploaded_updated += 1;
                    if matches!(transport, UploadTransport::Chunked) {
                        report.resumable_uploads += 1;
                    }
                }
                ContentWriteOutcome::Conflict => {
                    // Server forked a conflict copy under us (a race). Leave local
                    // state untouched; the next pass re-reconciles against a fresh
                    // manifest.
                    report.skipped_conflicts += 1;
                }
            }
        }

        // --- Pass 3: upload genuinely new local files ------------------------
        for new_name in scan_new_local_files(cache_root, &content_dir, &known_ids, &state)? {
            let source = content_dir.join(&new_name);
            let mut local = open_local_snapshot(cache_root, &source)?;
            budget.reserve_upload(local.length())?;
            let local_hash = local.hash().to_string();
            let local_size = local.length();
            let (created, transport) = self
                .upload_new_file(workspace_id, &new_name, &mut local)
                .await?;
            response_binding::validate_created_file(
                &created,
                workspace_id,
                &new_name,
                &local_hash,
                local_size,
            )?;
            if known_ids.contains(&created.id) || state.files.contains_key(&created.id) {
                bail!("remote create response reused an existing file id");
            }
            // Rename the human-named file to its server id so it becomes a
            // tracked body and is not re-uploaded next pass.
            let dest = content_dir.join(&created.id);
            drop(local);
            if source != dest {
                cache_root.rename_new(&source, &dest)?;
            }
            state.files.insert(
                created.id.clone(),
                FileSyncState {
                    content_hash: local_hash,
                    revision: created.revision,
                },
            );
            report.uploaded_new += 1;
            if matches!(transport, UploadTransport::Chunked) {
                report.resumable_uploads += 1;
            }
        }

        save_state(cache_root, &state_path, &state)?;
        Ok(())
    }

    /// Download the remote body beside the local file under a content-bound,
    /// non-replacing conflict name. An identical retained copy is idempotent;
    /// a modified reserved conflict leaf fails closed instead of being replaced.
    async fn write_remote_conflict(
        &self,
        cache_root: &SafeCacheRoot,
        content_dir: &Path,
        file: &DriveFile,
        budget: &mut SyncPassBudget,
    ) -> anyhow::Result<()> {
        let conflict_path = download_publication::remote_conflict_path(content_dir, file)?;
        if download_publication::existing_remote_conflict_is_current(
            cache_root,
            &conflict_path,
            file.content_hash
                .as_deref()
                .context("sync manifest omitted the remote content hash")?,
            MAX_SYNC_DOWNLOAD_BYTES,
        )? {
            return Ok(());
        }
        self.download_file_content_to_path(
            cache_root,
            file,
            &conflict_path,
            DownloadPublication::New,
            budget,
        )
        .await
        .map(|_| ())
    }

    /// Create a new file on the server, choosing the simple JSON route for small
    /// UTF-8 content and the chunked resumable route otherwise. Returns the
    /// created file and which transport was used.
    async fn upload_new_file(
        &self,
        workspace_id: &str,
        name: &str,
        source: &mut SafeLocalSnapshot,
    ) -> anyhow::Result<(DriveFile, UploadTransport)> {
        if source.length() <= SIMPLE_UPLOAD_MAX_BYTES as u64 {
            let bytes = source.read_all()?;
            if let Ok(text) = std::str::from_utf8(&bytes) {
                let file = self.create_file_simple(workspace_id, name, text).await?;
                return Ok((file, UploadTransport::Simple));
            }
        }
        let file = self
            .create_file_resumable(workspace_id, name, source)
            .await?;
        Ok((file, UploadTransport::Chunked))
    }

    /// `POST /files` with an inline UTF-8 content string.
    async fn create_file_simple(
        &self,
        workspace_id: &str,
        name: &str,
        content: &str,
    ) -> anyhow::Result<DriveFile> {
        let response = self
            .authorized(reqwest::Method::POST, "/files")
            .json(&json!({
                "workspace_id": workspace_id,
                "name": name,
                "kind": "file",
                "content": content,
            }))
            .send()
            .await?
            .error_for_status()
            .context("POST /files failed")?;
        let envelope: FileEnvelope =
            decode_json_limited(response, MAX_SYNC_ENVELOPE_BYTES, "file create").await?;
        Ok(envelope.file)
    }

    /// Create a file through a resumable session, streaming base64 chunks. Works
    /// for binary and large content within the server's per-request body limit.
    async fn create_file_resumable(
        &self,
        workspace_id: &str,
        name: &str,
        source: &mut SafeLocalSnapshot,
    ) -> anyhow::Result<DriveFile> {
        let total_size = source.length();
        let response = self
            .authorized(reqwest::Method::POST, "/uploads/resumable")
            .json(&json!({
                "workspace_id": workspace_id,
                "name": name,
                "total_size": total_size as i64,
            }))
            .send()
            .await?
            .error_for_status()
            .context("POST /uploads/resumable failed")?;
        let session: UploadSessionEnvelope =
            decode_json_limited(response, MAX_SYNC_ENVELOPE_BYTES, "upload session").await?;
        response_binding::validate_new_upload_session(
            &session.session,
            workspace_id,
            name,
            total_size,
        )?;
        let upload_id = session.session.id;

        // An empty file still needs one finishing request so the server
        // materialises a zero-byte body.
        if total_size == 0 {
            let response = self.put_resumable_chunk(&upload_id, 0, &[], true).await?;
            if response.conflict.is_some() {
                bail!("new resumable upload unexpectedly completed as a conflict");
            }
            return response
                .file
                .context("finishing resumable chunk did not return a file");
        }

        source.rewind()?;
        let mut offset = 0_u64;
        let mut created: Option<DriveFile> = None;
        let mut chunk = vec![0_u8; RESUMABLE_CHUNK_SIZE];
        let mut transmitted_hash = Sha256::new();
        let expected_hash = source.hash().to_string();
        while offset < total_size {
            let count = usize::try_from((total_size - offset).min(RESUMABLE_CHUNK_SIZE as u64))?;
            source.file_mut().read_exact(&mut chunk[..count])?;
            let finish = offset + count as u64 == total_size;
            transmitted_hash.update(&chunk[..count]);
            if finish && hex::encode(transmitted_hash.clone().finalize()) != expected_hash {
                bail!("local sync input changed while its resumable upload was in progress");
            }
            let response = self
                .put_resumable_chunk(&upload_id, offset as i64, &chunk[..count], finish)
                .await?;
            if finish {
                if response.conflict.is_some() {
                    bail!("new resumable upload unexpectedly completed as a conflict");
                }
                created = response.file;
            }
            offset += count as u64;
        }
        created.context("resumable upload did not return a created file")
    }

    /// Append (or finish) one resumable chunk.
    async fn put_resumable_chunk(
        &self,
        upload_id: &str,
        offset: i64,
        chunk: &[u8],
        finish: bool,
    ) -> anyhow::Result<UploadChunkEnvelope> {
        let response = self
            .authorized(
                reqwest::Method::PUT,
                &format!("/uploads/resumable/{upload_id}"),
            )
            .json(&json!({
                "offset": offset,
                "content_base64": STANDARD.encode(chunk),
                "finish": finish,
            }))
            .send()
            .await?
            .error_for_status()
            .context("PUT /uploads/resumable chunk failed")?;
        let envelope: UploadChunkEnvelope =
            decode_json_limited(response, MAX_SYNC_ENVELOPE_BYTES, "upload chunk").await?;
        response_binding::validate_chunk_session_id(&envelope.session.id, upload_id)?;
        Ok(envelope)
    }

    /// Update an existing file's content, choosing `PUT …/content` for small
    /// UTF-8 content and the streaming resumable route otherwise. Returns the write outcome
    /// (updated/conflict) and which transport was used.
    async fn upload_content_update(
        &self,
        workspace_id: &str,
        file_id: &str,
        source: &mut SafeLocalSnapshot,
        base_revision: i64,
    ) -> anyhow::Result<(ContentWriteOutcome, UploadTransport)> {
        if source.length() <= SIMPLE_UPLOAD_MAX_BYTES as u64 {
            let bytes = source.read_all()?;
            if let Ok(text) = std::str::from_utf8(&bytes) {
                let outcome = self
                    .put_content_simple(workspace_id, file_id, text, base_revision)
                    .await?;
                return Ok((outcome, UploadTransport::Simple));
            }
        }
        let outcome = self
            .replace_file_resumable(workspace_id, file_id, source, base_revision)
            .await?;
        Ok((outcome, UploadTransport::Chunked))
    }

    /// `PUT /files/{id}/content` with an inline UTF-8 string. `200` → updated,
    /// `409` → stale-base conflict (server forked a conflict copy).
    async fn put_content_simple(
        &self,
        workspace_id: &str,
        file_id: &str,
        content: &str,
        base_revision: i64,
    ) -> anyhow::Result<ContentWriteOutcome> {
        let response = self
            .authorized(reqwest::Method::PUT, &format!("/files/{file_id}/content"))
            .json(&json!({
                "base_revision": base_revision,
                "content": content,
            }))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Ok(ContentWriteOutcome::Conflict);
        }
        let response = response
            .error_for_status()
            .context("PUT /files/{id}/content failed")?;
        let envelope: FileEnvelope =
            decode_json_limited(response, MAX_SYNC_ENVELOPE_BYTES, "file update").await?;
        let expected_hash = hex::encode(Sha256::digest(content.as_bytes()));
        response_binding::validate_updated_file(
            &envelope.file,
            workspace_id,
            file_id,
            base_revision,
            &expected_hash,
            content.len() as u64,
        )?;
        Ok(ContentWriteOutcome::Updated {
            revision: envelope.file.revision,
            content_hash: expected_hash,
        })
    }

    /// Stream a large, fully changed existing body through a resumable
    /// replacement session. The server owns the target's workspace/name/parent
    /// from `target_file_id`; this client supplies only the immutable target,
    /// its baseline revision, and byte count.
    async fn replace_file_resumable(
        &self,
        workspace_id: &str,
        file_id: &str,
        source: &mut SafeLocalSnapshot,
        base_revision: i64,
    ) -> anyhow::Result<ContentWriteOutcome> {
        let total_size = source.length();
        let response = self
            .authorized(reqwest::Method::POST, "/uploads/resumable")
            .json(&json!({
                "target_file_id": file_id,
                "base_revision": base_revision,
                "total_size": total_size as i64,
            }))
            .send()
            .await?
            .error_for_status()
            .context("POST replacement resumable session failed")?;
        let session: UploadSessionEnvelope = decode_json_limited(
            response,
            MAX_SYNC_ENVELOPE_BYTES,
            "replacement upload session",
        )
        .await?;
        response_binding::validate_replacement_upload_session(
            &session.session,
            workspace_id,
            file_id,
            base_revision,
            total_size,
        )?;
        let upload_id = session.session.id;
        let expected_hash = source.hash().to_string();

        if total_size == 0 {
            return self.replacement_completion_outcome(
                workspace_id,
                file_id,
                base_revision,
                &expected_hash,
                total_size,
                self.put_resumable_chunk(&upload_id, 0, &[], true).await?,
            );
        }

        source.rewind()?;
        let mut offset = 0_u64;
        let mut chunk = vec![0_u8; RESUMABLE_CHUNK_SIZE];
        let mut transmitted_hash = Sha256::new();
        while offset < total_size {
            let count = usize::try_from((total_size - offset).min(RESUMABLE_CHUNK_SIZE as u64))?;
            source.file_mut().read_exact(&mut chunk[..count])?;
            let finish = offset + count as u64 == total_size;
            transmitted_hash.update(&chunk[..count]);
            if finish && hex::encode(transmitted_hash.clone().finalize()) != expected_hash {
                bail!("local sync input changed while its resumable replacement was in progress");
            }
            let response = self
                .put_resumable_chunk(&upload_id, offset as i64, &chunk[..count], finish)
                .await?;
            offset += count as u64;
            if finish {
                return self.replacement_completion_outcome(
                    workspace_id,
                    file_id,
                    base_revision,
                    &expected_hash,
                    total_size,
                    response,
                );
            }
        }
        bail!("replacement resumable upload did not send a terminal chunk")
    }

    fn replacement_completion_outcome(
        &self,
        workspace_id: &str,
        file_id: &str,
        base_revision: i64,
        expected_hash: &str,
        expected_size: u64,
        response: UploadChunkEnvelope,
    ) -> anyhow::Result<ContentWriteOutcome> {
        if response.conflict.is_some() {
            return Ok(ContentWriteOutcome::Conflict);
        }
        let file = response
            .file
            .context("replacement resumable completion did not return a file")?;
        response_binding::validate_updated_file(
            &file,
            workspace_id,
            file_id,
            base_revision,
            expected_hash,
            expected_size,
        )?;
        Ok(ContentWriteOutcome::Updated {
            revision: file.revision,
            content_hash: expected_hash.to_string(),
        })
    }

    async fn list_workspaces(&self) -> anyhow::Result<Vec<Workspace>> {
        let response = self
            .authorized(reqwest::Method::GET, "/sync/workspaces")
            .send()
            .await?
            .error_for_status()?;
        let response: WorkspaceListResponse =
            decode_json_limited(response, MAX_SYNC_JSON_BYTES, "workspace list").await?;
        if response.workspaces.len() > MAX_SYNC_RESPONSE_ITEMS {
            bail!(
                "workspace list exceeds its {}-item limit",
                MAX_SYNC_RESPONSE_ITEMS
            );
        }
        Ok(response.workspaces)
    }

    async fn resolved_actor(&self) -> anyhow::Result<String> {
        let response = self
            .authorized(reqwest::Method::GET, "/auth/me")
            .send()
            .await?
            .error_for_status()?;
        let response: MeResponseView =
            decode_json_limited(response, MAX_SYNC_JSON_BYTES, "sync account identity").await?;
        let actor = response.actor.trim().to_ascii_lowercase();
        if actor.is_empty() || actor.len() > 320 {
            bail!("sync account identity is invalid");
        }
        Ok(actor)
    }

    async fn workspace_manifest(
        &self,
        workspace_id: &str,
    ) -> anyhow::Result<WorkspaceManifestResponse> {
        let response = self
            .authorized(
                reqwest::Method::GET,
                &format!("/sync/workspaces/{workspace_id}/manifest"),
            )
            .send()
            .await?
            .error_for_status()?;
        let manifest: WorkspaceManifestResponse =
            decode_json_limited(response, MAX_SYNC_JSON_BYTES, "workspace manifest").await?;
        if manifest.files.len() > MAX_SYNC_RESPONSE_ITEMS {
            bail!(
                "workspace manifest exceeds its {}-item limit",
                MAX_SYNC_RESPONSE_ITEMS
            );
        }
        Ok(manifest)
    }

    async fn download_file_content_to_path(
        &self,
        cache_root: &SafeCacheRoot,
        file: &DriveFile,
        destination: &Path,
        publication: DownloadPublication,
        budget: &mut SyncPassBudget,
    ) -> anyhow::Result<DownloadPublicationOutcome> {
        let expected_size = file
            .size_bytes
            .context("sync manifest omitted the remote file size")?;
        let expected_size = u64::try_from(expected_size)
            .context("sync manifest reported a negative remote file size")?;
        if expected_size > MAX_SYNC_DOWNLOAD_BYTES {
            bail!(
                "remote file {} exceeds the {}-byte sync download limit",
                file.id,
                MAX_SYNC_DOWNLOAD_BYTES
            );
        }
        match &publication {
            DownloadPublication::TrackedReplacement {
                retained_local_bytes,
                ..
            } => {
                budget.reserve_recovery(cache_root, *retained_local_bytes)?;
            }
            DownloadPublication::New
                if destination.file_name().is_some_and(|name| {
                    name.as_encoded_bytes()
                        .ends_with(REMOTE_CONFLICT_SUFFIX.as_bytes())
                }) =>
            {
                budget.reserve_recovery(cache_root, expected_size)?;
            }
            DownloadPublication::New => {}
        }
        budget.reserve_download(cache_root.path(), expected_size)?;
        let expected_hash = file
            .content_hash
            .as_deref()
            .context("sync manifest omitted the remote content hash")?;
        let mut response = self
            .authorized(reqwest::Method::GET, &format!("/files/{}/content", file.id))
            .send()
            .await?
            .error_for_status()?;
        if let Some(declared_size) = response.content_length() {
            if declared_size != expected_size {
                bail!(
                    "remote file {} declared {declared_size} bytes but the manifest expected {expected_size}",
                    file.id
                );
            }
        }

        let mut target = SafeDownloadTarget::begin(cache_root, destination).with_context(|| {
            format!("failed to bind safe destination {}", destination.display())
        })?;
        let transfer: anyhow::Result<()> = async {
            let mut received = 0_u64;
            let mut hasher = Sha256::new();
            while let Some(chunk) = tokio::time::timeout(SYNC_BODY_IDLE_TIMEOUT, response.chunk())
                .await
                .context("remote file download stalled past its idle deadline")??
            {
                received = received
                    .checked_add(chunk.len() as u64)
                    .context("remote download byte count overflowed")?;
                if received > expected_size || received > MAX_SYNC_DOWNLOAD_BYTES {
                    bail!(
                        "remote file {} exceeded its expected {}-byte download budget",
                        file.id,
                        expected_size
                    );
                }
                hasher.update(&chunk);
                target.file_mut().write_all(&chunk)?;
            }
            if received != expected_size {
                bail!(
                    "remote file {} ended at {received} bytes but the manifest expected {expected_size}",
                    file.id
                );
            }
            let actual_hash = format!("{:x}", hasher.finalize());
            if actual_hash != expected_hash {
                bail!("remote file {} failed content-hash verification", file.id);
            }
            Ok(())
        }
        .await;
        transfer?;
        let prepared = download_publication::prepare(cache_root, destination, publication)
            .with_context(|| {
                format!(
                    "failed to preserve the reconciled local state for {}",
                    destination.display()
                )
            })?;
        download_publication::admit_prepared(cache_root, destination, &prepared, budget)
            .with_context(|| {
                format!(
                    "failed to admit retained local body for {}",
                    destination.display()
                )
            })?;
        target.commit_new().with_context(|| {
            format!(
                "failed to publish verified download to {}",
                destination.display()
            )
        })?;
        download_publication::finish(cache_root, prepared).with_context(|| {
            format!(
                "verified download reached {}, but local recovery cleanup failed",
                destination.display()
            )
        })
    }

    async fn sync_conflicts(&self) -> anyhow::Result<SyncConflictSummary> {
        let response = self
            .authorized(reqwest::Method::GET, "/sync/conflicts")
            .send()
            .await?
            .error_for_status()?;
        let response: SyncConflictsResponse =
            decode_json_limited(response, MAX_SYNC_JSON_BYTES, "sync conflicts").await?;
        if response.conflicts.len() > MAX_SYNC_RESPONSE_ITEMS {
            bail!("sync conflicts response exceeds its item limit");
        }
        Ok(SyncConflictSummary {
            total: response.conflicts.len(),
        })
    }

    async fn receipt_summary(&self) -> anyhow::Result<ReceiptSummary> {
        let response = self
            .authorized(reqwest::Method::GET, "/debug/receipts")
            .send()
            .await?
            .error_for_status()?;
        let response: ReceiptsResponse =
            decode_json_limited(response, MAX_SYNC_JSON_BYTES, "receipt summary").await?;
        if response.receipts.len() > MAX_SYNC_RESPONSE_ITEMS {
            bail!("receipt summary response exceeds its item limit");
        }
        Ok(ReceiptSummary {
            count: response.receipts.len(),
            newest_kind: response.receipts.last().map(|receipt| receipt.kind.clone()),
        })
    }

    /// Build a request with the bearer token and the optional actor header
    /// applied. All Drive calls go through here so auth is uniform.
    fn authorized(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let request = self
            .http
            .request(method, self.url(path))
            .bearer_auth(&self.config.token);
        if let Some(actor_email) = self.config.actor_email.as_deref() {
            request.header("X-ShellX-Actor", actor_email)
        } else {
            request
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url.trim_end_matches('/'), path)
    }
}

/// A local file whose content changed and must be pushed as a new revision.
struct PendingUpdate {
    file_id: String,
    base_revision: i64,
    local: SafeLocalSnapshot,
}

/// Enumerate regular files directly under `content_dir` that are genuinely new
/// local files: not a `.remote-conflict` sidecar, not a known remote id
/// (tracked body), and not already recorded in state. Returned names are the raw
/// file names to upload.
fn scan_new_local_files(
    cache_root: &SafeCacheRoot,
    content_dir: &Path,
    known_ids: &HashSet<String>,
    state: &WorkspaceSyncState,
) -> anyhow::Result<Vec<String>> {
    let mut new_files = Vec::new();
    for name in cache_root.regular_file_names(
        content_dir,
        MAX_SYNC_LOCAL_FILE_CANDIDATES,
        MAX_SYNC_LOCAL_FILENAME_BYTES,
    )? {
        let name = name.to_string_lossy().into_owned();
        if name.ends_with(REMOTE_CONFLICT_SUFFIX) {
            continue;
        }
        if known_ids.contains(&name) || state.files.contains_key(&name) {
            continue;
        }
        new_files.push(name);
    }
    // Deterministic order so a report and any test observe a stable sequence.
    new_files.sort();
    Ok(new_files)
}

/// The Drive protocol generates UUID workspace and file identifiers. Require
/// their canonical lowercase-hyphenated form before using any remote identifier
/// as a cache path component; accepting a generic string here would let a
/// malicious or compromised server steer writes outside the sync cache.
fn validate_remote_cache_id(kind: &str, id: &str) -> anyhow::Result<()> {
    let parsed = Uuid::parse_str(id)
        .with_context(|| format!("invalid remote {kind} id for local cache path"))?;
    if parsed.hyphenated().to_string() != id {
        bail!("invalid remote {kind} id for local cache path");
    }
    Ok(())
}

/// Validate all identifiers in a remote manifest before the reconciliation
/// pass reaches any `Path::join` call. `workspace_id` and `parent_id` are also
/// remote IDs, even though only `file.id` becomes a local body filename.
fn validate_workspace_manifest_ids(workspace_id: &str, files: &[DriveFile]) -> anyhow::Result<()> {
    for file in files {
        validate_remote_cache_id("file", &file.id)?;
        validate_remote_cache_id("workspace", &file.workspace_id)?;
        if file.workspace_id != workspace_id {
            bail!(
                "remote file {} belongs to workspace {} instead of {}",
                file.id,
                file.workspace_id,
                workspace_id
            );
        }
        if let Some(parent_id) = file.parent_id.as_deref() {
            validate_remote_cache_id("file parent", parent_id)?;
        }
    }
    Ok(())
}

/// Open and hash a regular local leaf without following links. The retained
/// handle is the same object later streamed to the server.
fn open_local_snapshot_if_exists(
    cache_root: &SafeCacheRoot,
    path: &Path,
) -> anyhow::Result<Option<SafeLocalSnapshot>> {
    match SafeLocalSnapshot::open(cache_root, path, MAX_SYNC_DOWNLOAD_BYTES) {
        Ok(input) => Ok(Some(input)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn open_local_snapshot(
    cache_root: &SafeCacheRoot,
    path: &Path,
) -> anyhow::Result<SafeLocalSnapshot> {
    Ok(SafeLocalSnapshot::open(
        cache_root,
        path,
        MAX_SYNC_DOWNLOAD_BYTES,
    )?)
}

/// Load per-workspace sync state; a missing file yields empty state.
fn load_state(cache_root: &SafeCacheRoot, path: &Path) -> anyhow::Result<WorkspaceSyncState> {
    match SafeLocalSnapshot::open(cache_root, path, MAX_SYNC_STATE_BYTES) {
        Ok(mut input) => {
            let bytes = input.read_all()?;
            serde_json::from_slice(&bytes).context("failed to parse workspace sync-state.json")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(WorkspaceSyncState::default())
        }
        Err(error) => bail!("failed to read sync-state.json: {error}"),
    }
}

fn save_state(
    cache_root: &SafeCacheRoot,
    path: &Path,
    state: &WorkspaceSyncState,
) -> anyhow::Result<()> {
    write_json(cache_root, path, state)
}

fn write_json(
    cache_root: &SafeCacheRoot,
    path: impl AsRef<Path>,
    value: &impl serde::Serialize,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() as u64 > MAX_SYNC_STATE_BYTES {
        bail!("local sync metadata exceeds its bounded size");
    }
    let mut target = SafeDownloadTarget::begin(cache_root, path.as_ref())?;
    target.file_mut().write_all(&bytes)?;
    target.commit()?;
    Ok(())
}

async fn decode_json_limited<T: DeserializeOwned>(
    mut response: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> anyhow::Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("{label} response exceeds its {max_bytes}-byte limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = tokio::time::timeout(SYNC_BODY_IDLE_TIMEOUT, response.chunk())
        .await
        .with_context(|| format!("{label} response stalled past its idle deadline"))??
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > max_bytes)
        {
            bail!("{label} response exceeds its {max_bytes}-byte limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).with_context(|| format!("failed to decode {label} response"))
}
