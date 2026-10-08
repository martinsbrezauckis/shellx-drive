use std::{
    fs,
    io::{Cursor, Read},
    path::Path,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::{
    converge_sync_roots, mirror::SIMPLE_EXISTING_REPLACEMENT_LIMIT, DesktopError,
    RemoteSessionRecord, Result, SyncCycleBudget, SyncRoot, SyncRootKind, MAX_DISCOVERY_ROOTS,
};

#[path = "http/manifest_budget.rs"]
mod manifest_budget;

const RESUMABLE_CHUNK_BYTES: usize = crate::budget::RESUMABLE_UPLOAD_CHUNK_BYTES as usize;
pub const MAX_SYNC_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_SYNC_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_SYNC_RESPONSE_ITEMS: usize = 10_000;
const MAX_ENVELOPE_JSON_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub storage_mode: String,
    pub archived: bool,
    /// Legacy workspace-list callers do not supply root authority metadata.
    /// Keep it when present so adapter/UI layers never erase a server-provided
    /// owner label, grant identity, or effective role while migrating to
    /// `/sync/roots`.
    #[serde(default)]
    pub owner_label: Option<String>,
    #[serde(default)]
    pub grant_id: Option<String>,
    #[serde(default)]
    pub role: Option<crate::SyncRootRole>,
}

/// A root-bound manifest. The returned root is current server authority, not
/// merely the discovery snapshot supplied by the caller; its role or expiry
/// can be narrowed before the client plans any remote mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncRootManifest {
    pub root: SyncRoot,
    pub scoped: bool,
    pub next_cursor: i64,
    pub files: Vec<RemoteFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteFileKind {
    File,
    Folder,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteFile {
    pub id: String,
    pub workspace_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: RemoteFileKind,
    pub revision: i64,
    pub trashed: bool,
    pub content_hash: Option<String>,
    pub size_bytes: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteChange {
    pub id: i64,
    pub workspace_id: String,
    pub kind: String,
    pub entity_type: String,
    pub entity_id: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerValidation {
    pub normalized_url: String,
    pub setup_required: bool,
}

/// Deliberately not `Debug`: a debugger or accidental structured log must not
/// print a bearer token returned by password login.
pub enum LoginOutcome {
    Authenticated {
        bearer_token: String,
        account_email: String,
        is_admin: bool,
        session_id: String,
        expires_at: DateTime<Utc>,
    },
    RequiresSecondFactor {
        account_email: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutOutcome {
    Revoked,
    AlreadyInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteSessionRevocationOutcome {
    Revoked,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExistingFileTransfer {
    Updated(RemoteFile),
    Conflict,
    /// A deliberately user-visible block. A legacy server did not expose the
    /// optimistic resumable replacement session, so no bytes were sent to an
    /// unsafe substitute endpoint.
    UnsupportedResumableReplacement {
        size_bytes: u64,
        required_endpoint: &'static str,
    },
}

/// Outcome of a revision-checked metadata move. A rejected metadata update is
/// intentionally distinct from a transport failure so the shell can preserve
/// both sides as a review instead of projecting an unsafe completed sync.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteMoveTransfer {
    Moved(RemoteFile),
    Conflict,
    NeedsReview,
}

#[derive(Clone)]
pub struct DriveHttpClient {
    base_url: Url,
    http: Client,
    cycle_budget: Option<SyncCycleBudget>,
}

trait CycleBudgetedRequest {
    async fn send_with_cycle_budget(self, budget: Option<&SyncCycleBudget>) -> Result<Response>;
}

impl CycleBudgetedRequest for reqwest::RequestBuilder {
    async fn send_with_cycle_budget(self, budget: Option<&SyncCycleBudget>) -> Result<Response> {
        if let Some(budget) = budget {
            budget.charge_transport_request()?;
        }
        Ok(self.send().await?)
    }
}

impl DriveHttpClient {
    pub fn new(server_url: &str) -> Result<Self> {
        let base_url = normalize_server_url(server_url)?;
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .user_agent("ShellX-Drive-Desktop/0.1.0")
            .build()?;
        Ok(Self {
            base_url,
            http,
            cycle_budget: None,
        })
    }

    pub fn with_cycle_budget(mut self, budget: &SyncCycleBudget) -> Self {
        self.cycle_budget = Some(budget.clone());
        self
    }

    pub fn normalized_url(&self) -> &str {
        self.base_url.as_str().trim_end_matches('/')
    }

    /// Verify that this is a reachable Drive local-auth server before a
    /// password is sent. The response contains no account secret.
    pub async fn validate_server(&self) -> Result<ServerValidation> {
        let response = self
            .request(Method::GET, "/auth/bootstrap/status")
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let body: BootstrapStatus = self
            .decode_json_limited(response, MAX_ENVELOPE_JSON_BYTES, "bootstrap status")
            .await?;
        Ok(ServerValidation {
            normalized_url: self.normalized_url().to_string(),
            setup_required: body.required,
        })
    }

    pub async fn login_password(&self, email: &str, password: &str) -> Result<LoginOutcome> {
        self.login(LoginPayload {
            email,
            password,
            totp_code: None,
            recovery_code: None,
        })
        .await
    }

    /// Continues the same login contract in-place after a 202, using exactly
    /// one of a TOTP code or recovery code. The original password remains only
    /// in the caller's transient form state.
    pub async fn continue_login(
        &self,
        email: &str,
        password: &str,
        totp_code: Option<&str>,
        recovery_code: Option<&str>,
    ) -> Result<LoginOutcome> {
        if totp_code.is_some() == recovery_code.is_some() {
            return Err(DesktopError::InvalidState(
                "provide exactly one TOTP code or recovery code".to_string(),
            ));
        }
        self.login(LoginPayload {
            email,
            password,
            totp_code,
            recovery_code,
        })
        .await
    }

    async fn login(&self, payload: LoginPayload<'_>) -> Result<LoginOutcome> {
        let response = self
            .request(Method::POST, "/auth/login")
            .json(&serde_json::json!({
                "email": payload.email,
                "password": payload.password,
                "totp_code": payload.totp_code,
                "recovery_code": payload.recovery_code,
                "cookie_only": false,
            }))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let status = response.status();
        if status != StatusCode::OK && status != StatusCode::ACCEPTED {
            return Err(server_error(status));
        }
        let login: LoginResponse = self
            .decode_json_limited(response, MAX_ENVELOPE_JSON_BYTES, "login")
            .await?;
        if status == StatusCode::ACCEPTED || login.requires_2fa {
            return Ok(LoginOutcome::RequiresSecondFactor {
                account_email: login.actor,
            });
        }
        authenticated_login_outcome(self.normalized_url(), login)
    }

    pub async fn validate_session(&self, bearer_token: &str) -> Result<String> {
        let response = self
            .authorized(Method::GET, "/auth/me", bearer_token)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let me: MeResponse = self
            .decode_json_limited(response, MAX_ENVELOPE_JSON_BYTES, "session validation")
            .await?;
        Ok(me.actor)
    }

    pub async fn list_workspaces(&self, bearer_token: &str) -> Result<Vec<Workspace>> {
        let response = self
            .authorized(Method::GET, "/sync/workspaces", bearer_token)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let workspaces: WorkspaceListResponse = self
            .decode_json_limited(response, MAX_SYNC_JSON_BYTES, "workspace list")
            .await?;
        if workspaces.workspaces.len() > MAX_SYNC_RESPONSE_ITEMS {
            return Err(DesktopError::InvalidState(format!(
                "Drive workspace list exceeds the {MAX_SYNC_RESPONSE_ITEMS}-item limit"
            )));
        }
        Ok(workspaces
            .workspaces
            .into_iter()
            .filter(|workspace| !workspace.archived)
            .collect())
    }

    /// Discover every root the current account may synchronize. The opaque
    /// root subject remains route data only; local namespace labels come from
    /// the separately bounded owner/root presentation fields.
    pub async fn discover_sync_roots(&self, bearer_token: &str) -> Result<Vec<SyncRoot>> {
        let response = self
            .authorized(Method::GET, "/sync/roots", bearer_token)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_root_discovery_success(response).await?;
        let discovery: SyncRootDiscoveryResponse = self
            .decode_json_limited(response, MAX_SYNC_JSON_BYTES, "sync root discovery")
            .await?;
        validate_sync_root_discovery(discovery)
    }

    /// Browse one bounded page of available roots. A page is presentation data;
    /// pairing revalidates the selected root separately before publication.
    pub async fn discover_sync_root_page(
        &self,
        bearer_token: &str,
        cursor: Option<&str>,
    ) -> Result<SyncRootPage> {
        self.discover_sync_root_page_limited(bearer_token, cursor, 50)
            .await
    }

    pub async fn discover_sync_root_page_limited(
        &self,
        bearer_token: &str,
        cursor: Option<&str>,
        limit: u8,
    ) -> Result<SyncRootPage> {
        if !(1..=50).contains(&limit) {
            return Err(DesktopError::InvalidState(
                "invalid Drive root page limit".to_string(),
            ));
        }
        if cursor.is_some_and(|value| value.is_empty() || value.len() > 2_048) {
            return Err(DesktopError::InvalidState(
                "invalid Drive root cursor".to_string(),
            ));
        }
        let mut url = self.url("/sync/roots/page");
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
        if let Some(cursor) = cursor {
            url.query_pairs_mut().append_pair("cursor", cursor);
        }
        let response = self
            .http
            .request(Method::GET, url)
            .bearer_auth(bearer_token)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let page: SyncRootPage = self
            .decode_json_limited(response, MAX_ENVELOPE_JSON_BYTES, "sync root page")
            .await?;
        validate_sync_root_page(page, cursor, limit)
    }

    /// Resolve one picker choice under current server authority. Missing and
    /// revoked choices have the same outcome; labels and roles are never input.
    pub async fn revalidate_selected_sync_root(
        &self,
        bearer_token: &str,
        root_id: &str,
        workspace_id: &str,
        root_file_id: Option<&str>,
    ) -> Result<SyncRoot> {
        if root_id.is_empty()
            || root_id.len() > 4_096
            || workspace_id.is_empty()
            || workspace_id.len() > 4_096
        {
            return Err(DesktopError::InvalidState(
                "invalid selected Drive root".to_string(),
            ));
        }
        let response = self
            .authorized(Method::POST, "/sync/roots/revalidate", bearer_token)
            .json(&serde_json::json!({"root_ids": [root_id]}))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let result: ConfiguredRootRevalidationResponse = self
            .decode_json_limited(
                response,
                MAX_ENVELOPE_JSON_BYTES,
                "selected root revalidation",
            )
            .await?;
        validate_selected_root_revalidation(root_id, workspace_id, root_file_id, result)
    }

    /// Refresh only already configured root subjects when unrelated shares make
    /// full discovery overflow. The server checks all IDs under one credential
    /// and storage transaction; a partial or mismatched reply is never used.
    pub async fn revalidate_configured_sync_roots(
        &self,
        bearer_token: &str,
        configured: &[SyncRoot],
    ) -> Result<Vec<SyncRoot>> {
        if configured.len() > MAX_DISCOVERY_ROOTS {
            return Err(DesktopError::InvalidState(
                "too many configured Drive roots".to_string(),
            ));
        }
        let ids = configured
            .iter()
            .map(|root| root.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if ids.len() != configured.len() {
            return Err(DesktopError::InvalidState(
                "duplicate configured Drive root ID".to_string(),
            ));
        }
        let response = self
            .authorized(Method::POST, "/sync/roots/revalidate", bearer_token)
            .json(&serde_json::json!({"root_ids": ids}))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let result: ConfiguredRootRevalidationResponse = decode_json_limited_with_budget(
            response,
            MAX_ENVELOPE_JSON_BYTES,
            "configured root revalidation",
            self.cycle_budget.as_ref(),
            false,
        )
        .await?;
        validate_configured_root_revalidation(configured, result)
    }

    /// Fetch the exact root's currently authorized manifest. Item grants must
    /// use this scoped route: falling back to a workspace manifest would leak
    /// sibling metadata before local filtering could run.
    pub async fn sync_root_manifest(
        &self,
        bearer_token: &str,
        requested_root: &SyncRoot,
    ) -> Result<SyncRootManifest> {
        requested_root.validate()?;
        match self
            .fetch_sync_root_manifest(bearer_token, requested_root)
            .await
        {
            Err(error) if access_generation_precondition_failed(&error) => {
                let refreshed_root = refreshed_manifest_root(
                    requested_root,
                    self.revalidate_configured_sync_roots(
                        bearer_token,
                        std::slice::from_ref(requested_root),
                    )
                    .await?,
                )?;
                self.fetch_sync_root_manifest(bearer_token, &refreshed_root)
                    .await
            }
            result => result,
        }
    }

    async fn fetch_sync_root_manifest(
        &self,
        bearer_token: &str,
        requested_root: &SyncRoot,
    ) -> Result<SyncRootManifest> {
        let response = self
            .http
            .request(Method::GET, self.sync_root_manifest_url(requested_root)?)
            .bearer_auth(bearer_token)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let manifest: SyncRootManifestResponse = decode_json_limited_with_budget(
            response,
            MAX_SYNC_JSON_BYTES,
            "sync root manifest",
            self.cycle_budget.as_ref(),
            true,
        )
        .await?;
        validate_sync_root_manifest(requested_root, manifest)
    }

    pub async fn workspace_manifest(
        &self,
        bearer_token: &str,
        workspace_id: &str,
    ) -> Result<Vec<RemoteFile>> {
        let response = self
            .authorized(
                Method::GET,
                &format!("/sync/workspaces/{workspace_id}/manifest"),
                bearer_token,
            )
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let manifest: ManifestResponse = self
            .decode_json_limited(response, MAX_SYNC_JSON_BYTES, "workspace manifest")
            .await?;
        validate_workspace_manifest(workspace_id, manifest)
    }

    pub async fn workspace_changes(
        &self,
        bearer_token: &str,
        workspace_id: &str,
        cursor: i64,
    ) -> Result<(i64, Vec<RemoteChange>)> {
        let response = self
            .authorized(
                Method::GET,
                &format!(
                    "/sync/workspaces/{workspace_id}/changes?cursor={}",
                    cursor.max(0)
                ),
                bearer_token,
            )
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let response = require_success(response).await?;
        let changes: ChangesResponse = self
            .decode_json_limited(response, MAX_SYNC_JSON_BYTES, "workspace changes")
            .await?;
        if changes.changes.len() > MAX_SYNC_RESPONSE_ITEMS {
            return Err(DesktopError::InvalidState(format!(
                "Drive change response exceeds the {MAX_SYNC_RESPONSE_ITEMS}-item limit"
            )));
        }
        Ok((changes.next_cursor, changes.changes))
    }

    /// Streams a download to a caller-provided sink. The desktop shell writes
    /// the chunks to an owned temporary file, hashes them, then atomically
    /// publishes only a verified body. No full remote file needs to be held in
    /// memory by this contract.
    pub async fn download_file_chunks(
        &self,
        bearer_token: &str,
        file_id: &str,
        expected_size: u64,
        mut sink: impl FnMut(&[u8]) -> std::io::Result<()>,
    ) -> Result<()> {
        let response = self
            .authorized(
                Method::GET,
                &format!("/files/{file_id}/content"),
                bearer_token,
            )
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let mut response = require_success(response).await?;
        validate_download_size(expected_size, response.content_length())?;
        let mut received = 0_u64;
        while let Some(chunk) = response.chunk().await? {
            received = advance_download_budget(received, chunk.len(), expected_size)?;
            sink(&chunk)?;
        }
        if received != expected_size {
            return Err(DesktopError::InvalidState(format!(
                "Drive download ended at {received} bytes but the manifest expected {expected_size}"
            )));
        }
        Ok(())
    }

    pub async fn create_folder(
        &self,
        bearer_token: &str,
        workspace_id: &str,
        parent_id: Option<&str>,
        name: &str,
    ) -> Result<RemoteFile> {
        let response = self
            .authorized(Method::POST, "/files", bearer_token)
            .json(&serde_json::json!({
                "workspace_id": workspace_id,
                "parent_id": parent_id,
                "name": name,
                "kind": "folder",
            }))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let envelope: FileEnvelope = self.decode_success_json(response, "folder create").await?;
        Ok(envelope.file)
    }

    /// Upload a new body. New large/binary files use the existing resumable
    /// create contract; only *existing-file* replacement is intentionally
    /// blocked when it exceeds the bounded update route.
    pub async fn upload_new_file(
        &self,
        bearer_token: &str,
        workspace_id: &str,
        parent_id: Option<&str>,
        name: &str,
        bytes: &[u8],
    ) -> Result<RemoteFile> {
        if bytes.len() as u64 <= SIMPLE_EXISTING_REPLACEMENT_LIMIT {
            if let Ok(content) = std::str::from_utf8(bytes) {
                let response = self
                    .authorized(Method::POST, "/files", bearer_token)
                    .json(&serde_json::json!({
                        "workspace_id": workspace_id,
                        "parent_id": parent_id,
                        "name": name,
                        "kind": "file",
                        "content": content,
                    }))
                    .send_with_cycle_budget(self.cycle_budget.as_ref())
                    .await?;
                let envelope: FileEnvelope =
                    self.decode_success_json(response, "file create").await?;
                return Ok(envelope.file);
            }
        }
        self.upload_new_resumable(bearer_token, workspace_id, parent_id, name, bytes)
            .await
    }

    /// Bounded upload variant for a filesystem body. New bodies larger than
    /// the simple route are read one resumable chunk at a time.
    pub async fn upload_new_file_from_path(
        &self,
        bearer_token: &str,
        workspace_id: &str,
        parent_id: Option<&str>,
        name: &str,
        path: &Path,
        size_bytes: u64,
    ) -> Result<RemoteFile> {
        self.upload_new_file_from_reader(
            bearer_token,
            workspace_id,
            parent_id,
            name,
            fs::File::open(path)?,
            size_bytes,
        )
        .await
    }

    /// Handle-based variant used by the Windows shell after it has opened a
    /// checked no-follow local source. Holding that handle prevents a later
    /// path swap from changing the bytes this request reads.
    pub async fn upload_new_file_from_reader(
        &self,
        bearer_token: &str,
        workspace_id: &str,
        parent_id: Option<&str>,
        name: &str,
        mut reader: impl Read,
        size_bytes: u64,
    ) -> Result<RemoteFile> {
        if size_bytes <= SIMPLE_EXISTING_REPLACEMENT_LIMIT {
            let size = usize::try_from(size_bytes).map_err(|_| {
                DesktopError::InvalidState("bounded upload size cannot fit in memory".to_string())
            })?;
            let mut bytes = vec![0; size];
            reader.read_exact(&mut bytes)?;
            return self
                .upload_new_file(bearer_token, workspace_id, parent_id, name, &bytes)
                .await;
        }
        self.upload_new_resumable_from_reader(
            bearer_token,
            workspace_id,
            parent_id,
            name,
            reader,
            size_bytes,
        )
        .await
    }

    pub async fn replace_existing_file(
        &self,
        bearer_token: &str,
        file_id: &str,
        base_revision: i64,
        bytes: &[u8],
    ) -> Result<ExistingFileTransfer> {
        if bytes.len() as u64 > SIMPLE_EXISTING_REPLACEMENT_LIMIT
            || std::str::from_utf8(bytes).is_err()
        {
            return self
                .replace_existing_resumable_from_reader(
                    bearer_token,
                    file_id,
                    base_revision,
                    Cursor::new(bytes),
                    bytes.len() as u64,
                )
                .await;
        }
        self.replace_existing_utf8(
            bearer_token,
            file_id,
            base_revision,
            std::str::from_utf8(bytes).expect("UTF-8 checked above"),
        )
        .await
    }

    /// Replacement path used by the desktop executor. Only a bounded simple
    /// text body is read into memory; binary and large updates are streamed
    /// through the optimistic resumable session in 512 KiB chunks.
    pub async fn replace_existing_file_from_path(
        &self,
        bearer_token: &str,
        file_id: &str,
        base_revision: i64,
        path: &Path,
        size_bytes: u64,
    ) -> Result<ExistingFileTransfer> {
        self.replace_existing_file_from_reader(
            bearer_token,
            file_id,
            base_revision,
            fs::File::open(path)?,
            size_bytes,
        )
        .await
    }

    /// Handle-based replacement variant. The caller is responsible for
    /// opening a checked source and preserving that handle across this async
    /// transfer rather than re-opening its path after a filesystem race.
    pub async fn replace_existing_file_from_reader(
        &self,
        bearer_token: &str,
        file_id: &str,
        base_revision: i64,
        mut reader: impl Read,
        size_bytes: u64,
    ) -> Result<ExistingFileTransfer> {
        if size_bytes <= SIMPLE_EXISTING_REPLACEMENT_LIMIT {
            let size = usize::try_from(size_bytes).map_err(|_| {
                DesktopError::InvalidState(
                    "bounded replacement size cannot fit in memory".to_string(),
                )
            })?;
            let mut bytes = vec![0; size];
            reader.read_exact(&mut bytes)?;
            return self
                .replace_existing_file(bearer_token, file_id, base_revision, &bytes)
                .await;
        }
        self.replace_existing_resumable_from_reader(
            bearer_token,
            file_id,
            base_revision,
            reader,
            size_bytes,
        )
        .await
    }

    async fn replace_existing_utf8(
        &self,
        bearer_token: &str,
        file_id: &str,
        base_revision: i64,
        content: &str,
    ) -> Result<ExistingFileTransfer> {
        let response = self
            .authorized(
                Method::PUT,
                &format!("/files/{file_id}/content"),
                bearer_token,
            )
            .json(&serde_json::json!({
                "base_revision": base_revision,
                "content": content,
            }))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(ExistingFileTransfer::Conflict);
        }
        let file: FileEnvelope = self
            .decode_success_json(response, "file replacement")
            .await?;
        let file = file.file;
        Ok(ExistingFileTransfer::Updated(file))
    }

    /// Start the versioned resumable replacement contract. Only the target and
    /// its known revision are supplied; Drive derives its workspace/name/parent
    /// from that target and forks a conflict copy if the revision went stale.
    async fn replace_existing_resumable_from_reader(
        &self,
        bearer_token: &str,
        file_id: &str,
        base_revision: i64,
        mut reader: impl Read,
        size_bytes: u64,
    ) -> Result<ExistingFileTransfer> {
        let response = self
            .authorized(Method::POST, "/uploads/resumable", bearer_token)
            .json(&replacement_session_body(
                file_id,
                base_revision,
                size_bytes,
            ))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        if is_unsupported_replacement_status(response.status()) {
            return Ok(ExistingFileTransfer::UnsupportedResumableReplacement {
                size_bytes,
                required_endpoint: "POST /uploads/resumable with target_file_id and base_revision",
            });
        }
        let session: UploadSessionEnvelope = self
            .decode_success_json(response, "replacement upload session")
            .await?;
        let session = session.session;
        if size_bytes == 0 {
            return replacement_completion_outcome(
                self.put_resumable_chunk(bearer_token, &session.id, 0, &[], true)
                    .await?,
            );
        }

        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; RESUMABLE_CHUNK_BYTES];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let finish = offset + read as u64 == size_bytes;
            let response = self
                .put_resumable_chunk(
                    bearer_token,
                    &session.id,
                    offset as i64,
                    &buffer[..read],
                    finish,
                )
                .await?;
            offset += read as u64;
            if finish {
                return replacement_completion_outcome(response);
            }
        }
        Err(DesktopError::InvalidState(
            "local file changed while its resumable replacement was in progress".to_string(),
        ))
    }

    /// Move/rename metadata with the desktop's persisted common-ancestor
    /// revision. The server must atomically reject a stale baseline rather than
    /// moving a concurrently changed Drive object.
    pub async fn move_remote_file(
        &self,
        bearer_token: &str,
        file_id: &str,
        base_revision: i64,
        parent_id: Option<&str>,
        name: &str,
    ) -> Result<RemoteMoveTransfer> {
        let response = self
            .authorized(Method::PATCH, &format!("/files/{file_id}"), bearer_token)
            .json(&remote_move_body(base_revision, parent_id, name))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        if let Some(outcome) = remote_move_terminal_outcome(response.status()) {
            return Ok(outcome);
        }
        let envelope: FileEnvelope = self.decode_success_json(response, "remote move").await?;
        Ok(RemoteMoveTransfer::Moved(envelope.file))
    }

    /// Recoverable remote deletion: Drive's trash endpoint, never its
    /// permanent `DELETE /files/{id}` route.
    pub async fn trash_file(&self, bearer_token: &str, file_id: &str) -> Result<RemoteFile> {
        let response = self
            .authorized(
                Method::POST,
                &format!("/files/{file_id}/trash"),
                bearer_token,
            )
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let envelope: FileEnvelope = self.decode_success_json(response, "trash file").await?;
        Ok(envelope.file)
    }

    /// Restore a previously trashed Drive object. The caller verifies that no
    /// live path collision exists before it asks Drive to untrash the object.
    pub async fn restore_file(&self, bearer_token: &str, file_id: &str) -> Result<RemoteFile> {
        let response = self
            .authorized(
                Method::POST,
                &format!("/files/{file_id}/restore"),
                bearer_token,
            )
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let envelope: FileEnvelope = self.decode_success_json(response, "restore file").await?;
        Ok(envelope.file)
    }

    pub async fn logout(&self, bearer_token: &str) -> Result<LogoutOutcome> {
        let response = self
            .authorized(Method::POST, "/auth/logout", bearer_token)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        logout_outcome_for_status(response.status())
    }

    /// Revoke one exact older session using a freshly authenticated session
    /// for the same account. A missing actor-scoped target is terminal; an
    /// invalid candidate bearer or transient server failure remains retryable.
    pub async fn revoke_session(
        &self,
        bearer_token: &str,
        session_id: &str,
    ) -> Result<RemoteSessionRevocationOutcome> {
        let response = self
            .http
            .post(self.session_revocation_url(session_id)?)
            .bearer_auth(bearer_token)
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        remote_session_revocation_outcome_for_status(response.status())
    }

    async fn upload_new_resumable(
        &self,
        bearer_token: &str,
        workspace_id: &str,
        parent_id: Option<&str>,
        name: &str,
        bytes: &[u8],
    ) -> Result<RemoteFile> {
        let response = self
            .authorized(Method::POST, "/uploads/resumable", bearer_token)
            .json(&serde_json::json!({
                "workspace_id": workspace_id,
                "parent_id": parent_id,
                "name": name,
                "total_size": bytes.len() as i64,
                "duplicate_policy": "keep_both",
            }))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let session: UploadSessionEnvelope = self
            .decode_success_json(response, "new upload session")
            .await?;
        let session = session.session;
        let mut offset = 0usize;
        let mut final_file = None;
        if bytes.is_empty() {
            final_file = self
                .put_resumable_chunk(bearer_token, &session.id, 0, bytes, true)
                .await?
                .file;
        } else {
            for chunk in bytes.chunks(RESUMABLE_CHUNK_BYTES) {
                let finish = offset + chunk.len() == bytes.len();
                let response = self
                    .put_resumable_chunk(bearer_token, &session.id, offset as i64, chunk, finish)
                    .await?;
                if finish {
                    final_file = response.file;
                }
                offset += chunk.len();
            }
        }
        final_file.ok_or_else(|| {
            DesktopError::InvalidState(
                "resumable create finished without a file response".to_string(),
            )
        })
    }

    async fn upload_new_resumable_from_reader(
        &self,
        bearer_token: &str,
        workspace_id: &str,
        parent_id: Option<&str>,
        name: &str,
        mut reader: impl Read,
        size_bytes: u64,
    ) -> Result<RemoteFile> {
        let response = self
            .authorized(Method::POST, "/uploads/resumable", bearer_token)
            .json(&serde_json::json!({
                "workspace_id": workspace_id,
                "parent_id": parent_id,
                "name": name,
                "total_size": size_bytes,
                "duplicate_policy": "keep_both",
            }))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        let session: UploadSessionEnvelope = self
            .decode_success_json(response, "streaming upload session")
            .await?;
        let session = session.session;
        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; RESUMABLE_CHUNK_BYTES];
        let mut final_file = None;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let finish = offset + read as u64 == size_bytes;
            let response = self
                .put_resumable_chunk(
                    bearer_token,
                    &session.id,
                    offset as i64,
                    &buffer[..read],
                    finish,
                )
                .await?;
            if finish {
                final_file = response.file;
            }
            offset += read as u64;
        }
        if offset != size_bytes {
            return Err(DesktopError::InvalidState(
                "local file changed while its resumable upload was in progress".to_string(),
            ));
        }
        final_file.ok_or_else(|| {
            DesktopError::InvalidState(
                "resumable create finished without a file response".to_string(),
            )
        })
    }

    async fn put_resumable_chunk(
        &self,
        bearer_token: &str,
        upload_id: &str,
        offset: i64,
        bytes: &[u8],
        finish: bool,
    ) -> Result<UploadChunkResponse> {
        let response = self
            .authorized(
                Method::PUT,
                &format!("/uploads/resumable/{upload_id}"),
                bearer_token,
            )
            .json(&serde_json::json!({
                "offset": offset,
                "content_base64": STANDARD.encode(bytes),
                "finish": finish,
            }))
            .send_with_cycle_budget(self.cycle_budget.as_ref())
            .await?;
        self.decode_success_json(response, "upload chunk").await
    }

    async fn decode_success_json<T: DeserializeOwned>(
        &self,
        response: Response,
        label: &str,
    ) -> Result<T> {
        let response = require_success(response).await?;
        self.decode_json_limited(response, MAX_ENVELOPE_JSON_BYTES, label)
            .await
    }

    async fn decode_json_limited<T: DeserializeOwned>(
        &self,
        response: Response,
        max_bytes: usize,
        label: &str,
    ) -> Result<T> {
        decode_json_limited_with_budget(
            response,
            max_bytes,
            label,
            self.cycle_budget.as_ref(),
            false,
        )
        .await
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.http.request(method, self.url(path))
    }

    fn authorized(
        &self,
        method: Method,
        path: &str,
        bearer_token: &str,
    ) -> reqwest::RequestBuilder {
        self.request(method, path).bearer_auth(bearer_token)
    }

    fn url(&self, path: &str) -> Url {
        self.base_url
            .join(path.trim_start_matches('/'))
            .expect("fixed Drive endpoint is a valid relative URL")
    }

    fn session_revocation_url(&self, session_id: &str) -> Result<Url> {
        if session_id.is_empty() || session_id.len() > 128 {
            return Err(DesktopError::InvalidState(
                "remote-session ID is empty or exceeds its bound".to_string(),
            ));
        }
        let mut url = self.url("/auth/sessions/");
        url.path_segments_mut()
            .map_err(|_| {
                DesktopError::InvalidState(
                    "Drive server URL cannot contain path segments".to_string(),
                )
            })?
            .pop_if_empty()
            .push(session_id)
            .push("revoke");
        Ok(url)
    }

    fn sync_root_manifest_url(&self, root: &SyncRoot) -> Result<Url> {
        if root.id.is_empty() || root.id.len() > 4 * 1024 {
            return Err(DesktopError::InvalidState(
                "sync root ID is empty or exceeds its bound".to_string(),
            ));
        }
        let mut url = self.url("/sync/roots/");
        url.path_segments_mut()
            .map_err(|_| {
                DesktopError::InvalidState(
                    "Drive server URL cannot contain path segments".to_string(),
                )
            })?
            .pop_if_empty()
            .push(&root.id)
            .push("manifest");
        url.query_pairs_mut()
            .append_pair("access_generation", &root.access_generation.to_string());
        Ok(url)
    }
}

#[path = "http/desktop_agent.rs"]
mod desktop_agent;
pub use desktop_agent::{
    DesktopAgentCommandEventDisposition, DesktopAgentDisconnectTransportError,
    DesktopAgentProgressReport, DesktopAgentTerminalReport,
};

fn authenticated_login_outcome(server_url: &str, login: LoginResponse) -> Result<LoginOutcome> {
    let bearer_token = login.token.ok_or_else(|| {
        DesktopError::InvalidState("server did not issue a bearer session token".to_string())
    })?;
    let session_id = login.session_id.ok_or_else(|| {
        DesktopError::InvalidState("server did not bind login to a session ID".to_string())
    })?;
    let expires_at = login.expires_at.ok_or_else(|| {
        DesktopError::InvalidState("server did not bind login to a session expiry".to_string())
    })?;
    let response_record = RemoteSessionRecord::from_login_response(
        server_url,
        &login.actor,
        &session_id,
        &expires_at,
    )?;
    let token_record =
        RemoteSessionRecord::from_local_bearer(server_url, &login.actor, &bearer_token)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "Drive login token did not match the local-session contract".to_string(),
                )
            })?;
    if response_record.expires_at <= Utc::now() {
        return Err(DesktopError::InvalidState(
            "Drive login returned an expired session".to_string(),
        ));
    }
    if response_record.session_id != token_record.session_id
        || response_record.expires_at.timestamp() != token_record.expires_at.timestamp()
    {
        return Err(DesktopError::InvalidState(
            "Drive login response did not match its bearer session".to_string(),
        ));
    }
    Ok(LoginOutcome::Authenticated {
        bearer_token,
        account_email: response_record.account_email,
        is_admin: login.is_admin,
        session_id: response_record.session_id,
        expires_at: response_record.expires_at,
    })
}

fn logout_outcome_for_status(status: StatusCode) -> Result<LogoutOutcome> {
    match status {
        status if status.is_success() => Ok(LogoutOutcome::Revoked),
        StatusCode::UNAUTHORIZED => Ok(LogoutOutcome::AlreadyInvalid),
        status => Err(server_error(status)),
    }
}

fn remote_session_revocation_outcome_for_status(
    status: StatusCode,
) -> Result<RemoteSessionRevocationOutcome> {
    match status {
        status if status.is_success() => Ok(RemoteSessionRevocationOutcome::Revoked),
        StatusCode::NOT_FOUND => Ok(RemoteSessionRevocationOutcome::AlreadyAbsent),
        status => Err(server_error(status)),
    }
}

fn validate_download_size(expected_size: u64, declared_size: Option<u64>) -> Result<()> {
    if expected_size > MAX_SYNC_DOWNLOAD_BYTES {
        return Err(DesktopError::InvalidState(format!(
            "Drive file exceeds the {MAX_SYNC_DOWNLOAD_BYTES}-byte sync download limit"
        )));
    }
    if let Some(declared_size) = declared_size {
        if declared_size != expected_size {
            return Err(DesktopError::InvalidState(format!(
                "Drive declared {declared_size} download bytes but the manifest expected {expected_size}"
            )));
        }
    }
    Ok(())
}

fn advance_download_budget(received: u64, chunk_len: usize, expected_size: u64) -> Result<u64> {
    let received = received
        .checked_add(u64::try_from(chunk_len).map_err(|_| {
            DesktopError::InvalidState("Drive download chunk size overflowed".to_string())
        })?)
        .ok_or_else(|| {
            DesktopError::InvalidState("Drive download byte count overflowed".to_string())
        })?;
    if received > expected_size || received > MAX_SYNC_DOWNLOAD_BYTES {
        return Err(DesktopError::InvalidState(format!(
            "Drive download exceeded its expected {expected_size}-byte budget"
        )));
    }
    Ok(received)
}

struct LoginPayload<'a> {
    email: &'a str,
    password: &'a str,
    totp_code: Option<&'a str>,
    recovery_code: Option<&'a str>,
}

#[derive(Deserialize)]
struct BootstrapStatus {
    required: bool,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: Option<String>,
    session_id: Option<String>,
    actor: String,
    is_admin: bool,
    requires_2fa: bool,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct MeResponse {
    actor: String,
}

#[derive(Deserialize)]
struct WorkspaceListResponse {
    workspaces: Vec<Workspace>,
}

#[derive(Deserialize)]
struct SyncRootDiscoveryResponse {
    roots: Vec<SyncRoot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SyncRootPage {
    pub roots: Vec<SyncRoot>,
    pub next_cursor: Option<String>,
}

fn validate_sync_root_page(
    page: SyncRootPage,
    previous: Option<&str>,
    limit: u8,
) -> Result<SyncRootPage> {
    if page.roots.len() > usize::from(limit)
        || page
            .next_cursor
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 2_048 || Some(value) == previous)
    {
        return Err(DesktopError::InvalidState(
            "invalid bounded Drive root page".to_string(),
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut subjects = std::collections::BTreeSet::new();
    for root in &page.roots {
        root.validate()?;
        if !ids.insert(root.id.as_str())
            || !subjects.insert((root.workspace_id.as_str(), root.root_file_id.as_deref()))
        {
            return Err(DesktopError::InvalidState(
                "Drive root page repeats a subject".to_string(),
            ));
        }
    }
    Ok(page)
}

#[derive(Deserialize)]
struct ConfiguredRootRevalidationResponse {
    roots: Vec<SyncRoot>,
    revoked_ids: Vec<String>,
    #[serde(default)]
    replacements: Vec<SyncRootReplacement>,
}

#[derive(Deserialize)]
struct SyncRootReplacement {
    requested_id: String,
    root: SyncRoot,
}

fn validate_selected_root_revalidation(
    root_id: &str,
    workspace_id: &str,
    root_file_id: Option<&str>,
    result: ConfiguredRootRevalidationResponse,
) -> Result<SyncRoot> {
    if !result.revoked_ids.is_empty() || result.roots.len() + result.replacements.len() != 1 {
        return Err(sync_root_access_removed_error());
    }
    let is_replacement = !result.replacements.is_empty();
    let root = if let Some(replacement) = result.replacements.into_iter().next() {
        if replacement.requested_id != root_id
            || root_file_id.is_none()
            || replacement.root.id == root_id
        {
            return Err(DesktopError::InvalidState(
                "invalid selected root replacement".to_string(),
            ));
        }
        replacement.root
    } else {
        result
            .roots
            .into_iter()
            .next()
            .ok_or_else(sync_root_access_removed_error)?
    };
    root.validate()?;
    if (!is_replacement && root.id != root_id)
        || root.workspace_id != workspace_id
        || root.root_file_id.as_deref() != root_file_id
    {
        return Err(DesktopError::InvalidState(
            "selected Drive root changed subject".to_string(),
        ));
    }
    Ok(root)
}

fn validate_configured_root_revalidation(
    configured: &[SyncRoot],
    result: ConfiguredRootRevalidationResponse,
) -> Result<Vec<SyncRoot>> {
    let expected = configured
        .iter()
        .map(|root| (root.id.as_str(), root))
        .collect::<std::collections::BTreeMap<_, _>>();
    if expected.len() != configured.len()
        || result.roots.len() + result.revoked_ids.len() + result.replacements.len()
            != configured.len()
    {
        return Err(DesktopError::InvalidState(
            "incomplete configured root revalidation".to_string(),
        ));
    }
    let mut observed = std::collections::BTreeSet::new();
    for root in &result.roots {
        root.validate()?;
        if !expected
            .get(root.id.as_str())
            .is_some_and(|saved| saved.same_manifest_subject(root))
            || !observed.insert(root.id.clone())
        {
            return Err(DesktopError::InvalidState(
                "configured root revalidation changed a root subject".to_string(),
            ));
        }
    }
    for id in &result.revoked_ids {
        if !expected.contains_key(id.as_str()) || !observed.insert(id.clone()) {
            return Err(DesktopError::InvalidState(
                "configured root revalidation returned an unknown revoked ID".to_string(),
            ));
        }
    }
    let mut refreshed = result.roots;
    let mut returned_ids = refreshed
        .iter()
        .map(|root| root.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for replacement in &result.replacements {
        replacement.root.validate()?;
        if !expected
            .get(replacement.requested_id.as_str())
            .is_some_and(|saved| {
                saved.kind == SyncRootKind::ItemGrant
                    && replacement.root.kind == SyncRootKind::ItemGrant
                    && saved.same_canonical_root(&replacement.root)
                    && saved.id != replacement.root.id
            })
            || !observed.insert(replacement.requested_id.clone())
            || !returned_ids.insert(replacement.root.id.clone())
        {
            return Err(DesktopError::InvalidState(
                "configured root replacement changed subject or repeated an ID".to_string(),
            ));
        }
    }
    refreshed.extend(
        result
            .replacements
            .into_iter()
            .map(|replacement| replacement.root),
    );
    Ok(refreshed)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SyncRootManifestMode {
    FullDesktopSync,
    ScopedDesktopSync,
}

#[derive(Deserialize)]
struct SyncRootManifestResponse {
    root: SyncRoot,
    mode: SyncRootManifestMode,
    next_cursor: i64,
    files: Vec<RemoteFile>,
}

#[derive(Deserialize)]
struct ManifestResponse {
    workspace_id: String,
    files: Vec<RemoteFile>,
}

fn validate_workspace_manifest(
    expected_workspace_id: &str,
    manifest: ManifestResponse,
) -> Result<Vec<RemoteFile>> {
    if manifest.workspace_id != expected_workspace_id
        || manifest
            .files
            .iter()
            .any(|file| file.workspace_id != expected_workspace_id)
    {
        return Err(DesktopError::InvalidState(
            "Drive workspace manifest is not bound to the requested workspace".to_string(),
        ));
    }
    if manifest.files.len() > MAX_SYNC_RESPONSE_ITEMS {
        return Err(DesktopError::InvalidState(format!(
            "Drive workspace manifest exceeds the {MAX_SYNC_RESPONSE_ITEMS}-item limit"
        )));
    }
    Ok(manifest.files)
}

fn validate_sync_root_discovery(discovery: SyncRootDiscoveryResponse) -> Result<Vec<SyncRoot>> {
    if discovery.roots.len() > MAX_DISCOVERY_ROOTS {
        return Err(DesktopError::RootDiscoveryOverflow);
    }
    let mut ids = std::collections::BTreeSet::new();
    for root in &discovery.roots {
        root.validate()?;
        if !ids.insert(root.id.as_str()) {
            return Err(DesktopError::InvalidState(
                "Drive sync root discovery contains duplicate root identities".to_string(),
            ));
        }
    }
    converge_sync_roots(&discovery.roots)
}

fn validate_sync_root_manifest(
    requested_root: &SyncRoot,
    manifest: SyncRootManifestResponse,
) -> Result<SyncRootManifest> {
    manifest.root.validate()?;
    if !requested_root.same_manifest_subject(&manifest.root)
        || manifest.root.access_generation != requested_root.access_generation
    {
        return Err(DesktopError::InvalidState(
            "Drive sync manifest is not bound to the requested root subject".to_string(),
        ));
    }
    let scoped = match (requested_root.kind, manifest.mode) {
        (SyncRootKind::Workspace, SyncRootManifestMode::FullDesktopSync) => false,
        (SyncRootKind::ItemGrant, SyncRootManifestMode::ScopedDesktopSync) => true,
        _ => {
            return Err(DesktopError::InvalidState(
                "Drive sync manifest mode does not match the requested root authority".to_string(),
            ));
        }
    };
    if manifest.files.len() > MAX_SYNC_RESPONSE_ITEMS {
        return Err(DesktopError::InvalidState(format!(
            "Drive sync root manifest exceeds the {MAX_SYNC_RESPONSE_ITEMS}-item limit"
        )));
    }
    if manifest
        .files
        .iter()
        .any(|file| file.workspace_id != requested_root.workspace_id)
    {
        return Err(DesktopError::InvalidState(
            "Drive sync root manifest contains a file from another workspace".to_string(),
        ));
    }
    if scoped {
        validate_scoped_root_descendants(requested_root, &manifest.files)?;
    }
    let mut files = manifest.files;
    if scoped {
        let root_id = requested_root.root_file_id.as_deref().ok_or_else(|| {
            DesktopError::InvalidState("scoped sync root is missing its root file ID".to_string())
        })?;
        let root = files
            .iter_mut()
            .find(|file| file.id == root_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "scoped sync manifest is missing its canonical root".to_string(),
                )
            })?;
        // The selected item is the local tree root. Its server parent is an
        // authority-irrelevant ancestor and must not enter the pair engine,
        // where it could create an escaping or sibling-derived path.
        root.parent_id = None;
    }
    Ok(SyncRootManifest {
        root: manifest.root,
        scoped,
        next_cursor: manifest.next_cursor,
        files,
    })
}

fn validate_scoped_root_descendants(root: &SyncRoot, files: &[RemoteFile]) -> Result<()> {
    let root_id = root.root_file_id.as_deref().ok_or_else(|| {
        DesktopError::InvalidState("scoped sync root is missing its root file ID".to_string())
    })?;
    let by_id = files
        .iter()
        .map(|file| (file.id.as_str(), file))
        .collect::<std::collections::BTreeMap<_, _>>();
    if by_id.len() != files.len() || !by_id.contains_key(root_id) {
        return Err(DesktopError::InvalidState(
            "scoped sync manifest is missing its canonical root or repeats an item ID".to_string(),
        ));
    }
    // Every validated chain joins the root or a previously validated chain.
    // Retaining those witnesses avoids walking a deep ancestry once per item.
    let mut rooted = std::collections::BTreeSet::from([root_id]);
    for file in files {
        let mut current = file;
        let mut ancestors = std::collections::BTreeSet::new();
        while !rooted.contains(current.id.as_str()) {
            if !ancestors.insert(current.id.as_str()) {
                return Err(DesktopError::InvalidState(
                    "scoped sync manifest contains a parent cycle".to_string(),
                ));
            }
            let parent_id = current.parent_id.as_deref().ok_or_else(|| {
                DesktopError::InvalidState(
                    "scoped sync manifest includes an item outside the granted subtree".to_string(),
                )
            })?;
            current = by_id.get(parent_id).copied().ok_or_else(|| {
                DesktopError::InvalidState(
                    "scoped sync manifest omits a descendant parent".to_string(),
                )
            })?;
        }
        rooted.extend(ancestors);
    }
    Ok(())
}

#[derive(Deserialize)]
struct ChangesResponse {
    next_cursor: i64,
    changes: Vec<RemoteChange>,
}

#[derive(Deserialize)]
struct FileEnvelope {
    file: RemoteFile,
}

#[derive(Deserialize)]
struct UploadSessionEnvelope {
    session: UploadSession,
}

#[derive(Deserialize)]
struct UploadSession {
    id: String,
}

#[derive(Deserialize)]
struct UploadChunkResponse {
    file: Option<RemoteFile>,
    #[serde(default)]
    conflict: Option<serde_json::Value>,
}

fn replacement_completion_outcome(response: UploadChunkResponse) -> Result<ExistingFileTransfer> {
    if response.conflict.is_some() {
        return Ok(ExistingFileTransfer::Conflict);
    }
    let file = response.file.ok_or_else(|| {
        DesktopError::InvalidState(
            "resumable replacement finished without a file response".to_string(),
        )
    })?;
    Ok(ExistingFileTransfer::Updated(file))
}

fn is_unsupported_replacement_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_IMPLEMENTED
    )
}

fn replacement_session_body(
    file_id: &str,
    base_revision: i64,
    size_bytes: u64,
) -> serde_json::Value {
    serde_json::json!({
        "target_file_id": file_id,
        "base_revision": base_revision,
        "total_size": size_bytes,
    })
}

fn remote_move_body(base_revision: i64, parent_id: Option<&str>, name: &str) -> serde_json::Value {
    serde_json::json!({
        "base_revision": base_revision,
        "name": name,
        "parent_id": parent_id,
        "move_to_root": parent_id.is_none(),
    })
}

fn remote_move_terminal_outcome(status: StatusCode) -> Option<RemoteMoveTransfer> {
    match status {
        StatusCode::CONFLICT => Some(RemoteMoveTransfer::Conflict),
        // These statuses can mean a stale parent/file or a rejected target
        // path. Keep both copies intact and let the desktop surface a review;
        // do not retry a guessed destination.
        StatusCode::BAD_REQUEST
        | StatusCode::NOT_FOUND
        | StatusCode::PRECONDITION_FAILED
        | StatusCode::LOCKED => Some(RemoteMoveTransfer::NeedsReview),
        _ => None,
    }
}

fn normalize_server_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input.trim())
        .map_err(|_| DesktopError::InvalidServerUrl("enter a full server URL".to_string()))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(DesktopError::InvalidServerUrl(
            "URL must include HTTPS and a host".to_string(),
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DesktopError::InvalidServerUrl(
            "URL must not include credentials, a query, or a fragment".to_string(),
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

async fn require_success(response: Response) -> Result<Response> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(server_error(response.status()))
    }
}

async fn require_root_discovery_success(response: Response) -> Result<Response> {
    if response.status() != StatusCode::PAYLOAD_TOO_LARGE {
        return require_success(response).await;
    }
    #[derive(Deserialize)]
    struct ErrorCode {
        error: String,
    }
    let value: Result<ErrorCode> =
        decode_json_limited(response, 4 * 1024, "root discovery error").await;
    if matches!(value, Ok(ErrorCode { error }) if error == "sync_root_discovery_overflow") {
        Err(DesktopError::RootDiscoveryOverflow)
    } else {
        Err(server_error(StatusCode::PAYLOAD_TOO_LARGE))
    }
}

async fn decode_json_limited<T: DeserializeOwned>(
    response: Response,
    max_bytes: usize,
    label: &str,
) -> Result<T> {
    decode_json_limited_with_budget(response, max_bytes, label, None, false).await
}

async fn decode_json_limited_with_budget<T: DeserializeOwned>(
    mut response: Response,
    max_bytes: usize,
    label: &str,
    cycle_budget: Option<&SyncCycleBudget>,
    count_files: bool,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(DesktopError::InvalidState(format!(
            "Drive {label} response exceeds its {max_bytes}-byte limit"
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if let Some(budget) = cycle_budget {
            budget.charge_transport_bytes(chunk.len())?;
        }
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > max_bytes)
        {
            return Err(DesktopError::InvalidState(format!(
                "Drive {label} response exceeds its {max_bytes}-byte limit"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    if let Some(budget) = cycle_budget.filter(|_| count_files) {
        let items = manifest_budget::count_manifest_files(&bytes)?;
        if items > MAX_SYNC_RESPONSE_ITEMS {
            return Err(DesktopError::InvalidState(format!(
                "Drive sync root manifest exceeds the {MAX_SYNC_RESPONSE_ITEMS}-item limit"
            )));
        }
        budget.charge_manifest_items(items)?;
    }
    serde_json::from_slice(&bytes).map_err(DesktopError::from)
}

fn server_error(status: StatusCode) -> DesktopError {
    let message = match status {
        StatusCode::UNAUTHORIZED => "sign-in was not accepted",
        StatusCode::FORBIDDEN => "the account cannot access this Drive location",
        StatusCode::NOT_FOUND => "the Drive endpoint was not found",
        StatusCode::CONFLICT => "Drive changed this item before the update could be applied",
        StatusCode::TOO_MANY_REQUESTS => "the server asked the client to slow down",
        status if status.is_server_error() => "the Drive server is temporarily unavailable",
        _ => "the Drive server rejected the request",
    };
    DesktopError::Server {
        status: status.as_u16(),
        message: message.to_string(),
    }
}

fn access_generation_precondition_failed(error: &DesktopError) -> bool {
    matches!(error, DesktopError::Server { status: 412, .. })
}

fn sync_root_access_removed_error() -> DesktopError {
    DesktopError::Server {
        status: StatusCode::NOT_FOUND.as_u16(),
        message: "the Drive location no longer has current access".to_string(),
    }
}

fn refreshed_manifest_root(requested: &SyncRoot, roots: Vec<SyncRoot>) -> Result<SyncRoot> {
    roots
        .into_iter()
        .find(|root| {
            requested.same_manifest_subject(root)
                || (requested.kind == SyncRootKind::ItemGrant
                    && root.kind == SyncRootKind::ItemGrant
                    && requested.same_canonical_root(root))
        })
        .ok_or_else(sync_root_access_removed_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_move_response_matches;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Duration;
    use std::io::Write as _;

    fn local_login_response(
        actor: &str,
        response_session_id: &str,
        token_session_id: &str,
        expires_at: DateTime<Utc>,
    ) -> LoginResponse {
        let claims = serde_json::json!({
            "jti": token_session_id,
            "email": actor,
            "issuer": "local-password",
            "subject": "local-password",
            "expires_at": expires_at.timestamp(),
            "admin": false,
        });
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        LoginResponse {
            token: Some(format!("sso.v1.{encoded}.opaque-signature")),
            session_id: Some(response_session_id.to_string()),
            actor: actor.to_string(),
            is_admin: false,
            requires_2fa: false,
            expires_at: Some(expires_at.to_rfc3339()),
        }
    }

    #[test]
    fn download_budget_rejects_oversize_or_inconsistent_responses() {
        assert!(validate_download_size(MAX_SYNC_DOWNLOAD_BYTES, None).is_ok());
        assert!(validate_download_size(MAX_SYNC_DOWNLOAD_BYTES + 1, None).is_err());
        assert!(validate_download_size(4, Some(5)).is_err());
        assert_eq!(advance_download_budget(0, 4, 4).unwrap(), 4);
        assert!(advance_download_budget(4, 1, 4).is_err());
    }

    #[test]
    fn scoped_generic_response_charges_bytes_and_blocks_a_second_request() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            let body = br#"{"ok":true}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let budget = SyncCycleBudget::with_manifest_transport_limit(
            crate::SyncPassLimits {
                max_requests: 1,
                ..crate::SyncPassLimits::default()
            },
            br#"{"ok":true}"#.len() - 1,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client = reqwest::Client::new();
            let url = format!("http://{address}/sync-response");
            let response = client
                .get(&url)
                .send_with_cycle_budget(Some(&budget))
                .await
                .unwrap();
            assert!(matches!(
                decode_json_limited_with_budget::<serde_json::Value>(
                    response,
                    MAX_ENVELOPE_JSON_BYTES,
                    "generic response",
                    Some(&budget),
                    false,
                )
                .await,
                Err(DesktopError::SyncCycleBudgetExceeded(_))
            ));
            assert!(matches!(
                client.get(&url).send_with_cycle_budget(Some(&budget)).await,
                Err(DesktopError::SyncCycleBudgetExceeded(_))
            ));
        });
        server.join().unwrap();
    }

    #[test]
    fn accepts_only_https_server_urls() {
        assert_eq!(
            DriveHttpClient::new("https://drive.example.test")
                .unwrap()
                .normalized_url(),
            "https://drive.example.test"
        );
        for insecure in [
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://drive.example.test",
        ] {
            assert!(matches!(
                DriveHttpClient::new(insecure),
                Err(DesktopError::InvalidServerUrl(_))
            ));
        }
    }

    #[test]
    fn workspace_manifest_rejects_envelope_or_record_workspace_mismatch() {
        let file = RemoteFile {
            id: "file-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            parent_id: None,
            name: "file.txt".to_string(),
            kind: RemoteFileKind::File,
            revision: 1,
            trashed: false,
            content_hash: Some("a".repeat(64)),
            size_bytes: Some(1),
        };
        assert!(validate_workspace_manifest(
            "workspace-1",
            ManifestResponse {
                workspace_id: "workspace-2".to_string(),
                files: vec![file.clone()],
            },
        )
        .is_err());

        let mut wrong_record = file;
        wrong_record.workspace_id = "workspace-2".to_string();
        assert!(validate_workspace_manifest(
            "workspace-1",
            ManifestResponse {
                workspace_id: "workspace-1".to_string(),
                files: vec![wrong_record],
            },
        )
        .is_err());
    }

    fn scoped_root(generation: u64) -> SyncRoot {
        SyncRoot {
            id: "item-grant:opaque-subject".to_string(),
            kind: SyncRootKind::ItemGrant,
            workspace_id: "workspace-1".to_string(),
            root_file_id: Some("folder-1".to_string()),
            grant_id: Some("grant-1".to_string()),
            owner_label: "Avery Example".to_string(),
            role: crate::SyncRootRole::Viewer,
            access_generation: generation,
            expires_at: None,
            label: "Projects".to_string(),
        }
    }

    #[test]
    fn unrelated_101st_root_overflows_discovery_but_exact_configured_revalidation_succeeds() {
        let configured = (0..100)
            .map(|index| {
                let mut root = scoped_root(1);
                root.id = format!("item-grant:{index}");
                root.root_file_id = Some(format!("folder-{index}"));
                root.grant_id = Some(format!("grant-{index}"));
                root
            })
            .collect::<Vec<_>>();
        assert!(validate_sync_root_discovery(SyncRootDiscoveryResponse {
            roots: configured.clone(),
        })
        .is_ok());
        let mut adversarial = configured.clone();
        let mut extra = scoped_root(1);
        extra.id = "item-grant:adversarial".to_string();
        extra.root_file_id = Some("folder-adversarial".to_string());
        extra.grant_id = Some("grant-adversarial".to_string());
        adversarial.push(extra);
        assert!(matches!(
            validate_sync_root_discovery(SyncRootDiscoveryResponse { roots: adversarial }),
            Err(DesktopError::RootDiscoveryOverflow)
        ));
        let active = validate_configured_root_revalidation(
            &configured,
            ConfiguredRootRevalidationResponse {
                roots: configured.clone(),
                revoked_ids: Vec::new(),
                replacements: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(active, configured);
    }

    #[test]
    fn configured_revalidation_requires_complete_exact_subjects() {
        let root = scoped_root(1);
        let mut wrong = root.clone();
        wrong.root_file_id = Some("sibling".to_string());
        for response in [
            ConfiguredRootRevalidationResponse {
                roots: Vec::new(),
                revoked_ids: Vec::new(),
                replacements: Vec::new(),
            },
            ConfiguredRootRevalidationResponse {
                roots: vec![wrong],
                revoked_ids: Vec::new(),
                replacements: Vec::new(),
            },
            ConfiguredRootRevalidationResponse {
                roots: vec![root.clone()],
                revoked_ids: vec![root.id.clone()],
                replacements: Vec::new(),
            },
        ] {
            assert!(
                validate_configured_root_revalidation(std::slice::from_ref(&root), response)
                    .is_err()
            );
        }
        assert!(validate_configured_root_revalidation(
            std::slice::from_ref(&root),
            ConfiguredRootRevalidationResponse {
                roots: Vec::new(),
                revoked_ids: vec![root.id.clone()],
                replacements: Vec::new(),
            }
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn configured_revalidation_accepts_only_unique_same_file_grant_replacements() {
        let saved = scoped_root(4);
        let mut replacement = saved.clone();
        replacement.id = "item-grant:new-grant".to_string();
        replacement.grant_id = Some("new-grant".to_string());
        replacement.access_generation = 5;
        let response = |root: SyncRoot| ConfiguredRootRevalidationResponse {
            roots: Vec::new(),
            revoked_ids: Vec::new(),
            replacements: vec![SyncRootReplacement {
                requested_id: saved.id.clone(),
                root,
            }],
        };
        assert_eq!(
            validate_configured_root_revalidation(
                std::slice::from_ref(&saved),
                response(replacement.clone())
            )
            .unwrap(),
            vec![replacement.clone()]
        );
        assert_eq!(
            refreshed_manifest_root(&saved, vec![replacement.clone()]).unwrap(),
            replacement
        );

        let mut wrong_file = replacement.clone();
        wrong_file.root_file_id = Some("sibling".to_string());
        assert!(validate_configured_root_revalidation(
            std::slice::from_ref(&saved),
            response(wrong_file)
        )
        .is_err());
        let mut wrong_workspace = replacement.clone();
        wrong_workspace.workspace_id = "other".to_string();
        assert!(validate_configured_root_revalidation(
            std::slice::from_ref(&saved),
            response(wrong_workspace)
        )
        .is_err());
        let mut duplicate = response(replacement);
        duplicate.revoked_ids.push(saved.id.clone());
        assert!(
            validate_configured_root_revalidation(std::slice::from_ref(&saved), duplicate).is_err()
        );
    }

    #[test]
    fn selected_pair_revalidation_requires_exact_current_file_subject() {
        let saved = scoped_root(1);
        let response = |root: SyncRoot| ConfiguredRootRevalidationResponse {
            roots: vec![root],
            revoked_ids: Vec::new(),
            replacements: Vec::new(),
        };
        assert_eq!(
            validate_selected_root_revalidation(
                &saved.id,
                &saved.workspace_id,
                saved.root_file_id.as_deref(),
                response(saved.clone())
            )
            .unwrap(),
            saved
        );
        let mut wrong = scoped_root(1);
        wrong.root_file_id = Some("sibling".to_string());
        assert!(validate_selected_root_revalidation(
            &saved.id,
            &saved.workspace_id,
            saved.root_file_id.as_deref(),
            response(wrong)
        )
        .is_err());
        let mut new_grant = scoped_root(2);
        new_grant.id = "item-grant:new".to_string();
        new_grant.grant_id = Some("new".to_string());
        let replacement = ConfiguredRootRevalidationResponse {
            roots: Vec::new(),
            revoked_ids: Vec::new(),
            replacements: vec![SyncRootReplacement {
                requested_id: saved.id.clone(),
                root: new_grant.clone(),
            }],
        };
        assert_eq!(
            validate_selected_root_revalidation(
                &saved.id,
                &saved.workspace_id,
                saved.root_file_id.as_deref(),
                replacement
            )
            .unwrap(),
            new_grant
        );
    }

    #[test]
    fn root_pages_reject_oversize_duplicate_and_nonadvancing_cursor() {
        let root = scoped_root(1);
        let page = SyncRootPage {
            roots: vec![root.clone()],
            next_cursor: Some("next".to_string()),
        };
        assert!(validate_sync_root_page(page, None, 50).is_ok());
        assert!(validate_sync_root_page(
            SyncRootPage {
                roots: vec![root.clone(), root],
                next_cursor: None
            },
            None,
            50
        )
        .is_err());
        assert!(validate_sync_root_page(
            SyncRootPage {
                roots: Vec::new(),
                next_cursor: Some("same".to_string())
            },
            Some("same"),
            50
        )
        .is_err());
    }

    fn manifest_file(id: &str, parent_id: Option<&str>) -> RemoteFile {
        RemoteFile {
            id: id.to_string(),
            workspace_id: "workspace-1".to_string(),
            parent_id: parent_id.map(str::to_string),
            name: id.to_string(),
            kind: RemoteFileKind::Folder,
            revision: 1,
            trashed: false,
            content_hash: None,
            size_bytes: None,
        }
    }

    #[test]
    fn scoped_ancestry_accepts_a_full_deep_manifest_in_either_order() {
        let requested = scoped_root(1);
        let mut files = vec![manifest_file("folder-1", Some("private-parent"))];
        for index in 1..MAX_SYNC_RESPONSE_ITEMS {
            let id = format!("descendant-{index}");
            let parent = if index == 1 {
                "folder-1".to_string()
            } else {
                format!("descendant-{}", index - 1)
            };
            files.push(manifest_file(&id, Some(&parent)));
        }
        validate_scoped_root_descendants(&requested, &files).unwrap();
        files.reverse();
        validate_scoped_root_descendants(&requested, &files).unwrap();
    }

    #[test]
    fn scoped_ancestry_keeps_rejecting_invalid_branches_after_a_valid_chain() {
        let requested = scoped_root(1);
        let valid = vec![
            manifest_file("folder-1", None),
            manifest_file("parent", Some("folder-1")),
            manifest_file("child", Some("parent")),
        ];
        for invalid in [
            vec![manifest_file("sibling", None)],
            vec![manifest_file("missing", Some("absent"))],
            vec![
                manifest_file("loop-a", Some("loop-b")),
                manifest_file("loop-b", Some("loop-a")),
            ],
            vec![manifest_file("child", Some("folder-1"))],
        ] {
            let mut files = valid.clone();
            files.extend(invalid);
            assert!(validate_scoped_root_descendants(&requested, &files).is_err());
        }
    }

    #[test]
    fn scoped_manifest_binds_root_generation_and_rejects_siblings() {
        let requested = scoped_root(4);
        let mut current = requested.clone();
        current.access_generation = 5;
        assert!(validate_sync_root_manifest(
            &requested,
            SyncRootManifestResponse {
                root: current.clone(),
                mode: SyncRootManifestMode::ScopedDesktopSync,
                next_cursor: 9,
                files: vec![
                    manifest_file("folder-1", None),
                    manifest_file("child", Some("folder-1")),
                ],
            },
        )
        .is_err());
        let accepted = validate_sync_root_manifest(
            &current,
            SyncRootManifestResponse {
                root: current.clone(),
                mode: SyncRootManifestMode::ScopedDesktopSync,
                next_cursor: 9,
                files: vec![
                    manifest_file("folder-1", None),
                    manifest_file("child", Some("folder-1")),
                ],
            },
        )
        .unwrap();
        assert!(accepted.scoped);
        assert_eq!(accepted.root.access_generation, 5);
        assert_eq!(
            accepted
                .files
                .iter()
                .find(|file| file.id == "folder-1")
                .and_then(|file| file.parent_id.as_deref()),
            None
        );

        assert!(validate_sync_root_manifest(
            &requested,
            SyncRootManifestResponse {
                root: requested.clone(),
                mode: SyncRootManifestMode::ScopedDesktopSync,
                next_cursor: 10,
                files: vec![
                    manifest_file("folder-1", None),
                    manifest_file("sibling", None),
                ],
            },
        )
        .is_err());
    }

    #[test]
    fn manifest_request_uses_the_exact_discovered_generation_and_retries_current_role() {
        let requested = scoped_root(4);
        let mut refreshed = requested.clone();
        refreshed.access_generation = 5;
        refreshed.role = crate::SyncRootRole::Editor;
        assert_eq!(
            refreshed_manifest_root(&requested, vec![refreshed.clone()]).unwrap(),
            refreshed
        );

        let client = DriveHttpClient::new("https://drive.example.test").unwrap();
        let url = client.sync_root_manifest_url(&refreshed).unwrap();
        assert_eq!(url.query(), Some("access_generation=5"));
        assert_eq!(
            url.path_segments().unwrap().collect::<Vec<_>>(),
            vec!["sync", "roots", "item-grant:opaque-subject", "manifest"]
        );
        assert!(access_generation_precondition_failed(
            &DesktopError::Server {
                status: 412,
                message: "changed".to_string(),
            }
        ));
        assert!(refreshed_manifest_root(&requested, Vec::new()).is_err());
    }

    #[test]
    fn scoped_manifest_projects_the_selected_root_without_its_server_parent() {
        let requested = scoped_root(1);
        let accepted = validate_sync_root_manifest(
            &requested,
            SyncRootManifestResponse {
                root: requested.clone(),
                mode: SyncRootManifestMode::ScopedDesktopSync,
                next_cursor: 0,
                files: vec![
                    manifest_file("folder-1", Some("private-parent")),
                    manifest_file("child", Some("folder-1")),
                ],
            },
        )
        .unwrap();
        assert_eq!(accepted.files[0].parent_id, None);
        assert_eq!(accepted.files[1].parent_id.as_deref(), Some("folder-1"));
    }

    #[test]
    fn root_discovery_rejects_missing_access_generation_and_converges_overlaps() {
        let absent_generation = serde_json::json!({
            "id": "item-grant:opaque",
            "kind": "item_grant",
            "workspace_id": "workspace-1",
            "root_file_id": "folder-1",
            "grant_id": "grant-1",
            "owner_label": "Avery Example",
            "role": "viewer",
            "expires_at": null,
            "label": "Projects"
        });
        assert!(serde_json::from_value::<SyncRoot>(absent_generation).is_err());

        let direct = scoped_root(2);
        let mut group = direct.clone();
        group.id = "item-grant:group".to_string();
        group.grant_id = Some("group-grant".to_string());
        group.role = crate::SyncRootRole::Editor;
        group.access_generation = 3;
        let roots = validate_sync_root_discovery(SyncRootDiscoveryResponse {
            roots: vec![direct, group.clone()],
        })
        .unwrap();
        assert_eq!(roots, vec![group]);
    }

    #[test]
    fn login_binds_actor_session_and_expiry_to_the_issued_bearer() {
        let expires_at = Utc::now() + Duration::hours(1);
        let outcome = authenticated_login_outcome(
            "https://drive.example.test",
            local_login_response(
                "Person@Example.Test",
                "session-42",
                "session-42",
                expires_at,
            ),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            LoginOutcome::Authenticated {
                account_email,
                session_id,
                ..
            } if account_email == "person@example.test" && session_id == "session-42"
        ));
        assert!(authenticated_login_outcome(
            "https://drive.example.test",
            local_login_response(
                "person@example.test",
                "confused-session",
                "session-42",
                expires_at,
            ),
        )
        .is_err());
    }

    #[test]
    fn exact_session_revoke_has_terminal_and_retryable_statuses() {
        let client = DriveHttpClient::new("https://drive.example.test/base").unwrap();
        assert_eq!(
            client
                .session_revocation_url("session-42")
                .unwrap()
                .as_str(),
            "https://drive.example.test/base/auth/sessions/session-42/revoke"
        );
        assert!(client.session_revocation_url("").is_err());
        assert_eq!(
            logout_outcome_for_status(StatusCode::UNAUTHORIZED).unwrap(),
            LogoutOutcome::AlreadyInvalid
        );
        assert_eq!(
            remote_session_revocation_outcome_for_status(StatusCode::NOT_FOUND).unwrap(),
            RemoteSessionRevocationOutcome::AlreadyAbsent
        );
        assert!(remote_session_revocation_outcome_for_status(StatusCode::UNAUTHORIZED).is_err());
        assert!(
            remote_session_revocation_outcome_for_status(StatusCode::SERVICE_UNAVAILABLE).is_err()
        );
    }

    #[test]
    fn replacement_contract_keeps_the_simple_body_bounded() {
        const { assert!(SIMPLE_EXISTING_REPLACEMENT_LIMIT < 2 * 1024 * 1024) };
        assert!(is_unsupported_replacement_status(StatusCode::NOT_FOUND));
        assert!(is_unsupported_replacement_status(
            StatusCode::NOT_IMPLEMENTED
        ));
        assert!(!is_unsupported_replacement_status(StatusCode::CONFLICT));
    }

    #[test]
    fn resumable_replacement_uses_only_the_immutable_target_contract() {
        assert_eq!(
            replacement_session_body("file-42", 7, 1_572_864),
            serde_json::json!({
                "target_file_id": "file-42",
                "base_revision": 7,
                "total_size": 1_572_864,
            })
        );
        assert!(matches!(
            replacement_completion_outcome(UploadChunkResponse {
                file: None,
                conflict: Some(serde_json::json!({ "conflict_file_id": "fork-9" })),
            }),
            Ok(ExistingFileTransfer::Conflict)
        ));
    }

    #[test]
    fn remote_move_contract_carries_the_common_ancestor_and_accepts_only_exact_result() {
        assert_eq!(
            remote_move_body(7, Some("folder-9"), "renamed.pdf"),
            serde_json::json!({
                "base_revision": 7,
                "name": "renamed.pdf",
                "parent_id": "folder-9",
                "move_to_root": false,
            })
        );
        let moved = RemoteFile {
            id: "file-42".to_string(),
            workspace_id: "workspace-1".to_string(),
            parent_id: Some("folder-9".to_string()),
            name: "renamed.pdf".to_string(),
            kind: RemoteFileKind::File,
            revision: 8,
            trashed: false,
            content_hash: Some("same-body".to_string()),
            size_bytes: Some(9),
        };
        assert!(remote_move_response_matches(
            &moved,
            "file-42",
            "workspace-1",
            7,
            Some("folder-9"),
            "renamed.pdf",
        ));
        for wrong in [
            RemoteFile {
                id: "other-file".to_string(),
                ..moved.clone()
            },
            RemoteFile {
                revision: 9,
                ..moved.clone()
            },
            RemoteFile {
                parent_id: None,
                ..moved.clone()
            },
            RemoteFile {
                name: "unexpected.pdf".to_string(),
                ..moved.clone()
            },
        ] {
            assert!(!remote_move_response_matches(
                &wrong,
                "file-42",
                "workspace-1",
                7,
                Some("folder-9"),
                "renamed.pdf",
            ));
        }
    }

    #[test]
    fn stale_or_unusable_move_responses_never_report_a_completed_move() {
        assert_eq!(
            remote_move_terminal_outcome(StatusCode::CONFLICT),
            Some(RemoteMoveTransfer::Conflict)
        );
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::PRECONDITION_FAILED,
            StatusCode::LOCKED,
        ] {
            assert_eq!(
                remote_move_terminal_outcome(status),
                Some(RemoteMoveTransfer::NeedsReview)
            );
        }
        assert_eq!(remote_move_terminal_outcome(StatusCode::OK), None);
    }
}
