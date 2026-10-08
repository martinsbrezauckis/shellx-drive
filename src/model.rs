use serde::{Deserialize, Serialize};

mod human_sharing;

pub use human_sharing::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub service: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugState {
    pub service: String,
    pub data_dir: String,
    pub e2e_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailOutboxItem {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub recipient_email: String,
    pub subject: String,
    pub related_type: Option<String>,
    pub related_id: Option<String>,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub sent_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub id: String,
    pub name: String,
    pub mode: String,
    pub data_dir: String,
    pub bind: String,
    pub service_user: String,
    pub service_group: String,
    pub read_write_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub network_policy: String,
    pub status: String,
    pub last_checked_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateSandboxProfileRequest {
    pub mode: Option<String>,
    pub data_dir: Option<String>,
    pub bind: Option<String>,
    pub read_write_paths: Option<Vec<String>>,
    pub read_only_paths: Option<Vec<String>>,
    pub network_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxProfileResponse {
    pub profile: SandboxProfile,
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxProfileMutationResponse {
    pub profile: SandboxProfile,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxApplyIntentResponse {
    pub profile: SandboxProfile,
    pub commands: Vec<String>,
    pub unit_preview: String,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxPreviewResponse {
    pub profile: SandboxProfile,
    pub commands: Vec<String>,
    pub unit_preview: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugSandboxesResponse {
    pub service: String,
    pub sandboxes: Vec<SandboxPreviewResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MaintenanceStatus {
    /// `None` means Drive did not run a host probe and therefore cannot make a
    /// truthful attachment claim.
    pub ubuntu_pro_attached: Option<bool>,
    /// Explicitly distinguishes an unassessed host from one assessed as
    /// attached or detached. The current self-hosted binary reports
    /// `unassessed`: it does not execute Ubuntu Pro or package-manager probes.
    pub host_posture: String,
    pub token_source: String,
    pub sudo_source: String,
    pub restart_policy: String,
    pub package_update_policy: String,
    pub last_run_at: Option<String>,
    pub last_result: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MaintenanceStatusResponse {
    pub maintenance: MaintenanceStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessCheck {
    pub name: String,
    pub status: String,
    pub critical: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessResponse {
    pub live: bool,
    pub ready: bool,
    pub state: String,
    pub checks: Vec<ReadinessCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugMaintenanceResponse {
    pub service: String,
    pub maintenance: MaintenanceStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminTotals {
    pub workspaces: i64,
    pub users: i64,
    pub members: i64,
    pub files: i64,
    pub folders: i64,
    pub trashed_files: i64,
    pub shares: i64,
    pub drops: i64,
    pub comments: i64,
    pub folder_templates: i64,
    pub receipts: i64,
    pub activity: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminSummary {
    pub service: String,
    pub totals: AdminTotals,
    pub job_totals: BackgroundJobTotals,
    pub recent_receipts: Vec<Receipt>,
    pub recent_activity: Vec<Activity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundJob {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub workspace_id: Option<String>,
    pub file_id: Option<String>,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundJobTotals {
    pub queued: i64,
    pub running: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub skipped: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackgroundJobRunResponse {
    pub processed: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub skipped: i64,
    pub jobs: Vec<BackgroundJob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePreview {
    pub file_id: String,
    pub workspace_id: String,
    pub revision: i64,
    pub kind: String,
    pub content: String,
    pub thumbnail_hash: Option<String>,
    pub thumbnail_content_type: Option<String>,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub status: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilePreviewResponse {
    pub preview: FilePreview,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub file: DriveFile,
    pub rank: f64,
    pub matched_fields: Vec<String>,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResponse {
    pub query: String,
    pub files: Vec<DriveFile>,
    pub results: Vec<SearchResult>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugSearchResponse {
    pub service: String,
    pub query: String,
    pub using_fts: bool,
    pub query_plan: Vec<String>,
    pub results: Vec<SearchResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugBrowseTotals {
    pub workspaces: i64,
    pub live_files: i64,
    pub live_folders: i64,
    pub trashed_items: i64,
    pub current_file_bytes: i64,
    pub max_direct_children: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugBrowseWorkspace {
    pub workspace_id: String,
    pub storage_mode: String,
    pub live_files: i64,
    pub live_folders: i64,
    pub trashed_items: i64,
    pub current_file_bytes: i64,
    pub max_direct_children: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugLargeFolder {
    pub folder_ref: String,
    pub workspace_id: String,
    pub direct_children: i64,
    pub folder_size_bytes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugBrowseResponse {
    pub service: String,
    pub page_size: i64,
    pub large_folders_limit: i64,
    pub folder_size_semantics: String,
    pub supported_sort_keys: Vec<String>,
    pub supported_filter_keys: Vec<String>,
    pub totals: DebugBrowseTotals,
    pub workspaces: Vec<DebugBrowseWorkspace>,
    pub large_folders: Vec<DebugLargeFolder>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHealthTotals {
    pub workspaces: i64,
    pub files: i64,
    pub folders: i64,
    pub trashed_files: i64,
    pub downloadable_files: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncWorkspaceHealth {
    pub workspace_id: String,
    pub name: String,
    pub storage_mode: String,
    pub files: i64,
    pub folders: i64,
    pub trashed_files: i64,
    pub downloadable_files: i64,
    pub last_updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncHealthResponse {
    pub mode: String,
    pub generated_at: String,
    pub actor: Option<String>,
    pub totals: SyncHealthTotals,
    pub workspaces: Vec<SyncWorkspaceHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugSyncResponse {
    pub service: String,
    pub sync: SyncHealthResponse,
    pub job_totals: BackgroundJobTotals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncChange {
    pub id: i64,
    pub workspace_id: String,
    pub kind: String,
    pub entity_type: String,
    pub entity_id: String,
    pub actor: String,
    pub receipt_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncChangesResponse {
    pub cursor: i64,
    pub next_cursor: i64,
    pub changes: Vec<SyncChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugSyncChangesResponse {
    pub service: String,
    pub changes: Vec<SyncChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncConflict {
    pub workspace_id: String,
    pub file_id: String,
    pub conflict_of_file_id: String,
    pub name: String,
    pub conflict_of_revision: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncConflictsResponse {
    pub conflicts: Vec<SyncConflict>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MobileWorkspace {
    pub id: String,
    pub name: String,
    pub storage_mode: String,
    pub created_at: String,
    pub sync_mode: String,
    pub offline_files: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MobileWorkspacesResponse {
    pub mode: String,
    pub workspaces: Vec<MobileWorkspace>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MobileFileMetadata {
    pub id: String,
    pub workspace_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: FileKind,
    pub revision: i64,
    pub trashed: bool,
    pub starred: bool,
    pub has_content: bool,
    pub downloadable: bool,
    pub offline_marked: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MobileManifestResponse {
    pub workspace_id: String,
    pub mode: String,
    pub files: Vec<MobileFileMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MobileOfflineRequest {
    pub file_id: String,
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileOfflineFile {
    pub actor_email: String,
    pub workspace_id: String,
    pub file_id: String,
    pub marked_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MobileOfflineListResponse {
    pub files: Vec<MobileOfflineFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MobileOfflineMutationResponse {
    pub file_id: String,
    pub offline: bool,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileChunkDescriptor {
    pub index: usize,
    pub offset: i64,
    pub length: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileChunkManifestResponse {
    pub file_id: String,
    pub workspace_id: String,
    pub revision: i64,
    pub content_bytes: i64,
    pub chunk_size: usize,
    pub content_sha256: String,
    pub chunks: Vec<FileChunkDescriptor>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeltaChunkOperation {
    Copy {
        source_index: usize,
    },
    Data {
        content: Option<String>,
        content_base64: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeltaContentRequest {
    pub base_revision: i64,
    pub chunk_size: usize,
    pub operations: Vec<DeltaChunkOperation>,
    pub expected_content_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaWriteStats {
    pub id: String,
    pub file_id: String,
    pub workspace_id: String,
    pub actor_email: String,
    pub base_revision: i64,
    pub new_revision: i64,
    pub chunk_size: usize,
    pub chunks_total: usize,
    pub chunks_reused: usize,
    pub uploaded_bytes: i64,
    pub reconstructed_bytes: i64,
    pub content_sha256: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaContentResponse {
    pub file: DriveFile,
    pub receipt: Receipt,
    pub delta: DeltaWriteStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugDeltaSyncResponse {
    pub service: String,
    pub writes: Vec<DeltaWriteStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugMobileSyncResponse {
    pub service: String,
    pub mode: String,
    pub offline_files: Vec<MobileOfflineFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TwinScenarioDescriptor {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TwinScenarioCatalog {
    pub scenarios: Vec<TwinScenarioDescriptor>,
    pub faults: Vec<TwinScenarioDescriptor>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunTwinScenarioRequest {
    pub scenario: String,
    #[serde(default)]
    pub faults: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TwinAssertionResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TwinScenarioRunResponse {
    pub scenario: String,
    pub faults: Vec<String>,
    pub passed: bool,
    pub workspace_id: String,
    pub file_id: String,
    pub assertions: Vec<TwinAssertionResult>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcloneEntry {
    pub path: String,
    pub kind: FileKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcloneBundle {
    #[serde(default = "default_rclone_format")]
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub entries: Vec<RcloneEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_collision_policy: Option<RcloneFolderCollisionPolicy>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RcloneFolderCollisionPolicy {
    #[default]
    KeepBoth,
    Cancel,
}

#[derive(Debug, Clone, Serialize)]
pub struct RcloneImportResponse {
    pub imported: Vec<DriveFile>,
    pub summary: RcloneImportSummary,
    pub actions: Vec<RcloneImportPreviewAction>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RcloneImportSummary {
    pub entries: i64,
    pub created_files: i64,
    pub updated_files: i64,
    pub created_folders: i64,
    pub existing_folders: i64,
    pub skipped_entries: i64,
    pub invalid_entries: i64,
    pub collisions: i64,
    pub estimated_bytes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RcloneImportPreviewAction {
    pub path: String,
    pub resolved_path: String,
    pub file_id: String,
    pub kind: FileKind,
    pub action: String,
    pub bytes: i64,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RcloneImportPreviewResponse {
    pub dry_run: bool,
    pub summary: RcloneImportSummary,
    pub actions: Vec<RcloneImportPreviewAction>,
    pub receipt: Receipt,
}

fn default_rclone_format() -> String {
    "shellx-rclone-v1".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct OidcConfigResponse {
    pub enabled: bool,
    pub flow: String,
    pub token_type: String,
    pub max_expires_in_seconds: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcExchangeRequest {
    pub email: String,
    pub issuer: String,
    pub subject: String,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OidcExchangeResponse {
    pub token_type: String,
    pub sso_token: String,
    pub session_id: String,
    pub actor: String,
    pub issuer: String,
    pub subject: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub id: String,
    pub kind: String,
    pub actor: String,
    pub target_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub recipient_email: String,
    pub workspace_id: Option<String>,
    pub file_id: Option<String>,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub related_type: Option<String>,
    pub related_id: Option<String>,
    pub read_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationListResponse {
    pub unread_count: i64,
    pub notifications: Vec<Notification>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationMutationResponse {
    pub notification: Option<Notification>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub storage_mode: String,
    pub created_at: String,
    pub updated_at: String,
    pub archived: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// One file row in the account-wide browser. The embedded file remains the
/// normal Drive file shape; the additional fields describe only the caller's
/// relationship to the already-authorized workspace. They deliberately do not
/// expose an owner email or any membership inventory.
#[derive(Debug, Clone, Serialize)]
pub struct BrowseFile {
    #[serde(flatten)]
    pub file: DriveFile,
    pub workspace_name: String,
    /// `owner`, `editor`, `viewer`, or `admin` for this caller.
    pub access_role: String,
    pub owned_by_actor: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedTenant {
    pub id: String,
    pub name: String,
    pub owner_email: String,
    pub plan: String,
    pub billing_status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveUser {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMember {
    pub workspace_id: String,
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveGroup {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub group_id: String,
    pub user_id: String,
    pub email: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceGroupGrant {
    pub workspace_id: String,
    pub group_id: String,
    pub group_name: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    pub owner_email: String,
    pub storage_mode: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateWorkspaceResponse {
    pub workspace: Workspace,
    pub owner: DriveUser,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateWorkspaceRequest {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceMutationResponse {
    pub workspace: Workspace,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateHostedTenantRequest {
    pub name: String,
    pub owner_email: String,
    pub plan: Option<String>,
    pub billing_status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostedTenantResponse {
    pub tenant: HostedTenant,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostedTenantListResponse {
    pub tenants: Vec<HostedTenant>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostedStatusResponse {
    pub hosted_mode: bool,
    pub public_base_url: String,
    pub billing_provider: String,
    pub public_rate_limit_per_minute: i64,
    pub public_signup_enabled: bool,
    pub backup_scheduler: String,
    pub drop_malware_scanning: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostedSignupRequest {
    pub email: String,
    pub password: String,
    pub tenant_name: String,
    pub workspace_name: String,
    pub storage_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostedSignupResponse {
    pub account: AuthAccount,
    pub tenant: HostedTenant,
    pub workspace: Workspace,
    pub owner: DriveUser,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugHostedResponse {
    pub service: String,
    pub status: HostedStatusResponse,
    pub tenants: Vec<HostedTenant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceInvitation {
    pub id: String,
    pub workspace_id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub invited_by: String,
    pub expires_at: String,
    pub member_expires_in_seconds: Option<i64>,
    pub accepted_at: Option<String>,
    pub canceled_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct WorkspaceInvitationSecret {
    pub invitation: WorkspaceInvitation,
    pub token_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateWorkspaceInvitationRequest {
    pub email: String,
    pub role: String,
    pub member_expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceInvitationMutationResponse {
    pub invitation: WorkspaceInvitation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceInvitationListResponse {
    pub invitations: Vec<WorkspaceInvitation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceInvitationAcceptResponse {
    pub invitation: WorkspaceInvitation,
    pub member: WorkspaceMember,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransferWorkspaceOwnerRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferWorkspaceOwnerResponse {
    pub old_owner: WorkspaceMember,
    pub new_owner: WorkspaceMember,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceLeaveResponse {
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugInvitationsResponse {
    pub service: String,
    pub invitations: Vec<WorkspaceInvitation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpsertWorkspaceMemberRequest {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoveWorkspaceMemberRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceMemberResponse {
    pub member: WorkspaceMember,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpsertGroupMemberRequest {
    pub email: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpsertWorkspaceGroupGrantRequest {
    pub group_id: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupResponse {
    pub group: DriveGroup,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupMemberResponse {
    pub member: GroupMember,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceGroupGrantResponse {
    pub grant: WorkspaceGroupGrant,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveGroupRole {
    pub group_id: String,
    pub group_name: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveWorkspacePermission {
    pub workspace_id: String,
    pub actor_email: String,
    pub role: String,
    pub direct_role: Option<String>,
    pub group_roles: Vec<EffectiveGroupRole>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugGroupsResponse {
    pub service: String,
    pub groups: Vec<DriveGroup>,
    pub members: Vec<GroupMember>,
    pub workspace_grants: Vec<WorkspaceGroupGrant>,
    pub effective_permissions: Vec<EffectiveWorkspacePermission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Folder,
}

impl FileKind {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            FileKind::File => "file",
            FileKind::Folder => "folder",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "folder" => FileKind::Folder,
            _ => FileKind::File,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveFile {
    pub id: String,
    pub workspace_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: FileKind,
    pub revision: i64,
    pub trashed: bool,
    pub starred: bool,
    pub content_hash: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Stored byte length of the file's current server-readable body.
    /// `Some(n)` for files and `None` for folders. If a caller uploads a
    /// client-encrypted archive, this is the ciphertext byte length; Drive does
    /// not perform or claim that encryption. Optional + `serde(default)` so
    /// older clients and stored payloads that predate this field still
    /// deserialize.
    #[serde(default)]
    pub size_bytes: Option<i64>,
    /// Recursive logical size for folders: the sum of current, non-trashed
    /// descendant file bodies. It excludes historical revisions, backup
    /// bundles, covers/thumbnails, and storage overhead. Files report `None`.
    #[serde(default)]
    pub folder_size_bytes: Option<i64>,
    /// Whether this folder has a custom cover image set (Google-Drive-style
    /// folder covers, served by `GET /files/{id}/cover`). Always `false` for
    /// files and for folders without a cover. Optional + `serde(default)` so
    /// older clients and stored payloads that predate this field still
    /// deserialize. The backing blob hash is deliberately not exposed.
    #[serde(default)]
    pub has_cover: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePolicy {
    pub workspace_id: String,
    pub quota_bytes: Option<i64>,
    pub public_links_enabled: bool,
    pub link_password_required: bool,
    pub allow_never_expire: bool,
    pub max_link_ttl_seconds: i64,
    pub drop_password_required: bool,
    pub max_drop_ttl_seconds: i64,
    pub trash_retention_days: i64,
    pub revision_retention_days: i64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateWorkspacePolicyRequest {
    #[serde(default)]
    pub quota_bytes: NullableI64Patch,
    pub public_links_enabled: Option<bool>,
    pub link_password_required: Option<bool>,
    pub allow_never_expire: Option<bool>,
    pub max_link_ttl_seconds: Option<i64>,
    pub drop_password_required: Option<bool>,
    pub max_drop_ttl_seconds: Option<i64>,
    pub trash_retention_days: Option<i64>,
    pub revision_retention_days: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub enum NullableI64Patch {
    #[default]
    Missing,
    Set(Option<i64>),
}

impl NullableI64Patch {
    pub fn is_present(&self) -> bool {
        matches!(self, Self::Set(_))
    }
}

impl<'de> Deserialize<'de> for NullableI64Patch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<i64>::deserialize(deserializer).map(Self::Set)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspacePolicyReadResponse {
    pub policy: WorkspacePolicy,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspacePolicyMutationResponse {
    pub policy: WorkspacePolicy,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceUsage {
    pub workspace_id: String,
    pub quota_bytes: Option<i64>,
    pub current_file_bytes: i64,
    pub revision_bytes: i64,
    pub trashed_file_bytes: i64,
    pub remaining_bytes: Option<i64>,
    /// Derived auxiliary rows are deliberately accounted separately from file
    /// bodies and revisions. They are not part of the ordinary file quota.
    pub auxiliary_storage_bytes: i64,
    pub auxiliary_file_metadata_bytes: i64,
    pub auxiliary_metadata_fts_projection_bytes: i64,
    pub auxiliary_comment_reply_body_bytes: i64,
    pub auxiliary_notification_bytes: i64,
    pub auxiliary_email_outbox_bytes: i64,
    pub auxiliary_storage_limit_bytes: i64,
    pub auxiliary_storage_remaining_bytes: i64,
    pub auxiliary_storage_over_limit: bool,
}

/// Derived, reconstructible workspace-local storage accounting. This is kept
/// separate from the regular file-body quota because it covers database rows
/// whose lifetime and admission rules differ from blobs and revisions.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceAuxiliaryStorageUsage {
    pub workspace_id: String,
    pub total_bytes: i64,
    pub file_metadata_bytes: i64,
    pub metadata_fts_projection_bytes: i64,
    pub comment_reply_body_bytes: i64,
    pub notification_bytes: i64,
    pub email_outbox_bytes: i64,
    pub limit_bytes: i64,
    pub remaining_bytes: i64,
    pub over_limit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileAccessStatistics {
    pub file_id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub access_count: i64,
    pub download_count: i64,
    pub last_accessed_at: Option<String>,
    pub last_downloaded_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceFileStatisticsResponse {
    pub workspace_id: String,
    pub access_count: i64,
    pub download_count: i64,
    pub files: Vec<FileAccessStatistics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminWorkspaceSummary {
    pub workspace: Workspace,
    pub usage: WorkspaceUsage,
    pub member_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminWorkspacesResponse {
    pub workspaces: Vec<AdminWorkspaceSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceDeleteResponse {
    pub workspace_id: String,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugUsageResponse {
    pub service: String,
    pub usage: Vec<WorkspaceUsage>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugPoliciesResponse {
    pub service: String,
    pub policies: Vec<WorkspacePolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupMetadata {
    pub backup_id: String,
    pub format: String,
    pub created_at: String,
    pub table_count: u64,
    pub row_count: u64,
    pub blob_count: u64,
    pub content_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupTable {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupBlob {
    pub hash: String,
    pub base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupBundle {
    pub format: String,
    pub backup_id: String,
    pub created_at: String,
    pub metadata: BackupMetadata,
    pub tables: Vec<BackupTable>,
    pub blobs: Vec<BackupBlob>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupListResponse {
    pub backups: Vec<BackupMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupJob {
    pub id: String,
    pub backup_id: String,
    pub kind: String,
    pub format: String,
    pub status: String,
    pub phase: String,
    pub actor: String,
    pub archive_sha256: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupJobResponse {
    pub job: BackupJob,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupMutationResponse {
    pub backup: BackupMetadata,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    pub enabled: bool,
    pub schedule: String,
    pub retention_count: i64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateBackupPolicyRequest {
    pub enabled: Option<bool>,
    pub schedule: Option<String>,
    pub retention_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupPolicyResponse {
    pub policy: BackupPolicy,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupPolicyMutationResponse {
    pub policy: BackupPolicy,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupDownloadResponse {
    pub bundle: BackupBundle,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupValidationResponse {
    pub valid: bool,
    pub backup: BackupMetadata,
    pub issues: Vec<String>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleLog {
    pub kind: String,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundle {
    pub id: String,
    pub service: String,
    pub generated_at: String,
    pub debug_export: serde_json::Value,
    pub logs: Vec<SupportBundleLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleMetadata {
    pub id: String,
    pub receipt_id: String,
    pub generated_at: String,
    pub debug_export_bytes: i64,
    pub logs_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupportBundleResponse {
    pub bundle: SupportBundle,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugSupportBundleResponse {
    pub service: String,
    pub support_bundles: Vec<SupportBundleMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugBackupsResponse {
    pub service: String,
    pub backups: Vec<BackupMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAccount {
    pub user_id: String,
    pub email: String,
    pub is_admin: bool,
    pub totp_enabled: bool,
    pub recovery_codes_remaining: usize,
    pub disabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct AuthAccountSecret {
    pub user_id: String,
    pub email: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub recovery_code_hashes: Vec<String>,
    pub disabled_at: Option<String>,
    /// Monotonic compare-and-swap token for password, TOTP, recovery-code,
    /// disable, and administrator-security changes.
    pub security_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapRequest {
    pub email: String,
    pub password: String,
    pub cookie_only: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapWizardRequest {
    pub email: String,
    pub password: String,
    pub workspace_name: String,
    pub storage_mode: Option<String>,
    pub cookie_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapWizardResponse {
    pub login: LoginResponse,
    pub account: AuthAccount,
    pub workspace: Workspace,
    pub owner: DriveUser,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapStatusResponse {
    pub required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistrationStatusResponse {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub cookie_only: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationPolicyRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistrationPolicyResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugRegistrationResponse {
    pub service: String,
    pub enabled: bool,
    pub accounts: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateAuthAccountRequest {
    pub email: String,
    pub password: String,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateAuthAccountRequest {
    pub disabled: Option<bool>,
    pub is_admin: Option<bool>,
    pub reset_password: Option<String>,
    pub reset_2fa: Option<bool>,
    /// Required when an administrator disables or demotes their own account.
    /// This is a typed confirmation of the affected account email.
    pub confirm_email: Option<String>,
    /// Required with `confirm_email` for a self-disable or self-demotion.
    /// It is verified against the current local account record and never kept.
    pub current_password: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthAccountMutationResponse {
    pub account: AuthAccount,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub totp_code: Option<String>,
    pub recovery_code: Option<String>,
    pub cookie_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub actor: String,
    pub is_admin: bool,
    pub requires_2fa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    pub totp_code: Option<String>,
    pub recovery_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangePasswordResponse {
    pub requires_2fa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<AuthAccount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordResetConsumeRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordResetResponse {
    pub queued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<AuthAccount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,
}

/// Administrator-controlled recovery link issuance. The plaintext capability
/// exists only in the immediate authenticated response and is never retained
/// in Drive storage, debug views, receipts, or security-event metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminPasswordResetLinkRequest {
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminPasswordResetLinkResponse {
    pub reset_link: String,
    pub expires_at: String,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminPasswordResetLinkRevocationResponse {
    pub revoked: bool,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct MeResponse {
    pub actor: String,
    pub is_admin: bool,
    pub auth_mode: String,
    pub totp_enabled: Option<bool>,
    pub account_security_available: bool,
    pub session_management_available: bool,
    pub notifications_available: bool,
    pub admin_tools_available: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TotpSetupRequest {
    pub password: String,
    pub code: Option<String>,
    pub recovery_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub otpauth_uri: String,
    pub qr_size: u8,
    pub qr_modules: String,
    #[serde(flatten)]
    pub replacement: AuthSessionReplacementResponse,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TotpCodeRequest {
    pub code: Option<String>,
    pub recovery_code: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
    #[serde(flatten)]
    pub replacement: AuthSessionReplacementResponse,
}

#[derive(Debug, Clone, Serialize)]
pub struct TotpDisableResponse {
    #[serde(flatten)]
    pub account: AuthAccount,
    #[serde(flatten)]
    pub replacement: AuthSessionReplacementResponse,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSessionReplacementResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_expires_at: Option<String>,
    /// Account-security mutations invoked by an account-wide delegation revoke
    /// that bearer instead of minting a human browser session for it.
    pub delegated_credential_revoked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthAccountListResponse {
    pub accounts: Vec<AuthAccount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugAuthResponse {
    pub service: String,
    pub accounts: Vec<AuthAccount>,
    pub sessions: Vec<AuthSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAttemptDebug {
    pub key: String,
    pub actor_email: Option<String>,
    #[serde(default)]
    pub client_fingerprint: Option<String>,
    pub scope: String,
    pub failures: i64,
    pub locked_until: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugAuthAttemptsResponse {
    pub service: String,
    pub attempts: Vec<AuthAttemptDebug>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthAttemptUnlockRequest {
    pub key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthAttemptUnlockResponse {
    pub removed: bool,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub id: String,
    pub actor_email: String,
    pub issuer: String,
    pub subject: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub created_at: String,
    pub revoked: bool,
}

/// A human-facing browser session. Raw network metadata is intentionally kept
/// out of [`AuthSession`] so debug/support exports cannot inherit it by simply
/// serializing the authentication ledger.
#[derive(Debug, Clone, Serialize)]
pub struct AccountSession {
    #[serde(flatten)]
    pub session: AuthSession,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub last_seen_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSessionListResponse {
    pub sessions: Vec<AccountSession>,
    pub current_session_id: Option<String>,
    pub total: usize,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSessionMutationResponse {
    pub session: AuthSession,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthLogoutResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<AuthSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_agent: Option<DelegatedAgent>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSessionBulkMutationResponse {
    pub revoked_sessions: usize,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub category: String,
    pub action: String,
    pub route: String,
    pub outcome: String,
    pub status_code: i64,
    pub actor_email: Option<String>,
    pub credential_kind: String,
    pub credential_ref: Option<String>,
    pub session_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub target_ref: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEventListResponse {
    pub events: Vec<SecurityEvent>,
    pub retention_days: i64,
    pub maximum_events: i64,
}

/// Metadata for a revocable application/device credential. The stored hash is
/// never serialized; `token` appears only in the create response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppToken {
    pub id: String,
    pub label: String,
    pub actor_email: String,
    pub workspace_ids: Vec<String>,
    pub expires_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateAppTokenRequest {
    pub label: String,
    pub actor_email: String,
    pub workspace_ids: Vec<String>,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateAppTokenResponse {
    pub app_token: AppToken,
    pub token: String,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppTokenListResponse {
    pub app_tokens: Vec<AppToken>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppTokenMutationResponse {
    pub app_token: AppToken,
    pub receipt: Receipt,
}

/// The maximum authority an AI/service credential may exercise inside one
/// granted folder. This is intentionally separate from human workspace roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPermission {
    View,
    Edit,
}

impl AgentPermission {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Edit => "edit",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "edit" => Self::Edit,
            _ => Self::View,
        }
    }

    pub fn allows_edit(self) -> bool {
        matches!(self, Self::Edit)
    }
}

/// Public management metadata for one folder grant and its current token.
/// Token hashes and plaintext token material are never part of this record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAccess {
    pub principal_id: String,
    pub name: String,
    pub grant_id: String,
    pub workspace_id: String,
    pub root_file_id: String,
    pub permission: AgentPermission,
    pub expires_at: String,
    pub grant_revoked_at: Option<String>,
    pub token_id: String,
    pub token_expires_at: String,
    pub token_last_used_at: Option<String>,
    pub token_revoked_at: Option<String>,
    pub principal_disabled: bool,
    pub created_by: String,
    pub created_at: String,
    pub root_name: String,
    pub workspace_name: String,
    pub active: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateAgentAccessRequest {
    pub name: Option<String>,
    pub principal_id: Option<String>,
    pub permission: AgentPermission,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateAgentAccessResponse {
    pub access: AgentAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentAccessListResponse {
    pub access: Vec<AgentAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentAccessMutationResponse {
    pub access: AgentAccess,
    pub receipt: Receipt,
}

/// Human-visible metadata for one reusable no-login agent identity. Folder
/// grants are independent; the current token is principal-wide.
#[derive(Debug, Clone, Serialize)]
pub struct AgentPrincipal {
    pub principal_id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: String,
    pub principal_disabled: bool,
    pub token_id: Option<String>,
    pub token_expires_at: Option<String>,
    pub token_last_used_at: Option<String>,
    pub token_revoked_at: Option<String>,
    pub active: bool,
    pub grants: Vec<AgentAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants_next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPrincipalListResponse {
    pub agents: Vec<AgentPrincipal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentPrincipalGrantListResponse {
    pub grants: Vec<AgentAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RotateAgentPrincipalRequest {
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotateAgentPrincipalResponse {
    pub agent: AgentPrincipal,
    pub token: String,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoveAgentPrincipalResponse {
    pub receipt: Receipt,
}

/// An explicit, account-wide delegation to an AI agent. This is distinct from
/// a folder grant and carries only the owner's current Drive authority.
#[derive(Debug, Clone, Serialize)]
pub struct DelegatedAgent {
    pub principal_id: String,
    pub name: String,
    pub owner_email: String,
    pub owner_is_admin: bool,
    pub token_id: String,
    pub token_expires_at: String,
    pub token_last_used_at: Option<String>,
    pub token_revoked_at: Option<String>,
    pub principal_disabled: bool,
    pub created_at: String,
    pub active: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateDelegatedAgentRequest {
    pub name: String,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDelegatedAgentResponse {
    pub agent: DelegatedAgent,
    /// Returned only at issuance or rotation; Drive stores a hash instead.
    pub token: String,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegatedAgentListResponse {
    pub agents: Vec<DelegatedAgent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegatedAgentMutationResponse {
    pub agent: DelegatedAgent,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentSessionResponse {
    pub principal_id: String,
    pub name: String,
    pub token_id: String,
    pub grants: Vec<AgentAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentCreateFileRequest {
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: FileKind,
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugSessionsResponse {
    pub service: String,
    pub sessions: Vec<AuthSession>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetentionRequest {
    pub workspace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetentionTrashCandidate {
    pub workspace_id: String,
    pub file_id: String,
    pub name: String,
    pub trashed_at: String,
    pub retention_days: i64,
    pub content_bytes: i64,
    #[serde(skip_serializing)]
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetentionRevisionCandidate {
    pub workspace_id: String,
    pub file_id: String,
    pub name: String,
    pub revision: i64,
    pub created_at: String,
    pub retention_days: i64,
    pub content_bytes: i64,
    #[serde(skip_serializing)]
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetentionTotals {
    pub trashed_files: usize,
    pub revisions: usize,
    pub content_bytes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetentionPreviewResponse {
    pub service: String,
    pub dry_run: bool,
    pub workspace_id: Option<String>,
    pub trash: Vec<RetentionTrashCandidate>,
    pub revisions: Vec<RetentionRevisionCandidate>,
    pub totals: RetentionTotals,
    /// Another bounded apply pass is needed to finish the current due set.
    pub more_available: bool,
    pub receipt: Option<Receipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub labels: Vec<String>,
    pub custom_metadata: serde_json::Value,
    /// Stored byte length of the file's content (`None` for folders), so the
    /// `GET /files/{id}/metadata` endpoint carries size alongside labels/custom
    /// metadata. `serde(default)` keeps older payloads deserializable.
    #[serde(default)]
    pub size_bytes: Option<i64>,
    /// Same recursive logical folder size as `DriveFile::folder_size_bytes`.
    #[serde(default)]
    pub folder_size_bytes: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateFileRequest {
    pub workspace_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: FileKind,
    pub content: Option<String>,
    /// Optional relative path for folder uploads (e.g. a browser
    /// `webkitRelativePath` like `docs/2026/report.txt`). When set, the create
    /// route materialises the intermediate folders under `parent_id` and lands
    /// the file at the leaf segment; `name`/`parent_id` are derived from it.
    /// `None`/absent for a plain single-file create (serde default keeps older
    /// clients compatible).
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateFileRequest {
    /// Optional optimistic precondition for metadata updates. Existing web
    /// clients may omit it; the desktop mirror supplies its persisted common
    /// ancestor revision for every inferred file rename/move.
    #[serde(default)]
    pub base_revision: Option<i64>,
    pub name: Option<String>,
    pub parent_id: Option<String>,
    pub move_to_root: Option<bool>,
    /// Destination behavior when a rename or move finds an active sibling.
    /// Omitted requests use the product default, `keep_both`; `replace` is
    /// limited to one file replacing another, and `cancel` leaves both intact.
    #[serde(default)]
    pub collision_policy: Option<String>,
    /// Exact active sibling selected by a `replace` collision policy.
    #[serde(default)]
    pub replace_target_id: Option<String>,
    /// Optimistic precondition for that exact active sibling. The replacement
    /// keeps its ID and revision lineage, so callers must confirm both values
    /// they chose to replace.
    #[serde(default)]
    pub replace_target_revision: Option<i64>,
    pub labels: Option<Vec<String>>,
    pub custom_metadata: Option<serde_json::Value>,
}

/// The copy API must distinguish an omitted destination from an explicit JSON
/// `null`: omission preserves the source parent while `null` targets the
/// workspace root.
#[derive(Debug, Clone, Default)]
pub enum CopyParentId {
    #[default]
    Omitted,
    Root,
    Parent(String),
}

impl<'de> Deserialize<'de> for CopyParentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match Option::<String>::deserialize(deserializer)? {
            Some(parent_id) => Self::Parent(parent_id),
            None => Self::Root,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CopyFileRequest {
    pub name: Option<String>,
    #[serde(default)]
    pub parent_id: CopyParentId,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileTreeNode {
    pub id: String,
    pub workspace_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub path: String,
    pub kind: FileKind,
    pub revision: i64,
    pub trashed: bool,
    pub starred: bool,
    pub updated_at: String,
    /// Stored byte length of the file's content (`None` for folders), mirroring
    /// `DriveFile::size_bytes` so tree consumers can show sizes too.
    pub size_bytes: Option<i64>,
    /// Recursive current-body size for folders; `None` for files.
    #[serde(default)]
    pub folder_size_bytes: Option<i64>,
    /// Whether this folder has a custom cover image set, mirroring
    /// `DriveFile::has_cover`. `serde(default)` for backward-compatible payloads.
    #[serde(default)]
    pub has_cover: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileTreeResponse {
    pub workspace_id: String,
    pub nodes: Vec<FileTreeNode>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BulkFileActionRequest {
    pub action: String,
    pub file_ids: Vec<String>,
}

/// Keep one bulk mutation bounded before authorization performs per-row reads.
pub const MAX_BULK_FILE_ACTIONS: usize = 512;

#[derive(Debug, Clone, Serialize)]
pub struct BulkFileActionResponse {
    pub files: Vec<DriveFile>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PutContentRequest {
    pub base_revision: i64,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileMutationResponse {
    pub file: DriveFile,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct OfficeProviderStatus {
    pub configured: bool,
    pub name: String,
    pub launch_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OfficeEditSession {
    pub file_id: String,
    pub actor_email: String,
    pub base_revision: i64,
    pub expires_at: String,
    pub launch_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OfficeOpenResponse {
    pub file: DriveFile,
    pub base_revision: i64,
    pub save_url: String,
    pub locking: String,
    pub provider: OfficeProviderStatus,
    pub edit_session: Option<OfficeEditSession>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OfficeSessionManifest {
    pub file: DriveFile,
    pub actor_email: String,
    pub provider_name: String,
    pub base_revision: i64,
    pub expires_at: String,
    pub locking: String,
    pub workspace_storage_mode: String,
    pub package_url: String,
    pub commit_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OfficePackageCommitQuery {
    pub base_revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugOfficeSession {
    pub id: String,
    pub file_id: String,
    pub actor_email: String,
    pub base_revision: i64,
    pub provider_name: String,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugOfficeSessionsResponse {
    pub service: String,
    pub sessions: Vec<DebugOfficeSession>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileOperationResponse {
    pub file: DriveFile,
    pub metadata: FileMetadata,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRevision {
    pub file_id: String,
    pub revision: i64,
    pub has_content: bool,
    pub content_bytes: i64,
    pub created_at: String,
    pub conflict_of_revision: Option<i64>,
    pub pinned: bool,
    pub current: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RevisionStorageSummary {
    pub revision_count: usize,
    pub content_bytes: i64,
    pub reclaimable_content_bytes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRevisionsResponse {
    pub revisions: Vec<FileRevision>,
    pub storage: RevisionStorageSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRevisionMutationResponse {
    pub revisions: Vec<FileRevision>,
    pub storage: RevisionStorageSummary,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRevisionPruneResponse {
    pub deleted_revisions: i64,
    pub deleted_content_bytes: i64,
    pub revisions: Vec<FileRevision>,
    pub storage: RevisionStorageSummary,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugFileTreeResponse {
    pub service: String,
    pub trees: Vec<FileTreeResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSession {
    pub id: String,
    pub workspace_id: String,
    pub actor_email: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub total_size: Option<i64>,
    pub received_bytes: i64,
    pub completed: bool,
    pub canceled: bool,
    pub file_id: Option<String>,
    pub upload_url: String,
    pub created_at: String,
    pub updated_at: String,
    pub canceled_at: Option<String>,
    /// Optional relative folder-upload path captured at session start (e.g. a
    /// browser `webkitRelativePath` like `docs/2026/report.txt`). When set, the
    /// resumable-finish handler materialises the intermediate folders under
    /// `parent_id` and lands the file at the leaf segment. `None` for a plain
    /// single-file upload. `serde(default)` keeps older payloads deserializable.
    #[serde(default)]
    pub path: Option<String>,
    /// Collision behavior retained until a new-file session is finalized.
    /// `keep_both` is the historical default; `cancel` keeps a user choice
    /// effective even when another upload wins the race after session start.
    #[serde(default = "default_upload_duplicate_policy")]
    pub duplicate_policy: String,
    /// Existing file this session replaces. Present only together with
    /// `base_revision`; absent for the established new-file upload flow.
    #[serde(default)]
    pub target_file_id: Option<String>,
    /// Optimistic revision captured when `target_file_id` was selected.
    #[serde(default)]
    pub base_revision: Option<i64>,
    /// Internal receipt linkage used to make a retried terminal chunk return
    /// the original completion outcome without issuing another mutation.
    #[serde(default, skip_serializing)]
    pub completion_receipt_id: Option<String>,
    /// Internal snapshot of the current target revision at a stale terminal
    /// completion. Keeps a final-chunk retry's conflict metadata immutable.
    #[serde(default, skip_serializing)]
    pub completion_current_revision: Option<i64>,
}

fn default_upload_duplicate_policy() -> String {
    "keep_both".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateUploadSessionRequest {
    /// Required for a new-file session. Replacement sessions derive their
    /// workspace, parent, and name from `target_file_id` instead.
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Required for a new-file session. Ignored for replacements so callers
    /// cannot retarget an existing-file update by supplying a duplicate name.
    #[serde(default)]
    pub name: Option<String>,
    pub total_size: Option<i64>,
    /// Optional relative path for folder uploads (e.g. a browser
    /// `webkitRelativePath` like `docs/2026/report.txt`). When set, the
    /// resumable-finish handler materialises the intermediate folders under
    /// `parent_id` and lands the file at the leaf segment; the final `name`/
    /// `parent_id` are derived from it. `None`/absent for a plain single-file
    /// upload (serde default keeps older clients compatible).
    #[serde(default)]
    pub path: Option<String>,
    /// Duplicate handling chosen after the advisory preflight. Older clients
    /// omit this and retain the historical keep-both behavior.
    #[serde(default)]
    pub duplicate_policy: Option<String>,
    /// When supplied together with `base_revision`, creates a resumable
    /// replacement session for this exact regular file.
    #[serde(default)]
    pub target_file_id: Option<String>,
    /// Optimistic revision for `target_file_id`. Both fields are required as a
    /// pair so a resumed session cannot silently overwrite a newer revision.
    #[serde(default)]
    pub base_revision: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadPreflightFile {
    pub name: String,
    pub size: i64,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadPreflightRequest {
    pub workspace_id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    pub files: Vec<UploadPreflightFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadPreflightConflict {
    pub index: usize,
    pub path: String,
    pub kind: String,
    pub existing_file_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadPreflightResponse {
    pub workspace_id: String,
    pub requested_bytes: i64,
    pub current_file_bytes: Option<i64>,
    pub quota_bytes: Option<i64>,
    pub remaining_bytes: Option<i64>,
    pub fits: bool,
    pub conflicts: Vec<UploadPreflightConflict>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadChunkRequest {
    pub offset: i64,
    pub content: Option<String>,
    pub content_base64: Option<String>,
    pub finish: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadSessionResponse {
    pub session: UploadSession,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadSessionListResponse {
    pub sessions: Vec<UploadSession>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadSessionMutationResponse {
    pub session: UploadSession,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UploadCleanupRequest {
    pub older_than_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadCleanupResponse {
    pub cleaned_sessions: i64,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugUploadsResponse {
    pub service: String,
    pub sessions: Vec<UploadSession>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadChunkResponse {
    pub session: UploadSession,
    pub file: Option<DriveFile>,
    pub receipt: Option<Receipt>,
    /// A stale replacement base preserves the uploaded bytes as this conflict
    /// file. It is returned on the terminal request (and a terminal retry)
    /// instead of silently replacing the newer current revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict: Option<StaleRevisionResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StaleRevisionResponse {
    pub error: &'static str,
    pub file_id: String,
    pub attempted_base_revision: i64,
    pub current_revision: i64,
    pub conflict_file_id: String,
    pub receipt: Receipt,
}

pub enum ContentWrite {
    Updated { file: DriveFile, receipt: Receipt },
    Conflict(StaleRevisionResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentReply {
    pub id: String,
    pub comment_id: String,
    pub author_email: String,
    pub body: String,
    pub created_at: String,
    pub updated_at: String,
    pub edited_at: Option<String>,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentThread {
    pub id: String,
    pub file_id: String,
    pub author_email: String,
    pub body: String,
    pub resolved: bool,
    pub created_at: String,
    pub updated_at: String,
    pub edited_at: Option<String>,
    pub deleted_at: Option<String>,
    pub replies: Vec<CommentReply>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCommentRequest {
    pub body: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCommentRequest {
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommentMutationResponse {
    pub comment: CommentThread,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCommentReplyRequest {
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommentReplyMutationResponse {
    pub reply: CommentReply,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderTemplateItem {
    pub id: String,
    pub template_id: String,
    pub path: String,
    pub kind: FileKind,
    pub content: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderTemplate {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub items: Vec<FolderTemplateItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateFolderTemplateItemRequest {
    pub path: String,
    pub kind: FileKind,
    pub content: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateFolderTemplateRequest {
    pub name: String,
    pub description: Option<String>,
    pub items: Vec<CreateFolderTemplateItemRequest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApplyFolderTemplateRequest {
    pub root_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FolderTemplateMutationResponse {
    pub template: FolderTemplate,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyFolderTemplateResponse {
    pub template: FolderTemplate,
    pub created_files: Vec<DriveFile>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activity {
    pub id: String,
    pub kind: String,
    pub actor: String,
    pub target_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareLink {
    pub id: String,
    pub file_id: String,
    /// Target kind of the shared node: `"file"` or `"folder"`. A folder share's
    /// scope is that folder's subtree (read-only). Stored in the `shares`
    /// table's `target_kind` column; defaults to `"file"` so pre-folder-share
    /// rows and payloads keep resolving unchanged.
    #[serde(default = "default_share_kind")]
    pub kind: String,
    /// When the link stops resolving, RFC3339. `None` (serialized as JSON
    /// `null`) means the link **never expires** — a permanent share. Created via
    /// `POST /shares` with `expires_in_seconds <= 0`.
    pub expires_at: Option<String>,
    /// The operator-selected lifetime used to render and edit this share
    /// consistently after refresh. `0` means never; legacy rows may omit it
    /// until migration derives the nearest supported choice.
    pub expires_in_seconds: Option<i64>,
    pub revoked: bool,
    pub created_at: String,
    pub access_count: i64,
    pub last_accessed_at: Option<String>,
    pub allow_download: bool,
    pub recipient_note: Option<String>,
    pub max_uses: Option<i64>,
    pub uses_remaining: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugShareLink {
    pub id: String,
    pub file_id: String,
    pub kind: String,
    pub expires_at: Option<String>,
    pub expires_in_seconds: Option<i64>,
    pub revoked: bool,
    pub created_at: String,
    pub access_count: i64,
    pub last_accessed_at: Option<String>,
    pub allow_download: bool,
    pub recipient_note_present: bool,
    pub max_uses: Option<i64>,
    pub uses_remaining: Option<i64>,
}

impl From<ShareLink> for DebugShareLink {
    fn from(share: ShareLink) -> Self {
        Self {
            id: share.id,
            file_id: share.file_id,
            kind: share.kind,
            expires_at: share.expires_at,
            expires_in_seconds: share.expires_in_seconds,
            revoked: share.revoked,
            created_at: share.created_at,
            access_count: share.access_count,
            last_accessed_at: share.last_accessed_at,
            allow_download: share.allow_download,
            recipient_note_present: share.recipient_note.is_some(),
            max_uses: share.max_uses,
            uses_remaining: share.uses_remaining,
        }
    }
}

fn default_share_kind() -> String {
    "file".to_string()
}

/// One entry inside a shared folder's subtree, returned by the public share
/// metadata endpoint (`GET /pub/shares/{id}` with `Accept: application/json`).
/// `path` is relative to the shared folder root (the folder's own name is NOT
/// included), so it can be passed straight to
/// `GET /pub/shares/{id}/content?path=<path>`.
#[derive(Debug, Clone, Serialize)]
pub struct ShareEntry {
    pub path: String,
    pub name: String,
    /// `"file"` or `"folder"`.
    pub kind: String,
    /// Byte length for files; `None` for folders.
    pub size_bytes: Option<i64>,
    /// Recursive current-body size for folders; `None` for files.
    pub folder_size_bytes: Option<i64>,
    /// Last modification time for the shared node, RFC3339. Public clients use
    /// this for the same useful file-browser context as the authenticated UI.
    pub updated_at: String,
}

/// Machine-readable metadata for a public share, served to agents that request
/// `Accept: application/json` (or `?format=json`) on `GET /pub/shares/{id}`.
/// Humans get the HTML guest page off the same URL instead.
#[derive(Debug, Clone, Serialize)]
pub struct PublicShareMetadata {
    /// `"file"` or `"folder"`.
    pub kind: String,
    pub name: String,
    /// Byte length for a shared file; `None` for folders.
    pub size_bytes: Option<i64>,
    /// Recursive current-body size for a shared folder; `None` for files.
    pub folder_size_bytes: Option<i64>,
    /// Last modification time for the shared root node, RFC3339.
    pub updated_at: String,
    /// Always `"read"` — public shares are read-only.
    pub permission: String,
    /// When the link stops resolving, RFC3339. `null` means the link **never
    /// expires** (a permanent share).
    pub expires_at: Option<String>,
    pub allow_download: bool,
    pub recipient_note: Option<String>,
    pub max_uses: Option<i64>,
    pub access_count: i64,
    pub uses_remaining: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// `true` when a link password must be supplied to read content (and, for a
    /// folder, to list `entries`).
    pub requires_password: bool,
    /// Subtree listing for a folder share. Present only when the caller is
    /// entitled to see it (no password required, or the correct password was
    /// supplied). Omitted entirely for file shares and for password-protected
    /// folder shares accessed without the password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<ShareEntry>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateShareRequest {
    pub file_id: String,
    pub password: String,
    pub expires_in_seconds: i64,
    pub notify_email: Option<String>,
    #[serde(default = "default_true")]
    pub allow_download: bool,
    #[serde(default)]
    pub recipient_note: Option<String>,
    #[serde(default)]
    pub max_uses: Option<i64>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateShareResponse {
    pub share: ShareLink,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateShareRequest {
    pub password: Option<String>,
    pub expires_in_seconds: Option<i64>,
    pub allow_download: Option<bool>,
    pub recipient_note: Option<String>,
    pub clear_recipient_note: Option<bool>,
    pub max_uses: Option<i64>,
    pub clear_max_uses: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShareListResponse {
    pub shares: Vec<ShareLink>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SharePasswordRequest {
    pub password: String,
    /// Optional relative path inside a folder share's subtree. Ignored for file
    /// shares; required (via body or `?path=`) to read a file from a folder
    /// share through the backward-compat `POST /pub/shares/{id}/content` route.
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropLink {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    #[serde(default)]
    pub inbox_file_id: Option<String>,
    pub expires_at: String,
    pub revoked: bool,
    pub created_at: String,
    pub upload_count: i64,
    pub last_uploaded_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateDropRequest {
    pub workspace_id: String,
    pub name: String,
    pub password: String,
    pub expires_in_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDropResponse {
    pub drop: DropLink,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateDropRequest {
    pub name: Option<String>,
    pub password: Option<String>,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DropListResponse {
    pub drops: Vec<DropLink>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatePublicDropUploadRequest {
    pub name: String,
    pub total_size: i64,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicDropUploadSession {
    pub id: String,
    pub upload_url: String,
    pub total_size: i64,
    pub received_bytes: i64,
    pub status: String,
    pub duplicate_policy: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicDropUploadResponse {
    pub session: PublicDropUploadSession,
    pub receipt: Option<Receipt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicDropAccessGrant {
    pub access_token: String,
    pub expires_at: i64,
    pub name: String,
}

/// Redacted operator view of one public Drop upload. File names, relative
/// paths, MIME declarations, client fingerprints, capability tokens, and file
/// ids are deliberately omitted.
#[derive(Debug, Clone, Serialize)]
pub struct DebugDropUploadSession {
    pub session_ref: String,
    pub status: String,
    pub total_size: i64,
    pub received_bytes: i64,
    pub chunk_count: i64,
    pub has_file: bool,
    pub last_error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub canceled_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugDropUploadHealthResponse {
    pub service: String,
    pub drop_ref: String,
    pub total_sessions: i64,
    pub listed_sessions: i64,
    pub sessions_truncated: bool,
    pub active_sessions: i64,
    pub completed_sessions: i64,
    pub canceled_sessions: i64,
    pub failed_sessions: i64,
    pub active_received_bytes: i64,
    pub sessions: Vec<DebugDropUploadSession>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugSharesResponse {
    pub service: String,
    pub shares: Vec<DebugShareLink>,
    pub attempts: Vec<AuthAttemptDebug>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugDropsResponse {
    pub service: String,
    pub drops: Vec<DropLink>,
    pub attempts: Vec<AuthAttemptDebug>,
}
