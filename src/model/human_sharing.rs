use serde::{Deserialize, Serialize};

use super::DriveFile;

#[derive(Debug, Clone, Serialize)]
pub struct HumanItemGrant {
    pub id: String,
    pub workspace_id: String,
    pub root_file_id: String,
    pub principal_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_ref: Option<String>,
    pub principal_label: String,
    pub role: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateHumanItemGrantRequest {
    pub principal_kind: String,
    #[serde(default)]
    pub principal_ref: Option<String>,
    pub role: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateHumanItemGrantRequest {
    pub role: Option<String>,
    #[serde(default)]
    pub expires_at: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HumanItemGrantResponse {
    pub grant: HumanItemGrant,
    pub receipt: super::Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct HumanItemGrantListResponse {
    pub grants: Vec<HumanItemGrant>,
    pub action_capabilities: ItemActionCapabilities,
    /// The administrator-controlled server policy that gates new and changed
    /// `everyone` grants. Existing grants remain visible and revocable.
    pub everyone_policy_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EveryoneGrantPolicy {
    pub everyone_grants_enabled: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateEveryoneGrantPolicyRequest {
    pub everyone_grants_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EveryoneGrantPolicyResponse {
    pub policy: EveryoneGrantPolicy,
}

#[derive(Debug, Clone, Serialize)]
pub struct EveryoneGrantPolicyMutationResponse {
    pub policy: EveryoneGrantPolicy,
    pub receipt: super::Receipt,
}

/// Explicit, item-scoped management affordances for a signed-in human.  This
/// is deliberately separate from an effective Viewer/Editor role: an Editor
/// granted a folder may collaborate within that subtree, but never delegate
/// human access or manage a workspace-wide guest or AI authority.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ItemActionCapabilities {
    pub manage_human_sharing: bool,
    pub manage_guest_links: bool,
    pub manage_ai_access: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ItemActionCapabilitiesResponse {
    pub file_id: String,
    pub workspace_id: String,
    pub action_capabilities: ItemActionCapabilities,
    pub access_generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveItemAccess {
    pub workspace_id: String,
    pub root_file_id: String,
    pub role: String,
    pub source: String,
    pub inherited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedItemRoot {
    pub file: DriveFile,
    pub workspace_id: String,
    pub root_file_id: String,
    /// Opaque authorized sync-root subject. This is either an item-grant root
    /// or a legacy whole-workspace membership root; it is never a bearer
    /// capability.
    pub sync_root_id: String,
    pub owner_label: String,
    pub role: String,
    pub source: String,
    pub inherited: bool,
    /// Present only for an item-scoped human grant. Legacy workspace members
    /// retain no synthetic grant id because their authority is the workspace
    /// membership represented by `sync_root_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// The exact authority epoch required to open this scoped manifest.
    pub access_generation: u64,
    pub action_capabilities: ItemActionCapabilities,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedItemRootsResponse {
    pub roots: Vec<SharedItemRoot>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedByMeRoot {
    pub file: DriveFile,
    pub grants: Vec<HumanItemGrant>,
    /// Active guest-link state for an owner-facing projection. Capability ids,
    /// passwords, notes, and public URLs are intentionally never included.
    pub guest_links: Vec<GuestLinkStatus>,
    pub action_capabilities: ItemActionCapabilities,
}

/// A bounded, non-capability description of one active guest link.
#[derive(Debug, Clone, Serialize)]
pub struct GuestLinkStatus {
    pub kind: String,
    /// `null` means this guest link never expires.
    pub expires_at: Option<String>,
    pub allow_download: bool,
    /// `null` means this guest link has no use limit.
    pub uses_remaining: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedByMeResponse {
    pub roots: Vec<SharedByMeRoot>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharePrincipal {
    pub kind: String,
    pub reference: String,
    pub label: String,
    /// Account principals are eligible only when an enabled auth account is
    /// present. Groups do not have a single account state, so this is null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_enabled: Option<bool>,
    pub can_receive_grant: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharePrincipalListResponse {
    pub principals: Vec<SharePrincipal>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncRoot {
    pub id: String,
    pub kind: String,
    pub workspace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub owner_label: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub label: String,
    /// A non-secret authority epoch. Clients must treat a changed value as a
    /// root invalidation and rediscover/reload rather than reusing a manifest.
    pub access_generation: u64,
    pub action_capabilities: ItemActionCapabilities,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncRootsResponse {
    pub roots: Vec<SyncRoot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncRootPageResponse {
    pub roots: Vec<SyncRoot>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncRootReplacement {
    pub requested_id: String,
    pub root: SyncRoot,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevalidateSyncRootsRequest {
    pub root_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RevalidateSyncRootsResponse {
    pub roots: Vec<SyncRoot>,
    pub revoked_ids: Vec<String>,
    pub replacements: Vec<SyncRootReplacement>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncRootManifestResponse {
    pub root: SyncRoot,
    pub mode: String,
    pub next_cursor: i64,
    pub files: Vec<DriveFile>,
}

/// An admin-only, canonical inventory row.  The file is represented exactly
/// once by its immutable canonical id, never once per recipient or grant.
#[derive(Debug, Clone, Serialize)]
pub struct CanonicalContentItem {
    pub file: DriveFile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
    pub owner_label: String,
    pub canonical_path: Vec<String>,
    pub share_summary: CanonicalShareSummary,
    pub action_capabilities: ItemActionCapabilities,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CanonicalShareSummary {
    pub human_grant_count: u64,
    pub inherited_human_grant_count: u64,
    pub guest_link_count: u64,
    pub ai_grant_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CanonicalHumanGrantDetail {
    #[serde(flatten)]
    pub grant: HumanItemGrant,
    pub inherited: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CanonicalContentResponse {
    pub items: Vec<CanonicalContentItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub access_generation: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "entries", rename_all = "snake_case")]
pub enum CanonicalShareDetails {
    Human(Vec<CanonicalHumanGrantDetail>),
    Guest(Vec<super::ShareLink>),
    Ai(Vec<super::AgentAccess>),
}

#[derive(Debug, Clone, Serialize)]
pub struct CanonicalShareDetailsResponse {
    pub item: CanonicalContentItem,
    #[serde(flatten)]
    pub details: CanonicalShareDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub access_generation: u64,
}
