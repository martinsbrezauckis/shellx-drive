mod actor_lists;
mod actor_scope;
mod admin_groups;
mod admin_provisioning;
mod admin_settings;
mod agent_access;
mod app_tokens;
mod auth_security;
mod auth_sessions;
mod auth_throttle;
mod authorization;
mod auxiliary_storage;
mod background_jobs;
mod backups;
mod bootstrap_provisioning;
mod bounded_files;
mod browse_filters;
mod collaboration_limits;
mod comments;
mod debug;
mod debug_health;
mod delta_stats;
mod derived;
mod derived_names;
mod desktop_agent;
mod download_subjects;
mod downloads;
mod drop_uploads;
mod drops;
mod e2e_human_sharing;
mod email_outbox;
mod file_access;
mod file_destination;
mod file_state;
mod files;
mod folder_covers;
mod folder_templates;
mod human_item_grants;
mod imports;
pub(crate) use imports::RcloneExportCompletion;
mod instance_policy;
mod invitation_publication;
#[cfg(test)]
mod invitation_publication_tests;
mod lifecycle;
mod maintenance;
mod mobile_offline;
mod notifications;
mod office_sessions;
mod opening;
mod password_resets;
mod public_rate_limit_cache;
mod quota_reservations;
mod revisions;
mod schema;
mod security_events;
mod shares;
mod support_bundles;
mod sync;
#[cfg(test)]
mod tests;
mod trash;
mod uploads;
pub(crate) use uploads::NewUploadCompletion;
mod webdav;
mod workspace_admin;
mod workspace_membership;
#[cfg(test)]
mod workspace_selection_tests;

use bounded_files::{
    effectively_live_sql_predicate, recursive_file_ids_in_tx, workspace_usage_buckets,
};
pub use browse_filters::FileBrowseFilters;

pub use agent_access::{
    AgentFileUpdate, AuthenticatedAgentToken, AuthenticatedDelegatedAgentToken,
};
pub(crate) use auth_security::{
    AuthSessionReplacement, AuthSessionRotation, VerifiedLocalSecondFactor,
};
pub(crate) use auth_throttle::{
    AuthAttemptAdmission, PublicCapabilityKind, PublicPasswordAttemptResult,
};
pub use auxiliary_storage::DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES;
pub(crate) use backups::publication::ManagedBackupGeneration;
pub use debug::{
    DebugActivitySummary, DebugAppTokenSummary, DebugImportSummary, DebugSyncConflictSummary,
    DebugWorkspaceSummary,
};
pub use debug_health::{DebugAgentHealthSummary, DebugFileAccessSummary};
pub use drop_uploads::{
    DropUploadAdmissionPolicy, DropUploadRecord, DropUploadSessionCreate,
    MAX_COMPLETED_FILES_PER_DROP,
};
pub use drops::{DropCreateFields, DropUpdateFields};
pub(crate) use e2e_human_sharing::E2eHumanSharingCleanupProbe;
pub use file_access::FileAccessKind;
pub use imports::ImportRunTotals;
pub(crate) use imports::{PreparedRcloneContent, PreparedRcloneEntry};
pub(crate) use instance_policy::{ensure_valid_sandbox_profile, validate_backup_retention_count};
pub use security_events::{
    NewSecurityEvent, MAX_SECURITY_EVENTS, MAX_SECURITY_EVENT_PAGE, SECURITY_EVENT_RETENTION_DAYS,
};
pub(crate) use shares::ClaimedShareAccess;
pub use shares::{ShareCreateFields, ShareUpdateFields};
pub use uploads::{UploadAdmissionPolicy, UploadSessionCreate};
pub use webdav::{
    DebugWebDavLock, WebDavLock, WebDavLockDepth, WebDavMutationTarget,
    MAX_WEBDAV_LOCK_TIMEOUT_SECONDS,
};

use self::collaboration_limits::{
    ensure_pending_invitation_capacity, ensure_workspace_member_capacity,
    prune_workspace_invitation_history, MAX_WORKSPACE_INVITATION_ROWS, MAX_WORKSPACE_MEMBERS,
};
pub(crate) use self::derived::MAX_DERIVED_INPUT_BYTES;
use self::derived::{
    empty_file_metadata, extract_search_text, generate_file_preview, GeneratedPreview,
};
use self::derived_names::derive_conflict_file_name;
use self::email_outbox::insert_workspace_email_outbox_locked;
use self::files::attach_folder_sizes_locked;
pub(crate) use self::folder_templates::PreparedFolderTemplateItem;

use std::{
    collections::{HashMap, HashSet},
    io::BufRead,
    path::Path,
    sync::{atomic::AtomicUsize, Arc, Mutex},
};

use chrono::{DateTime, Datelike, Duration, Utc};
use rusqlite::{
    params, params_from_iter,
    types::{Value as SqlValue, ValueRef},
    Connection, OptionalExtension, Row, TransactionBehavior,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission, WorkspaceRole},
    blob,
    error::{ApiError, ApiResult},
    fs_private,
    model::{
        AdminTotals, AppToken, AuthAccount, AuthAccountSecret, AuthAttemptDebug, BackgroundJob,
        BackgroundJobRunResponse, BackgroundJobTotals, BackupJob, BackupPolicy, BrowseFile,
        ContentWrite, CopyParentId, CreateFileRequest, DebugOfficeSession, DeltaWriteStats,
        DriveFile, DriveGroup, DriveUser, DropLink, EffectiveGroupRole,
        EffectiveWorkspacePermission, EmailOutboxItem, FileKind, FileMetadata, FilePreview,
        FileTreeResponse, FolderTemplate, FolderTemplateItem, GroupMember, HostedTenant,
        MobileOfflineFile, Notification, Receipt, RetentionRevisionCandidate, RetentionTotals,
        RetentionTrashCandidate, SandboxProfile, ShareEntry, ShareLink, StaleRevisionResponse,
        SupportBundleMetadata, SyncChange, SyncConflict, UpdateBackupPolicyRequest,
        UpdateFileRequest, UpdateSandboxProfileRequest, UpdateWorkspacePolicyRequest, Workspace,
        WorkspaceGroupGrant, WorkspaceInvitation, WorkspaceInvitationSecret, WorkspaceMember,
        WorkspacePolicy, WorkspaceUsage,
    },
};

pub struct ShareRecord {
    pub share: ShareLink,
    pub password_hash: String,
    pub password_required: bool,
}

impl ShareRecord {
    /// Stable in-memory binding for capabilities derived from the current
    /// share password policy. Argon2 salts make every password rotation change
    /// this value, including replacing a password with the same plaintext.
    pub fn authorization_fingerprint(&self) -> String {
        Self::authorization_fingerprint_for(self.password_required, &self.password_hash)
    }

    pub(crate) fn authorization_fingerprint_for(
        password_required: bool,
        password_hash: &str,
    ) -> String {
        crate::auth::token_hash(&format!(
            "share-authorization-v1\0{}\0{}",
            password_required, password_hash
        ))
    }
}

pub struct DropRecord {
    pub drop: DropLink,
    pub password_hash: String,
    pub password_required: bool,
}

impl DropRecord {
    pub fn authorization_fingerprint(&self) -> String {
        crate::auth::token_hash(&format!("drop-authorization-v1\0{}", self.password_hash))
    }
}

/// The account-wide browser uses explicit scopes rather than repurposing the
/// workspace manifest. This keeps the desktop sync contract workspace-local
/// while allowing the web product to page across the caller's visible files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBrowseScope {
    Files,
    Mine,
    SharedWithMe,
    Recent,
}

impl FileBrowseScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::Mine => "mine",
            Self::SharedWithMe => "shared",
            Self::Recent => "recent",
        }
    }

    pub const fn uses_recent_order(self) -> bool {
        matches!(self, Self::Recent)
    }

    pub const fn cursor_order(self) -> &'static str {
        if self.uses_recent_order() {
            "recent"
        } else {
            "name"
        }
    }
}

#[derive(Debug, Clone)]
pub enum FileBrowseCursor {
    /// Stable Unicode codepoint/byte ordering. SQLite's `BINARY` collation is
    /// deliberate here: it is locale-independent, preserves case, and avoids
    /// the ASCII-only behavior of SQLite `NOCASE` for non-ASCII Drive names.
    Name {
        kind_rank: i64,
        name: String,
        workspace_name: String,
        id: String,
    },
    Recent {
        updated_at: String,
        id: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct AuthThrottlePolicy {
    pub threshold: i64,
    pub base_lockout_seconds: i64,
    pub max_lockout_seconds: i64,
    pub decay_seconds: i64,
}

pub(crate) const MAX_FILE_TREE_DEPTH: usize = 256;
pub(crate) const MAX_FILE_TREE_NODES: usize = 10_000;
pub(crate) const MAX_FILE_NAME_BYTES: usize = 255;
pub(crate) const MAX_WORKSPACE_NAME_BYTES: usize = 255;
pub(crate) const MAX_COMPATIBILITY_FILE_LIST: usize = 10_000;
pub(crate) const MAX_FILE_REVISIONS: usize = 512;
pub(crate) const MAX_PINNED_FILE_REVISIONS: usize = 64;
pub(crate) const MAX_DEBUG_LIST_ROWS: i64 = 1_000;
pub(crate) const MAX_WORKSPACE_NOTIFICATION_RECIPIENTS: usize = 100;
const MAX_AUTH_ATTEMPT_ROWS: usize = 50_000;
const MAX_PUBLIC_SHARE_PATH_BYTES: usize = 4 * 1024 * 1024;
const BACKGROUND_JOB_BATCH_LIMIT: i64 = 256;
const BACKGROUND_JOB_LIST_LIMIT: i64 = 1_000;
const MAX_WORKSPACE_SEARCH_STORAGE_BYTES: i64 = 512 * 1024 * 1024;
const MAX_WORKSPACE_THUMBNAIL_BYTES: i64 = 1024 * 1024 * 1024;

const BACKUP_TABLES: &[&str] = &[
    "receipts",
    "activity",
    "tenants",
    "workspaces",
    "users",
    "auth_accounts",
    "auth_sessions",
    "app_tokens",
    "agent_principals",
    "agent_tokens",
    "auth_attempts",
    "password_reset_tokens",
    "email_outbox",
    "server_settings",
    "groups",
    "workspace_members",
    "workspace_invitations",
    "group_members",
    "workspace_group_grants",
    "workspace_policies",
    "backup_policy",
    "support_bundles",
    "import_runs",
    "sandbox_profiles",
    "files",
    "agent_folder_grants",
    // Insert grants before the generation record so archives have a canonical
    // shape. Online restore validates both rows but reinstates live grants and
    // advances the target's pre-restore epoch; archive authority never wins.
    "human_item_grants",
    "human_item_access_generation",
    "file_access_stats",
    "file_revisions",
    "file_text_index",
    "file_metadata",
    "upload_sessions",
    "sync_change_floors",
    "sync_changes",
    "delta_sync_writes",
    "background_jobs",
    "file_previews",
    "mobile_offline_files",
    "notifications",
    "office_edit_sessions",
    "comments",
    "comment_replies",
    "folder_templates",
    "folder_template_items",
    "shares",
    "share_access_grants",
    "drops",
    "drop_upload_sessions",
];
const WORKSPACE_INVITATION_TTL_DAYS: i64 = 7;

type RetentionApplyOutput = (
    Receipt,
    Vec<String>,
    Vec<RetentionTrashCandidate>,
    Vec<RetentionRevisionCandidate>,
);

#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<rusqlite::Connection>>,
    operator_credential_generation: Arc<str>,
    security_event_prune_countdown: Arc<AtomicUsize>,
    public_rate_limit_denials: public_rate_limit_cache::PublicRateLimitDenyCache,
    #[cfg(test)]
    parent_validation_pause: Arc<Mutex<Option<ParentValidationTestPause>>>,
}

#[cfg(test)]
struct ParentValidationTestPause {
    reached: std::sync::mpsc::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

impl Storage {
    pub fn ping(&self) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute_batch("SELECT 1;")
    }

    #[cfg(test)]
    fn install_parent_validation_pause(
        &self,
        reached: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    ) {
        *self.parent_validation_pause.lock().unwrap() =
            Some(ParentValidationTestPause { reached, resume });
    }

    #[cfg(test)]
    fn pause_after_parent_validation(&self) {
        if let Some(pause) = self.parent_validation_pause.lock().unwrap().as_ref() {
            pause.reached.send(()).unwrap();
            pause.resume.recv().unwrap();
        }
    }

    pub fn insert_receipt(
        &self,
        kind: &str,
        actor: &str,
        target_id: Option<&str>,
    ) -> rusqlite::Result<Receipt> {
        let receipt = new_receipt(kind, actor, target_id);

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn list_receipts(&self) -> rusqlite::Result<Vec<Receipt>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, kind, actor, target_id, created_at FROM receipts ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Receipt {
                id: row.get(0)?,
                kind: row.get(1)?,
                actor: row.get(2)?,
                target_id: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_recent_receipts(&self, limit: usize) -> rusqlite::Result<Vec<Receipt>> {
        self.list_receipts_bounded(limit, None, None, None)
            .map(|(_, receipts)| receipts)
    }

    pub fn list_receipts_bounded(
        &self,
        limit: usize,
        before: Option<&str>,
        after: Option<&str>,
        kind_prefix: Option<&str>,
    ) -> rusqlite::Result<(usize, Vec<Receipt>)> {
        let conn = self.conn.lock().unwrap();
        let total = conn.query_row(
            "SELECT COUNT(*) FROM receipts
             WHERE (?1 IS NULL OR created_at < ?1)
               AND (?2 IS NULL OR created_at >= ?2)
               AND (?3 IS NULL OR kind LIKE (?3 || '%'))",
            params![before, after, kind_prefix],
            |row| row.get::<_, i64>(0),
        )?;
        let mut stmt = conn.prepare(
            "SELECT id, kind, actor, target_id, created_at
             FROM receipts
             WHERE (?1 IS NULL OR created_at < ?1)
               AND (?2 IS NULL OR created_at >= ?2)
               AND (?3 IS NULL OR kind LIKE (?3 || '%'))
             ORDER BY created_at DESC, id DESC LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![
                before,
                after,
                kind_prefix,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok(Receipt {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    actor: row.get(2)?,
                    target_id: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )?;
        Ok((
            usize::try_from(total).unwrap_or(usize::MAX),
            rows.collect::<rusqlite::Result<Vec<_>>>()?,
        ))
    }

    pub fn create_password_reset_token(
        &self,
        email: &str,
        token_hash: &str,
        expires_at: &str,
    ) -> ApiResult<()> {
        let email = normalize_storage_email(email)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM password_reset_tokens
             WHERE email = ?1 AND used_at IS NULL",
            params![&email],
        )?;
        tx.execute(
            "INSERT INTO password_reset_tokens (
                id, email, token_hash, expires_at, used_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            params![
                Uuid::now_v7().to_string(),
                email,
                token_hash,
                expires_at,
                Utc::now().to_rfc3339(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_password_reset_token_and_email_if_none_active(
        &self,
        email: &str,
        token_hash: &str,
        expires_at: &str,
        subject: &str,
        body_text: &str,
    ) -> ApiResult<bool> {
        let email = normalize_storage_email(email)?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let active = tx.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM password_reset_tokens
                WHERE email = ?1 AND used_at IS NULL
                  AND julianday(expires_at) > julianday(?2)
             )",
            params![&email, &now],
            |row| row.get::<_, bool>(0),
        )?;
        if active {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "DELETE FROM password_reset_tokens
             WHERE email = ?1 AND (used_at IS NOT NULL OR julianday(expires_at) <= julianday(?2))",
            params![&email, &now],
        )?;
        tx.execute(
            "INSERT INTO password_reset_tokens (
                id, email, token_hash, expires_at, used_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            params![
                Uuid::now_v7().to_string(),
                email,
                token_hash,
                expires_at,
                now,
            ],
        )?;
        email_outbox::insert_email_outbox_locked(
            &tx,
            email_outbox::EmailDeliveryClass::AccountSecurity,
            None,
            "password_reset",
            &email,
            subject,
            body_text,
            Some("auth_account"),
            Some(&email),
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn consume_password_reset_token(
        &self,
        token_hash: &str,
        password_hash: &str,
    ) -> ApiResult<(AuthAccount, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let email = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction()?;
            let email = tx
                .query_row(
                    "SELECT email
                     FROM password_reset_tokens
                     WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                    params![token_hash, &now],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let Some(email) = email else {
                return Err(ApiError::Validation(
                    "password reset token is invalid or expired".to_string(),
                ));
            };
            invalidate_password_reset_tokens_in_tx(&tx, &email, &now)?;
            let changed = tx.execute(
                "UPDATE auth_accounts
                 SET password_hash = ?2, updated_at = ?3,
                     security_version = security_version + 1
                 WHERE email = ?1 AND disabled_at IS NULL",
                params![&email, password_hash, &now],
            )?;
            if changed == 0 {
                return Err(ApiError::Validation(
                    "password reset token is invalid or expired".to_string(),
                ));
            }
            tx.execute(
                "DELETE FROM auth_attempts
                 WHERE actor_email = ?1
                   AND scope IN (
                     'password',
                     'password_login_account',
                     'password_login_account_recovery',
                     'password_change',
                     'password_change_account',
                     'password_change_account_recovery',
                     'password_change_totp',
                     'password_change_totp_account',
                     'password_change_totp_account_recovery'
                   )",
                params![&email],
            )?;
            revoke_derived_actor_credentials_in_tx(&tx, &email, &now)?;
            tx.commit()?;
            email
        };
        let account = self.get_auth_account(&email)?.ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt("auth.password.reset", &email, Some(&email))?;
        Ok((account, receipt))
    }

    pub fn password_reset_token_is_active(&self, token_hash: &str) -> ApiResult<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM password_reset_tokens
                WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2
             )",
            params![token_hash, Utc::now().to_rfc3339()],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    pub fn registration_enabled(&self) -> ApiResult<bool> {
        // Public registration is deliberately unavailable in v0.1. Email is
        // the workspace identity key, so issuing a session before mailbox
        // verification would let an attacker pre-claim a future member. Keep
        // the status method for API compatibility while failing closed.
        Ok(false)
    }

    pub fn upsert_user(&self, email: &str) -> rusqlite::Result<DriveUser> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        if let Some(user) = conn
            .query_row(
                "SELECT id, email, created_at FROM users WHERE email = ?1",
                params![email],
                |row| {
                    Ok(DriveUser {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                },
            )
            .optional()?
        {
            return Ok(user);
        }

        let user = DriveUser {
            id: Uuid::now_v7().to_string(),
            email: email.to_string(),
            created_at: now,
        };
        conn.execute(
            "INSERT INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
            params![user.id, user.email, user.created_at],
        )?;
        Ok(user)
    }

    pub fn auth_account_count(&self) -> ApiResult<usize> {
        let conn = self.conn.lock().unwrap();
        Ok(
            conn.query_row("SELECT COUNT(*) FROM auth_accounts", [], |row| {
                row.get::<_, i64>(0)
            })? as usize,
        )
    }

    pub fn create_auth_account(
        &self,
        email: &str,
        password_hash: &str,
        is_admin: bool,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AuthAccount, Receipt)> {
        crate::auth::ensure_not_reserved_user_email(email)?;
        let now = Utc::now().to_rfc3339();
        let user_id = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_admin_authorized(&tx, admin_actor, source_credential)?;
            let user_id = tx
                .query_row(
                    "SELECT id FROM users WHERE email = ?1",
                    params![email],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .unwrap_or_else(|| Uuid::now_v7().to_string());
            tx.execute(
                "INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
                params![&user_id, email, &now],
            )?;
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO auth_accounts (
                    user_id, email, password_hash, is_admin, totp_secret,
                    totp_enabled, recovery_code_hashes, disabled_at,
                    created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, NULL, 0, '[]', NULL, ?5, ?5)",
                params![&user_id, email, password_hash, is_admin as i64, &now],
            )?;
            if inserted == 0 {
                return Err(ApiError::Conflict);
            }
            human_item_grants::provisioning::ensure_private_workspace_for_account_in_tx(
                &tx, &user_id, &now,
            )?;
            tx.commit()?;
            user_id
        };
        let account = self.get_auth_account(email)?.ok_or(ApiError::NotFound)?;
        debug_assert_eq!(account.user_id, user_id);
        let receipt = self.insert_receipt(
            "auth.account.create",
            &admin_actor.email,
            Some(&account.email),
        )?;
        Ok((account, receipt))
    }

    pub fn get_auth_account(&self, email: &str) -> ApiResult<Option<AuthAccount>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT user_id, email, is_admin, totp_enabled, recovery_code_hashes,
                    disabled_at, created_at, updated_at
             FROM auth_accounts WHERE email = ?1",
            params![email],
            row_to_auth_account,
        )
        .optional()
        .map_err(ApiError::from)
    }

    pub fn get_auth_account_secret(&self, email: &str) -> ApiResult<Option<AuthAccountSecret>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT user_id, email, password_hash, is_admin, totp_secret,
                    totp_enabled, recovery_code_hashes, disabled_at, security_version
             FROM auth_accounts WHERE email = ?1",
            params![email],
            row_to_auth_account_secret,
        )
        .optional()
        .map_err(ApiError::from)
    }

    pub fn list_auth_accounts(&self) -> ApiResult<Vec<AuthAccount>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT user_id, email, is_admin, totp_enabled, recovery_code_hashes,
                    disabled_at, created_at, updated_at
             FROM auth_accounts ORDER BY email ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_auth_account)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn change_auth_account_password(
        &self,
        email: &str,
        password_hash: &str,
        expected_security_version: i64,
        second_factor: VerifiedLocalSecondFactor,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AuthAccount, Receipt)> {
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_local_account_self_authorized(
                &tx,
                email,
                actor,
                source_credential,
            )?;
            auth_security::consume_current_second_factor_in_tx(
                &tx,
                email,
                expected_security_version,
                second_factor,
            )?;
            let changed = tx.execute(
                "UPDATE auth_accounts
                 SET password_hash = ?2, updated_at = ?3,
                     security_version = security_version + 1
                 WHERE email = ?1 AND disabled_at IS NULL AND security_version = ?4",
                params![email, password_hash, &now, expected_security_version],
            )?;
            if changed != 1 {
                return Err(ApiError::Conflict);
            }
            invalidate_password_reset_tokens_in_tx(&tx, email, &now)?;
            revoke_derived_actor_credentials_in_tx(&tx, email, &now)?;
            tx.commit()?;
        }
        let account = self.get_auth_account(email)?.ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt("auth.password.change", email, Some(email))?;
        Ok((account, receipt))
    }

    // Account mutation fields and the independently revalidated authorization
    // context are kept explicit at this privileged storage boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn update_auth_account(
        &self,
        email: &str,
        disabled: Option<bool>,
        is_admin: Option<bool>,
        password_hash: Option<&str>,
        reset_2fa: bool,
        expected_self_removal_security_version: Option<i64>,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AuthAccount, Receipt)> {
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_admin_authorized(&tx, admin_actor, source_credential)?;
            // Read and update the complete security row under the same write
            // transaction. A concurrent disable, password reset, admin change,
            // or 2FA reset can no longer be overwritten from a stale snapshot.
            let current = tx
                .query_row(
                    "SELECT user_id, email, password_hash, is_admin, totp_secret,
                            totp_enabled, recovery_code_hashes, disabled_at, security_version
                     FROM auth_accounts WHERE email = ?1",
                    params![email],
                    row_to_auth_account_secret,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if expected_self_removal_security_version
                .is_some_and(|expected| current.security_version != expected)
            {
                return Err(ApiError::Conflict);
            }
            let next_disabled_at = match disabled {
                Some(true) => Some(now.clone()),
                Some(false) => None,
                None => current.disabled_at.clone(),
            };
            let next_password_hash = password_hash.unwrap_or(&current.password_hash).to_string();
            let next_is_admin = is_admin.unwrap_or(current.is_admin);
            let next_totp_secret = (!reset_2fa)
                .then_some(current.totp_secret.clone())
                .flatten();
            let next_totp_enabled = !reset_2fa && current.totp_enabled;
            let next_recovery_hashes = if reset_2fa {
                "[]".to_string()
            } else {
                serde_json::to_string(&current.recovery_code_hashes).map_err(|error| {
                    ApiError::Validation(format!("failed to encode recovery code hashes: {error}"))
                })?
            };
            let removes_last_enabled_admin = current.is_admin
                && current.disabled_at.is_none()
                && (next_disabled_at.is_some() || !next_is_admin);
            if removes_last_enabled_admin {
                let enabled_admins = tx.query_row(
                    "SELECT COUNT(*) FROM auth_accounts
                     WHERE is_admin = 1 AND disabled_at IS NULL",
                    [],
                    |row| row.get::<_, i64>(0),
                )?;
                if enabled_admins <= 1 {
                    return Err(ApiError::Conflict);
                }
            }
            let changed = tx.execute(
                "UPDATE auth_accounts
                 SET password_hash = ?2, is_admin = ?3, totp_secret = ?4,
                     totp_enabled = ?5, recovery_code_hashes = ?6,
                     totp_last_used_counter = CASE WHEN ?9 THEN NULL ELSE totp_last_used_counter END,
                     disabled_at = ?7, updated_at = ?8,
                     security_version = security_version + 1
                 WHERE email = ?1",
                params![
                    email,
                    next_password_hash,
                    next_is_admin as i64,
                    next_totp_secret.as_deref(),
                    next_totp_enabled as i64,
                    next_recovery_hashes,
                    next_disabled_at.as_deref(),
                    &now,
                    reset_2fa
                ],
            )?;
            if changed != 1 {
                return Err(ApiError::Conflict);
            }
            if disabled.is_some() || is_admin.is_some() || password_hash.is_some() || reset_2fa {
                invalidate_password_reset_tokens_in_tx(&tx, email, &now)?;
            }
            if disabled == Some(true) || password_hash.is_some() || reset_2fa {
                revoke_derived_actor_credentials_in_tx(&tx, email, &now)?;
            }
            tx.commit()?;
        }
        let account = self.get_auth_account(email)?.ok_or(ApiError::NotFound)?;
        let kind = match (disabled, is_admin, password_hash.is_some(), reset_2fa) {
            (Some(true), None, false, false) => "auth.account.disable",
            (Some(false), None, false, false) => "auth.account.enable",
            (None, None, true, false) => "auth.account.password_reset",
            (None, None, false, true) => "auth.account.2fa_reset",
            _ => "auth.account.update",
        };
        let receipt = self.insert_receipt(kind, &admin_actor.email, Some(email))?;
        Ok((account, receipt))
    }

    pub(crate) fn update_totp_secret(
        &self,
        email: &str,
        secret: &str,
        expected_security_version: i64,
        second_factor: VerifiedLocalSecondFactor,
        rotation: &AuthSessionRotation<'_>,
    ) -> ApiResult<AuthAccount> {
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_local_account_self_authorized(
                &tx,
                email,
                rotation.actor,
                rotation.source_credential,
            )?;
            auth_security::consume_current_second_factor_in_tx(
                &tx,
                email,
                expected_security_version,
                second_factor,
            )?;
            let changed = tx.execute(
                "UPDATE auth_accounts
                 SET totp_secret = ?2, totp_enabled = 0, recovery_code_hashes = '[]',
                     totp_last_used_counter = NULL,
                     updated_at = ?3, security_version = security_version + 1
                 WHERE email = ?1 AND disabled_at IS NULL AND security_version = ?4",
                params![email, secret, &now, expected_security_version],
            )?;
            if changed != 1 {
                return Err(ApiError::Conflict);
            }
            invalidate_password_reset_tokens_in_tx(&tx, email, &now)?;
            auth_security::rotate_prior_security_state_in_tx(&tx, email, &now, rotation)?;
            tx.commit()?;
        }
        self.get_auth_account(email)?.ok_or(ApiError::NotFound)
    }

    pub(crate) fn enable_totp(
        &self,
        email: &str,
        recovery_code_hashes: &[String],
        expected_security_version: i64,
        second_factor: VerifiedLocalSecondFactor,
        rotation: &AuthSessionRotation<'_>,
    ) -> ApiResult<AuthAccount> {
        let now = Utc::now().to_rfc3339();
        let encoded = serde_json::to_string(recovery_code_hashes).map_err(|error| {
            ApiError::Validation(format!("failed to encode recovery code hashes: {error}"))
        })?;
        let matched_counter = auth_security::totp_counter_for_enable(second_factor)?;
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_local_account_self_authorized(
                &tx,
                email,
                rotation.actor,
                rotation.source_credential,
            )?;
            let changed = tx.execute(
                "UPDATE auth_accounts
                 SET totp_enabled = 1, recovery_code_hashes = ?2,
                     totp_last_used_counter = ?5, updated_at = ?3,
                     security_version = security_version + 1
                 WHERE email = ?1 AND totp_secret IS NOT NULL AND disabled_at IS NULL
                       AND totp_enabled = 0
                       AND security_version = ?4",
                params![
                    email,
                    encoded,
                    &now,
                    expected_security_version,
                    matched_counter
                ],
            )?;
            if changed != 1 {
                return Err(ApiError::Conflict);
            }
            invalidate_password_reset_tokens_in_tx(&tx, email, &now)?;
            auth_security::rotate_prior_security_state_in_tx(&tx, email, &now, rotation)?;
            tx.commit()?;
        }
        self.get_auth_account(email)?.ok_or(ApiError::NotFound)
    }

    pub(crate) fn disable_totp(
        &self,
        email: &str,
        expected_security_version: i64,
        second_factor: VerifiedLocalSecondFactor,
        rotation: &AuthSessionRotation<'_>,
    ) -> ApiResult<AuthAccount> {
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_local_account_self_authorized(
                &tx,
                email,
                rotation.actor,
                rotation.source_credential,
            )?;
            auth_security::consume_current_second_factor_in_tx(
                &tx,
                email,
                expected_security_version,
                second_factor,
            )?;
            let changed = tx.execute(
                "UPDATE auth_accounts
                 SET totp_secret = NULL, totp_enabled = 0, recovery_code_hashes = '[]',
                     totp_last_used_counter = NULL,
                     updated_at = ?2, security_version = security_version + 1
                 WHERE email = ?1 AND disabled_at IS NULL AND security_version = ?3",
                params![email, &now, expected_security_version],
            )?;
            if changed != 1 {
                return Err(ApiError::Conflict);
            }
            invalidate_password_reset_tokens_in_tx(&tx, email, &now)?;
            auth_security::rotate_prior_security_state_in_tx(&tx, email, &now, rotation)?;
            tx.commit()?;
        }
        self.get_auth_account(email)?.ok_or(ApiError::NotFound)
    }

    pub(crate) fn rotate_recovery_code_hashes(
        &self,
        email: &str,
        hashes: &[String],
        expected_security_version: i64,
        second_factor: VerifiedLocalSecondFactor,
        rotation: &AuthSessionRotation<'_>,
    ) -> ApiResult<AuthAccount> {
        let now = Utc::now().to_rfc3339();
        let encoded = serde_json::to_string(hashes).map_err(|error| {
            ApiError::Validation(format!("failed to encode recovery code hashes: {error}"))
        })?;
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_local_account_self_authorized(
                &tx,
                email,
                rotation.actor,
                rotation.source_credential,
            )?;
            auth_security::consume_current_second_factor_in_tx(
                &tx,
                email,
                expected_security_version,
                second_factor,
            )?;
            let changed = tx.execute(
                "UPDATE auth_accounts
                 SET recovery_code_hashes = ?2, updated_at = ?3,
                     security_version = security_version + 1
                 WHERE email = ?1 AND totp_enabled = 1 AND disabled_at IS NULL
                       AND security_version = ?4",
                params![email, encoded, &now, expected_security_version],
            )?;
            if changed != 1 {
                return Err(ApiError::Conflict);
            }
            invalidate_password_reset_tokens_in_tx(&tx, email, &now)?;
            auth_security::rotate_prior_security_state_in_tx(&tx, email, &now, rotation)?;
            tx.commit()?;
        }
        self.get_auth_account(email)?.ok_or(ApiError::NotFound)
    }

    pub fn consume_recovery_code_hash(&self, email: &str, hash: &str) -> ApiResult<bool> {
        let email = normalize_storage_email(email)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(encoded_before) = tx
            .query_row(
                "SELECT recovery_code_hashes
                 FROM auth_accounts
                 WHERE email = ?1 AND totp_enabled = 1 AND disabled_at IS NULL",
                params![&email],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        else {
            tx.commit()?;
            return Ok(false);
        };
        let mut hashes = parse_recovery_hashes(&encoded_before);
        let Some(position) = hashes.iter().position(|stored| stored == hash) else {
            tx.commit()?;
            return Ok(false);
        };
        hashes.remove(position);
        let encoded_after = serde_json::to_string(&hashes).map_err(|error| {
            ApiError::Validation(format!("failed to encode recovery code hashes: {error}"))
        })?;
        let now = Utc::now().to_rfc3339();
        let changed = tx.execute(
            "UPDATE auth_accounts
             SET recovery_code_hashes = ?2, updated_at = ?3,
                 security_version = security_version + 1
             WHERE email = ?1 AND recovery_code_hashes = ?4
                   AND totp_enabled = 1 AND disabled_at IS NULL",
            params![&email, encoded_after, now, encoded_before],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub fn create_workspace(
        &self,
        name: &str,
        owner_email: &str,
    ) -> rusqlite::Result<(Workspace, DriveUser, Receipt)> {
        self.create_workspace_with_mode(name, owner_email, "open")
    }

    pub fn create_workspace_with_mode(
        &self,
        name: &str,
        owner_email: &str,
        _storage_mode: &str,
    ) -> rusqlite::Result<(Workspace, DriveUser, Receipt)> {
        self.create_workspace_with_mode_and_tenant(name, owner_email, "open", None)
    }

    pub fn create_workspace_with_mode_and_tenant(
        &self,
        name: &str,
        owner_email: &str,
        _storage_mode: &str,
        tenant_id: Option<&str>,
    ) -> rusqlite::Result<(Workspace, DriveUser, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let owner = self.upsert_user(owner_email)?;
        let workspace = Workspace {
            id: Uuid::now_v7().to_string(),
            tenant_id: tenant_id.map(str::to_string),
            name: name.to_string(),
            storage_mode: "open".to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
            archived: false,
            archived_at: None,
            role: None,
        };

        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO workspaces (id, tenant_id, name, storage_mode, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &workspace.id,
                    &workspace.tenant_id,
                    &workspace.name,
                    &workspace.storage_mode,
                    &workspace.created_at,
                    &workspace.updated_at,
                ],
            )?;
            conn.execute(
                "INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?1, ?2, 'owner')",
                params![workspace.id, owner.id],
            )?;
        }

        let receipt = self.insert_receipt("workspace.create", &owner.email, Some(&workspace.id))?;
        Ok((workspace, owner, receipt))
    }

    pub fn create_hosted_tenant(
        &self,
        name: &str,
        owner_email: &str,
        plan: &str,
        billing_status: &str,
        actor: &str,
    ) -> ApiResult<(HostedTenant, Receipt)> {
        let name = validate_workspace_name(name)?;
        let owner_email = normalize_storage_email(owner_email)?;
        let plan = validate_non_empty_label(plan, "plan")?;
        let billing_status = validate_non_empty_label(billing_status, "billing_status")?;
        self.upsert_user(&owner_email)?;
        let now = Utc::now().to_rfc3339();
        let tenant = HostedTenant {
            id: Uuid::now_v7().to_string(),
            name,
            owner_email,
            plan,
            billing_status,
            created_at: now.clone(),
            updated_at: now,
        };
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO tenants (id, name, owner_email, plan, billing_status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &tenant.id,
                    &tenant.name,
                    &tenant.owner_email,
                    &tenant.plan,
                    &tenant.billing_status,
                    &tenant.created_at,
                    &tenant.updated_at,
                ],
            )?;
        }
        let receipt = self.insert_receipt("hosted.tenant.create", actor, Some(&tenant.id))?;
        Ok((tenant, receipt))
    }

    pub fn get_hosted_tenant(&self, tenant_id: &str) -> ApiResult<Option<HostedTenant>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT id, name, owner_email, plan, billing_status, created_at, updated_at
                 FROM tenants WHERE id = ?1",
                params![tenant_id],
                row_to_hosted_tenant,
            )
            .optional()?)
    }

    pub fn list_hosted_tenants(&self) -> ApiResult<Vec<HostedTenant>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, owner_email, plan, billing_status, created_at, updated_at
             FROM tenants ORDER BY created_at ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map([MAX_DEBUG_LIST_ROWS], row_to_hosted_tenant)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_workspace_policy(&self, workspace_id: &str) -> ApiResult<WorkspacePolicy> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        let policy = conn
            .query_row(
                "SELECT workspace_id, quota_bytes, public_links_enabled,
                        link_password_required, allow_never_expire,
                        max_link_ttl_seconds,
                        drop_password_required, max_drop_ttl_seconds,
                        trash_retention_days, revision_retention_days, updated_at
                 FROM workspace_policies WHERE workspace_id = ?1",
                params![workspace_id],
                row_to_workspace_policy,
            )
            .optional()?;
        Ok(policy.unwrap_or_else(|| default_workspace_policy(workspace_id)))
    }

    pub fn list_workspace_policies(&self) -> ApiResult<Vec<WorkspacePolicy>> {
        let workspaces = self.list_workspaces_bounded(MAX_DEBUG_LIST_ROWS)?;
        let mut policies = Vec::with_capacity(workspaces.len());
        for workspace in workspaces {
            policies.push(self.get_workspace_policy(&workspace.id)?);
        }
        policies.sort_by(|left, right| left.workspace_id.cmp(&right.workspace_id));
        Ok(policies)
    }

    pub fn update_workspace_policy(
        &self,
        workspace_id: &str,
        request: UpdateWorkspacePolicyRequest,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(WorkspacePolicy, Receipt)> {
        let quota_requested = request.quota_bytes.is_present();
        let expected_stored_updated_at = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT updated_at FROM workspace_policies WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        };
        let mut policy = self.get_workspace_policy(workspace_id)?;
        if let crate::model::NullableI64Patch::Set(value) = request.quota_bytes {
            policy.quota_bytes = value
                .map(|quota| validate_non_negative_i64(quota, "quota_bytes"))
                .transpose()?;
        }
        if let Some(value) = request.public_links_enabled {
            policy.public_links_enabled = value;
        }
        if let Some(value) = request.link_password_required {
            policy.link_password_required = value;
        }
        if let Some(value) = request.allow_never_expire {
            policy.allow_never_expire = value;
        }
        if let Some(value) = request.max_link_ttl_seconds {
            let value = validate_non_negative_i64(value, "max_link_ttl_seconds")?;
            crate::workspace_policy::checked_share_expiry(Utc::now(), value)?;
            policy.max_link_ttl_seconds = value;
        }
        if let Some(value) = request.drop_password_required {
            policy.drop_password_required = value;
        }
        if let Some(value) = request.max_drop_ttl_seconds {
            policy.max_drop_ttl_seconds = validate_non_negative_i64(value, "max_drop_ttl_seconds")?;
        }
        if let Some(value) = request.trash_retention_days {
            let value = validate_non_negative_i64(value, "trash_retention_days")?;
            crate::workspace_policy::checked_retention_cutoff(Utc::now(), value)?;
            policy.trash_retention_days = value;
        }
        if let Some(value) = request.revision_retention_days {
            let value = validate_non_negative_i64(value, "revision_retention_days")?;
            crate::workspace_policy::checked_retention_cutoff(Utc::now(), value)?;
            policy.revision_retention_days = value;
        }
        if policy.public_links_enabled
            && !policy.allow_never_expire
            && policy.max_link_ttl_seconds == 0
        {
            return Err(ApiError::Validation(
                "workspace policy: finite share ttl must be greater than zero when permanent links are disabled"
                    .to_string(),
            ));
        }
        policy.updated_at = Utc::now().to_rfc3339();

        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Manage,
            )?;
            if quota_requested {
                authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
            }
            let current_stored_updated_at = tx
                .query_row(
                    "SELECT updated_at FROM workspace_policies WHERE workspace_id = ?1",
                    params![workspace_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if current_stored_updated_at != expected_stored_updated_at {
                return Err(ApiError::Conflict);
            }
            tx.execute(
                "INSERT INTO workspace_policies (
                    workspace_id, quota_bytes, public_links_enabled,
                    link_password_required, allow_never_expire,
                    max_link_ttl_seconds,
                    drop_password_required, max_drop_ttl_seconds,
                    trash_retention_days, revision_retention_days, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(workspace_id) DO UPDATE SET
                    quota_bytes = excluded.quota_bytes,
                    public_links_enabled = excluded.public_links_enabled,
                    link_password_required = excluded.link_password_required,
                    allow_never_expire = excluded.allow_never_expire,
                    max_link_ttl_seconds = excluded.max_link_ttl_seconds,
                    drop_password_required = excluded.drop_password_required,
                    max_drop_ttl_seconds = excluded.max_drop_ttl_seconds,
                    trash_retention_days = excluded.trash_retention_days,
                    revision_retention_days = excluded.revision_retention_days,
                    updated_at = excluded.updated_at",
                params![
                    &policy.workspace_id,
                    policy.quota_bytes,
                    bool_to_i64(policy.public_links_enabled),
                    bool_to_i64(policy.link_password_required),
                    bool_to_i64(policy.allow_never_expire),
                    policy.max_link_ttl_seconds,
                    bool_to_i64(policy.drop_password_required),
                    policy.max_drop_ttl_seconds,
                    policy.trash_retention_days,
                    policy.revision_retention_days,
                    &policy.updated_at,
                ],
            )?;
            tx.commit()?;
        }
        let receipt =
            self.insert_receipt("workspace.policy.update", &actor.email, Some(workspace_id))?;
        Ok((policy, receipt))
    }

    pub fn get_backup_policy(&self) -> ApiResult<BackupPolicy> {
        let conn = self.conn.lock().unwrap();
        let policy = conn
            .query_row(
                "SELECT enabled, schedule, retention_count, updated_at
                 FROM backup_policy WHERE id = 'default'",
                [],
                row_to_backup_policy,
            )
            .optional()?;
        let policy = policy.unwrap_or_else(default_backup_policy);
        instance_policy::ensure_valid_backup_policy(&policy)?;
        Ok(policy)
    }

    pub fn update_backup_policy(
        &self,
        request: UpdateBackupPolicyRequest,
        actor: &str,
    ) -> ApiResult<(BackupPolicy, Receipt)> {
        let mut policy = self.get_backup_policy()?;
        if let Some(enabled) = request.enabled {
            policy.enabled = enabled;
        }
        if let Some(schedule) = request.schedule {
            policy.schedule = instance_policy::validate_backup_schedule(&schedule)?;
        }
        if let Some(retention_count) = request.retention_count {
            policy.retention_count =
                instance_policy::validate_backup_retention_count(retention_count)?;
        }
        instance_policy::ensure_valid_backup_policy(&policy)?;
        policy.updated_at = Utc::now().to_rfc3339();

        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO backup_policy (id, enabled, schedule, retention_count, updated_at)
                 VALUES ('default', ?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                    enabled = excluded.enabled,
                    schedule = excluded.schedule,
                    retention_count = excluded.retention_count,
                    updated_at = excluded.updated_at",
                params![
                    bool_to_i64(policy.enabled),
                    &policy.schedule,
                    policy.retention_count,
                    &policy.updated_at,
                ],
            )?;
        }
        let receipt = self.insert_receipt("backup.policy.update", actor, Some("default"))?;
        Ok((policy, receipt))
    }

    pub fn list_support_bundles(&self) -> ApiResult<Vec<SupportBundleMetadata>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, receipt_id, generated_at, debug_export_bytes, logs_count
             FROM support_bundles ORDER BY generated_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_support_bundle_metadata)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn workspace_usage(&self, workspace_id: &str) -> ApiResult<WorkspaceUsage> {
        let policy = self.get_workspace_policy(workspace_id)?;
        let auxiliary = self.workspace_auxiliary_storage_usage(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        // Presentation follows the effective-live tree, while quota below
        // deliberately remains retained-storage accounting.
        let (current_file_bytes, trashed_file_bytes) =
            workspace_usage_buckets(&conn, workspace_id)?;
        let revision_bytes = conn.query_row(
            "SELECT COALESCE(SUM(fr.content_bytes), 0)
             FROM file_revisions fr
             JOIN files f ON f.id = fr.file_id
             WHERE f.workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0),
        )?;
        // Quota is retained-storage accounting, not a member-visible tree
        // projection: it deliberately charges every stored row, including
        // legacy descendants below Trash, and must stay independent here.
        let current_quota_usage_bytes: i64 = conn.query_row(
            "SELECT COALESCE(SUM(
                    CASE WHEN content_bytes > 0 THEN content_bytes ELSE 1 END
                    + CASE WHEN cover_bytes > 0 THEN cover_bytes ELSE 0 END
                ), 0)
             FROM files
             WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get(0),
        )?;
        let retained_revision_bytes = retained_revision_quota_bytes(&conn, workspace_id)?;
        let quota_usage_bytes = current_quota_usage_bytes
            .checked_add(retained_revision_bytes)
            .ok_or_else(|| ApiError::Validation("workspace quota usage overflow".to_string()))?;
        let remaining_bytes = policy
            .quota_bytes
            .map(|quota| (quota - quota_usage_bytes).max(0));
        Ok(WorkspaceUsage {
            workspace_id: workspace_id.to_string(),
            quota_bytes: policy.quota_bytes,
            current_file_bytes,
            revision_bytes,
            trashed_file_bytes,
            remaining_bytes,
            auxiliary_storage_bytes: auxiliary.total_bytes,
            auxiliary_file_metadata_bytes: auxiliary.file_metadata_bytes,
            auxiliary_metadata_fts_projection_bytes: auxiliary.metadata_fts_projection_bytes,
            auxiliary_comment_reply_body_bytes: auxiliary.comment_reply_body_bytes,
            auxiliary_notification_bytes: auxiliary.notification_bytes,
            auxiliary_email_outbox_bytes: auxiliary.email_outbox_bytes,
            auxiliary_storage_limit_bytes: auxiliary.limit_bytes,
            auxiliary_storage_remaining_bytes: auxiliary.remaining_bytes,
            auxiliary_storage_over_limit: auxiliary.over_limit,
        })
    }

    pub fn list_workspace_usage(&self) -> ApiResult<Vec<WorkspaceUsage>> {
        let workspaces = self.list_workspaces_bounded(MAX_DEBUG_LIST_ROWS)?;
        let mut usage = Vec::with_capacity(workspaces.len());
        for workspace in workspaces {
            usage.push(self.workspace_usage(&workspace.id)?);
        }
        usage.sort_by(|left, right| left.workspace_id.cmp(&right.workspace_id));
        Ok(usage)
    }

    pub fn ensure_workspace_quota(
        &self,
        workspace_id: &str,
        existing_file_id: Option<&str>,
        new_content_bytes: i64,
    ) -> ApiResult<()> {
        let new_content_bytes = validate_non_negative_i64(new_content_bytes, "content_bytes")?;
        let policy = self.get_workspace_policy(workspace_id)?;
        let Some(quota_bytes) = policy.quota_bytes else {
            return Ok(());
        };
        let conn = self.conn.lock().unwrap();
        let current_file_bytes = conn.query_row(
            "SELECT COALESCE(SUM(
                    CASE WHEN content_bytes > 0 THEN content_bytes ELSE 1 END
                    + CASE WHEN cover_bytes > 0 THEN cover_bytes ELSE 0 END
                ), 0)
             FROM files
             WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0),
        )?;
        let retained_revision_bytes = retained_revision_quota_bytes(&conn, workspace_id)?;
        // On overwrite, the currently active body becomes retained revision
        // history. Keep its existing active charge and add the replacement.
        // A later transactional check repeats this admission atomically.
        let _ = existing_file_id;
        let projected_bytes = current_file_bytes
            .checked_add(retained_revision_bytes)
            .and_then(|value| value.checked_add(new_content_bytes.max(1)))
            .ok_or_else(|| ApiError::Validation("workspace quota usage overflow".to_string()))?;
        if projected_bytes > quota_bytes {
            return Err(ApiError::Validation(format!(
                "quota exceeded: {projected_bytes} bytes would exceed workspace quota {quota_bytes} bytes"
            )));
        }
        Ok(())
    }

    pub fn file_content_bytes(&self, file_id: &str) -> ApiResult<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT content_bytes FROM files WHERE id = ?1",
                params![file_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    pub fn workspace_storage_mode(&self, workspace_id: &str) -> ApiResult<String> {
        let conn = self.conn.lock().unwrap();
        let mode = conn
            .query_row(
                "SELECT storage_mode FROM workspaces WHERE id = ?1",
                params![workspace_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        Ok(mode)
    }

    pub fn list_workspaces(&self) -> rusqlite::Result<Vec<Workspace>> {
        self.list_workspaces_bounded(i64::MAX)
    }

    pub(crate) fn list_workspaces_bounded(&self, limit: i64) -> rusqlite::Result<Vec<Workspace>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, storage_mode, created_at, COALESCE(updated_at, created_at), archived_at, tenant_id
             FROM workspaces ORDER BY name ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit.max(1)], |row| {
            let archived_at: Option<String> = row.get(5)?;
            Ok(Workspace {
                id: row.get(0)?,
                name: row.get(1)?,
                storage_mode: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                archived: archived_at.is_some(),
                archived_at,
                tenant_id: row.get(6)?,
                role: None,
            })
        })?;
        rows.collect()
    }

    pub fn list_workspaces_for_actor(&self, actor: &Actor) -> ApiResult<Vec<Workspace>> {
        if actor.is_admin {
            return Ok(self.list_workspaces()?);
        }
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT w.id, w.name, w.storage_mode, w.created_at, COALESCE(w.updated_at, w.created_at), w.archived_at, w.tenant_id, wm.role
             FROM workspaces w
             JOIN workspace_members wm ON wm.workspace_id = w.id
             JOIN users u ON u.id = wm.user_id
             WHERE u.email = ?1 AND w.archived_at IS NULL
               AND (wm.expires_at IS NULL OR wm.expires_at > ?2)
             UNION ALL
             SELECT w.id, w.name, w.storage_mode, w.created_at, COALESCE(w.updated_at, w.created_at), w.archived_at, w.tenant_id, wgg.role
             FROM workspaces w
             JOIN workspace_group_grants wgg ON wgg.workspace_id = w.id
             JOIN group_members gm ON gm.group_id = wgg.group_id
             JOIN users u ON u.id = gm.user_id
             WHERE u.email = ?1 AND w.archived_at IS NULL
             ORDER BY name ASC",
        )?;
        let rows = stmt.query_map(params![actor.email, Utc::now().to_rfc3339()], |row| {
            let archived_at: Option<String> = row.get(5)?;
            Ok(Workspace {
                id: row.get(0)?,
                name: row.get(1)?,
                storage_mode: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                archived: archived_at.is_some(),
                archived_at,
                tenant_id: row.get(6)?,
                role: Some(row.get(7)?),
            })
        })?;
        let mut by_workspace: HashMap<String, Workspace> = HashMap::new();
        for row in rows {
            let workspace = row?;
            let id = workspace.id.clone();
            match by_workspace.get_mut(&id) {
                Some(existing) => {
                    let existing_role = existing.role.as_deref().unwrap_or("viewer");
                    let candidate_role = workspace.role.as_deref().unwrap_or("viewer");
                    if role_rank(candidate_role) > role_rank(existing_role) {
                        existing.role = workspace.role;
                    }
                }
                None => {
                    by_workspace.insert(id, workspace);
                }
            }
        }
        let mut workspaces = by_workspace.into_values().collect::<Vec<_>>();
        if let Some(allowed_workspace_ids) = actor.allowed_workspace_ids.as_ref() {
            workspaces.retain(|workspace| allowed_workspace_ids.contains(&workspace.id));
        }
        workspaces.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(workspaces)
    }

    pub fn list_workspace_members(&self, workspace_id: &str) -> ApiResult<Vec<WorkspaceMember>> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT wm.workspace_id, u.id, u.email, wm.role, u.created_at, wm.expires_at
             FROM workspace_members wm
             JOIN users u ON u.id = wm.user_id
             WHERE wm.workspace_id = ?1
             ORDER BY CASE wm.role WHEN 'owner' THEN 0 WHEN 'editor' THEN 1 ELSE 2 END, u.email ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![workspace_id, MAX_WORKSPACE_MEMBERS + 1],
            row_to_workspace_member,
        )?;
        let members = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if members.len() > MAX_WORKSPACE_MEMBERS as usize {
            return Err(ApiError::PayloadTooLarge(format!(
                "workspace membership exceeds the supported limit of {MAX_WORKSPACE_MEMBERS} direct members"
            )));
        }
        Ok(members)
    }

    pub(crate) fn workspace_member_count(&self, workspace_id: &str) -> ApiResult<usize> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        let count = conn.query_row(
            "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0),
        )?;
        usize::try_from(count)
            .map_err(|_| ApiError::Validation("workspace member count overflow".to_string()))
    }

    pub fn list_active_workspace_recipient_emails(
        &self,
        workspace_id: &str,
    ) -> ApiResult<Vec<String>> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        notifications::list_active_workspace_notification_recipients_locked(&conn, workspace_id)
    }

    pub fn upsert_workspace_member(
        &self,
        workspace_id: &str,
        email: &str,
        role: WorkspaceRole,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(WorkspaceMember, Receipt)> {
        self.workspace_storage_mode(workspace_id)?;
        let email = normalize_storage_email(email)?;
        let receipt = new_receipt("workspace.member.upsert", &actor.email, Some(workspace_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Manage,
            )?;
            let now = Utc::now().to_rfc3339();
            let user_id = tx
                .query_row(
                    "SELECT id FROM users WHERE email = ?1",
                    params![&email],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .unwrap_or_else(|| Uuid::now_v7().to_string());
            workspace_membership::ensure_role_transition_preserves_owner(
                &tx,
                workspace_id,
                &user_id,
                role,
            )?;
            ensure_workspace_member_capacity(&tx, workspace_id, &user_id)?;
            tx.execute(
                "INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
                params![&user_id, &email, &now],
            )?;
            tx.execute(
                "INSERT INTO workspace_members (workspace_id, user_id, role, expires_at)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(workspace_id, user_id) DO UPDATE
                 SET role = excluded.role, expires_at = NULL",
                params![workspace_id, user_id, role.as_db_str()],
            )?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let member = self
            .workspace_member_by_email(workspace_id, &email)?
            .ok_or(ApiError::NotFound)?;
        Ok((member, receipt))
    }

    pub fn remove_workspace_member(
        &self,
        workspace_id: &str,
        email: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Manage,
            )?;
            let user_id: String = tx
                .query_row(
                    "SELECT u.id FROM workspace_members wm
                     JOIN users u ON u.id = wm.user_id
                     WHERE wm.workspace_id = ?1 AND u.email = ?2",
                    params![workspace_id, email],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            workspace_membership::ensure_removal_preserves_owner(
                &tx,
                workspace_id,
                &user_id,
                "cannot remove the last workspace owner",
            )?;
            tx.execute(
                "DELETE FROM workspace_members WHERE workspace_id = ?1 AND user_id = ?2",
                params![workspace_id, user_id],
            )?;
            tx.commit()?;
        }
        Ok(self.insert_receipt("workspace.member.remove", &actor.email, Some(workspace_id))?)
    }

    pub fn get_workspace(&self, workspace_id: &str) -> ApiResult<Option<Workspace>> {
        let conn = self.conn.lock().unwrap();
        let workspace = conn
            .query_row(
                "SELECT id, name, storage_mode, created_at, COALESCE(updated_at, created_at), archived_at, tenant_id
                 FROM workspaces WHERE id = ?1",
                params![workspace_id],
                row_to_workspace,
            )
            .optional()?;
        Ok(workspace)
    }

    pub fn update_workspace_name(
        &self,
        workspace_id: &str,
        name: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Workspace, Receipt)> {
        let name = validate_workspace_name(name)?;
        self.workspace_storage_mode(workspace_id)?;
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Manage,
            )?;
            tx.execute(
                "UPDATE workspaces SET name = ?1, updated_at = ?2 WHERE id = ?3",
                params![name, now, workspace_id],
            )?;
            tx.commit()?;
        }
        let workspace = self
            .get_workspace(workspace_id)?
            .ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt("workspace.rename", &actor.email, Some(workspace_id))?;
        Ok((workspace, receipt))
    }

    pub fn set_workspace_archived(
        &self,
        workspace_id: &str,
        archived: bool,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Workspace, Receipt)> {
        self.workspace_storage_mode(workspace_id)?;
        let now = Utc::now().to_rfc3339();
        let archived_at = archived.then(|| now.clone());
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Manage,
            )?;
            tx.execute(
                "UPDATE workspaces SET archived_at = ?1, updated_at = ?2 WHERE id = ?3",
                params![archived_at, now, workspace_id],
            )?;
            tx.commit()?;
        }
        let workspace = self
            .get_workspace(workspace_id)?
            .ok_or(ApiError::NotFound)?;
        let kind = if archived {
            "workspace.archive"
        } else {
            "workspace.unarchive"
        };
        let receipt = self.insert_receipt(kind, &actor.email, Some(workspace_id))?;
        Ok((workspace, receipt))
    }

    pub fn list_workspace_invitations(
        &self,
        workspace_id: &str,
    ) -> ApiResult<Vec<WorkspaceInvitation>> {
        self.workspace_storage_mode(workspace_id)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, email, role, status, invited_by,
                    expires_at, accepted_at, canceled_at, created_at, updated_at,
                    member_expires_in_seconds
             FROM workspace_invitations
             WHERE workspace_id = ?1 AND publication_pending = 0
             ORDER BY created_at DESC, id DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![workspace_id, MAX_WORKSPACE_INVITATION_ROWS + 1],
            row_to_workspace_invitation,
        )?;
        let invitations = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if invitations.len() > MAX_WORKSPACE_INVITATION_ROWS as usize {
            return Err(ApiError::PayloadTooLarge(format!(
                "workspace invitation history exceeds the supported limit of {MAX_WORKSPACE_INVITATION_ROWS} entries"
            )));
        }
        Ok(invitations)
    }

    pub fn list_all_workspace_invitations(&self) -> ApiResult<Vec<WorkspaceInvitation>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, email, role, status, invited_by,
                    expires_at, accepted_at, canceled_at, created_at, updated_at,
                    member_expires_in_seconds
             FROM workspace_invitations
             WHERE publication_pending = 0
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_workspace_invitation)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn cancel_workspace_invitation(
        &self,
        workspace_id: &str,
        invitation_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(WorkspaceInvitation, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_workspace_authorized(
            &tx,
            workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Manage,
        )?;
        let mut invitation = tx
            .query_row(
                "SELECT id, workspace_id, email, role, status, invited_by,
                        expires_at, accepted_at, canceled_at, created_at, updated_at,
                        member_expires_in_seconds
                 FROM workspace_invitations
                 WHERE id = ?1 AND workspace_id = ?2 AND publication_pending = 0",
                params![invitation_id, workspace_id],
                row_to_workspace_invitation,
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if invitation.status != "pending" {
            return Err(ApiError::Validation(
                "only pending invitations can be canceled".to_string(),
            ));
        }
        invitation.status = "canceled".to_string();
        invitation.canceled_at = Some(now.clone());
        invitation.updated_at = now.clone();
        let changed = tx.execute(
            "UPDATE workspace_invitations
             SET status = 'canceled', canceled_at = ?1, updated_at = ?1
             WHERE id = ?2 AND workspace_id = ?3 AND status = 'pending'
               AND publication_pending = 0",
            params![&now, invitation_id, workspace_id],
        )?;
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        prune_workspace_invitation_history(&tx, workspace_id)?;
        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "workspace.invitation.cancel".to_string(),
            actor: actor.email.clone(),
            target_id: Some(invitation_id.to_string()),
            created_at: now,
        };
        tx.execute(
            "INSERT INTO receipts (id, kind, actor, target_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &receipt.id,
                &receipt.kind,
                &receipt.actor,
                &receipt.target_id,
                &receipt.created_at,
            ],
        )?;
        tx.execute(
            "INSERT INTO activity (id, kind, actor, target_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                Uuid::now_v7().to_string(),
                &receipt.kind,
                &receipt.actor,
                &receipt.target_id,
                &receipt.created_at,
            ],
        )?;
        record_sync_change_for_receipt(&tx, &receipt)?;
        tx.commit()?;
        Ok((invitation, receipt))
    }

    /// Accept an invitation only for the already authenticated account it was
    /// addressed to. The token lookup, account binding, membership write, and
    /// state transition share one immediate transaction so concurrent requests
    /// cannot consume one invitation twice.
    pub fn accept_workspace_invitation_for_account(
        &self,
        token_hash: &str,
        account_email: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(WorkspaceInvitation, WorkspaceMember, Receipt)> {
        let account_email = normalize_storage_email(account_email)?;
        if actor.email != account_email {
            return Err(ApiError::Forbidden);
        }
        let now_value = Utc::now();
        let now = now_value.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        let secret = tx
            .query_row(
                "SELECT id, workspace_id, email, role, token_hash, status, invited_by,
                        expires_at, accepted_at, canceled_at, created_at, updated_at,
                        member_expires_in_seconds
                 FROM workspace_invitations
                 WHERE token_hash = ?1 AND publication_pending = 0",
                params![token_hash],
                row_to_workspace_invitation_secret,
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        let mut invitation = secret.invitation;
        if invitation.status != "pending" {
            return Err(ApiError::NotFound);
        }
        let expires_at = DateTime::parse_from_rfc3339(&invitation.expires_at)
            .map_err(|_| ApiError::NotFound)?
            .with_timezone(&Utc);
        if expires_at <= now_value {
            return Err(ApiError::NotFound);
        }
        if invitation.email != account_email {
            return Err(ApiError::Forbidden);
        }
        let role = WorkspaceRole::parse(&invitation.role).ok_or(ApiError::NotFound)?;
        let user = tx
            .query_row(
                "SELECT id, email, created_at FROM users WHERE email = ?1",
                params![&account_email],
                |row| {
                    Ok(DriveUser {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_else(|| DriveUser {
                id: Uuid::now_v7().to_string(),
                email: account_email.clone(),
                created_at: now.clone(),
            });
        workspace_membership::ensure_role_transition_preserves_owner(
            &tx,
            &invitation.workspace_id,
            &user.id,
            role,
        )?;
        ensure_workspace_member_capacity(&tx, &invitation.workspace_id, &user.id)?;
        tx.execute(
            "INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
            params![&user.id, &user.email, &user.created_at],
        )?;
        let member_expires_at = invitation
            .member_expires_in_seconds
            .map(|seconds| (now_value + Duration::seconds(seconds)).to_rfc3339());
        tx.execute(
            "INSERT INTO workspace_members (workspace_id, user_id, role, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(workspace_id, user_id) DO UPDATE
             SET role = excluded.role, expires_at = excluded.expires_at",
            params![
                &invitation.workspace_id,
                &user.id,
                role.as_db_str(),
                member_expires_at.as_deref()
            ],
        )?;
        let changed = tx.execute(
            "UPDATE workspace_invitations
             SET status = 'accepted', accepted_at = ?1, updated_at = ?1
             WHERE id = ?2 AND status = 'pending' AND publication_pending = 0",
            params![&now, &invitation.id],
        )?;
        if changed != 1 {
            return Err(ApiError::NotFound);
        }
        prune_workspace_invitation_history(&tx, &invitation.workspace_id)?;
        let member = WorkspaceMember {
            workspace_id: invitation.workspace_id.clone(),
            user_id: user.id,
            email: account_email.clone(),
            role: role.as_db_str().to_string(),
            created_at: user.created_at,
            expires_at: member_expires_at,
        };
        invitation.status = "accepted".to_string();
        invitation.accepted_at = Some(now.clone());
        invitation.updated_at = now.clone();
        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "workspace.invitation.accept".to_string(),
            actor: account_email,
            target_id: Some(invitation.id.clone()),
            created_at: now,
        };
        tx.execute(
            "INSERT INTO receipts (id, kind, actor, target_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &receipt.id,
                &receipt.kind,
                &receipt.actor,
                &receipt.target_id,
                &receipt.created_at,
            ],
        )?;
        tx.commit()?;
        Ok((invitation, member, receipt))
    }

    pub fn transfer_workspace_owner(
        &self,
        workspace_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        new_owner_email: &str,
    ) -> ApiResult<(WorkspaceMember, WorkspaceMember, Receipt)> {
        self.workspace_storage_mode(workspace_id)?;
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Manage,
            )?;
            let old_owner_id = tx
                .query_row(
                    "SELECT u.id FROM workspace_members wm
                     JOIN users u ON u.id = wm.user_id
                     WHERE wm.workspace_id = ?1 AND u.email = ?2 AND wm.role = 'owner'",
                    params![workspace_id, &actor.email],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::Forbidden)?;
            let new_owner_id = tx
                .query_row(
                    "SELECT u.id FROM workspace_members wm
                     JOIN users u ON u.id = wm.user_id
                     WHERE wm.workspace_id = ?1 AND u.email = ?2",
                    params![workspace_id, new_owner_email],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            tx.execute(
                "UPDATE workspace_members SET role = 'owner', expires_at = NULL
                 WHERE workspace_id = ?1 AND user_id = ?2",
                params![workspace_id, &new_owner_id],
            )?;
            if old_owner_id != new_owner_id {
                tx.execute(
                    "UPDATE workspace_members SET role = 'editor'
                     WHERE workspace_id = ?1 AND user_id = ?2",
                    params![workspace_id, &old_owner_id],
                )?;
            }
            tx.commit()?;
        }
        let old_owner = self
            .workspace_member_by_email(workspace_id, &actor.email)?
            .ok_or(ApiError::NotFound)?;
        let new_owner = self
            .workspace_member_by_email(workspace_id, new_owner_email)?
            .ok_or(ApiError::NotFound)?;
        let receipt =
            self.insert_receipt("workspace.owner.transfer", &actor.email, Some(workspace_id))?;
        Ok((old_owner, new_owner, receipt))
    }

    pub fn leave_workspace(
        &self,
        workspace_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Read,
            )?;
            let user_id: String = tx
                .query_row(
                    "SELECT u.id FROM workspace_members wm
                     JOIN users u ON u.id = wm.user_id
                     WHERE wm.workspace_id = ?1 AND u.email = ?2",
                    params![workspace_id, &actor.email],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            workspace_membership::ensure_removal_preserves_owner(
                &tx,
                workspace_id,
                &user_id,
                "cannot leave as the last workspace owner",
            )?;
            tx.execute(
                "DELETE FROM workspace_members WHERE workspace_id = ?1 AND user_id = ?2",
                params![workspace_id, user_id],
            )?;
            tx.commit()?;
        }
        Ok(self.insert_receipt("workspace.member.leave", &actor.email, Some(workspace_id))?)
    }

    pub fn create_group(&self, name: &str, actor: &str) -> ApiResult<(DriveGroup, Receipt)> {
        let name = validate_group_name(name)?;
        let group = DriveGroup {
            id: Uuid::now_v7().to_string(),
            name,
            created_by: actor.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                r#"INSERT INTO "groups" (id, name, created_by, created_at)
                   VALUES (?1, ?2, ?3, ?4)"#,
                params![group.id, group.name, group.created_by, group.created_at],
            )?;
        }
        let receipt = self.insert_receipt("group.create", actor, Some(&group.id))?;
        Ok((group, receipt))
    }

    pub fn list_groups(&self) -> ApiResult<Vec<DriveGroup>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, name, created_by, created_at
               FROM "groups" ORDER BY name ASC LIMIT ?1"#,
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_group)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_all_group_members(&self) -> ApiResult<Vec<GroupMember>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT gm.group_id, u.id, u.email, gm.created_at
             FROM group_members gm
             JOIN users u ON u.id = gm.user_id
             JOIN \"groups\" g ON g.id = gm.group_id
             ORDER BY g.name ASC, u.email ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_group_member)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn upsert_group_member(
        &self,
        group_id: &str,
        email: &str,
        actor: &str,
    ) -> ApiResult<(GroupMember, Receipt)> {
        self.get_group(group_id)?.ok_or(ApiError::NotFound)?;
        let user = self.upsert_user(email)?;
        let now = Utc::now().to_rfc3339();
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO group_members (group_id, user_id, created_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(group_id, user_id) DO NOTHING",
                params![group_id, user.id, now],
            )?;
        }
        let member = self
            .group_member_by_email(group_id, email)?
            .ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt("group.member.upsert", actor, Some(group_id))?;
        Ok((member, receipt))
    }

    pub fn remove_group_member(
        &self,
        group_id: &str,
        email: &str,
        actor: &str,
    ) -> ApiResult<Receipt> {
        let member = self
            .group_member_by_email(group_id, email)?
            .ok_or(ApiError::NotFound)?;
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                params![group_id, member.user_id],
            )?;
        }
        Ok(self.insert_receipt("group.member.remove", actor, Some(group_id))?)
    }

    pub fn upsert_workspace_group_grant(
        &self,
        workspace_id: &str,
        group_id: &str,
        role: WorkspaceRole,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(WorkspaceGroupGrant, Receipt)> {
        self.workspace_storage_mode(workspace_id)?;
        self.get_group(group_id)?.ok_or(ApiError::NotFound)?;
        if role == WorkspaceRole::Owner {
            return Err(ApiError::Validation(
                "group grants may be viewer or editor".to_string(),
            ));
        }
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Manage,
            )?;
            tx.execute(
                "INSERT INTO workspace_group_grants (workspace_id, group_id, role, created_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(workspace_id, group_id) DO UPDATE SET
                    role = excluded.role,
                    created_at = excluded.created_at",
                params![workspace_id, group_id, role.as_db_str(), now],
            )?;
            tx.commit()?;
        }
        let grant = self
            .workspace_group_grant(workspace_id, group_id)?
            .ok_or(ApiError::NotFound)?;
        let receipt =
            self.insert_receipt("workspace.group.grant", &actor.email, Some(workspace_id))?;
        Ok((grant, receipt))
    }

    pub fn remove_workspace_group_grant(
        &self,
        workspace_id: &str,
        group_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Manage,
            )?;
            let changed = tx.execute(
                "DELETE FROM workspace_group_grants WHERE workspace_id = ?1 AND group_id = ?2",
                params![workspace_id, group_id],
            )?;
            if changed != 1 {
                return Err(ApiError::NotFound);
            }
            tx.commit()?;
        }
        Ok(self.insert_receipt("workspace.group.revoke", &actor.email, Some(workspace_id))?)
    }

    pub fn list_all_workspace_group_grants(&self) -> ApiResult<Vec<WorkspaceGroupGrant>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT wgg.workspace_id, wgg.group_id, g.name, wgg.role, wgg.created_at
             FROM workspace_group_grants wgg
             JOIN \"groups\" g ON g.id = wgg.group_id
             ORDER BY g.name ASC, wgg.workspace_id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_workspace_group_grant)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_effective_workspace_permissions(
        &self,
    ) -> ApiResult<Vec<EffectiveWorkspacePermission>> {
        #[derive(Default)]
        struct PermissionDraft {
            workspace_id: String,
            actor_email: String,
            direct_role: Option<String>,
            group_roles: Vec<EffectiveGroupRole>,
        }

        let conn = self.conn.lock().unwrap();
        let mut permissions: HashMap<(String, String), PermissionDraft> = HashMap::new();

        {
            let mut stmt = conn.prepare(
                "SELECT wm.workspace_id, u.email, wm.role
                 FROM workspace_members wm
                 JOIN users u ON u.id = wm.user_id
                 WHERE wm.expires_at IS NULL OR wm.expires_at > ?1
                 ORDER BY u.email ASC, wm.workspace_id ASC LIMIT ?2",
            )?;
            let rows = stmt.query_map(
                params![Utc::now().to_rfc3339(), MAX_DEBUG_LIST_ROWS],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?;
            for row in rows {
                let (workspace_id, actor_email, role) = row?;
                let key = (workspace_id.clone(), actor_email.clone());
                let draft = permissions.entry(key).or_insert_with(|| PermissionDraft {
                    workspace_id,
                    actor_email,
                    direct_role: None,
                    group_roles: Vec::new(),
                });
                draft.direct_role = Some(role);
            }
        }

        {
            let mut stmt = conn.prepare(
                "SELECT wgg.workspace_id, u.email, wgg.group_id, g.name, wgg.role
                 FROM workspace_group_grants wgg
                 JOIN \"groups\" g ON g.id = wgg.group_id
                 JOIN group_members gm ON gm.group_id = wgg.group_id
                 JOIN users u ON u.id = gm.user_id
                 ORDER BY u.email ASC, wgg.workspace_id ASC, g.name ASC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    EffectiveGroupRole {
                        group_id: row.get(2)?,
                        group_name: row.get(3)?,
                        role: row.get(4)?,
                    },
                ))
            })?;
            for row in rows {
                let (workspace_id, actor_email, group_role) = row?;
                let key = (workspace_id.clone(), actor_email.clone());
                let draft = permissions.entry(key).or_insert_with(|| PermissionDraft {
                    workspace_id,
                    actor_email,
                    direct_role: None,
                    group_roles: Vec::new(),
                });
                draft.group_roles.push(group_role);
            }
        }

        let mut rows = permissions
            .into_values()
            .map(|draft| {
                let role = draft
                    .direct_role
                    .iter()
                    .chain(draft.group_roles.iter().map(|group| &group.role))
                    .max_by_key(|role| role_rank(role))
                    .cloned()
                    .unwrap_or_else(|| "viewer".to_string());
                EffectiveWorkspacePermission {
                    workspace_id: draft.workspace_id,
                    actor_email: draft.actor_email,
                    role,
                    direct_role: draft.direct_role,
                    group_roles: draft.group_roles,
                }
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.actor_email
                .cmp(&right.actor_email)
                .then(left.workspace_id.cmp(&right.workspace_id))
        });
        Ok(rows)
    }

    pub fn get_sandbox_profile(&self) -> ApiResult<SandboxProfile> {
        let conn = self.conn.lock().unwrap();
        let profile = conn
            .query_row(
                "SELECT id, name, mode, data_dir, bind, service_user, service_group,
                        read_write_paths_json, read_only_paths_json, network_policy, status, last_checked_at
                 FROM sandbox_profiles WHERE id = 'default'",
                [],
                row_to_sandbox_profile,
            )
            .optional()?;
        drop(conn);
        if let Some(profile) = profile {
            instance_policy::ensure_valid_sandbox_profile(&profile)?;
            return Ok(profile);
        }
        self.insert_default_sandbox_profile()
    }

    pub fn update_sandbox_profile(
        &self,
        request: UpdateSandboxProfileRequest,
        actor: &str,
    ) -> ApiResult<(SandboxProfile, Receipt)> {
        let mut profile = self.get_sandbox_profile()?;
        if let Some(mode) = request.mode {
            if !matches!(mode.as_str(), "strict" | "local-dev") {
                return Err(ApiError::Validation(
                    "sandbox mode must be strict or local-dev".to_string(),
                ));
            }
            profile.mode = mode;
        }
        if let Some(data_dir) = request.data_dir {
            profile.data_dir =
                instance_policy::validate_sandbox_path("sandbox data_dir", &data_dir)?;
        }
        if let Some(bind) = request.bind {
            profile.bind = instance_policy::validate_sandbox_command_value("sandbox bind", &bind)?;
        }
        if let Some(paths) = request.read_write_paths {
            profile.read_write_paths = paths
                .into_iter()
                .map(|path| {
                    instance_policy::validate_sandbox_path("sandbox read_write_paths", &path)
                })
                .collect::<ApiResult<Vec<_>>>()?;
        }
        if let Some(paths) = request.read_only_paths {
            profile.read_only_paths = paths
                .into_iter()
                .map(|path| {
                    instance_policy::validate_sandbox_path("sandbox read_only_paths", &path)
                })
                .collect::<ApiResult<Vec<_>>>()?;
        }
        if let Some(network_policy) = request.network_policy {
            profile.network_policy = instance_policy::validate_sandbox_command_value(
                "sandbox network_policy",
                &network_policy,
            )?;
        }
        profile.status = "preview".to_string();
        profile.last_checked_at = Some(Utc::now().to_rfc3339());
        instance_policy::ensure_valid_sandbox_profile(&profile)?;
        self.store_sandbox_profile(&profile)?;
        let receipt = self.insert_receipt("sandbox.profile.update", actor, Some(&profile.id))?;
        Ok((profile, receipt))
    }

    pub fn record_sandbox_apply_intent(&self, actor: &str) -> ApiResult<Receipt> {
        let profile = self.get_sandbox_profile()?;
        Ok(self.insert_receipt("sandbox.apply.intent", actor, Some(&profile.id))?)
    }

    fn insert_default_sandbox_profile(&self) -> ApiResult<SandboxProfile> {
        let profile = default_sandbox_profile();
        self.store_sandbox_profile(&profile)?;
        Ok(profile)
    }

    fn store_sandbox_profile(&self, profile: &SandboxProfile) -> ApiResult<()> {
        instance_policy::ensure_valid_sandbox_profile(profile)?;
        let read_write_paths_json = serde_json::to_string(&profile.read_write_paths)
            .map_err(|error| ApiError::Validation(format!("invalid sandbox paths: {error}")))?;
        let read_only_paths_json = serde_json::to_string(&profile.read_only_paths)
            .map_err(|error| ApiError::Validation(format!("invalid sandbox paths: {error}")))?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sandbox_profiles
                (id, name, mode, data_dir, bind, service_user, service_group,
                 read_write_paths_json, read_only_paths_json, network_policy, status, last_checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                mode = excluded.mode,
                data_dir = excluded.data_dir,
                bind = excluded.bind,
                service_user = excluded.service_user,
                service_group = excluded.service_group,
                read_write_paths_json = excluded.read_write_paths_json,
                read_only_paths_json = excluded.read_only_paths_json,
                network_policy = excluded.network_policy,
                status = excluded.status,
                last_checked_at = excluded.last_checked_at",
            params![
                profile.id,
                profile.name,
                profile.mode,
                profile.data_dir,
                profile.bind,
                profile.service_user,
                profile.service_group,
                read_write_paths_json,
                read_only_paths_json,
                profile.network_policy,
                profile.status,
                profile.last_checked_at
            ],
        )?;
        Ok(())
    }

    pub fn ensure_workspace_permission(
        &self,
        workspace_id: &str,
        actor: &Actor,
        permission: WorkspacePermission,
    ) -> ApiResult<()> {
        if actor.is_admin {
            return Ok(());
        }
        if actor
            .allowed_workspace_ids
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(workspace_id))
        {
            return Err(ApiError::Forbidden);
        }
        self.workspace_storage_mode(workspace_id)?;
        let Some(role) = self.workspace_role_for_actor(workspace_id, &actor.email)? else {
            return Err(ApiError::Forbidden);
        };
        if role.allows(permission) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    fn workspace_role_for_actor(
        &self,
        workspace_id: &str,
        email: &str,
    ) -> ApiResult<Option<WorkspaceRole>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT wm.role
             FROM workspace_members wm
             JOIN users u ON u.id = wm.user_id
             WHERE wm.workspace_id = ?1 AND u.email = ?2
               AND (wm.expires_at IS NULL OR wm.expires_at > ?3)
             UNION ALL
             SELECT wgg.role
             FROM workspace_group_grants wgg
             JOIN group_members gm ON gm.group_id = wgg.group_id
             JOIN users u ON u.id = gm.user_id
             WHERE wgg.workspace_id = ?1 AND u.email = ?2",
        )?;
        let rows = stmt.query_map(
            params![workspace_id, email, Utc::now().to_rfc3339()],
            |row| row.get::<_, String>(0),
        )?;
        let mut effective_role: Option<WorkspaceRole> = None;
        for row in rows {
            let role = row?;
            let Some(role) = WorkspaceRole::parse(&role) else {
                continue;
            };
            if effective_role
                .map(|current| role_rank(role.as_db_str()) > role_rank(current.as_db_str()))
                .unwrap_or(true)
            {
                effective_role = Some(role);
            }
        }
        Ok(effective_role)
    }

    fn workspace_member_by_email(
        &self,
        workspace_id: &str,
        email: &str,
    ) -> ApiResult<Option<WorkspaceMember>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT wm.workspace_id, u.id, u.email, wm.role, u.created_at, wm.expires_at
                 FROM workspace_members wm
                 JOIN users u ON u.id = wm.user_id
                 WHERE wm.workspace_id = ?1 AND u.email = ?2",
                params![workspace_id, email],
                row_to_workspace_member,
            )
            .optional()?)
    }

    fn get_group(&self, group_id: &str) -> ApiResult<Option<DriveGroup>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                r#"SELECT id, name, created_by, created_at FROM "groups" WHERE id = ?1"#,
                params![group_id],
                row_to_group,
            )
            .optional()?)
    }

    fn group_member_by_email(&self, group_id: &str, email: &str) -> ApiResult<Option<GroupMember>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT gm.group_id, u.id, u.email, gm.created_at
                 FROM group_members gm
                 JOIN users u ON u.id = gm.user_id
                 WHERE gm.group_id = ?1 AND u.email = ?2",
                params![group_id, email],
                row_to_group_member,
            )
            .optional()?)
    }

    fn workspace_group_grant(
        &self,
        workspace_id: &str,
        group_id: &str,
    ) -> ApiResult<Option<WorkspaceGroupGrant>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT wgg.workspace_id, wgg.group_id, g.name, wgg.role, wgg.created_at
                 FROM workspace_group_grants wgg
                 JOIN \"groups\" g ON g.id = wgg.group_id
                 WHERE wgg.workspace_id = ?1 AND wgg.group_id = ?2",
                params![workspace_id, group_id],
                row_to_workspace_group_grant,
            )
            .optional()?)
    }

    pub fn create_file(
        &self,
        request: CreateFileRequest,
        content_hash: Option<String>,
    ) -> ApiResult<(DriveFile, Receipt)> {
        let content_bytes = if matches!(request.kind, FileKind::File) {
            request
                .content
                .as_ref()
                .map(|content| content.len() as i64)
                .unwrap_or(0)
        } else {
            0
        };
        self.create_file_with_content_bytes(request, content_hash, content_bytes)
    }

    pub(crate) fn create_file_authorized(
        &self,
        request: CreateFileRequest,
        content_hash: Option<String>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, Receipt)> {
        let content_bytes = if matches!(request.kind, FileKind::File) {
            request
                .content
                .as_ref()
                .map(|content| content.len() as i64)
                .unwrap_or(0)
        } else {
            0
        };
        self.create_file_with_content_bytes_authorized(
            request,
            content_hash,
            content_bytes,
            actor,
            source_credential,
        )
    }

    pub fn create_file_with_content_bytes(
        &self,
        request: CreateFileRequest,
        content_hash: Option<String>,
        content_bytes: i64,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.create_file_with_content_bytes_inner(
            request,
            content_hash,
            content_bytes,
            None,
            "system",
        )
    }

    pub fn create_file_with_content_bytes_as(
        &self,
        request: CreateFileRequest,
        content_hash: Option<String>,
        content_bytes: i64,
        actor: &str,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.create_file_with_content_bytes_inner(request, content_hash, content_bytes, None, actor)
    }

    pub(crate) fn create_file_with_content_bytes_authorized(
        &self,
        request: CreateFileRequest,
        content_hash: Option<String>,
        content_bytes: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.create_file_with_content_bytes_inner(
            request,
            content_hash,
            content_bytes,
            Some((actor, source_credential)),
            &actor.email,
        )
    }

    fn create_file_with_content_bytes_inner(
        &self,
        request: CreateFileRequest,
        content_hash: Option<String>,
        content_bytes: i64,
        authorization_context: Option<(&Actor, &DriveCredential)>,
        receipt_actor: &str,
    ) -> ApiResult<(DriveFile, Receipt)> {
        if content_hash.is_some() {
            self.ensure_workspace_server_content_allowed(&request.workspace_id)?;
        }
        let content_bytes = if matches!(request.kind, FileKind::File) {
            validate_non_negative_i64(content_bytes, "content_bytes")?
        } else {
            0
        };
        // The parent-chain and quota checks both run inside the insert
        // transaction so this file cannot land beneath a concurrently trashed
        // or newly-too-deep parent.
        let name = validate_file_name(&request.name)?;

        let now = Utc::now().to_rfc3339();
        let size_bytes = matches!(request.kind, FileKind::File).then_some(content_bytes);
        let file = DriveFile {
            id: Uuid::now_v7().to_string(),
            workspace_id: request.workspace_id,
            parent_id: request.parent_id,
            name,
            kind: request.kind,
            revision: 1,
            trashed: false,
            starred: false,
            content_hash,
            created_at: now.clone(),
            updated_at: now.clone(),
            size_bytes,
            folder_size_bytes: None,
            has_cover: false,
        };
        let receipt = new_receipt("file.create", receipt_actor, Some(&file.id));

        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if let Some((actor, source_credential)) = authorization_context {
                human_item_grants::access::ensure_item_destination_authorized_in_tx(
                    &tx,
                    &file.workspace_id,
                    file.parent_id.as_deref(),
                    actor,
                    source_credential,
                )?;
            }
            if let Some(parent_id) = file.parent_id.as_deref() {
                validate_parent_chain_in_tx(&tx, &file.workspace_id, parent_id, None)?;
            }
            file_destination::ensure_live_sibling_available_in_tx(
                &tx,
                &file.workspace_id,
                &file.id,
                file.parent_id.as_deref(),
                &file.name,
            )?;
            bounded_files::ensure_workspace_node_capacity(&tx, &file.workspace_id, 1)?;
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&file.workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            if let Some(quota_bytes) = quota_bytes {
                enforce_quota_in_txn(&tx, quota_bytes, &file.workspace_id, None, content_bytes)?;
            }
            tx.execute(
                "INSERT INTO files (id, workspace_id, parent_id, name, kind, revision, trashed, starred, content_hash, content_bytes, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    &file.id,
                    &file.workspace_id,
                    &file.parent_id,
                    &file.name,
                    file.kind.as_db_str(),
                    file.revision,
                    0,
                    0,
                    &file.content_hash,
                    content_bytes,
                    &file.created_at,
                    &file.updated_at,
                ],
            )?;
            tx.execute(
                "INSERT INTO file_revisions (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    &file.id,
                    file.revision,
                    &file.content_hash,
                    content_bytes,
                    &file.created_at,
                ],
            )?;
            refresh_file_search_index_locked(&tx, &file.id)?;
            insert_receipt_rows(&tx, &receipt)?;
            let _ = background_jobs::enqueue_file_background_jobs_in_tx(&tx, &file)?;
            tx.commit()?;
        }
        Ok((file, receipt))
    }

    pub fn ensure_workspace_server_content_allowed(&self, workspace_id: &str) -> ApiResult<()> {
        self.workspace_storage_mode(workspace_id)?;
        Ok(())
    }

    pub fn get_file(&self, file_id: &str) -> ApiResult<Option<DriveFile>> {
        let file = self.get_file_unaggregated(file_id)?;
        if file
            .as_ref()
            .is_some_and(|file| matches!(file.kind, FileKind::Folder))
        {
            return Ok(self
                .descendants_inclusive_bounded(file_id, false)?
                .into_iter()
                .find(|file| file.id == file_id));
        }
        Ok(file)
    }

    pub fn get_root_file_by_name(
        &self,
        workspace_id: &str,
        name: &str,
    ) -> ApiResult<Option<DriveFile>> {
        self.get_child_file_by_name(workspace_id, None, name)
    }

    pub fn get_child_file_by_name(
        &self,
        workspace_id: &str,
        parent_id: Option<&str>,
        name: &str,
    ) -> ApiResult<Option<DriveFile>> {
        self.get_active_child_file_by_name(workspace_id, parent_id, name)
    }

    /// Resolve the nested folder chain described by a relative upload `path`
    /// (e.g. a browser `webkitRelativePath` like `a/b/c.txt`), creating any
    /// missing intermediate folders idempotently under `parent_id`, and return
    /// `(deepest_folder_id, leaf_name)` — the parent the leaf file should be
    /// created under, and its file name.
    ///
    /// Every `/`-separated segment (including the leaf) is validated with
    /// [`validate_file_name`], which rejects `..`, empty segments (so an
    /// absolute `"/a"`, a trailing `"a/"`, and a doubled `"a//b"` are all
    /// refused), path separators, control characters, and hidden names — this is
    /// the traversal defence. An existing folder of the same name is reused; a
    /// name that already exists as a non-folder is a validation error (a file
    /// cannot also be a directory).
    pub fn resolve_relative_upload_path(
        &self,
        workspace_id: &str,
        parent_id: Option<&str>,
        path: &str,
    ) -> ApiResult<(Option<String>, String)> {
        self.resolve_relative_upload_path_inner(workspace_id, parent_id, path, None)
    }

    pub(crate) fn resolve_relative_upload_path_authorized(
        &self,
        workspace_id: &str,
        parent_id: Option<&str>,
        path: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Option<String>, String)> {
        self.resolve_relative_upload_path_inner(
            workspace_id,
            parent_id,
            path,
            Some((actor, source_credential)),
        )
    }

    fn resolve_relative_upload_path_inner(
        &self,
        workspace_id: &str,
        parent_id: Option<&str>,
        path: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(Option<String>, String)> {
        // Validate the workspace exists (NotFound otherwise) before creating.
        self.workspace_storage_mode(workspace_id)?;
        let normalized = normalize_relative_upload_path(path)?;
        let mut segments = normalized
            .split('/')
            .map(str::to_string)
            .collect::<Vec<_>>();
        let leaf = segments
            .pop()
            .ok_or_else(|| ApiError::Validation("upload path must not be empty".to_string()))?;

        let mut current_parent = parent_id.map(|value| value.to_string());
        for folder_name in &segments {
            let existing = if let Some((actor, source_credential)) = authorization_context {
                let mut conn = self.conn.lock().unwrap();
                let tx = conn.transaction()?;
                human_item_grants::access::ensure_item_destination_authorized_in_tx(
                    &tx,
                    workspace_id,
                    current_parent.as_deref(),
                    actor,
                    source_credential,
                )?;
                let existing = bounded_files::get_active_child_file_by_name_locked(
                    &tx,
                    workspace_id,
                    current_parent.as_deref(),
                    folder_name,
                )?;
                tx.commit()?;
                existing
            } else {
                self.get_child_file_by_name(workspace_id, current_parent.as_deref(), folder_name)?
            };
            current_parent = match existing {
                Some(file) if matches!(file.kind, FileKind::Folder) => Some(file.id),
                Some(_) => {
                    return Err(ApiError::Validation(format!(
                        "upload path segment '{folder_name}' already exists as a file, not a folder"
                    )));
                }
                None => {
                    let request = CreateFileRequest {
                        workspace_id: workspace_id.to_string(),
                        parent_id: current_parent.clone(),
                        name: folder_name.clone(),
                        kind: FileKind::Folder,
                        content: None,
                        path: None,
                    };
                    let (folder, _) =
                        if let Some((actor, source_credential)) = authorization_context {
                            self.create_file_authorized(request, None, actor, source_credential)?
                        } else {
                            self.create_file(request, None)?
                        };
                    Some(folder.id)
                }
            };
        }
        Ok((current_parent, leaf))
    }

    pub fn get_file_metadata(&self, file_id: &str) -> ApiResult<FileMetadata> {
        // Capture the file so the metadata response can carry its stored size
        // (`None` for folders) alongside labels/custom metadata.
        let file = self.get_file(file_id)?.ok_or(ApiError::NotFound)?;
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT labels_json, custom_json FROM file_metadata WHERE file_id = ?1",
                params![file_id],
                |row| {
                    let labels_json: String = row.get(0)?;
                    let custom_json: String = row.get(1)?;
                    Ok((labels_json, custom_json))
                },
            )
            .optional()?;
        let Some((labels_json, custom_json)) = row else {
            return Ok(FileMetadata {
                size_bytes: file.size_bytes,
                folder_size_bytes: file.folder_size_bytes,
                ..empty_file_metadata()
            });
        };
        Ok(FileMetadata {
            labels: serde_json::from_str(&labels_json).unwrap_or_default(),
            custom_metadata: serde_json::from_str(&custom_json).unwrap_or_else(|_| json!({})),
            size_bytes: file.size_bytes,
            folder_size_bytes: file.folder_size_bytes,
        })
    }

    pub fn list_all_file_metadata(&self) -> ApiResult<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT file_id, labels_json, custom_json, updated_at
             FROM file_metadata ORDER BY updated_at DESC, file_id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], |row| {
            let labels_json: String = row.get(1)?;
            let custom_json: String = row.get(2)?;
            Ok(json!({
                "file_id": row.get::<_, String>(0)?,
                "labels": serde_json::from_str::<Vec<String>>(&labels_json).unwrap_or_default(),
                "custom_metadata": serde_json::from_str::<Value>(&custom_json).unwrap_or_else(|_| json!({})),
                "updated_at": row.get::<_, String>(3)?,
            }))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_file(
        &self,
        file_id: &str,
        request: UpdateFileRequest,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        self.update_file_as(file_id, request, "system")
    }

    pub fn update_file_as(
        &self,
        file_id: &str,
        request: UpdateFileRequest,
        actor: &str,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        self.update_file_inner(file_id, request, actor, None)
    }

    pub(crate) fn update_file_authorized(
        &self,
        file_id: &str,
        request: UpdateFileRequest,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        self.update_file_inner(
            file_id,
            request,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn update_file_inner(
        &self,
        file_id: &str,
        request: UpdateFileRequest,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        let base_revision = request.base_revision;
        let replace_target_id = request.replace_target_id;
        let replace_target_revision = request.replace_target_revision;
        let collision_policy = file_destination::parse_destination_collision_policy(
            request.collision_policy.as_deref(),
        )?;
        let name = match request.name {
            Some(name) => Some(validate_file_name(&name)?),
            None => None,
        };
        let parent_change = if request.move_to_root.unwrap_or(false) {
            Some(None)
        } else {
            request.parent_id.map(Some)
        };
        let destination_change_requested = name.is_some() || parent_change.is_some();

        let requested_labels = request.labels;
        let requested_custom_metadata = request.custom_metadata;
        let labels_changed = requested_labels.is_some();
        let custom_changed = requested_custom_metadata.is_some();

        let updated_at = Utc::now().to_rfc3339();
        let (result_file_id, receipt) = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let current = tx
                .query_row(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files WHERE id = ?1",
                    params![file_id],
                    row_to_file,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                human_item_grants::access::ensure_item_authorized_in_tx(
                    &tx,
                    &current.id,
                    actor,
                    source_credential,
                    WorkspacePermission::Write,
                )?;
            }
            if base_revision.is_some_and(|revision| revision != current.revision) {
                return Err(ApiError::Conflict);
            }
            let next_name = name.clone().unwrap_or_else(|| current.name.clone());
            let next_parent_id = parent_change
                .clone()
                .unwrap_or_else(|| current.parent_id.clone());
            if let Some((actor, source_credential)) = authorization_context {
                human_item_grants::access::ensure_item_destination_authorized_in_tx(
                    &tx,
                    &current.workspace_id,
                    next_parent_id.as_deref(),
                    actor,
                    source_credential,
                )?;
            }
            if let Some(parent_id) = next_parent_id.as_deref() {
                validate_parent_chain_in_tx(&tx, &current.workspace_id, parent_id, Some(file_id))?;
            }
            #[cfg(test)]
            self.pause_after_parent_validation();
            let destination = if destination_change_requested {
                file_destination::resolve_move_destination_in_tx(
                    &tx,
                    &current,
                    next_parent_id.as_deref(),
                    &next_name,
                    collision_policy,
                    &updated_at,
                )?
            } else {
                file_destination::ResolvedMoveDestination::Move(next_name)
            };
            if let file_destination::ResolvedMoveDestination::Replace(target) = &destination {
                if current.trashed {
                    return Err(ApiError::NotFound);
                }
                if base_revision.is_none()
                    || replace_target_id.is_none()
                    || replace_target_revision.is_none()
                {
                    return Err(ApiError::Validation(
                        "replace requires base_revision, replace_target_id, and replace_target_revision"
                            .to_string(),
                    ));
                }
                if target.id != replace_target_id.unwrap()
                    || target.revision != replace_target_revision.unwrap()
                {
                    return Err(ApiError::Conflict);
                }
                if let Some((actor, source_credential)) = authorization_context {
                    human_item_grants::access::ensure_item_authorized_in_tx(
                        &tx,
                        &target.id,
                        actor,
                        source_credential,
                        WorkspacePermission::Write,
                    )?;
                }
                let file = file_destination::replace_source_at_destination_in_tx(
                    &tx,
                    &current,
                    target,
                    requested_labels.as_ref(),
                    requested_custom_metadata.as_ref(),
                    &updated_at,
                )?;
                refresh_file_search_index_locked(&tx, &file.id)?;
                let source_receipt = new_receipt("file.trash", receipt_actor, Some(file_id));
                let receipt = new_receipt("file.replace", receipt_actor, Some(&file.id));
                insert_receipt_rows(&tx, &source_receipt)?;
                insert_receipt_rows(&tx, &receipt)?;
                tx.commit()?;
                (file.id, receipt)
            } else {
                let file_destination::ResolvedMoveDestination::Move(next_name) = destination else {
                    unreachable!("replace was handled above");
                };
                let existing_metadata = tx
                    .query_row(
                        "SELECT labels_json, custom_json FROM file_metadata WHERE file_id = ?1",
                        params![file_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                let next_metadata = if labels_changed || custom_changed {
                    let prior_source_usage = existing_metadata
                        .as_ref()
                        .map(|(labels_json, custom_json)| {
                            auxiliary_storage::project_raw_file_metadata_storage_usage(
                                labels_json,
                                custom_json,
                            )
                        })
                        .transpose()?;
                    let labels = match requested_labels {
                        Some(labels) => labels,
                        None => existing_metadata
                            .as_ref()
                            .map(|(labels_json, _)| serde_json::from_str(labels_json))
                            .transpose()
                            .map_err(|error| {
                                ApiError::Validation(format!(
                                    "stored metadata labels are invalid: {error}"
                                ))
                            })?
                            .unwrap_or_default(),
                    };
                    let custom_metadata = match requested_custom_metadata {
                        Some(custom_metadata) => custom_metadata,
                        None => existing_metadata
                            .as_ref()
                            .map(|(_, custom_json)| serde_json::from_str(custom_json))
                            .transpose()
                            .map_err(|error| {
                                ApiError::Validation(format!(
                                    "stored custom metadata is invalid: {error}"
                                ))
                            })?
                            .unwrap_or_else(|| json!({})),
                    };
                    let projection =
                        auxiliary_storage::project_file_metadata_storage(labels, &custom_metadata)?;
                    let previous_metadata_fts_projection_bytes = tx
                        .query_row(
                            "SELECT projection_bytes
                         FROM workspace_auxiliary_metadata_fts_projection
                         WHERE file_id = ?1",
                            params![file_id],
                            |row| row.get::<_, i64>(0),
                        )
                        .optional()?
                        .unwrap_or(4);
                    let previous_usage = auxiliary_storage::WorkspaceAuxiliaryStorageDelta {
                        file_metadata_bytes: prior_source_usage
                            .as_ref()
                            .map(|usage| usage.file_metadata_bytes)
                            .unwrap_or(0),
                        metadata_fts_projection_bytes: previous_metadata_fts_projection_bytes,
                        ..auxiliary_storage::WorkspaceAuxiliaryStorageDelta::default()
                    };
                    let delta = projection.usage.checked_difference(previous_usage)?;
                    auxiliary_storage::ensure_workspace_auxiliary_storage_delta_fits_in_tx(
                        &tx,
                        &current.workspace_id,
                        delta,
                    )?;
                    Some(projection)
                } else {
                    None
                };
                let next_revision = current.revision + 1;
                let content_bytes = current.size_bytes.unwrap_or(0);
                tx.execute(
                    "UPDATE files
                 SET name = ?1, parent_id = ?2, revision = ?3, updated_at = ?4
                 WHERE id = ?5",
                    params![
                        next_name,
                        next_parent_id,
                        next_revision,
                        &updated_at,
                        file_id
                    ],
                )?;
                tx.execute(
                "INSERT INTO file_revisions (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    file_id,
                    next_revision,
                    &current.content_hash,
                    content_bytes,
                    &updated_at,
                ],
            )?;
                if let Some(metadata) = next_metadata {
                    tx.execute(
                        "INSERT INTO file_metadata (file_id, labels_json, custom_json, updated_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(file_id) DO UPDATE SET
                        labels_json = excluded.labels_json,
                        custom_json = excluded.custom_json,
                        updated_at = excluded.updated_at",
                        params![
                            file_id,
                            metadata.labels_json,
                            metadata.custom_json,
                            &updated_at,
                        ],
                    )?;
                }
                refresh_file_search_index_locked(&tx, file_id)?;
                let receipt = new_receipt("file.update", receipt_actor, Some(file_id));
                insert_receipt_rows(&tx, &receipt)?;
                tx.commit()?;
                (file_id.to_string(), receipt)
            }
        };

        let file = self.get_file(&result_file_id)?.ok_or(ApiError::NotFound)?;
        let metadata = self.get_file_metadata(&result_file_id)?;
        self.enqueue_file_background_jobs(&file)?;
        Ok((file, metadata, receipt))
    }

    pub fn copy_file(
        &self,
        file_id: &str,
        name: Option<String>,
        parent_id: Option<String>,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        self.copy_file_as(file_id, name, parent_id, "system")
    }

    pub fn copy_file_as(
        &self,
        file_id: &str,
        name: Option<String>,
        parent_id: Option<String>,
        actor: &str,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        self.copy_file_inner(
            file_id,
            name,
            parent_id
                .map(CopyParentId::Parent)
                .unwrap_or(CopyParentId::Omitted),
            actor,
            None,
            false,
        )
    }

    pub(crate) fn copy_file_authorized(
        &self,
        file_id: &str,
        name: Option<String>,
        parent_id: CopyParentId,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        self.copy_file_inner(
            file_id,
            name,
            parent_id,
            &actor.email,
            Some((actor, source_credential)),
            false,
        )
    }

    /// Copy to the exact caller-selected destination. Path-addressed protocols
    /// use this to reject a collision that appears after preflight; ordinary
    /// Drive copies retain their Keep Both behavior.
    pub(crate) fn copy_file_authorized_exact_destination(
        &self,
        file_id: &str,
        name: String,
        parent_id: CopyParentId,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        self.copy_file_inner(
            file_id,
            Some(name),
            parent_id,
            &actor.email,
            Some((actor, source_credential)),
            true,
        )
    }

    fn copy_file_inner(
        &self,
        file_id: &str,
        name: Option<String>,
        parent_id: CopyParentId,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
        destination_must_be_available: bool,
    ) -> ApiResult<(DriveFile, FileMetadata, Receipt)> {
        let source = self.get_file(file_id)?.ok_or(ApiError::NotFound)?;
        if source.trashed {
            return Err(ApiError::Validation("cannot copy trashed file".to_string()));
        }
        let requested_name = name.map(|name| validate_file_name(&name)).transpose()?;
        let requested_parent_id = parent_id;
        let now = Utc::now().to_rfc3339();
        let metadata = self.get_file_metadata(file_id)?;

        let (copied_files, receipt) = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

            let source = tx
                .query_row(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files
                     WHERE id = ?1 AND workspace_id = ?2 AND trashed = 0",
                    params![file_id, &source.workspace_id],
                    row_to_file,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                human_item_grants::access::ensure_item_authorized_in_tx(
                    &tx,
                    &source.id,
                    actor,
                    source_credential,
                    WorkspacePermission::Write,
                )?;
            }
            let source_workspace_id = source.workspace_id.clone();
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&source_workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            let requested_copy_name = requested_name
                .clone()
                .unwrap_or_else(|| source.name.clone());
            let copy_parent_id = match &requested_parent_id {
                CopyParentId::Omitted => source.parent_id.clone(),
                CopyParentId::Root => None,
                CopyParentId::Parent(parent_id) => Some(parent_id.clone()),
            };
            if let Some((actor, source_credential)) = authorization_context {
                human_item_grants::access::ensure_item_destination_authorized_in_tx(
                    &tx,
                    &source_workspace_id,
                    copy_parent_id.as_deref(),
                    actor,
                    source_credential,
                )?;
            }
            let destination_depth = copy_parent_id
                .as_deref()
                .map(|parent_id| {
                    validate_parent_chain_in_tx(
                        &tx,
                        &source_workspace_id,
                        parent_id,
                        Some(&source.id),
                    )
                })
                .transpose()?
                .unwrap_or(0);
            let root_copy_id = Uuid::now_v7().to_string();
            let copy_name = if destination_must_be_available {
                file_destination::ensure_live_sibling_available_in_tx(
                    &tx,
                    &source_workspace_id,
                    &root_copy_id,
                    copy_parent_id.as_deref(),
                    &requested_copy_name,
                )?;
                requested_copy_name
            } else {
                file_destination::available_copy_name_in_tx(
                    &tx,
                    &source_workspace_id,
                    copy_parent_id.as_deref(),
                    &requested_copy_name,
                )?
            };

            #[derive(Clone)]
            struct CopyEntry {
                source: DriveFile,
                target_id: String,
                target_parent_id: Option<String>,
                target_name: String,
                cover_hash: Option<String>,
                cover_bytes: i64,
                relative_depth: usize,
            }

            let entries = {
                let mut child_statement = tx.prepare(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files
                     WHERE workspace_id = ?1 AND parent_id = ?2 AND trashed = 0
                     ORDER BY lower(name) ASC, id ASC",
                )?;
                let (source_cover_hash, source_cover_bytes) =
                    copy_cover_reference_in_tx(&tx, &source.id)?;
                let mut stack = vec![CopyEntry {
                    source,
                    target_id: root_copy_id,
                    target_parent_id: copy_parent_id,
                    target_name: copy_name,
                    cover_hash: source_cover_hash,
                    cover_bytes: source_cover_bytes,
                    relative_depth: 0,
                }];
                let mut visited = HashSet::new();
                let mut entries = Vec::new();
                while let Some(entry) = stack.pop() {
                    if !visited.insert(entry.source.id.clone()) {
                        return Err(ApiError::Validation(
                            "file tree contains a parent cycle".to_string(),
                        ));
                    }
                    if entries.len() >= MAX_FILE_TREE_NODES {
                        return Err(ApiError::Validation(format!(
                            "file tree exceeds the {MAX_FILE_TREE_NODES}-item copy limit"
                        )));
                    }
                    let target_depth = destination_depth
                        .checked_add(entry.relative_depth)
                        .ok_or_else(|| {
                            ApiError::Validation("file tree depth overflow".to_string())
                        })?;
                    if target_depth > MAX_FILE_TREE_DEPTH {
                        return Err(ApiError::Validation(format!(
                            "file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
                        )));
                    }

                    let child_parent_id = entry.target_id.clone();
                    let child_depth = entry.relative_depth.checked_add(1).ok_or_else(|| {
                        ApiError::Validation("file tree depth overflow".to_string())
                    })?;
                    let children = child_statement
                        .query_map(params![&source_workspace_id, &entry.source.id], row_to_file)?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    for child in children.into_iter().rev() {
                        let (cover_hash, cover_bytes) = copy_cover_reference_in_tx(&tx, &child.id)?;
                        stack.push(CopyEntry {
                            target_id: Uuid::now_v7().to_string(),
                            target_parent_id: Some(child_parent_id.clone()),
                            target_name: child.name.clone(),
                            source: child,
                            cover_hash,
                            cover_bytes,
                            relative_depth: child_depth,
                        });
                    }
                    entries.push(entry);
                }
                entries
            };
            let copy_metadata = entries
                .iter()
                .map(|entry| {
                    let (labels_json, custom_json) = tx
                        .query_row(
                            "SELECT labels_json, custom_json FROM file_metadata WHERE file_id = ?1",
                            params![&entry.source.id],
                            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                        )
                        .optional()?
                        .unwrap_or_else(|| ("[]".to_string(), "{}".to_string()));
                    Ok::<_, ApiError>((
                        entry.source.id.clone(),
                        auxiliary_storage::project_persisted_file_metadata_storage(
                            &labels_json,
                            &custom_json,
                        )?,
                    ))
                })
                .collect::<ApiResult<HashMap<_, _>>>()?;
            let (file_metadata_bytes, metadata_fts_projection_bytes) = copy_metadata
                .values()
                .try_fold((0_i64, 0_i64), |(metadata, fts), projection| {
                    Ok::<_, ApiError>((
                        metadata
                            .checked_add(projection.usage.file_metadata_bytes)
                            .ok_or_else(|| {
                                ApiError::Validation("copy metadata budget overflow".to_string())
                            })?,
                        fts.checked_add(projection.usage.metadata_fts_projection_bytes)
                            .ok_or_else(|| {
                                ApiError::Validation(
                                    "copy metadata FTS budget overflow".to_string(),
                                )
                            })?,
                    ))
                })?;
            let metadata_delta = auxiliary_storage::WorkspaceAuxiliaryStorageDelta {
                file_metadata_bytes,
                metadata_fts_projection_bytes,
                ..auxiliary_storage::WorkspaceAuxiliaryStorageDelta::default()
            };
            auxiliary_storage::ensure_workspace_auxiliary_storage_delta_fits_in_tx(
                &tx,
                &source_workspace_id,
                metadata_delta,
            )?;

            let additional_quota_bytes = entries.iter().try_fold(0_i64, |total, entry| {
                total
                    .checked_add(
                        entry
                            .source
                            .size_bytes
                            .unwrap_or(0)
                            .max(1)
                            .checked_add(entry.cover_bytes)
                            .ok_or_else(|| {
                                ApiError::Validation("copy quota size overflow".to_string())
                            })?,
                    )
                    .ok_or_else(|| ApiError::Validation("copy quota size overflow".to_string()))
            })?;
            if let Some(quota_bytes) = quota_bytes {
                enforce_quota_charge_in_txn(
                    &tx,
                    quota_bytes,
                    &source_workspace_id,
                    None,
                    additional_quota_bytes,
                )?;
            }

            bounded_files::ensure_workspace_node_capacity(
                &tx,
                &source_workspace_id,
                entries.len(),
            )?;
            let mut copied_files = Vec::with_capacity(entries.len());
            for entry in entries {
                let content_bytes = entry.source.size_bytes.unwrap_or(0);
                let metadata = copy_metadata.get(&entry.source.id).ok_or_else(|| {
                    ApiError::Validation("copy metadata projection is missing".to_string())
                })?;
                let copied = DriveFile {
                    id: entry.target_id,
                    workspace_id: entry.source.workspace_id.clone(),
                    parent_id: entry.target_parent_id,
                    name: entry.target_name,
                    kind: entry.source.kind.clone(),
                    revision: 1,
                    trashed: false,
                    starred: false,
                    content_hash: entry.source.content_hash.clone(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                    size_bytes: matches!(entry.source.kind, FileKind::File)
                        .then_some(content_bytes),
                    folder_size_bytes: None,
                    has_cover: entry.cover_hash.is_some(),
                };
                tx.execute(
                    "INSERT INTO files (id, workspace_id, parent_id, name, kind, revision, trashed, starred, content_hash, content_bytes, created_at, updated_at, cover_hash, cover_bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, 0, ?6, ?7, ?8, ?8, ?9, ?10)",
                    params![
                        &copied.id,
                        &copied.workspace_id,
                        &copied.parent_id,
                        &copied.name,
                        copied.kind.as_db_str(),
                        &copied.content_hash,
                        content_bytes,
                        &now,
                        &entry.cover_hash,
                        entry.cover_bytes,
                    ],
                )?;
                tx.execute(
                    "INSERT INTO file_revisions (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                     VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL)",
                    params![
                        Uuid::now_v7().to_string(),
                        &copied.id,
                        &copied.content_hash,
                        content_bytes,
                        &now,
                    ],
                )?;
                tx.execute(
                    "INSERT INTO file_metadata (file_id, labels_json, custom_json, updated_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        &copied.id,
                        &metadata.labels_json,
                        &metadata.custom_json,
                        &now
                    ],
                )?;
                refresh_file_search_index_locked(&tx, &copied.id)?;
                copied_files.push(copied);
            }
            let receipt_target = copied_files
                .first()
                .map(|file| file.id.as_str())
                .ok_or_else(|| {
                    ApiError::Validation("copy produced an empty file tree".to_string())
                })?;
            let receipt = new_receipt("file.copy", receipt_actor, Some(receipt_target));
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            (copied_files, receipt)
        };

        let file = copied_files
            .first()
            .cloned()
            .ok_or_else(|| ApiError::Validation("copy produced an empty file tree".to_string()))?;
        for copied in &copied_files {
            if matches!(copied.kind, FileKind::File) {
                self.enqueue_file_background_jobs(copied)?;
            }
        }
        Ok((file, metadata, receipt))
    }

    pub(super) fn validate_parent_chain(
        &self,
        workspace_id: &str,
        parent_id: &str,
        forbidden_file_id: Option<&str>,
    ) -> ApiResult<usize> {
        let conn = self.conn.lock().unwrap();
        validate_parent_chain_in_connection(&conn, workspace_id, parent_id, forbidden_file_id)
    }

    pub fn put_content(
        &self,
        file_id: &str,
        base_revision: i64,
        content_hash: &str,
        content_bytes: i64,
    ) -> ApiResult<ContentWrite> {
        self.put_content_as(
            file_id,
            base_revision,
            content_hash,
            content_bytes,
            "system",
        )
    }

    pub fn put_content_as(
        &self,
        file_id: &str,
        base_revision: i64,
        content_hash: &str,
        content_bytes: i64,
        actor: &str,
    ) -> ApiResult<ContentWrite> {
        self.put_content_inner(
            file_id,
            base_revision,
            content_hash,
            content_bytes,
            actor,
            None,
        )
    }

    pub(crate) fn put_content_authorized(
        &self,
        file_id: &str,
        base_revision: i64,
        content_hash: &str,
        content_bytes: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<ContentWrite> {
        self.put_content_inner(
            file_id,
            base_revision,
            content_hash,
            content_bytes,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn put_content_inner(
        &self,
        file_id: &str,
        base_revision: i64,
        content_hash: &str,
        content_bytes: i64,
        receipt_actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<ContentWrite> {
        let content_bytes = validate_non_negative_i64(content_bytes, "content_bytes")?;
        struct ConflictMutation {
            conflict_file: DriveFile,
            current_file_id: String,
            current_revision: i64,
            receipt: Receipt,
        }
        enum Mutation {
            Updated(Receipt),
            Conflict(Box<ConflictMutation>),
        }
        let mutation = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let current = tx
                .query_row(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files WHERE id = ?1",
                    params![file_id],
                    row_to_file,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                human_item_grants::access::ensure_item_authorized_in_tx(
                    &tx,
                    &current.id,
                    actor,
                    source_credential,
                    WorkspacePermission::Write,
                )?;
            }
            if current.trashed {
                return Err(ApiError::NotFound);
            }
            if !matches!(current.kind, FileKind::File) {
                return Err(ApiError::Validation(
                    "folders cannot contain file content".to_string(),
                ));
            }
            if let Some(parent_id) = current.parent_id.as_deref() {
                validate_parent_chain_in_tx(&tx, &current.workspace_id, parent_id, Some(file_id))?;
            }
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&current.workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            if current.revision != base_revision {
                if let Some((actor, source_credential)) = authorization_context {
                    human_item_grants::access::ensure_item_destination_authorized_in_tx(
                        &tx,
                        &current.workspace_id,
                        current.parent_id.as_deref(),
                        actor,
                        source_credential,
                    )?;
                }
                let now = Utc::now().to_rfc3339();
                let conflict_name = file_destination::available_copy_name_in_tx(
                    &tx,
                    &current.workspace_id,
                    current.parent_id.as_deref(),
                    &derive_conflict_file_name(&current.name, &now)?,
                )?;
                let conflict_file = DriveFile {
                    id: Uuid::now_v7().to_string(),
                    workspace_id: current.workspace_id.clone(),
                    parent_id: current.parent_id.clone(),
                    name: conflict_name,
                    kind: FileKind::File,
                    revision: 1,
                    trashed: false,
                    starred: false,
                    content_hash: Some(content_hash.to_string()),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                    size_bytes: Some(content_bytes),
                    folder_size_bytes: None,
                    has_cover: false,
                };
                if let Some(quota_bytes) = quota_bytes {
                    enforce_quota_in_txn(
                        &tx,
                        quota_bytes,
                        &conflict_file.workspace_id,
                        None,
                        content_bytes,
                    )?;
                }
                bounded_files::ensure_workspace_node_capacity(&tx, &conflict_file.workspace_id, 1)?;
                tx.execute(
                    "INSERT INTO files (id, workspace_id, parent_id, name, kind, revision, trashed, starred, content_hash, content_bytes, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        &conflict_file.id,
                        &conflict_file.workspace_id,
                        &conflict_file.parent_id,
                        &conflict_file.name,
                        conflict_file.kind.as_db_str(),
                        conflict_file.revision,
                        0,
                        0,
                        &conflict_file.content_hash,
                        content_bytes,
                        &conflict_file.created_at,
                        &conflict_file.updated_at,
                    ],
                )?;
                tx.execute(
                    "INSERT INTO file_revisions (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision, conflict_of_file_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        Uuid::now_v7().to_string(),
                        &conflict_file.id,
                        conflict_file.revision,
                        &conflict_file.content_hash,
                        content_bytes,
                        &conflict_file.created_at,
                        base_revision,
                        &current.id,
                    ],
                )?;
                let receipt = new_receipt("file.conflict", receipt_actor, Some(&conflict_file.id));
                insert_receipt_rows(&tx, &receipt)?;
                let mutation = Mutation::Conflict(Box::new(ConflictMutation {
                    conflict_file,
                    current_file_id: current.id,
                    current_revision: current.revision,
                    receipt,
                }));
                tx.commit()?;
                mutation
            } else {
                let next_revision = current.revision + 1;
                let updated_at = Utc::now().to_rfc3339();
                if let Some(quota_bytes) = quota_bytes {
                    // `Some(file_id)` excludes this file's current bytes: an in-place
                    // overwrite only charges the delta. The SUM reads the pre-UPDATE
                    // row (enforced before the UPDATE below), same as the old check.
                    enforce_quota_in_txn(
                        &tx,
                        quota_bytes,
                        &current.workspace_id,
                        Some(file_id),
                        content_bytes,
                    )?;
                }
                tx.execute(
                "UPDATE files SET revision = ?1, content_hash = ?2, content_bytes = ?3, updated_at = ?4 WHERE id = ?5",
                params![next_revision, content_hash, content_bytes, &updated_at, file_id],
            )?;
                tx.execute(
                "INSERT INTO file_revisions (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    file_id,
                    next_revision,
                    content_hash,
                    content_bytes,
                    &updated_at,
                ],
            )?;
                let receipt = new_receipt("file.content.update", receipt_actor, Some(file_id));
                insert_receipt_rows(&tx, &receipt)?;
                tx.commit()?;
                Mutation::Updated(receipt)
            }
        };

        match mutation {
            Mutation::Updated(receipt) => {
                let file = self.get_file(file_id)?.ok_or(ApiError::NotFound)?;
                self.enqueue_file_background_jobs(&file)?;
                Ok(ContentWrite::Updated { file, receipt })
            }
            Mutation::Conflict(conflict) => {
                self.enqueue_file_background_jobs(&conflict.conflict_file)?;
                Ok(ContentWrite::Conflict(StaleRevisionResponse {
                    error: "stale_revision",
                    file_id: conflict.current_file_id,
                    attempted_base_revision: base_revision,
                    current_revision: conflict.current_revision,
                    conflict_file_id: conflict.conflict_file.id,
                    receipt: conflict.receipt,
                }))
            }
        }
    }

    /// Build the read-only subtree of a shared folder as `(relative_path, file)`
    /// pairs, where `relative_path` is relative to the shared folder root (the
    /// folder's own name is NOT included). This is the single source of truth for
    /// BOTH the folder-share listing ([`Self::share_folder_entries`]) and the
    /// per-file fetch ([`Self::share_folder_content`]): a path is fetchable if and
    /// only if it appears here, so scope escape is structurally impossible — the
    /// set only ever contains descendants of `folder_id` in the same workspace.
    ///
    /// Trashed nodes are excluded.
    fn share_subtree(&self, folder: &DriveFile) -> ApiResult<Vec<(String, DriveFile)>> {
        if !matches!(folder.kind, FileKind::Folder) {
            return Err(ApiError::Validation(
                "share target is not a folder".to_string(),
            ));
        }
        let all = self.active_descendants_inclusive_bounded(&folder.id)?;
        let mut paths = crate::path_projection::project_file_paths(
            &all,
            Some(&folder.id),
            MAX_PUBLIC_SHARE_PATH_BYTES,
            "public folder share",
        )?;
        let mut out = all
            .into_iter()
            .filter(|file| file.id != folder.id)
            .map(|file| {
                let path = paths.remove(&file.id).ok_or_else(|| {
                    ApiError::Validation(
                        "public folder share path projection is incomplete".to_string(),
                    )
                })?;
                Ok((path, file))
            })
            .collect::<ApiResult<Vec<_>>>()?;
        out.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(out)
    }

    /// Subtree listing for a folder share: every descendant file and folder as a
    /// [`ShareEntry`] with a path relative to the shared folder root. Read-only.
    pub fn share_folder_entries(&self, folder_id: &str) -> ApiResult<Vec<ShareEntry>> {
        Ok(self.share_folder_entries_with_subjects(folder_id)?.0)
    }

    /// Return the public folder entries together with the exact raw nodes that
    /// produced them.  The metadata route retains those nodes as an internal
    /// terminal-publication snapshot; it never exposes the extra fields.
    pub(crate) fn share_folder_entries_with_subjects(
        &self,
        folder_id: &str,
    ) -> ApiResult<(Vec<ShareEntry>, Vec<DriveFile>)> {
        let folder = self
            .get_file_unaggregated(folder_id)?
            .ok_or(ApiError::NotFound)?;
        let subtree = self.share_subtree(&folder)?;
        let mut entries = Vec::with_capacity(subtree.len());
        let mut subjects = Vec::with_capacity(subtree.len());
        for (path, file) in subtree {
            entries.push(ShareEntry {
                path,
                name: file.name.clone(),
                kind: file.kind.as_db_str().to_string(),
                size_bytes: file.size_bytes,
                folder_size_bytes: file.folder_size_bytes,
                updated_at: file.updated_at.clone(),
            });
            subjects.push(file);
        }
        Ok((entries, subjects))
    }

    /// Resolve one file inside a folder share's subtree by its relative path and
    /// return it. `rel_path` is matched against [`Self::share_subtree`], so only
    /// files strictly inside the shared folder can ever resolve — a `..`,
    /// absolute, or sibling/parent path simply has no match and yields
    /// `NotFound`. As defence-in-depth the path is also rejected up front if any
    /// segment is empty, `.`, `..`, or the path is absolute / uses `\`.
    /// A path that resolves to a folder (not a file) is `NotFound` — a folder has
    /// no content to serve.
    pub fn share_folder_content(&self, folder_id: &str, rel_path: &str) -> ApiResult<DriveFile> {
        // Reject obviously-malicious shapes before touching the subtree. This is
        // belt-and-braces on top of the subtree membership check below.
        let normalized = rel_path.trim();
        if normalized.is_empty() || normalized.starts_with('/') || normalized.contains('\\') {
            return Err(ApiError::NotFound);
        }
        for segment in normalized.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(ApiError::NotFound);
            }
        }
        let folder = self
            .get_file_unaggregated(folder_id)?
            .ok_or(ApiError::NotFound)?;
        let subtree = self.share_subtree(&folder)?;
        let file = subtree
            .into_iter()
            .find(|(path, _)| path == normalized)
            .map(|(_, file)| file)
            .ok_or(ApiError::NotFound)?;
        if !matches!(file.kind, FileKind::File) {
            return Err(ApiError::NotFound);
        }
        Ok(file)
    }

    pub fn descendants_inclusive(&self, file_id: &str) -> ApiResult<Vec<DriveFile>> {
        self.descendants_inclusive_bounded(file_id, false)
    }

    pub fn list_files(&self) -> ApiResult<Vec<DriveFile>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred, content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_file)?;
        let mut files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        attach_folder_sizes_locked(&conn, &mut files)?;
        Ok(files)
    }

    /// Return one keyset-bounded page for the account-level file browser.
    ///
    /// The query repeats the same direct/group membership policy used by
    /// `list_workspaces_for_actor`, but it never materializes that workspace
    /// list or every file before filtering. The `admin` relationship is
    /// intentionally separate from ownership: an administrator can inspect all
    /// workspaces but does not become their owner merely by browsing them.
    pub fn browse_files_for_actor(
        &self,
        actor: &Actor,
        scope: FileBrowseScope,
        cursor: Option<&FileBrowseCursor>,
        requested_limit: usize,
        filters: &FileBrowseFilters,
    ) -> ApiResult<(Vec<BrowseFile>, Option<FileBrowseCursor>)> {
        const MAX_BROWSE_PAGE_SIZE: usize = 100;
        let limit = requested_limit.clamp(1, MAX_BROWSE_PAGE_SIZE);

        let Some(actor_scope) = actor_scope::actor_workspace_scope(actor) else {
            return Ok((Vec::new(), None));
        };
        let visible_workspaces = actor_scope.sql;
        let mut parameters = actor_scope.parameters;
        let mut next_parameter = actor_scope.next_parameter;

        // Location-oriented views preserve the Drive folder hierarchy: show
        // only workspace roots, then let the browser enter a folder through
        // its workspace manifest. Recent is intentionally a cross-folder
        // activity list, so descendants remain eligible there.
        let scope_predicate = match scope {
            FileBrowseScope::Files | FileBrowseScope::Mine if filters.folder_id.is_some() => {
                "1 = 1"
            }
            FileBrowseScope::Files => "f.parent_id IS NULL",
            FileBrowseScope::Mine => "f.parent_id IS NULL AND vw.access_role = 'owner'",
            FileBrowseScope::SharedWithMe => "f.parent_id IS NULL AND vw.access_role != 'owner'",
            FileBrowseScope::Recent => "1 = 1",
        };
        let cursor_predicate = match (scope.uses_recent_order(), cursor) {
            (_, None) => String::new(),
            (true, Some(FileBrowseCursor::Recent { updated_at, id })) => {
                let updated_at_parameter = next_parameter;
                let id_parameter = next_parameter + 1;
                parameters.push(SqlValue::Text(updated_at.clone()));
                parameters.push(SqlValue::Text(id.clone()));
                next_parameter += 2;
                format!(
                    " AND (f.updated_at < ?{updated_at_parameter}
                              OR (f.updated_at = ?{updated_at_parameter} AND f.id < ?{id_parameter}))"
                )
            }
            (
                false,
                Some(FileBrowseCursor::Name {
                    kind_rank,
                    name,
                    workspace_name,
                    id,
                }),
            ) => {
                let kind_parameter = next_parameter;
                let name_parameter = next_parameter + 1;
                let workspace_parameter = next_parameter + 2;
                let id_parameter = next_parameter + 3;
                parameters.push(SqlValue::Integer(*kind_rank));
                parameters.push(SqlValue::Text(name.clone()));
                parameters.push(SqlValue::Text(workspace_name.clone()));
                parameters.push(SqlValue::Text(id.clone()));
                next_parameter += 4;
                format!(
                    " AND (
                        CASE WHEN f.kind = 'folder' THEN 0 ELSE 1 END > ?{kind_parameter}
                        OR (
                          CASE WHEN f.kind = 'folder' THEN 0 ELSE 1 END = ?{kind_parameter}
                          AND f.name COLLATE BINARY > ?{name_parameter}
                        ) OR (
                          CASE WHEN f.kind = 'folder' THEN 0 ELSE 1 END = ?{kind_parameter}
                          AND f.name COLLATE BINARY = ?{name_parameter}
                          AND vw.name COLLATE BINARY > ?{workspace_parameter}
                        ) OR (
                          CASE WHEN f.kind = 'folder' THEN 0 ELSE 1 END = ?{kind_parameter}
                          AND f.name COLLATE BINARY = ?{name_parameter}
                          AND vw.name COLLATE BINARY = ?{workspace_parameter}
                          AND f.id > ?{id_parameter}
                        )
                      )"
                )
            }
            (true, Some(FileBrowseCursor::Name { .. }))
            | (false, Some(FileBrowseCursor::Recent { .. })) => {
                return Err(ApiError::Validation(
                    "browse cursor order does not match the selected scope".to_string(),
                ));
            }
        };
        let filter_sql = filters.sql(&actor.email, &mut parameters, &mut next_parameter);
        let order_by = if scope.uses_recent_order() {
            "f.updated_at DESC, f.id DESC"
        } else {
            "CASE WHEN f.kind = 'folder' THEN 0 ELSE 1 END ASC,
             f.name COLLATE BINARY ASC,
             vw.name COLLATE BINARY ASC,
             f.id ASC"
        };
        let limit_parameter = next_parameter;
        parameters.push(SqlValue::Integer(
            i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX),
        ));
        let effective_visibility = effectively_live_sql_predicate("f");

        let sql = format!(
            "WITH visible_workspaces AS ({visible_workspaces})
             SELECT f.id, f.workspace_id, f.parent_id, f.name, f.kind, f.revision,
                    f.trashed, f.starred, f.content_hash, f.created_at, f.updated_at,
                    f.content_bytes, f.cover_hash, vw.name, vw.access_role,
                    CASE WHEN vw.access_role = 'owner' THEN 1 ELSE 0 END
             FROM files f
             JOIN visible_workspaces vw ON vw.id = f.workspace_id
             WHERE f.trashed = 0 AND {scope_predicate}{cursor_predicate}{filter_sql}
               AND {effective_visibility}
             ORDER BY {order_by}
             LIMIT ?{limit_parameter}"
        );

        let conn = self.conn.lock().unwrap();
        // Keep preflight and selection in one SQLite snapshot.
        let _read_snapshot = conn.unchecked_transaction()?;
        // Reject unsafe legacy labels before SQLite sorts a copy for every
        // matching file. BLOB length measures UTF-8 bytes, including NULs.
        let unsafe_workspace_name: bool = conn.query_row(
            &format!(
                "WITH visible_workspaces AS ({visible_workspaces})
                SELECT EXISTS (SELECT 1 FROM files f
                JOIN visible_workspaces vw ON vw.id = f.workspace_id
                WHERE f.trashed = 0 AND {scope_predicate}{cursor_predicate}{filter_sql}
                AND {effective_visibility}
                AND length(CAST(vw.name AS BLOB)) > {MAX_WORKSPACE_NAME_BYTES})"
            ),
            params_from_iter(parameters[..parameters.len() - 1].iter()),
            |row| row.get(0),
        )?;
        if unsafe_workspace_name {
            return Err(ApiError::PayloadTooLarge(
                "workspace name exceeds 255 bytes; rename it before browsing".to_string(),
            ));
        }
        let mut statement = conn.prepare(&sql)?;
        let mut rows = statement.query(params_from_iter(parameters.iter()))?;
        let mut files = Vec::with_capacity(limit + 1);
        while let Some(row) = rows.next()? {
            if let ValueRef::Text(name) = row.get_ref(13)? {
                if name.len() > MAX_WORKSPACE_NAME_BYTES {
                    return Err(ApiError::PayloadTooLarge(
                        "workspace name exceeds 255 bytes; rename it before browsing".to_string(),
                    ));
                }
            }
            let file = row_to_file(row)?;
            let access_role: String = row.get(14)?;
            let owned_by_actor: i64 = row.get(15)?;
            files.push(BrowseFile {
                file,
                workspace_name: row.get(13)?,
                access_role,
                owned_by_actor: owned_by_actor != 0,
            });
        }
        let has_more = files.len() > limit;
        if has_more {
            files.pop();
        }
        let next_cursor = has_more
            .then(|| {
                files.last().map(|file| {
                    if scope.uses_recent_order() {
                        FileBrowseCursor::Recent {
                            updated_at: file.file.updated_at.clone(),
                            id: file.file.id.clone(),
                        }
                    } else {
                        FileBrowseCursor::Name {
                            kind_rank: if matches!(&file.file.kind, FileKind::Folder) {
                                0
                            } else {
                                1
                            },
                            name: file.file.name.clone(),
                            workspace_name: file.workspace_name.clone(),
                            id: file.file.id.clone(),
                        }
                    }
                })
            })
            .flatten();
        Ok((files, next_cursor))
    }

    pub fn list_files_for_workspace(&self, workspace_id: &str) -> ApiResult<Vec<DriveFile>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred, content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files WHERE workspace_id = ?1 ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map(params![workspace_id], row_to_file)?;
        let mut files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        attach_folder_sizes_locked(&conn, &mut files)?;
        Ok(files)
    }

    pub fn list_active_files_for_workspace_bounded(
        &self,
        workspace_id: &str,
        max_rows: usize,
    ) -> ApiResult<Vec<DriveFile>> {
        let query_limit = i64::try_from(max_rows)
            .unwrap_or(i64::MAX)
            .saturating_add(1);
        let conn = self.conn.lock().unwrap();
        let effective_visibility = effectively_live_sql_predicate("files");
        let sql = format!(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1 AND trashed = 0
               AND {effective_visibility}
             ORDER BY updated_at DESC, id DESC
             LIMIT ?2"
        );
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params![workspace_id, query_limit], row_to_file)?;
        let files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if files.len() > max_rows {
            return Err(ApiError::Validation(format!(
                "workspace file tree exceeds the {max_rows}-item traversal limit"
            )));
        }
        // WebDAV does not expose recursive folder-size aggregates. Skipping
        // that workspace-wide derived query keeps this safety path bounded by
        // the same row limit as the materialized file list.
        Ok(files)
    }

    pub fn all_file_trees(&self) -> ApiResult<Vec<FileTreeResponse>> {
        let mut trees = Vec::new();
        let mut remaining = usize::try_from(MAX_DEBUG_LIST_ROWS).unwrap_or(1_000);
        for workspace in self.list_workspaces_bounded(MAX_DEBUG_LIST_ROWS)? {
            if remaining == 0 {
                break;
            }
            let mut tree = self.file_tree(&workspace.id)?;
            if tree.nodes.len() > remaining {
                tree.nodes.truncate(remaining);
            }
            remaining = remaining.saturating_sub(tree.nodes.len());
            trees.push(tree);
        }
        Ok(trees)
    }

    pub fn list_sync_changes(
        &self,
        cursor: i64,
        workspace_id: Option<&str>,
    ) -> ApiResult<Vec<SyncChange>> {
        let cursor = cursor.max(0);
        let conn = self.conn.lock().unwrap();
        if let Some(workspace_id) = workspace_id {
            let floor: i64 = conn.query_row(
                "SELECT COALESCE(floor_cursor, 0) FROM sync_change_floors WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get(0),
            ).optional()?.unwrap_or(0);
            if cursor < floor {
                return Err(ApiError::Conflict);
            }
            let mut stmt = conn.prepare(
                "SELECT id, workspace_id, kind, entity_type, entity_id, actor, receipt_id, created_at
                 FROM sync_changes
                 WHERE id > ?1 AND workspace_id = ?2
                 ORDER BY id ASC
                 LIMIT 500",
            )?;
            let rows = stmt.query_map(params![cursor, workspace_id], row_to_sync_change)?;
            return Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?);
        }
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, kind, entity_type, entity_id, actor, receipt_id, created_at
             FROM sync_changes
             WHERE id > ?1
             ORDER BY id ASC
             LIMIT 500",
        )?;
        let rows = stmt.query_map(params![cursor], row_to_sync_change)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_all_sync_changes(&self) -> ApiResult<Vec<SyncChange>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workspace_id, kind, entity_type, entity_id, actor, receipt_id, created_at
             FROM sync_changes
             ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_sync_change)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_delta_sync_write(
        &self,
        file_id: &str,
        workspace_id: &str,
        actor_email: &str,
        base_revision: i64,
        new_revision: i64,
        chunk_size: usize,
        chunks_total: usize,
        chunks_reused: usize,
        uploaded_bytes: i64,
        reconstructed_bytes: i64,
        content_sha256: &str,
    ) -> ApiResult<DeltaWriteStats> {
        let stats = DeltaWriteStats {
            id: Uuid::now_v7().to_string(),
            file_id: file_id.to_string(),
            workspace_id: workspace_id.to_string(),
            actor_email: actor_email.to_string(),
            base_revision,
            new_revision,
            chunk_size,
            chunks_total,
            chunks_reused,
            uploaded_bytes,
            reconstructed_bytes,
            content_sha256: content_sha256.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        self.retain_delta_stats_best_effort(&stats);
        Ok(stats)
    }

    pub fn list_delta_sync_writes(&self) -> ApiResult<Vec<DeltaWriteStats>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, file_id, workspace_id, actor_email, base_revision, new_revision,
                    chunk_size, chunks_total, chunks_reused, uploaded_bytes,
                    reconstructed_bytes, content_sha256, created_at
             FROM delta_sync_writes
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_delta_write_stats)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn index_file_text(&self, file: &DriveFile, content_text: &str) -> ApiResult<bool> {
        self.index_file_text_with_limit(file, content_text, MAX_WORKSPACE_SEARCH_STORAGE_BYTES)
    }

    fn index_file_text_with_limit(
        &self,
        file: &DriveFile,
        content_text: &str,
        search_storage_limit: i64,
    ) -> ApiResult<bool> {
        if !matches!(file.kind, FileKind::File) || file.trashed || file.content_hash.is_none() {
            self.clear_file_text_index(file)?;
            return Ok(false);
        }
        let updated_at = Utc::now().to_rfc3339();
        let content_bytes = i64::try_from(content_text.len()).map_err(|_| {
            ApiError::PayloadTooLarge("search text exceeds the supported size".to_string())
        })?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_subject_exists: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM files
                 WHERE id = ?1 AND workspace_id = ?2 AND kind = 'file' AND trashed = 0
                   AND revision = ?3 AND content_hash IS ?4
             )",
            params![
                &file.id,
                &file.workspace_id,
                file.revision,
                &file.content_hash,
            ],
            |row| row.get(0),
        )?;
        if !current_subject_exists {
            tx.commit()?;
            return Ok(false);
        }
        let existing_bytes: i64 = tx
            .query_row(
                "SELECT COALESCE(length(CAST(content_text AS BLOB)), 0)
             FROM file_text_index
             WHERE file_id = ?1
               AND source_revision = ?2
               AND source_content_hash IS ?3",
                params![&file.id, file.revision, &file.content_hash],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let current_bytes: i64 = tx.query_row(
            "SELECT COALESCE(SUM(length(CAST(content_text AS BLOB))), 0)
             FROM file_text_index WHERE workspace_id = ?1",
            params![&file.workspace_id],
            |row| row.get(0),
        )?;
        // FTS stores another content projection. Charge two bytes of derived
        // budget for every byte in the canonical extracted-text row.
        let projected_storage = current_bytes
            .saturating_sub(existing_bytes)
            .saturating_add(content_bytes)
            .saturating_mul(2);
        if projected_storage > search_storage_limit {
            tx.execute(
                "DELETE FROM file_text_index
                 WHERE file_id = ?1
                   AND source_revision = ?2
                   AND source_content_hash IS ?3",
                params![&file.id, file.revision, &file.content_hash],
            )?;
            refresh_file_search_index_locked(&tx, &file.id)?;
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO file_text_index (
                 file_id, workspace_id, source_revision, source_content_hash, content_text, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(file_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                source_revision = excluded.source_revision,
                source_content_hash = excluded.source_content_hash,
                content_text = excluded.content_text,
                updated_at = excluded.updated_at",
            params![
                &file.id,
                &file.workspace_id,
                file.revision,
                &file.content_hash,
                content_text,
                updated_at,
            ],
        )?;
        refresh_file_search_index_locked(&tx, &file.id)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn index_file_bytes(&self, file: &DriveFile, bytes: &[u8]) -> ApiResult<bool> {
        if bytes.len() as u64 > MAX_DERIVED_INPUT_BYTES {
            self.clear_file_text_index(file)?;
            return Ok(false);
        }
        let Some(content_text) = extract_search_text(&file.name, bytes)
            .map_err(|error| ApiError::Validation(format!("search extraction failed: {error}")))?
        else {
            self.clear_file_text_index(file)?;
            return Ok(false);
        };
        self.index_file_text(file, &content_text)
    }

    pub fn clear_file_text_index(&self, file: &DriveFile) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM file_text_index
             WHERE file_id = ?1
               AND source_revision = ?2
               AND source_content_hash IS ?3",
            params![&file.id, file.revision, &file.content_hash],
        )?;
        refresh_file_search_index_locked(&tx, &file.id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn enqueue_file_background_jobs(&self, file: &DriveFile) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _ = background_jobs::enqueue_file_background_jobs_in_tx(&tx, file)?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn enqueue_background_job(
        &self,
        kind: &str,
        workspace_id: &str,
        file_id: &str,
    ) -> ApiResult<()> {
        let file = self
            .get_file_unaggregated(file_id)?
            .ok_or(ApiError::NotFound)?;
        if file.workspace_id != workspace_id {
            return Err(ApiError::NotFound);
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _ = background_jobs::enqueue_background_job_in_tx(&tx, &file, kind)?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_background_jobs(&self) -> ApiResult<Vec<BackgroundJob>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, kind, status, workspace_id, file_id, attempts, last_error, created_at, updated_at, started_at, finished_at
             FROM background_jobs ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![BACKGROUND_JOB_LIST_LIMIT], row_to_background_job)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn queued_background_jobs(&self) -> ApiResult<Vec<BackgroundJob>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "WITH ranked_jobs AS (
                SELECT id, kind, status, workspace_id, file_id, attempts, last_error,
                       created_at, updated_at, started_at, finished_at,
                       ROW_NUMBER() OVER (
                           PARTITION BY COALESCE(workspace_id, '')
                           ORDER BY created_at ASC, id ASC
                       ) AS workspace_turn
                FROM background_jobs
                WHERE status = 'queued'
             )
             SELECT id, kind, status, workspace_id, file_id, attempts, last_error,
                    created_at, updated_at, started_at, finished_at
             FROM ranked_jobs
             ORDER BY workspace_turn ASC, created_at ASC, id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![BACKGROUND_JOB_BATCH_LIMIT], row_to_background_job)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn background_job_totals(&self) -> ApiResult<BackgroundJobTotals> {
        let conn = self.conn.lock().unwrap();
        Ok(BackgroundJobTotals {
            queued: count_background_jobs_by_status(&conn, "queued")?,
            running: count_background_jobs_by_status(&conn, "running")?,
            succeeded: count_background_jobs_by_status(&conn, "succeeded")?,
            failed: count_background_jobs_by_status(&conn, "failed")?,
            skipped: count_background_jobs_by_status(&conn, "skipped")?,
        })
    }

    pub fn run_queued_background_jobs(
        &self,
        data_dir: &Path,
    ) -> ApiResult<BackgroundJobRunResponse> {
        let queued = self.queued_background_jobs()?;
        let mut response = BackgroundJobRunResponse {
            processed: 0,
            succeeded: 0,
            failed: 0,
            skipped: 0,
            jobs: Vec::new(),
        };

        for job in queued {
            if !self.mark_background_job_running(&job.id)? {
                continue;
            }
            response.processed += 1;
            let (status, message) = match self.process_background_job(data_dir, &job) {
                Ok(outcome) => outcome,
                Err(error) => ("failed", Some(error)),
            };
            match status {
                "succeeded" => response.succeeded += 1,
                "skipped" => response.skipped += 1,
                _ => response.failed += 1,
            }
            self.finish_background_job(&job.id, status, message.as_deref())?;
        }

        response.jobs = self.list_background_jobs()?;
        Ok(response)
    }

    fn mark_background_job_running(&self, job_id: &str) -> ApiResult<bool> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE background_jobs
             SET status = 'running',
                 attempts = attempts + 1,
                 last_error = NULL,
                 started_at = ?1,
                 finished_at = NULL,
                 updated_at = ?1
             WHERE id = ?2 AND status = 'queued'",
            params![now, job_id],
        )?;
        Ok(updated == 1)
    }

    fn finish_background_job(
        &self,
        job_id: &str,
        status: &str,
        message: Option<&str>,
    ) -> ApiResult<()> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE background_jobs
             SET status = ?1,
                 last_error = ?2,
                 finished_at = ?3,
                 updated_at = ?3
             WHERE id = ?4",
            params![status, message, now, job_id],
        )?;
        background_jobs::prune_terminal_background_jobs(&tx)?;
        tx.commit()?;
        Ok(())
    }

    fn process_background_job(
        &self,
        data_dir: &Path,
        job: &BackgroundJob,
    ) -> Result<(&'static str, Option<String>), String> {
        let file_id = job
            .file_id
            .as_deref()
            .ok_or_else(|| "background job has no file id".to_string())?;
        let file = self
            .get_file(file_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "file no longer exists".to_string())?;
        if file.trashed {
            return Ok(("skipped", Some("file is trashed".to_string())));
        }
        if !matches!(file.kind, FileKind::File) {
            return Ok(("skipped", Some("file is not a regular file".to_string())));
        }
        let Some(content_hash) = file.content_hash.as_deref() else {
            if job.kind == "preview_text" {
                self.clear_stale_file_preview(data_dir, &file.id, file.revision)
                    .map_err(|error| error.to_string())?;
            }
            return Ok((
                "skipped",
                Some("file has no server-readable content".to_string()),
            ));
        };
        let Some(bytes) = blob::get_blob_limited(data_dir, content_hash, MAX_DERIVED_INPUT_BYTES)
            .map_err(|error| error.to_string())?
        else {
            if job.kind == "search_index" {
                self.clear_file_text_index(&file)
                    .map_err(|error| error.to_string())?;
            } else if job.kind == "preview_text" {
                self.clear_stale_file_preview(data_dir, &file.id, file.revision)
                    .map_err(|error| error.to_string())?;
            }
            return Ok((
                "skipped",
                Some(format!(
                    "file exceeds {} MiB derived-data processing limit",
                    MAX_DERIVED_INPUT_BYTES / (1024 * 1024)
                )),
            ));
        };

        match job.kind.as_str() {
            "search_index" => match extract_search_text(&file.name, &bytes) {
                Ok(Some(content)) if !content.trim().is_empty() => {
                    self.index_file_text(&file, &content)
                        .map_err(|error| error.to_string())?;
                    Ok(("succeeded", None))
                }
                Ok(_) => {
                    self.clear_file_text_index(&file)
                        .map_err(|error| error.to_string())?;
                    Ok(("skipped", Some("no extractable text".to_string())))
                }
                Err(error) => Err(error),
            },
            "preview_text" => {
                let blob_lifecycle_lock = blob::BlobLifecycleLock::acquire_shared(data_dir)
                    .map_err(|error| error.to_string())?;
                let preview = generate_file_preview(data_dir, &file, &bytes)?;
                let new_publication = preview.thumbnail_publication.clone();
                let upsert = self.upsert_file_preview(&file, preview);
                drop(blob_lifecycle_lock);
                let previous_hash = match upsert {
                    Ok(previous_hash) => previous_hash,
                    Err(error) => {
                        if let Some(publication) = new_publication.filter(|item| item.created) {
                            if let Err(cleanup_error) = self.cleanup_unreferenced_preview_hashes(
                                data_dir,
                                vec![publication.hash],
                            ) {
                                tracing::error!(%cleanup_error, "failed to compensate rejected preview publication");
                            }
                        }
                        return Err(error.to_string());
                    }
                };
                if let Some(previous_hash) = previous_hash.filter(|previous| {
                    new_publication
                        .as_ref()
                        .is_none_or(|current| current.hash != *previous)
                }) {
                    if let Err(error) =
                        self.cleanup_unreferenced_preview_hashes(data_dir, vec![previous_hash])
                    {
                        tracing::error!(%error, "failed to prune replaced preview blob");
                    }
                }
                Ok(("succeeded", None))
            }
            _ => Err(format!("unsupported background job kind: {}", job.kind)),
        }
    }

    fn upsert_file_preview(
        &self,
        file: &DriveFile,
        preview: GeneratedPreview,
    ) -> ApiResult<Option<String>> {
        let updated_at = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_revision = tx
            .query_row(
                "SELECT revision FROM files WHERE id = ?1",
                params![&file.id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if current_revision != file.revision {
            return Err(ApiError::Conflict);
        }
        let previous_hash = tx
            .query_row(
                "SELECT thumbnail_hash FROM file_previews WHERE file_id = ?1",
                params![&file.id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        let existing_thumbnail_bytes: i64 = tx
            .query_row(
                "SELECT thumbnail_bytes FROM file_previews WHERE file_id = ?1",
                params![&file.id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let current_thumbnail_bytes: i64 = tx.query_row(
            "SELECT COALESCE(SUM(thumbnail_bytes), 0)
             FROM file_previews WHERE workspace_id = ?1",
            params![&file.workspace_id],
            |row| row.get(0),
        )?;
        let projected_thumbnail_bytes = current_thumbnail_bytes
            .saturating_sub(existing_thumbnail_bytes)
            .saturating_add(preview.thumbnail_bytes);
        if projected_thumbnail_bytes > MAX_WORKSPACE_THUMBNAIL_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "workspace thumbnails exceed the {MAX_WORKSPACE_THUMBNAIL_BYTES}-byte derived-data budget"
            )));
        }
        tx.execute(
            "INSERT INTO file_previews (
                file_id, workspace_id, revision, kind, content,
                thumbnail_hash, thumbnail_content_type, thumbnail_bytes,
                width, height, status, updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(file_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                revision = excluded.revision,
                kind = excluded.kind,
                content = excluded.content,
                thumbnail_hash = excluded.thumbnail_hash,
                thumbnail_content_type = excluded.thumbnail_content_type,
                thumbnail_bytes = excluded.thumbnail_bytes,
                width = excluded.width,
                height = excluded.height,
                status = excluded.status,
                updated_at = excluded.updated_at",
            params![
                file.id,
                file.workspace_id,
                file.revision,
                preview.kind,
                preview.content,
                preview.thumbnail_hash,
                preview.thumbnail_content_type,
                preview.thumbnail_bytes,
                preview.width,
                preview.height,
                preview.status,
                updated_at
            ],
        )?;
        tx.commit()?;
        Ok(previous_hash)
    }

    fn cleanup_unreferenced_preview_hashes(
        &self,
        data_dir: &Path,
        hashes: Vec<String>,
    ) -> ApiResult<()> {
        let _exclusive = blob::BlobLifecycleLock::acquire_exclusive(data_dir)?;
        for hash in hashes
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
        {
            if !self.content_hash_is_referenced(&hash)? {
                blob::remove_blob(data_dir, &hash)?;
            }
        }
        Ok(())
    }

    fn clear_stale_file_preview(
        &self,
        data_dir: &Path,
        file_id: &str,
        current_revision: i64,
    ) -> ApiResult<()> {
        let previous_hash = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let previous_hash = tx
                .query_row(
                    "SELECT thumbnail_hash
                     FROM file_previews
                     WHERE file_id = ?1 AND revision <> ?2",
                    params![file_id, current_revision],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten();
            if previous_hash.is_some() {
                tx.execute(
                    "DELETE FROM file_previews WHERE file_id = ?1 AND revision <> ?2",
                    params![file_id, current_revision],
                )?;
            }
            tx.commit()?;
            previous_hash
        };
        if let Some(previous_hash) = previous_hash {
            self.cleanup_unreferenced_preview_hashes(data_dir, vec![previous_hash])?;
        }
        Ok(())
    }

    pub fn get_file_preview(&self, file_id: &str) -> ApiResult<Option<FilePreview>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT previews.file_id, previews.workspace_id, previews.revision,
                        previews.kind, previews.content, previews.thumbnail_hash,
                        previews.thumbnail_content_type, previews.width, previews.height,
                        previews.status, previews.updated_at
                 FROM file_previews previews
                 JOIN files ON files.id = previews.file_id
                 WHERE previews.file_id = ?1 AND previews.revision = files.revision",
                params![file_id],
                row_to_file_preview,
            )
            .optional()?)
    }

    pub fn list_file_previews(&self) -> ApiResult<Vec<FilePreview>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT file_id, workspace_id, revision, kind, content,
                    thumbnail_hash, thumbnail_content_type, width, height, status, updated_at
             FROM file_previews ORDER BY updated_at DESC, file_id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_file_preview)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn search_query_plan(&self, query: &str) -> ApiResult<Vec<String>> {
        let Some(fts_query) = normalize_fts_query(query)? else {
            return Ok(vec!["empty search query".to_string()]);
        };
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "EXPLAIN QUERY PLAN
             SELECT files.id
             FROM files
             JOIN file_search_fts ON file_search_fts.file_id = files.id
             WHERE files.trashed = 0 AND file_search_fts MATCH ?1
             ORDER BY bm25(file_search_fts)",
        )?;
        let rows = stmt.query_map(params![fts_query], |row| {
            Ok(format!(
                "{}|{}|{}|{}",
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn admin_totals(&self) -> ApiResult<AdminTotals> {
        let conn = self.conn.lock().unwrap();
        Ok(AdminTotals {
            workspaces: count_table(&conn, "workspaces")?,
            users: count_table(&conn, "users")?,
            members: count_table(&conn, "workspace_members")?,
            files: count_files_by_kind(&conn, "file")?,
            folders: count_files_by_kind(&conn, "folder")?,
            trashed_files: count_trashed_files(&conn)?,
            shares: count_table(&conn, "shares")?,
            drops: count_table(&conn, "drops")?,
            comments: count_table(&conn, "comments")?,
            folder_templates: count_table(&conn, "folder_templates")?,
            receipts: count_table(&conn, "receipts")?,
            activity: count_table(&conn, "activity")?,
        })
    }
}

pub(super) fn new_receipt(kind: &str, actor: &str, target_id: Option<&str>) -> Receipt {
    Receipt {
        id: Uuid::now_v7().to_string(),
        kind: kind.to_string(),
        actor: actor.to_string(),
        target_id: target_id.map(str::to_string),
        created_at: Utc::now().to_rfc3339(),
    }
}

pub(super) fn insert_receipt_rows(conn: &Connection, receipt: &Receipt) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO receipts (id, kind, actor, target_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &receipt.id,
            &receipt.kind,
            &receipt.actor,
            &receipt.target_id,
            &receipt.created_at
        ],
    )?;
    conn.execute(
        "INSERT INTO activity (id, kind, actor, target_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            Uuid::now_v7().to_string(),
            &receipt.kind,
            &receipt.actor,
            &receipt.target_id,
            &receipt.created_at
        ],
    )?;
    record_sync_change_for_receipt(conn, receipt)
}

fn subtree_contains_live_file_in_tx(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
) -> ApiResult<bool> {
    let ids = recursive_file_ids_in_tx(tx, &[root_id.to_string()])?;
    if ids.is_empty() {
        return Ok(false);
    }
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let count: i64 = tx.query_row(
        &format!("SELECT COUNT(*) FROM files WHERE id IN ({placeholders}) AND trashed = 0"),
        params_from_iter(ids.iter()),
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn delete_file_roots_in_tx(
    tx: &rusqlite::Transaction<'_>,
    roots: &[String],
) -> ApiResult<(usize, Vec<String>)> {
    let ids = recursive_file_ids_in_tx(tx, roots)?;
    if ids.is_empty() {
        return Ok((0, Vec::new()));
    }
    let hashes = Storage::collect_blob_hashes_for_file_ids(tx, &ids)?;
    let placeholders = std::iter::repeat_n("?", ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    for table_and_column in [
        ("file_search_fts", "file_id"),
        ("file_previews", "file_id"),
        ("file_metadata", "file_id"),
        ("file_revisions", "file_id"),
        ("files", "id"),
    ] {
        tx.execute(
            &format!(
                "DELETE FROM {} WHERE {} IN ({placeholders})",
                table_and_column.0, table_and_column.1
            ),
            params_from_iter(ids.iter()),
        )?;
    }
    Ok((ids.len(), hashes))
}

fn validate_parent_chain_in_connection(
    conn: &Connection,
    workspace_id: &str,
    parent_id: &str,
    forbidden_file_id: Option<&str>,
) -> ApiResult<usize> {
    let mut next_id = Some(parent_id.to_string());
    let mut visited = HashSet::new();
    let mut depth = 0_usize;
    while let Some(id) = next_id {
        if forbidden_file_id == Some(id.as_str()) {
            return Err(ApiError::Validation(
                "folder cannot move or copy into its descendant".to_string(),
            ));
        }
        if !visited.insert(id.clone()) {
            return Err(ApiError::Validation(
                "file tree contains a parent cycle".to_string(),
            ));
        }
        let parent = conn
            .query_row(
                "SELECT workspace_id, parent_id, kind, trashed FROM files WHERE id = ?1",
                params![&id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if parent.0 != workspace_id || parent.3 != 0 {
            return Err(ApiError::Validation(
                "parent must be an active folder in the same workspace".to_string(),
            ));
        }
        if parent.2 != "folder" {
            return Err(ApiError::Validation("parent must be a folder".to_string()));
        }
        depth = depth
            .checked_add(1)
            .ok_or_else(|| ApiError::Validation("file tree depth overflow".to_string()))?;
        if depth > MAX_FILE_TREE_DEPTH {
            return Err(ApiError::Validation(format!(
                "file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
            )));
        }
        next_id = parent.1;
    }
    Ok(depth)
}

pub(super) fn validate_parent_chain_in_tx(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    parent_id: &str,
    forbidden_file_id: Option<&str>,
) -> ApiResult<usize> {
    let mut next_id = Some(parent_id.to_string());
    let mut visited = HashSet::new();
    let mut depth = 0_usize;
    while let Some(id) = next_id {
        if forbidden_file_id == Some(id.as_str()) {
            return Err(ApiError::Validation(
                "folder cannot move or copy into its descendant".to_string(),
            ));
        }
        if !visited.insert(id.clone()) {
            return Err(ApiError::Validation(
                "file tree contains a parent cycle".to_string(),
            ));
        }
        let parent = tx
            .query_row(
                "SELECT workspace_id, parent_id, kind, trashed FROM files WHERE id = ?1",
                params![&id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if parent.0 != workspace_id || parent.3 != 0 {
            return Err(ApiError::Validation(
                "parent must be an active folder in the same workspace".to_string(),
            ));
        }
        if parent.2 != "folder" {
            return Err(ApiError::Validation("parent must be a folder".to_string()));
        }
        depth = depth
            .checked_add(1)
            .ok_or_else(|| ApiError::Validation("file tree depth overflow".to_string()))?;
        if depth > MAX_FILE_TREE_DEPTH {
            return Err(ApiError::Validation(format!(
                "file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
            )));
        }
        next_id = parent.1;
    }
    Ok(depth)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupV2TableHeader {
    columns: Vec<String>,
}

fn read_backup_v2_line<R: BufRead>(reader: &mut R, max_bytes: u64) -> ApiResult<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(ApiError::Validation(
                "backup v2 JSONL line is not newline terminated".to_string(),
            ));
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        let next_len = (line.len() as u64)
            .checked_add(consumed as u64)
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("backup v2 JSONL line overflow".to_string())
            })?;
        if next_len > max_bytes {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup v2 JSONL line exceeds {max_bytes} bytes"
            )));
        }
        line.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            line.pop();
            return Ok(Some(line));
        }
    }
}

fn table_columns(conn: &rusqlite::Connection, table: &str) -> ApiResult<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", quote_identifier(table)))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn table_primary_key_columns(conn: &rusqlite::Connection, table: &str) -> ApiResult<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", quote_identifier(table)))?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(5)?, row.get::<_, String>(1)?))
    })?;
    let mut columns = rows
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|(position, _)| *position > 0)
        .collect::<Vec<_>>();
    columns.sort_by_key(|(position, _)| *position);
    Ok(columns.into_iter().map(|(_, column)| column).collect())
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn sql_value_to_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => json!(value),
        ValueRef::Real(value) => json!(value),
        ValueRef::Text(value) => json!(String::from_utf8_lossy(value).to_string()),
        ValueRef::Blob(value) => json!({
            "__blob_base64": base64_encode(value),
        }),
    }
}

fn json_to_sql_value(value: &Value) -> ApiResult<SqlValue> {
    Ok(match value {
        Value::Null => SqlValue::Null,
        Value::Bool(value) => SqlValue::Integer(i64::from(*value)),
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                SqlValue::Integer(integer)
            } else if let Some(float) = value.as_f64() {
                SqlValue::Real(float)
            } else {
                return Err(ApiError::Validation(
                    "backup row contains unsupported number".to_string(),
                ));
            }
        }
        Value::String(value) => SqlValue::Text(value.clone()),
        Value::Array(_) => {
            return Err(ApiError::Validation(
                "backup row contains unsupported array value".to_string(),
            ));
        }
        Value::Object(value) => {
            let Some(encoded) = value.get("__blob_base64").and_then(Value::as_str) else {
                return Err(ApiError::Validation(
                    "backup row contains unsupported object value".to_string(),
                ));
            };
            SqlValue::Blob(base64_decode(encoded)?)
        }
    })
}

fn base64_encode(value: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(value)
}

fn base64_decode(value: &str) -> ApiResult<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD
        .decode(value)
        .map_err(|error| ApiError::Validation(format!("invalid backup blob value: {error}")))
}

fn retention_totals(
    trash: &[RetentionTrashCandidate],
    revisions: &[RetentionRevisionCandidate],
) -> RetentionTotals {
    RetentionTotals {
        trashed_files: trash.len(),
        revisions: revisions.len(),
        content_bytes: trash
            .iter()
            .map(|file| file.content_bytes)
            .chain(revisions.iter().map(|revision| revision.content_bytes))
            .sum(),
    }
}

fn retention_timestamp_due(
    value: &str,
    cutoff: &DateTime<Utc>,
    retention_days: i64,
) -> ApiResult<bool> {
    let timestamp = DateTime::parse_from_rfc3339(value)
        .map_err(|error| ApiError::Validation(format!("invalid retention timestamp: {error}")))?
        .with_timezone(&Utc);
    if retention_days == 0 {
        return Ok(true);
    }
    Ok(timestamp <= *cutoff)
}

fn invalidate_password_reset_tokens_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    invalidated_at: &str,
) -> ApiResult<()> {
    tx.execute(
        "UPDATE password_reset_tokens
         SET used_at = COALESCE(used_at, ?2)
         WHERE email = ?1 AND used_at IS NULL",
        params![email, invalidated_at],
    )?;
    Ok(())
}

fn revoke_derived_actor_credentials_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    revoked_at: &str,
) -> ApiResult<()> {
    auth_security::revoke_actor_credentials_in_tx(tx, email, revoked_at)
}

/// Folder covers reference existing workspace blobs. A copy keeps that
/// reference and its accounted byte length; no new blob is materialized.
fn copy_cover_reference_in_tx(
    tx: &rusqlite::Transaction<'_>,
    file_id: &str,
) -> ApiResult<(Option<String>, i64)> {
    let (cover_hash, cover_bytes) = tx.query_row(
        "SELECT cover_hash, cover_bytes FROM files WHERE id = ?1",
        params![file_id],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    if cover_hash.is_none() && cover_bytes != 0 {
        return Err(ApiError::Validation(
            "folder cover metadata has bytes without a cover hash".to_string(),
        ));
    }
    if cover_bytes < 0 {
        return Err(ApiError::Validation(
            "folder cover metadata has a negative byte count".to_string(),
        ));
    }
    Ok((cover_hash, cover_bytes))
}

pub(super) fn row_to_file(row: &Row<'_>) -> rusqlite::Result<DriveFile> {
    let kind_str: String = row.get(4)?;
    let trashed: i64 = row.get(6)?;
    let starred: i64 = row.get(7)?;
    let kind = FileKind::from_db_str(&kind_str);
    // Column 11 is the appended `content_bytes` (stored byte length of the
    // current revision). Files expose it as `size_bytes`; folders always carry
    // `content_bytes = 0` in the schema, so they report `None` instead of 0 B.
    let content_bytes: i64 = row.get(11)?;
    let size_bytes = matches!(kind, FileKind::File).then_some(content_bytes);
    // Column 12 is the appended `cover_hash` (a folder's custom cover image
    // blob, NULL for files and uncovered folders). Only its presence is exposed
    // to clients — the raw hash stays server-side.
    let cover_hash: Option<String> = row.get(12)?;
    Ok(DriveFile {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        parent_id: row.get(2)?,
        name: row.get(3)?,
        kind,
        revision: row.get(5)?,
        trashed: trashed != 0,
        starred: starred != 0,
        content_hash: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        size_bytes,
        folder_size_bytes: None,
        has_cover: cover_hash.is_some(),
    })
}

fn row_to_workspace_policy(row: &Row<'_>) -> rusqlite::Result<WorkspacePolicy> {
    let public_links_enabled: i64 = row.get(2)?;
    let link_password_required: i64 = row.get(3)?;
    let allow_never_expire: i64 = row.get(4)?;
    let drop_password_required: i64 = row.get(6)?;
    Ok(WorkspacePolicy {
        workspace_id: row.get(0)?,
        quota_bytes: row.get(1)?,
        public_links_enabled: public_links_enabled != 0,
        link_password_required: link_password_required != 0,
        allow_never_expire: allow_never_expire != 0,
        max_link_ttl_seconds: row.get(5)?,
        drop_password_required: drop_password_required != 0,
        max_drop_ttl_seconds: row.get(7)?,
        trash_retention_days: row.get(8)?,
        revision_retention_days: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn workspace_policy_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
) -> ApiResult<WorkspacePolicy> {
    let policy = tx
        .query_row(
            "SELECT workspace_id, quota_bytes, public_links_enabled,
                    link_password_required, allow_never_expire,
                    max_link_ttl_seconds,
                    drop_password_required, max_drop_ttl_seconds,
                    trash_retention_days, revision_retention_days, updated_at
             FROM workspace_policies WHERE workspace_id = ?1",
            params![workspace_id],
            row_to_workspace_policy,
        )
        .optional()?;
    Ok(policy.unwrap_or_else(|| default_workspace_policy(workspace_id)))
}

fn row_to_backup_policy(row: &Row<'_>) -> rusqlite::Result<BackupPolicy> {
    Ok(BackupPolicy {
        enabled: row.get::<_, i64>(0)? != 0,
        schedule: row.get(1)?,
        retention_count: row.get(2)?,
        updated_at: row.get(3)?,
    })
}

fn row_to_support_bundle_metadata(row: &Row<'_>) -> rusqlite::Result<SupportBundleMetadata> {
    Ok(SupportBundleMetadata {
        id: row.get(0)?,
        receipt_id: row.get(1)?,
        generated_at: row.get(2)?,
        debug_export_bytes: row.get(3)?,
        logs_count: row.get(4)?,
    })
}

fn row_to_app_token(row: &Row<'_>) -> rusqlite::Result<AppToken> {
    let workspace_ids_json: String = row.get(3)?;
    let workspace_ids =
        serde_json::from_str::<Vec<String>>(&workspace_ids_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let revoked_at: Option<String> = row.get(6)?;
    Ok(AppToken {
        id: row.get(0)?,
        label: row.get(1)?,
        actor_email: row.get(2)?,
        workspace_ids,
        expires_at: row.get(4)?,
        last_used_at: row.get(5)?,
        revoked: revoked_at.is_some(),
        revoked_at,
        created_at: row.get(7)?,
    })
}

fn row_to_auth_attempt(row: &Row<'_>) -> rusqlite::Result<AuthAttemptDebug> {
    Ok(AuthAttemptDebug {
        key: row.get(0)?,
        actor_email: row.get(1)?,
        client_fingerprint: row.get(2)?,
        scope: row.get(3)?,
        failures: row.get(4)?,
        locked_until: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn row_to_email_outbox_item(row: &Row<'_>) -> rusqlite::Result<EmailOutboxItem> {
    Ok(EmailOutboxItem {
        id: row.get(0)?,
        kind: row.get(1)?,
        status: row.get(2)?,
        recipient_email: row.get(3)?,
        subject: row.get(4)?,
        related_type: row.get(5)?,
        related_id: row.get(6)?,
        attempts: row.get(7)?,
        last_error: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        sent_at: row.get(11)?,
    })
}

fn row_to_auth_account(row: &Row<'_>) -> rusqlite::Result<AuthAccount> {
    let recovery_code_hashes: String = row.get(4)?;
    let hashes = parse_recovery_hashes(&recovery_code_hashes);
    let disabled_at: Option<String> = row.get(5)?;
    Ok(AuthAccount {
        user_id: row.get(0)?,
        email: row.get(1)?,
        is_admin: row.get::<_, i64>(2)? != 0,
        totp_enabled: row.get::<_, i64>(3)? != 0,
        recovery_codes_remaining: hashes.len(),
        disabled: disabled_at.is_some(),
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn row_to_auth_account_secret(row: &Row<'_>) -> rusqlite::Result<AuthAccountSecret> {
    let recovery_code_hashes: String = row.get(6)?;
    Ok(AuthAccountSecret {
        user_id: row.get(0)?,
        email: row.get(1)?,
        password_hash: row.get(2)?,
        is_admin: row.get::<_, i64>(3)? != 0,
        totp_secret: row.get(4)?,
        totp_enabled: row.get::<_, i64>(5)? != 0,
        recovery_code_hashes: parse_recovery_hashes(&recovery_code_hashes),
        disabled_at: row.get(7)?,
        security_version: row.get(8)?,
    })
}

fn parse_recovery_hashes(encoded: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(encoded).unwrap_or_default()
}

fn auth_attempt_key(
    actor_email: Option<&str>,
    scope: &str,
    client_fingerprint: Option<&str>,
) -> String {
    format!(
        "{}:{}:{}",
        scope.trim().to_ascii_lowercase(),
        actor_email
            .map(|email| email.trim().to_ascii_lowercase())
            .filter(|email| !email.is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        client_fingerprint
            .map(str::trim)
            .filter(|fingerprint| !fingerprint.is_empty())
            .unwrap_or("global")
    )
}

fn prune_auth_attempts_locked(conn: &rusqlite::Connection, now: &str) -> ApiResult<()> {
    conn.execute(
        "DELETE FROM auth_attempts
         WHERE julianday(updated_at) < julianday(?1, '-30 days')
           AND (locked_until IS NULL OR julianday(locked_until) <= julianday(?1))",
        params![now],
    )?;
    Ok(())
}

fn enforce_auth_attempt_row_cap_locked(conn: &rusqlite::Connection) -> ApiResult<()> {
    conn.execute(
        "DELETE FROM auth_attempts
         WHERE key IN (
             SELECT key FROM auth_attempts
             ORDER BY updated_at DESC, key ASC
             LIMIT -1 OFFSET ?1
         )",
        [i64::try_from(MAX_AUTH_ATTEMPT_ROWS).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

fn default_workspace_policy(workspace_id: &str) -> WorkspacePolicy {
    WorkspacePolicy {
        workspace_id: workspace_id.to_string(),
        quota_bytes: None,
        public_links_enabled: true,
        // Passwordless share links are allowed by default so the web UI's
        // one-click "Create link" (which posts an empty password) succeeds,
        // matching Google-Drive-style sharing. A workspace admin can turn the
        // requirement back ON via PATCH /workspaces/{id}/policy. Note: an
        // unconfigured workspace resolves its policy through this fallback
        // (there is no stored row), so this default applies to every workspace
        // that has never explicitly saved a link-password policy.
        link_password_required: false,
        allow_never_expire: false,
        max_link_ttl_seconds: 2_592_000,
        drop_password_required: true,
        max_drop_ttl_seconds: 2_592_000,
        trash_retention_days: 30,
        revision_retention_days: 90,
        updated_at: Utc::now().to_rfc3339(),
    }
}

fn default_backup_policy() -> BackupPolicy {
    BackupPolicy {
        enabled: false,
        schedule: "manual".to_string(),
        retention_count: 7,
        updated_at: Utc::now().to_rfc3339(),
    }
}

fn default_sandbox_profile() -> SandboxProfile {
    SandboxProfile {
        id: "default".to_string(),
        name: "Default ShellX Drive sandbox".to_string(),
        mode: "strict".to_string(),
        data_dir: "/var/lib/shellx-drive".to_string(),
        bind: "127.0.0.1:5758".to_string(),
        service_user: "shellx-drive".to_string(),
        service_group: "shellx-drive".to_string(),
        read_write_paths: vec!["/var/lib/shellx-drive".to_string()],
        read_only_paths: Vec::new(),
        network_policy: "loopback_default".to_string(),
        status: "preview".to_string(),
        last_checked_at: None,
    }
}

fn bool_to_i64(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn validate_non_negative_i64(value: i64, field: &str) -> ApiResult<i64> {
    if value < 0 {
        return Err(ApiError::Validation(format!(
            "{field} must not be negative"
        )));
    }
    Ok(value)
}

fn checked_stale_upload_cutoff(older_than_seconds: i64) -> ApiResult<String> {
    let duration = Duration::try_seconds(older_than_seconds.max(0)).ok_or_else(|| {
        ApiError::Validation("upload cleanup age exceeds the supported date range".to_string())
    })?;
    Utc::now()
        .checked_sub_signed(duration)
        .filter(|cutoff| (1..=9999).contains(&cutoff.year()))
        .map(|cutoff| cutoff.to_rfc3339())
        .ok_or_else(|| {
            ApiError::Validation("upload cleanup age exceeds the supported date range".to_string())
        })
}

fn ensure_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> rusqlite::Result<()> {
    let table = quote_identifier(table);
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(());
        }
    }
    conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {definition}"), [])?;
    Ok(())
}

/// Relax `shares.expires_at` from `NOT NULL` to nullable so a share can store
/// `NULL` = never expires. SQLite cannot drop a `NOT NULL` constraint in place,
/// so when a legacy DB still has the constraint we rebuild the table.
///
/// Safe to run every boot: it is a no-op once the column is already nullable
/// (fresh DBs create it that way). `share_access_grants` references `shares`,
/// so the migration rebuilds that dependent table too. This avoids SQLite's
/// `DROP TABLE shares` cascade deleting issued capability grants. The rebuild
/// runs in one transaction so an interrupted migration rolls back rather than
/// leaving a half-built table.
fn migrate_shares_expires_at_nullable(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mut expires_at_not_null = false;
    {
        let mut stmt = conn.prepare("PRAGMA table_info(shares)")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            let not_null: i64 = row.get(3)?;
            if name == "expires_at" && not_null != 0 {
                expires_at_not_null = true;
            }
        }
    }
    if !expires_at_not_null {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        r#"
        ALTER TABLE share_access_grants RENAME TO share_access_grants_migrate_old;
        ALTER TABLE shares RENAME TO shares_migrate_old;

        CREATE TABLE shares (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            password_required INTEGER NOT NULL DEFAULT 1,
            expires_at TEXT,
            expires_in_seconds INTEGER,
            revoked INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            access_count INTEGER NOT NULL DEFAULT 0,
            last_accessed_at TEXT,
            target_kind TEXT NOT NULL DEFAULT 'file',
            allow_download INTEGER NOT NULL DEFAULT 1,
            recipient_note TEXT,
            max_uses INTEGER,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        INSERT INTO shares
            (id, file_id, password_hash, password_required, expires_at, expires_in_seconds,
             revoked, created_at, access_count, last_accessed_at, target_kind,
             allow_download, recipient_note, max_uses)
            SELECT id, file_id, password_hash, password_required, expires_at, expires_in_seconds,
                   revoked, created_at, access_count, last_accessed_at, target_kind,
                   allow_download, recipient_note, max_uses
            FROM shares_migrate_old;

        CREATE TABLE share_access_grants_migrate_new (
            token_hash TEXT PRIMARY KEY,
            share_id TEXT NOT NULL,
            authorization_fingerprint TEXT,
            client_fingerprint TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (share_id) REFERENCES shares(id) ON DELETE CASCADE
        );
        INSERT INTO share_access_grants_migrate_new
            (token_hash, share_id, authorization_fingerprint, client_fingerprint, expires_at, created_at)
            SELECT token_hash, share_id, authorization_fingerprint, client_fingerprint, expires_at, created_at
            FROM share_access_grants_migrate_old;
        DROP TABLE share_access_grants_migrate_old;
        DROP TABLE shares_migrate_old;
        ALTER TABLE share_access_grants_migrate_new RENAME TO share_access_grants;
        CREATE INDEX idx_share_access_grants_share_expiry
            ON share_access_grants(share_id, expires_at);
        "#,
    )?;
    tx.commit()?;
    Ok(())
}

fn row_to_background_job(row: &Row<'_>) -> rusqlite::Result<BackgroundJob> {
    Ok(BackgroundJob {
        id: row.get(0)?,
        kind: row.get(1)?,
        status: row.get(2)?,
        workspace_id: row.get(3)?,
        file_id: row.get(4)?,
        attempts: row.get(5)?,
        last_error: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
        started_at: row.get(9)?,
        finished_at: row.get(10)?,
    })
}

fn row_to_backup_job(row: &Row<'_>) -> rusqlite::Result<BackupJob> {
    Ok(BackupJob {
        id: row.get(0)?,
        backup_id: row.get(1)?,
        kind: row.get(2)?,
        format: row.get(3)?,
        status: row.get(4)?,
        phase: row.get(5)?,
        actor: row.get(6)?,
        archive_sha256: row.get(7)?,
        last_error: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        started_at: row.get(11)?,
        finished_at: row.get(12)?,
    })
}

fn query_backup_job(conn: &rusqlite::Connection, job_id: &str) -> ApiResult<Option<BackupJob>> {
    conn.query_row(
        "SELECT id, backup_id, kind, format, status, phase, actor,
                archive_sha256, last_error, created_at, updated_at,
                started_at, finished_at
         FROM backup_jobs WHERE id = ?1",
        params![job_id],
        row_to_backup_job,
    )
    .optional()
    .map_err(Into::into)
}

fn bounded_backup_job_error(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn row_to_file_preview(row: &Row<'_>) -> rusqlite::Result<FilePreview> {
    Ok(FilePreview {
        file_id: row.get(0)?,
        workspace_id: row.get(1)?,
        revision: row.get(2)?,
        kind: row.get(3)?,
        content: row.get(4)?,
        thumbnail_hash: row.get(5)?,
        thumbnail_content_type: row.get(6)?,
        width: row.get(7)?,
        height: row.get(8)?,
        status: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn refresh_file_search_index_locked(conn: &Connection, file_id: &str) -> ApiResult<()> {
    conn.execute(
        "DELETE FROM file_search_fts WHERE file_id = ?1",
        params![file_id],
    )?;
    let file = conn
        .query_row(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred, content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files WHERE id = ?1",
            params![file_id],
            row_to_file,
        )
        .optional()?;
    let Some(file) = file else {
        return Ok(());
    };
    let (labels, metadata) = conn
        .query_row(
            "SELECT labels_json, custom_json FROM file_metadata WHERE file_id = ?1",
            params![file_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .unwrap_or_else(|| ("[]".to_string(), "{}".to_string()));
    let metadata = auxiliary_storage::project_persisted_file_metadata_storage(&labels, &metadata)?;
    let content = conn
        .query_row(
            "SELECT content_text
             FROM file_text_index
             WHERE file_id = ?1
               AND workspace_id = ?2
               AND source_revision = ?3
               AND source_content_hash IS ?4",
            params![
                file_id,
                &file.workspace_id,
                file.revision,
                &file.content_hash,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_default();
    conn.execute(
        "INSERT INTO file_search_fts (file_id, workspace_id, name, labels, metadata, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            &file.id,
            &file.workspace_id,
            &file.name,
            metadata.labels_json,
            metadata.custom_json,
            content
        ],
    )?;
    Ok(())
}

const MAX_SEARCH_QUERY_BYTES: usize = 1_024;
const MAX_SEARCH_TERMS: usize = 16;
const MAX_SEARCH_TERM_BYTES: usize = 128;

fn normalize_fts_query(query: &str) -> ApiResult<Option<String>> {
    if query.len() > MAX_SEARCH_QUERY_BYTES {
        return Err(ApiError::Validation(format!(
            "search query exceeds the {MAX_SEARCH_QUERY_BYTES}-byte limit"
        )));
    }
    let terms = search_terms(query);
    if terms.is_empty() {
        return Ok(None);
    }
    if terms.len() > MAX_SEARCH_TERMS {
        return Err(ApiError::Validation(format!(
            "search query exceeds the {MAX_SEARCH_TERMS}-term limit"
        )));
    }
    if terms.iter().any(|term| term.len() > MAX_SEARCH_TERM_BYTES) {
        return Err(ApiError::Validation(format!(
            "search term exceeds the {MAX_SEARCH_TERM_BYTES}-byte limit"
        )));
    }
    Ok(Some(
        terms
            .into_iter()
            .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" "),
    ))
}

fn search_terms(query: &str) -> Vec<String> {
    query
        .split(|character: char| !character.is_alphanumeric())
        .filter_map(|term| {
            let term = term.trim().to_ascii_lowercase();
            (!term.is_empty()).then_some(term)
        })
        .collect()
}

fn row_to_sync_change(row: &Row<'_>) -> rusqlite::Result<SyncChange> {
    Ok(SyncChange {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        kind: row.get(2)?,
        entity_type: row.get(3)?,
        entity_id: row.get(4)?,
        actor: row.get(5)?,
        receipt_id: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn row_to_delta_write_stats(row: &Row<'_>) -> rusqlite::Result<DeltaWriteStats> {
    let chunk_size: i64 = row.get(6)?;
    let chunks_total: i64 = row.get(7)?;
    let chunks_reused: i64 = row.get(8)?;
    Ok(DeltaWriteStats {
        id: row.get(0)?,
        file_id: row.get(1)?,
        workspace_id: row.get(2)?,
        actor_email: row.get(3)?,
        base_revision: row.get(4)?,
        new_revision: row.get(5)?,
        chunk_size: chunk_size.max(0) as usize,
        chunks_total: chunks_total.max(0) as usize,
        chunks_reused: chunks_reused.max(0) as usize,
        uploaded_bytes: row.get(9)?,
        reconstructed_bytes: row.get(10)?,
        content_sha256: row.get(11)?,
        created_at: row.get(12)?,
    })
}

fn row_to_sync_conflict(row: &Row<'_>) -> rusqlite::Result<SyncConflict> {
    Ok(SyncConflict {
        workspace_id: row.get(0)?,
        file_id: row.get(1)?,
        conflict_of_file_id: row.get(2)?,
        name: row.get(3)?,
        conflict_of_revision: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn row_to_sandbox_profile(row: &Row<'_>) -> rusqlite::Result<SandboxProfile> {
    let read_write_paths_json: String = row.get(7)?;
    let read_only_paths_json: String = row.get(8)?;
    let read_write_paths = serde_json::from_str(&read_write_paths_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let read_only_paths = serde_json::from_str(&read_only_paths_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(SandboxProfile {
        id: row.get(0)?,
        name: row.get(1)?,
        mode: row.get(2)?,
        data_dir: row.get(3)?,
        bind: row.get(4)?,
        service_user: row.get(5)?,
        service_group: row.get(6)?,
        read_write_paths,
        read_only_paths,
        network_policy: row.get(9)?,
        status: row.get(10)?,
        last_checked_at: row.get(11)?,
    })
}

fn row_to_mobile_offline_file(row: &Row<'_>) -> rusqlite::Result<MobileOfflineFile> {
    Ok(MobileOfflineFile {
        actor_email: row.get(0)?,
        workspace_id: row.get(1)?,
        file_id: row.get(2)?,
        marked_at: row.get(3)?,
    })
}

fn row_to_notification(row: &Row<'_>) -> rusqlite::Result<Notification> {
    Ok(Notification {
        id: row.get(0)?,
        recipient_email: row.get(1)?,
        workspace_id: row.get(2)?,
        file_id: row.get(3)?,
        kind: row.get(4)?,
        title: row.get(5)?,
        body: row.get(6)?,
        related_type: row.get(7)?,
        related_id: row.get(8)?,
        read_at: row.get(9)?,
        created_at: row.get(10)?,
    })
}

fn row_to_office_edit_session(row: &Row<'_>) -> rusqlite::Result<DebugOfficeSession> {
    Ok(DebugOfficeSession {
        id: row.get(0)?,
        file_id: row.get(1)?,
        actor_email: row.get(2)?,
        base_revision: row.get(3)?,
        provider_name: row.get(4)?,
        expires_at: row.get(5)?,
        used_at: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn row_to_folder_template_base(row: &Row<'_>) -> rusqlite::Result<FolderTemplate> {
    Ok(FolderTemplate {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        name: row.get(2)?,
        description: row.get(3)?,
        created_by: row.get(4)?,
        created_at: row.get(5)?,
        items: Vec::new(),
    })
}

fn row_to_folder_template_item(row: &Row<'_>) -> rusqlite::Result<FolderTemplateItem> {
    let kind: String = row.get(3)?;
    Ok(FolderTemplateItem {
        id: row.get(0)?,
        template_id: row.get(1)?,
        path: row.get(2)?,
        kind: FileKind::from_db_str(&kind),
        content: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn count_table(conn: &rusqlite::Connection, table: &str) -> rusqlite::Result<i64> {
    let sql = match table {
        "workspaces" => "SELECT COUNT(*) FROM workspaces",
        "users" => "SELECT COUNT(*) FROM users",
        "workspace_members" => "SELECT COUNT(*) FROM workspace_members",
        "shares" => "SELECT COUNT(*) FROM shares",
        "drops" => "SELECT COUNT(*) FROM drops",
        "comments" => "SELECT COUNT(*) FROM comments",
        "folder_templates" => "SELECT COUNT(*) FROM folder_templates",
        "receipts" => "SELECT COUNT(*) FROM receipts",
        "activity" => "SELECT COUNT(*) FROM activity",
        _ => unreachable!("unsupported admin count table"),
    };
    conn.query_row(sql, [], |row| row.get(0))
}

fn count_files_by_kind(conn: &rusqlite::Connection, kind: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM files WHERE kind = ?1 AND trashed = 0",
        params![kind],
        |row| row.get(0),
    )
}

fn count_trashed_files(conn: &rusqlite::Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM files WHERE trashed = 1", [], |row| {
        row.get(0)
    })
}

fn count_background_jobs_by_status(
    conn: &rusqlite::Connection,
    status: &str,
) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM background_jobs WHERE status = ?1",
        params![status],
        |row| row.get(0),
    )
}

fn row_to_workspace(row: &Row<'_>) -> rusqlite::Result<Workspace> {
    let archived_at: Option<String> = row.get(5)?;
    Ok(Workspace {
        id: row.get(0)?,
        name: row.get(1)?,
        storage_mode: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        archived: archived_at.is_some(),
        archived_at,
        tenant_id: row.get(6)?,
        role: None,
    })
}

fn row_to_hosted_tenant(row: &Row<'_>) -> rusqlite::Result<HostedTenant> {
    Ok(HostedTenant {
        id: row.get(0)?,
        name: row.get(1)?,
        owner_email: row.get(2)?,
        plan: row.get(3)?,
        billing_status: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn row_to_workspace_invitation(row: &Row<'_>) -> rusqlite::Result<WorkspaceInvitation> {
    Ok(WorkspaceInvitation {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        email: row.get(2)?,
        role: row.get(3)?,
        status: row.get(4)?,
        invited_by: row.get(5)?,
        expires_at: row.get(6)?,
        accepted_at: row.get(7)?,
        canceled_at: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        member_expires_in_seconds: row.get(11)?,
    })
}

fn row_to_workspace_invitation_secret(
    row: &Row<'_>,
) -> rusqlite::Result<WorkspaceInvitationSecret> {
    Ok(WorkspaceInvitationSecret {
        invitation: WorkspaceInvitation {
            id: row.get(0)?,
            workspace_id: row.get(1)?,
            email: row.get(2)?,
            role: row.get(3)?,
            status: row.get(5)?,
            invited_by: row.get(6)?,
            expires_at: row.get(7)?,
            accepted_at: row.get(8)?,
            canceled_at: row.get(9)?,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
            member_expires_in_seconds: row.get(12)?,
        },
        token_hash: row.get(4)?,
    })
}

fn row_to_drop_record(row: &Row<'_>) -> rusqlite::Result<DropRecord> {
    let revoked: i64 = row.get(5)?;
    Ok(DropRecord {
        drop: DropLink {
            id: row.get(0)?,
            workspace_id: row.get(1)?,
            name: row.get(2)?,
            inbox_file_id: row.get(9)?,
            expires_at: row.get(4)?,
            revoked: revoked != 0,
            created_at: row.get(6)?,
            upload_count: row.get(7)?,
            last_uploaded_at: row.get(8)?,
        },
        password_hash: row.get(3)?,
        password_required: row.get::<_, i64>(10)? != 0,
    })
}

fn record_sync_change_for_receipt(conn: &Connection, receipt: &Receipt) -> rusqlite::Result<()> {
    let Some(target_id) = receipt.target_id.as_deref() else {
        return Ok(());
    };
    let Some((workspace_id, entity_type, entity_id)) =
        infer_sync_change_target(conn, &receipt.kind, target_id)?
    else {
        return Ok(());
    };
    conn.execute(
        "INSERT INTO sync_changes (
            workspace_id, kind, entity_type, entity_id, actor, receipt_id, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            workspace_id,
            &receipt.kind,
            entity_type,
            entity_id,
            &receipt.actor,
            &receipt.id,
            &receipt.created_at,
        ],
    )?;
    Ok(())
}

fn infer_sync_change_target(
    conn: &Connection,
    kind: &str,
    target_id: &str,
) -> rusqlite::Result<Option<(String, String, String)>> {
    let is_workspace_target = kind.starts_with("workspace.")
        || kind.starts_with("import.")
        || kind.starts_with("retention.");
    if is_workspace_target && workspace_exists(conn, target_id)? {
        return Ok(Some((
            target_id.to_string(),
            "workspace".to_string(),
            target_id.to_string(),
        )));
    }

    let invitation_workspace_id = if kind.starts_with("workspace.invitation.") {
        conn.query_row(
            "SELECT workspace_id FROM workspace_invitations WHERE id = ?1",
            params![target_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    } else {
        None
    };
    if let Some(workspace_id) = invitation_workspace_id {
        return Ok(Some((
            workspace_id,
            "workspace_invitation".to_string(),
            target_id.to_string(),
        )));
    }

    if kind.starts_with("file.")
        || kind.starts_with("agent.file.")
        || kind.starts_with("mobile.")
        || kind == "upload.complete"
    {
        if let Some(workspace_id) = workspace_for_file(conn, target_id)? {
            return Ok(Some((
                workspace_id,
                "file".to_string(),
                target_id.to_string(),
            )));
        }
    }

    if kind.starts_with("upload.") {
        if let Some(workspace_id) = conn
            .query_row(
                "SELECT workspace_id FROM upload_sessions WHERE id = ?1",
                params![target_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok(Some((
                workspace_id,
                "upload".to_string(),
                target_id.to_string(),
            )));
        }
    }

    if kind.starts_with("comment.reply") {
        if let Some((workspace_id, comment_id)) = conn
            .query_row(
                "SELECT f.workspace_id, c.id
                 FROM comment_replies cr
                 JOIN comments c ON c.id = cr.comment_id
                 JOIN files f ON f.id = c.file_id
                 WHERE cr.id = ?1",
                params![target_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            return Ok(Some((workspace_id, "comment".to_string(), comment_id)));
        }
    }

    if kind.starts_with("comment.") {
        if let Some((workspace_id, comment_id)) = conn
            .query_row(
                "SELECT f.workspace_id, c.id
                 FROM comments c
                 JOIN files f ON f.id = c.file_id
                 WHERE c.id = ?1",
                params![target_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            return Ok(Some((workspace_id, "comment".to_string(), comment_id)));
        }
    }

    if kind.starts_with("share.") {
        if let Some((workspace_id, share_id)) = conn
            .query_row(
                "SELECT f.workspace_id, s.id
                 FROM shares s
                 JOIN files f ON f.id = s.file_id
                 WHERE s.id = ?1",
                params![target_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            return Ok(Some((workspace_id, "share".to_string(), share_id)));
        }
    }

    if kind.starts_with("drop.") {
        if let Some(workspace_id) = conn
            .query_row(
                "SELECT workspace_id FROM drops WHERE id = ?1",
                params![target_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok(Some((
                workspace_id,
                "drop".to_string(),
                target_id.to_string(),
            )));
        }
    }

    if kind.starts_with("folder_template.") {
        if let Some(workspace_id) = conn
            .query_row(
                "SELECT workspace_id FROM folder_templates WHERE id = ?1",
                params![target_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok(Some((
                workspace_id,
                "folder_template".to_string(),
                target_id.to_string(),
            )));
        }
    }

    Ok(None)
}

fn workspace_exists(conn: &Connection, workspace_id: &str) -> rusqlite::Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM workspaces WHERE id = ?1",
        params![workspace_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn workspace_for_file(conn: &Connection, file_id: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT workspace_id FROM files WHERE id = ?1",
        params![file_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

/// Enforce a workspace storage quota against an already-open transaction so the
/// usage SUM and the follow-on INSERT are one atomic critical section.
///
/// This closes the check-then-insert TOCTOU that `ensure_workspace_quota` left
/// open: that method SUMs usage under one connection lock and the row INSERT
/// happens under a *separate* lock, so two concurrent uploads can both pass the
/// SUM (neither had inserted yet) and then both insert, together exceeding the
/// quota. Running the SUM inside the same `BEGIN IMMEDIATE` transaction as the
/// insert serialises them — the second writer's SUM sees the first writer's
/// committed row, so it is correctly rejected.
///
/// `quota_bytes` is the workspace's configured limit; the caller fetches the
/// policy via [`Storage::workspace_quota_bytes`] *before* opening the txn to
/// avoid re-locking the (non-reentrant) connection mutex. On an overwrite, the
/// current body remains charged because it becomes retained history, and the
/// replacement body is added. The zero-byte-row charge is preserved: a 0-byte
/// file (and a folder) still costs one quota byte.
pub(in crate::storage) fn enforce_quota_in_txn(
    tx: &rusqlite::Transaction<'_>,
    quota_bytes: i64,
    workspace_id: &str,
    _existing_file_id: Option<&str>,
    new_content_bytes: i64,
) -> ApiResult<()> {
    enforce_quota_charge_in_txn(
        tx,
        quota_bytes,
        workspace_id,
        None,
        new_content_bytes.max(1),
    )
}

fn enforce_cover_quota_in_txn(
    tx: &rusqlite::Transaction<'_>,
    quota_bytes: i64,
    workspace_id: &str,
    file_id: &str,
    new_cover_bytes: i64,
) -> ApiResult<()> {
    let content_charge: i64 = tx.query_row(
        "SELECT CASE WHEN content_bytes > 0 THEN content_bytes ELSE 1 END
         FROM files
         WHERE id = ?1 AND workspace_id = ?2",
        params![file_id, workspace_id],
        |row| row.get(0),
    )?;
    enforce_quota_charge_in_txn(
        tx,
        quota_bytes,
        workspace_id,
        Some(file_id),
        content_charge + new_cover_bytes,
    )
}

fn enforce_quota_charge_in_txn(
    tx: &rusqlite::Transaction<'_>,
    quota_bytes: i64,
    workspace_id: &str,
    existing_file_id: Option<&str>,
    additional_quota_bytes: i64,
) -> ApiResult<()> {
    let current_file_bytes: i64 = tx.query_row(
        "SELECT COALESCE(SUM(
                CASE WHEN content_bytes > 0 THEN content_bytes ELSE 1 END
                + CASE WHEN cover_bytes > 0 THEN cover_bytes ELSE 0 END
            ), 0)
         FROM files
         WHERE workspace_id = ?1",
        params![workspace_id],
        |row| row.get(0),
    )?;
    let retained_revision_bytes = retained_revision_quota_bytes(tx, workspace_id)?;
    let existing_file_bytes: i64 = if let Some(file_id) = existing_file_id {
        tx.query_row(
            "SELECT CASE WHEN content_bytes > 0 THEN content_bytes ELSE 1 END
                    + CASE WHEN cover_bytes > 0 THEN cover_bytes ELSE 0 END
             FROM files
             WHERE id = ?1 AND workspace_id = ?2",
            params![file_id, workspace_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0)
    } else {
        0
    };
    let projected_bytes = current_file_bytes
        .checked_sub(existing_file_bytes)
        .and_then(|value| value.checked_add(retained_revision_bytes))
        .and_then(|value| value.checked_add(additional_quota_bytes))
        .ok_or_else(|| ApiError::Validation("workspace quota usage overflow".to_string()))?;
    if projected_bytes > quota_bytes {
        return Err(ApiError::Validation(format!(
            "quota exceeded: {projected_bytes} bytes would exceed workspace quota {quota_bytes} bytes"
        )));
    }
    Ok(())
}

/// Count retained bodies once per file and content hash. Metadata-only
/// revisions reuse the current body and therefore do not multiply its logical
/// quota charge, while distinct historical bodies remain charged until their
/// revision references are deleted. Body-less historical rows retain a
/// one-byte metadata charge in addition to the hard per-file row bound.
fn retained_revision_quota_bytes(
    conn: &rusqlite::Connection,
    workspace_id: &str,
) -> ApiResult<i64> {
    let retained_content_bytes: i64 = conn.query_row(
        "SELECT COALESCE(SUM(retained_bytes), 0)
         FROM (
             SELECT fr.file_id, fr.content_hash,
                    MAX(CASE WHEN fr.content_bytes > 0 THEN fr.content_bytes ELSE 1 END)
                        AS retained_bytes
             FROM file_revisions fr
             JOIN files f ON f.id = fr.file_id
             WHERE f.workspace_id = ?1
               AND fr.revision != f.revision
               AND fr.content_hash IS NOT NULL
               AND (f.content_hash IS NULL OR fr.content_hash != f.content_hash)
             GROUP BY fr.file_id, fr.content_hash
         )",
        params![workspace_id],
        |row| row.get(0),
    )?;
    let bodyless_revision_rows: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM file_revisions fr
         JOIN files f ON f.id = fr.file_id
         WHERE f.workspace_id = ?1
           AND fr.revision != f.revision
           AND fr.content_hash IS NULL",
        params![workspace_id],
        |row| row.get(0),
    )?;
    retained_content_bytes
        .checked_add(bodyless_revision_rows)
        .ok_or_else(|| ApiError::Validation("workspace revision quota overflow".to_string()))
}

pub(crate) fn validate_file_name(name: &str) -> ApiResult<String> {
    let trimmed = name.trim();
    let invalid = trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.starts_with('.')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.chars().any(char::is_control);
    if invalid {
        return Err(ApiError::Validation(
            "file name must be non-empty and must not contain path, hidden, or control characters"
                .to_string(),
        ));
    }
    if trimmed.len() > MAX_FILE_NAME_BYTES {
        return Err(ApiError::Validation(
            "file name must be 255 bytes or shorter".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn normalize_relative_upload_path(path: &str) -> ApiResult<String> {
    if path.is_empty() || path.len() > 1024 {
        return Err(ApiError::Validation(
            "upload path must be between 1 and 1024 bytes".to_string(),
        ));
    }
    let segments = path
        .split('/')
        .map(validate_file_name)
        .collect::<ApiResult<Vec<_>>>()?;
    if segments.len() > 32 {
        return Err(ApiError::Validation(
            "upload path must contain 32 segments or fewer".to_string(),
        ));
    }
    Ok(segments.join("/"))
}

fn validate_workspace_name(name: &str) -> ApiResult<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::Validation(
            "workspace name must be non-empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_WORKSPACE_NAME_BYTES {
        return Err(ApiError::Validation(
            "workspace name must be 255 bytes or shorter".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_non_empty_label(value: &str, label: &str) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::Validation(format!("{label} must be non-empty")));
    }
    Ok(trimmed.to_string())
}

pub(super) fn normalize_storage_email(email: &str) -> ApiResult<String> {
    let normalized = email.trim().to_lowercase();
    if normalized.is_empty() || !normalized.contains('@') {
        return Err(ApiError::Validation("email is invalid".to_string()));
    }
    Ok(normalized)
}

fn row_to_workspace_member(row: &Row<'_>) -> rusqlite::Result<WorkspaceMember> {
    Ok(WorkspaceMember {
        workspace_id: row.get(0)?,
        user_id: row.get(1)?,
        email: row.get(2)?,
        role: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
    })
}

fn row_to_group(row: &Row<'_>) -> rusqlite::Result<DriveGroup> {
    Ok(DriveGroup {
        id: row.get(0)?,
        name: row.get(1)?,
        created_by: row.get(2)?,
        created_at: row.get(3)?,
    })
}

fn row_to_group_member(row: &Row<'_>) -> rusqlite::Result<GroupMember> {
    Ok(GroupMember {
        group_id: row.get(0)?,
        user_id: row.get(1)?,
        email: row.get(2)?,
        created_at: row.get(3)?,
    })
}

fn row_to_workspace_group_grant(row: &Row<'_>) -> rusqlite::Result<WorkspaceGroupGrant> {
    Ok(WorkspaceGroupGrant {
        workspace_id: row.get(0)?,
        group_id: row.get(1)?,
        group_name: row.get(2)?,
        role: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn validate_group_name(name: &str) -> ApiResult<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::Validation(
            "group name must not be empty".to_string(),
        ));
    }
    if trimmed.len() > 120 {
        return Err(ApiError::Validation(
            "group name must be 120 characters or shorter".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn role_rank(role: &str) -> i64 {
    match role {
        "owner" => 3,
        "editor" => 2,
        "viewer" => 1,
        _ => 0,
    }
}
