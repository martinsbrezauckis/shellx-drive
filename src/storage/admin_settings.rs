use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{
        BackupPolicy, Receipt, SandboxProfile, UpdateBackupPolicyRequest,
        UpdateSandboxProfileRequest,
    },
};

use super::{
    authorization, default_backup_policy, default_sandbox_profile, insert_receipt_rows,
    instance_policy, new_receipt, row_to_backup_policy, row_to_sandbox_profile, Storage,
};

impl Storage {
    pub(crate) fn set_registration_enabled_authorized(
        &self,
        enabled: bool,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(bool, Receipt)> {
        if enabled {
            return Err(ApiError::Validation(
                "public registration is unavailable in v0.1; create accounts as an administrator or use verified workspace invitations"
                    .to_string(),
            ));
        }
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("registration.policy.update", &actor.email, None);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        tx.execute(
            "INSERT INTO server_settings (key, value, updated_at)
             VALUES ('registration_enabled', ?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params!["false", now],
        )?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((false, receipt))
    }

    pub(crate) fn update_backup_policy_authorized(
        &self,
        request: UpdateBackupPolicyRequest,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(BackupPolicy, Receipt)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let mut policy = tx
            .query_row(
                "SELECT enabled, schedule, retention_count, updated_at
                 FROM backup_policy WHERE id = 'default'",
                [],
                row_to_backup_policy,
            )
            .optional()?
            .unwrap_or_else(default_backup_policy);
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
        tx.execute(
            "INSERT INTO backup_policy (id, enabled, schedule, retention_count, updated_at)
             VALUES ('default', ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                enabled = excluded.enabled,
                schedule = excluded.schedule,
                retention_count = excluded.retention_count,
                updated_at = excluded.updated_at",
            params![
                policy.enabled as i64,
                &policy.schedule,
                policy.retention_count,
                &policy.updated_at
            ],
        )?;
        let receipt = new_receipt("backup.policy.update", &actor.email, Some("default"));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((policy, receipt))
    }

    pub(crate) fn update_sandbox_profile_authorized(
        &self,
        request: UpdateSandboxProfileRequest,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(SandboxProfile, Receipt)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let mut profile = tx
            .query_row(
                "SELECT id, name, mode, data_dir, bind, service_user, service_group,
                        read_write_paths_json, read_only_paths_json, network_policy, status,
                        last_checked_at
                 FROM sandbox_profiles WHERE id = 'default'",
                [],
                row_to_sandbox_profile,
            )
            .optional()?
            .unwrap_or_else(default_sandbox_profile);
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
        store_sandbox_profile_in_tx(&tx, &profile)?;
        let receipt = new_receipt("sandbox.profile.update", &actor.email, Some(&profile.id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((profile, receipt))
    }

    pub(crate) fn record_sandbox_apply_intent_authorized(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(SandboxProfile, Receipt)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let profile = tx
            .query_row(
                "SELECT id, name, mode, data_dir, bind, service_user, service_group,
                        read_write_paths_json, read_only_paths_json, network_policy, status,
                        last_checked_at
                 FROM sandbox_profiles WHERE id = 'default'",
                [],
                row_to_sandbox_profile,
            )
            .optional()?
            .unwrap_or_else(default_sandbox_profile);
        instance_policy::ensure_valid_sandbox_profile(&profile)?;
        store_sandbox_profile_in_tx(&tx, &profile)?;
        let receipt = new_receipt("sandbox.apply.intent", &actor.email, Some(&profile.id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((profile, receipt))
    }
}

fn store_sandbox_profile_in_tx(
    tx: &rusqlite::Transaction<'_>,
    profile: &SandboxProfile,
) -> ApiResult<()> {
    instance_policy::ensure_valid_sandbox_profile(profile)?;
    let read_write_paths_json = serde_json::to_string(&profile.read_write_paths)
        .map_err(|error| ApiError::Validation(format!("invalid sandbox paths: {error}")))?;
    let read_only_paths_json = serde_json::to_string(&profile.read_only_paths)
        .map_err(|error| ApiError::Validation(format!("invalid sandbox paths: {error}")))?;
    tx.execute(
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
