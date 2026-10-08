//! Durable server-side broker state for an enrolled desktop. This is not a
//! background worker and it deliberately stores no raw device or agent bearer.

mod disconnect;
mod guards;
mod history;
mod lifecycle;
mod progress;
mod rows;
mod schema;
mod terminal;

use chrono::Utc;
use rusqlite::{params, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{random_secret_token, token_hash, Actor, AuthMode, DriveCredential},
    desktop_agent::{
        command_expires_at, payload_hash, validate_device_assertion, validate_registration,
        DesktopAgentCommand, DesktopAgentCommandStatus, DesktopAgentDevice,
        DesktopAgentDeviceAssertion, DesktopAgentDeviceRegistration, DesktopAgentDeviceState,
        DesktopAgentEnrollment, DesktopAgentSubmitRequest, DesktopAgentTerminalCode,
    },
    error::{ApiError, ApiResult},
};

use super::{authorization, insert_receipt_rows, new_receipt, Storage};
use guards::*;
use rows::*;

const MAX_ACTIVE_COMMANDS_PER_DEVICE: i64 = 16;
const MAX_ACTIVE_COMMANDS_PER_OWNER: i64 = 64;
const MAX_TERMINAL_COMMANDS_PER_OWNER: i64 = 256;
const MAX_DEVICES_PER_OWNER: i64 = 16;
const MAX_COMMAND_EVENTS: i64 = 64;
const MAX_STALE_LEASE_RECOVERY: i64 = 32;
const DEFAULT_COMMAND_PAGE_LIMIT: i64 = 25;
const MAX_COMMAND_PAGE_LIMIT: i64 = 50;
const DEVICE_SECRET_PREFIX: &str = "sxd_device_";

pub(super) use schema::install_schema;

impl Storage {
    /// Register only an already signed-in local desktop session. The route must
    /// obtain `owner_session_id` through `require_local_session_actor`; a
    /// delegated bearer cannot create a device credential.
    pub fn register_desktop_agent_device(
        &self,
        owner: &Actor,
        owner_session_id: &str,
        registration: &DesktopAgentDeviceRegistration,
    ) -> ApiResult<DesktopAgentEnrollment> {
        validate_registration(registration)?;
        if registration.pending_disconnect_cleanup || registration.candidate_recovery {
            return Err(ApiError::Conflict);
        }
        // The exact parent session is currently a local-password session.
        // SSO enrollment needs a separately designed durable parent binding;
        // do not fabricate one from an email or account row.
        if owner.auth_mode != AuthMode::LocalAccount {
            return Err(ApiError::Forbidden);
        }
        let owner_credential = DriveCredential::UserSession(owner_session_id.to_string());
        let device_id = format!("device-{}", Uuid::now_v7());
        let device_credential = format!("{DEVICE_SECRET_PREFIX}{}", random_secret_token());
        let credential_hash = token_hash(&device_credential);
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, owner, &owner_credential)?;
        let (owner_account_id, owner_security_version) = account_binding_in_tx(&tx, owner)?;
        let device_count = tx.query_row(
            "SELECT COUNT(*) FROM desktop_agent_devices
             WHERE owner_account_id = ?1 AND state IN ('active', 'frozen')",
            [&owner_account_id],
            |row| row.get::<_, i64>(0),
        )?;
        if device_count >= MAX_DEVICES_PER_OWNER {
            return Err(ApiError::TooManyRequests);
        }
        if !history::admit_device_history_in_tx(&tx, &owner_account_id, &now)? {
            tx.commit()?;
            return Err(ApiError::TooManyRequests);
        }
        tx.execute(
            "INSERT INTO desktop_agent_devices (
                 id, owner_account_id, owner_session_id, owner_security_version,
                 pair_fingerprint, credential_hash, platform, app_version, state,
                 created_at, last_seen_at, last_ready_at, frozen_at, retired_at, revoked_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, NULL, NULL, NULL, NULL, NULL)",
            params![
                &device_id,
                &owner_account_id,
                owner_session_id,
                owner_security_version,
                &registration.pair_fingerprint,
                &credential_hash,
                enum_db(registration.platform)?,
                &registration.app_version,
                &now,
            ],
        )?;
        let receipt = new_receipt(
            "desktop_agent.device.register",
            &owner.email,
            Some(&device_id),
        );
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(DesktopAgentEnrollment {
            device_id,
            device_credential,
            credential_expires_at: None,
        })
    }

    pub fn list_desktop_agent_devices(
        &self,
        owner: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Vec<DesktopAgentDevice>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, owner, source_credential)?;
        let (owner_account_id, _) = account_binding_in_tx(&tx, owner)?;
        let devices = {
            let mut statement = tx.prepare(
                "SELECT id, platform, app_version, state, last_seen_at, last_ready_at, created_at
                 FROM desktop_agent_devices
                 WHERE owner_account_id = ?1
                 ORDER BY created_at DESC, id DESC LIMIT 50",
            )?;
            let rows = statement.query_map([owner_account_id], row_to_device)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.commit()?;
        Ok(devices)
    }

    pub fn revoke_desktop_agent_device(
        &self,
        device_id: &str,
        owner: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, owner, source_credential)?;
        let (owner_account_id, _) = account_binding_in_tx(&tx, owner)?;
        let updated = tx.execute(
            "UPDATE desktop_agent_devices
             SET state = 'revoked', revoked_at = COALESCE(revoked_at, ?1),
                 credential_hash = 'revoked:' || id
             WHERE id = ?2 AND owner_account_id = ?3 AND state NOT IN ('retired', 'revoked')",
            params![&now, device_id, &owner_account_id],
        )?;
        if updated != 1 {
            return Err(ApiError::NotFound);
        }
        invalidate_device_commands_in_tx(
            &tx,
            device_id,
            &now,
            DesktopAgentTerminalCode::AuthorizationLost,
        )?;
        let receipt = new_receipt("desktop_agent.device.revoke", &owner.email, Some(device_id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(())
    }

    pub fn retire_desktop_agent_device(
        &self,
        device_id: &str,
        device_credential: &str,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> ApiResult<()> {
        validate_device_assertion(assertion)?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device = authenticate_device_in_tx(&tx, device_id, device_credential, assertion)?;
        tx.execute(
            "UPDATE desktop_agent_devices
             SET state = 'retired', retired_at = COALESCE(retired_at, ?1),
                 credential_hash = 'retired:' || id
             WHERE id = ?2 AND state IN ('active', 'frozen')",
            params![&now, &device.id],
        )?;
        invalidate_device_commands_in_tx(
            &tx,
            &device.id,
            &now,
            DesktopAgentTerminalCode::CancelledBeforeStart,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn submit_desktop_agent_command(
        &self,
        owner: &Actor,
        source_credential: &DriveCredential,
        request: DesktopAgentSubmitRequest,
    ) -> ApiResult<DesktopAgentCommand> {
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (owner_account_id, owner_is_admin) =
            active_submission_owner_in_tx(&tx, owner, source_credential)?;
        let requester = requester_binding_in_tx(&tx, &owner_account_id, source_credential)?;
        expire_queued_commands_for_owner_in_tx(&tx, &owner_account_id, &now_text)?;
        let payload_hash = payload_hash(&request.payload)?;
        let payload_json = serde_json::to_string(&request.payload)
            .map_err(|_| ApiError::Validation("invalid_desktop_agent_payload".to_string()))?;
        let (device_id, target_key, initial_status, initial_code) = match request
            .device_id
            .as_deref()
        {
            Some(device_id) => {
                match device_state_for_owner_in_tx(&tx, device_id, &owner_account_id)? {
                    Some(DesktopAgentDeviceState::Active) => {
                        let device =
                            ensure_device_live_for_owner_in_tx(&tx, device_id, &owner_account_id)?;
                        if device.candidate_recovery {
                            return Err(ApiError::Conflict);
                        }
                        recover_stale_leases_in_tx(&tx, device_id, &now_text)?;
                        (
                            Some(device_id.to_string()),
                            format!("device:{device_id}"),
                            DesktopAgentCommandStatus::Queued,
                            None,
                        )
                    }
                    Some(DesktopAgentDeviceState::Frozen) => (
                        Some(device_id.to_string()),
                        format!("device:{device_id}"),
                        DesktopAgentCommandStatus::Rejected,
                        Some(DesktopAgentTerminalCode::PendingDisconnect),
                    ),
                    Some(DesktopAgentDeviceState::Retired)
                    | Some(DesktopAgentDeviceState::Revoked) => (
                        Some(device_id.to_string()),
                        format!("device:{device_id}"),
                        DesktopAgentCommandStatus::RequiresLocalGesture,
                        Some(DesktopAgentTerminalCode::RequiresLocalGesture),
                    ),
                    None => return Err(ApiError::NotFound),
                }
            }
            None => (
                None,
                "requires_local_gesture".to_string(),
                DesktopAgentCommandStatus::RequiresLocalGesture,
                Some(DesktopAgentTerminalCode::RequiresLocalGesture),
            ),
        };

        if let Some(existing) = idempotent_command_in_tx(
            &tx,
            &owner_account_id,
            &requester.principal_id,
            &target_key,
            &request.request_id,
        )? {
            if existing.kind == request.payload.kind() && existing.payload_hash == payload_hash {
                let command = load_command_for_owner_in_tx(&tx, &existing.id, &owner_account_id)?
                    .ok_or(ApiError::NotFound)?;
                tx.commit()?;
                return Ok(command);
            }
            return Err(ApiError::Conflict);
        }
        admit_terminal_command_capacity_in_tx(&tx, &owner_account_id, &now_text)?;
        if initial_status == DesktopAgentCommandStatus::Queued {
            admit_command_capacity_in_tx(&tx, &owner_account_id, device_id.as_deref())?;
        }
        let command_id = format!("command-{}", Uuid::now_v7());
        let expires_at = command_expires_at(now, request.expires_in_seconds);
        let terminal_code = initial_code.map(enum_db).transpose()?;
        let finished_at = initial_status.is_terminal().then_some(now_text.clone());
        tx.execute(
            "INSERT INTO desktop_agent_commands (
                 id, owner_account_id, device_id, target_key, requester_kind, requester_id,
                 requester_principal_id, owner_is_admin_at_enqueue, owner_security_version,
                 kind, payload_json,
                 payload_hash, request_id, expires_at, status, lease_id, lease_expires_at,
                 lease_event_sequence,
                 created_at, accepted_at, started_at, finished_at, terminal_code, result_code,
                 result_json, terminal_event_sequence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                       NULL, NULL, NULL, ?16, NULL, NULL, ?17, ?18, NULL, NULL, NULL)",
            params![
                &command_id,
                &owner_account_id,
                device_id,
                &target_key,
                requester.kind,
                requester.credential_id,
                requester.principal_id,
                i64::from(owner_is_admin),
                requester.owner_security_version,
                enum_db(request.payload.kind())?,
                &payload_json,
                &payload_hash,
                &request.request_id,
                &expires_at,
                enum_db(initial_status)?,
                &now_text,
                finished_at,
                terminal_code,
            ],
        )?;
        insert_event_in_tx(
            &tx,
            &command_id,
            1,
            &now_text,
            CommandEvent::initial(initial_status, initial_code),
        )?;
        let receipt = new_receipt(
            "desktop_agent.command.submit",
            &owner.email,
            Some(&command_id),
        );
        insert_receipt_rows(&tx, &receipt)?;
        let command = load_command_for_owner_in_tx(&tx, &command_id, &owner_account_id)?
            .ok_or(ApiError::NotFound)?;
        tx.commit()?;
        Ok(command)
    }
}
