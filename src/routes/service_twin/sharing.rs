use crate::{
    auth::{hash_password, verify_password, Actor, AuthMode, DriveCredential},
    error::{ApiError, ApiResult},
    model::{CreateFileRequest, FileKind, TwinScenarioDescriptor, TwinScenarioRunResponse},
    routes::shares::load_public_share,
    server::AppState,
    storage::{ShareCreateFields, ShareUpdateFields},
};

use super::assertion;

pub(super) const SCENARIO: &str = "share_lifecycle_roundtrip";
pub(super) const EXPIRED: &str = "expired_share_before_guest_open";
pub(super) const WRONG_PASSWORD: &str = "wrong_share_password";

pub(super) fn descriptor() -> TwinScenarioDescriptor {
    TwinScenarioDescriptor {
        id: SCENARIO.to_string(),
        description: "Creates, updates, opens, and revokes a guest share".to_string(),
    }
}

pub(super) fn fault_descriptors() -> Vec<TwinScenarioDescriptor> {
    vec![
        TwinScenarioDescriptor {
            id: EXPIRED.to_string(),
            description: "Expires a share before guest access".to_string(),
        },
        TwinScenarioDescriptor {
            id: WRONG_PASSWORD.to_string(),
            description: "Attempts guest access with the wrong password".to_string(),
        },
    ]
}

pub(super) async fn run(
    state: AppState,
    faults: Vec<String>,
) -> ApiResult<TwinScenarioRunResponse> {
    if faults.len() > 1 {
        return Err(ApiError::Validation(
            "share twin accepts one fault at a time".to_string(),
        ));
    }
    let (workspace, _, _) = state
        .storage
        .create_workspace("Twin Share Workspace", "twin@example.test")?;
    let content = b"shared service twin content";
    let _blob_lifecycle_lock = crate::blob::BlobLifecycleLock::acquire_shared(&state.data_dir())?;
    let hash = crate::blob::put_blob(&state.data_dir(), content)?;
    let (file, _) = state.storage.create_file_with_content_bytes(
        CreateFileRequest {
            workspace_id: workspace.id.clone(),
            parent_id: None,
            name: "shared.txt".to_string(),
            kind: FileKind::File,
            content: None,
            path: None,
        },
        Some(hash),
        content.len() as i64,
    )?;
    let password = "twin-share-password";
    let password_hash = hash_password(password)?;
    let operator = Actor {
        email: "twin@example.test".to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    };
    let credential = DriveCredential::Operator;
    let (created, _) = state.storage.create_share(
        ShareCreateFields {
            file_id: &file.id,
            password_hash: &password_hash,
            password_required: true,
            expires_in_seconds: 7_200,
            target_kind: "file",
            allow_download: true,
            recipient_note: Some("service twin"),
            max_uses: Some(4),
        },
        &operator,
        &credential,
    )?;
    let (mut updated, _) = state.storage.update_share(
        &created.id,
        ShareUpdateFields {
            password_hash: None,
            password_required: None,
            expires_in_seconds: Some(3_600),
            allow_download: Some(false),
            recipient_note: None,
            max_uses: None,
        },
        &operator,
        &credential,
    )?;
    let expired_faulted = faults.iter().any(|fault| fault == EXPIRED);
    let wrong_password_faulted = faults.iter().any(|fault| fault == WRONG_PASSWORD);
    if expired_faulted {
        updated = state
            .storage
            .update_share(
                &created.id,
                ShareUpdateFields {
                    password_hash: None,
                    password_required: None,
                    expires_in_seconds: Some(1),
                    allow_download: None,
                    recipient_note: None,
                    max_uses: None,
                },
                &operator,
                &credential,
            )?
            .0;
    }
    let loaded = if expired_faulted {
        // Exercise the real wall-clock expiry boundary without assuming a busy
        // CI host will advance `Utc::now()` in lockstep with one fixed timer.
        // Poll only this bounded debug scenario; production request handling
        // still performs one immediate fail-closed expiry check.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let loaded = load_public_share(&state, &created.id);
            if matches!(loaded, Err(ApiError::NotFound)) || tokio::time::Instant::now() >= deadline
            {
                break loaded;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    } else {
        load_public_share(&state, &created.id)
    };
    let expiry_contained = !expired_faulted || matches!(loaded, Err(ApiError::NotFound));
    let (guest_opened, wrong_password_contained) = match loaded {
        Ok((record, _)) if wrong_password_faulted => {
            let rejected = !verify_password(&record.password_hash, "wrong");
            (false, rejected)
        }
        Ok((record, _)) => (verify_password(&record.password_hash, password), true),
        Err(_) => (false, true),
    };
    let (revoked, _) = state
        .storage
        .revoke_share(&created.id, &operator, &credential)?;
    let revoked_hidden = matches!(
        load_public_share(&state, &created.id),
        Err(ApiError::NotFound)
    );
    let assertions = vec![
        assertion(
            "share_created",
            !created.revoked && created.file_id == file.id,
            "share was created for the scenario file",
            "share creation returned inconsistent state",
        ),
        assertion(
            "share_updated",
            updated.expires_in_seconds == Some(if expired_faulted { 1 } else { 3_600 })
                && !updated.allow_download,
            "share policy fields were updated",
            "share policy update was not persisted",
        ),
        assertion(
            "guest_opened",
            guest_opened,
            "guest access accepted the current password",
            "guest access was blocked by the injected fault",
        ),
        assertion(
            "expiry_fault_contained",
            expiry_contained,
            "expired share access failed closed",
            "expired share remained visible",
        ),
        assertion(
            "password_fault_contained",
            wrong_password_contained,
            "wrong password access was rejected",
            "wrong password access was accepted",
        ),
        assertion(
            "revoked_share_hidden",
            revoked.revoked && revoked_hidden,
            "revoked share is no longer guest-visible",
            "revoked share remained guest-visible",
        ),
    ];
    let passed = assertions.iter().all(|assertion| assertion.passed);
    let receipt = state
        .storage
        .insert_receipt("twin.run", "system", Some(&workspace.id))?;
    Ok(TwinScenarioRunResponse {
        scenario: SCENARIO.to_string(),
        faults,
        passed,
        workspace_id: workspace.id,
        file_id: file.id,
        assertions,
        receipt,
    })
}
