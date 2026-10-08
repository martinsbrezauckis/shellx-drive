use axum::http::{header, HeaderMap, HeaderValue};

use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    error::{ApiError, ApiResult},
    model::{TwinScenarioDescriptor, TwinScenarioRunResponse},
    routes::uploads::put_upload_bytes,
    server::AppState,
    storage::{UploadAdmissionPolicy, UploadSessionCreate},
};

use super::assertion;

pub(super) const SCENARIO: &str = "upload_roundtrip";
pub(super) const STALE_OFFSET: &str = "stale_upload_offset";
pub(super) const INTERRUPT: &str = "interrupt_upload_before_finalize";

pub(super) fn descriptor() -> TwinScenarioDescriptor {
    TwinScenarioDescriptor {
        id: SCENARIO.to_string(),
        description: "Creates, chunks, and finalizes a resumable upload".to_string(),
    }
}

pub(super) fn fault_descriptors() -> Vec<TwinScenarioDescriptor> {
    vec![
        TwinScenarioDescriptor {
            id: STALE_OFFSET.to_string(),
            description: "Submits a chunk at a stale offset before recovery".to_string(),
        },
        TwinScenarioDescriptor {
            id: INTERRUPT.to_string(),
            description: "Interrupts an upload before finalization".to_string(),
        },
    ]
}

pub(super) async fn run(
    state: AppState,
    faults: Vec<String>,
) -> ApiResult<TwinScenarioRunResponse> {
    if faults.len() > 1 {
        return Err(ApiError::Validation(
            "upload twin accepts one fault at a time".to_string(),
        ));
    }
    let content = b"service twin resumable upload";
    let (workspace, _, _) = state
        .storage
        .create_workspace("Twin Upload Workspace", "twin@example.test")?;
    let session = state.storage.create_upload_session(
        UploadSessionCreate {
            workspace_id: &workspace.id,
            actor_email: "system@local",
            parent_id: None,
            name: "twin-upload.txt",
            total_size: Some(content.len() as i64),
            path: None,
            duplicate_policy: "keep_both",
        },
        UploadAdmissionPolicy::default(),
    )?;
    let headers = operator_headers(&state)?;
    let midpoint = content.len() / 2;
    let stale_faulted = faults.iter().any(|fault| fault == STALE_OFFSET);
    let interrupted = faults.iter().any(|fault| fault == INTERRUPT);
    let stale_rejected = if stale_faulted {
        let ingress_permit = state.try_authenticated_upload_ingress(crate::auth::ADMIN_ACTOR)?;
        matches!(
            put_upload_bytes(
                state.clone(),
                headers.clone(),
                session.id.clone(),
                1,
                false,
                content[..midpoint].to_vec(),
                ingress_permit,
            )
            .await,
            Err(ApiError::Conflict)
        )
    } else {
        true
    };
    let ingress_permit = state.try_authenticated_upload_ingress(crate::auth::ADMIN_ACTOR)?;
    let first = put_upload_bytes(
        state.clone(),
        headers.clone(),
        session.id.clone(),
        0,
        false,
        content[..midpoint].to_vec(),
        ingress_permit,
    )
    .await?
    .0;
    let (terminal, file_id) = if interrupted {
        let operator = Actor {
            email: "system@local".to_string(),
            is_admin: true,
            auth_mode: AuthMode::Operator,
            allowed_workspace_ids: None,
        };
        let (canceled, _) = state.storage.cancel_upload_session_authorized(
            &session.id,
            &operator,
            &DriveCredential::Operator,
        )?;
        if let Ok(path) = crate::routes::uploads::validated_upload_part_path(&state, &session.id) {
            let _ = std::fs::remove_file(path);
        }
        (canceled, None)
    } else {
        let ingress_permit = state.try_authenticated_upload_ingress(crate::auth::ADMIN_ACTOR)?;
        let response = put_upload_bytes(
            state.clone(),
            headers,
            session.id.clone(),
            first.session.received_bytes,
            true,
            content[midpoint..].to_vec(),
            ingress_permit,
        )
        .await?
        .0;
        (response.session, response.file.map(|file| file.id))
    };
    let current = state
        .storage
        .get_upload_session(&session.id)?
        .ok_or(ApiError::NotFound)?;
    let assertions = vec![
        assertion(
            "session_created",
            first.session.received_bytes == midpoint as i64,
            "upload session accepted the first chunk",
            "upload session did not acknowledge the first chunk",
        ),
        assertion(
            "offset_current",
            !stale_faulted,
            "all chunks used the current offset",
            "a stale offset was injected and rejected",
        ),
        assertion(
            "stale_offset_contained",
            stale_rejected,
            "stale offset handling preserved the session",
            "stale offset was not rejected",
        ),
        assertion(
            "upload_finalized",
            current.completed
                && !current.canceled
                && current.received_bytes == content.len() as i64,
            "upload finalized at the declared size",
            "upload was interrupted before finalization",
        ),
        assertion(
            "interruption_contained",
            !interrupted || (terminal.canceled && !terminal.completed),
            "interruption left a terminal non-completed session",
            "interrupted upload remained writable",
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
        file_id: file_id.unwrap_or(session.id),
        assertions,
        receipt,
    })
}

fn operator_headers(state: &AppState) -> ApiResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", state.config.token))
            .map_err(|_| ApiError::Validation("invalid operator token header".to_string()))?,
    );
    Ok(headers)
}
