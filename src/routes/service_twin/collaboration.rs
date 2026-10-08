use crate::{
    auth::{Actor, AuthMode, DriveCredential, WorkspacePermission, WorkspaceRole},
    blob,
    error::{ApiError, ApiResult},
    model::{
        ContentWrite, CreateFileRequest, FileKind, TwinScenarioDescriptor, TwinScenarioRunResponse,
    },
    server::AppState,
};

use super::assertion;

pub(super) const SCENARIO: &str = "collaboration_revision_roundtrip";
pub(super) const STALE_REVISION: &str = "stale_collaboration_revision";
pub(super) const VIEWER_COMMENT: &str = "viewer_comment_attempt";

pub(super) fn descriptor() -> TwinScenarioDescriptor {
    TwinScenarioDescriptor {
        id: SCENARIO.to_string(),
        description: "Exercises comment, reply, resolution, and revision lifecycle".to_string(),
    }
}

pub(super) fn fault_descriptors() -> Vec<TwinScenarioDescriptor> {
    vec![
        TwinScenarioDescriptor {
            id: STALE_REVISION.to_string(),
            description: "Attempts a content write from a stale revision".to_string(),
        },
        TwinScenarioDescriptor {
            id: VIEWER_COMMENT.to_string(),
            description: "Attempts a comment write as a workspace viewer".to_string(),
        },
    ]
}

pub(super) fn run(state: AppState, faults: Vec<String>) -> ApiResult<TwinScenarioRunResponse> {
    if faults.len() > 1 {
        return Err(ApiError::Validation(
            "collaboration twin accepts one fault at a time".to_string(),
        ));
    }
    let owner = "twin@example.test";
    let viewer_email = "twin-viewer@example.test";
    let (workspace, _, _) = state
        .storage
        .create_workspace("Twin Collaboration Workspace", owner)?;
    let operator = Actor {
        email: owner.to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    };
    state.storage.upsert_workspace_member(
        &workspace.id,
        viewer_email,
        WorkspaceRole::Viewer,
        &operator,
        &DriveCredential::Operator,
    )?;
    let initial = b"revision one";
    let _blob_lifecycle_lock = blob::BlobLifecycleLock::acquire_shared(&state.data_dir())?;
    let initial_hash = blob::put_blob(&state.data_dir(), initial)?;
    let (file, _) = state.storage.create_file_with_content_bytes(
        CreateFileRequest {
            workspace_id: workspace.id.clone(),
            parent_id: None,
            name: "collaboration.txt".to_string(),
            kind: FileKind::File,
            content: None,
            path: None,
        },
        Some(initial_hash),
        initial.len() as i64,
    )?;
    let (comment, _) = state
        .storage
        .create_comment(&file.id, owner, "Initial note")?;
    let (comment, _) = state
        .storage
        .update_comment(&comment.id, owner, "Updated note")?;
    let (reply, _) = state
        .storage
        .create_comment_reply(&comment.id, owner, "Acknowledged")?;
    let (resolved, _) = state.storage.resolve_comment(&comment.id, owner)?;

    let viewer_faulted = faults.iter().any(|fault| fault == VIEWER_COMMENT);
    let viewer = Actor {
        email: viewer_email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };
    let viewer_denied = !viewer_faulted
        || matches!(
            state.storage.ensure_workspace_permission(
                &workspace.id,
                &viewer,
                WorkspacePermission::Write,
            ),
            Err(ApiError::Forbidden)
        );

    let stale_faulted = faults.iter().any(|fault| fault == STALE_REVISION);
    let next = b"revision two";
    let next_hash = blob::put_blob(&state.data_dir(), next)?;
    let stale_contained = if stale_faulted {
        matches!(
            state.storage.put_content(
                &file.id,
                file.revision.saturating_sub(1),
                &next_hash,
                next.len() as i64,
            )?,
            ContentWrite::Conflict(ref conflict)
                if conflict.error == "stale_revision" && conflict.file_id == file.id
        )
    } else {
        true
    };
    let updated =
        match state
            .storage
            .put_content(&file.id, file.revision, &next_hash, next.len() as i64)?
        {
            ContentWrite::Updated { file, .. } => file,
            ContentWrite::Conflict(_) => return Err(ApiError::Conflict),
        };
    let comments = state.storage.list_comments_for_file(&file.id)?;
    let revisions = state.storage.list_file_revisions(&file.id)?;
    let assertions = vec![
        assertion(
            "comment_lifecycle",
            resolved.resolved
                && comments.len() == 1
                && comments[0].body == "Updated note"
                && comments[0].replies.iter().any(|row| row.id == reply.id),
            "comment, edit, reply, and resolution were persisted",
            "comment lifecycle state is incomplete",
        ),
        assertion(
            "comment_permission_current",
            !viewer_faulted,
            "comment writes used an editor-capable actor",
            "a viewer comment write was injected and denied",
        ),
        assertion(
            "viewer_write_contained",
            viewer_denied,
            "viewer write permission failed closed",
            "viewer was allowed to write a comment",
        ),
        assertion(
            "revision_current",
            !stale_faulted,
            "content write used the current revision",
            "a stale content revision was injected",
        ),
        assertion(
            "stale_revision_contained",
            stale_contained,
            "stale revision handling preserved the current branch",
            "stale revision was not isolated as a conflict",
        ),
        assertion(
            "revision_advanced",
            updated.revision == file.revision + 1
                && revisions.iter().any(|revision| revision.current),
            "revision history advanced and has one current revision",
            "revision history did not advance cleanly",
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
