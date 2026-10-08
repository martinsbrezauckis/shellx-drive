use std::collections::HashSet;

use crate::{
    error::{ApiError, ApiResult},
    model::{CreateFileRequest, FileKind, TwinScenarioDescriptor, TwinScenarioRunResponse},
    server::AppState,
    storage::{WebDavLockDepth, WebDavMutationTarget},
};

use super::assertion;

pub(super) const SCENARIO: &str = "webdav_lock_roundtrip";
pub(super) const CONFLICTING_TOKEN: &str = "conflicting_webdav_lock";

pub(super) fn descriptor() -> TwinScenarioDescriptor {
    TwinScenarioDescriptor {
        id: SCENARIO.to_string(),
        description: "Locks, authorizes a mutation, refreshes, and unlocks a DAV resource"
            .to_string(),
    }
}

pub(super) fn fault_descriptors() -> Vec<TwinScenarioDescriptor> {
    vec![TwinScenarioDescriptor {
        id: CONFLICTING_TOKEN.to_string(),
        description: "Attempts a conflicting exclusive lock".to_string(),
    }]
}

pub(super) fn run(state: AppState, faults: Vec<String>) -> ApiResult<TwinScenarioRunResponse> {
    let (workspace, _, _) = state
        .storage
        .create_workspace("Twin WebDAV Workspace", "twin@example.test")?;
    let (file, _) = state.storage.create_file_with_content_bytes(
        CreateFileRequest {
            workspace_id: workspace.id.clone(),
            parent_id: None,
            name: "dav.txt".to_string(),
            kind: FileKind::File,
            content: None,
            path: None,
        },
        None,
        0,
    )?;
    let lock = state.storage.create_webdav_lock(
        &workspace.id,
        Some(&file.id),
        "/dav.txt",
        "twin@example.test",
        WebDavLockDepth::Zero,
        3_600,
    )?;
    let target = [WebDavMutationTarget::Resource(Some(file.id.clone()))];
    let no_token_blocked = matches!(
        state.storage.ensure_webdav_mutation_allowed(
            &workspace.id,
            &target,
            &HashSet::new(),
            "twin@example.test",
            false,
        ),
        Err(ApiError::Locked)
    );
    let submitted = HashSet::from([lock.token.clone()]);
    let correct_token_allowed = state
        .storage
        .ensure_webdav_mutation_allowed(
            &workspace.id,
            &target,
            &submitted,
            "twin@example.test",
            false,
        )
        .is_ok();
    let faulted = faults.iter().any(|fault| fault == CONFLICTING_TOKEN);
    let conflict_contained = !faulted
        || matches!(
            state.storage.create_webdav_lock(
                &workspace.id,
                Some(&file.id),
                "/dav.txt",
                "other@example.test",
                WebDavLockDepth::Zero,
                3_600,
            ),
            Err(ApiError::Locked)
        );
    let refreshed = state.storage.refresh_webdav_lock(
        &workspace.id,
        Some(&file.id),
        &lock.token,
        "twin@example.test",
        false,
        7_200,
    )?;
    state.storage.unlock_webdav_lock(
        &workspace.id,
        Some(&file.id),
        &lock.token,
        "twin@example.test",
        false,
    )?;
    let unlocked_allowed = state
        .storage
        .ensure_webdav_mutation_allowed(
            &workspace.id,
            &target,
            &HashSet::new(),
            "twin@example.test",
            false,
        )
        .is_ok();
    let assertions = vec![
        assertion(
            "lock_blocks_unconditional_mutation",
            no_token_blocked,
            "locked mutation without a token was rejected",
            "locked mutation was accepted without a token",
        ),
        assertion(
            "lock_token_allows_mutation",
            correct_token_allowed,
            "matching lock token authorized the mutation",
            "matching lock token did not authorize the mutation",
        ),
        assertion(
            "lock_request_current",
            !faulted,
            "no conflicting lock was requested",
            "a conflicting lock request was injected",
        ),
        assertion(
            "conflicting_lock_contained",
            conflict_contained,
            "conflicting exclusive lock was rejected",
            "conflicting exclusive lock was accepted",
        ),
        assertion(
            "lock_refreshed",
            refreshed.timeout_seconds == 7_200,
            "lock refresh updated the timeout",
            "lock refresh did not update the timeout",
        ),
        assertion(
            "unlock_restores_mutation",
            unlocked_allowed,
            "unlock removed the mutation precondition",
            "resource remained locked after unlock",
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
