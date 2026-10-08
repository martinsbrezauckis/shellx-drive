use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    model::{TwinScenarioDescriptor, TwinScenarioRunResponse},
    server::AppState,
};

use super::assertion;

pub(super) const SCENARIO: &str = "backup_readiness_roundtrip";
pub(super) const INTERRUPT: &str = "interrupt_backup_job";

pub(super) fn descriptor() -> TwinScenarioDescriptor {
    TwinScenarioDescriptor {
        id: SCENARIO.to_string(),
        description: "Exercises durable create, validate, and restore job terminal state"
            .to_string(),
    }
}

pub(super) fn fault_descriptors() -> Vec<TwinScenarioDescriptor> {
    vec![TwinScenarioDescriptor {
        id: INTERRUPT.to_string(),
        description: "Interrupts a running backup job before completion".to_string(),
    }]
}

pub(super) fn run(state: AppState, faults: Vec<String>) -> ApiResult<TwinScenarioRunResponse> {
    let (workspace, _, _) = state
        .storage
        .create_workspace("Twin Backup Workspace", "twin@example.test")?;
    let backup_id = Uuid::now_v7().to_string();
    let created =
        state
            .storage
            .enqueue_scheduled_backup_job("create", &backup_id, "system@local")?;
    let running = state
        .storage
        .claim_backup_job(&created.id)?
        .ok_or(ApiError::NotFound)?;
    let interrupted_faulted = faults.iter().any(|fault| fault == INTERRUPT);
    let (create_terminal, validate_terminal, restore_terminal) = if interrupted_faulted {
        state
            .storage
            .update_backup_job_phase(&running.id, "snapshot")?;
        state.storage.interrupt_backup_job(&running.id)?;
        (
            state
                .storage
                .get_backup_job(&running.id)?
                .ok_or(ApiError::NotFound)?,
            None,
            None,
        )
    } else {
        let create = state.storage.finish_backup_job(
            &running.id,
            "succeeded",
            "complete",
            Some(&"a".repeat(64)),
            None,
        )?;
        let validate =
            state
                .storage
                .enqueue_scheduled_backup_job("validate", &backup_id, "system@local")?;
        let validate_running = state
            .storage
            .claim_backup_job(&validate.id)?
            .ok_or(ApiError::NotFound)?;
        debug_assert_eq!(validate.id, validate_running.id);
        let validate = state.storage.finish_backup_job(
            &validate_running.id,
            "succeeded",
            "complete",
            Some(&"a".repeat(64)),
            None,
        )?;
        let restore =
            state
                .storage
                .enqueue_scheduled_backup_job("restore", &backup_id, "system@local")?;
        let restore_running = state
            .storage
            .claim_backup_job(&restore.id)?
            .ok_or(ApiError::NotFound)?;
        debug_assert_eq!(restore.id, restore_running.id);
        // This scenario runs inside the normal application request admission
        // read permit. A real restore reserves the write permit before its 202
        // response, so attempting that writer upgrade here would correctly
        // conflict with this request's own read permit. Exercise the durable
        // synthetic job lifecycle here; the real restore admission/readiness
        // barrier is covered by the backup-route integration tests.
        let restore = state.storage.finish_backup_job(
            &restore_running.id,
            "succeeded",
            "ready",
            Some(&"a".repeat(64)),
            None,
        )?;
        (create, Some(validate), Some(restore))
    };
    let schema = state.storage.backup_v2_schema()?;
    let interruption_contained = !interrupted_faulted || create_terminal.status == "interrupted";
    let assertions = vec![
        assertion(
            "create_job_terminal",
            create_terminal.status == "succeeded",
            "backup create job reached a successful terminal state",
            "backup create job was interrupted",
        ),
        assertion(
            "validate_job_terminal",
            validate_terminal
                .as_ref()
                .is_some_and(|job| job.status == "succeeded"),
            "backup validation job reached a successful terminal state",
            "backup validation did not complete",
        ),
        assertion(
            "restore_job_terminal",
            restore_terminal
                .as_ref()
                .is_some_and(|job| job.status == "succeeded")
                && state.backup_maintenance().is_none(),
            "restore job reached its terminal state without maintenance residue",
            "restore job did not complete cleanly",
        ),
        assertion(
            "backup_schema_available",
            !schema.is_empty(),
            "backup v2 schema is available for validation",
            "backup v2 schema is unavailable",
        ),
        assertion(
            "interruption_contained",
            interruption_contained,
            "running backup interruption became a durable terminal state",
            "running backup interruption was not persisted",
        ),
        assertion(
            "job_identity_stable",
            created.id == running.id && create_terminal.backup_id == backup_id,
            "backup job identity remained stable through the lifecycle",
            "backup job identity changed during execution",
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
        file_id: created.id,
        assertions,
        receipt,
    })
}
