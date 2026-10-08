use rusqlite::Transaction;

use crate::{
    desktop_agent::{
        validate_result_payload, DesktopAgentCommandPayload, DesktopAgentResultPayload,
        DesktopAgentTerminalCode, DesktopAgentTerminalRequest, DesktopAgentTerminalStatus,
    },
    error::{ApiError, ApiResult},
};

use super::rows::CommandRow;

mod start_pair;

#[cfg(test)]
#[path = "terminal/tests.rs"]
mod tests;

pub(super) fn validate_terminal_request(
    command: &CommandRow,
    request: &DesktopAgentTerminalRequest,
) -> ApiResult<()> {
    match request.status {
        DesktopAgentTerminalStatus::Succeeded
            if request.terminal_code == DesktopAgentTerminalCode::Completed
                && request.result_code == command.kind.successful_result_code() =>
        {
            let result = request.result.as_ref().ok_or_else(invalid_terminal)?;
            validate_result_payload(&command.payload, result).map_err(|_| invalid_terminal())?;
            validate_result_matches_payload(&command.payload, result)
        }
        DesktopAgentTerminalStatus::Succeeded => Err(invalid_terminal()),
        _ if request.terminal_code != DesktopAgentTerminalCode::Completed
            && request.result_code.is_none()
            && request.result.is_none() =>
        {
            Ok(())
        }
        _ => Err(invalid_terminal()),
    }
}

pub(super) fn terminal_retry_matches(
    tx: &Transaction<'_>,
    command: &CommandRow,
    command_id: &str,
    request: &DesktopAgentTerminalRequest,
) -> ApiResult<bool> {
    if !command.status.is_terminal()
        || command.status != request.status.into()
        || command.terminal_code != Some(request.terminal_code)
        || command.result_code != request.result_code
        || command.result != request.result
        || request.assertion.last_terminal_command_id.as_deref() != Some(command_id)
    {
        return Ok(false);
    }
    let sequence = tx.query_row(
        "SELECT terminal_event_sequence FROM desktop_agent_commands WHERE id = ?1",
        [command_id],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    Ok(sequence == Some(request.event_sequence))
}

fn validate_result_matches_payload(
    payload: &DesktopAgentCommandPayload,
    result: &DesktopAgentResultPayload,
) -> ApiResult<()> {
    let matches = match (payload, result) {
        (
            DesktopAgentCommandPayload::SetPaused { paused },
            DesktopAgentResultPayload::Pause {
                paused: observed_paused,
            },
        ) => paused == observed_paused,
        (
            DesktopAgentCommandPayload::SetLaunchAtLogin { enabled },
            DesktopAgentResultPayload::LaunchAtLogin {
                enabled: observed_enabled,
            },
        ) => enabled == observed_enabled,
        (
            DesktopAgentCommandPayload::PrepareReviewAction {
                pair_id,
                review_id,
                action,
            },
            DesktopAgentResultPayload::ReviewPrepared {
                pair_id: observed_pair_id,
                review_id: observed_review_id,
                action: observed_action,
                ..
            },
        ) => {
            observed_pair_id.as_deref() == pair_id.as_deref()
                && pair_id.is_some()
                && review_id == observed_review_id
                && action == observed_action
        }
        (
            DesktopAgentCommandPayload::ConfirmReviewAction {
                pair_id,
                review_id,
                action,
                prepared_confirmation_id,
                fingerprint,
            },
            DesktopAgentResultPayload::ReviewConfirmed {
                pair_id: observed_pair_id,
                review_id: observed_review_id,
                action: observed_action,
                prepared_confirmation_id: observed_prepared_confirmation_id,
                fingerprint: observed_fingerprint,
            },
        ) => {
            observed_pair_id.as_deref() == pair_id.as_deref()
                && pair_id.is_some()
                && review_id == observed_review_id
                && action == observed_action
                && prepared_confirmation_id == observed_prepared_confirmation_id
                && fingerprint == observed_fingerprint
        }
        (
            DesktopAgentCommandPayload::InstallDesktopUpdate { candidate_id },
            DesktopAgentResultPayload::UpdateInstall {
                candidate_id: observed_candidate_id,
                ..
            },
        ) => candidate_id == observed_candidate_id,
        (
            DesktopAgentCommandPayload::OpenLocalFolder { pair_id },
            DesktopAgentResultPayload::LocalFolderDispatch {
                dispatched,
                pair_id: observed_pair_id,
            },
        )
        | (
            DesktopAgentCommandPayload::OpenDrive { pair_id },
            DesktopAgentResultPayload::DriveDispatch {
                dispatched,
                pair_id: observed_pair_id,
            },
        ) => *dispatched && (pair_id.is_none() || pair_id == observed_pair_id),
        (
            DesktopAgentCommandPayload::Disconnect,
            DesktopAgentResultPayload::Disconnect { cleanup_completed },
        ) => *cleanup_completed,
        (
            DesktopAgentCommandPayload::SelectPair { pair_id },
            DesktopAgentResultPayload::PairSelected {
                pair_id: observed_pair_id,
            },
        ) => pair_id == observed_pair_id,
        _ => start_pair::result_matches(payload, result).unwrap_or(true),
    };
    matches.then_some(()).ok_or_else(invalid_terminal)
}

fn invalid_terminal() -> ApiError {
    ApiError::Validation("invalid_desktop_agent_terminal".to_string())
}
