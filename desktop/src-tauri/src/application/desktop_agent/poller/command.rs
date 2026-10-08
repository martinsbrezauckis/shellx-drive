//! Broker outcome reporting after a native command dispatcher returns.

use shellx_drive_desktop_core::Result as CoreResult;
use tauri::AppHandle;

use super::{
    super::dispatcher::{record_and_report_terminal, CommandExecution},
    resume_agent_disconnect_completion, CommandLease, Runtime,
};

pub(super) async fn finish_command_execution(
    app: &AppHandle,
    runtime: &Runtime,
    lease: CommandLease<'_>,
    execution: CommandExecution,
) -> CoreResult<()> {
    match execution {
        CommandExecution::Terminal(outcome) => {
            record_and_report_terminal(
                runtime,
                lease.client,
                lease.device_credential,
                lease.command_id,
                lease.lease_id,
                outcome,
            )
            .await
        }
        CommandExecution::DisconnectPending => {
            resume_agent_disconnect_completion(app);
            Ok(())
        }
        CommandExecution::DisconnectInterrupted => {
            super::start_polling(app, runtime);
            Ok(())
        }
        CommandExecution::RelaunchPending
        | CommandExecution::DisconnectCompleted
        | CommandExecution::DisconnectBlocked => Ok(()),
    }
}
