//! Unpaired retries for the capability-authenticated Disconnect continuation.

use chrono::Utc;
use std::time::Duration;
use tauri::{AppHandle, Manager};

use super::super::dispatcher::resume_pending_disconnect_completion;
use super::{Runtime, AGENT_POLL_INTERVAL};

const AGENT_DISCONNECT_LOCAL_FINALIZATION_RETRIES: usize = 3;

#[cfg(test)]
#[path = "disconnect_tests.rs"]
mod tests;

/// Resume a capability-authenticated Disconnect completion even after local
/// cleanup removed the paired session and disabled normal device polling.
pub(crate) fn resume_agent_disconnect_completion(app: &AppHandle) {
    let manager = app.state::<crate::application::ConnectionManager>();
    for runtime in manager.all_runtimes() {
        resume_for_runtime(app, runtime);
    }
}

fn resume_for_runtime(app: &AppHandle, runtime: std::sync::Arc<Runtime>) {
    if runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .is_none()
    {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut local_finalization_failures = 0;
        loop {
            match resume_pending_disconnect_completion(&runtime).await {
                Ok(()) => {
                    super::start_polling(&app, &runtime);
                    return;
                }
                Err(error) => {
                    eprintln!(
                        "ShellX Drive desktop-agent Disconnect completion remains pending: {error}"
                    );
                }
            }
            let Some(delay) = next_retry_delay(&runtime, &mut local_finalization_failures) else {
                return;
            };
            tokio::time::sleep(delay).await;
        }
    });
}

fn next_retry_delay(runtime: &Runtime, local_failures: &mut usize) -> Option<Duration> {
    let continuation = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()?;
    next_retry_delay_for(&continuation, Utc::now(), local_failures)
}

fn next_retry_delay_for(
    continuation: &shellx_drive_desktop_core::DesktopAgentDisconnectContinuation,
    now: chrono::DateTime<Utc>,
    local_failures: &mut usize,
) -> Option<Duration> {
    if !continuation.requires_capability_retry() {
        return None;
    }
    let requires_local_finalization = matches!(
        continuation.phase,
        shellx_drive_desktop_core::DesktopAgentDisconnectPhase::TerminalAccepted
            | shellx_drive_desktop_core::DesktopAgentDisconnectPhase::RetirementCancelled
            | shellx_drive_desktop_core::DesktopAgentDisconnectPhase::RetirementBlocked
            | shellx_drive_desktop_core::DesktopAgentDisconnectPhase::CompletionBlocked
    ) || now >= continuation.completion_expires_at;
    if requires_local_finalization {
        if *local_failures == 0 {
            *local_failures = 1;
            return Some(Duration::ZERO);
        }
        if *local_failures <= AGENT_DISCONNECT_LOCAL_FINALIZATION_RETRIES {
            *local_failures += 1;
            return Some(AGENT_POLL_INTERVAL);
        }
        return None;
    }
    (continuation.completion_expires_at - now)
        .to_std()
        .ok()
        .map(|remaining| remaining.min(AGENT_POLL_INTERVAL))
}
