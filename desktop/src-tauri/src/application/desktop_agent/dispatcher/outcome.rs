//! Exact bounded terminal outcomes for one broker command.

use shellx_drive_desktop_core::{
    DesktopAgentResultCode, DesktopAgentResultPayload, DesktopAgentTerminalCode,
    DesktopAgentTerminalStatus,
};

#[derive(Clone)]
pub(in crate::application::desktop_agent) struct CommandOutcome {
    pub(super) status: DesktopAgentTerminalStatus,
    pub(super) code: DesktopAgentTerminalCode,
    pub(super) result_code: Option<DesktopAgentResultCode>,
    pub(super) result: Option<DesktopAgentResultPayload>,
}

impl CommandOutcome {
    pub(super) fn succeeded(
        result_code: DesktopAgentResultCode,
        result: DesktopAgentResultPayload,
    ) -> Self {
        Self {
            status: DesktopAgentTerminalStatus::Succeeded,
            code: DesktopAgentTerminalCode::Completed,
            result_code: Some(result_code),
            result: Some(result),
        }
    }

    pub(super) fn local_gesture() -> Self {
        Self {
            status: DesktopAgentTerminalStatus::Rejected,
            code: DesktopAgentTerminalCode::RequiresLocalGesture,
            result_code: None,
            result: None,
        }
    }

    pub(super) fn failed() -> Self {
        Self {
            status: DesktopAgentTerminalStatus::Failed,
            code: DesktopAgentTerminalCode::NativeDispatchFailed,
            result_code: None,
            result: None,
        }
    }

    pub(super) fn failed_with(code: DesktopAgentTerminalCode) -> Self {
        Self {
            status: DesktopAgentTerminalStatus::Failed,
            code,
            result_code: None,
            result: None,
        }
    }
}
