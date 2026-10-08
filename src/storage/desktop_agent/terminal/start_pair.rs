use crate::desktop_agent::{DesktopAgentCommandPayload, DesktopAgentResultPayload};

pub(super) fn result_matches(
    payload: &DesktopAgentCommandPayload,
    result: &DesktopAgentResultPayload,
) -> Option<bool> {
    let (
        DesktopAgentCommandPayload::StartPair { workspace_id },
        DesktopAgentResultPayload::RootsRefreshed {
            workspace_id: observed_workspace_id,
            added_root_count,
            existing_root_count,
        },
    ) = (payload, result)
    else {
        return None;
    };
    Some(
        workspace_id == observed_workspace_id
            && (*added_root_count > 0 || *existing_root_count > 0),
    )
}
