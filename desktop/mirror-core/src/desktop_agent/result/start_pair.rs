use crate::{DesktopError, Result};

use super::{ensure_opaque_id, DesktopAgentResultPayload};

pub(super) fn validate_roots_refreshed(result: &DesktopAgentResultPayload) -> Result<()> {
    let DesktopAgentResultPayload::RootsRefreshed {
        workspace_id,
        added_root_count,
        existing_root_count,
    } = result
    else {
        unreachable!("caller matches only roots-refreshed results");
    };
    ensure_opaque_id("workspace ID", workspace_id)?;
    if *added_root_count == 0 && *existing_root_count == 0 {
        return Err(DesktopError::InvalidState(
            "desktop-agent root refresh did not retain an authorized workspace root".to_string(),
        ));
    }
    Ok(())
}
