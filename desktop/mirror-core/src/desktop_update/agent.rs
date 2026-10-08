use crate::{DesktopError, DesktopState, Result};

use super::{validate_candidate_id, DesktopUpdateRestartIntent};

impl DesktopUpdateRestartIntent {
    pub fn for_agent(
        target_version: String,
        candidate_id: String,
        command_id: String,
    ) -> Result<Self> {
        let mut intent = Self::new(target_version, candidate_id)?;
        validate_candidate_id(&command_id)?;
        intent.agent_command_id = Some(command_id);
        Ok(intent)
    }
}

impl DesktopState {
    pub fn record_desktop_update_restart_for_agent(
        &mut self,
        target_version: String,
        candidate_id: String,
        command_id: String,
    ) -> Result<()> {
        self.pending_desktop_update_restart = Some(DesktopUpdateRestartIntent::for_agent(
            target_version,
            candidate_id,
            command_id,
        )?);
        Ok(())
    }

    pub fn complete_desktop_update_restart_for_agent(
        &mut self,
        candidate_id: &str,
        command_id: &str,
    ) -> Result<()> {
        let Some(intent) = self.pending_desktop_update_restart.as_ref() else {
            return Ok(());
        };
        if intent.candidate_id() != Some(candidate_id)
            || intent.agent_command_id() != Some(command_id)
        {
            return Err(DesktopError::InvalidState(
                "desktop update restart completion does not match intent".to_string(),
            ));
        }
        self.pending_desktop_update_restart = None;
        Ok(())
    }

    /// Clear local agent records after confirmed retirement; the caller persists the state.
    pub fn retire_desktop_agent_control(&mut self) {
        self.desktop_agent_control.clear_after_retirement();
        let _ = self
            .pending_desktop_update_restart
            .take_if(|intent| intent.agent_command_id().is_some());
    }
}
