use crate::{DesktopError, DesktopState, Result};

use super::{validate_version, DesktopUpdateRestartIntent, DesktopUpdateRestartReadback};

impl DesktopState {
    pub fn record_desktop_update_restart(
        &mut self,
        target_version: String,
        candidate_id: String,
    ) -> Result<()> {
        self.pending_desktop_update_restart = Some(DesktopUpdateRestartIntent::new(
            target_version,
            candidate_id,
        )?);
        Ok(())
    }

    pub fn read_desktop_update_restart(
        &mut self,
        running_version: &str,
    ) -> Result<DesktopUpdateRestartReadback> {
        validate_version(running_version)?;
        let Some(intent) = self.pending_desktop_update_restart.as_ref() else {
            return Ok(DesktopUpdateRestartReadback::None);
        };
        if intent.target_version == running_version {
            let version = intent.target_version.clone();
            let candidate_id = intent.candidate_id.clone();
            let agent_command_id = intent.agent_command_id.clone();
            if agent_command_id.is_none() {
                self.pending_desktop_update_restart = None;
            }
            Ok(DesktopUpdateRestartReadback::Applied {
                version,
                candidate_id,
                agent_command_id,
            })
        } else {
            Ok(DesktopUpdateRestartReadback::Unconfirmed {
                target_version: intent.target_version.clone(),
                candidate_id: intent.candidate_id.clone(),
                agent_command_id: intent.agent_command_id.clone(),
            })
        }
    }

    pub fn cancel_desktop_update_restart(&mut self, candidate_id: &str) -> Result<()> {
        let Some(intent) = self.pending_desktop_update_restart.as_ref() else {
            return Ok(());
        };
        if intent.candidate_id() != Some(candidate_id) {
            return Err(DesktopError::InvalidState(
                "desktop update restart cancellation does not match intent".to_string(),
            ));
        }
        self.pending_desktop_update_restart = None;
        Ok(())
    }
}
