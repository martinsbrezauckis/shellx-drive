//! Durable, non-secret evidence for a desktop update restart.

use serde::{Deserialize, Serialize};

use crate::{DesktopError, Result};

mod agent;
mod readback;
#[cfg(test)]
mod tests;

const MAX_UPDATE_VERSION_BYTES: usize = 128;
const MAX_UPDATE_CANDIDATE_ID_BYTES: usize = 192;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DesktopUpdateRestartIntent {
    target_version: String,
    #[serde(default)]
    candidate_id: Option<String>,
    #[serde(default)]
    agent_command_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesktopUpdateRestartReadback {
    None,
    Applied {
        version: String,
        candidate_id: Option<String>,
        agent_command_id: Option<String>,
    },
    Unconfirmed {
        target_version: String,
        candidate_id: Option<String>,
        agent_command_id: Option<String>,
    },
}

impl DesktopUpdateRestartIntent {
    pub fn new(target_version: String, candidate_id: String) -> Result<Self> {
        validate_version(&target_version)?;
        validate_candidate_id(&candidate_id)?;
        Ok(Self {
            target_version,
            candidate_id: Some(candidate_id),
            agent_command_id: None,
        })
    }

    pub fn target_version(&self) -> &str {
        &self.target_version
    }

    pub fn candidate_id(&self) -> Option<&str> {
        self.candidate_id.as_deref()
    }

    pub fn agent_command_id(&self) -> Option<&str> {
        self.agent_command_id.as_deref()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_version(&self.target_version)?;
        self.candidate_id
            .as_deref()
            .map(validate_candidate_id)
            .transpose()?;
        match (&self.candidate_id, &self.agent_command_id) {
            (Some(_), Some(command_id)) => validate_candidate_id(command_id),
            (_, None) => Ok(()),
            (None, Some(_)) => Err(DesktopError::InvalidState(
                "desktop update agent command has no candidate ID".to_string(),
            )),
        }
    }
}

fn validate_version(version: &str) -> Result<()> {
    if version.is_empty()
        || version.len() > MAX_UPDATE_VERSION_BYTES
        || version.chars().any(char::is_control)
    {
        return Err(DesktopError::InvalidState(
            "desktop update version is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_candidate_id(candidate_id: &str) -> Result<()> {
    if candidate_id.is_empty()
        || candidate_id.len() > MAX_UPDATE_CANDIDATE_ID_BYTES
        || !candidate_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DesktopError::InvalidState(
            "desktop update candidate ID is invalid".to_string(),
        ));
    }
    Ok(())
}
