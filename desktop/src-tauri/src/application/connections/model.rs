use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use shellx_drive_desktop_core::{DesktopError, DirectoryIdentity, Result as CoreResult};

use crate::session_identity::SessionIdentity;

pub(crate) const LEGACY_CONNECTION_ID: &str = "legacy";
pub(crate) const MAX_CONNECTIONS: usize = 16;
pub(crate) const MAX_RESERVED_FOLDERS: usize = 128;
pub(crate) const SYNC_INTERVALS: [u64; 6] = [20, 60, 300, 900, 1_800, 3_600];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AppPreferences {
    pub(crate) initialized: bool,
    pub(crate) theme: String,
    pub(crate) launch_at_login: bool,
    pub(crate) default_sync_interval_seconds: u64,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            initialized: false,
            theme: "system".to_string(),
            launch_at_login: true,
            default_sync_interval_seconds: 20,
        }
    }
}

impl AppPreferences {
    pub(super) fn validate(&self) -> CoreResult<()> {
        if !matches!(self.theme.as_str(), "system" | "light" | "dark")
            || !SYNC_INTERVALS.contains(&self.default_sync_interval_seconds)
        {
            return Err(invalid("invalid app appearance or sync check interval"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConnectionLifecycle {
    Preparing,
    Active,
    Removing,
    Recovery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConnectionStorage {
    Legacy,
    Profile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConnectionIdentity {
    pub(super) server_url: String,
    pub(super) account_email: String,
}

impl ConnectionIdentity {
    pub(super) fn session(&self) -> SessionIdentity {
        SessionIdentity::new(&self.server_url, &self.account_email)
    }

    pub(super) fn from_session(identity: SessionIdentity) -> Self {
        Self {
            server_url: identity.server_url,
            account_email: identity.email,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ReservedFolder {
    pub(super) path: PathBuf,
    pub(super) identity: Option<DirectoryIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConnectionProfile {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) storage: ConnectionStorage,
    pub(super) identity: Option<ConnectionIdentity>,
    pub(super) interval_seconds: Option<u64>,
    pub(super) lifecycle: ConnectionLifecycle,
    pub(super) reserved_folders: Vec<ReservedFolder>,
    pub(super) recovery_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AppCatalog {
    pub(super) schema_version: u32,
    pub(super) preferences: AppPreferences,
    pub(super) connections: Vec<ConnectionProfile>,
    /// Retained state directories must not be rediscovered as orphan setup.
    #[serde(default)]
    pub(super) retired_ids: Vec<String>,
}

impl Default for AppCatalog {
    fn default() -> Self {
        Self {
            schema_version: 1,
            preferences: AppPreferences::default(),
            connections: Vec::new(),
            retired_ids: Vec::new(),
        }
    }
}

impl AppCatalog {
    pub(super) fn validate(&self) -> CoreResult<()> {
        self.preferences.validate()?;
        if self.schema_version != 1
            || self.connections.len() > MAX_CONNECTIONS
            || self.retired_ids.len() > 256
        {
            return Err(invalid("unsupported or oversized connection catalog"));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut identities = std::collections::BTreeSet::new();
        for id in &self.retired_ids {
            validate_id(id)?;
            if !ids.insert(id) {
                return Err(invalid("duplicate retired connection ID"));
            }
        }
        for profile in &self.connections {
            validate_id(&profile.id)?;
            validate_name(&profile.name)?;
            if !ids.insert(&profile.id)
                || (profile.storage == ConnectionStorage::Legacy)
                    != (profile.id == LEGACY_CONNECTION_ID)
                || profile
                    .interval_seconds
                    .is_some_and(|value| !SYNC_INTERVALS.contains(&value))
                || profile.reserved_folders.len() > MAX_RESERVED_FOLDERS
                || profile
                    .recovery_error
                    .as_ref()
                    .is_some_and(|value| value.len() > 2_048)
            {
                return Err(invalid("invalid or duplicate connection profile"));
            }
            if let Some(identity) = &profile.identity {
                let canonical = verified_identity(&identity.server_url, &identity.account_email)?;
                if canonical.server_url != identity.server_url
                    || canonical.email != identity.account_email
                    || !identities.insert(canonical.credential_key())
                {
                    return Err(invalid(
                        "invalid or duplicate reserved server/account identity",
                    ));
                }
            }
            for folder in &profile.reserved_folders {
                if !folder.path.is_absolute()
                    || folder.path.as_os_str().len() > 32_768
                    || folder
                        .path
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
                {
                    return Err(invalid("invalid reserved local folder"));
                }
            }
        }
        Ok(())
    }
}

pub(super) fn validate_id(id: &str) -> CoreResult<()> {
    if id == LEGACY_CONNECTION_ID {
        return Ok(());
    }
    match uuid::Uuid::parse_str(id) {
        Ok(value) if value.hyphenated().to_string() == id => Ok(()),
        _ => Err(invalid("unknown or invalid connection ID")),
    }
}

pub(super) fn validate_name(name: &str) -> CoreResult<()> {
    if name.is_empty()
        || name.len() > 160
        || name != name.trim()
        || name.chars().any(char::is_control)
    {
        return Err(invalid(
            "connection name must contain 1 to 160 printable bytes",
        ));
    }
    Ok(())
}

pub(super) fn verified_identity(server_url: &str, email: &str) -> CoreResult<SessionIdentity> {
    // The caller obtains `email` from a successful authenticated server reply.
    // This function only canonicalizes it; parsing a token is not verification.
    let client = shellx_drive_desktop_core::DriveHttpClient::new(server_url)?;
    let email = email.trim().to_ascii_lowercase();
    if email.is_empty()
        || email.len() > 254
        || email
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(invalid("Drive returned an invalid account identity"));
    }
    Ok(SessionIdentity::new(client.normalized_url(), email))
}

pub(super) fn invalid(message: impl Into<String>) -> DesktopError {
    DesktopError::InvalidState(message.into())
}
