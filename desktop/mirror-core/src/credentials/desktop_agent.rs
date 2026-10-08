//! Fixed Windows Credential Manager namespace for device-broker secrets.

use crate::{CredentialStore, DesktopError, Result};

use super::{
    delete_all_service_credentials_for, delete_and_verify_service_credential_for,
    entry_for_service, service_account_keys_for,
};

use super::{
    WINDOWS_DESKTOP_AGENT_CREDENTIAL_SERVICE as DEVICE_SERVICE,
    WINDOWS_DESKTOP_AGENT_DISCONNECT_SERVICE as DISCONNECT_SERVICE,
};

/// Exact Credential Manager service for `sxd_device_` credentials. It never
/// shares a service name with owner session bearers or staged candidates.
pub struct WindowsDesktopAgentCredentialStore;
/// Completion capabilities remain separate from device credentials so normal
/// Disconnect credential cleanup cannot erase a pending terminal retry.
pub struct WindowsDesktopAgentDisconnectCredentialStore;

impl WindowsDesktopAgentCredentialStore {
    fn entry(account_key: &str) -> Result<keyring::Entry> {
        entry_for_service(DEVICE_SERVICE, account_key)
    }

    pub fn service_account_keys() -> Result<Vec<String>> {
        service_account_keys_for(DEVICE_SERVICE)
    }

    pub fn delete_all_service_credentials() -> Result<()> {
        delete_all_service_credentials_for(DEVICE_SERVICE)
    }
}

impl CredentialStore for WindowsDesktopAgentCredentialStore {
    fn get(&self, account_key: &str) -> Result<Option<String>> {
        Self::entry(account_key)?
            .get_password()
            .map(Some)
            .or_else(|error| match error {
                keyring::Error::NoEntry => Ok(None),
                error => Err(DesktopError::Credential(error.to_string())),
            })
    }

    fn set(&self, account_key: &str, credential: &str) -> Result<()> {
        Self::entry(account_key)?
            .set_password(credential)
            .map_err(|error| DesktopError::Credential(error.to_string()))
    }

    fn delete(&self, account_key: &str) -> Result<()> {
        delete_and_verify_service_credential_for(DEVICE_SERVICE, account_key)
    }
}

impl WindowsDesktopAgentDisconnectCredentialStore {
    fn entry(account_key: &str) -> Result<keyring::Entry> {
        entry_for_service(DISCONNECT_SERVICE, account_key)
    }

    pub fn service_account_keys() -> Result<Vec<String>> {
        service_account_keys_for(DISCONNECT_SERVICE)
    }

    pub fn delete_all_service_credentials() -> Result<()> {
        delete_all_service_credentials_for(DISCONNECT_SERVICE)
    }
}

impl CredentialStore for WindowsDesktopAgentDisconnectCredentialStore {
    fn get(&self, account_key: &str) -> Result<Option<String>> {
        Self::entry(account_key)?
            .get_password()
            .map(Some)
            .or_else(|error| match error {
                keyring::Error::NoEntry => Ok(None),
                error => Err(DesktopError::Credential(error.to_string())),
            })
    }

    fn set(&self, account_key: &str, credential: &str) -> Result<()> {
        Self::entry(account_key)?
            .set_password(credential)
            .map_err(|error| DesktopError::Credential(error.to_string()))
    }

    fn delete(&self, account_key: &str) -> Result<()> {
        delete_and_verify_service_credential_for(DISCONNECT_SERVICE, account_key)
    }
}
