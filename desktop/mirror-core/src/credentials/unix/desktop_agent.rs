//! Separate OS credential namespaces for device and Disconnect capabilities.

use crate::{CredentialStore, Result};

use super::{
    credential_error, delete_all_for_service, delete_exact, get_exact, CredentialRegistry,
    DESKTOP_AGENT_DEVICE_SERVICE, DESKTOP_AGENT_DISCONNECT_SERVICE,
};

macro_rules! desktop_agent_store {
    ($name:ident, $service:expr) => {
        impl $name {
            pub fn service_account_keys() -> Result<Vec<String>> {
                CredentialRegistry::load()?.keys($service)
            }

            pub fn delete_all_service_credentials() -> Result<()> {
                delete_all_for_service($service)
            }

            fn entry(account_key: &str) -> Result<keyring::Entry> {
                keyring::Entry::new($service, account_key)
                    .map_err(|error| credential_error(error.to_string()))
            }
        }

        impl CredentialStore for $name {
            fn get(&self, account_key: &str) -> Result<Option<String>> {
                get_exact($service, account_key)
            }

            fn set(&self, account_key: &str, value: &str) -> Result<()> {
                CredentialRegistry::load()?.insert($service, account_key)?;
                Self::entry(account_key)?
                    .set_password(value)
                    .map_err(|error| credential_error(error.to_string()))
            }

            fn delete(&self, account_key: &str) -> Result<()> {
                delete_exact($service, account_key)
            }
        }
    };
}

/// Broker device credentials never share a namespace with Drive sessions.
#[cfg(target_os = "macos")]
pub struct MacOsDesktopAgentCredentialStore;
/// Disconnect completion capabilities stay distinct from device credentials.
#[cfg(target_os = "macos")]
pub struct MacOsDesktopAgentDisconnectCredentialStore;
/// Broker device credentials never share a namespace with Drive sessions.
#[cfg(target_os = "linux")]
pub struct LinuxDesktopAgentCredentialStore;
/// Disconnect completion capabilities stay distinct from device credentials.
#[cfg(target_os = "linux")]
pub struct LinuxDesktopAgentDisconnectCredentialStore;

#[cfg(target_os = "macos")]
desktop_agent_store!(
    MacOsDesktopAgentCredentialStore,
    DESKTOP_AGENT_DEVICE_SERVICE
);
#[cfg(target_os = "macos")]
desktop_agent_store!(
    MacOsDesktopAgentDisconnectCredentialStore,
    DESKTOP_AGENT_DISCONNECT_SERVICE
);
#[cfg(target_os = "linux")]
desktop_agent_store!(
    LinuxDesktopAgentCredentialStore,
    DESKTOP_AGENT_DEVICE_SERVICE
);
#[cfg(target_os = "linux")]
desktop_agent_store!(
    LinuxDesktopAgentDisconnectCredentialStore,
    DESKTOP_AGENT_DISCONNECT_SERVICE
);
