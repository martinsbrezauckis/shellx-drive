//! Keychain/Secret-Service credential stores with a private non-secret index.
//!
//! Neither macOS Keychain nor the portable Secret Service API exposes a safe
//! service-wide enumeration primitive through `keyring`. We therefore retain
//! only the exact account keys that this application successfully attempts in
//! a private, owner-only registry. Cleanup never infers a name, scans another
//! application's entries, or deletes when that registry cannot be verified.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::{
    CredentialStore, DesktopError, DisconnectCredentialNamespace, DisconnectCredentialSlot, Result,
};

const CANONICAL_SERVICE: &str = "com.shellx.drive.desktop";
const PENDING_SERVICE: &str = "com.shellx.drive.desktop.pending-candidate";
const DESKTOP_AGENT_DEVICE_SERVICE: &str = "com.shellx.drive.desktop.agent-device";
const DESKTOP_AGENT_DISCONNECT_SERVICE: &str = "com.shellx.drive.desktop.agent-disconnect";
const REGISTRY_DIRECTORY: &str = ".shellx-drive-credential-registry-v1";
const REGISTRY_FILE: &str = "service-account-keys.json";
const REGISTRY_VERSION: u8 = 1;

#[path = "unix/registry_validation.rs"]
mod registry_validation;
use registry_validation::{validate_account_key, validate_service};
#[path = "unix/desktop_agent.rs"]
mod desktop_agent;
#[cfg(target_os = "linux")]
pub use desktop_agent::{
    LinuxDesktopAgentCredentialStore, LinuxDesktopAgentDisconnectCredentialStore,
};
#[cfg(target_os = "macos")]
pub use desktop_agent::{
    MacOsDesktopAgentCredentialStore, MacOsDesktopAgentDisconnectCredentialStore,
};

/// Canonical Keychain store on macOS.
#[cfg(target_os = "macos")]
pub struct MacOsCredentialStore;
/// Pending-candidate Keychain store on macOS.
#[cfg(target_os = "macos")]
pub struct PendingMacOsCredentialStore;
/// Canonical Secret Service store on Linux.
#[cfg(target_os = "linux")]
pub struct LinuxCredentialStore;
/// Pending-candidate Secret Service store on Linux.
#[cfg(target_os = "linux")]
pub struct PendingLinuxCredentialStore;

macro_rules! credential_store {
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

            fn set(&self, account_key: &str, bearer_token: &str) -> Result<()> {
                // Persist the non-secret exact key first. A failed provider
                // write can leave a harmless stale registry entry, whereas a
                // provider success followed by an unrecorded registry failure
                // would make later exact cleanup impossible to prove.
                CredentialRegistry::load()?.insert($service, account_key)?;
                Self::entry(account_key)?
                    .set_password(bearer_token)
                    .map_err(|error| credential_error(error.to_string()))
            }

            fn delete(&self, account_key: &str) -> Result<()> {
                delete_exact($service, account_key)
            }
        }
    };
}

#[cfg(target_os = "macos")]
credential_store!(MacOsCredentialStore, CANONICAL_SERVICE);
#[cfg(target_os = "macos")]
credential_store!(PendingMacOsCredentialStore, PENDING_SERVICE);
#[cfg(target_os = "linux")]
credential_store!(LinuxCredentialStore, CANONICAL_SERVICE);
#[cfg(target_os = "linux")]
credential_store!(PendingLinuxCredentialStore, PENDING_SERVICE);

macro_rules! canonical_lifecycle {
    ($name:ident, $pending:ident, $agent:ident) => {
        impl $name {
            pub fn delete_service_credentials_except(account_key: &str) -> Result<()> {
                for key in Self::service_account_keys()? {
                    if key != account_key {
                        delete_exact(CANONICAL_SERVICE, &key)?;
                    }
                }
                if Self::service_account_keys()?
                    .iter()
                    .any(|key| key != account_key)
                {
                    return Err(credential_error(
                        "exact canonical cleanup was not confirmed",
                    ));
                }
                Ok(())
            }

            pub fn disconnect_credential_slots() -> Result<Vec<DisconnectCredentialSlot>> {
                let canonical = Self::service_account_keys()?
                    .into_iter()
                    .map(|account_key| DisconnectCredentialSlot {
                        namespace: DisconnectCredentialNamespace::Canonical,
                        account_key,
                    });
                let pending = $pending::service_account_keys()?
                    .into_iter()
                    .map(|account_key| DisconnectCredentialSlot {
                        namespace: DisconnectCredentialNamespace::PendingCandidate,
                        account_key,
                    });
                let agent = $agent::service_account_keys()?
                    .into_iter()
                    .map(|account_key| DisconnectCredentialSlot {
                        namespace: DisconnectCredentialNamespace::DesktopAgentDevice,
                        account_key,
                    });
                let mut slots = canonical.chain(pending).chain(agent).collect::<Vec<_>>();
                slots.sort();
                slots.dedup();
                Ok(slots)
            }

            pub fn delete_and_verify_disconnect_credential_slot(
                slot: &DisconnectCredentialSlot,
            ) -> Result<()> {
                match slot.namespace {
                    DisconnectCredentialNamespace::Canonical => {
                        delete_exact(CANONICAL_SERVICE, &slot.account_key)
                    }
                    DisconnectCredentialNamespace::PendingCandidate => {
                        delete_exact(PENDING_SERVICE, &slot.account_key)
                    }
                    DisconnectCredentialNamespace::DesktopAgentDevice => {
                        Err(credential_error(
                            "retained desktop-agent credential needs connection ownership recovery before cleanup",
                        ))
                    }
                    DisconnectCredentialNamespace::DesktopAgentDeviceScoped => {
                        crate::validate_desktop_agent_device_credential_key(&slot.account_key)?;
                        delete_exact(DESKTOP_AGENT_DEVICE_SERVICE, &slot.account_key)
                    }
                }
            }
        }
    };
}

#[cfg(target_os = "macos")]
canonical_lifecycle!(
    MacOsCredentialStore,
    PendingMacOsCredentialStore,
    MacOsDesktopAgentCredentialStore
);
#[cfg(target_os = "linux")]
canonical_lifecycle!(
    LinuxCredentialStore,
    PendingLinuxCredentialStore,
    LinuxDesktopAgentCredentialStore
);

fn get_exact(service: &str, account_key: &str) -> Result<Option<String>> {
    keyring::Entry::new(service, account_key)
        .map_err(|error| credential_error(error.to_string()))?
        .get_password()
        .map(Some)
        .or_else(|error| match error {
            keyring::Error::NoEntry => Ok(None),
            error => Err(credential_error(error.to_string())),
        })
}

fn delete_exact(service: &str, account_key: &str) -> Result<()> {
    let entry = keyring::Entry::new(service, account_key)
        .map_err(|error| credential_error(error.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => {}
        Err(error) => return Err(credential_error(error.to_string())),
    }
    if get_exact(service, account_key)?.is_some() {
        return Err(credential_error(
            "exact credential removal was not confirmed",
        ));
    }
    CredentialRegistry::load()?.remove(service, account_key)
}

fn delete_all_for_service(service: &str) -> Result<()> {
    for key in CredentialRegistry::load()?.keys(service)? {
        delete_exact(service, &key)?;
    }
    if !CredentialRegistry::load()?.keys(service)?.is_empty() {
        return Err(credential_error(
            "service credential cleanup was not confirmed",
        ));
    }
    Ok(())
}

fn credential_error(reason: impl AsRef<str>) -> DesktopError {
    DesktopError::Credential(format!(
        "{} credential storage is unavailable or could not be verified: {}",
        platform_label(),
        reason.as_ref()
    ))
}

#[cfg(target_os = "macos")]
fn platform_label() -> &'static str {
    "macOS Keychain"
}

#[cfg(target_os = "linux")]
fn platform_label() -> &'static str {
    "Linux Secret Service"
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    version: u8,
    services: BTreeMap<String, BTreeSet<String>>,
}

struct CredentialRegistry {
    path: PathBuf,
    file: RegistryFile,
}

impl CredentialRegistry {
    fn load() -> Result<Self> {
        let directory = registry_directory()?;
        Self::load_from_path(directory.join(REGISTRY_FILE))
    }

    fn load_from_path(path: PathBuf) -> Result<Self> {
        let file = match fs::read(&path) {
            Ok(bytes) => {
                verify_private_file(&path)?;
                let file = serde_json::from_slice::<RegistryFile>(&bytes)
                    .map_err(|error| credential_error(error.to_string()))?;
                if file.version != REGISTRY_VERSION {
                    return Err(credential_error(
                        "credential registry version is unsupported",
                    ));
                }
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => RegistryFile {
                version: REGISTRY_VERSION,
                ..RegistryFile::default()
            },
            Err(error) => return Err(DesktopError::Io(error)),
        };
        Ok(Self { path, file })
    }

    fn keys(&self, service: &str) -> Result<Vec<String>> {
        validate_service(service)?;
        Ok(self
            .file
            .services
            .get(service)
            .into_iter()
            .flatten()
            .cloned()
            .collect())
    }

    fn insert(&mut self, service: &str, account_key: &str) -> Result<()> {
        validate_service(service)?;
        validate_account_key(account_key)?;
        self.file
            .services
            .entry(service.to_string())
            .or_default()
            .insert(account_key.to_string());
        self.persist()
    }

    fn remove(&mut self, service: &str, account_key: &str) -> Result<()> {
        validate_service(service)?;
        if let Some(keys) = self.file.services.get_mut(service) {
            keys.remove(account_key);
            if keys.is_empty() {
                self.file.services.remove(service);
            }
        }
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| credential_error("registry has no parent"))?;
        let bytes = serde_json::to_vec(&self.file)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".shellx-drive-credential-registry-")
            .suffix(".next")
            .tempfile_in(parent)?;
        verify_private_file(temporary.path())?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.path).map_err(|error| error.error)?;
        verify_private_file(&self.path)
    }
}

#[path = "unix/uninstall_registry.rs"]
mod uninstall_registry;
pub use uninstall_registry::uninstall_credential_registry_empty;

fn registry_directory() -> Result<PathBuf> {
    let data = crate::state::default_state_directory()?;
    let directory = data.join(REGISTRY_DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Ok(_) => verify_private_directory(&directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(&directory)?;
        }
        Err(error) => return Err(DesktopError::Io(error)),
    }
    Ok(directory)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new().mode(0o700).create(path)?;
    verify_private_directory(path)
}

#[cfg(unix)]
fn verify_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(credential_error(
            "credential registry directory is not private",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(credential_error("credential registry file is not private"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "unix/registry_tests.rs"]
mod registry_tests;
