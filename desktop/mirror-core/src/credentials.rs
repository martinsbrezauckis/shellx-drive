use std::{collections::BTreeMap, sync::Mutex};

#[cfg(target_os = "windows")]
use crate::DesktopError;
use crate::Result;

#[cfg(target_os = "windows")]
mod desktop_agent;
#[cfg(target_os = "windows")]
mod disconnect;
mod exact;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use unix::uninstall_credential_registry_empty;

#[cfg(target_os = "windows")]
pub use desktop_agent::{
    WindowsDesktopAgentCredentialStore, WindowsDesktopAgentDisconnectCredentialStore,
};
pub use exact::{
    classify_exact_credential_readback, classify_exact_credential_removal,
    classify_exact_credential_write, ExactCredentialRead, ExactCredentialRemoval,
    ExactCredentialWrite,
};
#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use unix::{LinuxCredentialStore, PendingLinuxCredentialStore};
#[cfg(target_os = "linux")]
pub use unix::{LinuxDesktopAgentCredentialStore, LinuxDesktopAgentDisconnectCredentialStore};
#[cfg(target_os = "macos")]
#[allow(unused_imports)]
pub use unix::{MacOsCredentialStore, PendingMacOsCredentialStore};
#[cfg(target_os = "macos")]
pub use unix::{MacOsDesktopAgentCredentialStore, MacOsDesktopAgentDisconnectCredentialStore};

#[cfg(any(target_os = "windows", test))]
const WINDOWS_CREDENTIAL_SERVICE: &str = "com.shellx.drive.desktop";
#[cfg(target_os = "windows")]
const WINDOWS_PENDING_CREDENTIAL_SERVICE: &str = "com.shellx.drive.desktop.pending-candidate";
#[cfg(target_os = "windows")]
const WINDOWS_DESKTOP_AGENT_CREDENTIAL_SERVICE: &str = "com.shellx.drive.desktop.agent-device";
#[cfg(target_os = "windows")]
const WINDOWS_DESKTOP_AGENT_DISCONNECT_SERVICE: &str = "com.shellx.drive.desktop.agent-disconnect";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_KEYRING_TARGET_DIVIDER: &str = ".";

/// Platform credential boundary. Callers pass only an account-specific key and
/// bearer value; serializable desktop state never sees either value.
pub trait CredentialStore: Send + Sync {
    fn get(&self, account_key: &str) -> Result<Option<String>>;
    fn set(&self, account_key: &str, bearer_token: &str) -> Result<()>;
    fn delete(&self, account_key: &str) -> Result<()>;
}

#[derive(Default)]
pub struct FakeCredentialStore {
    values: Mutex<BTreeMap<String, String>>,
}

impl CredentialStore for FakeCredentialStore {
    fn get(&self, account_key: &str) -> Result<Option<String>> {
        Ok(self
            .values
            .lock()
            .expect("fake credential lock")
            .get(account_key)
            .cloned())
    }

    fn set(&self, account_key: &str, bearer_token: &str) -> Result<()> {
        self.values
            .lock()
            .expect("fake credential lock")
            .insert(account_key.to_string(), bearer_token.to_string());
        Ok(())
    }

    fn delete(&self, account_key: &str) -> Result<()> {
        self.values
            .lock()
            .expect("fake credential lock")
            .remove(account_key);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub struct WindowsCredentialStore;

/// Pending candidate bearers never share the canonical service namespace.
/// That prevents an ambiguous candidate cleanup from replacing the only
/// authorizer for the already-paired account.
#[cfg(target_os = "windows")]
pub struct PendingWindowsCredentialStore;

#[cfg(target_os = "windows")]
struct ServiceCredentialTarget {
    target_name: String,
    account_key: String,
}

#[cfg(target_os = "windows")]
impl WindowsCredentialStore {
    fn entry(account_key: &str) -> Result<keyring::Entry> {
        entry_for_service(WINDOWS_CREDENTIAL_SERVICE, account_key)
    }

    /// Removes every generic Credential Manager record that this app's
    /// `keyring` service can have created for the current Windows user.
    ///
    /// The Windows-native keyring backend stores `Entry::new(service, user)`
    /// at the exact target name `{user}.{service}` and also stores `user` in
    /// the credential metadata. We require both values to agree before a
    /// delete, never inspect `CredentialBlob`, and re-enumerate afterwards.
    /// A malformed record claiming our suffix causes an error rather than a
    /// broad deletion, so the NSIS hook can leave the installed cleanup mode
    /// available for a safe retry.
    pub fn delete_all_service_credentials() -> Result<()> {
        delete_all_service_credentials_for(WINDOWS_CREDENTIAL_SERVICE)
    }

    /// Removes exact service records other than the newly published session.
    /// The retained key is still exact service metadata, not a prefix or a
    /// caller-controlled deletion pattern.
    pub fn delete_service_credentials_except(account_key: &str) -> Result<()> {
        let targets = enumerate_service_credential_targets(WINDOWS_CREDENTIAL_SERVICE)?;
        for target in targets
            .iter()
            .filter(|target| target.account_key != account_key)
        {
            delete_service_credential(&target.target_name)?;
        }

        if enumerate_service_credential_targets(WINDOWS_CREDENTIAL_SERVICE)?
            .iter()
            .any(|target| target.account_key != account_key)
        {
            return Err(credential_cleanup_error(
                "credential removal was not complete",
            ));
        }
        Ok(())
    }

    /// Enumerates only the non-secret account keys attached to this app's exact
    /// fixed-service records. Callers may use those keys with [`CredentialStore`]
    /// to retire superseded sessions without reading arbitrary Credential
    /// Manager records or exposing target metadata outside the process.
    pub fn service_account_keys() -> Result<Vec<String>> {
        service_account_keys_for(WINDOWS_CREDENTIAL_SERVICE)
    }
}

#[cfg(target_os = "windows")]
impl PendingWindowsCredentialStore {
    fn entry(account_key: &str) -> Result<keyring::Entry> {
        entry_for_service(WINDOWS_PENDING_CREDENTIAL_SERVICE, account_key)
    }

    /// Enumerates only account keys in the separate pending-candidate
    /// namespace. Callers still validate the bounded session-key grammar.
    pub fn service_account_keys() -> Result<Vec<String>> {
        service_account_keys_for(WINDOWS_PENDING_CREDENTIAL_SERVICE)
    }

    pub fn delete_all_service_credentials() -> Result<()> {
        delete_all_service_credentials_for(WINDOWS_PENDING_CREDENTIAL_SERVICE)
    }
}

#[cfg(target_os = "windows")]
fn entry_for_service(service: &str, account_key: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(service, account_key)
        .map_err(|error| DesktopError::Credential(error.to_string()))
}

#[cfg(target_os = "windows")]
fn service_account_keys_for(service: &str) -> Result<Vec<String>> {
    let mut keys = enumerate_service_credential_targets(service)?
        .into_iter()
        .map(|target| target.account_key)
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    Ok(keys)
}

#[cfg(target_os = "windows")]
fn delete_all_service_credentials_for(service: &str) -> Result<()> {
    let targets = enumerate_service_credential_targets(service)?;
    for target in targets {
        delete_service_credential(&target.target_name)?;
    }
    if !enumerate_service_credential_targets(service)?.is_empty() {
        return Err(credential_cleanup_error(
            "credential removal was not complete",
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn delete_and_verify_service_credential_for(service: &str, account_key: &str) -> Result<()> {
    let targets = enumerate_service_credential_targets(service)?;
    for target in targets
        .iter()
        .filter(|target| target.account_key == account_key)
    {
        delete_service_credential(&target.target_name)?;
    }
    if enumerate_service_credential_targets(service)?
        .iter()
        .any(|target| target.account_key == account_key)
    {
        return Err(credential_cleanup_error(
            "exact credential removal was not complete",
        ));
    }
    Ok(())
}

/// Returns true only for the exact target construction used by keyring's
/// Windows-native backend for this application's fixed service identifier.
/// This is deliberately equality, not a prefix or wildcard match.
#[cfg(test)]
fn is_windows_keyring_target_for_service(target_name: &str, username: &str) -> bool {
    is_windows_keyring_target_for_named_service(target_name, username, WINDOWS_CREDENTIAL_SERVICE)
}

#[cfg(any(target_os = "windows", test))]
fn is_windows_keyring_target_for_named_service(
    target_name: &str,
    username: &str,
    service: &str,
) -> bool {
    !username.is_empty()
        && target_name == format!("{username}{WINDOWS_KEYRING_TARGET_DIVIDER}{service}")
}

#[cfg(test)]
fn has_windows_keyring_service_suffix(target_name: &str) -> bool {
    has_windows_keyring_named_service_suffix(target_name, WINDOWS_CREDENTIAL_SERVICE)
}

#[cfg(any(target_os = "windows", test))]
fn has_windows_keyring_named_service_suffix(target_name: &str, service: &str) -> bool {
    target_name.ends_with(&format!("{WINDOWS_KEYRING_TARGET_DIVIDER}{service}"))
}

#[cfg(target_os = "windows")]
fn credential_cleanup_error(reason: &str) -> DesktopError {
    // Do not include a target name, account name, or operating-system error
    // text. The uninstall caller needs only a generic failure signal.
    DesktopError::Credential(format!(
        "Windows Credential Manager cleanup failed: {reason}"
    ))
}

#[cfg(target_os = "windows")]
fn enumerate_service_credential_targets(service: &str) -> Result<Vec<ServiceCredentialTarget>> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_NOT_FOUND},
        Security::Credentials::{
            CredEnumerateW, CredFree, CREDENTIALW, CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
            CRED_MAX_USERNAME_LENGTH, CRED_TYPE_GENERIC,
        },
    };

    struct CredentialEnumeration(*mut *mut CREDENTIALW);

    impl Drop for CredentialEnumeration {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // CredEnumerateW owns this allocation. We never copy or read
                // CredentialBlob before returning it to the OS.
                unsafe { CredFree(self.0.cast::<c_void>()) };
            }
        }
    }

    let mut count = 0_u32;
    let mut credentials: *mut *mut CREDENTIALW = ptr::null_mut();
    if unsafe { CredEnumerateW(ptr::null(), 0, &mut count, &mut credentials) } == 0 {
        return if unsafe { GetLastError() } == ERROR_NOT_FOUND {
            Ok(Vec::new())
        } else {
            Err(credential_cleanup_error(
                "credential enumeration did not complete",
            ))
        };
    }
    if credentials.is_null() {
        return Err(credential_cleanup_error(
            "credential enumeration returned an invalid result",
        ));
    }

    let allocation = CredentialEnumeration(credentials);
    let credentials = unsafe { std::slice::from_raw_parts(credentials, count as usize) };
    let mut targets = Vec::new();
    for credential in credentials {
        if credential.is_null() {
            return Err(credential_cleanup_error(
                "credential enumeration returned an invalid record",
            ));
        }
        let credential = unsafe { &**credential };
        if credential.Type != CRED_TYPE_GENERIC {
            continue;
        }

        // TargetName and UserName are non-secret metadata. The fixed maximum
        // bounds prevent an unexpected non-terminated pointer from becoming
        // an unbounded read. CredentialBlob is intentionally never touched.
        let target_name = unsafe {
            read_wide_metadata(
                credential.TargetName,
                CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize + 1,
            )
        };
        let Some(target_name) = target_name else {
            return Err(credential_cleanup_error(
                "credential enumeration returned invalid target metadata",
            ));
        };
        if !has_windows_keyring_named_service_suffix(&target_name, service) {
            continue;
        }

        let username = unsafe {
            read_wide_metadata(credential.UserName, CRED_MAX_USERNAME_LENGTH as usize + 1)
        };
        let Some(username) = username else {
            return Err(credential_cleanup_error(
                "a Drive credential had invalid account metadata",
            ));
        };
        if !is_windows_keyring_target_for_named_service(&target_name, &username, service) {
            return Err(credential_cleanup_error(
                "a Drive credential did not match the expected service target",
            ));
        }
        targets.push(ServiceCredentialTarget {
            target_name,
            account_key: username,
        });
    }

    drop(allocation);
    Ok(targets)
}

#[cfg(target_os = "windows")]
fn delete_service_credential(target_name: &str) -> Result<()> {
    use std::iter::once;
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_NOT_FOUND},
        Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC},
    };

    let target_name = target_name
        .encode_utf16()
        .chain(once(0))
        .collect::<Vec<_>>();
    if unsafe { CredDeleteW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0
        && unsafe { GetLastError() } != ERROR_NOT_FOUND
    {
        return Err(credential_cleanup_error(
            "credential deletion did not complete",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
unsafe fn read_wide_metadata(value: *const u16, max_len: usize) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // CREDENTIALW documents these metadata fields as NUL-terminated LPWSTR
    // values. Read only one documented code unit at a time, with the caller's
    // Win32 maximum as a ceiling; never manufacture a slice past the proven
    // terminator extent.
    let mut units = Vec::with_capacity(max_len);
    for offset in 0..max_len {
        let unit = unsafe { value.add(offset).read_unaligned() };
        if unit == 0 {
            return String::from_utf16(&units).ok();
        }
        units.push(unit);
    }
    None
}

#[cfg(target_os = "windows")]
impl CredentialStore for WindowsCredentialStore {
    fn get(&self, account_key: &str) -> Result<Option<String>> {
        match Self::entry(account_key)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(DesktopError::Credential(error.to_string())),
        }
    }

    fn set(&self, account_key: &str, bearer_token: &str) -> Result<()> {
        Self::entry(account_key)?
            .set_password(bearer_token)
            .map_err(|error| DesktopError::Credential(error.to_string()))
    }

    fn delete(&self, account_key: &str) -> Result<()> {
        match Self::entry(account_key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(DesktopError::Credential(error.to_string())),
        }
    }
}

#[cfg(target_os = "windows")]
impl CredentialStore for PendingWindowsCredentialStore {
    fn get(&self, account_key: &str) -> Result<Option<String>> {
        match Self::entry(account_key)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(DesktopError::Credential(error.to_string())),
        }
    }

    fn set(&self, account_key: &str, bearer_token: &str) -> Result<()> {
        Self::entry(account_key)?
            .set_password(bearer_token)
            .map_err(|error| DesktopError::Credential(error.to_string()))
    }

    fn delete(&self, account_key: &str) -> Result<()> {
        match Self::entry(account_key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(DesktopError::Credential(error.to_string())),
        }
    }
}

#[cfg(test)]
#[path = "credentials/tests.rs"]
mod tests;
