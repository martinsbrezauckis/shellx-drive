//! Domain-separated native credential locators for device registrations.

use super::fingerprint::{ensure_fingerprint, ensure_opaque_id, hash_fingerprint_field};
use crate::{DesktopError, Result};
use sha2::{Digest, Sha256};

/// Native device-secret locator bound to the locally admitted server/account
/// identity. A server-supplied device ID is never itself a credential key.
/// The fixed ASCII digest fits every supported native credential backend.
/// The colon makes this namespace disjoint from all valid remote opaque IDs.
pub fn desktop_agent_device_credential_key(
    enrollment_fingerprint: &str,
    device_id: &str,
) -> Result<String> {
    ensure_fingerprint(enrollment_fingerprint)?;
    ensure_opaque_id("desktop-agent device ID", device_id)?;
    let mut hasher = Sha256::new();
    hasher.update(b"shellx-drive-desktop-agent-device-credential-v1\0");
    hash_fingerprint_field(&mut hasher, enrollment_fingerprint);
    hash_fingerprint_field(&mut hasher, device_id);
    Ok(format!(
        "sxd_device_v1:{}",
        crate::hex_digest(hasher.finalize().as_slice())
    ))
}

/// Old bare-ID cleanup journals remain readable, but cannot authorize native
/// deletion before the complete connection inventory proves their ownership.
pub fn validate_desktop_agent_device_credential_key(key: &str) -> Result<()> {
    let digest = key.strip_prefix("sxd_device_v1:").ok_or_else(|| {
        DesktopError::Credential(
            "Retained desktop-agent credential needs connection ownership recovery before cleanup."
                .to_string(),
        )
    })?;
    ensure_fingerprint(digest)
}
