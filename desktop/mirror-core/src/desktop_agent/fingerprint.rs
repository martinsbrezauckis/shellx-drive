//! Pair-fingerprint helpers shared by registration and durable state validation.

use sha2::{Digest, Sha256};

use crate::{DesktopError, Result, SyncPair};

const MAX_AGENT_OPAQUE_ID_BYTES: usize = 192;
pub(super) const MAX_NATIVE_REVIEW_ID_BYTES: usize = 4 * 1024;

/// Native review IDs include the planner's reason and relative path. They are
/// lookup keys, never filesystem input; execution still requires an exact
/// pending review and its prepared witness.
pub(super) fn ensure_native_review_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NATIVE_REVIEW_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(DesktopError::InvalidState(
            "review ID must be bounded non-control text".to_string(),
        ));
    }
    Ok(())
}

/// Legacy root-specific fingerprint retained only to recognize old enrollment
/// state during the fail-closed migration. New registrations use
/// [`desktop_agent_enrollment_fingerprint`].
pub fn desktop_agent_pair_fingerprint(pair: &SyncPair) -> String {
    let mut hasher = Sha256::new();
    hash_fingerprint_field(&mut hasher, pair.server_url.trim_end_matches('/'));
    hash_fingerprint_field(&mut hasher, &pair.account_email.trim().to_ascii_lowercase());
    hash_fingerprint_field(&mut hasher, &pair.workspace_id);
    hash_fingerprint_field(&mut hasher, pair.remote_root_id.as_deref().unwrap_or(""));
    crate::hex_digest(hasher.finalize().as_slice())
}

/// Bind desktop-agent enrollment to the one Drive server/account identity
/// permitted across every configured local root. Root selection remains
/// marker-bound locally, while switching an authorized root cannot strand an
/// already enrolled outbound device.
pub fn desktop_agent_enrollment_fingerprint(server_url: &str, account_email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shellx-drive-desktop-agent-enrollment-v1\0");
    hash_fingerprint_field(&mut hasher, server_url.trim_end_matches('/'));
    hash_fingerprint_field(&mut hasher, &account_email.trim().to_ascii_lowercase());
    crate::hex_digest(hasher.finalize().as_slice())
}

pub(super) fn hash_fingerprint_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

pub(super) fn ensure_fingerprint(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DesktopError::InvalidState(
            "desktop-agent pair fingerprint must be a lowercase SHA-256 digest".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_opaque_id(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_AGENT_OPAQUE_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DesktopError::InvalidState(format!(
            "{label} must be a bounded opaque identifier"
        )));
    }
    Ok(())
}
