//! Fixed Drive service namespaces and bounded non-secret account keys.

use super::{
    credential_error, Result, CANONICAL_SERVICE, DESKTOP_AGENT_DEVICE_SERVICE,
    DESKTOP_AGENT_DISCONNECT_SERVICE, PENDING_SERVICE,
};

pub(super) fn validate_service(service: &str) -> Result<()> {
    if matches!(
        service,
        CANONICAL_SERVICE
            | PENDING_SERVICE
            | DESKTOP_AGENT_DEVICE_SERVICE
            | DESKTOP_AGENT_DISCONNECT_SERVICE
    ) {
        Ok(())
    } else {
        Err(credential_error("unknown credential service"))
    }
}

pub(super) fn validate_account_key(account_key: &str) -> Result<()> {
    if !account_key.is_empty() && account_key.len() <= 1_024 && !account_key.contains('\0') {
        Ok(())
    } else {
        Err(credential_error("credential account key is invalid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_services_are_the_only_accepted_namespaces() {
        assert!(validate_service(CANONICAL_SERVICE).is_ok());
        assert!(validate_service(PENDING_SERVICE).is_ok());
        assert!(validate_service(DESKTOP_AGENT_DEVICE_SERVICE).is_ok());
        assert!(validate_service(DESKTOP_AGENT_DISCONNECT_SERVICE).is_ok());
        assert!(validate_service("com.shellx.drive.desktop.other").is_err());
    }

    #[test]
    fn account_keys_are_bounded_and_nul_free() {
        assert!(validate_account_key("https://drive.example|person@example.test").is_ok());
        assert!(validate_account_key("").is_err());
        assert!(validate_account_key("bad\0key").is_err());
    }
}
