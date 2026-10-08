use super::*;

#[test]
fn device_credentials_legacy_journal_cleanup_is_rejected_before_native_provider_access() {
    #[cfg(target_os = "linux")]
    use crate::LinuxCredentialStore as Native;
    #[cfg(target_os = "macos")]
    use crate::MacOsCredentialStore as Native;
    #[cfg(target_os = "windows")]
    use crate::WindowsCredentialStore as Native;
    let scoped_spelling =
        crate::desktop_agent_device_credential_key(&"a".repeat(64), "device_fixture").unwrap();
    for key in ["device_fixture", scoped_spelling.as_str()] {
        let slot = DisconnectCredentialSlot {
            namespace: DisconnectCredentialNamespace::DesktopAgentDevice,
            account_key: key.to_string(),
        };
        // Both old slot spellings are refused before Keychain, Secret Service
        // or Credential Manager lookup/deletion. This uses no real credential.
        assert!(Native::delete_and_verify_disconnect_credential_slot(&slot).is_err());
        let intent = DisconnectCleanupIntent::for_disconnect(None, vec![slot]).unwrap();
        let bytes = serde_json::to_vec(&intent).unwrap();
        let retained: DisconnectCleanupIntent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(retained, intent);
    }
}

#[test]
fn device_credentials_scoped_journal_roundtrip_retains_exact_cleanup_authority() {
    let key =
        crate::desktop_agent_device_credential_key(&"a".repeat(64), "device_fixture").unwrap();
    let slot = DisconnectCredentialSlot {
        namespace: DisconnectCredentialNamespace::DesktopAgentDeviceScoped,
        account_key: key,
    };
    let mut intent = DisconnectCleanupIntent::for_disconnect(None, vec![slot.clone()]).unwrap();
    intent.confirm_remote_retirement();
    let bytes = serde_json::to_vec(&intent).unwrap();
    let mut restored: DisconnectCleanupIntent = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.next_credential_slot(), Some(&slot));
    restored.acknowledge_credential_slot(&slot).unwrap();
    assert!(restored.is_complete());
    let invalid = DisconnectCredentialSlot {
        account_key: "device_fixture".into(),
        ..slot
    };
    assert!(DisconnectCleanupIntent::for_disconnect(None, vec![invalid]).is_err());
}
