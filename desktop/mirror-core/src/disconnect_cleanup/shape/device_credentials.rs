use super::*;

pub(super) fn validate_scoped_slots(slots: &[DisconnectCredentialSlot]) -> Result<()> {
    for slot in slots {
        if slot.namespace == DisconnectCredentialNamespace::DesktopAgentDeviceScoped {
            crate::validate_desktop_agent_device_credential_key(&slot.account_key)?;
        }
    }
    Ok(())
}
