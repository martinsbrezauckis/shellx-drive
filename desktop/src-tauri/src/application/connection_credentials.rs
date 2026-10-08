//! Exact credential ownership shared by connection and agent offboarding.

use super::Runtime;
use shellx_drive_desktop_core::{DesktopState, DisconnectCredentialSlot, Result as CoreResult};

pub(crate) fn cleanup_slots(
    runtime: &Runtime,
    state: &DesktopState,
) -> CoreResult<Vec<DisconnectCredentialSlot>> {
    #[cfg(target_os = "windows")]
    {
        return super::windows::disconnect_cleanup::scoped_credential_slots(runtime, state);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use crate::session_identity::pending_credential_slot;
        use shellx_drive_desktop_core::DisconnectCredentialNamespace;
        #[cfg(target_os = "linux")]
        use shellx_drive_desktop_core::LinuxCredentialStore as Native;
        #[cfg(target_os = "macos")]
        use shellx_drive_desktop_core::MacOsCredentialStore as Native;
        let agent = super::desktop_agent::scoped_device_cleanup_slot(state)?;
        Ok(Native::disconnect_credential_slots()?
            .into_iter()
            .filter(|slot| match slot.namespace {
                DisconnectCredentialNamespace::Canonical => {
                    runtime.owns_credential_key(&slot.account_key)
                }
                DisconnectCredentialNamespace::PendingCandidate => {
                    pending_credential_slot(state, &slot.account_key).is_ok()
                }
                DisconnectCredentialNamespace::DesktopAgentDevice
                | DisconnectCredentialNamespace::DesktopAgentDeviceScoped => agent
                    .as_ref()
                    .is_some_and(|agent| agent.account_key == slot.account_key),
            })
            .map(|mut slot| {
                if matches!(
                    slot.namespace,
                    DisconnectCredentialNamespace::DesktopAgentDevice
                        | DisconnectCredentialNamespace::DesktopAgentDeviceScoped
                ) {
                    slot.namespace = DisconnectCredentialNamespace::DesktopAgentDeviceScoped;
                }
                slot
            })
            .collect())
    }
}
