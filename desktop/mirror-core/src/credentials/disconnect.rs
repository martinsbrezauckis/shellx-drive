//! Typed Disconnect cleanup across the three fixed Windows credential services.

use crate::{DisconnectCredentialNamespace, DisconnectCredentialSlot, Result};

use super::{
    delete_and_verify_service_credential_for, PendingWindowsCredentialStore,
    WindowsCredentialStore, WindowsDesktopAgentCredentialStore, WINDOWS_CREDENTIAL_SERVICE,
    WINDOWS_DESKTOP_AGENT_CREDENTIAL_SERVICE, WINDOWS_PENDING_CREDENTIAL_SERVICE,
};

impl WindowsCredentialStore {
    /// Lists every exact local session-bearing credential that Disconnect owns.
    /// The durable journal receives typed namespaces, never service strings.
    pub fn disconnect_credential_slots() -> Result<Vec<DisconnectCredentialSlot>> {
        let canonical = Self::service_account_keys()?
            .into_iter()
            .map(|account_key| DisconnectCredentialSlot {
                namespace: DisconnectCredentialNamespace::Canonical,
                account_key,
            });
        let pending = PendingWindowsCredentialStore::service_account_keys()?
            .into_iter()
            .map(|account_key| DisconnectCredentialSlot {
                namespace: DisconnectCredentialNamespace::PendingCandidate,
                account_key,
            });
        let agent = WindowsDesktopAgentCredentialStore::service_account_keys()?
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

    /// Deletes and re-enumerates exactly one service/key pair captured before
    /// remote retirement, including the independent device-agent namespace.
    pub fn delete_and_verify_disconnect_credential_slot(
        slot: &DisconnectCredentialSlot,
    ) -> Result<()> {
        let service = match slot.namespace {
            DisconnectCredentialNamespace::Canonical => WINDOWS_CREDENTIAL_SERVICE,
            DisconnectCredentialNamespace::PendingCandidate => WINDOWS_PENDING_CREDENTIAL_SERVICE,
            DisconnectCredentialNamespace::DesktopAgentDevice => {
                WINDOWS_DESKTOP_AGENT_CREDENTIAL_SERVICE
            }
        };
        delete_and_verify_service_credential_for(service, &slot.account_key)
    }
}
