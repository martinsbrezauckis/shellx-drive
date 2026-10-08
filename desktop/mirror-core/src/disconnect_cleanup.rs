//! Durable, non-secret local cleanup work that remains after Disconnect.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{DesktopError, PairMarker, Result, SyncPair};

mod shape;

pub const MAX_DISCONNECT_CLEANUP_CREDENTIAL_SLOTS: usize = 128;
pub const MAX_DISCONNECT_CLEANUP_MARKERS: usize = crate::MAX_SYNC_PAIRS;

/// Fixed Credential Manager services which may own a local session-bearing
/// slot. The names are deliberately not persisted: the enum preserves the
/// namespace without turning state into a service-name parser.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectCredentialNamespace {
    #[default]
    Canonical,
    PendingCandidate,
    /// Separate fixed credential service for an enrolled device broker token.
    /// It is never interpreted as a Drive bearer or a delegated-agent token.
    /// Legacy bare-ID journals remain retained until ownership migration.
    DesktopAgentDevice,
    /// Locally derived, connection-scoped locator in that same device service.
    DesktopAgentDeviceScoped,
}

/// A non-secret, exact locator for one fixed-service credential. It contains
/// only the fixed namespace and canonical account key, never a target pattern
/// or bearer value.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DisconnectCredentialSlot {
    pub namespace: DisconnectCredentialNamespace,
    pub account_key: String,
}

/// The exact marker owned by a disconnected pair. It is retained only until
/// the marker is safely removed, never as a new pairing authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisconnectMarkerCleanup {
    pub local_root: PathBuf,
    pub marker: PairMarker,
}

/// A bounded, non-secret journal for cleanup that follows confirmed remote
/// retirement. Credential slots are typed fixed-service account-key locators,
/// not bearer values; each is acknowledged only after its exact Windows
/// credential slot was deleted and re-enumerated as absent.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisconnectCleanupIntent {
    /// False until every remote session retirement has been confirmed. Legacy
    /// or interrupted state therefore never authorizes local deletion merely
    /// because it has no configured pair.
    #[serde(default)]
    pub remote_retirement_confirmed: bool,
    #[serde(default)]
    pub marker: Option<DisconnectMarkerCleanup>,
    /// Additional markers for inactive sync locations. `marker` remains the
    /// current durable head so v2 journals migrate without ambiguity.
    #[serde(default)]
    pub additional_markers: Vec<DisconnectMarkerCleanup>,
    #[serde(default)]
    pub credential_slots: Vec<DisconnectCredentialSlot>,
}

impl DisconnectCleanupIntent {
    pub fn for_disconnect(
        pair: Option<&SyncPair>,
        credential_slots: Vec<DisconnectCredentialSlot>,
    ) -> Result<Self> {
        Self::for_disconnect_pairs(pair.into_iter().cloned().collect(), credential_slots)
    }

    pub fn for_disconnect_pairs(
        mut pairs: Vec<SyncPair>,
        credential_slots: Vec<DisconnectCredentialSlot>,
    ) -> Result<Self> {
        pairs.sort_by_key(|pair| pair.local_root.to_string_lossy().to_ascii_lowercase());
        let mut markers = pairs.into_iter().map(|pair| DisconnectMarkerCleanup {
            local_root: pair.local_root.clone(),
            marker: PairMarker::from(&pair),
        });
        let intent = Self {
            remote_retirement_confirmed: false,
            marker: markers.next(),
            additional_markers: markers.collect(),
            credential_slots,
        };
        intent.validate_shape()?;
        Ok(intent)
    }

    pub fn is_complete(&self) -> bool {
        self.remote_retirement_confirmed
            && self.marker.is_none()
            && self.additional_markers.is_empty()
            && self.credential_slots.is_empty()
    }

    pub fn remote_retirement_confirmed(&self) -> bool {
        self.remote_retirement_confirmed
    }

    pub fn confirm_remote_retirement(&mut self) {
        self.remote_retirement_confirmed = true;
    }

    pub fn acknowledge_marker(&mut self) {
        self.marker = if self.additional_markers.is_empty() {
            None
        } else {
            Some(self.additional_markers.remove(0))
        };
    }

    pub fn markers(&self) -> impl Iterator<Item = &DisconnectMarkerCleanup> {
        self.marker.iter().chain(self.additional_markers.iter())
    }

    pub fn next_credential_slot(&self) -> Option<&DisconnectCredentialSlot> {
        self.credential_slots.first()
    }

    pub fn acknowledge_credential_slot(&mut self, slot: &DisconnectCredentialSlot) -> Result<()> {
        if self.next_credential_slot() != Some(slot) {
            return Err(DesktopError::InvalidState(
                "disconnect cleanup attempted an unexpected credential slot".to_string(),
            ));
        }
        self.credential_slots.remove(0);
        Ok(())
    }
}

#[cfg(test)]
#[path = "disconnect_cleanup/tests.rs"]
mod tests;
