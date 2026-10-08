//! Shape validation for the durable cleanup journal.

use super::*;

impl DisconnectCleanupIntent {
    pub(crate) fn validate_shape(&self) -> Result<()> {
        if self.markers().count() > MAX_DISCONNECT_CLEANUP_MARKERS {
            return Err(DesktopError::InvalidState(format!(
                "disconnect cleanup contains more than {MAX_DISCONNECT_CLEANUP_MARKERS} markers"
            )));
        }
        let marker_roots = self
            .markers()
            .map(|marker| marker.local_root.to_string_lossy().to_ascii_lowercase())
            .collect::<Vec<_>>();
        if !marker_roots.windows(2).all(|roots| roots[0] < roots[1]) {
            return Err(DesktopError::InvalidState(
                "disconnect cleanup markers must be sorted and unique".to_string(),
            ));
        }
        if self.credential_slots.len() > MAX_DISCONNECT_CLEANUP_CREDENTIAL_SLOTS {
            return Err(DesktopError::InvalidState(format!(
                "disconnect cleanup contains {} credential slots; maximum is {MAX_DISCONNECT_CLEANUP_CREDENTIAL_SLOTS}",
                self.credential_slots.len()
            )));
        }
        if !self
            .credential_slots
            .windows(2)
            .all(|slots| slots[0] < slots[1])
        {
            return Err(DesktopError::InvalidState(
                "disconnect cleanup credential slots must be sorted and unique".to_string(),
            ));
        }
        if self
            .credential_slots
            .iter()
            .any(|slot| slot.account_key.is_empty())
        {
            return Err(DesktopError::InvalidState(
                "disconnect cleanup credential slots must have exact account keys".to_string(),
            ));
        }
        Ok(())
    }
}
