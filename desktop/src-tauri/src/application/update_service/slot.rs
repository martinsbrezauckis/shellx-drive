use tauri_plugin_updater::Update;

use super::{DesktopUpdateService, DesktopUpdateServiceError};

#[derive(Default)]
pub(super) enum UpdateSlot {
    #[default]
    Empty,
    Ready {
        candidate_id: String,
        update: Box<Update>,
    },
    Installing,
}

impl DesktopUpdateService {
    pub(super) fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, UpdateSlot>, DesktopUpdateServiceError> {
        self.0
            .lock()
            .map_err(|_| DesktopUpdateServiceError::StateUnavailable)
    }

    pub(super) fn take_ready(
        &self,
        requested_candidate_id: &str,
    ) -> Result<(String, Update), DesktopUpdateServiceError> {
        let mut slot = self.lock()?;
        match std::mem::replace(&mut *slot, UpdateSlot::Installing) {
            UpdateSlot::Ready {
                candidate_id,
                update,
            } if candidate_id == requested_candidate_id => Ok((candidate_id, *update)),
            UpdateSlot::Ready {
                candidate_id,
                update,
            } => {
                *slot = UpdateSlot::Ready {
                    candidate_id,
                    update,
                };
                Err(DesktopUpdateServiceError::CandidateMismatch)
            }
            UpdateSlot::Empty => {
                *slot = UpdateSlot::Empty;
                Err(DesktopUpdateServiceError::NoCheckedUpdate)
            }
            UpdateSlot::Installing => {
                *slot = UpdateSlot::Installing;
                Err(DesktopUpdateServiceError::InProgress)
            }
        }
    }

    pub(super) fn restore_ready(
        &self,
        candidate_id: String,
        update: Update,
    ) -> Result<(), DesktopUpdateServiceError> {
        *self.lock()? = UpdateSlot::Ready {
            candidate_id,
            update: Box::new(update),
        };
        Ok(())
    }

    pub(super) fn clear_installing(&self) -> Result<(), DesktopUpdateServiceError> {
        *self.lock()? = UpdateSlot::Empty;
        Ok(())
    }
}
