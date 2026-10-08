//! Pure state admission for the installed package's final removal step.

use crate::DesktopState;

impl DesktopState {
    /// An untrusted command-line flag may only finish package removal after
    /// the interactive app has already retired every remote authority.
    /// Credential-provider inventories are checked separately by the native
    /// shell and must also be empty before the flag can change local startup.
    pub fn uninstall_cleanup_ready(&self) -> bool {
        self.pairs().next().is_none()
            && self.sync_roots.is_empty()
            && self.sync_root_base.is_none()
            && self.active_remote_session.is_none()
            && self.pending_remote_revocations.is_empty()
            && self.pending_candidate_session.is_none()
            && self.pending_disconnect_cleanup.is_none()
            && self.pending_desktop_agent_disconnect.is_none()
            && self.pending_desktop_update_restart.is_none()
            && !self.desktop_agent_control.enabled
            && self.desktop_agent_control.device_id.is_none()
            && self.desktop_agent_control.credential_expires_at.is_none()
            && self.desktop_agent_control.pair_fingerprint.is_none()
            && self.desktop_agent_control.command_journal.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::{DesktopAgentCommandKind, DesktopState};

    #[test]
    fn uninstall_flag_requires_finished_disconnect_and_no_remote_authority() {
        let mut state = DesktopState::default();
        assert!(state.uninstall_cleanup_ready());

        state.sync_root_base = Some("/tmp/Drive".into());
        assert!(!state.uninstall_cleanup_ready());
        state.sync_root_base = None;

        state.pending_candidate_session = Some(crate::RemoteSessionRecord {
            server_url: "https://drive.example.test".to_string(),
            account_email: "person@example.test".to_string(),
            session_id: "session".to_string(),
            expires_at: Utc::now(),
        });
        assert!(!state.uninstall_cleanup_ready());
        state.pending_candidate_session = None;

        state.desktop_agent_control.enabled = true;
        assert!(!state.uninstall_cleanup_ready());
        state.desktop_agent_control.enabled = false;

        state
            .desktop_agent_control
            .record_lease(
                "command-1".to_string(),
                "lease-1".to_string(),
                DesktopAgentCommandKind::SyncNow,
                Utc::now(),
            )
            .unwrap();
        assert!(!state.uninstall_cleanup_ready());
    }
}
