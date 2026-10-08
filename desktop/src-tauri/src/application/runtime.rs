//! Platform-neutral desktop runtime state, status, and credential admission.

use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Mutex,
    },
};

use chrono::Utc;
use shellx_drive_desktop_core::{
    default_state_path, sync_pair_identity_matches, AuthOffboardingGate, CoordinatorViewSnapshot,
    DesktopError, DesktopState, DesktopUpdateRestartReadback, MirrorCoordinator,
    RemoteSessionRecord, Result as CoreResult, ReviewAction, StateStore, SyncPair, SyncStatus,
};

use crate::{application::local_usage::LocalUsageCache, session_identity::SessionIdentity};

#[path = "connection_runtime.rs"]
mod connection_state;
mod session_admission;

pub(crate) struct Runtime {
    state_load_unavailable: bool,
    pub(crate) store: StateStore,
    pub(crate) coordinator: MirrorCoordinator,
    pub(crate) platform: Box<dyn crate::platform::PlatformServices>,
    pub(crate) session: Mutex<Option<SessionIdentity>>,
    /// The app catalog reserves this account before credential publication.
    /// This is a non-secret ownership locator, including unpaired recovery.
    owned_session_identity: Mutex<Option<SessionIdentity>>,
    pub(crate) pending_login: Mutex<Option<PendingLogin>>,
    pub(crate) auth_offboarding: AuthOffboardingGate,
    pub(crate) auth_publication: tokio::sync::Mutex<()>,
    pub(crate) candidate_recovery_pending: AtomicBool,
    pub(crate) candidate_recovery_identities: Mutex<BTreeSet<String>>,
    pub(crate) update_recovery_target_version: Mutex<Option<String>>,
    pub(crate) pending_review_confirmation: Mutex<Option<PendingReviewConfirmation>>,
    pub(crate) next_review_confirmation: AtomicU64,
    pub(crate) polling_enabled: AtomicBool,
    pub(crate) poll_generation: AtomicU64,
    last_sync_check_finished: Mutex<Option<std::time::Instant>>,
    pub(crate) agent_polling_enabled: AtomicBool,
    pub(crate) agent_poll_generation: AtomicU64,
    pub(crate) local_usage_cache: LocalUsageCache,
}

/// Passwords may live only between a 202 login response and its TOTP or
/// recovery continuation. This type intentionally has no `Debug` impl.
pub(crate) struct PendingLogin {
    pub(crate) server_url: String,
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) generation: u64,
}

pub(crate) struct PendingReviewConfirmation {
    pub(crate) id: String,
    pub(crate) review_id: String,
    pub(crate) action: ReviewAction,
    pub(crate) pair_id: String,
    pub(crate) fingerprint: String,
    pub(crate) expires_at: chrono::DateTime<Utc>,
}
const MAX_RECOVERY_IDENTITIES: usize = 128;

impl Runtime {
    /// Construct state only after the caller completed any platform-owned
    /// recovery work. This keeps retained-content cleanup out of common
    /// orchestration and prevents Unix from accidentally adopting NTFS work.
    pub(crate) fn load_state() -> CoreResult<(StateStore, DesktopState)> {
        let store = StateStore::new(default_state_path()?);
        let state = match store.load() {
            Ok(state) => state,
            Err(error)
                if store.path().parent().is_some_and(|parent| {
                    parent
                        .join(".shellx-drive-private/connections-v1/catalog.json")
                        .is_file()
                }) =>
            {
                // The catalog retains identity/folder reservations and will
                // project this connection as unavailable. Keep the unreadable
                // legacy bytes intact so the app can show that recovery state.
                DesktopState {
                    last_error: Some(format!(
                        "Drive cannot read its retained connection state: {error}"
                    )),
                    ..DesktopState::default()
                }
            }
            Err(error) => return Err(error),
        };
        Ok((store, state))
    }

    pub(crate) fn from_loaded_state(
        platform: Box<dyn crate::platform::PlatformServices>,
        store: StateStore,
        state: DesktopState,
    ) -> Self {
        let state_load_unavailable = state.last_error.as_deref().is_some_and(|error| {
            error.starts_with("Drive cannot read its retained connection state:")
        });
        Self {
            state_load_unavailable,
            store,
            coordinator: MirrorCoordinator::new(state),
            platform,
            session: Mutex::new(None),
            owned_session_identity: Mutex::new(None),
            pending_login: Mutex::new(None),
            auth_offboarding: AuthOffboardingGate::default(),
            auth_publication: tokio::sync::Mutex::new(()),
            candidate_recovery_pending: AtomicBool::new(false),
            candidate_recovery_identities: Mutex::new(BTreeSet::new()),
            update_recovery_target_version: Mutex::new(None),
            pending_review_confirmation: Mutex::new(None),
            next_review_confirmation: AtomicU64::new(0),
            polling_enabled: AtomicBool::new(false),
            poll_generation: AtomicU64::new(0),
            last_sync_check_finished: Mutex::new(None),
            agent_polling_enabled: AtomicBool::new(false),
            agent_poll_generation: AtomicU64::new(0),
            local_usage_cache: LocalUsageCache::default(),
        }
    }

    pub(crate) fn save(&self) -> CoreResult<()> {
        self.ensure_state_available()?;
        self.store.save(&self.coordinator.snapshot())
    }

    pub(crate) fn note_update_restart_readback(&self, readback: &DesktopUpdateRestartReadback) {
        let target_version = match readback {
            DesktopUpdateRestartReadback::Unconfirmed {
                target_version,
                agent_command_id: None,
                ..
            } => Some(target_version.clone()),
            _ => None,
        };
        *self
            .update_recovery_target_version
            .lock()
            .expect("update recovery target lock") = target_version;
    }

    pub(crate) fn update_recovery_target_version(&self) -> Option<String> {
        self.update_recovery_target_version
            .lock()
            .expect("update recovery target lock")
            .clone()
    }

    pub(crate) fn clear_update_recovery_target_version(&self) {
        *self
            .update_recovery_target_version
            .lock()
            .expect("update recovery target lock") = None;
    }

    pub(crate) fn credential_key(server_url: &str, email: &str) -> String {
        SessionIdentity::credential_key_for(server_url, email)
    }

    fn pair_credential_available(&self) -> bool {
        self.pair_credential_available_for(&self.coordinator.snapshot())
    }

    fn pair_credential_available_for(&self, state: &DesktopState) -> bool {
        let Some(pair) = state.pair.as_ref() else {
            return true;
        };
        self.platform
            .credentials()
            .get(&Self::credential_key(&pair.server_url, &pair.account_email))
            .ok()
            .flatten()
            .is_some()
    }

    pub(crate) fn status_for_view_snapshot(
        &self,
        snapshot: &CoordinatorViewSnapshot,
    ) -> SyncStatus {
        if self.candidate_recovery_pending() {
            SyncStatus::Error
        } else {
            snapshot.state.status(
                snapshot.active_run,
                snapshot.offline,
                self.pair_credential_available_for(&snapshot.state),
            )
        }
    }

    pub(crate) fn status(&self) -> SyncStatus {
        self.status_for_view_snapshot(&self.coordinator.view_snapshot())
    }

    pub(crate) fn require_pair_credential(&self) -> CoreResult<()> {
        if self.coordinator.snapshot().pair.is_some() && !self.pair_credential_available() {
            return Err(DesktopError::NeedsReconnect);
        }
        Ok(())
    }

    pub(crate) fn ensure_disconnect_cleanup_complete(&self) -> CoreResult<()> {
        let state = self.coordinator.snapshot();
        if state.has_pending_disconnect_cleanup()
            || state.pending_desktop_agent_disconnect().is_some_and(
                shellx_drive_desktop_core::DesktopAgentDisconnectContinuation::blocks_new_pairing,
            )
        {
            return Err(DesktopError::InvalidState(
                "Disconnect local cleanup is pending; its broker terminal completion may also be pending. Retry Disconnect before signing in, pairing, or syncing."
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure_login_matches_retained_pair(
        &self,
        normalized_url: &str,
        email: &str,
    ) -> CoreResult<()> {
        if let Some(pair) = self.coordinator.snapshot().pair {
            if !sync_pair_identity_matches(&pair, normalized_url, email) {
                return Err(DesktopError::InvalidState(
                    "Reconnect must use the server and account retained by this pair; disconnect explicitly before choosing another account"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn current_session(&self) -> CoreResult<SessionIdentity> {
        self.session
            .lock()
            .expect("session lock")
            .clone()
            .or_else(|| {
                self.coordinator
                    .snapshot()
                    .pair
                    .map(|pair| SessionIdentity::new(pair.server_url, pair.account_email))
            })
            .or_else(|| {
                self.owned_session_identity
                    .lock()
                    .expect("owned identity lock")
                    .clone()
            })
            .ok_or(DesktopError::NeedsSetup)
    }

    pub(crate) fn current_token(&self, session: &SessionIdentity) -> CoreResult<String> {
        self.platform
            .credentials()
            .get(&Self::credential_key(&session.server_url, &session.email))?
            .ok_or(DesktopError::NeedsReconnect)
    }

    pub(crate) fn candidate_recovery_pending(&self) -> bool {
        self.candidate_recovery_pending
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn set_candidate_recovery_pending(&self, pending: bool) {
        self.candidate_recovery_pending
            .store(pending, std::sync::atomic::Ordering::Release);
        if !pending {
            self.candidate_recovery_identities
                .lock()
                .expect("candidate recovery identity lock")
                .clear();
        }
    }

    /// Retain only non-secret canonical identity keys while a native
    /// candidate-store recovery is unresolved. The native adapter decides how
    /// to enumerate its pending slots; the shared runtime owns the admission
    /// latch that blocks all sync, review, and pairing work meanwhile.
    pub(crate) fn remember_candidate_recovery_identity(&self, identity: &SessionIdentity) {
        let key = identity.credential_key();
        let mut identities = self
            .candidate_recovery_identities
            .lock()
            .expect("candidate recovery identity lock");
        if identities.len() < MAX_RECOVERY_IDENTITIES || identities.contains(&key) {
            identities.insert(key);
        }
    }

    pub(crate) fn remember_candidate_recovery_record(&self, record: &RemoteSessionRecord) {
        self.remember_candidate_recovery_identity(&SessionIdentity::new(
            &record.server_url,
            &record.account_email,
        ));
    }

    pub(crate) fn require_candidate_recovery_complete(&self) -> CoreResult<()> {
        (!self.candidate_recovery_pending())
            .then_some(())
            .ok_or_else(|| {
                DesktopError::Credential(
                    "Drive credential recovery must finish before sign-in, pairing, or sync"
                        .to_string(),
                )
            })
    }
}

pub(crate) fn pair_location_label(pair: &SyncPair) -> String {
    pair.remote_root_name
        .as_ref()
        .map(|root_name| format!("{} / {root_name}", pair.workspace_name))
        .unwrap_or_else(|| format!("{} / Workspace root", pair.workspace_name))
}

pub(crate) fn status_code(status: SyncStatus) -> &'static str {
    match status {
        SyncStatus::NeedsSetup => "needs_setup",
        SyncStatus::NeedsReconnect => "needs_reconnect",
        SyncStatus::Synced => "synced",
        SyncStatus::Syncing => "syncing",
        SyncStatus::Paused => "paused",
        SyncStatus::Offline => "offline",
        SyncStatus::NeedsReview => "needs_review",
        SyncStatus::Error => "error",
    }
}

pub(crate) fn host_label(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

pub(crate) fn invalidate_pending_confirmation(runtime: &Runtime) {
    *runtime
        .pending_review_confirmation
        .lock()
        .expect("review confirmation lock") = None;
}

#[cfg(test)]
#[path = "runtime/lifecycle_tests.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "runtime/tests.rs"]
pub(crate) mod tests;
#[cfg(test)]
#[path = "runtime/update_recovery_tests.rs"]
mod update_recovery_tests;
