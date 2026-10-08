use std::sync::Arc;

use shellx_drive_desktop_core::{DesktopState, Result as CoreResult};

use super::{migration::*, model::*, ConnectionManager, ConnectionsView};

impl ConnectionManager {
    pub(crate) fn begin_connection(&self, name: String) -> CoreResult<String> {
        validate_name(&name)?;
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        self.ensure_mutation_allowed()?;
        if !catalog.preferences.initialized {
            return Err(invalid("save app preferences before adding a connection"));
        }
        if catalog.connections.len() >= MAX_CONNECTIONS {
            return Err(invalid(
                "the maximum number of Drive connections has been reached",
            ));
        }
        let id = uuid::Uuid::new_v4().hyphenated().to_string();
        let state = DesktopState {
            launch_at_login: catalog.preferences.launch_at_login,
            ..DesktopState::default()
        };
        let store = self.store.create_profile(&id)?;
        store.save(&state)?;
        let runtime = Arc::new((self.factory)(store, state)?);
        let mut candidate = catalog.clone();
        candidate.connections.push(ConnectionProfile {
            id: id.clone(),
            name,
            storage: ConnectionStorage::Profile,
            identity: None,
            interval_seconds: None,
            lifecycle: ConnectionLifecycle::Preparing,
            reserved_folders: Vec::new(),
            recovery_error: None,
        });
        // The durable entry exists before its ID is returned to authentication.
        // If persistence fails, the private orphan is recovered on restart.
        self.store.save(&candidate)?;
        self.runtimes
            .write()
            .expect("connection runtimes lock")
            .insert(id.clone(), runtime);
        *catalog = candidate;
        Ok(id)
    }

    /// Call with the server-confirmed actor before writing a canonical bearer.
    /// The catalog lock makes duplicate identity admission atomic across drafts.
    pub(crate) fn reserve_identity(
        &self,
        id: &str,
        normalized_url: &str,
        verified_email: &str,
    ) -> CoreResult<()> {
        let runtime = self.resolve(Some(id))?;
        let identity = verified_identity(normalized_url, verified_email)?;
        let key = identity.credential_key();
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        self.ensure_mutation_allowed()?;
        let current = catalog
            .connections
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| invalid("unknown connection ID"))?;
        if current.lifecycle == ConnectionLifecycle::Removing {
            return Err(invalid("connection removal must finish before signing in"));
        }
        if current
            .identity
            .as_ref()
            .is_some_and(|saved| saved.session().credential_key() != key)
        {
            return Err(invalid(
                "sign-in must use the server and account retained by this connection",
            ));
        }
        let runtimes = self.runtimes.read().expect("connection runtimes lock");
        for profile in catalog
            .connections
            .iter()
            .filter(|profile| profile.id != id)
        {
            let duplicate = profile
                .identity
                .as_ref()
                .is_some_and(|saved| saved.session().credential_key() == key)
                || runtimes.get(&profile.id).is_some_and(|other| {
                    state_identity_keys(&other.coordinator.snapshot()).contains(&key)
                });
            if duplicate {
                return Err(invalid(format!(
                    "this server account already belongs to {} (connection {})",
                    profile.name, profile.id
                )));
            }
        }
        drop(runtimes);
        let mut candidate = catalog.clone();
        candidate
            .connections
            .iter_mut()
            .find(|profile| profile.id == id)
            .expect("known connection")
            .identity = Some(ConnectionIdentity::from_session(identity.clone()));
        self.store.save(&candidate)?;
        *catalog = candidate;
        runtime.set_owned_session_identity(identity);
        Ok(())
    }

    pub(crate) fn complete_connection(&self, id: &str) -> CoreResult<ConnectionsView> {
        let runtime = self.resolve(Some(id))?;
        // Completion is explicit admission, including a paired setup recovered
        // after a crash. Reserve its coordinator through identity and disk
        // readback so an in-flight sign-in, root edit or cleanup cannot race it.
        let operation = runtime.coordinator.begin_lifecycle_operation()?;
        let state = runtime.coordinator.snapshot();
        runtime.require_pair_credential()?;
        if state.pairs().next().is_none()
            || state.has_pending_disconnect_cleanup()
            || state.pending_desktop_agent_disconnect().is_some_and(
                shellx_drive_desktop_core::DesktopAgentDisconnectContinuation::blocks_new_pairing,
            )
            || state.pending_candidate_session.is_some()
            || runtime.candidate_recovery_pending()
            || runtime
                .pending_login
                .lock()
                .expect("pending login lock")
                .is_some()
        {
            return Err(invalid("sign-in, folder pairing and credential recovery must finish before saving this connection"));
        }
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        self.ensure_mutation_allowed()?;
        let mut candidate = catalog.clone();
        let profile = candidate
            .connections
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| invalid("unknown connection ID"))?;
        if profile.lifecycle == ConnectionLifecycle::Removing {
            return Err(invalid("connection removal is pending"));
        }
        let recovering = profile.lifecycle == ConnectionLifecycle::Recovery;
        if recovering {
            let durable = self
                .store
                .require_state_file(id, &profile.storage)?
                .load()?;
            if durable != state {
                return Err(invalid(
                    "saved connection state changed; reopen Drive before resuming setup",
                ));
            }
        }
        let identity = profile
            .identity
            .as_ref()
            .ok_or_else(|| invalid("this connection has no verified account identity"))?;
        if !state.pairs().all(|pair| {
            shellx_drive_desktop_core::sync_pair_identity_matches(
                pair,
                &identity.server_url,
                &identity.account_email,
            )
        }) {
            return Err(invalid(
                "paired roots do not match this connection's verified account",
            ));
        }
        profile.lifecycle = ConnectionLifecycle::Active;
        profile.recovery_error = None;
        if recovering {
            merge_folders(&mut profile.reserved_folders, state_folders(&state));
        } else {
            profile.reserved_folders = state_folders(&state);
        }
        self.store.save(&candidate)?;
        *catalog = candidate;
        drop(catalog);
        drop(operation);
        Ok(self.view())
    }

    pub(crate) fn save_connection(
        &self,
        id: &str,
        name: String,
        interval_seconds: Option<u64>,
    ) -> CoreResult<ConnectionsView> {
        self.resolve(Some(id))?;
        validate_name(&name)?;
        if interval_seconds.is_some_and(|value| !SYNC_INTERVALS.contains(&value)) {
            return Err(invalid("choose an offered sync check interval"));
        }
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        self.ensure_mutation_allowed()?;
        let mut candidate = catalog.clone();
        let profile = candidate
            .connections
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| invalid("unknown connection ID"))?;
        if profile.lifecycle == ConnectionLifecycle::Removing {
            return Err(invalid("connection removal is pending"));
        }
        profile.name = name;
        profile.interval_seconds = interval_seconds;
        self.store.save(&candidate)?;
        *catalog = candidate;
        drop(catalog);
        Ok(self.view())
    }

    /// Save this intent before native retirement clears pair/root metadata.
    pub(crate) fn mark_removing(&self, id: &str) -> CoreResult<()> {
        self.mark_removal(id, false)
    }

    /// Cancellation and completion compete in the same catalog transaction.
    /// An editor cancellation can never retire an already-active connection.
    /// Removing remains admitted so a failed native cleanup can be retried.
    pub(crate) fn mark_removing_if_preparing(&self, id: &str) -> CoreResult<()> {
        self.mark_removal(id, true)
    }

    fn mark_removal(&self, id: &str, only_preparing: bool) -> CoreResult<()> {
        let runtime = self.resolve(Some(id))?;
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        self.ensure_mutation_allowed()?;
        let mut candidate = catalog.clone();
        let profile = candidate
            .connections
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| invalid("unknown connection ID"))?;
        if only_preparing
            && !matches!(
                profile.lifecycle,
                ConnectionLifecycle::Preparing | ConnectionLifecycle::Removing
            )
        {
            return Err(invalid("this saved connection is managed with Remove server; cancelling an editor keeps it connected"));
        }
        merge_folders(
            &mut profile.reserved_folders,
            state_folders(&runtime.coordinator.snapshot()),
        );
        profile.lifecycle = ConnectionLifecycle::Removing;
        self.store.save(&candidate)?;
        *catalog = candidate;
        Ok(())
    }

    /// Native Disconnect proves exact credential/marker retirement. This last
    /// catalog step additionally refuses retained sessions or unfinished work.
    pub(crate) fn finish_removal(&self, id: &str) -> CoreResult<ConnectionsView> {
        let runtime = self.resolve(Some(id))?;
        let snapshot = runtime.coordinator.view_snapshot();
        if snapshot.active_run
            || snapshot.disconnect_requested
            || !snapshot.state.uninstall_cleanup_ready()
            || runtime.candidate_recovery_pending()
            || runtime.session.lock().expect("session lock").is_some()
            || runtime
                .pending_login
                .lock()
                .expect("pending login lock")
                .is_some()
        {
            return Err(invalid(
                "connection retirement or cleanup is still pending; its folders remain reserved",
            ));
        }
        // Check durable state, not only a transient empty coordinator snapshot.
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        self.ensure_mutation_allowed()?;
        let profile = catalog
            .connections
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| invalid("unknown connection ID"))?;
        if profile.lifecycle != ConnectionLifecycle::Removing {
            return Err(invalid(
                "request connection removal before finalizing cleanup",
            ));
        }
        let store = self.store.require_state_file(id, &profile.storage)?;
        if !store.load()?.uninstall_cleanup_ready() {
            return Err(invalid("saved connection cleanup is not terminal"));
        }
        let mut candidate = catalog.clone();
        candidate.connections.retain(|profile| profile.id != id);
        if !candidate.retired_ids.iter().any(|retired| retired == id) {
            candidate.retired_ids.push(id.to_string());
        }
        self.store.save(&candidate)?;
        *catalog = candidate;
        self.runtimes
            .write()
            .expect("connection runtimes lock")
            .remove(id);
        self.unavailable
            .write()
            .expect("connection availability lock")
            .remove(id);
        drop(catalog);
        Ok(self.view())
    }

    /// Autostart is applied once by the app command, with rollback if this
    /// persistence fails; individual runtime pairing/removal never changes it.
    pub(crate) fn save_preferences(
        &self,
        theme: String,
        launch_at_login: bool,
        default_sync_interval_seconds: u64,
    ) -> CoreResult<ConnectionsView> {
        let preferences = AppPreferences {
            initialized: true,
            theme,
            launch_at_login,
            default_sync_interval_seconds,
        };
        preferences.validate()?;
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        self.ensure_mutation_allowed()?;
        let mut candidate = catalog.clone();
        candidate.preferences = preferences;
        self.store.save(&candidate)?;
        *catalog = candidate;
        drop(catalog);
        Ok(self.view())
    }

    /// Retain both sides of a reviewed folder replacement until native
    /// publication and catalog completion agree about the new binding.
    pub(crate) fn retain_folder_reservation(
        &self,
        id: &str,
        path: std::path::PathBuf,
        identity: Option<shellx_drive_desktop_core::DirectoryIdentity>,
    ) -> CoreResult<()> {
        let runtime = self.resolve(Some(id))?;
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        self.ensure_mutation_allowed()?;
        let mut candidate = catalog.clone();
        let profile = candidate
            .connections
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| invalid("unknown connection ID"))?;
        merge_folders(
            &mut profile.reserved_folders,
            state_folders(&runtime.coordinator.snapshot()),
        );
        merge_folders(
            &mut profile.reserved_folders,
            vec![ReservedFolder { path, identity }],
        );
        self.store.save(&candidate)?;
        *catalog = candidate;
        Ok(())
    }
}
