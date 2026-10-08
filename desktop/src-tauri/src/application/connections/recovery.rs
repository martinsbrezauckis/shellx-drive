use std::{path::Path, sync::Arc};

use shellx_drive_desktop_core::{CredentialStore, DesktopState, Result as CoreResult, StateStore};

use super::{migration::*, model::*, ConnectionManager, Runtime};

impl ConnectionManager {
    pub(super) fn reconcile_catalog(&self) -> CoreResult<()> {
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        let mut candidate = catalog.clone();
        for id in self.store.profile_ids()? {
            if candidate.connections.iter().any(|profile| profile.id == id)
                || candidate.retired_ids.contains(&id)
            {
                continue;
            }
            if candidate.connections.len() >= MAX_CONNECTIONS {
                return Err(invalid("too many retained connections need recovery"));
            }
            candidate.connections.push(ConnectionProfile {
                id,
                name: "Recovered setup".to_string(),
                storage: ConnectionStorage::Profile,
                identity: None,
                interval_seconds: None,
                lifecycle: ConnectionLifecycle::Recovery,
                reserved_folders: Vec::new(),
                recovery_error: Some("An interrupted connection setup needs recovery.".to_string()),
            });
        }
        let mut runtimes = self.runtimes.write().expect("connection runtimes lock");
        let mut unavailable = self
            .unavailable
            .write()
            .expect("connection availability lock");
        for profile in &mut candidate.connections {
            let store = self.state_store(&profile.id, &profile.storage)?;
            // StateStore::load normally defaults a missing file to empty. A
            // catalog reference instead requires that exact file to exist.
            let loaded = self
                .store
                .require_state_file(&profile.id, &profile.storage)
                .and_then(|store| store.load());
            let state = match loaded {
                Ok(state) => state,
                Err(error) => {
                    profile.lifecycle = ConnectionLifecycle::Recovery;
                    profile.recovery_error = Some(match error {
                        shellx_drive_desktop_core::DesktopError::Io(error) if error.kind() == std::io::ErrorKind::NotFound =>
                            "The saved connection state is missing. Restore it and reopen Drive; its identity and folders remain reserved.".to_string(),
                        _ => "The saved connection state cannot be safely read. Restore it and reopen Drive; its identity and folders remain reserved.".to_string(),
                    });
                    unavailable.insert(profile.id.clone());
                    runtimes.insert(
                        profile.id.clone(),
                        blocked_runtime(
                            store,
                            profile.recovery_error.as_deref().expect("recovery error"),
                        ),
                    );
                    continue;
                }
            };
            let discovered = state_identity(&state)?;
            if profile
                .identity
                .as_ref()
                .zip(discovered.as_ref())
                .is_some_and(|(saved, actual)| {
                    saved.session().credential_key() != actual.session().credential_key()
                })
            {
                profile.lifecycle = ConnectionLifecycle::Recovery;
                profile.recovery_error = Some("Saved connection identity does not match its catalog. Restore its retained state before continuing.".to_string());
                unavailable.insert(profile.id.clone());
                runtimes.insert(
                    profile.id.clone(),
                    blocked_runtime(
                        store,
                        profile.recovery_error.as_deref().expect("recovery error"),
                    ),
                );
                continue;
            }
            if profile.identity.is_none() {
                profile.identity = discovered;
            }
            merge_folders(&mut profile.reserved_folders, state_folders(&state));
            if profile.lifecycle == ConnectionLifecycle::Preparing {
                profile.lifecycle = ConnectionLifecycle::Recovery;
                profile.recovery_error = Some(
                    "Connection setup was interrupted. Finish setup or remove this connection."
                        .to_string(),
                );
            }
            if state.has_pending_disconnect_cleanup() {
                profile.lifecycle = ConnectionLifecycle::Removing;
            } else if profile.lifecycle == ConnectionLifecycle::Active
                && state.pairs().next().is_none()
            {
                profile.lifecycle = ConnectionLifecycle::Recovery;
                profile.recovery_error = Some("This saved connection has no admitted local folder. Finish setup or remove it.".to_string());
            }
            let runtime = if profile.storage == ConnectionStorage::Legacy {
                Arc::clone(&self.primary)
            } else {
                match (self.factory)(store, state) {
                    Ok(runtime) => Arc::new(runtime),
                    Err(_) => {
                        profile.lifecycle = ConnectionLifecycle::Recovery;
                        profile.recovery_error = Some("Native recovery could not safely load this connection. Reopen Drive after restoring its state.".to_string());
                        unavailable.insert(profile.id.clone());
                        let store = self.state_store(&profile.id, &profile.storage)?;
                        blocked_runtime(
                            store,
                            profile.recovery_error.as_deref().expect("recovery error"),
                        )
                    }
                }
            };
            if let Some(identity) = &profile.identity {
                runtime.set_owned_session_identity(identity.session());
            }
            runtimes.insert(profile.id.clone(), runtime);
        }
        // Only catalog metadata is migrated. No primary state save, credential
        // rename, marker rewrite, or local-content move occurs here.
        self.store.save(&candidate)?;
        *catalog = candidate;
        Ok(())
    }
}

/// Projection-only placeholders must never execute native recovery or expose a
/// real credential provider for a missing/corrupt referenced state.
fn blocked_runtime(store: StateStore, message: &str) -> Arc<Runtime> {
    Arc::new(Runtime::from_loaded_state(
        Box::new(BlockedPlatform(BlockedCredentials)),
        store,
        DesktopState {
            last_error: Some(message.to_string()),
            ..DesktopState::default()
        },
    ))
}

struct BlockedCredentials;

impl CredentialStore for BlockedCredentials {
    fn get(&self, _: &str) -> CoreResult<Option<String>> {
        Err(invalid("saved connection state is unavailable"))
    }
    fn set(&self, _: &str, _: &str) -> CoreResult<()> {
        Err(invalid("saved connection state is unavailable"))
    }
    fn delete(&self, _: &str) -> CoreResult<()> {
        Err(invalid("saved connection state is unavailable"))
    }
}

struct BlockedPlatform(BlockedCredentials);

impl crate::platform::PlatformServices for BlockedPlatform {
    fn credentials(&self) -> &dyn CredentialStore {
        &self.0
    }
    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        &self.0
    }
    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        &self.0
    }
    fn set_launch_at_login(&self, _: bool) -> CoreResult<()> {
        Err(invalid("saved connection state is unavailable"))
    }
    fn open_local_root(&self, _: &Path) -> CoreResult<()> {
        Err(invalid("saved connection state is unavailable"))
    }
    fn open_drive_url(&self, _: &str) -> CoreResult<()> {
        Err(invalid("saved connection state is unavailable"))
    }
}
