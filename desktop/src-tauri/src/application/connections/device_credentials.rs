//! Ownership-proved migration from the old global device-ID credential slots.

use std::collections::{BTreeMap, BTreeSet};

use shellx_drive_desktop_core::{
    classify_exact_credential_removal, desktop_agent_device_credential_key,
    desktop_agent_enrollment_fingerprint, desktop_agent_pair_fingerprint,
    validate_desktop_agent_device_credential_key, CredentialStore, DesktopError, DesktopState,
    DisconnectCredentialNamespace, ExactCredentialRemoval, Result as CoreResult,
};

use super::{migration::state_identity, ConnectionManager, ConnectionStorage};
use crate::{
    application::desktop_agent::write_exact_agent_credential, session_identity::SessionIdentity,
};

mod admission;
use admission::{admit_destinations, credential_slot_claims, migration_fingerprint};

const RECOVERY: &str = "Desktop-agent credential ownership recovery is pending. Its retained secret was kept; restore all retained connection states and reopen Drive before retrying desktop control or Disconnect.";

impl ConnectionManager {
    /// Native startup cleanup refuses every legacy device journal slot. Only
    /// after catalog reconciliation may this complete inventory grant a raw
    /// slot to exactly one durable owner. Unreadable states reserve ownership.
    pub(super) fn migrate_desktop_agent_credentials(&self) -> CoreResult<()> {
        let runtimes = self
            .runtimes
            .read()
            .expect("connection runtimes lock")
            .clone();
        let mut states = runtimes
            .iter()
            .map(|(id, runtime)| (id.clone(), runtime.coordinator.snapshot()))
            .collect::<BTreeMap<_, _>>();
        let mut complete = !self.has_unavailable_connections();
        // Retired directories are retained evidence, not permission to ignore
        // their possible old device/journal ownership.
        for id in self.store.profile_ids()? {
            if states.contains_key(&id) {
                continue;
            }
            match self
                .store
                .require_state_file(&id, &ConnectionStorage::Profile)
                .and_then(|store| store.load())
            {
                Ok(state) => {
                    states.insert(id, state);
                }
                Err(_) => complete = false,
            }
        }
        let mut owners = BTreeMap::<String, BTreeSet<String>>::new();
        for (id, state) in &states {
            for key in credential_slot_claims(state) {
                owners.entry(key).or_default().insert(id.clone());
            }
        }
        let mut catalog = self.catalog.lock().expect("connection catalog lock");
        let mut candidate = catalog.clone();
        for profile in &mut candidate.connections {
            let Some(runtime) = runtimes.get(&profile.id) else {
                continue;
            };
            let state = runtime.coordinator.snapshot();
            let legacy_keys = legacy_keys(&state);
            if legacy_keys.is_empty() {
                if profile.recovery_error.as_deref() == Some(RECOVERY) {
                    profile.recovery_error = None;
                }
                continue;
            }
            let unambiguous = complete && legacy_keys.iter().all(|key| {
                owners.get(key).is_some_and(|owners| owners.len() == 1 && owners.contains(&profile.id))
                    // A server could have used the spelling of a new scoped
                    // locator as its old device ID. Never adopt that slot.
                    && validate_desktop_agent_device_credential_key(key).is_err()
            });
            let identity = profile
                .identity
                .as_ref()
                .map(|identity| identity.session())
                .or_else(|| {
                    state_identity(&state)
                        .ok()
                        .flatten()
                        .map(|identity| identity.session())
                });
            let result = if unambiguous {
                identity.ok_or_else(recovery_error).and_then(|identity| {
                    admit_destinations(&state, &identity, &profile.id, &owners)?;
                    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
                    let next = migrate_owned_state(
                        &state,
                        &identity,
                        runtime.platform.desktop_agent_credentials(),
                    )?;
                    runtime.store.save(&next)?;
                    operation.finish_state(next);
                    Ok(())
                })
            } else {
                Err(recovery_error())
            };
            if result.is_err() {
                profile.recovery_error = Some(RECOVERY.to_string());
            } else if profile.recovery_error.as_deref() == Some(RECOVERY) {
                profile.recovery_error = None;
            }
        }
        if candidate != *catalog {
            self.store.save(&candidate)?;
            *catalog = candidate;
        }
        Ok(())
    }
}

fn recovery_error() -> DesktopError {
    DesktopError::Credential(RECOVERY.to_string())
}

fn device_claims(state: &DesktopState) -> BTreeSet<String> {
    state
        .desktop_agent_control
        .device_id
        .iter()
        .cloned()
        .chain(
            state
                .pending_disconnect_cleanup
                .iter()
                .flat_map(|cleanup| cleanup.credential_slots.iter())
                .filter(|slot| slot.namespace == DisconnectCredentialNamespace::DesktopAgentDevice)
                .map(|slot| slot.account_key.clone()),
        )
        .collect()
}

fn legacy_keys(state: &DesktopState) -> BTreeSet<String> {
    let mut keys = device_claims(state);
    if state.desktop_agent_control.credential_key.is_some() {
        if let Some(device_id) = &state.desktop_agent_control.device_id {
            keys.remove(device_id);
            // The same old ID might independently remain in a pending journal.
            if state
                .pending_disconnect_cleanup
                .iter()
                .flat_map(|cleanup| &cleanup.credential_slots)
                .any(|slot| {
                    slot.namespace == DisconnectCredentialNamespace::DesktopAgentDevice
                        && &slot.account_key == device_id
                })
            {
                keys.insert(device_id.clone());
            }
        }
    }
    keys
}

fn migrate_owned_state(
    state: &DesktopState,
    identity: &SessionIdentity,
    credentials: &dyn CredentialStore,
) -> CoreResult<DesktopState> {
    let fingerprint = migration_fingerprint(state, identity)?;
    if state.desktop_agent_control.enabled && state.desktop_agent_control.credential_key.is_none() {
        let binding = state.desktop_agent_control.pair_fingerprint.as_deref();
        // Preserve the serialized historical fingerprint and journal exactly.
        // An older root-bound enrollment can still be disabled safely, while
        // its existing assertion policy remains in force until re-enrollment.
        if binding != Some(&fingerprint)
            && !state.pairs().any(|pair| {
                desktop_agent_enrollment_fingerprint(&pair.server_url, &pair.account_email)
                    == fingerprint
                    && binding == Some(desktop_agent_pair_fingerprint(pair).as_str())
            })
        {
            return Err(recovery_error());
        }
    }
    let mut next = state.clone();
    for legacy in legacy_keys(state) {
        if validate_desktop_agent_device_credential_key(&legacy).is_ok() {
            return Err(recovery_error());
        }
        let scoped = desktop_agent_device_credential_key(&fingerprint, &legacy)?;
        migrate_exact_credential(credentials, &legacy, &scoped)?;
        if next.desktop_agent_control.device_id.as_deref() == Some(&legacy)
            && next.desktop_agent_control.credential_key.is_none()
        {
            next.desktop_agent_control.credential_key = Some(scoped.clone());
        }
        if let Some(cleanup) = &mut next.pending_disconnect_cleanup {
            for slot in &mut cleanup.credential_slots {
                if slot.namespace == DisconnectCredentialNamespace::DesktopAgentDevice
                    && slot.account_key == legacy
                {
                    slot.namespace = DisconnectCredentialNamespace::DesktopAgentDeviceScoped;
                    slot.account_key = scoped.clone();
                }
            }
            cleanup.credential_slots.sort();
            cleanup.credential_slots.dedup();
        }
    }
    Ok(next)
}

/// Copy/read back the scoped destination before removing the proved old slot.
/// If state publication fails after deletion, the durable old owner can resume
/// from its own scoped copy on restart. Conflicting copies are retained.
fn migrate_exact_credential(
    store: &dyn CredentialStore,
    legacy: &str,
    scoped: &str,
) -> CoreResult<()> {
    let old = store.get(legacy)?;
    let new = store.get(scoped)?;
    match (old.as_deref(), new.as_deref()) {
        (Some(old), Some(new)) if old != new => return Err(recovery_error()),
        (Some(old), None) => write_exact_agent_credential(store, scoped, old)?,
        _ => {}
    }
    if old.is_some()
        && classify_exact_credential_removal(store.delete(legacy), store.get(legacy))
            != ExactCredentialRemoval::Removed
    {
        return Err(recovery_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
