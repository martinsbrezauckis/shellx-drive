use shellx_drive_desktop_core::{DesktopState, Result as CoreResult};

use super::{model::*, Runtime};

pub(super) fn legacy_catalog(primary: &Runtime) -> CoreResult<AppCatalog> {
    let state = primary.coordinator.snapshot();
    let persisted = primary.store.path().try_exists()?;
    let has_connection = !state.uninstall_cleanup_ready()
        || state.pairs().next().is_some()
        || primary.session.lock().expect("session lock").is_some();
    let mut catalog = AppCatalog::default();
    if persisted || has_connection {
        catalog.preferences.initialized = true;
        catalog.preferences.launch_at_login = state.launch_at_login;
    }
    if has_connection {
        let identity = state_identity(&state)?;
        let name = identity
            .as_ref()
            .map(|identity| {
                url::Url::parse(&identity.server_url)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_string))
                    .unwrap_or_else(|| "Drive".to_string())
            })
            .unwrap_or_else(|| "Drive recovery".to_string());
        catalog.connections.push(ConnectionProfile {
            id: LEGACY_CONNECTION_ID.to_string(),
            name,
            storage: ConnectionStorage::Legacy,
            identity,
            interval_seconds: None,
            lifecycle: if state.has_pending_disconnect_cleanup() {
                ConnectionLifecycle::Removing
            } else if state.pairs().next().is_some() {
                ConnectionLifecycle::Active
            } else {
                ConnectionLifecycle::Recovery
            },
            reserved_folders: state_folders(&state),
            recovery_error: None,
        });
    }
    catalog.validate()?;
    Ok(catalog)
}

pub(super) fn state_identity(state: &DesktopState) -> CoreResult<Option<ConnectionIdentity>> {
    let identity = state
        .pair
        .as_ref()
        .map(|pair| (&pair.server_url, &pair.account_email))
        .or_else(|| {
            state
                .active_remote_session
                .as_ref()
                .map(|record| (&record.server_url, &record.account_email))
        });
    identity
        .map(|(url, email)| verified_identity(url, email).map(ConnectionIdentity::from_session))
        .transpose()
}

pub(super) fn state_identity_keys(state: &DesktopState) -> Vec<String> {
    let mut keys = state
        .pairs()
        .map(|pair| {
            crate::session_identity::SessionIdentity::credential_key_for(
                &pair.server_url,
                &pair.account_email,
            )
        })
        .chain(state.active_remote_session.iter().map(|record| {
            crate::session_identity::SessionIdentity::credential_key_for(
                &record.server_url,
                &record.account_email,
            )
        }))
        .collect::<Vec<_>>();
    // A rejected duplicate can retain an exact pending session for cleanup.
    // That session does not claim the account's canonical credential or block
    // the real owner's reconnect. Canonical ownership comes only from catalog
    // admission, paired roots or an actually published active session.
    keys.sort();
    keys.dedup();
    keys
}

pub(super) fn state_folders(state: &DesktopState) -> Vec<ReservedFolder> {
    let mut folders = Vec::new();
    if let Some(base) = &state.sync_root_base {
        folders.push(ReservedFolder {
            path: base.clone(),
            identity: state
                .pairs()
                .find(|pair| pair.local_root == *base)
                .and_then(|pair| pair.local_root_identity.clone()),
        });
    }
    folders.extend(state.pairs().map(|pair| ReservedFolder {
        path: pair.local_root.clone(),
        identity: pair.local_root_identity.clone(),
    }));
    if let Some(cleanup) = &state.pending_disconnect_cleanup {
        folders.extend(cleanup.markers().map(|marker| ReservedFolder {
            path: marker.local_root.clone(),
            identity: marker.marker.local_root_identity.clone(),
        }));
    }
    merge_folders(&mut folders, Vec::new());
    folders
}

pub(super) fn merge_folders(existing: &mut Vec<ReservedFolder>, additional: Vec<ReservedFolder>) {
    for folder in additional {
        if let Some(previous) = existing.iter_mut().find(|value| value.path == folder.path) {
            if previous.identity.is_none() {
                previous.identity = folder.identity;
            }
        } else {
            existing.push(folder);
        }
    }
    existing.sort_by(|left, right| left.path.cmp(&right.path));
    existing.dedup_by(|left, right| left.path == right.path);
}
