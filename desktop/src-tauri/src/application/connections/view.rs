use serde::Serialize;
use shellx_drive_desktop_core::{ActivityEntry, CoordinatorViewSnapshot, DesktopState};

use super::{model::*, ConnectionManager};
use crate::application::{runtime::pair_location_label, DesktopView, Runtime};

const MAX_CONNECTION_ACTIVITY: usize = 200;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionsView {
    pub(crate) app_version: &'static str,
    pub(crate) preferences: AppPreferences,
    pub(crate) connections: Vec<ConnectionView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) interval_seconds: Option<u64>,
    pub(crate) effective_interval_seconds: u64,
    pub(crate) connection_folder: Option<String>,
    pub(crate) lifecycle: ConnectionLifecycle,
    pub(crate) view: DesktopView,
}

impl ConnectionManager {
    pub(crate) fn view(&self) -> ConnectionsView {
        // Clone metadata before filesystem usage projection; never hold the
        // catalog admission lock during a bounded local-usage walk.
        let catalog = self
            .catalog
            .lock()
            .expect("connection catalog lock")
            .clone();
        let runtimes = self
            .runtimes
            .read()
            .expect("connection runtimes lock")
            .clone();
        let unavailable = self
            .unavailable
            .read()
            .expect("connection availability lock")
            .clone();
        let connections = catalog
            .connections
            .iter()
            .filter_map(|profile| {
                let runtime = runtimes.get(&profile.id)?;
                let snapshot = runtime.coordinator.view_snapshot();
                if profile.lifecycle == ConnectionLifecycle::Preparing
                    && snapshot.state.pairs().next().is_none()
                {
                    return None;
                }
                let (mut view, connection_folder) = project_connection_snapshot(runtime, snapshot);
                view.launch_at_login = catalog.preferences.launch_at_login;
                if let Some(error) = &profile.recovery_error {
                    view.error = Some(error.clone());
                    if profile.lifecycle == ConnectionLifecycle::Recovery {
                        view.status = "error";
                    }
                }
                if let Some(identity) = &profile.identity {
                    if view.account.is_empty() {
                        view.account = identity.account_email.clone();
                    }
                    if view.server_url.is_empty() {
                        view.server_url = identity.server_url.clone();
                        view.server_host = super::super::runtime::host_label(&identity.server_url);
                    }
                }
                if unavailable.contains(&profile.id) && view.local_root.is_empty() {
                    if let Some(folder) = profile.reserved_folders.first() {
                        view.local_root = folder.path.display().to_string();
                    }
                }
                Some(ConnectionView {
                    id: profile.id.clone(),
                    name: profile.name.clone(),
                    interval_seconds: profile.interval_seconds,
                    effective_interval_seconds: profile
                        .interval_seconds
                        .unwrap_or(catalog.preferences.default_sync_interval_seconds),
                    connection_folder,
                    lifecycle: profile.lifecycle,
                    view,
                })
            })
            .collect();
        ConnectionsView {
            app_version: env!("CARGO_PKG_VERSION"),
            preferences: catalog.preferences,
            connections,
        }
    }
}

pub(super) fn project_connection_snapshot(
    runtime: &Runtime,
    snapshot: CoordinatorViewSnapshot,
) -> (DesktopView, Option<String>) {
    let connection_folder = snapshot
        .state
        .sync_root_base
        .as_ref()
        .map(|path| path.display().to_string());
    let activity = connection_activity(&snapshot.state);
    let mut view = runtime.view_from_coordinator_snapshot(snapshot);
    // Runtime.view remains the selected-root projection used by the agent.
    // Only the app catalog exposes a connection-wide history image.
    view.activity = activity;
    (view, connection_folder)
}

fn connection_activity(state: &DesktopState) -> Vec<ActivityEntry> {
    let active = state
        .activity
        .iter()
        .enumerate()
        .map(|(index, entry)| (state.pair.as_ref(), index, entry));
    let inactive = state.inactive_pairs.iter().flat_map(|profile| {
        profile
            .activity
            .iter()
            .enumerate()
            .map(move |(index, entry)| (Some(&profile.pair), index, entry))
    });
    // Durable state bounds each root to 200 entries and the connection to 100
    // roots. Sort borrowed records; clone only the retained connection-wide 200.
    let mut entries: Vec<_> = active.chain(inactive).collect();
    entries.sort_unstable_by(|left, right| {
        right
            .2
            .at
            .cmp(&left.2.at)
            .then_with(|| {
                left.0
                    .map(|pair| &pair.local_root)
                    .cmp(&right.0.map(|pair| &pair.local_root))
            })
            .then_with(|| right.1.cmp(&left.1))
    });
    entries
        .into_iter()
        .take(MAX_CONNECTION_ACTIVITY)
        .map(|(pair, _, entry)| {
            let mut entry = entry.clone();
            if let Some(pair) = pair {
                // Display names can repeat; the reserved physical-folder path
                // makes the root label unambiguous without changing file paths.
                entry.result = format!(
                    "{} [{}] · {}",
                    pair_location_label(pair),
                    pair.local_root.display(),
                    entry.result
                );
            }
            entry
        })
        .collect()
}
