//! App-owned catalog around independently authenticated native runtimes.
//!
//! The sync core remains one account per Runtime. Catalog admission owns IDs,
//! identity reservations and lifecycle metadata; native adapters still own
//! credential retirement and physical filesystem publication.

mod device_credentials;
mod migration;
mod model;
mod mutations;
mod recovery;
mod store;
#[cfg(test)]
mod tests;
mod view;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use shellx_drive_desktop_core::{
    DesktopState, DirectoryIdentity, Result as CoreResult, StateStore,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::Runtime;
use crate::session_identity::SessionIdentity;
use migration::{merge_folders, state_folders};
use model::{invalid, validate_id, AppCatalog, ConnectionStorage};
use store::CatalogStore;

pub(crate) use model::{AppPreferences, ConnectionLifecycle, LEGACY_CONNECTION_ID};
pub(crate) use view::{ConnectionView, ConnectionsView};

pub(crate) type RuntimeFactory = fn(StateStore, DesktopState) -> CoreResult<Runtime>;

#[derive(Clone, Debug)]
pub(crate) struct ConnectionFolderReservation {
    pub(crate) connection_id: String,
    pub(crate) name: String,
    pub(crate) path: std::path::PathBuf,
    pub(crate) identity: Option<DirectoryIdentity>,
}

pub(crate) struct ConnectionManager {
    primary: Arc<Runtime>,
    factory: RuntimeFactory,
    store: CatalogStore,
    catalog: Mutex<AppCatalog>,
    runtimes: RwLock<BTreeMap<String, Arc<Runtime>>>,
    unavailable: RwLock<BTreeSet<String>>,
    // Native folder validation and publication hold this only through local
    // admission. No network request may run while holding the global lock.
    pub(crate) admission: tokio::sync::Mutex<()>,
    sync_permits: Arc<Semaphore>,
    update_in_progress: AtomicBool,
}

pub(crate) struct GlobalUpdateGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for GlobalUpdateGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

impl ConnectionManager {
    pub(crate) fn load(primary: Arc<Runtime>, factory: RuntimeFactory) -> CoreResult<Self> {
        let manager = Self::load_without_credential_migration(primary, factory)?;
        manager.migrate_desktop_agent_credentials()?;
        Ok(manager)
    }

    /// Package-removal verification cannot move or retire a retained secret.
    pub(crate) fn load_without_credential_migration(
        primary: Arc<Runtime>,
        factory: RuntimeFactory,
    ) -> CoreResult<Self> {
        let store = CatalogStore::new(primary.store.path())?;
        let catalog = match store.load()? {
            Some(catalog) => catalog,
            None => migration::legacy_catalog(&primary)?,
        };
        let manager = Self {
            primary,
            factory,
            store,
            catalog: Mutex::new(catalog),
            runtimes: RwLock::new(BTreeMap::new()),
            unavailable: RwLock::new(BTreeSet::new()),
            admission: tokio::sync::Mutex::new(()),
            sync_permits: Arc::new(Semaphore::new(2)),
            update_in_progress: AtomicBool::new(false),
        };
        manager.reconcile_catalog()?;
        Ok(manager)
    }

    pub(crate) fn resolve(&self, connection_id: Option<&str>) -> CoreResult<Arc<Runtime>> {
        // The app retains its primary platform/updater owner after a legacy
        // connection is retired. That Arc is no longer a connection and must
        // never acquire a replacement profile's canonical credential by default.
        let id = connection_id.unwrap_or(LEGACY_CONNECTION_ID);
        validate_id(id)?;
        if self
            .unavailable
            .read()
            .expect("connection availability lock")
            .contains(id)
        {
            return Err(invalid("this connection's saved state is unavailable; its identity and folders remain reserved"));
        }
        self.runtimes
            .read()
            .expect("connection runtimes lock")
            .get(id)
            .cloned()
            .ok_or_else(|| invalid("unknown connection ID"))
    }

    /// Access the app's platform services even when the legacy connection
    /// needs recovery. This does not admit state or credential mutation;
    /// connection work must still use `resolve` and its lifecycle guards.
    pub(crate) fn app_service_runtime(&self) -> Arc<Runtime> {
        Arc::clone(&self.primary)
    }

    pub(crate) fn all_runtimes(&self) -> Vec<Arc<Runtime>> {
        let unavailable = self
            .unavailable
            .read()
            .expect("connection availability lock")
            .clone();
        let runtimes = self.runtimes.read().expect("connection runtimes lock");
        let mut result = runtimes
            .iter()
            .filter(|(id, _)| !unavailable.contains(*id))
            .map(|(_, runtime)| Arc::clone(runtime))
            .collect::<Vec<_>>();
        if !unavailable.contains(LEGACY_CONNECTION_ID)
            && !result
                .iter()
                .any(|runtime| Arc::ptr_eq(runtime, &self.primary))
        {
            result.insert(0, Arc::clone(&self.primary));
        }
        result
    }

    pub(crate) fn id_for_runtime(&self, runtime: &Runtime) -> Option<String> {
        self.runtimes
            .read()
            .expect("connection runtimes lock")
            .iter()
            .find(|(_, candidate)| std::ptr::eq(candidate.as_ref(), runtime))
            .map(|(id, _)| id.clone())
    }

    pub(crate) fn identity_for(&self, id: &str) -> Option<SessionIdentity> {
        self.catalog
            .lock()
            .expect("connection catalog lock")
            .connections
            .iter()
            .find(|profile| profile.id == id)
            .and_then(|profile| profile.identity.as_ref())
            .map(|identity| identity.session())
    }

    pub(crate) fn identity_for_runtime(&self, runtime: &Runtime) -> Option<SessionIdentity> {
        self.id_for_runtime(runtime)
            .and_then(|id| self.identity_for(&id))
    }

    pub(crate) fn has_unavailable_connections(&self) -> bool {
        !self
            .unavailable
            .read()
            .expect("connection availability lock")
            .is_empty()
    }

    pub(crate) fn is_preparing(&self, id: &str) -> bool {
        self.catalog
            .lock()
            .expect("connection catalog lock")
            .connections
            .iter()
            .any(|profile| profile.id == id && profile.lifecycle == ConnectionLifecycle::Preparing)
    }

    pub(crate) fn preferences(&self) -> AppPreferences {
        self.catalog
            .lock()
            .expect("connection catalog lock")
            .preferences
            .clone()
    }

    pub(crate) fn effective_interval(&self, runtime: &Runtime) -> Duration {
        let id = self.id_for_runtime(runtime);
        let catalog = self.catalog.lock().expect("connection catalog lock");
        let seconds = id
            .and_then(|id| catalog.connections.iter().find(|profile| profile.id == id))
            .and_then(|profile| profile.interval_seconds)
            .unwrap_or(catalog.preferences.default_sync_interval_seconds);
        Duration::from_secs(seconds)
    }

    pub(crate) fn may_sync(&self, runtime: &Runtime) -> bool {
        if self.update_in_progress.load(Ordering::Acquire) {
            return false;
        }
        self.id_for_runtime(runtime).is_some_and(|id| {
            let catalog = self.catalog.lock().expect("connection catalog lock");
            catalog
                .connections
                .iter()
                .any(|profile| profile.id == id && profile.lifecycle == ConnectionLifecycle::Active)
                && !self
                    .unavailable
                    .read()
                    .expect("connection availability lock")
                    .contains(&id)
        })
    }

    pub(crate) fn ensure_mutation_allowed(&self) -> CoreResult<()> {
        if self.update_in_progress.load(Ordering::Acquire) {
            return Err(invalid(
                "a desktop update is in progress; retry after it finishes",
            ));
        }
        Ok(())
    }

    /// Serialize the flag with catalog mutation, then release that lock before
    /// the caller quiesces runtimes or downloads the verified update.
    pub(crate) fn begin_global_update(&self) -> CoreResult<GlobalUpdateGuard<'_>> {
        let _catalog = self.catalog.lock().expect("connection catalog lock");
        self.update_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| invalid("a desktop update is already in progress"))?;
        Ok(GlobalUpdateGuard {
            flag: &self.update_in_progress,
        })
    }

    /// Tokio's semaphore is FIFO. Each runtime also retains its own pass lock.
    pub(crate) async fn acquire_sync_permit(&self) -> CoreResult<OwnedSemaphorePermit> {
        Arc::clone(&self.sync_permits)
            .acquire_owned()
            .await
            .map_err(|_| invalid("sync scheduler is stopped"))
    }

    pub(crate) async fn acquire_sync_permit_for(
        &self,
        runtime: &Runtime,
    ) -> CoreResult<OwnedSemaphorePermit> {
        if !self.may_sync(runtime) {
            return Err(invalid(
                "connection setup or removal must finish before sync",
            ));
        }
        let permit = self.acquire_sync_permit().await?;
        if !self.may_sync(runtime) {
            return Err(invalid(
                "connection setup or removal must finish before sync",
            ));
        }
        Ok(permit)
    }

    /// Include durable roots even when the state is unavailable or cleanup has
    /// already cleared its live pair fields. Native physical checks stay below
    /// this metadata collection boundary.
    pub(crate) fn folder_reservations(&self) -> Vec<ConnectionFolderReservation> {
        let catalog = self
            .catalog
            .lock()
            .expect("connection catalog lock")
            .clone();
        let runtimes = self.runtimes.read().expect("connection runtimes lock");
        catalog
            .connections
            .iter()
            .flat_map(|profile| {
                let mut folders = profile.reserved_folders.clone();
                if let Some(runtime) = runtimes.get(&profile.id) {
                    merge_folders(&mut folders, state_folders(&runtime.coordinator.snapshot()));
                }
                folders
                    .into_iter()
                    .map(|folder| ConnectionFolderReservation {
                        connection_id: profile.id.clone(),
                        name: profile.name.clone(),
                        path: folder.path,
                        identity: folder.identity,
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub(crate) fn validate_local_folder(&self, id: &str, path: &Path) -> CoreResult<()> {
        self.ensure_mutation_allowed()?;
        self.resolve(Some(id))?;
        let reservations = self
            .folder_reservations()
            .into_iter()
            .map(|folder| (folder.name, folder.path))
            .collect::<Vec<_>>();
        super::connection_folders::ensure_separate_folder(path, &reservations)
    }

    pub(crate) fn validate_add_root_folder(&self, id: &str, path: &Path) -> CoreResult<()> {
        self.ensure_mutation_allowed()?;
        self.resolve(Some(id))?;
        let reservations = self
            .folder_reservations()
            .into_iter()
            .filter(|folder| folder.connection_id != id)
            .map(|folder| (folder.name, folder.path))
            .collect::<Vec<_>>();
        super::connection_folders::ensure_separate_folder(path, &reservations)
    }

    /// A missing disk on another connection cannot halt a healthy admitted
    /// connection. Its own native adapter still verifies its saved identity and
    /// marker. New admission uses the stricter helpers above.
    pub(crate) fn validate_existing_connection_folder(
        &self,
        id: &str,
        path: &Path,
    ) -> CoreResult<()> {
        self.resolve(Some(id))?;
        let reservations = self
            .folder_reservations()
            .into_iter()
            .filter(|folder| folder.connection_id != id)
            .map(|folder| (folder.name, folder.path))
            .collect::<Vec<_>>();
        super::connection_folders::ensure_existing_folder_separate(path, &reservations)
    }

    pub(super) fn state_store(
        &self,
        id: &str,
        storage: &ConnectionStorage,
    ) -> CoreResult<StateStore> {
        self.store.profile_store(id, storage)
    }
}
