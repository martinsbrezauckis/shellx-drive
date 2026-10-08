use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use directories::ProjectDirs;

use crate::{
    state_limits::{validate_desktop_state, MAX_DESKTOP_STATE_BYTES},
    DesktopError, DesktopState, PairMarker, Result, SyncPair,
};

#[cfg(unix)]
mod unix_app_data;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairMarkerDisposition {
    Created,
    ExistingIdentical,
}

pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<DesktopState> {
        let mut file = match fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DesktopState::default());
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_DESKTOP_STATE_BYTES {
            return Err(DesktopError::InvalidState(format!(
                "state file exceeds the {MAX_DESKTOP_STATE_BYTES}-byte limit or is not a regular file"
            )));
        }
        let bytes = read_state_bytes_bounded(&mut file)?;
        let mut state = serde_json::from_slice::<DesktopState>(&bytes)
            .map_err(|error| DesktopError::InvalidState(error.to_string()))?;
        match state.schema_version {
            // Older schemas predate one or more non-secret identity fields.
            // Deserialization keeps them readable through defaults; a missing
            // physical pair-root identity stays `None` so native operations
            // require an explicit re-pair instead of silently adopting a path.
            1..=6 => state.schema_version = 7,
            7 => {}
            version => {
                return Err(DesktopError::InvalidState(format!(
                    "unsupported schema version {version}"
                )));
            }
        }
        validate_desktop_state(&state)?;
        state.prune_remote_sessions(chrono::Utc::now());
        Ok(state)
    }

    /// Atomic replacement prevents a stopped process from leaving a half JSON
    /// baseline that could misclassify the next reconciliation.
    pub fn save(&self, state: &DesktopState) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            DesktopError::InvalidState("state path has no parent directory".to_string())
        })?;
        fs::create_dir_all(parent)?;
        validate_desktop_state(state)?;
        let bytes = serde_json::to_vec_pretty(state)?;
        if bytes.len() as u64 > MAX_DESKTOP_STATE_BYTES {
            return Err(DesktopError::InvalidState(format!(
                "state serialization exceeds the {MAX_DESKTOP_STATE_BYTES}-byte limit"
            )));
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(".shellx-drive-state-")
            .suffix(".next")
            .tempfile_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }
}

/// Prepare the root marker and persist a new pair without publishing it to the
/// in-memory coordinator first. If this operation created the marker and state
/// persistence fails, the caller's exact-marker rollback runs before failure is
/// returned. An identical orphan marker is retained so the same setup can be
/// retried after an interrupted earlier attempt.
pub fn persist_pairing_state<PrepareMarker, RollbackMarker>(
    store: &StateStore,
    current: &DesktopState,
    pair: SyncPair,
    prepare_marker: PrepareMarker,
    rollback_marker: RollbackMarker,
) -> Result<DesktopState>
where
    PrepareMarker: FnOnce(&PairMarker) -> Result<PairMarkerDisposition>,
    RollbackMarker: FnOnce(&PairMarker) -> Result<()>,
{
    let marker = PairMarker::from(&pair);
    let mut candidate = current.clone();
    candidate.configure_pair(pair)?;
    let disposition = prepare_marker(&marker)?;
    if let Err(save_error) = store.save(&candidate) {
        if disposition == PairMarkerDisposition::Created {
            if let Err(rollback_error) = rollback_marker(&marker) {
                return Err(DesktopError::InvalidState(format!(
                    "pair state was not saved and its owned marker could not be rolled back: {rollback_error}"
                )));
            }
        }
        return Err(save_error);
    }
    Ok(candidate)
}

fn read_state_bytes_bounded(reader: impl Read) -> Result<Vec<u8>> {
    let maximum_plus_one = MAX_DESKTOP_STATE_BYTES
        .checked_add(1)
        .expect("desktop state limit has room for a boundary byte");
    let mut bytes = Vec::new();
    reader.take(maximum_plus_one).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DESKTOP_STATE_BYTES {
        return Err(DesktopError::InvalidState(format!(
            "state file exceeds the {MAX_DESKTOP_STATE_BYTES}-byte limit"
        )));
    }
    Ok(bytes)
}

const PRIVATE_STATE_DIRECTORY: &str = ".shellx-drive-private";

pub(crate) fn default_state_directory() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("com", "ShellX", "Drive Desktop").ok_or_else(|| {
        DesktopError::InvalidState(
            "could not determine user application data directory".to_string(),
        )
    })?;
    let directory = dirs.data_local_dir().to_path_buf();
    #[cfg(unix)]
    unix_app_data::initialize(&directory)?;
    Ok(directory)
}

pub fn default_state_path() -> Result<PathBuf> {
    Ok(default_state_directory()?.join("state.json"))
}

/// Return a dedicated, protected child of the ordinary per-user state directory.
/// Keeping this separate lets an upgrade retain legacy non-secret state while
/// making the process-lease boundary fail closed if its ACL cannot be proven.
pub fn private_state_directory() -> Result<PathBuf> {
    let state_directory = default_state_directory()?;
    fs::create_dir_all(&state_directory)?;
    let private_directory = state_directory.join(PRIVATE_STATE_DIRECTORY);
    crate::paths::ensure_private_staging_directory(&private_directory)?;
    Ok(private_directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        plan_reconciliation, BaselineEntry, DirectoryIdentity, LocalEntry, RemoteEntry,
        RemoteEntryKind,
    };
    use chrono::{Duration, Utc};
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn pair(local_root: PathBuf) -> SyncPair {
        SyncPair {
            server_url: "https://drive.example".to_string(),
            account_email: "owner@example.test".to_string(),
            workspace_id: "workspace".to_string(),
            workspace_name: "Workspace".to_string(),
            remote_root_id: None,
            remote_root_name: None,
            local_root,
            local_root_identity: None,
        }
    }

    #[test]
    fn round_trips_non_secret_state() {
        let directory = tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state.json"));
        let state = DesktopState {
            change_cursor: 42,
            ..DesktopState::default()
        };
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().change_cursor, 42);
        assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".shellx-drive-state-")
        }));
    }

    #[test]
    fn remote_session_inventory_round_trips_and_prunes_expiry() {
        let directory = tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state.json"));
        let now = Utc::now();
        let future = crate::RemoteSessionRecord::new(
            "https://drive.example.test",
            "person@example.test",
            "future-session",
            now + Duration::hours(1),
        )
        .unwrap();
        let expired = crate::RemoteSessionRecord::new(
            "https://drive.example.test",
            "person@example.test",
            "expired-session",
            now - Duration::hours(1),
        )
        .unwrap();
        let state = DesktopState {
            active_remote_session: Some(future.clone()),
            pending_remote_revocations: vec![expired, future.clone()],
            ..DesktopState::default()
        };
        store.save(&state).unwrap();
        let serialized = fs::read_to_string(store.path()).unwrap();
        assert!(!serialized.contains("bearer"));
        assert!(!serialized.contains("token"));
        let loaded = store.load().unwrap();
        assert_eq!(loaded.active_remote_session, Some(future.clone()));
        assert_eq!(loaded.pending_remote_revocations, vec![future]);
    }

    #[test]
    fn pairing_state_failure_rolls_back_only_a_marker_created_by_this_attempt() {
        let directory = tempdir().unwrap();
        let state_path = directory.path().join("state.json");
        fs::create_dir(&state_path).unwrap();
        let store = StateStore::new(state_path);
        let marker_created = std::cell::Cell::new(false);
        let marker_rolled_back = std::cell::Cell::new(false);

        let result = persist_pairing_state(
            &store,
            &DesktopState::default(),
            pair(directory.path().join("Drive")),
            |_| {
                marker_created.set(true);
                Ok(PairMarkerDisposition::Created)
            },
            |_| {
                marker_rolled_back.set(true);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(marker_created.get());
        assert!(marker_rolled_back.get());
    }

    #[test]
    fn identical_orphan_marker_can_complete_an_interrupted_pairing_retry() {
        let directory = tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state.json"));
        let local_root = directory.path().join("Drive");
        let expected = pair(local_root.clone());

        let committed = persist_pairing_state(
            &store,
            &DesktopState::default(),
            expected.clone(),
            |marker| {
                assert_eq!(marker, &PairMarker::from(&expected));
                Ok(PairMarkerDisposition::ExistingIdentical)
            },
            |_| panic!("an existing identical marker is not owned by this retry"),
        )
        .unwrap();

        assert_eq!(committed.pair, Some(expected));
        assert_eq!(store.load().unwrap(), committed);
    }

    #[test]
    fn state_read_rejects_a_byte_past_the_limit() {
        let bytes = vec![0_u8; MAX_DESKTOP_STATE_BYTES as usize + 1];
        assert!(read_state_bytes_bounded(&mut bytes.as_slice()).is_err());
    }

    #[test]
    fn save_does_not_reuse_a_predictable_temporary_name() {
        let directory = tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state.json"));
        fs::write(store.path().with_extension("json.next"), b"occupied").unwrap();

        store.save(&DesktopState::default()).unwrap();
        store.save(&DesktopState::default()).unwrap();

        assert_eq!(
            fs::read(store.path().with_extension("json.next")).unwrap(),
            b"occupied"
        );
        assert_eq!(store.load().unwrap().schema_version, 7);
    }

    #[test]
    fn v1_identity_migration_stays_passive_until_a_verified_observation_persists_it() {
        let directory = tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state.json"));
        let mut v1 = DesktopState {
            schema_version: 1,
            baseline: BTreeMap::from([(
                "folder".to_string(),
                BaselineEntry {
                    remote_id: "folder".to_string(),
                    parent_id: None,
                    relative_path: PathBuf::from("Projects"),
                    kind: "folder".to_string(),
                    content_hash: None,
                    revision: 1,
                    directory_identity: None,
                },
            )]),
            ..DesktopState::default()
        };
        let mut raw = serde_json::to_value(&v1).unwrap();
        raw["baseline"]["folder"]
            .as_object_mut()
            .unwrap()
            .remove("directory_identity");
        fs::write(store.path(), serde_json::to_vec(&raw).unwrap()).unwrap();

        v1 = store.load().unwrap();
        assert_eq!(v1.schema_version, 7);
        assert!(v1.baseline["folder"].directory_identity.is_none());

        // The Windows baseline builder performs this assignment only after it
        // opens the unchanged directory with a no-reparse FILE_ID_INFO handle.
        let identity = DirectoryIdentity::windows(7, [9; 16]);
        v1.baseline.get_mut("folder").unwrap().directory_identity = Some(identity.clone());
        store.save(&v1).unwrap();
        let observed = store.load().unwrap();
        assert_eq!(
            observed.baseline["folder"].directory_identity,
            Some(identity)
        );

        let plan = plan_reconciliation(
            &observed.baseline,
            None,
            &[RemoteEntry {
                id: "folder".to_string(),
                parent_id: None,
                name: "Projects".to_string(),
                kind: RemoteEntryKind::Folder,
                revision: 1,
                content_hash: None,
                size_bytes: None,
                trashed: false,
            }],
            &[LocalEntry {
                relative_path: PathBuf::from("Renamed"),
                content_hash: None,
                size_bytes: 0,
                is_directory: true,
                directory_identity: observed.baseline["folder"].directory_identity.clone(),
            }],
            Utc::now(),
        )
        .unwrap();
        assert!(matches!(
            plan.actions.as_slice(),
            [crate::SyncAction::MoveRemote {
                folder_precondition: Some(_),
                ..
            }]
        ));
    }
}

#[cfg(test)]
#[path = "state_agent_disconnect_tests.rs"]
mod state_agent_disconnect_tests;
