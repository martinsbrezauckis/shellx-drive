//! Linux reconciliation authority-boundary tests.

use super::*;

use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{SyncRootKind, SyncRootRole};
use std::{io::Read, os::unix::fs::MetadataExt};

fn root(role: SyncRootRole, expires_at: Option<chrono::DateTime<Utc>>) -> SyncRoot {
    SyncRoot {
        id: "item-grant:opaque".to_string(),
        kind: SyncRootKind::ItemGrant,
        workspace_id: "workspace".to_string(),
        root_file_id: Some("folder".to_string()),
        grant_id: Some("grant".to_string()),
        owner_label: "Owner".to_string(),
        role,
        access_generation: 1,
        expires_at,
        label: "Shared folder".to_string(),
    }
}

#[test]
fn viewer_or_expired_grant_cannot_reach_a_write_terminal_boundary() {
    assert!(require_write_grant(&root(SyncRootRole::Viewer, None)).is_err());
    assert!(require_write_grant(&root(
        SyncRootRole::Editor,
        Some(Utc::now() - Duration::seconds(1)),
    ))
    .is_err());
    assert!(require_write_grant(&root(SyncRootRole::Editor, None)).is_ok());
}

#[test]
fn ordinary_linux_plan_rejects_aggregate_downloads_above_pass_budget() {
    let per_file_bytes = 11 * 1024 * 1024 * 1024;
    let remote = ["one", "two"].map(|id| RemoteEntry {
        id: id.to_string(),
        parent_id: None,
        name: format!("{id}.bin"),
        kind: RemoteEntryKind::File,
        revision: 1,
        content_hash: Some("a".repeat(64)),
        size_bytes: Some(per_file_bytes),
        trashed: false,
    });
    let plan = ReconcilePlan {
        actions: remote
            .iter()
            .map(|entry| SyncAction::Download {
                remote_id: entry.id.clone(),
                relative_path: PathBuf::from(&entry.name),
                revision: entry.revision,
                precondition: DownloadPrecondition::Absent,
            })
            .collect(),
        reviews: Vec::new(),
        remote_paths: Default::default(),
    };

    let mut cycle_budget = SyncCycleBudget::new(SyncPassLimits::default());
    assert!(cycle_budget
        .admit(&remote, &plan.actions)
        .unwrap_err()
        .to_string()
        .contains("aggregate download limit"));

    let within_limit = remote.clone().map(|mut entry| {
        entry.size_bytes = Some(10 * 1024 * 1024 * 1024);
        entry
    });
    assert!(cycle_budget.admit(&within_limit, &plan.actions).is_ok());

    let mut missing_size = within_limit;
    missing_size[0].size_bytes = None;
    assert!(cycle_budget.admit(&missing_size, &plan.actions).is_err());
}

#[test]
fn upload_snapshot_keeps_validated_bytes_after_an_in_place_source_edit() {
    let directory = tempfile::tempdir().unwrap();
    let local_root = directory.path().join("paired");
    fs::create_dir(&local_root).unwrap();
    let relative_path = PathBuf::from("notes.txt");
    let source_path = local_root.join(&relative_path);
    fs::write(&source_path, b"source bytes").unwrap();
    let original_inode = fs::metadata(&source_path).unwrap().ino();
    let original_hash = shellx_drive_desktop_core::hash_reader_bounded(
        fs::File::open(&source_path).unwrap(),
        shellx_drive_desktop_core::LocalScanLimits::default().max_file_bytes,
    )
    .unwrap()
    .0;
    let guard = UnixRootGuard::acquire(&local_root, None).unwrap();
    let pair = SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: local_root.clone(),
        local_root_identity: Some(guard.identity().clone()),
    };
    let planned = LocalEntry {
        relative_path: relative_path.clone(),
        content_hash: Some(original_hash),
        size_bytes: b"source bytes".len() as u64,
        is_directory: false,
        directory_identity: None,
    };
    let UploadSnapshot {
        area,
        batch,
        mut file,
        size_bytes,
    } = upload_snapshot(&guard, &pair, &relative_path, &planned).unwrap();

    // This modifies the same inode after validation, at the point where both
    // Linux create and replacement previously streamed the live descriptor.
    fs::write(&source_path, b"changed data").unwrap();
    assert_eq!(fs::metadata(&source_path).unwrap().ino(), original_inode);
    let mut uploaded_bytes = Vec::new();
    file.read_to_end(&mut uploaded_bytes).unwrap();
    assert_eq!(size_bytes, planned.size_bytes);
    assert_eq!(uploaded_bytes, b"source bytes");
    drop(file);
    area.remove_batch(&batch).unwrap();
    assert!(!batch.exists());

    assert!(upload_snapshot(&guard, &pair, &relative_path, &planned).is_err());
    let staging = shellx_drive_desktop_core::upload_staging_root(&local_root).unwrap();
    assert_eq!(
        fs::read_dir(staging)
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir())
            .count(),
        0
    );

    fs::write(&source_path, b"source bytes").unwrap();
    let stale_batch = area.create_batch(9_999).unwrap();
    fs::File::open(&stale_batch)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(
            std::time::SystemTime::now() - std::time::Duration::from_secs(25 * 60 * 60),
        ))
        .unwrap();
    let snapshot = upload_snapshot(&guard, &pair, &relative_path, &planned).unwrap();
    assert!(!stale_batch.exists());
    drop(snapshot.file);
    snapshot.area.remove_batch(&snapshot.batch).unwrap();
}
