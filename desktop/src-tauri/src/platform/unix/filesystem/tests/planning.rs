//! Planning must observe the same native directory identities as its baseline.

use std::{collections::BTreeMap, fs, path::PathBuf};

use chrono::Utc;
use shellx_drive_desktop_core::{
    inspect_local_tree_with_cancellation, plan_reconciliation, BaselineEntry, RemoteEntry,
    RemoteEntryKind, SyncAction,
};

use super::{test_fixture_directory, UnixRootGuard};

#[test]
fn unchanged_tracked_unix_folder_does_not_require_review() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).expect("paired root");
    fs::create_dir(root.join("Folder")).expect("tracked folder");
    let guard = UnixRootGuard::acquire(&root, None).expect("root guard");
    let baseline = saved_folder(&guard);
    let local = planning_tree(&guard, &root);

    let plan = plan_reconciliation(
        &baseline,
        None,
        &[remote_folder("Folder", 1)],
        &local.entries,
        Utc::now(),
    )
    .expect("unchanged plan");
    assert!(plan.actions.is_empty());
    assert!(
        plan.reviews.is_empty(),
        "unchanged folder needs no decision: {:?}",
        plan.reviews
    );
}

#[test]
fn native_unix_folder_rename_plans_one_outbound_folder_move() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).expect("paired root");
    fs::create_dir(root.join("Folder")).expect("tracked folder");
    let guard = UnixRootGuard::acquire(&root, None).expect("root guard");
    let baseline = saved_folder(&guard);
    fs::rename(root.join("Folder"), root.join("Renamed")).expect("native local rename");
    let local = planning_tree(&guard, &root);

    let plan = plan_reconciliation(
        &baseline,
        None,
        &[remote_folder("Folder", 1)],
        &local.entries,
        Utc::now(),
    )
    .expect("outbound folder plan");
    assert!(
        plan.reviews.is_empty(),
        "identity-preserving rename: {:?}",
        plan.reviews
    );
    assert_eq!(plan.actions.len(), 1);
    assert!(
        matches!(&plan.actions[0], SyncAction::MoveRemote { from, to, folder_precondition: Some(_), .. }
        if from == &PathBuf::from("Folder") && to == &PathBuf::from("Renamed"))
    );
}

#[test]
fn remote_unix_folder_rename_plans_one_inbound_folder_move() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).expect("paired root");
    fs::create_dir(root.join("Folder")).expect("tracked folder");
    let guard = UnixRootGuard::acquire(&root, None).expect("root guard");
    let baseline = saved_folder(&guard);
    let local = planning_tree(&guard, &root);

    let plan = plan_reconciliation(
        &baseline,
        None,
        &[remote_folder("Renamed", 2)],
        &local.entries,
        Utc::now(),
    )
    .expect("inbound folder plan");
    assert!(
        plan.reviews.is_empty(),
        "verified unchanged source: {:?}",
        plan.reviews
    );
    assert_eq!(plan.actions.len(), 1);
    assert!(
        matches!(&plan.actions[0], SyncAction::MoveLocal { from, to, folder_precondition: Some(_), .. }
        if from == &PathBuf::from("Folder") && to == &PathBuf::from("Renamed"))
    );
}

#[test]
fn replaced_unix_folder_still_requires_review() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).expect("paired root");
    fs::create_dir(root.join("Folder")).expect("tracked folder");
    let guard = UnixRootGuard::acquire(&root, None).expect("root guard");
    let baseline = saved_folder(&guard);
    // Retain the original inode outside the paired root so the replacement
    // cannot accidentally reuse its identity on the temporary filesystem.
    fs::rename(
        root.join("Folder"),
        directory.path().join("retained-original"),
    )
    .expect("retain original folder");
    fs::create_dir(root.join("Folder")).expect("different folder at the saved path");
    let local = planning_tree(&guard, &root);

    let plan = plan_reconciliation(
        &baseline,
        None,
        &[remote_folder("Folder", 1)],
        &local.entries,
        Utc::now(),
    )
    .expect("replacement plan");
    assert!(plan.actions.is_empty());
    assert_eq!(plan.reviews.len(), 1);
}

fn planning_tree(
    guard: &UnixRootGuard,
    root: &std::path::Path,
) -> shellx_drive_desktop_core::LocalTreeInspection {
    let mut local =
        inspect_local_tree_with_cancellation(root, || Ok(())).expect("bounded planning scan");
    guard
        .observe_directory_identities(&mut local, || Ok(()))
        .expect("native planning identities");
    local
}

fn saved_folder(guard: &UnixRootGuard) -> BTreeMap<String, BaselineEntry> {
    BTreeMap::from([(
        "folder".to_string(),
        BaselineEntry {
            remote_id: "folder".to_string(),
            parent_id: None,
            relative_path: PathBuf::from("Folder"),
            kind: "folder".to_string(),
            content_hash: None,
            revision: 1,
            directory_identity: Some(
                guard
                    .local_directory_identity(std::path::Path::new("Folder"))
                    .expect("saved native identity"),
            ),
        },
    )])
}

fn remote_folder(name: &str, revision: i64) -> RemoteEntry {
    RemoteEntry {
        id: "folder".to_string(),
        parent_id: None,
        name: name.to_string(),
        kind: RemoteEntryKind::Folder,
        revision,
        content_hash: None,
        size_bytes: None,
        trashed: false,
    }
}
