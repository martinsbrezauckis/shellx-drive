use std::path::Path;

use shellx_drive_desktop_core::{RemoteEntry, RemoteEntryKind};

use super::remote_match::exact_file;

fn file(id: &str, name: &str) -> RemoteEntry {
    RemoteEntry {
        id: id.to_string(),
        parent_id: None,
        name: name.to_string(),
        kind: RemoteEntryKind::File,
        revision: 7,
        content_hash: Some("hash".to_string()),
        size_bytes: Some(4),
        trashed: false,
    }
}

#[test]
fn terminal_witness_rejects_revision_path_and_collision_drift() {
    let expected = file("tracked", "report.txt");
    assert!(exact_file(
        std::slice::from_ref(&expected),
        None,
        &expected,
        Path::new("report.txt")
    ));

    let mut revised = expected.clone();
    revised.revision += 1;
    assert!(!exact_file(
        &[revised],
        None,
        &expected,
        Path::new("report.txt")
    ));
    assert!(!exact_file(
        std::slice::from_ref(&expected),
        None,
        &expected,
        Path::new("moved.txt")
    ));
    assert!(!exact_file(
        &[expected.clone(), file("collision", "report.txt")],
        None,
        &expected,
        Path::new("report.txt")
    ));
}
