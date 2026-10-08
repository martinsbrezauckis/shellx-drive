use super::*;

fn create_node(storage: &Storage, workspace_id: &str, name: &str, kind: FileKind) -> DriveFile {
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: None,
                name: name.to_string(),
                kind,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0
}

#[test]
fn concurrent_keep_both_moves_allocate_distinct_names() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("drive.db");
    let first = Storage::open(path.clone()).unwrap();
    first.migrate().unwrap();
    let second = Storage::open(path).unwrap();
    for storage in [&first, &second] {
        storage
            .conn
            .lock()
            .unwrap()
            .busy_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    }
    let (workspace, _, _) = first
        .create_workspace("Race", "owner@example.test")
        .unwrap();
    let destination = create_node(&first, &workspace.id, "destination", FileKind::Folder);
    let first_source = create_node(&first, &workspace.id, "first.txt", FileKind::File);
    let second_source = create_node(&first, &workspace.id, "second.txt", FileKind::File);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let spawn_move = |storage: Storage, source_id: String| {
        let barrier = barrier.clone();
        let destination_id = destination.id.clone();
        std::thread::spawn(move || {
            barrier.wait();
            storage.update_file(
                &source_id,
                UpdateFileRequest {
                    base_revision: Some(1),
                    name: Some("winner.txt".to_string()),
                    parent_id: Some(destination_id),
                    move_to_root: None,
                    collision_policy: None,
                    replace_target_id: None,
                    replace_target_revision: None,
                    labels: None,
                    custom_metadata: None,
                },
            )
        })
    };
    let first_move = spawn_move(first.clone(), first_source.id.clone());
    let second_move = spawn_move(second, second_source.id.clone());
    barrier.wait();
    let outcomes = [first_move.join().unwrap(), second_move.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 2);
    let names = [first_source.id, second_source.id]
        .map(|id| first.get_file(&id).unwrap().unwrap())
        .into_iter()
        .map(|file| file.name)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        std::collections::BTreeSet::from([
            "winner.txt".to_string(),
            "winner (copy).txt".to_string(),
        ])
    );
}
