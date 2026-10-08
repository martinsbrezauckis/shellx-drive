use super::*;

#[test]
fn startup_requeues_claimed_jobs_and_caps_repeated_crashes() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Job recovery", "owner@example.test")
        .unwrap();
    let first = create_file(&storage, &workspace.id, "first.txt");
    let second = create_file(&storage, &workspace.id, "second.txt");
    let jobs = storage.queued_background_jobs().unwrap();
    for job in &jobs {
        assert!(storage.mark_background_job_running(&job.id).unwrap());
    }
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE background_jobs SET attempts = ?1 WHERE file_id = ?2",
            params![MAX_BACKGROUND_JOB_ATTEMPTS, &second.id],
        )
        .unwrap();

    assert_eq!(storage.recover_running_background_jobs().unwrap(), (2, 2));
    let jobs = storage.list_background_jobs().unwrap();
    let recovered = jobs
        .iter()
        .filter(|job| job.file_id.as_deref() == Some(first.id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(recovered.len(), 2);
    assert!(recovered.iter().all(|job| job.status == "queued"));
    assert!(recovered.iter().all(|job| {
        job.last_error
            .as_deref()
            .unwrap()
            .contains("restarted before")
    }));
    let capped = jobs
        .iter()
        .filter(|job| job.file_id.as_deref() == Some(second.id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(capped.len(), 2);
    assert!(capped.iter().all(|job| job.status == "failed"));
    assert!(capped.iter().all(|job| job.finished_at.is_some()));
}
