use super::*;
use shellx_drive_desktop_core::{download_staging_root, initialize_owned_staging_root};
use std::fs;

#[test]
fn admission_counts_recovery_and_reserve() {
    let budget = DownloadSpaceBudget::new(100, 200);
    let required = budget.required_bytes().unwrap();
    assert_eq!(required, 300 + FREE_SPACE_RESERVE_BYTES);
    assert!(ensure_available(required - 1, required).is_err());
    assert!(ensure_available(required, required).is_ok());
    assert!(DownloadSpaceBudget::new(u64::MAX, 1)
        .required_bytes()
        .is_err());
}

#[test]
fn write_rejects_an_oversized_requirement_before_touching_payload() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("payload");
    let mut file = File::create(&path).unwrap();
    let mut budget = DownloadSpaceBudget::new(u64::MAX, 0);
    assert!(budget.write_chunk(&mut file, b"blocked").is_err());
    assert_eq!(file.metadata().unwrap().len(), 0);

    let mut progressing = DownloadSpaceBudget::new(10, 20);
    progressing.written_bytes = 4;
    assert_eq!(
        progressing.required_bytes().unwrap(),
        26 + FREE_SPACE_RESERVE_BYTES
    );
}

#[test]
fn terminal_remote_and_local_drift_do_not_retain_verified_downloads() {
    let directory = tempfile::tempdir().unwrap();
    let pair = directory.path().join("paired");
    fs::create_dir(&pair).unwrap();
    let staging = download_staging_root(&pair).unwrap();
    let owned = initialize_owned_staging_root(&pair, &staging, "download").unwrap();
    // Repeated remote drift, local precondition drift, and a terminal manifest
    // error have the same disposition: no local body was displaced.
    for revision in 1..=3 {
        let batch = owned.create_batch(revision).unwrap();
        fs::write(batch.join("payload"), b"verified remote").unwrap();
        finish_failed_download(&owned, &batch, false).unwrap();
        assert!(!batch.exists());
    }

    let partial = owned.create_batch(4).unwrap();
    fs::write(partial.join("payload"), b"partial").unwrap();
    finish_failed_download(&owned, &partial, false).unwrap();
    assert!(!partial.exists());
}

#[test]
fn prepared_replacement_keeps_prior_local_body_for_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let pair = directory.path().join("paired");
    fs::create_dir(&pair).unwrap();
    let staging = download_staging_root(&pair).unwrap();
    let owned = initialize_owned_staging_root(&pair, &staging, "download").unwrap();

    let verified = owned.create_batch(2).unwrap();
    fs::write(verified.join("payload"), b"verified remote").unwrap();
    fs::write(verified.join("local-recovery"), b"previous local").unwrap();
    finish_failed_download(&owned, &verified, true).unwrap();
    assert_eq!(
        fs::read(verified.join("local-recovery")).unwrap(),
        b"previous local"
    );
    assert!(owned.remove_batch(&verified).is_err());
}
