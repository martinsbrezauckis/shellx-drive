use rusqlite::{params, Connection};

use super::*;

#[test]
fn large_current_subject_set_is_verified_in_bounded_query_batches() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE files (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            revision INTEGER NOT NULL,
            content_hash TEXT,
            content_bytes INTEGER
         );",
    )
    .unwrap();
    let hash = "a".repeat(64);
    let subjects = (0..1_025)
        .map(|index| CurrentFileSubject {
            file_id: format!("file-{index}"),
            revision: 7,
            content_hash: hash.clone(),
            expected_size: 19,
        })
        .collect::<Vec<_>>();
    {
        let tx = conn.transaction().unwrap();
        for subject in &subjects {
            tx.execute(
                "INSERT INTO files (id, kind, revision, content_hash, content_bytes)
                 VALUES (?1, 'file', ?2, ?3, ?4)",
                params![
                    &subject.file_id,
                    subject.revision,
                    &subject.content_hash,
                    subject.expected_size as i64
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let tx = conn.transaction().unwrap();
    let refs = subjects.iter().collect::<Vec<_>>();
    ensure_current_file_subjects(&tx, &refs).unwrap();
    tx.execute(
        "UPDATE files SET revision = revision + 1 WHERE id = ?1",
        params![&subjects[1_024].file_id],
    )
    .unwrap();
    assert!(matches!(
        ensure_current_file_subjects(&tx, &refs),
        Err(ApiError::NotFound)
    ));
}
