use std::collections::HashMap;

use rusqlite::{params_from_iter, Transaction};

use crate::{
    download_subjects::CurrentFileSubject,
    error::{ApiError, ApiResult},
};

const SUBJECT_QUERY_BATCH: usize = 512;

#[cfg(test)]
mod tests;

pub(super) fn ensure_current_file_subjects(
    tx: &Transaction<'_>,
    subjects: &[&CurrentFileSubject],
) -> ApiResult<()> {
    let mut stored = HashMap::with_capacity(subjects.len());
    for batch in subjects.chunks(SUBJECT_QUERY_BATCH) {
        let placeholders = std::iter::repeat_n("?", batch.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT id, revision, content_hash, content_bytes FROM files
             WHERE kind = 'file' AND id IN ({placeholders})"
        );
        let mut statement = tx.prepare(&sql)?;
        let rows = statement.query_map(
            params_from_iter(batch.iter().map(|subject| subject.file_id.as_str())),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ),
                ))
            },
        )?;
        stored.extend(rows.collect::<rusqlite::Result<HashMap<_, _>>>()?);
    }
    for subject in subjects {
        let matches = stored
            .get(&subject.file_id)
            .is_some_and(|(revision, hash, bytes)| {
                *revision == subject.revision
                    && hash.as_deref() == Some(subject.content_hash.as_str())
                    && super::stored_size_matches(*bytes, subject.expected_size)
            });
        if !matches {
            return Err(ApiError::NotFound);
        }
    }
    Ok(())
}
