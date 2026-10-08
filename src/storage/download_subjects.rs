use std::collections::HashSet;

use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    download_subjects::{CurrentFileSubject, FileContentSubject, RevisionSubject},
    error::{ApiError, ApiResult},
};

mod bulk;

pub(super) fn ensure_file_content_subjects(
    tx: &Transaction<'_>,
    scoped_file_ids: &[String],
    subjects: &[FileContentSubject],
) -> ApiResult<()> {
    let scoped = scoped_file_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if subjects.len() > 64
        && subjects
            .iter()
            .all(|subject| matches!(subject, FileContentSubject::Current(_)))
    {
        let current = subjects
            .iter()
            .filter_map(|subject| match subject {
                FileContentSubject::Current(subject) => Some(subject),
                FileContentSubject::Revision(_) => None,
            })
            .collect::<Vec<_>>();
        if current
            .iter()
            .any(|subject| !scoped.contains(subject.file_id.as_str()))
        {
            return Err(ApiError::NotFound);
        }
        return bulk::ensure_current_file_subjects(tx, &current);
    }
    for subject in subjects {
        if !scoped.contains(subject.file_id()) {
            return Err(ApiError::NotFound);
        }
        match subject {
            FileContentSubject::Current(subject) => ensure_current_file_subject(tx, subject)?,
            FileContentSubject::Revision(subject) => ensure_revision_subject(tx, subject)?,
        }
    }
    Ok(())
}

pub(super) fn ensure_current_file_subjects(
    tx: &Transaction<'_>,
    scoped_file_ids: &[String],
    subjects: &[CurrentFileSubject],
) -> ApiResult<()> {
    let scoped = scoped_file_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if subjects.len() > 64 {
        if subjects
            .iter()
            .any(|subject| !scoped.contains(subject.file_id.as_str()))
        {
            return Err(ApiError::NotFound);
        }
        return bulk::ensure_current_file_subjects(tx, &subjects.iter().collect::<Vec<_>>());
    }
    for subject in subjects {
        if !scoped.contains(subject.file_id.as_str()) {
            return Err(ApiError::NotFound);
        }
        ensure_current_file_subject(tx, subject)?;
    }
    Ok(())
}

fn ensure_current_file_subject(
    tx: &Transaction<'_>,
    subject: &CurrentFileSubject,
) -> ApiResult<()> {
    let stored = tx
        .query_row(
            "SELECT revision, content_hash, content_bytes
             FROM files WHERE id = ?1 AND kind = 'file'",
            params![&subject.file_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()?;
    let matches = stored.is_some_and(|(revision, hash, bytes)| {
        revision == subject.revision
            && hash.as_deref() == Some(subject.content_hash.as_str())
            && stored_size_matches(bytes, subject.expected_size)
    });
    matches.then_some(()).ok_or(ApiError::NotFound)
}

fn ensure_revision_subject(tx: &Transaction<'_>, subject: &RevisionSubject) -> ApiResult<()> {
    let stored = tx
        .query_row(
            "SELECT content_hash, content_bytes FROM file_revisions
             WHERE file_id = ?1 AND revision = ?2",
            params![&subject.file_id, subject.revision],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let matches = stored.is_some_and(|(hash, bytes)| {
        hash.as_deref() == Some(subject.content_hash.as_str())
            && stored_size_matches(Some(bytes), subject.expected_size)
    });
    matches.then_some(()).ok_or(ApiError::NotFound)
}

fn stored_size_matches(stored: Option<i64>, expected: u64) -> bool {
    stored.and_then(|bytes| u64::try_from(bytes).ok()) == Some(expected)
}
