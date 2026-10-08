use crate::{
    error::{ApiError, ApiResult},
    model::DriveFile,
};

/// Immutable identity of the current body selected while preparing a ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CurrentFileSubject {
    pub file_id: String,
    pub revision: i64,
    pub content_hash: String,
    pub expected_size: u64,
}

impl CurrentFileSubject {
    pub(crate) fn from_file(file: &DriveFile) -> ApiResult<Self> {
        let content_hash = file.content_hash.clone().ok_or(ApiError::NotFound)?;
        let expected_size = u64::try_from(file.size_bytes.ok_or(ApiError::NotFound)?)
            .map_err(|_| ApiError::Validation("file has an invalid stored size".to_string()))?;
        Ok(Self {
            file_id: file.id.clone(),
            revision: file.revision,
            content_hash,
            expected_size,
        })
    }
}

/// Immutable identity of a selected historical revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RevisionSubject {
    pub file_id: String,
    pub revision: i64,
    pub content_hash: String,
    pub expected_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FileContentSubject {
    Current(CurrentFileSubject),
    Revision(RevisionSubject),
}

impl FileContentSubject {
    pub(crate) fn file_id(&self) -> &str {
        match self {
            Self::Current(subject) => &subject.file_id,
            Self::Revision(subject) => &subject.file_id,
        }
    }

    pub(crate) fn expected_size(&self) -> u64 {
        match self {
            Self::Current(subject) => subject.expected_size,
            Self::Revision(subject) => subject.expected_size,
        }
    }
}
