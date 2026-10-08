use crate::Result;

/// The result of probing an exact credential destination after a mutating
/// Credential Manager call. Providers can report an error after committing a
/// write or deletion, so callers must make authority decisions from readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactCredentialRead {
    Matches,
    DifferentOrAbsent,
    Unknown,
}

pub fn classify_exact_credential_readback(
    readback: Result<Option<String>>,
    expected: &str,
) -> ExactCredentialRead {
    match readback {
        Ok(Some(value)) if value == expected => ExactCredentialRead::Matches,
        Ok(_) => ExactCredentialRead::DifferentOrAbsent,
        Err(_) => ExactCredentialRead::Unknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactCredentialWrite {
    Written,
    NotWritten,
    Unknown,
}

pub fn classify_exact_credential_write(
    _write: Result<()>,
    readback: Result<Option<String>>,
    expected: &str,
) -> ExactCredentialWrite {
    match classify_exact_credential_readback(readback, expected) {
        ExactCredentialRead::Matches => ExactCredentialWrite::Written,
        ExactCredentialRead::DifferentOrAbsent => ExactCredentialWrite::NotWritten,
        ExactCredentialRead::Unknown => ExactCredentialWrite::Unknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactCredentialRemoval {
    Removed,
    Retained,
    Unknown,
}

pub fn classify_exact_credential_removal(
    _delete: Result<()>,
    readback: Result<Option<String>>,
) -> ExactCredentialRemoval {
    match readback {
        Ok(None) => ExactCredentialRemoval::Removed,
        Ok(Some(_)) => ExactCredentialRemoval::Retained,
        Err(_) => ExactCredentialRemoval::Unknown,
    }
}
