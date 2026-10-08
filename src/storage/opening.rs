use std::{
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc, Mutex},
};

use uuid::Uuid;

use super::{fs_private, public_rate_limit_cache, Storage};

impl Storage {
    pub fn open(path: PathBuf) -> rusqlite::Result<Self> {
        // Direct users have no configured bearer. A fresh generation makes
        // operator-authorized deferred work fail closed across a reopen.
        Self::open_with_operator_credential_generation(path, format!("unbound-{}", Uuid::now_v7()))
    }

    pub(crate) fn open_with_operator_credential_generation(
        path: PathBuf,
        operator_credential_generation: String,
    ) -> rusqlite::Result<Self> {
        let conn = rusqlite::Connection::open(&path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        fs_private::set_file_private(&path)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            operator_credential_generation: Arc::from(operator_credential_generation),
            security_event_prune_countdown: Arc::new(AtomicUsize::new(0)),
            public_rate_limit_denials: public_rate_limit_cache::PublicRateLimitDenyCache::default(),
            #[cfg(test)]
            parent_validation_pause: Arc::new(Mutex::new(None)),
        })
    }
}
