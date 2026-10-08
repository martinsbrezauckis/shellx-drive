use std::{io, path::PathBuf};

use thiserror::Error;

pub type Result<T, E = DesktopError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum DesktopError {
    #[error("another synchronization pass is already active")]
    SyncAlreadyRunning,
    #[error("synchronization stopped because Disconnect is waiting")]
    SyncCancelledForDisconnect,
    #[error("sync is paused; resume before starting a reconciliation pass")]
    SyncPaused,
    #[error("a deletion or conflict review is pending; recheck it before another sync pass")]
    ReviewPending,
    #[error("a sync pair has not been configured")]
    NeedsSetup,
    #[error("the saved Drive pair needs you to sign in again before synchronization can continue")]
    NeedsReconnect,
    #[error("local folder must be empty before it can be paired: {0}")]
    LocalFolderNotEmpty(PathBuf),
    #[error("unsafe filesystem link, hard link, or Windows reparse point: {0}")]
    UnsafeLink(PathBuf),
    #[error("unsafe local path: {0}")]
    UnsafePath(String),
    #[error("selected remote folder was not present in the manifest: {0}")]
    UnknownRemoteRoot(String),
    #[error("remote manifest has a parent cycle at {0}")]
    RemoteParentCycle(String),
    #[error("remote manifest contains a case-colliding path: {0}")]
    CaseCollision(String),
    #[error("unsupported server URL: {0}")]
    InvalidServerUrl(String),
    #[error("server rejected the request ({status}): {message}")]
    Server { status: u16, message: String },
    #[error("Drive has more available locations than this desktop can discover; existing locations may continue, but adding locations is paused")]
    RootDiscoveryOverflow,
    #[error("credential store error: {0}")]
    Credential(String),
    #[error("state file is invalid: {0}")]
    InvalidState(String),
    #[error("sync cycle resource budget exceeded: {0}")]
    SyncCycleBudgetExceeded(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
