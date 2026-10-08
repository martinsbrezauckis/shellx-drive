use std::{io::Read as _, path::Path, time::Duration};

use anyhow::{bail, Context as _};
use sha2::{Digest as _, Sha256};

const MAX_ADDITIONAL_CA_BYTES: u64 = 1024 * 1024;
const SYNC_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub(super) struct AdditionalCa {
    certificate: reqwest::Certificate,
    pub(super) sha256: String,
}

pub(super) fn read_additional_ca(path: &Path) -> anyhow::Result<AdditionalCa> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open Drive CA file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect Drive CA file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("Drive CA file must be a real regular file, not a link");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.mode() & 0o022 != 0 {
            bail!("Drive CA file must not be writable by group or other users");
        }
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid && metadata.uid() != 0 {
            bail!("Drive CA file must be owned by the current user or root");
        }
    }
    if metadata.len() > MAX_ADDITIONAL_CA_BYTES {
        bail!("Drive CA file exceeds the 1 MiB size limit");
    }

    let mut pem = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_ADDITIONAL_CA_BYTES + 1)
        .read_to_end(&mut pem)
        .with_context(|| format!("failed to read Drive CA file {}", path.display()))?;
    if pem.len() as u64 > MAX_ADDITIONAL_CA_BYTES {
        bail!("Drive CA file exceeds the 1 MiB size limit");
    }
    if pem.is_empty() {
        bail!("Drive CA file is empty");
    }

    let certificate = reqwest::Certificate::from_pem(&pem)
        .context("Drive CA file is not a valid PEM certificate")?;
    let sha256 = hex::encode(Sha256::digest(&pem));
    Ok(AdditionalCa {
        certificate,
        sha256,
    })
}

pub(super) fn build_http_client(
    additional_ca: Option<&AdditionalCa>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(SYNC_CONNECT_TIMEOUT)
        .timeout(SYNC_REQUEST_TIMEOUT);
    if let Some(additional_ca) = additional_ca {
        builder = builder.add_root_certificate(additional_ca.certificate.clone());
    }
    builder
        .build()
        .context("failed to build the Drive sync HTTP client")
}
