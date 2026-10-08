use std::{io::Write, net::IpAddr, path::Path};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::sync_client_fs::{SafeCacheRoot, SafeDownloadTarget, SafeLocalSnapshot};

const SYNC_PROFILE_MARKER: &str = ".shellx-drive-sync-profile.json";
const SYNC_PROFILE_SCHEMA: &str = "shellx-drive.sync-profile/v1";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SyncCacheProfile {
    schema: String,
    base_url: String,
    actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    additional_ca_sha256: Option<String>,
}

pub(super) fn validate_base_url(raw: &str) -> anyhow::Result<String> {
    let mut url =
        reqwest::Url::parse(raw.trim()).context("sync base URL must be an absolute URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("sync base URL must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("sync base URL must not contain a query or fragment");
    }
    let host = url
        .host_str()
        .context("sync base URL must include a host")?;
    match url.scheme() {
        "https" => {}
        "http"
            if host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback()) => {}
        "http" => bail!("sync base URL must use HTTPS except for loopback development"),
        _ => bail!("sync base URL must use HTTP or HTTPS"),
    }
    let normalized_path = url.path().trim_end_matches('/').to_string();
    url.set_path(&normalized_path);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

pub(super) fn validate_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
    {
        bail!(
            "sync profile name must be 1-64 lowercase letters, digits, '_' or '-', starting with a letter or digit"
        );
    }
    Ok(())
}

pub(super) fn bind(
    cache_root: &SafeCacheRoot,
    base_url: &str,
    actor: &str,
    additional_ca_sha256: Option<&str>,
    adopt_existing_cache: bool,
) -> anyhow::Result<()> {
    let marker_path = cache_root.path().join(SYNC_PROFILE_MARKER);
    let expected = SyncCacheProfile {
        schema: SYNC_PROFILE_SCHEMA.to_string(),
        base_url: base_url.to_string(),
        actor: actor.to_string(),
        additional_ca_sha256: additional_ca_sha256.map(str::to_string),
    };
    match read(cache_root, &marker_path) {
        Ok(actual) => {
            if actual != expected {
                bail!(
                    "sync cache belongs to a different Drive server, TLS trust, or account; choose another --cache-dir/--profile"
                );
            }
            Ok(())
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            if !cache_root.is_empty()? && !adopt_existing_cache {
                bail!(
                    "sync cache has legacy data but no profile marker; rerun once with --adopt-existing-cache after verifying the server and account"
                );
            }
            write_new(cache_root, &marker_path, &expected).or_else(|write_error| {
                if write_error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
                {
                    let actual = read(cache_root, &marker_path)?;
                    if actual == expected {
                        return Ok(());
                    }
                }
                Err(write_error)
            })
        }
        Err(error) => Err(error),
    }
}

pub(super) fn preflight(
    cache_root: &SafeCacheRoot,
    base_url: &str,
    additional_ca_sha256: Option<&str>,
    adopt_existing_cache: bool,
) -> anyhow::Result<()> {
    let marker_path = cache_root.path().join(SYNC_PROFILE_MARKER);
    match read(cache_root, &marker_path) {
        Ok(actual) => {
            if actual.schema != SYNC_PROFILE_SCHEMA
                || actual.base_url != base_url
                || actual.additional_ca_sha256.as_deref() != additional_ca_sha256
            {
                bail!(
                    "sync cache belongs to a different Drive server or TLS trust; choose another --cache-dir/--profile"
                );
            }
            Ok(())
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            if !cache_root.is_empty()? && !adopt_existing_cache {
                bail!(
                    "sync cache has legacy data but no profile marker; rerun once with --adopt-existing-cache after verifying the server and account"
                );
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn read(cache_root: &SafeCacheRoot, marker_path: &Path) -> anyhow::Result<SyncCacheProfile> {
    let mut input = SafeLocalSnapshot::open(cache_root, marker_path, 4096)?;
    let bytes = input.read_all()?;
    serde_json::from_slice(&bytes).context("failed to parse sync cache profile marker")
}

fn write_new(
    cache_root: &SafeCacheRoot,
    path: &Path,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() as u64 > 4096 {
        bail!("sync cache profile marker exceeds its bounded size");
    }
    let mut target = SafeDownloadTarget::begin(cache_root, path)?;
    target.file_mut().write_all(&bytes)?;
    target.commit_new()?;
    Ok(())
}
