//! ShellX Drive's signed artifact-name contract. Tauri's Minisign global
//! signature authenticates its `timestamp:...\tfile:...` trusted comment as
//! well as the artifact bytes. The release signers derive this name from the
//! admitted package version, never from the public update feed.

use base64::Engine;
use minisign_verify::{PublicKey, Signature};
use semver::Version;
use url::Url;

pub(super) fn verify(
    bytes: &[u8],
    signature: &str,
    public_key: &str,
    current: &str,
    advertised: &str,
    platform: &str,
    download_url: &Url,
) -> Result<(), String> {
    let decode = |value: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| "invalid signature encoding".to_owned())
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|_| "invalid signature text".to_owned())
            })
    };
    let key = PublicKey::decode(&decode(public_key)?).map_err(|_| "invalid updater public key")?;
    let signature =
        Signature::decode(&decode(signature)?).map_err(|_| "invalid updater signature")?;
    // Reading a trusted comment before this check would restore the original
    // unsigned-metadata vulnerability. Global-signature verification is required.
    key.verify(bytes, &signature, true)
        .map_err(|_| "updater signature verification failed")?;
    verify_identity(
        signature.trusted_comment(),
        current,
        advertised,
        platform,
        download_url,
    )
}

fn verify_identity(
    comment: &str,
    current: &str,
    advertised: &str,
    platform: &str,
    download_url: &Url,
) -> Result<(), String> {
    let current = Version::parse(current).map_err(|_| "invalid installed version")?;
    let version = Version::parse(advertised).map_err(|_| "invalid advertised version")?;
    if version.to_string() != advertised || !version.cmp_precedence(&current).is_gt() {
        return Err("signed updater must advance the installed version".into());
    }
    let expected = super::release_url_policy::expected_artifact_name(platform, &version)?;
    let (timestamp, leaf) = comment
        .strip_prefix("timestamp:")
        .and_then(|value| value.split_once("\tfile:"))
        .ok_or("invalid signed updater identity")?;
    if timestamp.is_empty()
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
        || timestamp.parse::<u64>().is_err()
        || leaf != expected
    {
        return Err("signed updater identity does not match the selected release".into());
    }
    // GitHub may normalize the transport filename, while the authenticated
    // trusted comment must retain the signer's original package basename.
    // Reuse exact URL admission at direct installation as well as download.
    super::release_url_policy::validate_artifact_url(download_url, &version, platform)
}

#[cfg(test)]
mod tests;
