//! Fixed-origin transport rules for ShellX Drive updater metadata and artifacts.

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::redirect::Policy;
use semver::Version;
use url::Url;

const GITHUB_HOST: &str = "github.com";
const REPOSITORY: &str = "martinsbrezauckis/shellx-drive";
const LATEST_PATH: &str = "/martinsbrezauckis/shellx-drive/releases/latest/download/latest.json";
const VERSIONED_LATEST_PREFIX: &str = "/martinsbrezauckis/shellx-drive/releases/download/v";
const RELEASE_CDN_HOSTS: &[&str] = &[
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const MAX_REDIRECTS: usize = 3;
// `Version` permits build metadata, whose `+` must be encoded in an asset leaf
// just as the manifest compiler's `encodeURIComponent` call does. Release tags
// retain their literal `+` because GitHub resolves that path form.
const ARTIFACT_LEAF_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'+');

pub(super) fn expected_artifact_name(platform: &str, version: &Version) -> Result<String, String> {
    Ok(match platform {
        "windows-x86_64-nsis" => format!("ShellX Drive Desktop_{version}_x64-setup.exe"),
        "darwin-aarch64-app" => format!("ShellX Drive Desktop_{version}_aarch64.app.tar.gz"),
        "linux-x86_64-appimage" => format!("ShellX_Drive_{version}_amd64.AppImage"),
        "linux-x86_64-deb" => format!("shellx-drive_{version}_amd64.deb"),
        _ => return Err("unsupported signed updater platform".into()),
    })
}

pub(super) fn validate_feed_endpoint(url: &Url) -> Result<(), String> {
    if is_github_feed_url(url) {
        Ok(())
    } else {
        Err("updater feed URL is not the fixed ShellX Drive GitHub release endpoint".into())
    }
}

pub(super) fn validate_artifact_url(
    url: &Url,
    version: &Version,
    platform: &str,
) -> Result<(), String> {
    let canonical = canonical_artifact_urls(version, platform)?;
    if is_secure_public_url(url)
        && canonical
            .iter()
            .any(|candidate| url.as_str() == candidate.as_str())
    {
        Ok(())
    } else {
        Err("updater artifact URL is not the exact signed ShellX Drive GitHub release asset".into())
    }
}

pub(super) fn feed_redirect_policy() -> Policy {
    Policy::custom(|attempt| {
        if redirect_count_allowed(attempt.previous().len())
            && is_allowed_feed_redirect(attempt.url())
        {
            attempt.follow()
        } else {
            attempt.error(std::io::Error::other(
                "updater feed redirect violates the fixed release transport policy",
            ))
        }
    })
}

pub(super) fn artifact_redirect_policy(
    version: &Version,
    platform: &str,
) -> Result<Policy, String> {
    let canonical = canonical_artifact_urls(version, platform)?;
    Ok(Policy::custom(move |attempt| {
        if redirect_count_allowed(attempt.previous().len())
            && is_allowed_artifact_redirect(attempt.url(), &canonical)
        {
            attempt.follow()
        } else {
            attempt.error(std::io::Error::other(
                "updater artifact redirect violates the fixed release transport policy",
            ))
        }
    }))
}

fn canonical_artifact_url(version: &Version, platform: &str) -> Result<Url, String> {
    let artifact = expected_artifact_name(platform, version)?;
    artifact_url(version, &artifact)
}

fn canonical_artifact_urls(version: &Version, platform: &str) -> Result<Vec<Url>, String> {
    let artifact = expected_artifact_name(platform, version)?;
    let mut urls = vec![canonical_artifact_url(version, platform)?];
    if let Some(normalized) = github_artifact_name(&artifact) {
        if normalized != artifact {
            urls.push(artifact_url(version, &normalized)?);
        }
    }
    Ok(urls)
}

// Match the admitted ASCII basename grammar and GitHub's space-to-dot
// mapping exactly. Other provider renaming is not a transport alias. Legacy
// URLs retain their existing support for SemVer build metadata and long names.
fn github_artifact_name(artifact: &str) -> Option<String> {
    let bytes = artifact.as_bytes();
    if bytes.len() > 128
        || !bytes.first()?.is_ascii_alphanumeric()
        || !bytes.last()?.is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b' ' | b'-'))
    {
        return None;
    }
    Some(artifact.replace(' ', "."))
}

fn artifact_url(version: &Version, artifact: &str) -> Result<Url, String> {
    let artifact = utf8_percent_encode(artifact, ARTIFACT_LEAF_ENCODE_SET);
    Url::parse(&format!(
        "https://{GITHUB_HOST}/{REPOSITORY}/releases/download/v{version}/{artifact}"
    ))
    .map_err(|_| "fixed GitHub artifact URL is invalid".into())
}

fn redirect_count_allowed(previous_len: usize) -> bool {
    previous_len <= MAX_REDIRECTS
}

fn is_allowed_feed_redirect(url: &Url) -> bool {
    is_github_feed_url(url) || is_official_release_cdn(url)
}

fn is_allowed_artifact_redirect(url: &Url, canonical: &[Url]) -> bool {
    canonical.contains(url) || is_official_release_cdn(url)
}

fn is_github_feed_url(url: &Url) -> bool {
    if !is_secure_public_url(url) || url.host_str() != Some(GITHUB_HOST) || url.query().is_some() {
        return false;
    }
    if url.path() == LATEST_PATH {
        return true;
    }
    url.path()
        .strip_prefix(VERSIONED_LATEST_PREFIX)
        .and_then(|value| value.strip_suffix("/latest.json"))
        .is_some_and(|version| !version.is_empty() && Version::parse(version).is_ok())
}

fn is_official_release_cdn(url: &Url) -> bool {
    is_secure_public_url(url)
        && url
            .host_str()
            .is_some_and(|host| RELEASE_CDN_HOSTS.contains(&host))
        && url.path() != "/"
}

fn is_secure_public_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_signed_artifacts_for_every_shipped_platform() {
        let version = Version::parse("1.2.3").unwrap();
        for platform in [
            "windows-x86_64-nsis",
            "darwin-aarch64-app",
            "linux-x86_64-appimage",
            "linux-x86_64-deb",
        ] {
            let url = canonical_artifact_url(&version, platform).unwrap();
            validate_artifact_url(&url, &version, platform).unwrap();
        }
    }

    #[test]
    fn accepts_exact_legacy_and_github_normalized_transport_names() {
        let version = Version::parse("0.1.11").unwrap();
        for (platform, names) in [
            (
                "windows-x86_64-nsis",
                vec![
                    "ShellX%20Drive%20Desktop_0.1.11_x64-setup.exe",
                    "ShellX.Drive.Desktop_0.1.11_x64-setup.exe",
                ],
            ),
            (
                "darwin-aarch64-app",
                vec![
                    "ShellX%20Drive%20Desktop_0.1.11_aarch64.app.tar.gz",
                    "ShellX.Drive.Desktop_0.1.11_aarch64.app.tar.gz",
                ],
            ),
            (
                "linux-x86_64-appimage",
                vec!["ShellX_Drive_0.1.11_amd64.AppImage"],
            ),
            ("linux-x86_64-deb", vec!["shellx-drive_0.1.11_amd64.deb"]),
        ] {
            let urls = canonical_artifact_urls(&version, platform).unwrap();
            assert_eq!(urls.len(), names.len());
            for name in names {
                let url = Url::parse(&format!(
                    "https://github.com/{REPOSITORY}/releases/download/v0.1.11/{name}"
                ))
                .unwrap();
                validate_artifact_url(&url, &version, platform).unwrap();
            }
        }
    }

    #[test]
    fn provider_normalization_preserves_prereleases_and_does_not_sanitize_other_names() {
        let version = Version::parse("1.2.3-rc.1").unwrap();
        let url = Url::parse(&format!(
            "https://github.com/{REPOSITORY}/releases/download/v1.2.3-rc.1/ShellX.Drive.Desktop_1.2.3-rc.1_x64-setup.exe"
        )).unwrap();
        validate_artifact_url(&url, &version, "windows-x86_64-nsis").unwrap();
        let version = Version::parse("1.2.3-rc.1+build.4").unwrap();
        assert_eq!(
            canonical_artifact_urls(&version, "windows-x86_64-nsis")
                .unwrap()
                .len(),
            1
        );
        let normalized = Url::parse(&format!(
            "https://github.com/{REPOSITORY}/releases/download/v1.2.3-rc.1+build.4/ShellX.Drive.Desktop_1.2.3-rc.1%2Bbuild.4_x64-setup.exe"
        )).unwrap();
        assert!(validate_artifact_url(&normalized, &version, "windows-x86_64-nsis").is_err());
        for name in [
            "bad+name.exe",
            "bad/name.exe",
            ".bad.exe",
            "bad.exe.",
            "bad.exe\n",
        ] {
            assert!(github_artifact_name(name).is_none());
        }
        assert!(github_artifact_name(&"x".repeat(128)).is_some());
        assert!(github_artifact_name(&"x".repeat(129)).is_none());
    }

    #[test]
    fn canonical_urls_match_manifest_leaf_encoding_with_build_metadata() {
        let version = Version::parse("1.2.3-rc.1+build.4").unwrap();
        for (platform, encoded_leaf) in [
            (
                "windows-x86_64-nsis",
                "ShellX%20Drive%20Desktop_1.2.3-rc.1%2Bbuild.4_x64-setup.exe",
            ),
            (
                "darwin-aarch64-app",
                "ShellX%20Drive%20Desktop_1.2.3-rc.1%2Bbuild.4_aarch64.app.tar.gz",
            ),
            (
                "linux-x86_64-appimage",
                "ShellX_Drive_1.2.3-rc.1%2Bbuild.4_amd64.AppImage",
            ),
            (
                "linux-x86_64-deb",
                "shellx-drive_1.2.3-rc.1%2Bbuild.4_amd64.deb",
            ),
        ] {
            let url = canonical_artifact_url(&version, platform).unwrap();
            assert_eq!(
                url.as_str(),
                format!(
                    "https://github.com/{REPOSITORY}/releases/download/v1.2.3-rc.1+build.4/{encoded_leaf}"
                )
            );
            validate_artifact_url(&url, &version, platform).unwrap();
        }
    }

    #[test]
    fn rejects_artifact_url_origin_and_path_aliases_before_download() {
        let version = Version::parse("1.2.3").unwrap();
        for url in [
            "http://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX%20Drive%20Desktop_1.2.3_x64-setup.exe",
            "https://attacker.example/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX%20Drive%20Desktop_1.2.3_x64-setup.exe",
            "https://github.com:444/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX%20Drive%20Desktop_1.2.3_x64-setup.exe",
            "https://user@github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX%20Drive%20Desktop_1.2.3_x64-setup.exe",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX%20Drive%20Desktop_1.2.3_x64-setup.exe?token=secret",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX%20Drive%20Desktop_1.2.3_x64-setup.exe#fragment",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX%2520Drive%2520Desktop_1.2.3_x64-setup.exe",
            "https://github.com/other/repository/releases/download/v1.2.3/ShellX%20Drive%20Desktop_1.2.3_x64-setup.exe",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.2/ShellX%20Drive%20Desktop_1.2.3_x64-setup.exe",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX%2EDrive%2EDesktop_1.2.3_x64-setup.exe",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX_Drive_Desktop_1.2.3_x64-setup.exe",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX.Drive%20Desktop_1.2.3_x64-setup.exe",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX.Drive.Desktop_1.2.3_aarch64.app.tar.gz",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.2/ShellX.Drive.Desktop_1.2.3_x64-setup.exe",
            "https://github.com/other/repository/releases/download/v1.2.3/ShellX.Drive.Desktop_1.2.3_x64-setup.exe",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/ShellX.Drive.Desktop_1.2.3_x64-setup.exe?token=secret",
        ] {
            assert!(validate_artifact_url(&Url::parse(url).unwrap(), &version, "windows-x86_64-nsis").is_err());
        }
    }

    #[test]
    fn allows_only_fixed_github_and_official_cdn_redirect_destinations() {
        let version = Version::parse("1.2.3").unwrap();
        let canonical = canonical_artifact_urls(&version, "windows-x86_64-nsis").unwrap();
        for url in &canonical {
            assert!(is_allowed_artifact_redirect(url, &canonical));
        }
        for url in [
            "https://objects.githubusercontent.com/github-production-release-asset-2e65be/1?X-Amz-Signature=abc",
            "https://release-assets.githubusercontent.com/github-production-release-asset-2e65be/1?X-Amz-Signature=abc",
        ] {
            assert!(is_allowed_artifact_redirect(&Url::parse(url).unwrap(), &canonical));
        }
        for url in [
            "http://objects.githubusercontent.com/github-production-release-asset-2e65be/1",
            "https://user@objects.githubusercontent.com/github-production-release-asset-2e65be/1",
            "https://objects.githubusercontent.com:444/github-production-release-asset-2e65be/1",
            "https://objects.githubusercontent.com/github-production-release-asset-2e65be/1#fragment",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/other.exe",
            "https://attacker.example/release",
        ] {
            assert!(!is_allowed_artifact_redirect(&Url::parse(url).unwrap(), &canonical));
        }
        assert!(redirect_count_allowed(3));
        assert!(!redirect_count_allowed(4));
    }

    #[test]
    fn accepts_only_the_fixed_feed_or_a_versioned_release_feed() {
        for url in [
            "https://github.com/martinsbrezauckis/shellx-drive/releases/latest/download/latest.json",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.3/latest.json",
        ] {
            validate_feed_endpoint(&Url::parse(url).unwrap()).unwrap();
        }
        for url in [
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/latest.json",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/download/vnot-a-version/latest.json",
            "https://github.com/martinsbrezauckis/shellx-drive/releases/latest/download/latest.json?token=secret",
            "https://attacker.example/latest.json",
        ] {
            assert!(validate_feed_endpoint(&Url::parse(url).unwrap()).is_err());
        }
    }
}
