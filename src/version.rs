//! Version + update-check primitives.
//!
//! Two surfaces sit on top of this module:
//! * `GET /version` reports the running build (`VersionInfo`). An administrator
//!   UI records and polls it; when the live build differs from the one the tab
//!   loaded, it shows a "new version available — reload" banner.
//! * Administrator-only `GET /update/check` compares the running semver against
//!   the latest public GitHub release and returns an [`UpdateStatus`]. The server proxies GitHub
//!   (the web UI's `default-src 'self'` CSP forbids the browser calling
//!   api.github.com directly), which also keeps the check un-spoofable.
//!
//! The semver parse/compare/slug-normalise logic is a direct port of the audited
//! ShellX Canvas updater (`app/src/lib/update/github-release.ts`), so the two
//! products behave identically. Pure logic lives here with unit tests; the async
//! GitHub fetch + TTL cache live in `routes::version`.

use serde::Serialize;

/// Crate semver, e.g. `0.1.0`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Short git SHA captured at build time (`unknown` outside a git checkout).
pub const GIT_SHA: &str = env!("SHELLX_DRIVE_GIT_SHA");
/// Commit time (RFC3339) captured at build time (empty outside a git checkout).
pub const BUILT_AT: &str = env!("SHELLX_DRIVE_BUILT_AT");

/// Per-build identity the update banner keys off, e.g. `0.1.0+8c30682`. Changes
/// on every commit, so each deploy is detectable by a connected browser.
pub fn build_id() -> String {
    format!("{VERSION}+{GIT_SHA}")
}

/// Payload of `GET /version` (public, unauthenticated).
#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub service: &'static str,
    /// Semantic version from `Cargo.toml`.
    pub version: &'static str,
    /// Per-build id (`version+sha`) — the value the UI compares to detect a deploy.
    pub build: String,
    /// Short git SHA.
    pub commit: &'static str,
    /// Commit time (RFC3339) or empty.
    pub built_at: &'static str,
}

impl VersionInfo {
    pub fn current() -> Self {
        VersionInfo {
            service: "shellx-drive",
            version: VERSION,
            build: build_id(),
            commit: GIT_SHA,
            built_at: BUILT_AT,
        }
    }
}

/// Outcome kinds for a GitHub release check — mirrors the Canvas updater states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatusKind {
    /// Running the latest (or newer, e.g. a dev build) — nothing to do.
    Current,
    /// A newer published release exists.
    Available,
    /// No release repo configured (`SHELLX_DRIVE_UPDATE_REPO` empty).
    Unconfigured,
    /// The check could not complete (network/parse/GitHub error).
    Error,
}

/// Result of a GitHub release check, returned by `GET /update/check`.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateStatus {
    pub kind: UpdateStatusKind,
    pub current_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Direct Linux server archive selected from the official release assets.
    /// The server never installs it automatically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_url: Option<String>,
    pub checked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl UpdateStatus {
    pub fn unconfigured(current_version: &str, checked_at: String) -> Self {
        UpdateStatus {
            kind: UpdateStatusKind::Unconfigured,
            current_version: current_version.to_string(),
            repo: None,
            latest_version: None,
            release_url: None,
            release_name: None,
            published_at: None,
            body: None,
            download_url: None,
            checksum_url: None,
            checked_at,
            reason: Some("No public GitHub release repository is configured.".to_string()),
        }
    }

    pub fn error(
        repo: Option<String>,
        current_version: &str,
        checked_at: String,
        reason: impl Into<String>,
    ) -> Self {
        UpdateStatus {
            kind: UpdateStatusKind::Error,
            current_version: current_version.to_string(),
            repo,
            latest_version: None,
            release_url: None,
            release_name: None,
            published_at: None,
            body: None,
            download_url: None,
            checksum_url: None,
            checked_at,
            reason: Some(reason.into()),
        }
    }
}

/// A parsed semantic version (major.minor.patch with optional prerelease).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Option<String>,
}

/// Parse `1.2.3`, `v1.2.3`, `1.2.3-beta.1`, ignoring any `+build` metadata.
/// Returns `None` for anything that is not a clean semver core.
pub fn parse_version(value: &str) -> Option<ParsedVersion> {
    let raw = value.trim();
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    // Drop build metadata (`+…`).
    let core = raw.split('+').next().unwrap_or(raw);
    let (nums, prerelease) = match core.split_once('-') {
        Some((n, pre)) => (n, Some(pre.to_string())),
        None => (core, None),
    };
    let mut parts = nums.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None; // more than 3 numeric segments → not a clean core
    }
    if let Some(pre) = &prerelease {
        if pre.is_empty() {
            return None;
        }
    }
    Some(ParsedVersion {
        major,
        minor,
        patch,
        prerelease,
    })
}

/// Compare two versions. `Some(1)` if `a > b`, `Some(-1)` if `a < b`, `Some(0)`
/// if equal, `None` if either is unparseable. A release *without* a prerelease
/// outranks one with the same core *with* a prerelease (SemVer §11).
pub fn compare_versions(a: &str, b: &str) -> Option<i32> {
    let left = parse_version(a)?;
    let right = parse_version(b)?;
    for (l, r) in [
        (left.major, right.major),
        (left.minor, right.minor),
        (left.patch, right.patch),
    ] {
        if l > r {
            return Some(1);
        }
        if l < r {
            return Some(-1);
        }
    }
    match (&left.prerelease, &right.prerelease) {
        (None, None) => Some(0),
        (None, Some(_)) => Some(1),
        (Some(_), None) => Some(-1),
        (Some(lp), Some(rp)) => Some(match lp.cmp(rp) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }),
    }
}

/// Accept only bare `owner/repo` slugs. Anything containing a scheme or
/// `github.com`, or not matching `word/word`, is rejected → the update surface
/// can never be pointed at an arbitrary URL, local path, or private host.
pub fn normalize_repo_slug(repo: &str) -> Option<String> {
    let trimmed = repo.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.contains("github.com")
    {
        return None;
    }
    let mut segments = trimmed.split('/');
    let owner = segments.next().unwrap_or("");
    let name = segments.next().unwrap_or("");
    if segments.next().is_some() || owner.is_empty() || name.is_empty() {
        return None;
    }
    let ok = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    };
    if ok(owner) && ok(name) {
        Some(format!("{owner}/{name}"))
    } else {
        None
    }
}

/// Strip a leading `v` from a release tag (`v1.2.3` → `1.2.3`).
pub fn clean_tag(tag: &str) -> String {
    tag.trim()
        .strip_prefix('v')
        .unwrap_or(tag.trim())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects() {
        assert_eq!(
            parse_version("v1.2.3"),
            Some(ParsedVersion {
                major: 1,
                minor: 2,
                patch: 3,
                prerelease: None
            })
        );
        assert_eq!(
            parse_version("0.1.0-beta.2+build9"),
            Some(ParsedVersion {
                major: 0,
                minor: 1,
                patch: 0,
                prerelease: Some("beta.2".into())
            })
        );
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("not-a-version"), None);
        assert_eq!(parse_version("2026-07-04-ux10"), None);
    }

    #[test]
    fn compares_cores_and_prereleases() {
        assert_eq!(compare_versions("1.0.0", "0.9.9"), Some(1));
        assert_eq!(compare_versions("0.1.0", "0.2.0"), Some(-1));
        assert_eq!(compare_versions("1.2.3", "1.2.3"), Some(0));
        // release outranks its own prerelease
        assert_eq!(compare_versions("1.0.0", "1.0.0-rc.1"), Some(1));
        assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0"), Some(-1));
        assert_eq!(compare_versions("bad", "1.0.0"), None);
    }

    #[test]
    fn newer_release_is_detected() {
        // running 0.1.0, latest 0.2.0 => update available (latest > current)
        assert_eq!(compare_versions("0.2.0", "0.1.0"), Some(1));
        // running a dev build ahead of the last release => not "available"
        assert_eq!(compare_versions("0.1.0", "0.2.0"), Some(-1));
    }

    #[test]
    fn slug_rejects_urls_and_paths() {
        assert_eq!(
            normalize_repo_slug("owner/repo"),
            Some("owner/repo".to_string())
        );
        assert_eq!(
            normalize_repo_slug("  example-owner/example-repo "),
            Some("example-owner/example-repo".to_string())
        );
        assert_eq!(normalize_repo_slug("https://github.com/o/r"), None);
        assert_eq!(normalize_repo_slug("github.com/o/r"), None);
        assert_eq!(normalize_repo_slug("/etc/passwd"), None);
        assert_eq!(normalize_repo_slug("owner/repo/extra"), None);
        assert_eq!(normalize_repo_slug(""), None);
        assert_eq!(normalize_repo_slug("onlyowner"), None);
    }

    #[test]
    fn cleans_tags() {
        assert_eq!(clean_tag("v0.2.0"), "0.2.0");
        assert_eq!(clean_tag("0.2.0"), "0.2.0");
    }
}
