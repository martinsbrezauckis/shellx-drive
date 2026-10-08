//! Version + update routes.
//!
//! * `GET /version` — public build identity for support and status checks. The
//!   administrator UI also polls it to detect a redeploy.
//! * `GET /update/check` — server-administrator only. Server-side proxy of the
//!   latest public GitHub release (the browser's `default-src 'self'` CSP forbids
//!   calling api.github.com directly), returning a bounded [`UpdateStatus`].
//!   Results are cached in-process so repeated About-panel opens don't hammer
//!   GitHub's unauthenticated rate limit.

use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
use chrono::Utc;
use serde::Deserialize;

use crate::auth::require_admin;
use crate::error::ApiResult;
use crate::server::AppState;
use crate::version::{
    self, clean_tag, compare_versions, UpdateStatus, UpdateStatusKind, VersionInfo,
};

mod checker;
mod response;
pub(crate) use checker::UpdateChecker;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/version", get(version_info))
        .route("/update/check", get(update_check))
}

/// Public build identity. Only the administrator UI turns build drift into a
/// server-reload notice.
async fn version_info() -> Json<VersionInfo> {
    Json(VersionInfo::current())
}

/// GitHub release check for the Settings ▸ About panel. Server upgrades are an
/// operator concern, so ordinary users and application tokens cannot trigger or
/// observe this outbound check.
async fn update_check(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<UpdateStatus>> {
    let _admin = require_admin(&state, &headers)?;
    let now = Utc::now().to_rfc3339();

    let Some(repo) = state.config.update_repo.clone() else {
        return Ok(Json(UpdateStatus::unconfigured(version::VERSION, now)));
    };

    Ok(Json(state.update_checker.check(&repo, now).await))
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: Option<String>,
    name: Option<String>,
    html_url: Option<String>,
    published_at: Option<String>,
    body: Option<String>,
    #[serde(default)]
    assets: Vec<GithubAsset>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

/// Fetch the latest stable release and turn it into an [`UpdateStatus`]. Never
/// panics — every failure path is mapped to an `error`/`current` status.
async fn resolve_update(client: &reqwest::Client, repo: &str, checked_at: String) -> UpdateStatus {
    match fetch_latest_release(client, repo).await {
        Err(reason) => {
            UpdateStatus::error(Some(repo.to_string()), version::VERSION, checked_at, reason)
        }
        Ok(None) => UpdateStatus {
            // Repo reachable but no published release yet (or the only ones are
            // drafts/prereleases) — you're effectively up to date.
            kind: UpdateStatusKind::Current,
            current_version: version::VERSION.to_string(),
            repo: Some(repo.to_string()),
            latest_version: None,
            release_url: None,
            release_name: None,
            published_at: None,
            body: None,
            download_url: None,
            checksum_url: None,
            checked_at,
            reason: Some("No public release has been published yet.".to_string()),
        },
        Ok(Some(release)) => {
            let latest = clean_tag(release.tag_name.as_deref().unwrap_or_default());
            let newer = matches!(compare_versions(&latest, version::VERSION), Some(1));
            let release_url = release
                .html_url
                .filter(|u| u.starts_with("https://github.com/"))
                .unwrap_or_else(|| format!("https://github.com/{repo}/releases/tag/{latest}"));
            let (download_url, checksum_url) =
                server_release_assets(repo, &latest, &release.assets);
            UpdateStatus {
                kind: if newer {
                    UpdateStatusKind::Available
                } else {
                    UpdateStatusKind::Current
                },
                current_version: version::VERSION.to_string(),
                repo: Some(repo.to_string()),
                latest_version: Some(latest),
                release_url: Some(release_url),
                release_name: release.name.filter(|n| !n.trim().is_empty()),
                published_at: release.published_at,
                body: release.body.filter(|b| !b.trim().is_empty()),
                download_url,
                checksum_url,
                checked_at,
                reason: None,
            }
        }
    }
}

fn server_release_assets(
    repo: &str,
    version: &str,
    assets: &[GithubAsset],
) -> (Option<String>, Option<String>) {
    let archive_name = format!("shellx-drive-{version}-linux-x86_64.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let trusted_prefix = format!("https://github.com/{repo}/releases/download/");
    let find = |expected: &str| {
        assets
            .iter()
            .find(|asset| {
                asset.name == expected && asset.browser_download_url.starts_with(&trusted_prefix)
            })
            .map(|asset| asset.browser_download_url.clone())
    };
    (find(&archive_name), find(&checksum_name))
}

/// GET the latest *stable* release from the public GitHub API. `Ok(None)` when
/// GitHub replies 404 (repo/releases not found) or the latest is a draft/prerelease.
async fn fetch_latest_release(
    client: &reqwest::Client,
    repo: &str,
) -> Result<Option<GithubRelease>, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let response = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!("GitHub responded with HTTP {}", response.status()));
    }
    let release = self::response::decode_github_release(response).await?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    Ok(Some(release))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_downloads_require_exact_official_linux_assets() {
        let assets = vec![
            GithubAsset {
                name: "shellx-drive-0.2.0-linux-x86_64.tar.gz".to_string(),
                browser_download_url: "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v0.2.0/shellx-drive-0.2.0-linux-x86_64.tar.gz".to_string(),
            },
            GithubAsset {
                name: "shellx-drive-0.2.0-linux-x86_64.tar.gz.sha256".to_string(),
                browser_download_url: "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v0.2.0/shellx-drive-0.2.0-linux-x86_64.tar.gz.sha256".to_string(),
            },
            GithubAsset {
                name: "shellx-drive-0.2.0-linux-x86_64.tar.gz".to_string(),
                browser_download_url: "https://github.com/attacker/drive/releases/download/v0.2.0/shellx-drive-0.2.0-linux-x86_64.tar.gz".to_string(),
            },
        ];
        let (archive, checksum) =
            server_release_assets("martinsbrezauckis/shellx-drive", "0.2.0", &assets);
        assert!(archive
            .unwrap()
            .contains("/martinsbrezauckis/shellx-drive/"));
        assert!(checksum.unwrap().ends_with(".tar.gz.sha256"));

        let (archive, checksum) =
            server_release_assets("martinsbrezauckis/shellx-drive", "0.3.0", &assets);
        assert!(archive.is_none());
        assert!(checksum.is_none());
    }
}
