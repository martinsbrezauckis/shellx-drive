use super::GithubRelease;

const MAX_UPDATE_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_TAG_BYTES: usize = 128;
const MAX_RELEASE_NAME_BYTES: usize = 512;
const MAX_RELEASE_URL_BYTES: usize = 2 * 1024;
const MAX_PUBLISHED_AT_BYTES: usize = 128;
const MAX_RELEASE_BODY_BYTES: usize = 64 * 1024;
const MAX_RELEASE_ASSETS: usize = 64;
const MAX_ASSET_NAME_BYTES: usize = 256;
const MAX_ASSET_URL_BYTES: usize = 2 * 1024;

pub(super) async fn decode_github_release(
    mut response: reqwest::Response,
) -> Result<GithubRelease, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_UPDATE_RESPONSE_BYTES as u64)
    {
        return Err("GitHub release response exceeded the 512 KiB limit".to_string());
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(MAX_UPDATE_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| "GitHub release response size overflowed".to_string())?;
        // reqwest yields decoded chunks here, so compressed responses are
        // bounded by their decompressed byte count rather than Content-Length.
        if next_len > MAX_UPDATE_RESPONSE_BYTES {
            return Err("GitHub release response exceeded the 512 KiB limit".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    let release: GithubRelease =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    sanitize_release(release)
}

fn sanitize_release(mut release: GithubRelease) -> Result<GithubRelease, String> {
    if release
        .tag_name
        .as_ref()
        .is_some_and(|value| value.len() > MAX_TAG_BYTES)
    {
        return Err("GitHub release tag exceeded the 128-byte limit".to_string());
    }
    release.name = bounded_nonempty(release.name, MAX_RELEASE_NAME_BYTES);
    release.html_url = drop_oversized(release.html_url, MAX_RELEASE_URL_BYTES);
    release.published_at = drop_oversized(release.published_at, MAX_PUBLISHED_AT_BYTES);
    release.body = bounded_nonempty(release.body, MAX_RELEASE_BODY_BYTES);
    release.assets.truncate(MAX_RELEASE_ASSETS);
    release.assets.retain(|asset| {
        !asset.name.trim().is_empty()
            && asset.name.len() <= MAX_ASSET_NAME_BYTES
            && asset
                .browser_download_url
                .starts_with("https://github.com/")
            && asset.browser_download_url.len() <= MAX_ASSET_URL_BYTES
    });
    Ok(release)
}

fn bounded_nonempty(value: Option<String>, maximum: usize) -> Option<String> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|mut value| {
            truncate_utf8(&mut value, maximum);
            value
        })
}

fn drop_oversized(value: Option<String>, maximum: usize) -> Option<String> {
    value.filter(|value| !value.trim().is_empty() && value.len() <= maximum)
}

fn truncate_utf8(value: &mut String, maximum: usize) {
    if value.len() <= maximum {
        return;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use tower_http::compression::CompressionLayer;

    #[tokio::test]
    async fn oversized_decoded_response_is_rejected_before_json_parsing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .fallback(get(|| async { "x".repeat(MAX_UPDATE_RESPONSE_BYTES + 1) }))
                    .layer(CompressionLayer::new().gzip(true)),
            )
            .await
            .unwrap();
        });
        let response = reqwest::get(format!("http://{address}/")).await.unwrap();
        assert_eq!(
            response.content_length(),
            None,
            "gzip must decode in reqwest"
        );
        let error = decode_github_release(response).await.unwrap_err();
        server.abort();
        assert!(error.contains("512 KiB limit"));
        assert!(!error.to_ascii_lowercase().contains("json"));
    }

    #[test]
    fn retained_release_fields_are_utf8_safe_and_bounded() {
        let release = sanitize_release(GithubRelease {
            tag_name: Some("v1.2.3".to_string()),
            name: Some("name".repeat(500)),
            html_url: Some(format!("https://github.com/{}", "x".repeat(3_000))),
            published_at: Some("p".repeat(200)),
            body: Some("🦀".repeat(MAX_RELEASE_BODY_BYTES)),
            assets: vec![],
            draft: false,
            prerelease: false,
        })
        .unwrap();
        assert!(release.name.unwrap().len() <= MAX_RELEASE_NAME_BYTES);
        assert!(release.body.unwrap().len() <= MAX_RELEASE_BODY_BYTES);
        assert!(release.html_url.is_none());
        assert!(release.published_at.is_none());

        let oversized_tag = GithubRelease {
            tag_name: Some("v".repeat(MAX_TAG_BYTES + 1)),
            name: None,
            html_url: None,
            published_at: None,
            body: None,
            assets: vec![],
            draft: false,
            prerelease: false,
        };
        assert!(sanitize_release(oversized_tag).is_err());
    }
}
