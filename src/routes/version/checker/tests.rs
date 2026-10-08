use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{
    extract::Request,
    http::{header, StatusCode},
    response::IntoResponse,
    Router,
};

use super::*;

#[test]
fn negative_cache_backoff_is_exponential_and_bounded() {
    assert_eq!(negative_cache_ttl(1), Duration::from_secs(5));
    assert_eq!(negative_cache_ttl(2), Duration::from_secs(10));
    assert_eq!(negative_cache_ttl(7), UPDATE_ERROR_BACKOFF_MAX);
    assert_eq!(negative_cache_ttl(u32::MAX), UPDATE_ERROR_BACKOFF_MAX);
}

#[tokio::test]
async fn update_transport_rejects_http_and_does_not_follow_redirects() {
    let target_hits = Arc::new(AtomicUsize::new(0));
    let hits = target_hits.clone();
    // Use a fallback fixture so source route-inventory checks do not mistake
    // these test-only paths for product registrations.
    let app = Router::new().fallback(move |request: Request| {
        let hits = hits.clone();
        async move {
            match request.uri().path() {
                "/redirect" => (StatusCode::FOUND, [(header::LOCATION, "/target")]).into_response(),
                "/target" => {
                    hits.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK.into_response()
                }
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let redirect_client = reqwest::Client::builder()
        .redirect(update_redirect_policy())
        .build()
        .unwrap();
    let response = redirect_client
        .get(format!("http://{address}/redirect"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);

    let checker = UpdateChecker::new().unwrap();
    assert!(checker
        .client
        .get(format!("http://{address}/target"))
        .send()
        .await
        .is_err());
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn concurrent_cache_misses_start_only_one_outbound_refresh() {
    let checker = UpdateChecker::new().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let resolve = |calls: Arc<AtomicUsize>| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(25)).await;
        UpdateStatus::error(
            Some("owner/repo".to_string()),
            version::VERSION,
            "now".to_string(),
            "offline",
        )
    };

    let (first, second, third) = tokio::join!(
        checker.resolve_with("owner/repo", "one".to_string(), || resolve(calls.clone())),
        checker.resolve_with("owner/repo", "two".to_string(), || resolve(calls.clone())),
        checker.resolve_with("owner/repo", "three".to_string(), || resolve(calls.clone())),
    );

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(first.kind, UpdateStatusKind::Error));
    assert!(matches!(second.kind, UpdateStatusKind::Error));
    assert!(matches!(third.kind, UpdateStatusKind::Error));
    let cached = checker
        .resolve_with("owner/repo", "four".to_string(), || resolve(calls.clone()))
        .await;
    assert_eq!(cached.reason.as_deref(), Some("offline"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
