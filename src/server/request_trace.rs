use axum::{extract::MatchedPath, http::Request};
use tower_http::trace::MakeSpan;
use tracing::Span;

/// Builds useful request spans without recording raw capability-bearing URIs.
///
/// Matched route templates retain endpoint-level diagnostics while keeping
/// share, Drop, download-ticket, and Office capability values out of logs.
/// Unmatched requests deliberately use a constant instead of the raw path.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SafeMakeSpan;

impl<B> MakeSpan<B> for SafeMakeSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str)
            .unwrap_or("<unmatched>");
        tracing::debug_span!(
            "http.request",
            method = %request.method(),
            route = %route,
            version = ?request.version(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;
    use tower_http::trace::{MakeSpan, TraceLayer};
    use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

    use super::SafeMakeSpan;

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn trace_spans_keep_route_diagnostics_without_raw_capabilities() {
        const MATCHED_SECRET: &str = "matched-capability-secret-8f39";
        const UNMATCHED_SECRET: &str = "unmatched-capability-secret-4a62";
        const QUERY_SECRET: &str = "query-secret-3c17";

        let bytes = Arc::new(Mutex::new(Vec::new()));
        let sink = bytes.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("debug"))
            .with_span_events(FmtSpan::NEW)
            .with_writer(move || SharedWriter(sink.clone()))
            .with_ansi(false)
            .without_time()
            .finish();

        let _subscriber_guard = tracing::subscriber::set_default(subscriber);
        let app = Router::new()
            .route_service("/pub/shares/{share_id}", get(|| async { "ok" }))
            .layer(TraceLayer::new_for_http().make_span_with(SafeMakeSpan));
        app.oneshot(
            Request::builder()
                .uri(format!("/pub/shares/{MATCHED_SECRET}?proof={QUERY_SECRET}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        let request = Request::builder()
            .uri(format!("/unknown/{UNMATCHED_SECRET}?proof={QUERY_SECRET}"))
            .body(())
            .unwrap();
        let mut make_span = SafeMakeSpan;
        let span = make_span.make_span(&request);
        let _entered = span.enter();
        tracing::debug!("unmatched request observed");

        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(output.contains("/pub/shares/{share_id}"), "{output}");
        assert!(output.contains("<unmatched>"), "{output}");
        assert!(output.contains("method=GET"), "{output}");
        assert!(!output.contains(MATCHED_SECRET), "{output}");
        assert!(!output.contains(UNMATCHED_SECRET), "{output}");
        assert!(!output.contains(QUERY_SECRET), "{output}");
    }
}
