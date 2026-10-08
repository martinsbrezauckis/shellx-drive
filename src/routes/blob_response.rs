//! Shared HTTP response builder for stored blob content.
//!
//! Every file-like read path authorizes and records statistics before calling
//! this module.  The module owns only the bounded, disk-backed response:
//! content-type hardening, `Range`, and bounded producer construction. Keeping
//! that boundary here prevents protocol adapters from accidentally reverting
//! to `fs::read` / `Body::from(Vec<u8>)` for multi-gigabyte Drive objects.

use std::{
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    http::{header, StatusCode},
    response::Response,
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::mpsc,
};
use tokio_stream::Stream;

use crate::error::ApiResult;

mod guarded_bytes;
pub(crate) use guarded_bytes::{
    guard_blob_receiver_with_total_deadline, guard_bounded_bytes_response_with_total_deadline,
};

const BLOB_STREAM_CHANNEL_CAPACITY: usize = 4;
const BLOB_STREAM_CHUNK_BYTES: usize = 64 * 1024;
const BLOB_STREAM_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(30);
const BLOB_STREAM_MIN_TOTAL_SECONDS: u64 = 30;
// A supported 2 GiB blob takes over four hours at the minimum delivery rate.
const BLOB_STREAM_MAX_TOTAL_SECONDS: u64 = 5 * 60 * 60;
const BLOB_STREAM_MIN_DELIVERY_BYTES_PER_SECOND: u64 = 128 * 1024;

fn blob_stream_total_timeout(length: u64) -> Duration {
    let delivery_seconds = length.div_ceil(BLOB_STREAM_MIN_DELIVERY_BYTES_PER_SECOND);
    Duration::from_secs(
        delivery_seconds
            .saturating_add(BLOB_STREAM_MIN_TOTAL_SECONDS)
            .clamp(BLOB_STREAM_MIN_TOTAL_SECONDS, BLOB_STREAM_MAX_TOTAL_SECONDS),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Inline,
    Attachment,
}

impl Disposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Attachment => "attachment",
        }
    }
}

/// Optional headers for a known-safe stored derivative (for example a PNG
/// thumbnail).  Ordinary user file content uses [`serve_blob_file`] and has
/// its type inferred from the filename under the inline allowlist.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlobResponseOverrides {
    pub content_type: &'static str,
    pub cache_control: &'static str,
}

impl BlobResponseOverrides {
    pub(crate) const IMAGE_CACHE: Self = Self {
        content_type: "image/png",
        cache_control: "private, no-store",
    };
}

/// Outcome of parsing a single HTTP `Range` header against a known body length.
enum RangeOutcome {
    /// A satisfiable byte range, inclusive on both ends.
    Satisfiable { start: u64, end: u64 },
    /// A syntactically valid but unsatisfiable range (→ `416`).
    Unsatisfiable,
    /// No usable range; serve the full body (`200`).
    Ignore,
}

/// Stream a stored blob while retaining an admission guard until EOF or body
/// cancellation. Public and authenticated routes use this to make concurrency
/// limits describe active response bodies rather than response construction.
pub(crate) async fn serve_blob_file_with_guard<G>(
    file_name: &str,
    path: &Path,
    range_header: Option<&str>,
    disposition: Disposition,
    guard: G,
) -> ApiResult<Response>
where
    G: Send + 'static,
{
    serve_blob_file_with_overrides_and_guard(
        file_name,
        path,
        range_header,
        disposition,
        None,
        guard,
    )
    .await
}

/// Open and position the immutable blob before running a terminal publication
/// check. A failed check drops the open handle without constructing a body.
pub(crate) async fn serve_blob_file_with_guard_after_open<G, F>(
    file_name: &str,
    path: &Path,
    range_header: Option<&str>,
    disposition: Disposition,
    guard: G,
    after_open: F,
) -> ApiResult<Response>
where
    G: Send + 'static,
    F: FnOnce() -> ApiResult<()> + Send,
{
    serve_blob_file_with_overrides_and_guard_after_open(
        file_name,
        path,
        range_header,
        disposition,
        None,
        guard,
        after_open,
    )
    .await
}

pub(crate) async fn serve_blob_file_with_overrides_and_guard<G>(
    file_name: &str,
    path: &Path,
    range_header: Option<&str>,
    disposition: Disposition,
    overrides: Option<BlobResponseOverrides>,
    guard: G,
) -> ApiResult<Response>
where
    G: Send + 'static,
{
    serve_blob_file_with_overrides_and_guard_after_open(
        file_name,
        path,
        range_header,
        disposition,
        overrides,
        guard,
        || Ok(()),
    )
    .await
}

pub(crate) async fn serve_blob_file_with_overrides_and_guard_after_open<G, F>(
    file_name: &str,
    path: &Path,
    range_header: Option<&str>,
    disposition: Disposition,
    overrides: Option<BlobResponseOverrides>,
    guard: G,
    after_open: F,
) -> ApiResult<Response>
where
    G: Send + 'static,
    F: FnOnce() -> ApiResult<()> + Send,
{
    let total = tokio::fs::metadata(path).await?.len();
    let (content_type, disposition_value, cache_control) = match overrides {
        Some(overrides) => (
            overrides.content_type,
            content_disposition(file_name, disposition),
            overrides.cache_control,
        ),
        None => {
            let (content_type, disposition_value) =
                content_response_headers(file_name, disposition);
            (content_type, disposition_value, "private, no-store")
        }
    };
    let range = range_header.map(|value| parse_single_range(value, total));
    let mut file = tokio::fs::File::open(path).await?;
    if matches!(range, Some(RangeOutcome::Unsatisfiable)) {
        after_open()?;
        return Ok(Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{total}"))
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .body(Body::empty())
            .unwrap());
    }

    let (status, length, content_range, start) = match range {
        Some(RangeOutcome::Satisfiable { start, end }) => {
            let length = end - start + 1;
            (
                StatusCode::PARTIAL_CONTENT,
                length,
                Some(format!("bytes {start}-{end}/{total}")),
                start,
            )
        }
        _ => (StatusCode::OK, total, None, 0),
    };
    if start != 0 {
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    after_open()?;
    let (sender, receiver) = mpsc::channel(BLOB_STREAM_CHANNEL_CAPACITY);
    let (producer_done_tx, producer_done_rx) = tokio::sync::oneshot::channel();
    let body = guarded_bytes::guard_blob_receiver_with_total_deadline(
        receiver,
        guard,
        blob_stream_total_timeout(length),
        producer_done_rx,
    );
    tokio::spawn(async move {
        produce_blob_body(file.take(length), sender).await;
        let _ = producer_done_tx.send(());
    });
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_DISPOSITION, disposition_value)
        .header(header::CONTENT_LENGTH, length)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; sandbox",
        );
    if let Some(value) = content_range {
        builder = builder.header(header::CONTENT_RANGE, value);
    }
    Ok(builder.body(body).unwrap())
}

/// Decouple disk reads from socket polling with a small bounded queue. If the
/// receiver stops draining for the deadline, the producer exits. The body
/// retains its admission guard through EOF, drop, or the absolute deadline.
async fn produce_blob_body(
    mut reader: tokio::io::Take<tokio::fs::File>,
    sender: mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let mut buffer = vec![0_u8; BLOB_STREAM_CHUNK_BYTES];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) => {
                let _ =
                    tokio::time::timeout(BLOB_STREAM_BACKPRESSURE_TIMEOUT, sender.send(Err(error)))
                        .await;
                return;
            }
        };
        let chunk = Bytes::copy_from_slice(&buffer[..read]);
        match tokio::time::timeout(BLOB_STREAM_BACKPRESSURE_TIMEOUT, sender.send(Ok(chunk))).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return,
        }
    }
}

/// Retain an admission guard for an already-built response body. This covers
/// authenticated streamed formats (for example generated ZIPs and backups)
/// that are not served through the stored-blob response builder.
pub(crate) fn guard_response_body<G>(response: Response, guard: G) -> Response
where
    G: Send + Unpin + 'static,
{
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::from_stream(GuardedStream::new(body.into_data_stream(), guard)),
    )
}

struct GuardedStream<S, G> {
    stream: S,
    _guard: G,
}

impl<S, G> GuardedStream<S, G> {
    fn new(stream: S, guard: G) -> Self {
        Self {
            stream,
            _guard: guard,
        }
    }
}

impl<S, G> Stream for GuardedStream<S, G>
where
    S: Stream + Unpin,
    G: Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(context)
    }
}

pub(crate) fn is_initial_content_request(range_header: Option<&str>) -> bool {
    let Some(value) = range_header.map(str::trim) else {
        return true;
    };
    let Some((unit, range)) = value.split_once('=') else {
        return false;
    };
    unit.eq_ignore_ascii_case("bytes") && range.trim_start().starts_with("0-")
}

/// Whether this filename's inferred type is safe to serve inline.
pub(crate) fn is_safe_inline_file_name(name: &str) -> bool {
    is_safe_inline_type(guess_content_type(name))
}

fn content_response_headers(file_name: &str, disposition: Disposition) -> (&'static str, String) {
    let (content_type, disposition) = match disposition {
        Disposition::Attachment => ("application/octet-stream", Disposition::Attachment),
        Disposition::Inline => {
            let guessed = guess_content_type(file_name);
            if is_safe_inline_type(guessed) {
                (guessed, Disposition::Inline)
            } else {
                ("application/octet-stream", Disposition::Attachment)
            }
        }
    };
    (content_type, content_disposition(file_name, disposition))
}

fn content_disposition(file_name: &str, disposition: Disposition) -> String {
    format!(
        "{}; filename*=UTF-8''{}",
        disposition.as_str(),
        percent_encode_filename(file_name)
    )
}

/// Best-effort MIME type from a filename extension. Falls back to
/// `application/octet-stream` for anything unrecognized. Markdown deliberately
/// maps to `text/plain` (never `text/html`) so it can never be rendered as an
/// interpretable document.
fn guess_content_type(name: &str) -> &'static str {
    let extension = name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "txt" | "md" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Content types that are safe to serve INLINE (as a navigable top-level
/// document) because they cannot execute script in the Drive origin. Compared
/// on the base media type, ignoring any `; charset=...` parameter. Notably
/// EXCLUDES `text/html`, `image/svg+xml`, and `application/xml`, which can run
/// script when opened as a document, and any unmapped type.
fn is_safe_inline_type(content_type: &str) -> bool {
    const SAFE_INLINE_TYPES: [&str; 14] = [
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/bmp",
        "image/x-icon",
        "application/pdf",
        "video/mp4",
        "video/webm",
        "video/quicktime",
        "audio/mpeg",
        "audio/wav",
        "audio/ogg",
        "text/plain",
    ];
    let base = content_type.split(';').next().unwrap_or("").trim();
    SAFE_INLINE_TYPES.contains(&base)
}

/// RFC 5987 percent-encoding for the `filename*=UTF-8''<value>` parameter.
/// Keeps only the RFC "attr-char" unreserved set; everything else (including
/// spaces → `%20`) is percent-encoded, which also neutralizes header injection.
fn percent_encode_filename(name: &str) -> String {
    name.bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' => {
                vec![byte as char]
            }
            other => format!("%{other:02X}").chars().collect(),
        })
        .collect()
}

/// Parse a single-range HTTP `Range` header (`bytes=start-end`, `bytes=start-`,
/// or `bytes=-suffix`) against a body of `total` bytes. Multi-range requests
/// fall back to the first range; malformed or non-`bytes` units are ignored
/// (full body served).
fn parse_single_range(header_value: &str, total: u64) -> RangeOutcome {
    let Some(spec) = header_value.trim().strip_prefix("bytes=") else {
        return RangeOutcome::Ignore;
    };
    let first = spec.split(',').next().unwrap_or("").trim();
    let Some((start_str, end_str)) = first.split_once('-') else {
        return RangeOutcome::Ignore;
    };
    let start_str = start_str.trim();
    let end_str = end_str.trim();

    if total == 0 {
        return RangeOutcome::Unsatisfiable;
    }

    if start_str.is_empty() {
        let Ok(suffix) = end_str.parse::<u64>() else {
            return RangeOutcome::Ignore;
        };
        if suffix == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        let length = suffix.min(total);
        return RangeOutcome::Satisfiable {
            start: total - length,
            end: total - 1,
        };
    }

    let Ok(start) = start_str.parse::<u64>() else {
        return RangeOutcome::Ignore;
    };
    if start >= total {
        return RangeOutcome::Unsatisfiable;
    }
    let end = if end_str.is_empty() {
        total - 1
    } else {
        let Ok(end) = end_str.parse::<u64>() else {
            return RangeOutcome::Ignore;
        };
        end.min(total - 1)
    };
    if end < start {
        return RangeOutcome::Unsatisfiable;
    }
    RangeOutcome::Satisfiable { start, end }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use axum::{body::to_bytes, http::header};

    use crate::error::ApiError;

    use super::*;

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn unsatisfiable_range_runs_terminal_authorization_before_length_response() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        tokio::fs::write(&path, b"secret").await.unwrap();
        for range in ["bytes=999-", "bytes=-0", "bytes=5-4"] {
            let checked = Arc::new(AtomicBool::new(false));
            let marker = checked.clone();
            let denied = serve_blob_file_with_guard_after_open(
                "blob.txt",
                &path,
                Some(range),
                Disposition::Inline,
                (),
                move || {
                    marker.store(true, Ordering::SeqCst);
                    Err(ApiError::Forbidden)
                },
            )
            .await;
            assert!(matches!(denied, Err(ApiError::Forbidden)), "{range}");
            assert!(checked.load(Ordering::SeqCst), "{range}");
        }

        let allowed = serve_blob_file_with_guard_after_open(
            "blob.txt",
            &path,
            Some("bytes=-0"),
            Disposition::Inline,
            (),
            || Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(allowed.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(allowed.headers()[header::CONTENT_RANGE], "bytes */6");
        assert!(to_bytes(allowed.into_body(), 1).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn response_guard_lives_until_the_stream_body_finishes() {
        let dropped = Arc::new(AtomicBool::new(false));
        let response = Response::new(Body::from("bounded body"));
        let response = guard_response_body(response, DropFlag(dropped.clone()));
        assert!(!dropped.load(Ordering::SeqCst));
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), b"bounded body");
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn stored_blob_small_unread_body_keeps_guard_until_body_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small-blob");
        tokio::fs::write(&path, b"small stored blob").await.unwrap();

        for range in [None, Some("bytes=0-4")] {
            let dropped = Arc::new(AtomicBool::new(false));
            let response = serve_blob_file_with_guard(
                "blob.txt",
                &path,
                range,
                Disposition::Inline,
                DropFlag(dropped.clone()),
            )
            .await
            .unwrap();

            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                !dropped.load(Ordering::SeqCst),
                "guard dropped before body consumption for {range:?}"
            );
            drop(response);
            assert!(dropped.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn stored_blob_range_keeps_headers_bytes_and_guard_through_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("range-blob");
        tokio::fs::write(&path, b"0123456789").await.unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let response = serve_blob_file_with_guard(
            "blob.txt",
            &path,
            Some("bytes=2-5"),
            Disposition::Inline,
            DropFlag(dropped.clone()),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
        assert!(!dropped.load(Ordering::SeqCst));
        assert_eq!(
            to_bytes(response.into_body(), 4).await.unwrap(),
            b"2345"[..]
        );
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn stored_blob_total_deadline_is_bounded_and_scales_with_range_length() {
        assert_eq!(blob_stream_total_timeout(0), Duration::from_secs(30));
        assert!(blob_stream_total_timeout(1024 * 1024) > Duration::from_secs(30));
        assert_eq!(
            blob_stream_total_timeout(2 * 1024 * 1024 * 1024),
            Duration::from_secs(2 * 1024 * 1024 * 1024 / (128 * 1024) + 30)
        );
        assert_eq!(
            blob_stream_total_timeout(u64::MAX),
            Duration::from_secs(5 * 60 * 60)
        );
    }
}
