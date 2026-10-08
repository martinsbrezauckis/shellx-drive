use super::*;

#[test]
fn declared_size_at_limit_is_accepted_and_oversize_is_rejected() {
    assert_eq!(MAX_UPDATE_FEED_BYTES, 1_048_576);
    assert_eq!(MAX_COMPRESSED_INSTALLER_BYTES, 536_870_912);
    assert!(BoundedBody::new(Some(32), 32, "fixture response").is_ok());
    let error = BoundedBody::new(Some(33), 32, "fixture response")
        .err()
        .expect("oversize declaration must fail");
    assert_eq!(
        error.to_string(),
        "fixture response exceeds the 32-byte limit"
    );
}

#[test]
fn streamed_size_is_checked_before_buffer_growth() {
    let mut body = BoundedBody::new(None, 4, "fixture response").unwrap();
    body.push(b"1234").unwrap();
    assert_eq!(body.as_bytes(), b"1234");

    assert!(body.push(b"5").is_err());
    assert_eq!(body.as_bytes(), b"1234");
}

#[test]
fn cumulative_size_overflow_is_rejected() {
    assert!(checked_body_len(usize::MAX, 1, usize::MAX, "fixture response").is_err());
}

#[test]
fn progress_runs_only_after_an_accepted_chunk() {
    let mut body = BoundedBody::new(None, 4, "fixture response").unwrap();
    let mut progress = 0;
    body.push_and_then(b"1234", || progress += 1).unwrap();
    assert_eq!(progress, 1);

    assert!(body.push_and_then(b"5", || progress += 1).is_err());
    assert_eq!(progress, 1);
    assert_eq!(body.as_bytes(), b"1234");
}

#[test]
fn underdeclared_stream_still_stops_at_the_cumulative_limit() {
    let mut body = BoundedBody::new(Some(2), 4, "fixture response").unwrap();
    let mut progress = Vec::new();
    body.push_and_then(b"12", || progress.push(2)).unwrap();
    body.push_and_then(b"34", || progress.push(2)).unwrap();

    assert!(body.push_and_then(b"5", || progress.push(1)).is_err());
    assert_eq!(body.as_bytes(), b"1234");
    assert_eq!(progress, [2, 2]);
}
