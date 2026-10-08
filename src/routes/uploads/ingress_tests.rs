use std::{sync::mpsc, time::Duration};

use axum::http::StatusCode;
use tower::ServiceExt as _;

use crate::error::ApiError;

mod fixture;
use fixture::{Fixture, Transport, OWNER};

#[derive(Clone, Copy)]
enum Cancellation {
    Abort,
    Timeout,
}

#[test]
fn json_chunk_abort_retains_ingress_until_chunk_worker_exits() {
    cancelled_chunk(Transport::Json, Cancellation::Abort, false);
}

#[test]
fn json_chunk_timeout_retains_ingress_until_finalizer_exits() {
    cancelled_chunk(Transport::Json, Cancellation::Timeout, true);
}

#[test]
fn binary_chunk_abort_retains_ingress_until_chunk_worker_exits() {
    cancelled_chunk(Transport::Binary, Cancellation::Abort, false);
}

#[test]
fn binary_chunk_timeout_retains_ingress_until_finalizer_exits() {
    cancelled_chunk(Transport::Binary, Cancellation::Timeout, true);
}

fn cancelled_chunk(transport: Transport, cancellation: Cancellation, finish: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let fixture = Fixture::new();
        let first = fixture
            .state
            .try_authenticated_upload_ingress(OWNER)
            .unwrap();
        let second = fixture
            .state
            .try_authenticated_upload_ingress(OWNER)
            .unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        // Delay the actual chunk/finalizer in the sole blocking lane. The
        // bounded wait also makes panic teardown release the test runtime.
        let blocker = tokio::task::spawn_blocking(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5))
        });
        entered_rx.await.unwrap();

        let app = fixture.router();
        let request = fixture.request(transport, OWNER, true, finish);
        let (timeout_tx, timeout_rx) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            let response = app.oneshot(request);
            tokio::pin!(response);
            match cancellation {
                Cancellation::Abort => {
                    response.await.unwrap();
                    panic!("chunk completed while its blocking lane was held");
                }
                Cancellation::Timeout => {
                    tokio::select! {
                        _ = &mut response => panic!("chunk completed before timeout was armed"),
                        _ = timeout_rx => {}
                    }
                    assert!(tokio::time::timeout(Duration::ZERO, response)
                        .await
                        .is_err());
                }
            }
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match fixture.state.try_authenticated_upload_ingress(OWNER) {
                    Err(ApiError::TooManyRequests) => break,
                    Ok(permit) => drop(permit),
                    Err(error) => panic!("unexpected admission error: {error:?}"),
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("real chunk handler did not acquire the third ingress slot");

        match cancellation {
            Cancellation::Abort => {
                waiter.abort();
                assert!(waiter.await.unwrap_err().is_cancelled());
            }
            Cancellation::Timeout => {
                timeout_tx.send(()).unwrap();
                waiter.await.unwrap();
            }
        }
        assert!(
            matches!(
                fixture.state.try_authenticated_upload_ingress(OWNER),
                Err(ApiError::TooManyRequests)
            ),
            "cancelled request released admission before its real worker finished"
        );
        assert_eq!(fixture.session().received_bytes, 0);

        release_tx.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(permit) = fixture.state.try_authenticated_upload_ingress(OWNER) {
                    drop(permit);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finished chunk worker did not release admission");
        let session = fixture.session();
        assert_eq!(session.received_bytes, 1);
        assert_eq!(session.completed, finish);
        if !finish {
            assert_eq!(fixture.part_bytes(), b"x");
        }
        drop((first, second));
    });
}

#[tokio::test]
async fn json_chunk_authorization_success_and_saturation_leave_exact_state() {
    normal_chunk(Transport::Json).await;
}

#[tokio::test]
async fn binary_chunk_authorization_success_and_saturation_leave_exact_state() {
    normal_chunk(Transport::Binary).await;
}

async fn normal_chunk(transport: Transport) {
    let fixture = Fixture::new();
    for (actor, authenticated, expected) in [
        (OWNER, false, StatusCode::UNAUTHORIZED),
        ("other@example.test", true, StatusCode::NOT_FOUND),
    ] {
        let response = fixture
            .router()
            .oneshot(fixture.request(transport, actor, authenticated, true))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(fixture.session().received_bytes, 0);
    }
    let permits = (0..3)
        .map(|_| {
            fixture
                .state
                .try_authenticated_upload_ingress(OWNER)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let response = fixture
        .router()
        .oneshot(fixture.request(transport, OWNER, true, true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fixture.session().received_bytes, 0);
    drop(permits);
    let response = fixture
        .router()
        .oneshot(fixture.request(transport, OWNER, true, true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["session"]["completed"], true);
    assert_eq!(body["file"]["size_bytes"], 1);
    assert_eq!(fixture.session().received_bytes, 1);
    assert!(fixture.session().completed);
    let permits = (0..3)
        .map(|_| {
            fixture
                .state
                .try_authenticated_upload_ingress(OWNER)
                .unwrap()
        })
        .collect::<Vec<_>>();
    drop(permits);
}
