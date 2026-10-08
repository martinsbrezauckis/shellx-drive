use std::{sync::mpsc, time::Duration};

use super::*;

mod blocking;
mod drop_upload;
mod metadata_planning;
mod password_budget;
mod upload_finalization;

#[tokio::test]
async fn public_governors_reject_concurrent_work_without_queueing() {
    let password = PasswordWorkGovernor::new(2, 1);
    let first = password.try_acquire_public().unwrap();
    assert!(matches!(
        password.try_acquire_public(),
        Err(ApiError::TooManyRequests)
    ));
    let second = password.try_acquire_account().unwrap();
    assert!(matches!(
        password.try_acquire_account(),
        Err(ApiError::TooManyRequests)
    ));
    drop(first);
    assert!(password.try_acquire_public().is_ok());
    drop(second);

    let drop_finalization = PublicDropFinalizationGovernor::new(1);
    let permit = drop_finalization.try_acquire().unwrap();
    assert!(matches!(
        drop_finalization.try_acquire(),
        Err(ApiError::TooManyRequests)
    ));
    drop(permit);
    assert!(drop_finalization.try_acquire().is_ok());

    let chunk_ingress = PublicDropChunkIngressGovernor::new(1, 1, 1);
    let permit = chunk_ingress.try_acquire("drop-a", "client-a").unwrap();
    assert!(matches!(
        chunk_ingress.try_acquire("drop-b", "client-b"),
        Err(ApiError::TooManyRequests)
    ));
    drop(permit);
    assert!(chunk_ingress.try_acquire("drop-b", "client-b").is_ok());

    let partitioned = PartitionedGovernor::new(2, 1);
    let first_partition = partitioned.try_acquire("first").unwrap();
    assert!(matches!(
        partitioned.try_acquire("first"),
        Err(ApiError::TooManyRequests)
    ));
    let second_partition = partitioned.try_acquire("second").unwrap();
    assert!(matches!(
        partitioned.try_acquire("third"),
        Err(ApiError::TooManyRequests)
    ));
    drop(first_partition);
    assert!(partitioned.try_acquire("first").is_ok());
    drop(second_partition);
}

#[test]
fn authenticated_upload_ingress_matches_the_three_worker_browser_scheduler() {
    let governor = authenticated_upload_ingress_governor();
    let first = governor.try_acquire("owner@example.test").unwrap();
    let second = governor.try_acquire("owner@example.test").unwrap();
    let third = governor.try_acquire("owner@example.test").unwrap();
    assert!(matches!(
        governor.try_acquire("owner@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    drop((first, second, third));
    assert!(governor.try_acquire("owner@example.test").is_ok());
}

#[tokio::test]
async fn cancelled_public_password_caller_keeps_capacity_until_blocking_work_exits() {
    let governor = PasswordWorkGovernor::new(2, 1);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let background = governor.clone();
    let caller = tokio::spawn(async move {
        background
            .run_blocking_public(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .await
    });

    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    caller.abort();
    assert!(matches!(
        governor.try_acquire_public(),
        Err(ApiError::TooManyRequests)
    ));

    release_tx.send(()).unwrap();
    for _ in 0..100 {
        if let Ok(permit) = governor.try_acquire_public() {
            drop(permit);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("blocking work finished without releasing the public password permit");
}
