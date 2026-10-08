use super::*;

#[test]
fn sync_compute_governor_rejects_per_actor_and_global_saturation() {
    let governor = sync_compute_governor();
    let first = governor.try_acquire("first@example.test").unwrap();
    assert!(matches!(
        governor.try_acquire("first@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    let second = governor.try_acquire("second@example.test").unwrap();
    assert!(matches!(
        governor.try_acquire("third@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    drop((first, second));
}

#[tokio::test]
async fn cancelled_caller_holds_partitioned_permit_until_blocking_work_exits() {
    let governor = PartitionedGovernor::new(1, 1);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let background = governor.clone();
    let caller = tokio::spawn(async move {
        background
            .run_blocking("owner@example.test", move || {
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
        governor.try_acquire("other@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    release_tx.send(()).unwrap();
    for _ in 0..100 {
        if governor.try_acquire("other@example.test").is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("blocking partitioned work finished without releasing its permit");
}
