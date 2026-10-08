use super::*;

#[test]
fn metadata_planning_rejects_per_actor_and_global_saturation() {
    let governor = metadata_planning_governor();
    let first = governor.try_acquire("same@example.test").unwrap();
    let second = governor.try_acquire("same@example.test").unwrap();
    assert!(matches!(
        governor.try_acquire("same@example.test"),
        Err(ApiError::TooManyRequests)
    ));

    let mut others = Vec::new();
    for index in 0..14 {
        others.push(
            governor
                .try_acquire(&format!("actor-{index}@example.test"))
                .unwrap(),
        );
    }
    assert!(matches!(
        governor.try_acquire("global@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    drop((first, second, others));
}

#[tokio::test]
async fn retained_planning_admission_covers_work_and_response_lifetime() {
    let governor = PartitionedGovernor::new(1, 1);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let background = governor.clone();
    let caller = tokio::spawn(async move {
        background
            .run_blocking_retained("owner@example.test", move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(7)
            })
            .await
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        governor.try_acquire("other@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    assert!(matches!(
        governor.try_acquire("owner@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    release_tx.send(()).unwrap();
    let (value, response_permit) = caller.await.unwrap().unwrap();
    assert_eq!(value, 7);
    assert!(matches!(
        governor.try_acquire("other@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    drop(response_permit);
    assert!(governor.try_acquire("other@example.test").is_ok());
}

#[tokio::test]
async fn cancelled_retained_planning_keeps_capacity_until_worker_exits() {
    let governor = PartitionedGovernor::new(1, 1);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let background = governor.clone();
    let caller = tokio::spawn(async move {
        background
            .run_blocking_retained("owner@example.test", move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    caller.abort();
    assert!(matches!(
        governor.try_acquire("owner@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    release_tx.send(()).unwrap();
    for _ in 0..100 {
        if governor.try_acquire("owner@example.test").is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("cancelled worker did not release its planning permit");
}
