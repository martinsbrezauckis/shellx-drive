use std::sync::mpsc;

use super::*;

#[test]
fn authenticated_upload_finalization_rejects_per_actor_and_global_saturation() {
    let governor = authenticated_upload_finalization_governor();
    let owner_one = governor.try_acquire("owner@example.test").unwrap();
    let owner_two = governor.try_acquire("owner@example.test").unwrap();
    let owner_three = governor.try_acquire("owner@example.test").unwrap();
    assert!(matches!(
        governor.try_acquire("owner@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    let editor = governor.try_acquire("editor@example.test").unwrap();
    assert!(matches!(
        governor.try_acquire("third@example.test"),
        Err(ApiError::TooManyRequests)
    ));
    drop((owner_one, owner_two, owner_three, editor));
}

#[tokio::test]
async fn cancelled_upload_finalizer_keeps_its_actor_permit_until_worker_exit() {
    let governor = authenticated_upload_finalization_governor();
    let first = governor.try_acquire("owner@example.test").unwrap();
    let second = governor.try_acquire("owner@example.test").unwrap();
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
        governor.try_acquire("owner@example.test"),
        Err(ApiError::TooManyRequests)
    ));

    release_tx.send(()).unwrap();
    drop((first, second));
    for _ in 0..100 {
        if let Ok(permit) = governor.try_acquire("owner@example.test") {
            drop(permit);
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("cancelled upload finalizer released capacity before its worker exited");
}
