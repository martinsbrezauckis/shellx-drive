use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};

use super::*;

#[tokio::test]
async fn public_budget_admission_and_completion_remain_inside_the_verifier_permit() {
    let governor = PasswordWorkGovernor::new(2, 1);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (completed_tx, completed_rx) = mpsc::channel();
    let background = governor.clone();
    let first = tokio::spawn(async move {
        background
            .verify_public_with_budget(
                "invalid-hash",
                "wrong-password",
                true,
                move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(7_u8)
                },
                move |verified, admission| {
                    assert!(!verified);
                    assert_eq!(admission, 7);
                    completed_tx.send(()).unwrap();
                    Ok(())
                },
            )
            .await
    });

    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    let second_admitted = Arc::new(AtomicBool::new(false));
    let observed = second_admitted.clone();
    assert!(matches!(
        governor
            .verify_public_with_budget(
                "invalid-hash",
                "wrong-password",
                true,
                move || {
                    observed.store(true, Ordering::SeqCst);
                    Ok(())
                },
                |_, ()| Ok(())
            )
            .await,
        Err(ApiError::TooManyRequests)
    ));
    assert!(!second_admitted.load(Ordering::SeqCst));

    release_tx.send(()).unwrap();
    assert_eq!(first.await.unwrap().unwrap(), (false, ()));
    completed_rx.recv().unwrap();
    assert!(governor.try_acquire_public().is_ok());
}
