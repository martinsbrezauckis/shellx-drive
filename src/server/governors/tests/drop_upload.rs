use super::super::*;

#[test]
fn drop_chunk_ingress_is_bounded_by_drop_client_and_process() {
    let governor = PublicDropChunkIngressGovernor::new(3, 2, 1);
    let first = governor.try_acquire("drop-a", "client-a").unwrap();
    assert!(matches!(
        governor.try_acquire("drop-b", "client-a"),
        Err(ApiError::TooManyRequests)
    ));
    let second = governor.try_acquire("drop-a", "client-b").unwrap();
    assert!(matches!(
        governor.try_acquire("drop-a", "client-c"),
        Err(ApiError::TooManyRequests)
    ));
    let third = governor.try_acquire("drop-b", "client-c").unwrap();
    assert!(matches!(
        governor.try_acquire("drop-c", "client-d"),
        Err(ApiError::TooManyRequests)
    ));
    drop((first, second, third));
    assert!(governor.try_acquire("drop-c", "client-a").is_ok());
}
