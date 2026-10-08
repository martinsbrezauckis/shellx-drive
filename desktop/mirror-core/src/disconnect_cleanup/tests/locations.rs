use super::*;

#[test]
fn disconnect_advances_through_every_location_marker() {
    let mut second = pair();
    second.workspace_id = "workspace-two".to_string();
    second.local_root = PathBuf::from("D:/Drive");
    let mut intent =
        DisconnectCleanupIntent::for_disconnect_pairs(vec![second, pair()], vec![]).unwrap();
    assert_eq!(intent.markers().count(), 2);
    intent.confirm_remote_retirement();
    intent.acknowledge_marker();
    assert_eq!(intent.markers().count(), 1);
    intent.acknowledge_marker();
    assert!(intent.is_complete());
}
