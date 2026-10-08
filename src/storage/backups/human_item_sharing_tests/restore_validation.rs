use serde_json::json;

use super::*;

#[test]
fn legacy_restore_rejects_malformed_item_grants_without_mutating_live_state() {
    let (_directory, storage, workspace_id) = storage();
    let root = create(&storage, &workspace_id, None, "Malformed grant root");
    enable_everyone_grants(&storage);
    storage
        .create_human_item_grant(
            &root,
            &grant("everyone", None),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let before = storage.export_backup_tables().unwrap();
    let mut malformed = before.clone();
    let grants = malformed
        .iter_mut()
        .find(|table| table.name == "human_item_grants")
        .unwrap();
    let principal_ref = grants
        .columns
        .iter()
        .position(|column| column == "principal_ref")
        .unwrap();
    grants.rows[0][principal_ref] = json!("must-not-exist-for-everyone");

    assert!(storage.restore_backup_tables(&malformed).is_err());
    assert_eq!(
        serde_json::to_value(storage.export_backup_tables().unwrap()).unwrap(),
        serde_json::to_value(before).unwrap()
    );
}
