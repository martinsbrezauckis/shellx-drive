use super::{
    limits::{insert_file, insert_grant},
    *,
};
use crate::storage::human_item_grants::retention::{
    MAX_CURRENT_HUMAN_ITEM_GRANTS, MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_WORKSPACE,
};

#[test]
fn database_wide_current_grant_cap_bounds_complete_discovery() {
    let (_directory, storage, _private_workspace_id) = storage();
    let mut workspace_ids = Vec::new();
    let workspace_count =
        MAX_CURRENT_HUMAN_ITEM_GRANTS / MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_WORKSPACE;
    for index in 0..workspace_count {
        workspace_ids.push(
            storage
                .create_workspace(&format!("Bounded {index}"), OWNER)
                .unwrap()
                .0
                .id,
        );
    }
    let target_workspace = storage
        .create_workspace("Bounded target", OWNER)
        .unwrap()
        .0
        .id;
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for (workspace_index, workspace_id) in workspace_ids.iter().enumerate() {
            for grant_index in 0..MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_WORKSPACE {
                let id = format!("global-{workspace_index:02}-{grant_index:04}");
                insert_file(&tx, workspace_id, &id);
                insert_grant(
                    &tx,
                    &format!("grant-{id}"),
                    workspace_id,
                    &id,
                    &format!("principal-{id}"),
                    None,
                );
            }
        }
        tx.commit().unwrap();
    }
    let target = create(
        &storage,
        &target_workspace,
        None,
        "global-overflow",
        FileKind::File,
    );
    assert!(matches!(
        storage.create_human_item_grant(
            &target,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        ),
        Err(ApiError::PayloadTooLarge(message))
            if message.contains("10000 current grants")
    ));
}
