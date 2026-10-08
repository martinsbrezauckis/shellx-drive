use super::*;
use crate::error::ApiError;

mod work_budget;

fn storage() -> (tempfile::TempDir, Storage) {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    (temp, storage)
}

#[test]
fn distributed_failures_lock_each_capability_and_verified_recovery_clears_it() {
    for kind in [PublicCapabilityKind::Share, PublicCapabilityKind::Drop] {
        let (_temp, storage) = storage();
        let capability_id = format!("{}-capability", kind.label());
        for attempt in 0..CAPABILITY_POLICY.threshold {
            let client = format!("client-{attempt}");
            let admission = storage
                .admit_public_capability_password_attempt(kind, &capability_id, &client)
                .unwrap();
            assert_eq!(admission, AuthAttemptAdmission::Ordinary);
            let result = storage
                .complete_public_capability_password_attempt(
                    kind,
                    &capability_id,
                    &client,
                    admission,
                    false,
                )
                .unwrap();
            assert_eq!(
                result.locked_out,
                attempt + 1 == CAPABILITY_POLICY.threshold
            );
        }

        let recovery = storage
            .admit_public_capability_password_attempt(kind, &capability_id, "recovery-client")
            .unwrap();
        assert_eq!(recovery, AuthAttemptAdmission::SharedRecovery);
        assert!(matches!(
            storage.admit_public_capability_password_attempt(kind, &capability_id, "other-client"),
            Err(ApiError::TooManyRequests)
        ));
        storage
            .complete_public_capability_password_attempt(
                kind,
                &capability_id,
                "recovery-client",
                recovery,
                true,
            )
            .unwrap();
        assert_eq!(
            storage
                .admit_public_capability_password_attempt(kind, &capability_id, "other-client")
                .unwrap(),
            AuthAttemptAdmission::Ordinary
        );
        let resource_ref = password_resource_ref(kind, &capability_id);
        let remaining = storage.list_auth_attempts().unwrap();
        assert!(remaining
            .iter()
            .filter(|attempt| attempt.actor_email.as_deref() == Some(&resource_ref))
            .all(|attempt| attempt.scope == kind.client_scope()));
        assert!(remaining.iter().any(|attempt| {
            attempt.actor_email.as_deref() == Some(&resource_ref)
                && attempt.client_fingerprint.as_deref() == Some("client-0")
        }));
    }
}

#[test]
fn password_rotation_clears_every_client_and_shared_partition() {
    for kind in [PublicCapabilityKind::Share, PublicCapabilityKind::Drop] {
        let (_temp, storage) = storage();
        let capability_id = format!("{}-rotation", kind.label());
        for client in ["client-a", "client-b"] {
            storage
                .reserve_public_capability_password_work(kind, &capability_id, client)
                .unwrap();
            let admission = storage
                .admit_public_capability_password_attempt(kind, &capability_id, client)
                .unwrap();
            storage
                .complete_public_capability_password_attempt(
                    kind,
                    &capability_id,
                    client,
                    admission,
                    false,
                )
                .unwrap();
        }
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        clear_public_capability_password_budget_in_tx(&tx, kind, &capability_id).unwrap();
        tx.commit().unwrap();
        drop(conn);
        let resource_ref = password_resource_ref(kind, &capability_id);
        assert!(storage
            .list_auth_attempts()
            .unwrap()
            .iter()
            .all(|attempt| attempt.actor_email.as_deref() != Some(&resource_ref)));
    }
}
