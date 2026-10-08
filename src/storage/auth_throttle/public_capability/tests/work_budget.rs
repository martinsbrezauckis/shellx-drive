use super::*;
use crate::storage::auth_throttle::public_capability::work_budget::{
    PASSWORD_WORK_CAPABILITY_LIMIT, PASSWORD_WORK_CLIENT_LIMIT,
};

#[test]
fn successful_passwords_do_not_reset_pre_argon_work_reservations() {
    for kind in [PublicCapabilityKind::Share, PublicCapabilityKind::Drop] {
        let (_temp, storage) = storage();
        let capability_id = format!("{}-work", kind.label());
        let client = "client-a";

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
                true,
            )
            .unwrap();
        for _ in 1..PASSWORD_WORK_CLIENT_LIMIT {
            storage
                .reserve_public_capability_password_work(kind, &capability_id, client)
                .unwrap();
        }
        assert!(matches!(
            storage.reserve_public_capability_password_work(kind, &capability_id, client),
            Err(ApiError::TooManyRequests)
        ));

        storage
            .reserve_public_capability_password_work(kind, &capability_id, "client-b")
            .unwrap();
        for index in 11..PASSWORD_WORK_CAPABILITY_LIMIT {
            storage
                .reserve_public_capability_password_work(
                    kind,
                    &capability_id,
                    &format!("distributed-{index}"),
                )
                .unwrap();
        }
        assert!(matches!(
            storage.reserve_public_capability_password_work(
                kind,
                &capability_id,
                "one-client-too-many"
            ),
            Err(ApiError::TooManyRequests)
        ));

        let resource_ref = password_resource_ref(kind, &capability_id);
        let remaining = storage.list_auth_attempts().unwrap();
        assert!(remaining.iter().any(|attempt| {
            attempt.actor_email.as_deref() == Some(&resource_ref)
                && attempt.scope == kind.work_client_scope()
        }));
        assert!(remaining.iter().any(|attempt| {
            attempt.actor_email.as_deref() == Some(&resource_ref)
                && attempt.scope == kind.work_shared_scope()
        }));
    }
}
