use crate::error::ApiResult;

use super::{PartitionedGovernor, PartitionedPermit};

const ADMIN_JSON_INGRESS_CONCURRENCY: usize = 8;
const USER_JSON_INGRESS_CONCURRENCY: usize = 24;
const ACCOUNT_JSON_INGRESS_CONCURRENCY: usize = 8;
const PUBLIC_JSON_INGRESS_CONCURRENCY: usize = 8;
const AUTHENTICATED_JSON_INGRESS_PER_ACTOR: usize = 4;
const UNTRUSTED_JSON_INGRESS_PER_CLIENT: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum JsonIngressClass {
    Admin,
    User,
    Account,
    Public,
}

#[derive(Clone)]
pub(in crate::server) struct JsonIngressGovernor {
    admin: PartitionedGovernor,
    users: PartitionedGovernor,
    account: PartitionedGovernor,
    public: PartitionedGovernor,
}

impl Default for JsonIngressGovernor {
    fn default() -> Self {
        Self {
            admin: PartitionedGovernor::new(
                ADMIN_JSON_INGRESS_CONCURRENCY,
                AUTHENTICATED_JSON_INGRESS_PER_ACTOR,
            ),
            users: PartitionedGovernor::new(
                USER_JSON_INGRESS_CONCURRENCY,
                AUTHENTICATED_JSON_INGRESS_PER_ACTOR,
            ),
            account: PartitionedGovernor::new(
                ACCOUNT_JSON_INGRESS_CONCURRENCY,
                UNTRUSTED_JSON_INGRESS_PER_CLIENT,
            ),
            public: PartitionedGovernor::new(
                PUBLIC_JSON_INGRESS_CONCURRENCY,
                UNTRUSTED_JSON_INGRESS_PER_CLIENT,
            ),
        }
    }
}

impl JsonIngressGovernor {
    pub(in crate::server) fn try_acquire(
        &self,
        class: JsonIngressClass,
        partition: &str,
    ) -> ApiResult<PartitionedPermit> {
        match class {
            JsonIngressClass::Admin => self.admin.try_acquire(partition),
            JsonIngressClass::User => self.users.try_acquire(partition),
            JsonIngressClass::Account => self.account.try_acquire(partition),
            JsonIngressClass::Public => self.public.try_acquire(partition),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ApiError;

    #[test]
    fn public_saturation_preserves_admin_capacity() {
        let governor = JsonIngressGovernor::default();
        let mut public = Vec::new();
        for client in 0..(PUBLIC_JSON_INGRESS_CONCURRENCY / UNTRUSTED_JSON_INGRESS_PER_CLIENT) {
            for _ in 0..UNTRUSTED_JSON_INGRESS_PER_CLIENT {
                public.push(
                    governor
                        .try_acquire(JsonIngressClass::Public, &format!("client-{client}"))
                        .unwrap(),
                );
            }
        }
        assert!(matches!(
            governor.try_acquire(JsonIngressClass::Public, "overflow"),
            Err(ApiError::TooManyRequests)
        ));
        assert!(governor
            .try_acquire(JsonIngressClass::Admin, "admin@example.test")
            .is_ok());
        drop(public);
    }
}
