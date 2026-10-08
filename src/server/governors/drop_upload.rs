use crate::error::ApiResult;

use super::{PartitionedGovernor, PartitionedPermit};

const PUBLIC_DROP_CHUNK_INGRESS_CONCURRENCY: usize = 8;
const PUBLIC_DROP_CHUNK_INGRESS_PER_DROP: usize = 4;
const PUBLIC_DROP_CHUNK_INGRESS_PER_CLIENT: usize = 2;

#[derive(Clone)]
pub(crate) struct PublicDropChunkIngressGovernor {
    drops: PartitionedGovernor,
    clients: PartitionedGovernor,
}

pub(crate) struct PublicDropChunkIngressPermit {
    _drop: PartitionedPermit,
    _client: PartitionedPermit,
}

impl Default for PublicDropChunkIngressGovernor {
    fn default() -> Self {
        Self::new(
            PUBLIC_DROP_CHUNK_INGRESS_CONCURRENCY,
            PUBLIC_DROP_CHUNK_INGRESS_PER_DROP,
            PUBLIC_DROP_CHUNK_INGRESS_PER_CLIENT,
        )
    }
}

impl PublicDropChunkIngressGovernor {
    pub(super) fn new(global: usize, per_drop: usize, per_client: usize) -> Self {
        Self {
            drops: PartitionedGovernor::new(global, per_drop),
            clients: PartitionedGovernor::new(global, per_client),
        }
    }

    pub(crate) fn try_acquire(
        &self,
        drop_id: &str,
        transport_fingerprint: &str,
    ) -> ApiResult<PublicDropChunkIngressPermit> {
        let drop = self.drops.try_acquire(drop_id)?;
        let client = self.clients.try_acquire(transport_fingerprint)?;
        Ok(PublicDropChunkIngressPermit {
            _drop: drop,
            _client: client,
        })
    }
}
