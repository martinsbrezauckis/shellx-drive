use crate::error::ApiResult;

use super::{PartitionedGovernor, PartitionedPermit};

// Modern galleries fan out several image requests. Keep that burst available
// while bounding the process, each Share, and each transport client.
const PUBLIC_BODY_STREAM_CONCURRENCY: usize = 64;
const PUBLIC_BODY_STREAMS_PER_SHARE: usize = 16;
const PUBLIC_BODY_STREAMS_PER_CLIENT: usize = 8;

#[derive(Clone)]
pub(crate) struct PublicBodyStreamGovernor {
    shares: PartitionedGovernor,
    clients: PartitionedGovernor,
}

pub(crate) struct PublicBodyStreamPermit {
    _share: PartitionedPermit,
    _client: PartitionedPermit,
}

impl Default for PublicBodyStreamGovernor {
    fn default() -> Self {
        Self {
            shares: PartitionedGovernor::new(
                PUBLIC_BODY_STREAM_CONCURRENCY,
                PUBLIC_BODY_STREAMS_PER_SHARE,
            ),
            clients: PartitionedGovernor::new(
                PUBLIC_BODY_STREAM_CONCURRENCY,
                PUBLIC_BODY_STREAMS_PER_CLIENT,
            ),
        }
    }
}

impl PublicBodyStreamGovernor {
    pub(crate) fn try_acquire(
        &self,
        share_id: &str,
        client_fingerprint: &str,
    ) -> ApiResult<PublicBodyStreamPermit> {
        let share = self.shares.try_acquire(share_id)?;
        let client = self.clients.try_acquire(client_fingerprint)?;
        Ok(PublicBodyStreamPermit {
            _share: share,
            _client: client,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ApiError;

    #[test]
    fn one_client_cannot_fill_the_global_public_stream_pool_across_shares() {
        let governor = PublicBodyStreamGovernor::default();
        let mut permits = Vec::new();
        for index in 0..PUBLIC_BODY_STREAMS_PER_CLIENT {
            permits.push(
                governor
                    .try_acquire(&format!("share-{index}"), "client-a")
                    .unwrap(),
            );
        }
        assert!(matches!(
            governor.try_acquire("another-share", "client-a"),
            Err(ApiError::TooManyRequests)
        ));
        assert!(governor.try_acquire("another-share", "client-b").is_ok());
        drop(permits);
    }
}
