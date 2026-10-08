use super::PartitionedGovernor;

// Terminal resumable uploads copy the complete part into the blob store and
// commit the durable completion transaction. Keep those long blocking workers
// distinct from request-body ingress and routine sync computation.
const GLOBAL_CONCURRENCY: usize = 4;
const PER_ACTOR_CONCURRENCY: usize = 3;

pub(in crate::server) fn authenticated_upload_finalization_governor() -> PartitionedGovernor {
    PartitionedGovernor::new(GLOBAL_CONCURRENCY, PER_ACTOR_CONCURRENCY)
}
