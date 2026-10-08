//! Canonical human item-sharing storage.  The submodules keep provisioning,
//! mutations, principal lookup, and effective access independently reviewable.

pub(in crate::storage) mod access;
pub(in crate::storage) mod actor_visibility;
mod admin_content;
mod capabilities;
mod mutations;
pub(in crate::storage) mod policy;
mod principals;
pub(super) mod provisioning;
mod publication;
mod retention;
mod shared_by_me;
mod shared_roots;
mod sync_roots;
#[cfg(test)]
mod tests;
