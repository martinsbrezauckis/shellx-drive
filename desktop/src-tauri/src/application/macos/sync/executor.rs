//! Focused macOS terminal-sync action modules.

mod inbound;
mod inbound_move;
mod local;
#[cfg(test)]
mod move_tests;
mod operations;
mod outbound;
mod outbound_move;
mod outbound_witness;
#[cfg(test)]
mod outbound_witness_tests;
mod presentation;
mod remote;
mod remote_match;
#[cfg(test)]
mod remote_match_tests;
mod transfer;
mod upload;

pub(super) use operations::execute_actions;

pub(super) fn local_entries(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    pair: &shellx_drive_desktop_core::SyncPair,
) -> shellx_drive_desktop_core::Result<Vec<shellx_drive_desktop_core::LocalEntry>> {
    local::entries(guard, pair)
}
