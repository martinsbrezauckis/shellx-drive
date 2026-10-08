//! Shared desktop application state and platform-specific execution adapters.
//!
//! Commands, status projection, lifecycle serialization, and credential
//! admission are platform-neutral. Native filesystem publication and
//! target-specific shell execution remain isolated below `windows`, `macos`,
//! and `linux`; the Unix targets share descriptor-bound confinement services.

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub(crate) mod auth_publication;
pub(crate) mod commands;
pub(crate) mod desktop_agent;
mod disconnect;
pub(crate) mod lifecycle;
mod local_usage;
pub(crate) mod review;
pub(crate) mod root_discovery;
mod runtime;
mod sync_terminal;
#[cfg(any(target_os = "macos", target_os = "linux", test))]
mod unix_candidate_recovery;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix_uninstall;
pub(crate) mod update_service;
mod view;

pub(crate) use disconnect::request_disconnect_after_sync;
pub(crate) use runtime::{
    invalidate_pending_confirmation, PendingLogin, PendingReviewConfirmation, Runtime,
};
pub(crate) use view::{DesktopView, SyncLocationView};

#[cfg(target_os = "windows")]
pub(crate) mod windows;

#[cfg(target_os = "linux")]
pub(crate) mod linux;

// The macOS shell owns only macOS lifecycle and filesystem adapters. Shared
// view, validation, root-discovery, and review-confirmation policy remains
// above this boundary.
#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(target_os = "linux")]
pub(crate) use linux::run_from_args;
#[cfg(target_os = "macos")]
pub(crate) use macos::run_from_args;
#[cfg(target_os = "windows")]
pub(crate) use windows::run_from_args;
#[cfg(target_os = "windows")]
pub(crate) use windows::startup;
