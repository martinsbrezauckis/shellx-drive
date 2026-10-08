//! Ubuntu desktop-shell admission.
//!
//! This module owns Linux-only command wiring and keeps the shared runtime
//! free of filesystem, keyring, and desktop-session assumptions.  The
//! executor only calls descriptor-bound Unix primitives; when one cannot
//! prove its precondition, it preserves bytes and returns a review/error.

mod add_root;
mod auth;
mod candidate;
pub(crate) mod disconnect;
mod reconcile;
pub(crate) mod roots;
mod shell;
pub(crate) mod sync;
mod tray_policy;

#[path = "../../windows/app_updates.rs"]
mod app_updates;

pub(crate) use shell::{run_from_args, update_tray};
