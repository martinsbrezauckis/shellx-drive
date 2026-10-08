//! ShellX Drive Desktop binary entry point.
//!
//! Product behavior lives in the shared application module. Platform-specific
//! code is admitted only through the platform adapter boundary.

#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

#[cfg(feature = "desktop-shell")]
mod session_identity;

#[cfg(feature = "desktop-shell")]
mod platform;

#[cfg(feature = "desktop-shell")]
#[cfg_attr(
    not(target_os = "windows"),
    allow(dead_code, private_interfaces, unused_imports)
)]
mod application;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn main() {
    eprintln!(
        "ShellX Drive Desktop has no supported native adapter on this host. Use a supported ShellX Drive Desktop installer."
    );
}

#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(application::run_from_args());
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(application::run_from_args());
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(application::run_from_args());
}
