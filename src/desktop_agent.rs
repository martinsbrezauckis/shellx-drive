//! Typed, bounded protocol shared by the server broker and the native desktop
//! client. This module deliberately contains no transport, shell, path, or
//! arbitrary Tauri-command abstraction.

mod payload;
mod readback;
mod readback_validation;
mod result;
mod types;
mod validation;

pub use payload::*;
pub use readback::*;
pub use result::*;
pub use types::*;
pub use validation::{
    command_expires_at, parse_submit_request, payload_hash, validate_device_assertion,
    validate_disconnect_completion_request, validate_disconnect_retirement_request,
    validate_lease_event, validate_registration, validate_result_payload,
    DESKTOP_AGENT_LEASE_SECONDS, DESKTOP_AGENT_RELAUNCH_GRACE_SECONDS,
};
