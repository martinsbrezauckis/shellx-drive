//! Typed, non-secret contract for the outbound desktop-agent broker.
//!
//! Transport lives in the HTTP child module; this root retains only bounded
//! protocol, durable state, and test module wiring.

mod claim_decode;
mod claim_parse;
mod credential_key;
mod disconnect;
#[cfg(test)]
mod disconnect_tests;
mod fingerprint;
mod journal;
mod pagination;
mod protocol;
mod result;
#[cfg(test)]
mod result_tests;
mod state;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;

pub use credential_key::{
    desktop_agent_device_credential_key, validate_desktop_agent_device_credential_key,
};
pub use disconnect::*;
pub use fingerprint::{desktop_agent_enrollment_fingerprint, desktop_agent_pair_fingerprint};
use fingerprint::{ensure_fingerprint, ensure_native_review_id, ensure_opaque_id};
pub use pagination::*;
pub use protocol::*;
pub use result::*;
pub use state::*;
