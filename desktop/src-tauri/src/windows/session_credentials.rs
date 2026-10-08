//! Serialized publication and retirement of desktop session credentials.

#[path = "session_credentials/publication.rs"]
mod publication;

pub(super) use super::disconnect_retirement::retire_stored_credentials_for_disconnect as disconnect_credentials;
pub(in crate::application) use publication::complete_staged_candidate_promotion;
pub(super) use publication::publish_authenticated_session;
