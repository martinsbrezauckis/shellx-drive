use crate::error::ApiResult;

use super::{
    validate_device_assertion, validate_lease_event, validate_lease_id, DesktopAgentDeviceAssertion,
};

pub fn validate_disconnect_retirement_request(
    lease_id: &str,
    assertion: &DesktopAgentDeviceAssertion,
) -> ApiResult<()> {
    validate_lease_id(lease_id)?;
    validate_device_assertion(assertion)
}

pub fn validate_disconnect_completion_request(lease_id: &str, sequence: i64) -> ApiResult<()> {
    validate_lease_event(lease_id, sequence)
}
