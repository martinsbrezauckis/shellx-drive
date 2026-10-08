use std::time::Duration;

use shellx_drive_desktop_core::{DisconnectRequest, Result as CoreResult};

use super::Runtime;

const SYNC_CANCELLATION_POLL: Duration = Duration::from_millis(20);

/// Request cooperative sync cancellation and wait without holding either the
/// coordinator or authentication-publication mutex. The pending request keeps
/// new sync and lifecycle work fenced until its caller promotes it after
/// acquiring the publication mutex.
pub(crate) async fn request_disconnect_after_sync(
    runtime: &Runtime,
) -> CoreResult<DisconnectRequest> {
    let request = runtime.coordinator.request_disconnect()?;
    while !request.is_ready()? {
        tokio::time::sleep(SYNC_CANCELLATION_POLL).await;
    }
    Ok(request)
}
