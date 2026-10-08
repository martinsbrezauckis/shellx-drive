use std::path::Path;

use crate::{
    validate_root_pair_binding, ActivityEntry, BaselineEntry, DesktopError, DesktopState, Result,
    ReviewItem, SyncPair, MAX_PENDING_REMOTE_REVOCATIONS,
};

pub(crate) const MAX_DESKTOP_STATE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_BASELINE_ENTRIES: usize = 10_000;
const MAX_REVIEW_ENTRIES: usize = 20_000;
const MAX_ACTIVITY_ENTRIES: usize = 200;
const MAX_ID_BYTES: usize = 4 * 1024;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_PATH_COMPONENTS: usize = 128;
const MAX_REVIEW_ACTIONS: usize = 16;

pub(crate) fn validate_desktop_state(state: &DesktopState) -> Result<()> {
    state.validate_pair_profiles()?;
    if state.sync_roots.len() > crate::MAX_DISCOVERY_ROOTS {
        return Err(DesktopError::InvalidState(format!(
            "saved sync roots exceed the {}-root desktop limit",
            crate::MAX_DISCOVERY_ROOTS
        )));
    }
    if let Some(base) = &state.sync_root_base {
        ensure_path("sync root base", base)?;
    }
    ensure_count(
        "pending remote revocations",
        state.pending_remote_revocations.len(),
        MAX_PENDING_REMOTE_REVOCATIONS,
    )?;

    if let Some(record) = &state.active_remote_session {
        record.validate()?;
    }
    if let Some(record) = &state.pending_candidate_session {
        record.validate()?;
    }
    for record in &state.pending_remote_revocations {
        record.validate()?;
    }
    if let Some(cleanup) = state.pending_disconnect_cleanup() {
        cleanup.validate_shape()?;
        for marker in cleanup.markers() {
            if !matches!(marker.marker.schema_version, 1 | 2) {
                return Err(DesktopError::InvalidState(
                    "disconnect cleanup marker has an unsupported schema version".to_string(),
                ));
            }
            ensure_path("disconnect cleanup local root", &marker.local_root)?;
            ensure_text(
                "disconnect cleanup marker workspace ID",
                &marker.marker.workspace_id,
                MAX_ID_BYTES,
            )?;
            if let Some(remote_root_id) = &marker.marker.remote_root_id {
                ensure_text(
                    "disconnect cleanup marker remote root ID",
                    remote_root_id,
                    MAX_ID_BYTES,
                )?;
            }
            ensure_text(
                "disconnect cleanup marker server URL",
                &marker.marker.server_url,
                MAX_TEXT_BYTES,
            )?;
        }
        for slot in &cleanup.credential_slots {
            ensure_text(
                "disconnect cleanup credential slot",
                &slot.account_key,
                MAX_TEXT_BYTES,
            )?;
            if slot.account_key.is_empty() {
                return Err(DesktopError::InvalidState(
                    "disconnect cleanup contains an empty credential slot".to_string(),
                ));
            }
        }
    }
    if let Some(continuation) = state.pending_desktop_agent_disconnect() {
        continuation.validate()?;
        let expects_control = matches!(
            continuation.phase,
            crate::DesktopAgentDisconnectPhase::RetiringRemote
                | crate::DesktopAgentDisconnectPhase::RetirementCancelled
                | crate::DesktopAgentDisconnectPhase::RetirementBlocked
        );
        if state.desktop_agent_control.enabled != expects_control {
            return Err(DesktopError::InvalidState(
                "desktop-agent Disconnect continuation does not match device-control retirement"
                    .to_string(),
            ));
        }
        let cleanup_expected = matches!(
            continuation.phase,
            crate::DesktopAgentDisconnectPhase::RetiringRemote
                | crate::DesktopAgentDisconnectPhase::LocalCleanup
                | crate::DesktopAgentDisconnectPhase::RetirementCancelled
                | crate::DesktopAgentDisconnectPhase::RetirementBlocked
        );
        if state.has_pending_disconnect_cleanup() != cleanup_expected {
            return Err(DesktopError::InvalidState(
                "desktop-agent Disconnect continuation does not match local cleanup state"
                    .to_string(),
            ));
        }
    }
    if let Some(unconfirmed) = &state.unconfirmed_desktop_agent_disconnect {
        unconfirmed.validate()?;
    }
    state.desktop_agent_control.validate()?;
    if let Some(intent) = &state.pending_desktop_update_restart {
        intent.validate()?;
    }

    if let Some(pair) = &state.pair {
        validate_pair(pair)?;
    }
    validate_sync_collections(
        &state.baseline,
        &state.reviews,
        &state.activity,
        state.last_error.as_deref(),
    )?;
    for profile in &state.inactive_pairs {
        validate_pair(&profile.pair)?;
        validate_sync_collections(
            &profile.baseline,
            &profile.reviews,
            &profile.activity,
            profile.last_error.as_deref(),
        )?;
    }
    for (pair_id, metadata) in &state.sync_roots {
        ensure_text("sync root pair ID", pair_id, MAX_ID_BYTES)?;
        metadata.root.validate()?;
        let pair = state
            .pairs()
            .find(|pair| crate::sync_pair_id(pair) == *pair_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "saved sync root authority has no configured pair".to_string(),
                )
            })?;
        validate_root_pair_binding(pair, &metadata.root)?;
    }
    Ok(())
}

fn validate_pair(pair: &SyncPair) -> Result<()> {
    ensure_text("pair server URL", &pair.server_url, MAX_TEXT_BYTES)?;
    ensure_text("pair account email", &pair.account_email, MAX_TEXT_BYTES)?;
    ensure_text("pair workspace ID", &pair.workspace_id, MAX_ID_BYTES)?;
    ensure_text("pair workspace name", &pair.workspace_name, MAX_TEXT_BYTES)?;
    if let Some(id) = &pair.remote_root_id {
        ensure_text("pair remote root ID", id, MAX_ID_BYTES)?;
    }
    if let Some(name) = &pair.remote_root_name {
        ensure_text("pair remote root name", name, MAX_TEXT_BYTES)?;
    }
    ensure_path("pair local root", &pair.local_root)
}

fn validate_sync_collections(
    baseline: &std::collections::BTreeMap<String, BaselineEntry>,
    reviews: &[ReviewItem],
    activity: &[ActivityEntry],
    last_error: Option<&str>,
) -> Result<()> {
    ensure_count("baseline", baseline.len(), MAX_BASELINE_ENTRIES)?;
    ensure_count("reviews", reviews.len(), MAX_REVIEW_ENTRIES)?;
    ensure_count("activity", activity.len(), MAX_ACTIVITY_ENTRIES)?;
    for (key, entry) in baseline {
        ensure_text("baseline key", key, MAX_ID_BYTES)?;
        ensure_text("baseline remote ID", &entry.remote_id, MAX_ID_BYTES)?;
        if let Some(parent_id) = &entry.parent_id {
            ensure_text("baseline parent ID", parent_id, MAX_ID_BYTES)?;
        }
        ensure_path("baseline path", &entry.relative_path)?;
        ensure_text("baseline kind", &entry.kind, 32)?;
        if let Some(hash) = &entry.content_hash {
            ensure_text("baseline content hash", hash, 256)?;
        }
    }
    for review in reviews {
        ensure_text("review ID", &review.id, MAX_ID_BYTES)?;
        ensure_path("review path", &review.relative_path)?;
        ensure_text("review summary", &review.summary, MAX_TEXT_BYTES)?;
        ensure_count("review actions", review.actions.len(), MAX_REVIEW_ACTIONS)?;
    }
    for activity in activity {
        ensure_text("activity direction", &activity.direction, MAX_ID_BYTES)?;
        ensure_path("activity path", &activity.relative_path)?;
        ensure_text("activity result", &activity.result, MAX_TEXT_BYTES)?;
    }
    if let Some(error) = last_error {
        ensure_text("last error", error, MAX_TEXT_BYTES)?;
    }
    Ok(())
}

fn ensure_count(label: &str, actual: usize, maximum: usize) -> Result<()> {
    if actual > maximum {
        return Err(DesktopError::InvalidState(format!(
            "{label} contains {actual} entries; maximum is {maximum}"
        )));
    }
    Ok(())
}

fn ensure_text(label: &str, value: &str, maximum: usize) -> Result<()> {
    if value.len() > maximum {
        return Err(DesktopError::InvalidState(format!(
            "{label} exceeds the {maximum}-byte limit"
        )));
    }
    Ok(())
}

fn ensure_path(label: &str, path: &Path) -> Result<()> {
    let rendered = path.to_string_lossy();
    if rendered.len() > MAX_PATH_BYTES || path.components().count() > MAX_PATH_COMPONENTS {
        return Err(DesktopError::InvalidState(format!(
            "{label} exceeds the persisted path budget"
        )));
    }
    Ok(())
}
