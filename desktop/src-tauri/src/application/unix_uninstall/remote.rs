//! Remote session retirement shared by Unix Disconnect and uninstall.

use std::collections::BTreeSet;

use shellx_drive_desktop_core::{
    CredentialStore, DesktopError, DesktopState, DriveHttpClient, Result as CoreResult, StateStore,
};

#[cfg(test)]
use shellx_drive_desktop_core::{
    LogoutOutcome, RemoteSessionRecord, RemoteSessionRevocationOutcome,
};

#[cfg(target_os = "linux")]
use shellx_drive_desktop_core::{
    LinuxCredentialStore as CanonicalStore, PendingLinuxCredentialStore as PendingStore,
};
#[cfg(target_os = "macos")]
use shellx_drive_desktop_core::{
    MacOsCredentialStore as CanonicalStore, PendingMacOsCredentialStore as PendingStore,
};

use crate::session_identity::{
    canonical_credential_identity, pending_credential_slot, SessionIdentity,
};

#[cfg(test)]
mod identity_tests;
mod retirement;
#[cfg(all(test, target_os = "linux"))]
mod tests;
use retirement::retire_stored_sessions;

/// Retire remote sessions before a Unix caller deletes local state.
pub(crate) async fn retire_remote_credentials(
    store: &StateStore,
    state: &mut DesktopState,
) -> CoreResult<()> {
    if state
        .pending_disconnect_cleanup()
        .is_some_and(|cleanup| cleanup.remote_retirement_confirmed())
    {
        return Ok(());
    }
    let stored = load_stored_credentials(state)?;
    if stored.is_empty()
        && (state.pair.is_some()
            || state.active_remote_session.is_some()
            || state.pending_candidate_session.is_some()
            || !state.pending_remote_revocations.is_empty())
    {
        return Err(DesktopError::Credential(
            "a saved Drive session has no retrievable credential; credentials were kept for retry"
                .to_string(),
        ));
    }

    revoke_desktop_agent_device(store, state, &stored).await?;
    retire_stored_sessions(
        store,
        state,
        &stored,
        |credential, record| {
            let server_url = credential.identity.server_url.clone();
            let token = credential.token.clone();
            let session_id = record.session_id.clone();
            async move {
                DriveHttpClient::new(&server_url)?
                    .revoke_session(&token, &session_id)
                    .await
            }
        },
        |credential| {
            let server_url = credential.identity.server_url.clone();
            let token = credential.token.clone();
            async move { DriveHttpClient::new(&server_url)?.logout(&token).await }
        },
    )
    .await
}

async fn revoke_desktop_agent_device(
    store: &StateStore,
    state: &mut DesktopState,
    stored: &[StoredCredential],
) -> CoreResult<()> {
    if !state.desktop_agent_control.enabled {
        return Ok(());
    }
    let device_id = state
        .desktop_agent_control
        .device_id
        .as_deref()
        .ok_or_else(|| {
            DesktopError::InvalidState("desktop-agent enrollment has no device ID".to_string())
        })?;
    let pair = state.pair.as_ref().ok_or_else(|| {
        DesktopError::InvalidState(
            "desktop-agent enrollment has no paired owner identity for remote retirement"
                .to_string(),
        )
    })?;
    let owner = stored
        .iter()
        .find(|credential| {
            credential.identity.server_url == pair.server_url.trim_end_matches('/')
                && credential
                    .identity
                    .email
                    .eq_ignore_ascii_case(pair.account_email.trim())
        })
        .ok_or_else(|| {
            DesktopError::Credential(
                "desktop-agent retirement has no same-owner Drive bearer; credentials were kept"
                    .to_string(),
            )
        })?;
    DriveHttpClient::new(&owner.identity.server_url)?
        .revoke_desktop_agent_device(device_id, &owner.token)
        .await?;
    state.clear_desktop_agent_disconnect_retirement_block()?;
    state.retire_desktop_agent_control();
    store.save(state)
}

fn load_stored_credentials(state: &DesktopState) -> CoreResult<Vec<StoredCredential>> {
    load_stored_credentials_from(state, &CanonicalStore, &PendingStore)
}

fn load_stored_credentials_from(
    state: &DesktopState,
    canonical: &dyn CredentialStore,
    pending: &dyn CredentialStore,
) -> CoreResult<Vec<StoredCredential>> {
    use shellx_drive_desktop_core::DisconnectCredentialNamespace;
    let intent = state.pending_disconnect_cleanup().ok_or_else(|| {
        DesktopError::InvalidState(
            "Remote retirement requires the exact connection cleanup journal.".into(),
        )
    })?;
    let mut stored = Vec::new();
    for slot in &intent.credential_slots {
        match slot.namespace {
            DisconnectCredentialNamespace::Canonical => {
                let identity = canonical_credential_identity(state, &slot.account_key)?;
                if let Some(token) = canonical.get(&slot.account_key)? {
                    stored.push(StoredCredential {
                        identity,
                        token,
                        session_id: None,
                    });
                }
            }
            DisconnectCredentialNamespace::PendingCandidate => {
                let locator = pending_credential_slot(state, &slot.account_key)?;
                if let Some(token) = pending.get(&slot.account_key)? {
                    stored.push(StoredCredential {
                        identity: locator.identity,
                        token,
                        session_id: Some(locator.session_id),
                    });
                }
            }
            DisconnectCredentialNamespace::DesktopAgentDevice
            | DisconnectCredentialNamespace::DesktopAgentDeviceScoped => {}
        }
    }
    Ok(stored)
}

fn direct_sessions(state: &DesktopState, stored: &[StoredCredential]) -> BTreeSet<String> {
    let mut sessions = BTreeSet::new();
    for credential in stored {
        if let Some(session_id) = &credential.session_id {
            sessions.insert(session_id.clone());
        } else if let Some(record) = state.active_remote_session.as_ref().filter(|record| {
            record.identity_matches(&credential.identity.server_url, &credential.identity.email)
        }) {
            sessions.insert(record.session_id.clone());
        }
    }
    sessions
}

struct StoredCredential {
    identity: SessionIdentity,
    token: String,
    session_id: Option<String>,
}

fn remove_direct_session_record(state: &mut DesktopState, credential: &StoredCredential) {
    let matches_identity = |record: &shellx_drive_desktop_core::RemoteSessionRecord| {
        record.identity_matches(&credential.identity.server_url, &credential.identity.email)
            && credential
                .session_id
                .as_ref()
                .is_none_or(|session_id| record.session_id == *session_id)
    };
    if state
        .active_remote_session
        .as_ref()
        .is_some_and(matches_identity)
    {
        state.active_remote_session = None;
    }
    if state
        .pending_candidate_session
        .as_ref()
        .is_some_and(matches_identity)
    {
        state.pending_candidate_session = None;
    }
    state
        .pending_remote_revocations
        .retain(|record| !matches_identity(record));
}
