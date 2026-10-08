//! Remote session retirement shared by Unix Disconnect and uninstall.

use std::{collections::BTreeSet, future::Future};

use shellx_drive_desktop_core::{
    CredentialStore, DesktopError, DesktopState, DriveHttpClient, LogoutOutcome,
    RemoteSessionRecord, RemoteSessionRevocationOutcome, Result as CoreResult, StateStore,
};

#[cfg(target_os = "linux")]
use shellx_drive_desktop_core::{
    LinuxCredentialStore as CanonicalStore, PendingLinuxCredentialStore as PendingStore,
};
#[cfg(target_os = "macos")]
use shellx_drive_desktop_core::{
    MacOsCredentialStore as CanonicalStore, PendingMacOsCredentialStore as PendingStore,
};

use crate::session_identity::SessionIdentity;

#[cfg(all(test, target_os = "linux"))]
mod tests;

/// Retire remote sessions before a Unix caller deletes local state.
pub(crate) async fn retire_remote_credentials(
    store: &StateStore,
    state: &mut DesktopState,
) -> CoreResult<()> {
    let stored = load_stored_credentials()?;
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

async fn retire_stored_sessions<Revoke, RevokeFuture, Logout, LogoutFuture>(
    store: &StateStore,
    state: &mut DesktopState,
    stored: &[StoredCredential],
    mut revoke: Revoke,
    mut logout: Logout,
) -> CoreResult<()>
where
    Revoke: FnMut(&StoredCredential, &RemoteSessionRecord) -> RevokeFuture,
    RevokeFuture: Future<Output = CoreResult<RemoteSessionRevocationOutcome>>,
    Logout: FnMut(&StoredCredential) -> LogoutFuture,
    LogoutFuture: Future<Output = CoreResult<LogoutOutcome>>,
{
    let direct_sessions = direct_sessions(state, stored);
    let records = state
        .pending_remote_revocations
        .iter()
        .chain(state.pending_candidate_session.iter())
        .chain(state.active_remote_session.iter())
        .cloned()
        .collect::<Vec<_>>();
    for record in records {
        if direct_sessions.contains(&record.session_id) {
            continue;
        }
        let actor = stored
            .iter()
            .find(|credential| {
                credential.identity.credential_key()
                    == SessionIdentity::new(&record.server_url, &record.account_email)
                        .credential_key()
            })
            .ok_or_else(|| {
                DesktopError::Credential(
                    "a saved remote session has no same-account retirement bearer; credentials were kept"
                        .to_string(),
                )
            })?;
        match revoke(actor, &record).await? {
            RemoteSessionRevocationOutcome::Revoked
            | RemoteSessionRevocationOutcome::AlreadyAbsent => {
                state.remove_remote_session_record(&record);
                store.save(state)?;
            }
        }
    }
    for credential in stored {
        match logout(credential).await? {
            LogoutOutcome::Revoked | LogoutOutcome::AlreadyInvalid => {
                remove_direct_session_record(state, credential);
                store.save(state)?;
            }
        }
    }
    if state.pending_candidate_session.is_some()
        || state.active_remote_session.is_some()
        || !state.pending_remote_revocations.is_empty()
    {
        return Err(DesktopError::Credential(
            "not every saved Drive session reached confirmed remote retirement; credentials were kept"
                .to_string(),
        ));
    }
    Ok(())
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
            credential.identity.credential_key()
                == SessionIdentity::new(&pair.server_url, &pair.account_email).credential_key()
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

fn load_stored_credentials() -> CoreResult<Vec<StoredCredential>> {
    let mut stored = Vec::new();
    for key in CanonicalStore::service_account_keys()? {
        let identity = SessionIdentity::parse_canonical_credential_key(&key).ok_or_else(|| {
            DesktopError::Credential(
                "a saved Drive credential has an invalid identity; credentials were kept"
                    .to_string(),
            )
        })?;
        let token = CanonicalStore.get(&key)?.ok_or_else(|| {
            DesktopError::Credential(
                "a saved Drive credential could not be read; credentials were kept".to_string(),
            )
        })?;
        stored.push(StoredCredential {
            identity,
            token,
            session_id: None,
        });
    }
    for key in PendingStore::service_account_keys()? {
        let slot = SessionIdentity::parse_pending_service_key(&key).ok_or_else(|| {
            DesktopError::Credential(
                "a staged Drive credential has an invalid identity; credentials were kept"
                    .to_string(),
            )
        })?;
        let token = PendingStore.get(&key)?.ok_or_else(|| {
            DesktopError::Credential(
                "a staged Drive credential could not be read; credentials were kept".to_string(),
            )
        })?;
        stored.push(StoredCredential {
            identity: slot.identity,
            token,
            session_id: Some(slot.session_id),
        });
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
