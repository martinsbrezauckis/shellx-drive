use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::{
    auth::{constant_time_str_eq, Actor, DriveCredential},
    download_subjects::FileContentSubject,
    error::ApiError,
    storage::Storage,
    streaming_zip,
};

pub(super) fn public_archive_revalidator(
    storage: Storage,
    share_id: String,
    share_root_id: String,
    expected_fingerprint: String,
) -> streaming_zip::ArchiveEntryRevalidator {
    Arc::new(move |subject| {
        let share = storage.get_share(&share_id)?.ok_or(ApiError::NotFound)?;
        let expired = share.share.expires_at.as_deref().is_some_and(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|expires_at| expires_at.with_timezone(&Utc) <= Utc::now())
                .unwrap_or(true)
        });
        if share.share.revoked
            || expired
            || !share.share.allow_download
            || share.share.file_id != share_root_id
            || storage.file_is_effectively_trashed(&share_root_id)?
        {
            return Err(ApiError::NotFound);
        }
        if let Some(subject) = subject {
            storage.ensure_share_file_ticket_authorized(
                &share_root_id,
                &subject.file_id,
                subject,
            )?;
        }
        if !constant_time_str_eq(&expected_fingerprint, &share.authorization_fingerprint()) {
            return Err(ApiError::NotFound);
        }
        Ok(())
    })
}

pub(super) fn authenticated_archive_revalidator(
    storage: Storage,
    workspace_id: String,
    source_file_ids: Vec<String>,
    actor: Actor,
    source_credential: DriveCredential,
) -> streaming_zip::ArchiveEntryRevalidator {
    Arc::new(move |subject| match subject {
        Some(subject) => {
            let file_ids = [subject.file_id.clone()];
            let content_subjects = [FileContentSubject::Current(subject.clone())];
            storage.ensure_download_ticket_authorized(
                &workspace_id,
                &file_ids,
                &content_subjects,
                &actor,
                &source_credential,
            )
        }
        None => storage.ensure_download_ticket_authorized(
            &workspace_id,
            &source_file_ids,
            &[],
            &actor,
            &source_credential,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;

    #[test]
    fn authenticated_revalidator_observes_session_revocation() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let email = "archive-owner@example.test";
        storage
            .bootstrap_auth_account(email, "stored-password-hash")
            .unwrap();
        let account = storage.get_auth_account_secret(email).unwrap().unwrap();
        let session_id = uuid::Uuid::now_v7().to_string();
        storage
            .record_auth_session(
                &session_id,
                email,
                "local-password",
                &account.user_id,
                "stored-session-token-hash",
                &(Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            )
            .unwrap();
        let workspace = storage.create_workspace("Archive", email).unwrap().0;
        let actor = Actor {
            email: email.to_string(),
            is_admin: false,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        };
        let revalidator = authenticated_archive_revalidator(
            storage.clone(),
            workspace.id,
            Vec::new(),
            actor,
            DriveCredential::UserSession(session_id.clone()),
        );

        revalidator(None).unwrap();
        storage.revoke_auth_session(&session_id, email).unwrap();
        assert!(matches!(revalidator(None), Err(ApiError::Unauthenticated)));
    }
}
