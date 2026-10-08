//! Terminal authorization for buffered file and activity metadata responses.
//!
//! The initial route authentication admits a request, but listing and tree
//! work can select a buffered response before a session, app token, or
//! workspace membership changes. These helpers retain the exact represented
//! workspace subjects and make the existing transactional check the final
//! operation before Axum constructs JSON.

use crate::{
    auth::{Actor, DriveCredential},
    error::ApiResult,
    model::{BrowseFile, DriveFile, SearchResult},
    storage::Storage,
};

pub(crate) fn revalidate_file_metadata_publication(
    storage: &Storage,
    files: &[DriveFile],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    storage.ensure_file_metadata_publication_authorized(
        &files
            .iter()
            .map(|file| (file.id.clone(), file.workspace_id.clone(), file.trashed))
            .collect::<Vec<_>>(),
        actor,
        source_credential,
    )
}

pub(crate) fn revalidate_search_metadata_publication(
    storage: &Storage,
    results: &[SearchResult],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    revalidate_item_metadata_publication(
        storage,
        results.iter().map(|result| &result.file),
        actor,
        source_credential,
    )
}

pub(crate) fn revalidate_browse_metadata_publication(
    storage: &Storage,
    files: &[BrowseFile],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    revalidate_item_metadata_publication(
        storage,
        files.iter().map(|file| &file.file),
        actor,
        source_credential,
    )
}

pub(crate) fn revalidate_file_id_metadata_publication(
    storage: &Storage,
    file_ids: &[String],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    storage.ensure_items_publication_authorized(
        file_ids,
        actor,
        source_credential,
        crate::auth::WorkspacePermission::Read,
    )
}

fn revalidate_item_metadata_publication<'a>(
    storage: &Storage,
    files: impl IntoIterator<Item = &'a DriveFile>,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    storage.ensure_items_publication_authorized(
        &files
            .into_iter()
            .map(|file| file.id.clone())
            .collect::<Vec<_>>(),
        actor,
        source_credential,
        crate::auth::WorkspacePermission::Read,
    )
}

pub(crate) fn revalidate_workspace_metadata_publication(
    storage: &Storage,
    workspace_ids: &[String],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    storage.ensure_workspace_metadata_publication_authorized(
        workspace_ids,
        actor,
        source_credential,
    )
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;
    use crate::{
        auth::AuthMode,
        error::ApiError,
        model::{CreateFileRequest, FileKind},
    };

    fn session_for_existing_account(storage: &Storage, email: &str) -> (Actor, DriveCredential) {
        let account = storage.get_auth_account_secret(email).unwrap().unwrap();
        let session_id = uuid::Uuid::now_v7().to_string();
        storage
            .record_auth_session(
                &session_id,
                email,
                "local-password",
                &account.user_id,
                &format!("stored-session-token-hash-{session_id}"),
                &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            )
            .unwrap();
        (
            Actor {
                email: email.to_string(),
                is_admin: false,
                auth_mode: AuthMode::LocalAccount,
                allowed_workspace_ids: None,
            },
            DriveCredential::UserSession(session_id),
        )
    }

    #[test]
    fn file_metadata_terminal_check_rejects_a_session_revoked_after_selection() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let email = "metadata-publication@example.test";
        storage
            .bootstrap_auth_account(email, "stored-password-hash")
            .unwrap();
        let (actor, source_credential) = session_for_existing_account(&storage, email);
        let workspace = storage.create_workspace("Metadata", email).unwrap().0;
        let selected = vec![
            storage
                .create_file(
                    CreateFileRequest {
                        workspace_id: workspace.id,
                        parent_id: None,
                        name: "selected-before-revocation.txt".to_string(),
                        kind: FileKind::File,
                        content: None,
                        path: None,
                    },
                    None,
                )
                .unwrap()
                .0,
        ];

        let DriveCredential::UserSession(session_id) = &source_credential else {
            unreachable!();
        };
        storage.revoke_auth_session(session_id, email).unwrap();

        assert!(matches!(
            revalidate_file_metadata_publication(&storage, &selected, &actor, &source_credential,),
            Err(ApiError::Unauthenticated)
        ));
    }

    #[test]
    fn file_metadata_terminal_check_allows_an_owner_to_publish_trash() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let email = "trash-metadata-owner@example.test";
        storage
            .bootstrap_auth_account(email, "stored-password-hash")
            .unwrap();
        let (actor, source_credential) = session_for_existing_account(&storage, email);
        let workspace = storage.create_workspace("Trash metadata", email).unwrap().0;
        let file = storage
            .create_file(
                CreateFileRequest {
                    workspace_id: workspace.id,
                    parent_id: None,
                    name: "trashed-before-publication.txt".to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                None,
            )
            .unwrap()
            .0;
        let selected = vec![storage.set_trashed(&file.id, true).unwrap().0];

        revalidate_file_metadata_publication(&storage, &selected, &actor, &source_credential)
            .unwrap();

        let DriveCredential::UserSession(session_id) = &source_credential else {
            unreachable!();
        };
        storage.revoke_auth_session(session_id, email).unwrap();
        assert!(matches!(
            revalidate_file_metadata_publication(&storage, &selected, &actor, &source_credential),
            Err(ApiError::Unauthenticated)
        ));
    }

    #[test]
    fn file_metadata_terminal_check_deduplicates_compatibility_list_subjects() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let email = "metadata-dedup@example.test";
        storage
            .bootstrap_auth_account(email, "stored-password-hash")
            .unwrap();
        let (actor, source_credential) = session_for_existing_account(&storage, email);
        let workspace = storage.create_workspace("Metadata", email).unwrap().0;
        let selected_workspace_ids = vec![workspace.id; 1_001];

        revalidate_workspace_metadata_publication(
            &storage,
            &selected_workspace_ids,
            &actor,
            &source_credential,
        )
        .unwrap();
    }
}
