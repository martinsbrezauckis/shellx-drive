use crate::{
    auth::{Actor, DriveCredential},
    download_subjects::{CurrentFileSubject, FileContentSubject},
    error::ApiResult,
    model::DriveFile,
    storage::{ImportRunTotals, RcloneExportCompletion, Storage},
};

/// Durable authority and immutable content identity retained until a direct
/// authenticated blob has been opened and is ready for publication.
pub(crate) struct AuthenticatedFilePublication {
    storage: Storage,
    workspace_id: String,
    file_id: String,
    actor: Actor,
    source_credential: DriveCredential,
    subject: CurrentFileSubject,
}

/// Durable authority and immutable identities retained while a buffered
/// workspace response is assembled. Unlike a direct body stream, a buffered
/// response can select several files before it is ready to publish.
pub(crate) struct AuthenticatedWorkspacePublication {
    storage: Storage,
    workspace_id: String,
    file_ids: Vec<String>,
    content_subjects: Vec<FileContentSubject>,
    actor: Actor,
    source_credential: DriveCredential,
}

impl AuthenticatedWorkspacePublication {
    pub(crate) fn new<'a>(
        storage: &Storage,
        workspace_id: &str,
        files: impl IntoIterator<Item = &'a DriveFile>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Self> {
        let mut file_ids = Vec::new();
        let mut content_subjects = Vec::new();
        for file in files {
            file_ids.push(file.id.clone());
            if file.content_hash.is_some() {
                content_subjects.push(FileContentSubject::Current(CurrentFileSubject::from_file(
                    file,
                )?));
            }
        }
        Ok(Self {
            storage: storage.clone(),
            workspace_id: workspace_id.to_string(),
            file_ids,
            content_subjects,
            actor: actor.clone(),
            source_credential: source_credential.clone(),
        })
    }

    pub(crate) fn revalidate(&self) -> ApiResult<()> {
        self.storage.ensure_download_ticket_authorized(
            &self.workspace_id,
            &self.file_ids,
            &self.content_subjects,
            &self.actor,
            &self.source_credential,
        )
    }

    pub(crate) fn complete_rclone_export_authorized(
        &self,
        run_id: &str,
        totals: ImportRunTotals,
        statistics_targets: &[(String, String)],
    ) -> ApiResult<()> {
        self.storage
            .complete_rclone_export_authorized(RcloneExportCompletion {
                run_id,
                workspace_id: &self.workspace_id,
                file_ids: &self.file_ids,
                content_subjects: &self.content_subjects,
                actor: &self.actor,
                source_credential: &self.source_credential,
                totals,
                statistics_targets,
            })
    }
}

impl AuthenticatedFilePublication {
    pub(crate) fn new(
        storage: &Storage,
        file: &DriveFile,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Self> {
        Ok(Self {
            storage: storage.clone(),
            workspace_id: file.workspace_id.clone(),
            file_id: file.id.clone(),
            actor: actor.clone(),
            source_credential: source_credential.clone(),
            subject: CurrentFileSubject::from_file(file)?,
        })
    }

    pub(crate) fn content_hash(&self) -> &str {
        &self.subject.content_hash
    }

    pub(crate) fn file_id(&self) -> &str {
        &self.file_id
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub(crate) fn actor_email(&self) -> &str {
        &self.actor.email
    }

    pub(crate) fn revalidate(&self) -> ApiResult<()> {
        self.storage.ensure_download_ticket_authorized(
            &self.workspace_id,
            std::slice::from_ref(&self.file_id),
            &[FileContentSubject::Current(self.subject.clone())],
            &self.actor,
            &self.source_credential,
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::{
        auth::AuthMode,
        error::ApiError,
        model::{CreateFileRequest, FileKind},
    };

    #[test]
    fn buffered_workspace_publication_rechecks_the_originating_session() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let email = "buffered-export@example.test";
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
        let workspace = storage
            .create_workspace("Buffered export", email)
            .unwrap()
            .0;
        let file = storage
            .create_file_with_content_bytes(
                CreateFileRequest {
                    workspace_id: workspace.id.clone(),
                    parent_id: None,
                    name: "selected.txt".to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                Some("a".repeat(64)),
                0,
            )
            .unwrap()
            .0;
        let actor = Actor {
            email: email.to_string(),
            is_admin: false,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        };
        let publication = AuthenticatedWorkspacePublication::new(
            &storage,
            &workspace.id,
            std::iter::once(&file),
            &actor,
            &DriveCredential::UserSession(session_id.clone()),
        )
        .unwrap();

        publication.revalidate().unwrap();
        storage.revoke_auth_session(&session_id, email).unwrap();
        assert!(matches!(
            publication.revalidate(),
            Err(ApiError::Unauthenticated)
        ));
    }
}
