use chrono::{Duration, Utc};
use tempfile::TempDir;

use crate::{
    auth::{Actor, AuthMode, DriveCredential, WorkspacePermission},
    error::ApiError,
    model::{CreateFileRequest, CreateHumanItemGrantRequest, FileKind, UpdateFileRequest},
    storage::Storage,
};

const OWNER: &str = "owner@example.test";
const RECIPIENT: &str = "recipient@example.test";

fn operator() -> Actor {
    Actor {
        email: "system@local".to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    }
}

fn human(email: &str) -> Actor {
    Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    }
}

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
    (human(email), DriveCredential::UserSession(session_id))
}

fn storage() -> (TempDir, Storage, String) {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (account, _) = storage
        .bootstrap_auth_account(OWNER, "owner-password")
        .unwrap();
    storage
        .create_auth_account(
            RECIPIENT,
            "recipient-password",
            false,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    (
        directory,
        storage,
        format!("private-v1:{}", account.user_id),
    )
}

fn create(
    storage: &Storage,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
    kind: FileKind,
) -> String {
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: parent_id.map(str::to_string),
                name: name.to_string(),
                kind,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0
        .id
}

fn human_grant(kind: &str, reference: Option<&str>, role: &str) -> CreateHumanItemGrantRequest {
    CreateHumanItemGrantRequest {
        principal_kind: kind.to_string(),
        principal_ref: reference.map(str::to_string),
        role: role.to_string(),
        expires_at: None,
    }
}

mod access;
mod actor_visibility;
mod global_limit;
mod limits;
mod migration;
mod principals;
mod shared_by_me;
mod sharing_pages;
