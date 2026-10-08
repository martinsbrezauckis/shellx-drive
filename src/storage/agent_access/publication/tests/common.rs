use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    model::{CreateFileRequest, FileKind},
    storage::Storage,
};

pub(super) fn test_source(
    storage: &Storage,
    email: &str,
) -> (Actor, DriveCredential, String, crate::model::DriveFile) {
    storage
        .bootstrap_auth_account(email, "stored-password-hash")
        .unwrap();
    let account = storage.get_auth_account_secret(email).unwrap().unwrap();
    let session_id = Uuid::now_v7().to_string();
    storage
        .record_auth_session(
            &session_id,
            email,
            "local-password",
            &account.user_id,
            &format!("test-agent-publication-session-{session_id}"),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let actor = Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };
    let credential = DriveCredential::UserSession(session_id);
    let workspace = storage
        .create_workspace("Agent publication", email)
        .unwrap()
        .0;
    let root = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "Agent root".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0;
    (actor, credential, workspace.id, root)
}
