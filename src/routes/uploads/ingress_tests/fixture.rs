use axum::{body::Body, http::Request, Router};

use crate::{
    config::{Config, PublicOrigin},
    model::UploadSession,
    server::AppState,
    storage::{UploadAdmissionPolicy, UploadSessionCreate},
};

pub(super) const OWNER: &str = "owner@example.test";

#[derive(Clone, Copy)]
pub(super) enum Transport {
    Json,
    Binary,
}

pub(super) struct Fixture {
    pub(super) state: AppState,
    upload_id: String,
    _data: tempfile::TempDir,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        let state = AppState::open(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.path().to_path_buf(),
            token: "upload-test-token".to_string(),
            bootstrap_token: None,
            e2e_enabled: true,
            email_transport: "capture".to_string(),
            email_from: "Drive <noreply@example.test>".to_string(),
            public_origin: PublicOrigin::parse("http://127.0.0.1").unwrap(),
            email_smtp_host_source: "not_configured".to_string(),
            email_smtp_port: None,
            email_smtp_user_source: "not_configured".to_string(),
            maintenance_token_source: "not_configured".to_string(),
            maintenance_sudo_source: "not_configured".to_string(),
            local_session_ttl_seconds: 2_592_000,
            office_provider_name: "Office editor".to_string(),
            office_provider_url: None,
            office_session_ttl_seconds: 900,
            hosted_mode: false,
            hosted_billing_provider: "none".to_string(),
            hosted_public_rate_limit_per_minute: 60,
            backup_max_archive_bytes: 9 * 1024 * 1024 * 1024 * 1024,
            secure_cookies: false,
            trust_proxy_headers: false,
            update_repo: None,
        })
        .unwrap();
        let (workspace, _, _) = state
            .storage
            .create_workspace("Upload ingress", OWNER)
            .unwrap();
        let session = state
            .storage
            .create_upload_session(
                UploadSessionCreate {
                    workspace_id: &workspace.id,
                    actor_email: OWNER,
                    parent_id: None,
                    name: "one-byte.txt",
                    total_size: Some(1),
                    path: None,
                    duplicate_policy: "keep_both",
                },
                UploadAdmissionPolicy::default(),
            )
            .unwrap();
        Self {
            state,
            upload_id: session.id,
            _data: data,
        }
    }

    pub(super) fn router(&self) -> Router {
        super::super::router().with_state(self.state.clone())
    }

    pub(super) fn request(
        &self,
        transport: Transport,
        actor: &str,
        authenticated: bool,
        finish: bool,
    ) -> Request<Body> {
        let (path, content_type, body) = match transport {
            Transport::Json => (
                format!("/uploads/resumable/{}", self.upload_id),
                "application/json",
                serde_json::json!({"offset": 0, "content": "x", "finish": finish}).to_string(),
            ),
            Transport::Binary => (
                format!(
                    "/uploads/resumable/{}/content?offset=0&finish={finish}",
                    self.upload_id
                ),
                "application/octet-stream",
                "x".to_string(),
            ),
        };
        let mut request = Request::builder()
            .method("PUT")
            .uri(path)
            .header("content-type", content_type)
            .header("x-shellx-actor", actor);
        if authenticated {
            request = request.header("authorization", "Bearer upload-test-token");
        }
        request.body(Body::from(body)).unwrap()
    }

    pub(super) fn session(&self) -> UploadSession {
        self.state
            .storage
            .get_upload_session(&self.upload_id)
            .unwrap()
            .unwrap()
    }

    pub(super) fn part_bytes(&self) -> Vec<u8> {
        std::fs::read(
            super::super::locking::upload_part_path(&self.state, &self.upload_id).unwrap(),
        )
        .unwrap()
    }
}
