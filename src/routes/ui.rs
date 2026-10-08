use axum::{
    http::{header, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use tower_http::compression::CompressionLayer;

use crate::server::AppState;

const HTML: &str = include_str!("../../web/drive.html");
const CSS: &str = include_str!("../../web/drive.css");
const ADMIN_BACKUPS_JS: &str = include_str!("../../web/admin-backups.js");
const ADMIN_CLARITY_JS: &str = include_str!("../../web/admin-clarity.js");
const ADMIN_PASSWORD_RESET_JS: &str = include_str!("../../web/admin-password-reset.js");
const ADMIN_SECURITY_JS: &str = include_str!("../../web/admin-security.js");
const DOWNLOAD_TICKETS_JS: &str = include_str!("../../web/download-tickets.js");
const UPLOAD_PROGRESS_JS: &str = include_str!("../../web/upload-progress.js");
const DRIVE_UPLOADS_JS: &str = include_str!("../../web/drive-uploads.js");
const DRIVE_FILE_MOVES_JS: &str = include_str!("../../web/drive-file-moves.js");
const DRIVE_BROWSER_JS: &str = include_str!("../../web/drive-browser.js");
const DRIVE_PREVIEW_JS: &str = include_str!("../../web/drive-preview.js");
const DRIVE_AGENT_DELEGATIONS_JS: &str = include_str!("../../web/drive-agent-delegations.js");
const DRIVE_AGENT_ACCESS_JS: &str = include_str!("../../web/drive-agent-access.js");
const DRIVE_INVITATION_LINK_JS: &str = include_str!("../../web/drive-invitation-link.js");
const DRIVE_WORKSPACE_INVITATIONS_JS: &str =
    include_str!("../../web/drive-workspace-invitations.js");
const DRIVE_HUMAN_SHARING_CONTRACT_JS: &str =
    include_str!("../../web/drive-human-sharing-contract.js");
const DRIVE_HUMAN_SHARING_DRAWER_JS: &str = include_str!("../../web/drive-human-sharing-drawer.js");
const DRIVE_EVERYONE_GRANT_POLICY_JS: &str =
    include_str!("../../web/drive-everyone-grant-policy.js");
const DRIVE_HUMAN_SHARING_ADMIN_JS: &str = include_str!("../../web/drive-human-sharing-admin.js");
const DRIVE_HUMAN_SHARING_BROWSER_JS: &str =
    include_str!("../../web/drive-human-sharing-browser.js");
const DRIVE_HUMAN_SHARING_PAGES_JS: &str = include_str!("../../web/drive-human-sharing-pages.js");
const DRIVE_HUMAN_SHARING_JS: &str = include_str!("../../web/drive-human-sharing.js");
const DRIVE_GUEST_LINKS_JS: &str = include_str!("../../web/drive-guest-links.js");
const DRIVE_COLLABORATION_JS: &str = include_str!("../../web/drive-collaboration.js");
const DRIVE_DEBUG_JS: &str = include_str!("../../web/drive-debug.js");
const DRIVE_FORMAT_JS: &str = include_str!("../../web/drive-format.js");
const DRIVE_FILE_TYPES_JS: &str = include_str!("../../web/drive-file-types.js");
const DRIVE_SETTINGS_JS: &str = include_str!("../../web/drive-settings.js");
const DRIVE_SESSIONS_JS: &str = include_str!("../../web/drive-sessions.js");
const DRIVE_WORKSPACE_POLICY_JS: &str = include_str!("../../web/drive-workspace-policy.js");
const DRIVE_ACCOUNT_JS: &str = include_str!("../../web/drive-account.js");
const DRIVE_ACCOUNT_STATE_JS: &str = include_str!("../../web/drive-account-state.js");
const DRIVE_MOBILE_SYNC_JS: &str = include_str!("../../web/drive-mobile-sync.js");
const DRIVE_AUTH_LIFECYCLE_JS: &str = include_str!("../../web/drive-auth-lifecycle.js");
const DRIVE_AUTH_HYDRATION_JS: &str = include_str!("../../web/drive-auth-hydration.js");
const DRIVE_API_JS: &str = include_str!("../../web/drive-api.js");
const DRIVE_VERSION_JS: &str = include_str!("../../web/drive-version.js");
const JS: &str = include_str!("../../web/drive.js");
const MANIFEST: &str = include_str!("../../web/manifest.webmanifest");
const SERVICE_WORKER: &str = include_str!("../../web/sw.js");
const PUBLIC_SHARE_CSS: &str = include_str!("../../web/public-share.css");
const PUBLIC_SHARE_ACCESS_JS: &str = include_str!("../../web/public-share-access.js");
const PUBLIC_SHARE_PREVIEW_JS: &str = include_str!("../../web/public-share-preview.js");
const PUBLIC_SHARE_JS: &str = include_str!("../../web/public-share.js");
const PUBLIC_INVITATION_CSS: &str = include_str!("../../web/public-invitation.css");
const PUBLIC_INVITATION_JS: &str = include_str!("../../web/public-invitation.js");
const PUBLIC_PASSWORD_RESET_CSS: &str = include_str!("../../web/public-password-reset.css");
const PUBLIC_PASSWORD_RESET_JS: &str = include_str!("../../web/public-password-reset.js");
const PUBLIC_DROP_CSS: &str = include_str!("../../web/public-drop.css");
const PUBLIC_DROP_ACCESS_JS: &str = include_str!("../../web/public-drop-access.js");
const PUBLIC_DROP_JS: &str = include_str!("../../web/public-drop.js");
const ICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="ShellX Drive"><rect width="128" height="128" rx="28" fill="#0f141a"/><path d="M30 46a10 10 0 0 1 10-10h17a6 6 0 0 1 4.4 2l6 6.4a6 6 0 0 0 4.4 2h22a10 10 0 0 1 10 10v33a10 10 0 0 1-10 10H40a10 10 0 0 1-10-10Z" fill="#b4dc19"/><path d="M57 55 73 67 57 79" fill="none" stroke="#0f141a" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;
const APP_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const PUBLIC_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/reset-password", get(public_password_reset_page))
        .route("/favicon.ico", get(favicon))
        .route("/assets/drive.css", get(css))
        .route("/assets/admin-backups.js", get(admin_backups_js))
        .route("/assets/admin-clarity.js", get(admin_clarity_js))
        .route(
            "/assets/admin-password-reset.js",
            get(admin_password_reset_js),
        )
        .route("/assets/admin-security.js", get(admin_security_js))
        .route("/assets/download-tickets.js", get(download_tickets_js))
        .route("/assets/upload-progress.js", get(upload_progress_js))
        .route("/assets/drive-uploads.js", get(drive_uploads_js))
        .route("/assets/drive-file-moves.js", get(drive_file_moves_js))
        .route("/assets/drive-browser.js", get(drive_browser_js))
        .route("/assets/drive-preview.js", get(drive_preview_js))
        .route(
            "/assets/drive-agent-delegations.js",
            get(drive_agent_delegations_js),
        )
        .route("/assets/drive-agent-access.js", get(drive_agent_access_js))
        .route(
            "/assets/drive-invitation-link.js",
            get(drive_invitation_link_js),
        )
        .route(
            "/assets/drive-workspace-invitations.js",
            get(drive_workspace_invitations_js),
        )
        .route(
            "/assets/drive-human-sharing-contract.js",
            get(drive_human_sharing_contract_js),
        )
        .route(
            "/assets/drive-human-sharing-drawer.js",
            get(drive_human_sharing_drawer_js),
        )
        .route(
            "/assets/drive-everyone-grant-policy.js",
            get(drive_everyone_grant_policy_js),
        )
        .route(
            "/assets/drive-human-sharing-admin.js",
            get(drive_human_sharing_admin_js),
        )
        .route(
            "/assets/drive-human-sharing-browser.js",
            get(drive_human_sharing_browser_js),
        )
        .route(
            "/assets/drive-human-sharing-pages.js",
            get(drive_human_sharing_pages_js),
        )
        .route(
            "/assets/drive-human-sharing.js",
            get(drive_human_sharing_js),
        )
        .route(
            "/assets/drive-collaboration.js",
            get(drive_collaboration_js),
        )
        .route("/assets/drive-guest-links.js", get(drive_guest_links_js))
        .route("/assets/drive-debug.js", get(drive_debug_js))
        .route("/assets/drive-format.js", get(drive_format_js))
        .route("/assets/drive-file-types.js", get(drive_file_types_js))
        .route("/assets/drive-settings.js", get(drive_settings_js))
        .route("/assets/drive-sessions.js", get(drive_sessions_js))
        .route(
            "/assets/drive-workspace-policy.js",
            get(drive_workspace_policy_js),
        )
        .route("/assets/drive-account.js", get(drive_account_js))
        .route(
            "/assets/drive-account-state.js",
            get(drive_account_state_js),
        )
        .route("/assets/drive-mobile-sync.js", get(drive_mobile_sync_js))
        .route(
            "/assets/drive-auth-lifecycle.js",
            get(drive_auth_lifecycle_js),
        )
        .route(
            "/assets/drive-auth-hydration.js",
            get(drive_auth_hydration_js),
        )
        .route("/assets/drive-api.js", get(drive_api_js))
        .route("/assets/drive-version.js", get(drive_version_js))
        .route("/assets/drive.js", get(js))
        .route("/assets/public-share.css", get(public_share_css))
        .route(
            "/assets/public-share-access.js",
            get(public_share_access_js),
        )
        .route(
            "/assets/public-share-preview.js",
            get(public_share_preview_js),
        )
        .route("/assets/public-share.js", get(public_share_js))
        .route("/assets/public-invitation.css", get(public_invitation_css))
        .route("/assets/public-invitation.js", get(public_invitation_js))
        .route(
            "/assets/public-password-reset.css",
            get(public_password_reset_css),
        )
        .route(
            "/assets/public-password-reset.js",
            get(public_password_reset_js),
        )
        .route("/assets/public-drop.css", get(public_drop_css))
        .route("/assets/public-drop-access.js", get(public_drop_access_js))
        .route("/assets/public-drop.js", get(public_drop_js))
        .route("/manifest.webmanifest", get(manifest))
        .route("/sw.js", get(service_worker))
        .route("/assets/shellx-drive-icon.svg", get(icon))
        // This router contains only embedded HTML and static UI assets. Keep
        // compression here rather than on the application router so file and
        // download streams retain their range/streaming behavior.
        .layer(CompressionLayer::new())
}

async fn index() -> Response {
    asset("text/html; charset=utf-8", HTML)
}

/// Password-reset capability page. The token exists only in `#token=...`, so
/// the request URL, static assets, and referrers never receive it.
async fn public_password_reset_page() -> Response {
    public_html(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Reset password · ShellX Drive</title>
    <link rel="stylesheet" href="/assets/public-password-reset.css" />
  </head>
  <body>
    <main class="password-reset-shell">
      <section class="password-reset-card" aria-labelledby="password-reset-title">
        <p class="password-reset-eyebrow">ShellX Drive</p>
        <h1 id="password-reset-title">Reset your password</h1>
        <p id="password-reset-status" role="status" aria-live="polite">Preparing password reset…</p>
        <form id="password-reset-form" hidden>
          <label for="password-reset-new">New password</label>
          <input id="password-reset-new" type="password" autocomplete="new-password" required />
          <label for="password-reset-confirm">Confirm new password</label>
          <input id="password-reset-confirm" type="password" autocomplete="new-password" required />
          <button id="password-reset-submit" type="submit">Reset password</button>
        </form>
        <p id="password-reset-guidance">Use your password reset link to set a new password.</p>
        <a id="password-reset-sign-in" href="/" hidden>Return to Drive sign-in</a>
      </section>
    </main>
    <script src="/assets/public-password-reset.js" defer></script>
  </body>
</html>"#
            .to_string(),
    )
}

async fn css() -> Response {
    asset("text/css; charset=utf-8", CSS)
}

async fn js() -> Response {
    asset("text/javascript; charset=utf-8", JS)
}

async fn admin_backups_js() -> Response {
    asset("text/javascript; charset=utf-8", ADMIN_BACKUPS_JS)
}

async fn admin_clarity_js() -> Response {
    asset("text/javascript; charset=utf-8", ADMIN_CLARITY_JS)
}

async fn admin_password_reset_js() -> Response {
    asset("text/javascript; charset=utf-8", ADMIN_PASSWORD_RESET_JS)
}

async fn admin_security_js() -> Response {
    asset("text/javascript; charset=utf-8", ADMIN_SECURITY_JS)
}

async fn download_tickets_js() -> Response {
    asset("text/javascript; charset=utf-8", DOWNLOAD_TICKETS_JS)
}

async fn upload_progress_js() -> Response {
    asset("text/javascript; charset=utf-8", UPLOAD_PROGRESS_JS)
}

async fn drive_uploads_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_UPLOADS_JS)
}

async fn drive_file_moves_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_FILE_MOVES_JS)
}

async fn drive_browser_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_BROWSER_JS)
}

async fn drive_preview_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_PREVIEW_JS)
}

async fn drive_agent_delegations_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_AGENT_DELEGATIONS_JS)
}

async fn drive_agent_access_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_AGENT_ACCESS_JS)
}

async fn drive_invitation_link_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_INVITATION_LINK_JS)
}

async fn drive_human_sharing_contract_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        DRIVE_HUMAN_SHARING_CONTRACT_JS,
    )
}

async fn drive_human_sharing_drawer_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        DRIVE_HUMAN_SHARING_DRAWER_JS,
    )
}

async fn drive_everyone_grant_policy_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        DRIVE_EVERYONE_GRANT_POLICY_JS,
    )
}

async fn drive_human_sharing_admin_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        DRIVE_HUMAN_SHARING_ADMIN_JS,
    )
}

async fn drive_human_sharing_browser_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        DRIVE_HUMAN_SHARING_BROWSER_JS,
    )
}

async fn drive_human_sharing_pages_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        DRIVE_HUMAN_SHARING_PAGES_JS,
    )
}

async fn drive_human_sharing_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_HUMAN_SHARING_JS)
}

async fn drive_workspace_invitations_js() -> Response {
    asset(
        "text/javascript; charset=utf-8",
        DRIVE_WORKSPACE_INVITATIONS_JS,
    )
}

async fn drive_collaboration_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_COLLABORATION_JS)
}

async fn drive_guest_links_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_GUEST_LINKS_JS)
}

async fn drive_debug_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_DEBUG_JS)
}

async fn drive_format_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_FORMAT_JS)
}

async fn drive_file_types_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_FILE_TYPES_JS)
}

async fn drive_settings_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_SETTINGS_JS)
}

async fn drive_sessions_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_SESSIONS_JS)
}

async fn drive_workspace_policy_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_WORKSPACE_POLICY_JS)
}

async fn drive_account_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_ACCOUNT_JS)
}

async fn drive_account_state_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_ACCOUNT_STATE_JS)
}

async fn drive_mobile_sync_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_MOBILE_SYNC_JS)
}

async fn drive_auth_lifecycle_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_AUTH_LIFECYCLE_JS)
}

async fn drive_auth_hydration_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_AUTH_HYDRATION_JS)
}

async fn drive_api_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_API_JS)
}

async fn drive_version_js() -> Response {
    asset("text/javascript; charset=utf-8", DRIVE_VERSION_JS)
}

async fn public_share_css() -> Response {
    asset("text/css; charset=utf-8", PUBLIC_SHARE_CSS)
}

async fn public_share_access_js() -> Response {
    asset("text/javascript; charset=utf-8", PUBLIC_SHARE_ACCESS_JS)
}

async fn public_share_js() -> Response {
    asset("text/javascript; charset=utf-8", PUBLIC_SHARE_JS)
}

async fn public_share_preview_js() -> Response {
    asset("text/javascript; charset=utf-8", PUBLIC_SHARE_PREVIEW_JS)
}

async fn public_invitation_css() -> Response {
    asset("text/css; charset=utf-8", PUBLIC_INVITATION_CSS)
}

async fn public_invitation_js() -> Response {
    asset("text/javascript; charset=utf-8", PUBLIC_INVITATION_JS)
}

async fn public_password_reset_css() -> Response {
    asset("text/css; charset=utf-8", PUBLIC_PASSWORD_RESET_CSS)
}

async fn public_password_reset_js() -> Response {
    asset("text/javascript; charset=utf-8", PUBLIC_PASSWORD_RESET_JS)
}

async fn public_drop_css() -> Response {
    asset("text/css; charset=utf-8", PUBLIC_DROP_CSS)
}

async fn public_drop_access_js() -> Response {
    asset("text/javascript; charset=utf-8", PUBLIC_DROP_ACCESS_JS)
}

async fn public_drop_js() -> Response {
    asset("text/javascript; charset=utf-8", PUBLIC_DROP_JS)
}

async fn manifest() -> Response {
    asset("application/manifest+json; charset=utf-8", MANIFEST)
}

async fn service_worker() -> Response {
    asset("text/javascript; charset=utf-8", SERVICE_WORKER)
}

async fn icon() -> Response {
    asset("image/svg+xml; charset=utf-8", ICON)
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_SECURITY_POLICY, APP_CSP),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (REFERRER_POLICY, "same-origin"),
            (X_FRAME_OPTIONS, "DENY"),
        ],
        body,
    )
        .into_response()
}

pub(crate) fn public_html(body: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, PUBLIC_CSP),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (REFERRER_POLICY, "same-origin"),
            (X_FRAME_OPTIONS, "DENY"),
        ],
        body,
    )
        .into_response()
}
