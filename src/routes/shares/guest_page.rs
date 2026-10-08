//! Guest HTML rendering for public-share capability URLs.

use axum::{http::StatusCode, response::Response};

use crate::{
    model::{DriveFile, FileKind},
    routes::ui,
};

use super::request_helpers::escape_html;

pub(super) fn render_share_page(
    share_id: &str,
    target: &DriveFile,
    password_required: bool,
) -> Response {
    let public_name = if password_required {
        "Protected share"
    } else {
        target.name.as_str()
    };
    let escaped_name = escape_html(public_name);
    let escaped_share_id = escape_html(share_id);
    let kind = if password_required {
        "protected"
    } else {
        target.kind.as_db_str()
    };
    let kind_label = if password_required {
        "Password required"
    } else if matches!(target.kind, FileKind::Folder) {
        "Shared folder"
    } else {
        "Shared file"
    };
    ui::public_html(format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{escaped_name} · ShellX Drive Share</title>
    <link rel="stylesheet" href="/assets/public-share.css?v=2026-07-18-collab1" />
  </head>
  <body>
    <header class="public-share-header">
      <a class="public-share-brand" href="/" aria-label="ShellX Drive home">
        <img src="/assets/shellx-drive-icon.svg" alt="" />
        <span>ShellX Drive</span>
      </a>
      <span class="read-only-chip">Read only</span>
    </header>
    <main
      id="public-share-app"
      class="public-share-shell"
      data-share-id="{escaped_share_id}"
      data-share-kind="{kind}"
    >
      <section class="public-share-summary" aria-labelledby="share-title">
        <div id="share-root-icon" class="share-root-icon" aria-hidden="true"></div>
        <div class="public-share-title">
          <p>{kind_label}</p>
          <h1 id="share-title">{escaped_name}</h1>
          <div id="share-root-meta" class="share-root-meta" aria-live="polite">
            <span>Checking link…</span>
          </div>
        </div>
      </section>

      <section id="share-access-panel" class="share-access-panel" hidden aria-labelledby="access-title">
        <div>
          <h2 id="access-title">This link is protected</h2>
          <p>Enter the password supplied by the owner to open this share.</p>
        </div>
        <form id="share-access-form" class="share-access-form">
          <label for="share-password">Link password</label>
          <div>
            <input id="share-password" type="password" autocomplete="current-password" required />
            <button id="share-access-button" type="submit">Open share</button>
          </div>
        </form>
      </section>

      <output id="share-status" class="share-status" role="status" aria-live="polite"></output>

      <section id="shared-file-panel" class="shared-file-panel" hidden aria-label="Shared file">
        <div id="shared-file-visual" class="shared-file-visual" aria-hidden="true"></div>
        <div class="shared-file-details">
          <h2 id="shared-file-name">{escaped_name}</h2>
          <dl id="shared-file-attributes" class="shared-file-attributes"></dl>
          <div class="shared-file-actions">
            <button id="shared-file-preview" class="primary-share-action" type="button" hidden>Preview</button>
            <button id="shared-file-download" class="secondary-share-action" type="button">Download file</button>
          </div>
          <p id="shared-file-unavailable" class="share-unavailable" hidden>Preview and download are unavailable for this file. Ask the link owner for a downloadable version.</p>
        </div>
      </section>

      <section id="shared-folder-panel" class="shared-folder-panel" hidden aria-label="Shared folder contents">
        <div class="share-browser-toolbar">
          <nav id="share-breadcrumb" class="share-breadcrumb" aria-label="Shared folder path"></nav>
          <span id="share-folder-count"></span>
        </div>
        <div class="share-browser-controls" aria-label="Shared folder search and sorting">
          <label class="share-search-control">
            <span class="sr-only">Search this folder</span>
            <input id="share-folder-search" type="search" placeholder="Search this folder" autocomplete="off" />
          </label>
          <label><span>Sort</span><select id="share-folder-sort">
            <option value="name">Name</option><option value="modified">Modified</option>
            <option value="size">Size</option><option value="type">Type</option>
          </select></label>
          <button id="share-folder-sort-direction" type="button" aria-pressed="false">Ascending</button>
          <label class="share-folders-first"><input id="share-folders-first" type="checkbox" checked /><span>Folders first</span></label>
          <div class="share-layout-controls" aria-label="Folder layout">
            <button id="share-layout-list" type="button" aria-pressed="true">List</button>
            <button id="share-layout-grid" type="button" aria-pressed="false">Grid</button>
          </div>
        </div>
        <div class="share-selection-toolbar" aria-live="polite">
          <label><input id="share-select-visible" type="checkbox" /><span>Select all</span></label>
          <span id="share-selection-count">No items selected</span>
          <div>
            <button id="share-selection-clear" type="button" hidden>Clear</button>
            <button id="share-selection-download" class="primary-share-action" type="button" disabled>Download selected</button>
          </div>
        </div>
        <div class="share-entry-columns" aria-hidden="true">
          <span></span><span>Name</span><span>Modified</span><span>Size</span><span></span>
        </div>
        <div id="share-entry-list" class="share-entry-list"></div>
        <nav id="share-folder-pagination" class="share-folder-pagination" aria-label="Shared folder pages" hidden>
          <button id="share-folder-page-previous" type="button">Previous</button>
          <span id="share-folder-page-position">Page 1 of 1</span>
          <button id="share-folder-page-next" type="button">Next</button>
        </nav>
        <div id="share-folder-empty" class="share-folder-empty" hidden>
          <span class="empty-folder-icon" aria-hidden="true"></span>
          <strong id="share-folder-empty-title">This folder is empty</strong>
          <p id="share-folder-empty-copy">There are no files or subfolders here.</p>
        </div>
      </section>
    </main>
    <div id="share-preview-modal" class="share-preview-modal" hidden role="dialog" aria-modal="true" aria-labelledby="share-preview-title">
      <div class="share-preview-panel">
        <header class="share-preview-head">
          <div class="share-preview-heading">
            <strong id="share-preview-title">Preview</strong>
            <span id="share-preview-position"></span>
          </div>
          <div>
            <button id="share-preview-download" class="secondary-share-action" type="button">Download</button>
            <button id="share-preview-close" class="share-preview-close" type="button" aria-label="Close preview">Close</button>
          </div>
        </header>
        <div class="share-preview-stage">
          <button id="share-preview-previous" class="share-preview-navigation previous" type="button" aria-label="Previous media">‹</button>
          <div id="share-preview-body" class="share-preview-body"></div>
          <button id="share-preview-next" class="share-preview-navigation next" type="button" aria-label="Next media">›</button>
        </div>
      </div>
    </div>
    <script src="/assets/download-tickets.js?v=2026-08-26-auth-epoch1" defer></script>
    <script src="/assets/drive-browser.js?v=2026-07-18-collab1" defer></script>
    <script src="/assets/public-share-access.js?v=2026-08-26-password-lifetime1" defer></script>
    <script src="/assets/public-share-preview.js?v=2026-08-26-password-lifetime1" defer></script>
    <script src="/assets/public-share.js?v=2026-08-26-password-lifetime1" defer></script>
  </body>
</html>"#
    ))
}

/// Use one deliberately content-free response for every unavailable browser
/// capability. Keep this page self-contained so no resource request receives a
/// referrer derived from the capability URL.
pub(super) fn render_link_unavailable_page() -> Response {
    let mut response = ui::public_html(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Link unavailable · ShellX Drive</title>
  </head>
  <body>
    <main>
      <h1>Link unavailable</h1>
      <p>This link is unavailable.</p>
    </main>
  </body>
</html>"#
            .to_string(),
    );
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}
