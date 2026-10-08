# ShellX Drive API

This document is the public route catalog for the ShellX Drive server. Unless a
route says it is public, send `Authorization: Bearer <token>`.

For ordinary authenticated item routes, an item that the caller cannot read
returns `404`, as does an unknown item ID. An item the caller can read may
return `403` when the requested action requires more authority.

Actor-aware routes also accept `x-shellx-actor: user@example.test`. With the
configured server token and no actor header, the request runs as the local admin
actor. With the configured server token and an actor header, workspace roles are
checked for that actor. Admin-token identity-bridge sessions use the same actor path without
requiring the shared server token. Admins can also issue hashed, revocable app
tokens for backup clients and devices. Each app token is permanently bound to
one actor and an explicit workspace allowlist; requests retain that bound
identity and scope. Use the owner's current local/SSO session or account-wide
delegation for ordinary client, notification, and account-management routes,
and current administrator authority for admin routes. Reserve the server token
and actor header for operator controls.

Drive has two deliberately separate `sxd_agent_` credential classes. A legacy
folder agent is a no-login principal with an explicit View/Edit subtree grant;
its token is accepted only by the bounded `/agent/v1` routes. An account-wide
delegated agent acts through the ordinary authenticated Drive and account routes
as either a local-auth owner or a supported external SSO ordinary user. Local
delegations use the owner's current resource and, where applicable, current
administrator role. External SSO delegations are bound to one exact live parent
session and remain ordinary-user delegations. Choose a folder token for
`/agent/v1` subtree operations and an account-wide delegation for normal,
account, sharing, Office, WebDAV, sync, or search routes; administrator routes
additionally require the current administrator authority described above.

Both token classes are returned only at issuance or rotation and stored as
hashes. Delegated authority ends when its token or principal is revoked or
expires, or when the local owner account is disabled; an administrator role loss
ends its corresponding delegated administrator authority. An external SSO
delegation also ends when its exact parent session is revoked or expires, or
when its stored session id, email, issuer, subject, or token-hash witness no
longer matches. It has no provider-admin role and no agent route exposes a
provider credential. Parent bindings are operational state, excluded from
backups and purged on restore; a target-retained external SSO delegation stays
inert until a human signs in and reissues one.

Stored file-body read routes stream from the blob store rather than buffering a
whole object in the server. They accept one HTTP `Range` request and return
`206`, `Content-Range`, `Content-Length`, and `Accept-Ranges: bytes` when it is
satisfiable; all file content responses include `X-Content-Type-Options:
nosniff`, and successful content responses include a restrictive content
policy.

## Route Index

```text
GET /health
GET /version
GET /update/check
GET /
GET /favicon.ico
GET /assets/drive.css
GET /assets/drive-browser.js
GET /assets/drive-uploads.js
GET /assets/drive-mobile-sync.js
GET /assets/drive-sessions.js
GET /assets/drive.js
GET /manifest.webmanifest
GET /sw.js
GET /assets/shellx-drive-icon.svg
GET /reset-password
GET /hosted/status
POST /hosted/signup
POST /workspaces
GET /workspaces/{workspace_id}/members
POST /workspaces/{workspace_id}/members
DELETE /workspaces/{workspace_id}/members
PATCH /workspaces/{workspace_id}
GET /workspaces/{workspace_id}/invitations
POST /workspaces/{workspace_id}/invitations
POST /workspaces/{workspace_id}/invitations/{invitation_id}/resend
POST /workspaces/{workspace_id}/invitations/{invitation_id}/cancel
GET /pub/invitations/accept
POST /pub/invitations/accept
POST /workspaces/{workspace_id}/leave
POST /workspaces/{workspace_id}/transfer-owner
POST /workspaces/{workspace_id}/archive
POST /workspaces/{workspace_id}/unarchive
GET /workspaces/{workspace_id}/usage
GET /workspaces/{workspace_id}/file-statistics
GET /workspaces/{workspace_id}/policy
PATCH /workspaces/{workspace_id}/policy
GET /groups
POST /groups
POST /groups/{group_id}/members
DELETE /groups/{group_id}/members
POST /workspaces/{workspace_id}/group-grants
DELETE /workspaces/{workspace_id}/group-grants/{group_id}
GET /admin/human-sharing-policy
PATCH /admin/human-sharing-policy
GET /share-principals?file_id=&kind=&query=&limit=
GET /files/{file_id}/human-grants
POST /files/{file_id}/human-grants
GET /files/{file_id}/action-capabilities
PATCH /human-grants/{grant_id}
DELETE /human-grants/{grant_id}
GET /sharing/shared-with-me
GET /sharing/shared-by-me
GET /files
POST /files
PATCH /files/{file_id}
DELETE /files/{file_id}
GET /files/{file_id}/content
GET /files/{file_id}/download
POST /files/{file_id}/download
PUT /files/{file_id}/content
GET /files/{file_id}/preview
POST /files/{file_id}/preview
GET /files/{file_id}/thumbnail
PUT /files/{file_id}/cover
GET /files/{file_id}/cover
DELETE /files/{file_id}/cover
GET /files/{file_id}/metadata
GET /files/{file_id}/agent-access
POST /files/{file_id}/agent-access
GET /agent-principals
DELETE /agent-principals/{principal_id}
GET /agent-principals/{principal_id}/grants
POST /agent-principals/{principal_id}/rotate
POST /agent-access/{grant_id}/rotate
POST /agent-access/{grant_id}/revoke
GET /agent-delegations
POST /agent-delegations
POST /agent-delegations/{principal_id}/rotate
POST /agent-delegations/{principal_id}/revoke
GET /desktop-agent/devices
POST /desktop-agent/devices/register
GET /desktop-agent/commands
POST /desktop-agent/commands
GET /desktop-agent/commands/{command_id}
POST /desktop-agent/commands/{command_id}/cancel
POST /desktop-agent/commands/{command_id}/acknowledge
POST /desktop-agent/commands/{command_id}/progress
POST /desktop-agent/commands/{command_id}/terminal
POST /desktop-agent/commands/{command_id}/disconnect-retire
POST /desktop-agent/commands/{command_id}/disconnect-complete
POST /desktop-agent/devices/{device_id}/claim
POST /desktop-agent/devices/{device_id}/heartbeat
POST /desktop-agent/devices/{device_id}/retire
POST /desktop-agent/devices/{device_id}/revoke
GET /agent/v1/access
GET /agent/v1/grants/{grant_id}/tree
POST /agent/v1/grants/{grant_id}/files
GET /agent/v1/grants/{grant_id}/files/{file_id}
PATCH /agent/v1/grants/{grant_id}/files/{file_id}
GET /agent/v1/grants/{grant_id}/files/{file_id}/content
PUT /agent/v1/grants/{grant_id}/files/{file_id}/content?base_revision=
POST /files/{file_id}/copy
GET /files/{file_id}/revisions
POST /files/{file_id}/revisions/prune
DELETE /files/{file_id}/revisions/{revision}
POST /files/{file_id}/revisions/{revision}/download
POST /files/{file_id}/revisions/{revision}/restore
POST /files/{file_id}/revisions/{revision}/pin
POST /files/{file_id}/revisions/{revision}/unpin
POST /files/{file_id}/download-zip
POST /files/download-zip
GET /downloads/{ticket}
GET /downloads/files/{ticket}
GET /workspaces/{workspace_id}/tree
POST /files/bulk
POST /uploads/preflight
POST /uploads/resumable
GET /uploads/resumable/{upload_id}
PUT /uploads/resumable/{upload_id}
PUT /uploads/resumable/{upload_id}/content?offset=&finish=
GET /workspaces/{workspace_id}/uploads
POST /uploads/resumable/{upload_id}/cancel
POST /admin/uploads/cleanup
POST /files/{file_id}/trash
POST /files/{file_id}/restore
POST /workspaces/{workspace_id}/trash/empty
POST /files/{file_id}/star
POST /files/{file_id}/unstar
GET /search?q=
GET /recent
GET /shared
GET /starred
GET /activity
GET /notifications
GET /notifications?unread_only=true
POST /notifications/{notification_id}/read
POST /notifications/read-all
GET /sync/workspaces
GET /sync/health
GET /sync/workspaces/{workspace_id}/manifest
GET /sync/mobile/workspaces
GET /sync/mobile/workspaces/{workspace_id}/manifest
GET /sync/mobile/offline
POST /sync/mobile/offline
GET /sync/mobile/files/{file_id}/content
GET /sync/files/{file_id}/chunks
PUT /sync/files/{file_id}/delta
GET /sync/changes
GET /sync/workspaces/{workspace_id}/changes
GET /sync/conflicts
GET /sync/roots
GET /sync/roots/page?cursor=
POST /sync/roots/revalidate
GET /sync/roots/{root_id}/manifest?access_generation=
POST /shares
GET /files/{file_id}/shares
GET /workspaces/{workspace_id}/shares
PATCH /shares/{share_id}
POST /shares/{share_id}/revoke
GET /pub/shares/{share_id}
GET /pub/shares/{share_id}/content
GET /pub/shares/{share_id}/thumbnail
POST /pub/shares/{share_id}/download
POST /pub/shares/{share_id}/preview
POST /pub/shares/{share_id}/download-zip
POST /pub/shares/{share_id}/content
POST /drops
GET /workspaces/{workspace_id}/drops
PATCH /drops/{drop_id}
POST /drops/{drop_id}/revoke
GET /pub/drops/{drop_id}
POST /pub/drops/{drop_id}/preflight
POST /pub/drops/{drop_id}/uploads
PUT /pub/drops/{drop_id}/uploads/{session_id}?offset=&finish=
POST /pub/drops/{drop_id}/uploads/{session_id}/cancel
GET /files/{file_id}/comments
POST /files/{file_id}/comments
PATCH /comments/{comment_id}
DELETE /comments/{comment_id}
POST /comments/{comment_id}/replies
PATCH /comment-replies/{reply_id}
DELETE /comment-replies/{reply_id}
POST /comments/{comment_id}/resolve
GET /workspaces/{workspace_id}/folder-templates
POST /workspaces/{workspace_id}/folder-templates
POST /workspaces/{workspace_id}/folder-templates/{template_id}/apply
DELETE /workspaces/{workspace_id}/folder-templates/{template_id}
GET /office/status
POST /office/files/{file_id}/open
POST /office/files/{file_id}/save
GET /office/sessions/{token}
GET /office/sessions/{token}/package
PUT /office/sessions/{token}/package
POST /office/sessions/{token}/save
GET /workspaces/{workspace_id}/export/rclone
POST /workspaces/{workspace_id}/import/rclone/preview
POST /workspaces/{workspace_id}/import/rclone
GET /drive/v3/files
POST /drive/v3/files
GET /drive/v3/files/{file_id}
GET /drive/v3/files/{file_id}?alt=media
OPTIONS /dav/{workspace_id}
OPTIONS /dav/{workspace_id}/{path}
PROPFIND /dav/{workspace_id}
PROPFIND /dav/{workspace_id}/{path}
MKCOL /dav/{workspace_id}/{path}
GET /dav/{workspace_id}/{path}
PUT /dav/{workspace_id}/{path}
DELETE /dav/{workspace_id}/{path}
MOVE /dav/{workspace_id}/{path}
COPY /dav/{workspace_id}/{path}
LOCK /dav/{workspace_id}/{path}
UNLOCK /dav/{workspace_id}/{path}
LOCK /dav/{workspace_id}
UNLOCK /dav/{workspace_id}
GET /auth/bootstrap/status
POST /auth/bootstrap
POST /auth/bootstrap/wizard
GET /auth/registration/status
POST /auth/register
POST /auth/login
POST /auth/logout
GET /auth/me
GET /auth/security-events
GET /auth/sessions
POST /auth/sessions/revoke-others
POST /auth/sessions/{session_id}/revoke
POST /auth/password/change
POST /auth/password/reset/request
POST /auth/password/reset/consume
POST /auth/2fa/setup
POST /auth/2fa/enable
POST /auth/2fa/disable
POST /auth/recovery-codes/rotate
GET /auth/oidc/config
POST /auth/oidc/exchange
GET /admin/summary
GET /admin/canonical-content?limit=&cursor=&query=
GET /admin/canonical-content/{file_id}/share-details?kind=&limit=&cursor=
GET /admin/workspaces
DELETE /admin/workspaces/{workspace_id}
GET /admin/hosted/tenants
POST /admin/hosted/tenants
GET /admin/auth/users
POST /admin/auth/users
PATCH /admin/auth/users/{email}
POST /admin/auth/users/{email}/password-reset-link
DELETE /admin/auth/users/{email}/password-reset-link
GET /admin/auth/attempts
POST /admin/auth/attempts/unlock
GET /admin/email
POST /admin/email
GET /admin/registration-policy
PATCH /admin/registration-policy
GET /admin/sessions
POST /admin/sessions/{session_id}/revoke
GET /admin/security-events
GET /admin/app-tokens
POST /admin/app-tokens
POST /admin/app-tokens/{token_id}/revoke
GET /ready
GET /admin/backups
POST /admin/backups
GET /admin/backups/{backup_id}
GET /admin/backup-jobs/{job_id}
GET /admin/backups/{backup_id}/download
POST /admin/backups/{backup_id}/validate
DELETE /admin/backups/{backup_id}
GET /admin/backup-policy
PATCH /admin/backup-policy
POST /admin/backups/{backup_id}/restore
POST /admin/retention/preview
POST /admin/retention/apply
GET /admin/sandbox
PATCH /admin/sandbox
POST /admin/sandbox/preview
POST /admin/sandbox/apply-intent
GET /admin/maintenance
POST /admin/maintenance/blobs/gc
GET /admin/support-bundle
```

## Health And Web UI

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/health` | Public liveness check. |
| GET | `/` | ShellX Drive web app shell. |
| GET | `/assets/drive.css` | Web app stylesheet. |
| GET | `/assets/drive-browser.js` | Modular sorting, filtering, persisted browse preferences, and bounded paging rules shared by authenticated and guest folder browsers. |
| GET | `/assets/drive-uploads.js` | Modular browser upload controller for bounded raw chunks, three-worker scheduling, pause/retry/cancel actions, and metadata-only reload recovery. |
| GET | `/assets/drive-mobile-sync.js` | Metadata-only offline manifest persistence and rclone import/export orchestration. |
| GET | `/assets/admin-password-reset.js` | Administrator-only manual password-recovery-link controls. The returned link is kept only in the current tab until copied or hidden. |
| GET | `/assets/drive.js` | Web app script. |
| GET | `/manifest.webmanifest` | Installable PWA manifest for mobile and desktop browsers. |
| GET | `/sw.js` | App-shell service worker. It revalidates the app shell and exact static asset URLs from the network, retaining successful same-origin responses only as offline fallbacks; authenticated API payloads are never cached, and public capability pages never fall back to the Drive shell. |
| GET | `/assets/shellx-drive-icon.svg` | PWA app icon. |

The web app camera upload control uses the same `/uploads/resumable` API as
drag/drop upload, so phone capture creates normal upload sessions, receipts,
debug upload rows, and background preview/search work.

## Version And Updates

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/version` | Public. Report the running build: `{ service, version, build, commit, built_at }`. `build` is `version+shortsha` (e.g. `0.1.0+8c30682`) and changes on every deploy. |
| GET | `/update/check` | Server administrator only. Check the latest public GitHub release for a newer server version, returning an `UpdateStatus` (see below). Ordinary users and application tokens receive `403`. Successful results are cached in-process for 30 minutes; failures use bounded 5-second to 5-minute backoff. One outbound refresh is allowed at a time. |

`UpdateStatus`:
`{ kind, current_version, repo?, latest_version?, release_url?, release_name?, published_at?, body?, download_url?, checksum_url?, checked_at, reason? }`
where `kind` is one of `current` (up to date, or the repo has no published release
yet), `available` (a newer release exists — `latest_version`/`release_url`/`body`
are populated), `unconfigured` (no release repo set), or `error` (the check could
not complete; the reason is human-readable and the result uses bounded backoff).

The proxied response is capped at 512 KiB of decoded bytes before JSON parsing.
Retained release fields are bounded separately; release notes are capped at 64
KiB, oversized tags are rejected, and at most 64 bounded release assets are
considered. Direct download links are returned only for the exact official
Linux archive and adjacent checksum under the configured GitHub repository.

**Server-proxied GitHub checks.** The web app's `Content-Security-Policy` is
`default-src 'self'`: the browser uses the same-origin server endpoint, which
checks GitHub and returns the result. The server validates the `owner/repo` slug
and contacts the fixed `api.github.com` host.

**Update mechanism.** An administrator's web UI records the `build` from
`/version`, polls it every 60 seconds and on tab focus, and shows a dismissible
"new version available — reload" banner when the live build differs from the one
the tab loaded. Ordinary users do not run this server-release watcher and do not
see server update controls. Reloading picks up the fresh app shell (the service
worker is network-first for navigation). Settings ▸ About shows the running
version to everyone, but only a server administrator can run `/update/check` or
see the reviewed server download links. The administrator reviews, verifies,
installs, and restarts the server through the documented package workflow.
The release repo is configured with
`SHELLX_DRIVE_UPDATE_REPO` (a bare `owner/repo` slug; empty disables the GitHub
check — the in-app reload banner still works, since it only depends on `/version`).

## Folder-scoped AI access

Folder-grant creation, listing, and revocation use the ordinary signed-in human
credential. They require current Read access to the folder and Write authority
for the whole workspace. Principal inventory, rotation, and removal are scoped
to the principal's creator:

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/files/{file_id}/agent-access?limit=&cursor=` | List public metadata for AI grants rooted at this folder. Results use a canonical-UUID keyset cursor, default to 25 rows, allow at most 50, and return `next_cursor` when another page exists. Plaintext tokens and token hashes are never returned. |
| POST | `/files/{file_id}/agent-access` | First share: send a new `name`, `permission` (`view` or `edit`), and optional grant `expires_in_seconds` (1 hour to 365 days; default 30 days). This creates the named no-login principal, one independent folder grant, and a token returned once. Later share: send exactly one existing `principal_id` selected from `GET /agent-principals`, plus permission and optional grant expiry. It adds a folder grant and returns no new token. |
| GET | `/agent-principals?limit=&cursor=` | Account Settings inventory of the caller's named AI-worker principals and current key metadata. Principal pages default to 25 and allow at most 50. Each principal includes a separately bounded first grant page plus `grants_next_cursor` when more folder grants exist. Plaintext keys and hashes are never returned. |
| DELETE | `/agent-principals/{principal_id}` | Creator-owned global removal. In one transaction, disables the worker, revokes every unrevoked key and folder grant, and writes an audit receipt. The worker disappears from normal inventory and selection; historical rows remain for audit. It does not erase Drive files. |
| GET | `/agent-principals/{principal_id}/grants?limit=&cursor=` | Continue one caller-owned principal's folder grants with the same canonical-UUID cursor and 25/default, 50/maximum page contract. |
| POST | `/agent-principals/{principal_id}/rotate` | Account Settings key rotation. Body: optional key `expires_in_seconds` (same range/default). Revokes the old principal key and returns the replacement once; it is immediately the key for every folder grant assigned to that principal. The returned principal contains at most the first 25 grants and uses `grants_next_cursor` for continuation. Already-authenticated writes recheck the exact old token at their final mutation boundary. |
| POST | `/agent-access/{grant_id}/rotate` | Compatibility route only. It resolves the grant's principal and performs the same principal-wide rotation; it is not a per-folder key. Use the Account Settings principal route for new clients. |
| POST | `/agent-access/{grant_id}/revoke` | Remove this folder grant only. It does not revoke the principal or affect that principal's independent grants on other folders. |

Agent calls send `Authorization: Bearer sxd_agent_...`. Every request rechecks
the exact token, principal, grant expiry/revocation, View/Edit ceiling, stored
resource identity, and folder ancestry. The granted root can be read but cannot
be renamed or moved; valid IDs outside the subtree remain forbidden.

A principal is one reusable worker identity across its granted folders. Its
single active key is principal-wide; its folder grants each retain their own
root, View/Edit ceiling, expiry, and removal lifecycle. Removing one grant
therefore removes access to only that subtree, while principal-wide key rotation
invalidates the old key for every assigned subtree. The worker is a portable,
creator-owned identity: removing the creator's human membership from one
workspace leaves the separate worker's grants active. A human with Write
authority on a folder can remove that folder grant; the creator can remove the
worker globally from Account Settings, which disables its key and every grant.

| Method | Route | Permission and behavior |
| --- | --- | --- |
| GET | `/agent/v1/access?limit=&cursor=` | Return the current no-login identity and one active-grant page. Results use the same canonical-UUID cursor and 25/default, 50/maximum contract; follow `next_cursor` until it is absent. Revoked and expired history is excluded before the page is materialized. |
| GET | `/agent/v1/grants/{grant_id}/tree` | View or Edit. Return at most 10,000 active subtree rows with a maximum depth of 256. |
| POST | `/agent/v1/grants/{grant_id}/files` | Edit. Create a file/folder under the grant root or an in-scope `parent_id`. Body: `name`, `kind`, optional `parent_id`, and optional UTF-8 file `content`. |
| GET | `/agent/v1/grants/{grant_id}/files/{file_id}` | View or Edit. Read file metadata for an in-scope resource. |
| PATCH | `/agent/v1/grants/{grant_id}/files/{file_id}` | Edit. Rename a descendant and/or move it to an in-scope `parent_id`. Root mutation and out-of-scope destinations are forbidden. |
| GET | `/agent/v1/grants/{grant_id}/files/{file_id}/content` | View or Edit. Stream an in-scope file with the ordinary safe inline/range behavior. |
| PUT | `/agent/v1/grants/{grant_id}/files/{file_id}/content?base_revision=N` | Edit. Authenticate before collecting at most 8 MiB of raw content, then replace the file only if the optimistic revision still matches. A stale revision returns `412`. |

This legacy folder-scoped agent surface intentionally has no trash/delete, restore/revision,
share/drop/comment, Office, WebDAV, sync, search/Recent/Shared, workspace/member,
backup, debug, or server-management endpoint. Adding one of those adapters is a
new authorization decision and requires it to consume the same exact-token and
subtree boundary. It is not the account-wide delegation surface below. Agent
activity receipts identify principal and token IDs but never store the plaintext
token.

## Account-wide delegated agents

Account-wide delegation is for an agent that must use the same ordinary Drive
and account API as a local-auth owner or a supported external SSO ordinary user,
not for expanding a folder grant. The bearer resolves to the owner identity and
follows the existing workspace membership, item, sharing, and personal-settings
checks of the corresponding human route. A local delegation follows the owner's
current administrator role; an external SSO delegation is always ordinary-user
authority. It can therefore use the existing file, search, sync, collaboration,
notification, session, and personal-setting routes without a parallel agent-only
adapter. Existing role, confirmation, password, and second-factor requirements
still apply. A non-admin owner is still rejected by administrator and debug
routes.

The delegation lifecycle routes accept a current local/SSO user, a current
account-wide delegation for that same owner, or the configured operator as
`system@local`. The last is a server-admin posture, not a browser identity.
App tokens and legacy folder agents are rejected.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/agent-delegations` | List the authenticated owner's account-wide delegated principals, including revoked history, newest first. Optional `limit` is 1–50 (default 25), and `cursor` is the previous page's `next_cursor` UUID. Token values and hashes are never returned. |
| POST | `/agent-delegations` | Create a named account-wide delegated principal. Body: `name` (1–120 bytes) and optional `expires_in_seconds` (1 hour to 365 days; default 30 days). An external SSO result is capped at its live parent-session expiry. The response returns its plaintext `sxd_agent_` token once, the public agent record, and a receipt. |
| POST | `/agent-delegations/{principal_id}/rotate` | Replace one owner-owned delegated token. Body: optional `expires_in_seconds` with the same range/default. An external SSO replacement is capped at its live parent-session expiry. The old token remains valid until the replacement passes its terminal publication check; success returns only the new token, agent record, and receipt. |
| POST | `/agent-delegations/{principal_id}/revoke` | Revoke one owner-owned account-wide delegated principal and token, returning its public record and receipt. |

Each owner can retain at most 50 enabled account-wide agents and 200 total
account-wide principal records. A principal retains at most 64 key records.
Quota checks run in the issuance transaction, including staged issuances.
Revoked records remain for at least 365 days; once a quota is full, Drive can
remove older revoked records that have no Office edit session, backup job, or
folder grant reference. A quota error leaves existing credentials active.

Delegation issuance and rotation are staged. Drive rechecks the exact creator
credential and current owner authority before publishing the token and again
before returning the response; a late revoke, disablement, expiry, or role loss
does not release a usable token. For external SSO, that recheck includes the
same parent session id, email, issuer, subject, and stored token-hash witness
observed at staging. A different SSO session for the same email cannot list,
rotate, or revoke its predecessor's agents. Every delegated request is likewise
checked at admission and inside the durable mutation/terminal-publication paths
used by the existing human route.

External SSO delegation has an explicit persisted `external_sso` parent kind;
it never falls back to local-account authority based on a matching email. Its
operational parent binding is intentionally excluded from archives and purged
before restore. A target-retained principal and token therefore remain
fail-closed until a new human SSO session issues a new delegation. Current OIDC
issuance mints only ordinary users, so external SSO administrator delegation
depends on adding the equivalent supported human administrator capability.

Account-security routes retain their human safeguards. A delegated agent may
read the owner's own security events and sessions, revoke the owner's ordinary
sessions, and change password or TOTP/recovery settings only with the same
current password and any required TOTP or recovery-code evidence. An
agent-initiated security rotation revokes its acting delegation instead of
minting a browser session. `POST /auth/logout` revokes that exact delegated
credential and returns `delegated_agent` plus a receipt; it never returns a
made-up local-session id.

Delegated administrator access has the same supported route catalog and action
guards as its current administrator owner. In particular, a self-disable or
self-demotion through `PATCH /admin/auth/users/{email}` requires both
`confirm_email` equal to the affected normalized email and `current_password`
verified against that account. The delegated bearer is only identity binding;
it cannot replace the typed confirmation, password, or any existing second
factor. Drive rejects a self-removal that would leave no enabled local
administrator. Password material is never retained in receipts or the security
ledger.

## Desktop agent control broker

`/desktop-agent` is a server-brokered, device-pulled control protocol with typed,
bounded commands and results. A desktop claims short leases through its outbound
connection to Drive. Listener addresses, filesystem paths, shell text, and
arbitrary native-command payloads remain outside that command schema. A command
without a target, or one targeting a retired or revoked device, is `requires_local_gesture`; a frozen
device is rejected, while a selected active device remains queued only until
its bounded expiry rather than being replayed elsewhere.

Enrollment requires a current local-password (`AuthMode::LocalAccount`) session
for the owner. External SSO sessions and their parent-bound delegations cannot
bootstrap device enrollment, and Drive does not infer a local enrollment right
from an email or account row. After enrollment, owner command actions accept a
current user session or an account-wide delegated agent.

`check_desktop_update` only checks for a signed candidate. An owner session or
account-wide delegated agent can submit `install_desktop_update` for an exact
candidate already checked by the enrolled desktop. The command can install
without a separate approval prompt on that device; give delegated command
access only to agents you trust to make that update decision.

The desktop's opaque enrollment fingerprint binds the canonical server and
account, so switching selected locations within that account preserves the
enrollment. Earlier experimental location-bound enrollments require local
disablement and re-enrollment; they are not silently rebound.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/desktop-agent/devices` | List the authenticated owner's enrolled device metadata. A current user session or an account-wide delegated agent may read this list; folder grants and app tokens cannot. |
| POST | `/desktop-agent/devices/register` | Enroll a device from the owner's current **local session** only. The response returns `device_id` and a plaintext `sxd_device_` credential once for platform credential storage; subsequent device and command responses omit it and its hash. |
| GET | `/desktop-agent/commands` | Page the owner's bounded command summaries and enum-only lifecycle events. |
| POST | `/desktop-agent/commands` | Submit a typed, short-lived command for the authenticated owner. The current user session or account-wide delegated agent must remain live. An idempotency `request_id` may be retried only with the same owner, principal, target, kind, and payload. |
| GET | `/desktop-agent/commands/{command_id}` | Read one owner-owned command summary. Cross-owner IDs do not disclose a command. |
| POST | `/desktop-agent/commands/{command_id}/cancel` | Request cancellation of one owner-owned command. |
| POST | `/desktop-agent/devices/{device_id}/claim` | Device bearer only. Assert the bound device state and claim at most one bounded lease, or return no claim. |
| POST | `/desktop-agent/devices/{device_id}/heartbeat` | Device bearer only. Refresh bounded observed device state. |
| POST | `/desktop-agent/devices/{device_id}/retire` | Device bearer only. Retire itself and cancel or interrupt its queued work. |
| POST | `/desktop-agent/devices/{device_id}/revoke` | Current owner user session or delegated owner only. Revoke a device and invalidate its active work. |
| POST | `/desktop-agent/commands/{command_id}/acknowledge` | Device bearer only. Acknowledge its current lease. |
| POST | `/desktop-agent/commands/{command_id}/progress` | Device bearer only. Publish a fixed phase and bounded progress value for its current lease. |
| POST | `/desktop-agent/commands/{command_id}/terminal` | Device bearer only. Publish a fixed terminal status and code for its current lease. A successful terminal state requires bounded `result_code` and tagged kind-specific `result`; both are omitted for every non-success state. |
| POST | `/desktop-agent/commands/{command_id}/disconnect-retire` | Claimed Disconnect capability only. Body: `{ "lease_id", "assertion" }`. Admit retirement of the exact device-bound owner session, then permit an exact retry using the original assertion after that session is revoked. Returns `204`. |
| POST | `/desktop-agent/commands/{command_id}/disconnect-complete` | The same Disconnect capability only. Body: `{ "lease_id", "event_sequence", "cancelled"?: boolean }`. After admitted retirement and local cleanup, publish the fixed completion or requested cancellation terminal; retry only the same lease, sequence and disposition. Returns `204`. |

Registration, submit, claim, acknowledgement, progress, and terminal handling
recheck the owner account, bound session or delegated source, role, security
version, device state, and lease in their committing transaction. A pending
desktop disconnect cleanup blocks ordinary success reporting; the narrow
Disconnect continuation below reports completion only after cleanup. Candidate
recovery, source revocation, disabled owner, or lost authority cannot be
reported as completed. Command payloads,
events, and result fields are finite typed enums; `result` contains only
kind-specific limited counts, booleans, statuses, opaque ids, or authorized
display labels. They do not carry paths, URLs, logs, raw errors, provider
credentials, device credential hashes, or command secrets.
`prepare_review_action` and `confirm_review_action` payloads require the exact
`pair_id`, `review_id`, and action; their readback echoes that pair binding.
`review_confirmed` also binds `prepared_confirmation_id`,
`update_install` to `candidate_id`, and `local_folder_dispatch` or
`drive_dispatch` to `{ "dispatched": true, "pair_id"? }`. Explicit submitted
pair and updater-candidate ids echo only through those bounded result fields.
Desktop-agent tables are ephemeral control-plane state: backups omit them and
restore purges any retained enrollment, command, event and Disconnect-capability
rows.

Each owner may have 16 active or frozen devices and 64 retained device rows in
total. Enrollment reuses space by removing the oldest retired or revoked
devices, while preserving devices with nonterminal commands or unexpired
Disconnect completion capabilities, including completion retries. Historical
commands and events remain readable after their device is removed; the command's
`device_id` becomes null. Enrollment returns `429` when protected history fills
capacity, and becomes available after that authority expires. Existing larger
histories are pruned in batches of at most 64 rows per enrollment attempt;
retrying a rejected attempt continues that bounded cleanup.

Only a claimed `disconnect` command returns a one-time
`disconnect_completion_capability` (`sxd_disconnect_`) and its paired
`disconnect_completion_expires_at` deadline. The desktop stores the capability
in its dedicated OS credential namespace; the server retains only its hash.
Owner agents submit commands and read their outcomes without receiving this
capability. It cannot authorize other commands or arbitrary session revocation.
Before retirement, the desktop durably records the exact retry witness and
retires its other owned sessions through the existing exact-session route.
The capability then retires only the session bound to the enrolled device.
First retirement requires a live ordinary lease; admitted retirement extends
that command's recovery lease to the capability deadline. The initial
45-second claim lease is not the post-retirement completion deadline.
The local continuation survives unpairing and response loss. A server terminal
receipt is persisted before deleting the capability. Capability expiry, account
security changes, external revocation and source-authority loss prevent a new
success. Neither retirement alone nor a lost response proves cleanup succeeded.

After cancellation is active, a non-cancellation device command event receives
`409 { "error": "desktop_agent_cancellation_requested" }`. The cancel request
itself returns `200`; the only accepted terminal is `interrupted` /
`cancellation_requested`, with no success result.
Cancellation does not promise rollback of effects already performed. Before
Disconnect retirement is admitted, cancellation uses the normal device-bearer
terminal route within its ordinary lease, not the recovery-capability deadline.
The desktop retains the exact terminal witness through response loss and clears
its cleanup freeze only after acceptance. If Disconnect retirement was already
admitted, an exact retirement retry still
confirms that fact so cleanup can finish before the cancelled terminal.
Disconnect also distinguishes
`desktop_agent_disconnect_capability_expired` and
`desktop_agent_disconnect_authorization_lost`; a generic conflict is not a
cancellation signal.

`desktop_view` accepts the strict payload
`{ "section"?: "pairs"|"reviews", "after"?: opaque_cursor, "limit"?: 1..50 }`;
the default is the `pairs` section with a limit of 25. Pair cursors are a
stable `pair_id`; review cursors are the bounded opaque
`pair_id/review_id` pair. `discover_roots` accepts the equally strict
`{ "after"?: sync_root_id, "limit"?: 1..50 }` payload, also defaulting to 25.
Both successful results retain their existing summary counts and return a
non-null page that echoes the submitted cursor and limit, plus `next_after`.
The desktop-view page is `{ "section", "after", "limit", "rows" }`: pair rows
contain `pair_id`, workspace and optional remote-root ids/names, `selected`, a
bounded status, and `pending_review_count`; review rows contain `review_id`,
`pair_id`, an item label, a typed reason, and typed actions. The root page is
`{ "after", "limit", "rows" }`; each row has workspace, sync-root, optional
remote-root ids, workspace/root/owner labels, role, and selection status.
Root `after` and `next_after` are opaque actor-bound server cursors. A page can
be empty with an advancing cursor when canonical or revoked candidates are
skipped; clients follow `next_after` until it is null. The requested limit is
1–50. Root rows are unique within a page and retain the server's private-first
order. Labels are bounded
authorized UI data, never local paths, credentials, raw logs, or raw errors;
the complete result is capped at 64 KiB. Historical stored count-only results
deserialize as `page: null` for history compatibility, but are never accepted
as a new actionable terminal readback.

`start_pair` accepts `{ "workspace_id" }`. It refreshes an already configured
workspace under the existing local base. A new workspace or first root returns
`requires_local_gesture`; the native picker must select an exact root ID before
it can be added. The command does not auto-admit newly shared roots.
Success is `roots_refreshed` with `{ "workspace_id", "added_root_count",
"existing_root_count" }`, counting only usable configured roots in the
requested workspace; at least one count must be positive. Initial local base
selection remains `requires_local_gesture`. Agents can page `discover_roots`
and `desktop_view` to inspect authorized opaque IDs; adding a new location
remains a native desktop action.

Ordinary acknowledgement and progress renew a lease for 45 seconds.
`relaunch_pending` is accepted only for `install_desktop_update` after that
same command has durably reported `updating`; it receives a 300-second restart
grace capped by the command deadline. Submitters that expect a restart may set
the command deadline up to 600 seconds. Restart intent is not installation
success: completion still requires the bounded `update_install` terminal result
for the exact candidate and installed version, with the normal authority and
lease checks and exact retry matching.

## Workspace and file API

Workspace names contain 1–255 UTF-8 bytes after surrounding whitespace is trimmed.
The same limit applies when a workspace is created or renamed.

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/workspaces` | Create an ordinary Drive workspace. Requires current administrator or operator authority; an ordinary user or non-admin delegated credential cannot create one. Body: `name`, `owner_email`, optional compatibility field `storage_mode` (only `open` is accepted). |
| GET | `/workspaces/{workspace_id}/members` | List workspace members. Requires owner/manage permission. Direct membership is bounded to 100 rows per workspace. |
| POST | `/workspaces/{workspace_id}/members` | Add or update `owner`, `editor`, or `viewer`. Requires owner/manage permission. A new direct member is rejected after the 100-row workspace limit; updating an existing member remains available. |
| DELETE | `/workspaces/{workspace_id}/members` | Remove a member by email. Requires owner/manage permission. |
| PATCH | `/workspaces/{workspace_id}` | Rename a workspace and write `workspace.rename`. |
| GET | `/workspaces/{workspace_id}/invitations` | List redacted workspace invitations. Accept tokens are never listed. |
| POST | `/workspaces/{workspace_id}/invitations` | Create an invitation and return its one-time public accept token. Optional `member_expires_in_seconds` bounds the accepted collaborator membership; owners cannot expire and finite access must be at least one hour. Pending invitations are capped at 256 per workspace; creating another invite for the same normalized email rotates the existing pending row instead of accumulating state. Invitation state, receipt, and captured email queue row commit atomically. |
| POST | `/workspaces/{workspace_id}/invitations/{invitation_id}/resend` | Rotate and return a new one-time invitation token. |
| POST | `/workspaces/{workspace_id}/invitations/{invitation_id}/cancel` | Cancel a pending invitation. |
| GET | `/pub/invitations/accept` | Browser invitation page. Invitation links carry the one-time token only in `#token=...`, so it is not sent in the page request, browser referrer, or asset requests. The page requires an existing signed-in Drive account. |
| POST | `/pub/invitations/accept` | Accept an invitation for its addressed account using that account's current local/SSO session or account-wide delegation. Browser cookie requests require `Origin` equal to `SHELLX_DRIVE_PUBLIC_ORIGIN`; a missing Origin is rejected. Manual clients send an explicit bearer credential. Operator, app and folder-agent credentials are rejected; the addressed account and live credential are rechecked with the membership change. JSON body: `{ "token": "<one-time token>" }`. A finite invitation converts its relative access duration into an absolute member `expires_at`; expired direct memberships are excluded from effective access. |
| POST | `/workspaces/{workspace_id}/leave` | Remove the signed actor from a workspace when that does not orphan ownership. |
| POST | `/workspaces/{workspace_id}/transfer-owner` | Transfer owner role to another member. |
| POST | `/workspaces/{workspace_id}/archive` | Archive a workspace. |
| POST | `/workspaces/{workspace_id}/unarchive` | Unarchive a workspace. |
| GET | `/workspaces/{workspace_id}/usage` | Return file quota, active/revision/trash/remaining bytes, plus the separate bounded metadata-and-collaboration allocation and its file-metadata, metadata-search, comment/reply, notification, and queued-email categories. Requires read permission. |
| GET | `/workspaces/{workspace_id}/file-statistics` | Return workspace-wide successful preview and download totals plus at most 200 tracked live files ordered by activity. Requires manage permission. Thumbnail, cover, and metadata requests do not count; reusable preview ranges and duplicate archive entries count once. WebDAV GET, mobile offline content, office package reads, rclone export, and Drive-compatible `alt=media` count as downloads. Counter failures are best-effort and never block content delivery. |
| GET | `/workspaces/{workspace_id}/policy` | Return workspace quota, sharing defaults, and retention settings. Requires read permission. |
| PATCH | `/workspaces/{workspace_id}/policy` | Update quota, sharing defaults, and retention settings. Requires manage permission and writes `workspace.policy.update`. |
| GET | `/groups` | List groups, group members, and workspace group grants visible to an authenticated operator. |
| POST | `/groups` | Create a group. Writes `group.create`. |
| POST | `/groups/{group_id}/members` | Add a user email to a group. Writes `group.member.upsert`. |
| DELETE | `/groups/{group_id}/members` | Remove a user email from a group. Writes `group.member.remove`. |
| POST | `/workspaces/{workspace_id}/group-grants` | Grant a group `viewer` or `editor` access to a workspace. Requires workspace manage permission and writes `workspace.group.grant`. |
| DELETE | `/workspaces/{workspace_id}/group-grants/{group_id}` | Revoke a workspace group grant. Requires workspace manage permission and writes `workspace.group.revoke`. |

Workspace member and invitation `email` fields are normalized account/login
identifiers. Invitation acceptance requires the exact addressed signed-in Drive
account. Invitation create and resend return a one-time link for the caller to
deliver through a trusted out-of-band channel. Verify recipient identity and
confirm delivery through that channel; Drive checks the normalized account
email. The captured queue row records capture processing.

## Human item sharing

Human item grants are separate from workspace membership, guest links, and
folder-scoped AI access. They grant account, group, or policy-gated `everyone`
principals Viewer or Editor access to one item subtree. An item Editor may edit
content but cannot delegate access: only a whole-workspace owner or
administrator may create, change, or revoke a human item grant. Item grants do
not provide workspace membership or WebDAV access.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/admin/human-sharing-policy` | Return the administrator-controlled `everyone_grants_enabled` policy. |
| PATCH | `/admin/human-sharing-policy` | Administrator only. Set `{ "everyone_grants_enabled": boolean }`, returning policy and receipt. Existing `everyone` grants remain visible and revocable when the policy is disabled. |
| GET | `/share-principals?file_id=&kind=account\|group&query=&limit=` | Whole-workspace owner/admin on `file_id` only. Search enabled account or group principals; query is required and `limit` is 1–50. |
| GET | `/files/{file_id}/human-grants` | Whole-workspace owner/admin only. Return grants, current item action capabilities, and the `everyone` policy state. |
| POST | `/files/{file_id}/human-grants` | Whole-workspace owner/admin only. Body: `principal_kind` (`account`, `group`, or `everyone`), `principal_ref` (required except `everyone`), `role` (`viewer` or `editor`), and optional future RFC 3339 `expires_at`. Returns the active grant and receipt. |
| GET | `/files/{file_id}/action-capabilities` | Read permission. Return UI-safe per-item sharing/guest/AI management flags and the current `access_generation`. |
| PATCH | `/human-grants/{grant_id}` | Whole-workspace owner/admin only. Change optional `role` and/or `expires_at`; use `expires_at:null` to clear expiry. Returns the grant and receipt. |
| DELETE | `/human-grants/{grant_id}` | Whole-workspace owner/admin only. Revoke the grant and return `204`. |
| GET | `/sharing/shared-with-me?limit=&cursor=` | List the caller's current shared roots, including the root's access generation. Returns `roots` and an opaque `next_cursor` (or `null`). |
| GET | `/sharing/shared-by-me?limit=&cursor=` | List the caller's managed shared roots and their active human-grant/guest-link summaries. Returns `roots` and an opaque `next_cursor` (or `null`). |
| GET | `/files` | List files visible to the actor. Each file carries `size_bytes` (current stored content byte length; `null` for folders) and `folder_size_bytes` (recursive current-body bytes; `null` for files). This legacy unpaged list returns HTTP 413 if the combined visible workspace files and item-shared roots exceed 10,000; use `GET /browse/files` for paged browsing. |
| POST | `/files` | Create a file or folder. Editors and owners can write. Body: `workspace_id`, `name`, `kind` (`file`/`folder`), optional `parent_id`, `content`, and optional `path` — a relative path (e.g. `a/b/c.txt`) whose intermediate folders are created idempotently under the target parent, used for folder uploads. Each `path` segment is validated (no `..`, absolute, empty, separator, or control characters); traversal is rejected. |
| PATCH | `/files/{file_id}` | Rename, move, relabel, or update custom metadata. Body: optional `name`, `parent_id` (move under another folder), `move_to_root` (`true` moves the item to the workspace root), `labels`, `custom_metadata`, optimistic `base_revision`, and `collision_policy` (`keep_both`, `cancel`, or `replace`; omitted is `keep_both`). Metadata is stored and indexed atomically: at most 64 unique normalized labels (64 UTF-8 bytes each, 8 KiB serialized total) and a JSON object of at most 64 KiB, depth 16, 4,096 nodes, 2,048 keys, 512 arrays, and 4,096 scalars. When supplied, a stale `base_revision` returns `409` before mutation. On an active-sibling collision, `keep_both` atomically derives a final name; `cancel` returns `409` without mutation; file-on-file `replace` additionally requires the exact `replace_target_id` and `replace_target_revision` plus source `base_revision`, retains the destination item's ID/history, and trashes the source. The returned `file` is authoritative. Use `move_to_root: true` rather than `parent_id: null` to move to the root — JSON/serde cannot distinguish an explicit `null` from an absent `parent_id`, so a bare `null` is treated as "no move". Any accepted change advances the sync revision. |
| DELETE | `/files/{file_id}` | **New in this release.** Permanently delete a file or folder (recursive for folders) and ref-count-clean the underlying blob. Requires write permission. Returns `204`. This is irreversible, unlike `/trash`. |
| GET | `/files/{file_id}/content` | Serve server-readable file content inline. **New in this release:** sets `Content-Type` by extension, `Content-Disposition: inline`, and `Accept-Ranges: bytes`, and honors a `Range` request header (returns `206 Partial Content`). Requires read permission. |
| GET | `/files/{file_id}/download` | Serve file content as an authenticated, disk-streamed attachment. Agent/API clients may use this route directly. |
| POST | `/files/{file_id}/download` | Authorize a native browser download and return a 120-second, one-use `/downloads/files/{ticket}` capability. The authenticated request carries no file body; the platform download manager receives the disk stream without a JavaScript `Blob`. |
| PUT | `/files/{file_id}/content` | Replace content with optimistic `base_revision`; conflict creates a conflict copy. |
| GET | `/files/{file_id}/preview` | Return generated preview metadata for an open-workspace file. Image previews include thumbnail metadata; unsupported formats return an explicit fallback state. |
| POST | `/files/{file_id}/preview` | Authorize a 120-second inline media capability for an open-workspace file. It supports up to 64 bounded requests so browser video/audio/PDF range fetching works even when authentication normally travels in a bearer header. |
| GET | `/files/{file_id}/thumbnail` | Download the generated image thumbnail for a file preview. Requires read permission and returns 404 when no thumbnail exists. |
| PUT | `/files/{file_id}/cover` | Set a custom cover image for a folder (Google-Drive-style). Body is raw image bytes (PNG/JPEG/GIF/WebP, signature-validated); requires write permission. Returns 400 when the target is not a folder. Surfaced as `has_cover` on the folder. |
| GET | `/files/{file_id}/cover` | Download a folder's custom cover image with its detected content type and `nosniff`. Requires read permission; returns 404 when the folder has no cover. |
| DELETE | `/files/{file_id}/cover` | Remove a folder's custom cover image and reference-count the backing blob. Requires write permission; idempotent. |
| GET | `/files/{file_id}/metadata` | Read labels, custom metadata, and the same file/folder logical-size fields for one item. |
| POST | `/files/{file_id}/copy` | Copy a file or folder within its workspace, preserving content hash and metadata. Omit `parent_id` to retain the source parent, send `parent_id:null` for the workspace root, or send a folder id. A sibling collision in that destination folder atomically returns a derived final name such as `photo (copy).png`, then `photo (copy2).png`; the response `file.name` and `file.parent_id` are authoritative. |
| GET | `/files/{file_id}/revisions` | List stored content/metadata revision rows for a file. |
| POST | `/files/{file_id}/revisions/prune` | Apply the workspace revision-retention policy to one file. Current and pinned revisions are preserved; the response reports deleted rows/bytes and updated storage impact. Requires manage permission. |
| DELETE | `/files/{file_id}/revisions/{revision}` | Delete one historical, unpinned revision and reclaim an unreferenced blob. Current and pinned revisions are rejected. |
| POST | `/files/{file_id}/revisions/{revision}/download` | Authorize a one-use native download capability for the exact historical revision body. |
| POST | `/files/{file_id}/revisions/{revision}/restore` | Restore an older content revision as a new current revision. |
| POST | `/files/{file_id}/revisions/{revision}/pin` | Pin a revision so retention cleanup preserves it. |
| POST | `/files/{file_id}/revisions/{revision}/unpin` | Clear a revision retention pin. |
| POST | `/files/{file_id}/download-zip` | Prepare one folder as the same bounded ZIP64 ticket stream used by bulk download. Returns a 120-second, one-use `download_url`; browser cookie callers are protected by exact-Origin mutation checks. |
| POST | `/files/download-zip` | Authorize a same-folder multi-selection and return a 120-second, one-use `download_url`. Selected folders expand recursively; requires read permission. Body: `{ "file_ids": [...] }`. Open workspaces only. |
| GET | `/downloads/{ticket}` | Redeem a prepared archive exactly once. Streams a bounded ZIP64 response from immutable blobs without buffering the files or complete archive in server or browser memory. A public-share archive rechecks that its source share is still unrevoked and unexpired at redemption. |
| GET | `/downloads/files/{ticket}` | Redeem a prepared single-file download or inline preview capability. Bodies stream from the immutable blob with range support and `no-store`; download capabilities are one-use while preview capabilities allow at most 64 requests before expiry. |
| GET | `/workspaces/{workspace_id}/tree` | Return folder/file tree state for navigation, including `folder_size_bytes`. |
| POST | `/files/bulk` | Bulk trash, restore, star, or unstar files visible to the actor. State actions are strict transitions: every selected item must already be live for trash, trashed for restore, unstarred for star, or starred for unstar. A mixed or already-target-state request returns `400 validation_error` before mutating any row or creating a receipt. |
| POST | `/uploads/preflight` | Advisory batch preflight before session creation. Body: `workspace_id`, optional `parent_id`, and up to 512 `{ name, size, path? }` rows. Returns aggregate quota fit plus duplicate and path-blocker conflicts without creating sessions. For an item-scoped editor without workspace Read access, `current_file_bytes`, `quota_bytes`, and `remaining_bytes` are null; `fits` remains available. The create route rechecks quota and `duplicate_policy`, so clients must not treat preflight as a reservation. |
| POST | `/uploads/resumable` | Start one of two bounded session types. A new-file session supplies `workspace_id`, `name`, **required `total_size`** (0..=2 GiB), optional `parent_id`, validated relative `path`, and optional `duplicate_policy`: omitted/`keep_both` atomically derives a final name, `cancel` rejects a collision (legacy `skip` is accepted), and `replace` is valid only with explicit `target_file_id` plus `base_revision`. An existing-file replacement supplies that exact target/revision pair and may omit `duplicate_policy` for compatibility or use `replace`; it rejects `keep_both`/`cancel`. Drive derives workspace, parent, and name from the live target row. Admission enforces actor/session limits and reserves quota capacity before body transfer. |
| GET | `/uploads/resumable/{upload_id}` | Inspect resumable upload state, including `received_bytes`, completion state, created/updated `file_id`, and persisted replacement target/base intent. Receipt linkage remains internal. |
| PUT | `/uploads/resumable/{upload_id}/content?offset=&finish=` | Preferred browser transport. Append one raw `application/octet-stream` chunk, maximum 8 MiB. Wrong/stale offsets and concurrent writes return HTTP 409; the client reconciles with `GET` and retries from acknowledged `received_bytes`. `finish=true` publishes only at the exact declared size. Replacement completion atomically advances the target revision and completes the session. If `base_revision` is stale, Drive leaves the target unchanged, stores the uploaded bytes as a conflict file, and returns that file plus `conflict` metadata. Retrying the terminal request returns the original file, receipt, and conflict metadata without another mutation. |
| PUT | `/uploads/resumable/{upload_id}` | Compatibility JSON transport with the same create/replacement completion semantics. Append a maximum-8-MiB decoded chunk using `offset`, either text `content` or binary-safe `content_base64`, and optional `finish`. Existing clients remain supported; browser uploads use the raw route to avoid Base64 expansion. |
| GET | `/workspaces/{workspace_id}/uploads` | List the caller's resumable upload sessions in the workspace; administrators can list all sessions. |
| POST | `/uploads/resumable/{upload_id}/cancel` | Cancel an incomplete upload session under the same per-session write lock and remove its partial body. |
| POST | `/admin/uploads/cleanup` | Admin cleanup for old incomplete/canceled upload sessions. |
| POST | `/files/{file_id}/trash` | Mark a live file as trashed. An already-trashed target returns `400 validation_error` without a revision, timestamp, or receipt change. |
| POST | `/files/{file_id}/restore` | Restore a trashed file. An already-live target returns `400 validation_error` without a revision, timestamp, or receipt change. |
| POST | `/workspaces/{workspace_id}/trash/empty` | **New in this release.** Permanently delete only trashed subtrees whose full contents passed the workspace retention cutoff; recent items remain. Requires write permission. Returns `{"deleted": N, "retained": N, "retained_items": [{"file_id": "...", "name": "..."}]}`. |
| POST | `/files/{file_id}/star` | Mark an unstarred file starred. An already-starred target returns `400 validation_error` without a timestamp or receipt change. |
| POST | `/files/{file_id}/unstar` | Clear the starred marker. An already-unstarred target returns `400 validation_error` without a timestamp or receipt change. |
| GET | `/search?q=` | Ranked full-text search over visible indexed files. Returns the first 100 matches in backward-compatible `files` plus rich `results` with rank, snippet, and matched fields. `has_more` indicates additional matches outside this bounded first page. |
| GET | `/browse/files?scope=&limit=&cursor=` | Account-wide, keyset-paginated browser view across active workspaces already visible to the actor. `scope` is `files`, `mine`, `shared`, or `recent`; `limit` is 1..100 and `cursor` is an opaque scope-and-filter-bound continuation. Files/Mine/Shared return top-level workspace items only, preserving folder navigation instead of duplicating descendants in a flat list; they are folders-first with stable binary name/workspace/ID ordering. Recent is an intentional cross-folder activity list ordered newest-first. Optional filters are `type_filter` (folders, docs, sheets, pdfs, images, videos, audio, archives), `owner_scope` (owned, shared), `modified_since` (RFC3339), `workspace_id` (UUID), `folder_id` (UUID, requires `workspace_id`, includes descendants), and `state_filter` (shared active guest link, starred, offline). Filters apply before paging; repeat them unchanged with each cursor. Rows add `workspace_name`, the caller's `access_role`, and `owned_by_actor` without exposing owner email or membership inventory. |
| GET | `/recent` | Recent visible files. |
| GET | `/shared` | Actor-specific files from workspaces where the actor is a non-owner member. |
| GET | `/starred` | Starred visible files. |
| GET | `/activity` | Recent activity, **scoped in this release to the actor's visible workspaces** (previously system-wide). |
| GET | `/notifications` | Actor-scoped notification inbox with `unread_count` and recent notification rows. |
| GET | `/notifications?unread_only=true` | Actor-scoped unread notifications only. |
| POST | `/notifications/{notification_id}/read` | Mark one notification read and write `notification.read`. |
| POST | `/notifications/read-all` | Mark all actor notifications read and write `notification.read_all`. |

Workspace file bodies can be indexed, previewed, exported, and downloaded.
File names, labels, custom metadata, and extracted text participate in ranked
search. Ordinary file bodies are server-readable. For privacy from the server
operator, encrypt locally before upload, keep the keys with the client, and
store the resulting ciphertext bytes.

Notifications are recipient-email scoped. They are generated for invitations,
share notices, comments/replies, public drop uploads, and sync conflicts.
Notification read/unread state is user-facing inbox state; receipts and activity
remain the audit log.

ZIP delivery allows 30 seconds plus the planned file bytes and conservative ZIP64
metadata overhead at 128 KiB/s, capped at five hours. Client progress does not
restart this total deadline; an undrained producer queue also stops after 30
seconds. The 50 GiB archive limit remains supported, but an archive near that
limit must sustain roughly 2.85 MiB/s to finish within five hours. Expiry or
disconnect stops delivery, and producer capacity returns only after the blocking
ZIP worker exits.

## Sync API

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/sync/workspaces` | List actor-visible workspaces for sync clients. Actor requests include each workspace `role`. |
| GET | `/sync/health` | Summarize workspace/file sync health for the actor. |
| GET | `/sync/workspaces/{workspace_id}/manifest` | Full active-file desktop sync manifest for one workspace. Trashed rows are excluded and the response fails with `413` above 10,000 active items rather than allocating an unbounded server/client snapshot. |
| GET | `/sync/mobile/workspaces` | Mobile workspace list with offline counts. |
| GET | `/sync/mobile/workspaces/{workspace_id}/manifest` | Metadata-only mobile manifest. It omits content hashes and file bodies. |
| GET | `/sync/mobile/offline` | List files the actor marked for mobile download. |
| POST | `/sync/mobile/offline` | Add or remove a mobile-download mark. |
| GET | `/sync/mobile/files/{file_id}/content` | Disk-stream a marked file so a mobile client can download it while online; supports HTTP `Range`. |
| GET | `/sync/files/{file_id}/chunks` | Return the current fixed-size chunk manifest for a file. Query `chunk_size` defaults to 1 MiB and may be lowered for tests, but a request is rejected when it would produce more than 16,384 descriptors; use at least `ceil(file_size / 16,384)` bytes. The current in-memory manifest algorithm rejects files above 32 MiB. |
| PUT | `/sync/files/{file_id}/delta` | Reconstruct a new revision from ordered `copy` and `data` operations, preserving stale `base_revision` conflict behavior. The current in-memory delta base and reconstruction cap is 32 MiB; use resumable full-content upload for larger files. |
| GET | `/sync/changes` | Cursor-based change feed across visible workspaces. |
| GET | `/sync/workspaces/{workspace_id}/changes` | Cursor-based change feed for one workspace. |
| GET | `/sync/conflicts` | List stale-write conflict copies visible to the actor. |
| GET | `/sync/roots` | Compatibility full list of the caller's sync roots, with a bounded publication limit of 2,000 IDs. Scalable discovery should use `/sync/roots/page`. Each `SyncRoot` includes its opaque `id`, current role, action capabilities, and `access_generation`. |
| GET | `/sync/roots/page?cursor=...&limit=50` | Page through current effective sync roots. Omit `cursor` for the first page; `limit` defaults to 50 and accepts 1–50. Returns `{ roots, next_cursor }` with at most the requested number of roots and less than 1 MiB of JSON; a page may be empty while `next_cursor` advances. Private workspaces, owned workspaces, shared workspaces, then canonical item roots appear in deterministic ID order. The opaque cursor is bound to the current actor, credential, and workspace scope. Every page uses current authority; concurrent additions before the cursor require a fresh discovery to appear. Revalidate selected roots before pairing. |
| POST | `/sync/roots/revalidate` | Revalidate at most 100 distinct, bounded configured `root_ids` under one current actor credential and storage transaction. Returns `{ roots, revoked_ids, replacements }`, partitioning exactly the requested IDs. Each replacement is `{ requested_id, root }` and identifies an active canonical grant for the same file as the requested grant. Inaccessible or removed requested IDs appear only in `revoked_ids`; unrelated roots are never listed. |
| GET | `/sync/roots/{root_id}/manifest?access_generation=N` | Return `SyncRootManifestResponse { root, mode, next_cursor, files }` for one current root. `N` is required and must be a canonical positive unsigned integer (no leading zero); use the `access_generation` returned by discovery or configured-root revalidation. `mode` is `scoped_desktop_sync` for an item-grant root or `full_desktop_sync` otherwise. |

Workspace and root manifests capture `next_cursor` before selecting files.
Resume the change feed from that cursor so concurrent mutations remain visible,
including changes absent from the manifest. A change already reflected in the
manifest may replay; clients should apply changes idempotently or fetch a fresh
manifest.

Root discovery is an authenticated ordinary-actor view: it includes only roots
currently resolved for that actor, never public share or Drop grants. The
compatibility full list returns `413 sync_root_discovery_overflow` when its
bounded publication limit is exceeded. Desktop uses paged discovery for its
location picker and revalidates configured roots separately; it admits only
explicitly selected locations, up to the desktop's 100-location limit. The
root `access_generation` is an authority epoch, distinct from the page cursor.
A stale manifest generation returns `412 precondition_failed`; a revoked or
expired root no longer resolves. Revalidate the exact root before retrying
with its newly returned generation, then fetch a fresh manifest for that authority.
Configured-root replacement keeps only the exact file subject: a revoked child
grant is reported in `revoked_ids` even when a broader ancestor grant remains
active. The ancestor can be selected separately through paged discovery.

Desktop sync is full sync for visible content. Mobile sync is metadata first
and only downloads explicitly marked files while online. The PWA service worker
caches only the app shell; mobile manifest snapshots are metadata-only file
lists stored in browser storage by actor and workspace. The web build does not
store marked file bodies or put authenticated API responses in the shared
service-worker cache.

Delta sync uses fixed-size SHA-256 chunk manifests. Clients call
`GET /sync/files/{file_id}/chunks`, then send `PUT /sync/files/{file_id}/delta`
with ordered `copy` operations for unchanged chunks and `data` or
`content_base64` operations for changed bytes. The server reconstructs a full
blob and commits it through the same optimistic revision path as
`PUT /files/{file_id}/content`; stale bases return the same `stale_revision`
conflict shape and create a normal conflict copy. Debug routes expose only
delta sync stats such as uploaded bytes, reused chunks, reconstructed bytes,
and content hashes, never raw chunk bytes or patch bodies.

Destructive batch operations that can remove many file-level history rows
(empty trash and retention application) publish one `workspace.rescan` change
per affected workspace in the same database transaction as the deletion. A
sync client that sees this operation must discard incremental assumptions for
that workspace and fetch a fresh manifest; the marker cannot commit without the
deletion, or vice versa.

The bundled `shellx-drive-sync sync-once` binary is a headless protocol
reference, not an installed Drive desktop client. Its `--actor <email>` switch
is only for an operator-controlled actor-scoped run; a normal local/SSO or
delegated user run omits it. It also accepts repeated `--workspace <id>` flags
for selected workspace sync and repeated `--safe-space <id>` flags to write local `safe-space.json`
metadata with `local_agent_visible=false`. `--profile <name>` creates an
independent server/account cache below `<cache-dir>/profiles/<name>`;
`--adopt-existing-cache` is a one-time explicit migration for a verified
non-empty cache that predates profile binding. Every pass resolves `/auth/me`
and refuses a marker whose canonical server URL or verified actor differs. It
snapshots `/sync/conflicts` and its authorized product receipts for conflict and
receipt correlation without changing server route semantics. `/debug/receipts`
is an optional administrator diagnostic and is never required for normal sync.

Private self-hosted HTTPS is supported without operating-system certificate
installation: `--ca-file <pem>` adds the Drive proxy's private CA only to the
sync client's TLS roots. Certificate and hostname verification remain enabled,
and the client binds the CA digest into its cache profile before sending a
credential. Publicly trusted Drive origins need no CA option.

On Unix, the effective cache root and every managed directory must be owned by
the current user with owner-only `0700` access bits. An inherited setgid flag is
allowed because it grants no group access; other special bits are rejected.
Existing directories that do not meet that policy are rejected without
silently changing their permissions. Upload input leaves must be regular files
owned by the current user, have exactly one hard link, and grant no group/other
write access; ordinary owner-created `0644` files remain valid. These checks
are made on already-open, no-follow handles before bytes can be authenticated
or uploaded.

Both bundled sync clients stream remote bodies into private staging files,
enforce the manifest byte length throughout the transfer, verify the completed
content hash before publication, and reject a single body above the server's
2 GiB resumable-file ceiling. A missing, negative, short, long, or
hash-mismatched body is deleted from staging and never published as the local
file. macOS and Linux check the staging filesystem before and during each
download for the remaining body, any planned local replacement recovery copy,
and a 512 MiB free-space reserve. An incomplete failed download removes only
its owned partial batch; verified bodies that need replacement review remain
retained for recovery.

The full two-way desktop sync contract (auth, every upload/update/delta route
with request/response shapes, the content-hash algorithm, revision/conflict
semantics, and size thresholds) is documented for external client implementers
in the desktop sync [protocol contract](DESKTOP_SYNC_CONTRACT.md). The bundled
`shellx-drive-sync` binary and `SyncClient` are headless reference
implementations of that contract, separate from the installed applications
under `desktop/`.

## Sharing And Drops

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/shares` | Create a read-only guest share for one file **or folder**. In addition to password/expiry and optional `notify_email`, `allow_download` controls save actions, `recipient_note` is shown to the guest, and optional `max_uses` limits fresh guest sessions. `notify_email` records legacy capture-outbox metadata; deliver the share link through a trusted channel and confirm delivery there. Upload access is a separate Drop contract; editable access is a workspace collaborator role. |
| GET | `/files/{file_id}/shares` | List managed shares for one file. |
| GET | `/workspaces/{workspace_id}/shares` | List managed shares in one workspace. |
| PATCH | `/shares/{share_id}` | Update share password, expiry, download permission, recipient note, or visit limit. Use `clear_recipient_note`/`clear_max_uses` to remove optional values. The link settings UI persists these exact fields rather than maintaining a second settings source. |
| POST | `/shares/{share_id}/revoke` | Revoke a share. |
| GET | `/pub/shares/{share_id}` | Dual-use share view: HTML guest page for a browser (`Accept: text/html`); machine-readable JSON metadata for an agent (`Accept: application/json` or `?format=json`). Before a protected link is authenticated, both surfaces disclose only that a password is required; target metadata follows successful verification. Finite-use metadata claims a visit and returns a client-bound `access_token`. Unknown, revoked, expired, and exhausted browser links all render the same generic `404` HTML page; JSON/API callers receive generic `404` JSON. |
| GET | `/pub/shares/{share_id}/content` | Public read of raw share content. File share → the file's bytes; folder share → the file at `?path=<relpath>` inside the subtree. Finite-use links require metadata `access_token` in `X-Share-Access-Token` plus its bound client cookie or `X-ShellX-Public-Client-Secret`; unlimited links accept direct `X-Share-Password`. URL query parameters are never a credential channel. |
| GET | `/pub/shares/{share_id}/thumbnail` | Capability-scoped PNG thumbnail. File share → shared file; folder share → descendant at `?path=<relpath>`. Uses the same finite-use token/binding or unlimited password proof as content; `404` when no thumbnail exists. |
| POST | `/pub/shares/{share_id}/download` | Prepare a short-lived attachment ticket for the shared file or a folder descendant. JSON body: `{ "path": "docs/readme.txt" }` (omit `path` for a file share). The request uses the normal share password/grant; the returned `/downloads/files/{ticket}` URL contains no password and streams through the browser download manager. The ticket is bound to the requesting client. Redemption rechecks that binding, expiry, revocation, password-policy generation, subtree membership, trash state, and download policy. |
| POST | `/pub/shares/{share_id}/preview` | Prepare a short-lived bounded-reuse inline ticket for an image or video, using the same optional `path` body. The native media URL supports byte ranges without materializing the file as a JavaScript `Blob`; redemption repeats the client binding, public-share state, and scope checks. |
| POST | `/pub/shares/{share_id}/download-zip` | Prepare one recursive ZIP from selected direct children of a folder currently visible in the guest browser. Body: `{ "base_path": "docs", "paths": ["docs/a.txt", "docs/photos"] }`; uses the same finite-use token/binding or unlimited password proof and subtree checks as content, and returns a one-use `download_url`. Redemption rechecks share revocation and expiry. Planner, pending-ticket, pending-entry, and producer admission are workspace-partitioned so many shares from one workspace cannot occupy the global archive pool. |
| POST | `/pub/shares/{share_id}/content` | Backward-compatible public download (JSON body `{ "password": ..., "path"?: ... }`), used by the HTML guest page; disk-streamed and range-capable. |
| POST | `/drops` | Create a password-protected guest upload drop for a workspace. `expires_in_seconds` must be positive, within the workspace Drop TTL limit, and yield a supported RFC 3339 expiry year (at most 9999). |
| GET | `/workspaces/{workspace_id}/drops` | List managed upload drops for a workspace. Authenticated Write response includes `inbox_file_id` for each Drop; it is `null` until the first admitted upload and can point to a moved or trashed folder until the next admission repairs it. The owner UI offers **Open inbox** only for a live root folder. |
| PATCH | `/drops/{drop_id}` | Update drop name, password, expiry, or revoked state. A supplied `expires_in_seconds` follows the same positive TTL and supported-date limits as creation. |
| POST | `/drops/{drop_id}/revoke` | Revoke an upload drop. |
| GET | `/pub/drops/{drop_id}` | Browser guest upload page for a live drop. |
| POST | `/pub/drops/{drop_id}/preflight` | Exchange the current Drop password (UTF-8 encoded as standard Base64 in `X-ShellX-Drop-Password-B64`) for a one-hour HMAC-signed `access_token`. The token is bound to the requesting client's separate proof-of-possession secret and the Drop's live authorization fingerprint, carries no Drop metadata, and creates no upload session. Browser clients receive the secret only as an HttpOnly cookie; native clients use the contract below. Keep the token in memory and send it over HTTPS in the documented request header, leaving URLs and logs free of credentials. Revocation, expiry, password rotation, or server-secret rotation invalidates it. |
| POST | `/pub/drops/{drop_id}/uploads` | Start a write-only Drop upload session. JSON carries bounded metadata only: `{ name, total_size, path?, content_type? }`. Browser clients send the preflight grant in `X-ShellX-Drop-Access-Token`; password-header fallback remains for API compatibility and is subject to the success-independent password-work budget. Admission transactionally materializes or repairs the Drop inbox, charges its folder against workspace quota, reserves declared bytes, checks file node headroom, and applies finite per-client, per-Drop, per-workspace, and server-wide public-upload budgets even when general workspace quota is unset. Rejected admission rolls back a newly created inbox. |
| PUT | `/pub/drops/{drop_id}/uploads/{session_id}?offset=&finish=` | Append one raw `application/octet-stream` chunk (maximum 8 MiB). The acknowledged `received_bytes` is the resumable offset; `finish=true` publishes only when it equals `total_size`. |
| POST | `/pub/drops/{drop_id}/uploads/{session_id}/cancel` | Cancel one active write-only session and remove its partial body. Requires the Drop password. |

Public share and drop routes do not use the server bearer token. They require
the per-link password and reject expired or revoked links. Drop authentication,
workspace policy/quota checks, client-partitioned throttling, and session state
are rechecked for every metadata, chunk, and cancel request. Drop sessions have
no GET/browse/content route. Each Drop writes into its own owner-visible root
inbox folder, including optional relative upload paths. A missing or moved
inbox is replaced on the next admitted upload. Duplicate names use the
explicit `keep_both` policy; an existing file is never overwritten or revised
by a guest Drop. Public completion responses omit the resolved file name so
guests cannot infer collisions with earlier uploads.

Share and drop creation also obey the workspace policy returned by
`GET /workspaces/{workspace_id}/policy`: `public_links_enabled` can block new
guest links, password-required settings reject empty link passwords, and max TTL
settings reject overly long share/drop expiry requests. Permanent share links
also require the explicit `allow_never_expire: true` workspace policy. Policy
rejections are validation errors and do not write `share.create` or
`drop.create` receipts. Every newly set non-empty share or Drop password must be
at least 12 characters. Existing legacy links keep accepting their stored
password until an owner rotates it; rotation must use the current minimum.

**`POST /shares` request contract**

```json
{
  "file_id": "<id>",
  "password": "",
  "expires_in_seconds": 0,
  "notify_email": null,
  "allow_download": true,
  "recipient_note": "Optional message for guests",
  "max_uses": 1
}
```

- `password` — the link password. An empty string means **no password**. The
  default workspace policy sets `link_password_required: false`, so a passwordless
  link is created (Google-Drive-style one-click "Create link"). A workspace admin
  can turn the requirement ON (`PATCH /workspaces/{id}/policy` with
  `link_password_required: true`); an empty password is then rejected with
  `400 "workspace policy: share password is required"`, and the caller must send a
  non-empty password of at least 12 characters.
- `expires_in_seconds` — a positive value expires the link at
  `created_at + seconds` and may not exceed `max_link_ttl_seconds`. `<= 0`
  creates a **permanent link** (`expires_at` stored as `NULL`, serialized as
  JSON `null`) only when the workspace owner has set
  `allow_never_expire: true`; fresh and migrated workspaces default to false.
  Otherwise the server returns
  `400 "workspace policy: permanent share links are disabled"`.
- `allow_download` — defaults to `true`. When false, the guest may preview safe
  inline types in the Drive UI, but download buttons, `?download=true`, archive
  preparation, legacy attachment reads, and non-previewable raw types are
  denied. This is a best-effort UI policy: a browser necessarily receives the
  bytes it renders, so it is not DRM.
- `recipient_note` — optional, bounded owner text shown on the guest page.
- `max_uses` — optional integer from 1 to 1,000,000. Each fresh successful
  metadata visit consumes one use and receives an opaque, short-lived access
  grant for that browser session. Existing grants remain usable, while another
  fresh visit after exhaustion returns `404` without leaking share metadata.

`PATCH /shares/{id}` follows the same policy: sending `expires_in_seconds: 0`
flips an existing link to never-expire only when permanent links are allowed; a
positive value re-dates it; omitting the field leaves the current expiry
unchanged. `clear_recipient_note: true` and `clear_max_uses: true` remove those
limits explicitly. Clearing a visit limit makes future fresh visits unlimited;
raw access-grant values and hashes are never returned by management/debug APIs.

### Dual-use share links (human + agent)

One share link is created (the same `POST /shares` flow) and works for BOTH a
human (browser → HTML guest page) and a CLI agent (curl/API → JSON + raw bytes).
The public routes content-negotiate browser HTML or agent JSON from the same
capability id. All share access is **read-only** and strictly scoped to the
shared file or folder subtree.

`POST /shares` targets a file or a folder via `file_id` (folders are file-tree
nodes too). The persisted share records its `kind` (`"file"` or `"folder"`).
Creating a share requires the creator's write permission on the workspace (which
implies read on the target).

`GET /pub/shares/{id}` with `Accept: application/json` (or `?format=json`) returns:

```json
{
  "kind": "file" | "folder",
  "name": "<file or folder name>",
  "size_bytes": 12 | null,
  "folder_size_bytes": 34 | null,
  "updated_at": "<rfc3339>",
  "permission": "read",
  "allow_download": true,
  "recipient_note": "Optional message for guests" | null,
  "max_uses": 1 | null,
  "access_count": 1,
  "uses_remaining": 0 | null,
  "access_token": "<opaque session grant>", // one-hour client-bound browser/read grant, bounded by link expiry
  "expires_at": "<rfc3339>" | null,   // null = never expires (permanent link)
  "requires_password": true | false,
  "entries": [                       // folder shares only
    { "path": "docs/readme.txt", "name": "readme.txt", "kind": "file",   "size_bytes": 12,   "folder_size_bytes": null, "updated_at": "<rfc3339>" },
    { "path": "docs",            "name": "docs",        "kind": "folder", "size_bytes": null, "folder_size_bytes": 12,   "updated_at": "<rfc3339>" }
  ]
}
```

`entries` lists the folder subtree with paths **relative to the shared folder
root** (the folder's own name is not included), ready to pass to the content
route. For a password-protected folder, `entries` is omitted until the correct
password is supplied (the folder analogue of "content needs the password"); the
caller still learns `requires_password: true`.

Share access grants are bound to the requesting client proof and cannot be
replayed from another client on the same network. Finite-use links claim one
visit during JSON metadata access and return `access_token`; subsequent reads
require that token and the bound client proof, even for passwordless links.
Unlimited links accept a direct password read. Password rotation, revocation,
grant expiry, server-secret rotation, or a changed client binding requires a
fresh metadata exchange for a token-bound read.

### Public client proof contract

Browser Share/Drop exchanges set a random 32-byte secret in an HttpOnly,
`SameSite=Strict` cookie. The browser automatically sends it on later `/pub`
requests and prepared `/downloads` navigation; JavaScript never reads it.
Native or agent clients generate their own 32 random bytes, encode them as 64
hexadecimal characters, and send the same value in
`X-ShellX-Public-Client-Secret` on the password exchange and every later request
that presents the returned grant, upload-session id, or prepared download URL.
This client secret is separate from the capability token. Keep it in temporary
private client storage and send it only in the documented cookie or header.
Keep URLs, logs, and exported configuration limited to non-secret metadata.
IP-derived fingerprints remain only
for throttling and security audit partitioning, so network changes do not
silently turn a copied token into valid proof.

`folder_size_bytes` is the recursive sum of current, non-trashed descendant
file bodies. It deliberately excludes revision history, backups, thumbnails,
covers, and storage overhead, so it is a browsing value rather than quota or
billing usage. The value is derived in one recursive SQL query and remains
available for every workspace.

`GET /pub/shares/{id}/content` returns raw bytes:

- **File share** — the shared file's bytes (`?path=` is ignored).
- **Folder share** — the file at `?path=<relpath>` inside the subtree
  (`?path=` is required). Paths are validated to resolve **inside** the shared
  folder: `..`, absolute paths, and any path escaping the subtree are rejected
  with `404`. A folder share never exposes siblings, parents, other folders, or
  other workspaces.

Bytes are served through the same XSS-safe logic as `/files/{id}/content`
(safe-inline allowlist otherwise forced to `attachment` +
`application/octet-stream`, always `X-Content-Type-Options: nosniff`), and honour
HTTP `Range` requests.

The guest browser streams large protected files through native download/media
tickets. It prepares a ticket with `POST /pub/shares/{id}/download` or
`POST /pub/shares/{id}/preview`, passing `{ "path": "<relative path>" }` for a
folder descendant. The response supplies `download_url` or `content_url` plus
`expires_in_seconds`; both point at `GET /downloads/files/{ticket}`. Download
tickets are one-use, while preview tickets permit a bounded number of range
requests so the browser media pipeline can seek. Every redemption revalidates
the share and selected file, so revocation, expiry, password rotation, policy
changes, moves outside the subtree, and trashing take effect immediately.

The human HTML route uses the same metadata to render a read-only browser with
direct-child folder navigation, breadcrumbs, type/modified/size attributes, and
generated image thumbnails. It supports current-folder selection, recursive ZIP
downloads, and previous/next navigation across previewable media in that folder.
Folder paths remain API identifiers; the visible UI uses normal folder names and
icons.

**Password and visit proof (agent)**: supply the link password via the
`X-Share-Password: <pw>` header for metadata. A finite-use link claims one visit
on the JSON metadata request and returns `access_token`; subsequent content,
thumbnail, ZIP, and ticket requests require `X-Share-Access-Token` plus the
client cookie set on that metadata response (or the corresponding
`X-ShellX-Public-Client-Secret`). An unlimited link accepts the password directly
on content requests. Password query parameters are ignored so browser history,
copied URLs, and proxy access logs do not retain the credential. A wrong or
missing proof returns `401`; repeated password failures share the per-link
lockout (`429`). The legacy
`POST /pub/shares/{id}/content` (JSON body `{ "password" }`, used by the HTML
form) keeps its `403`-on-wrong-password contract and now also accepts an optional
`path` for folder shares.

Revoked and expired shares return `404` with no metadata leak.

Worked example — an agent reading a shared folder end-to-end:

```bash
BASE=https://drive.example.test
ID=<share_id>
SECRET_HELPER=./scripts/curl_secret_config.sh # reviewed source or admitted package
read -r -s -p 'Share password: ' SHARE_PASSWORD; printf '\n' >&2
SHARE_HEADER="$(printf '%s' "$SHARE_PASSWORD" | bash "$SECRET_HELPER" --share-password-stdin)"
unset SHARE_PASSWORD
trap 'rm -f -- "$SHARE_HEADER"' EXIT

# 1. Discover and claim one visit on finite-use links. Keep the bound cookie.
COOKIE_JAR=$(mktemp); chmod 600 "$COOKIE_JAR"
SHARE_META=$(mktemp); chmod 600 "$SHARE_META"
SHARE_ACCESS_HEADER=$(mktemp); chmod 600 "$SHARE_ACCESS_HEADER"
trap 'rm -f -- "$SHARE_HEADER" "$COOKIE_JAR" "$SHARE_META" "$SHARE_ACCESS_HEADER"' EXIT
curl -fsS --header @"$SHARE_HEADER" -H 'Accept: application/json' \
  -c "$COOKIE_JAR" "$BASE/pub/shares/$ID" -o "$SHARE_META"
# For finite-use links, put .access_token from metadata in the private header file:
if [ "$(jq -r '.max_uses // empty' "$SHARE_META")" ]; then
  printf 'X-Share-Access-Token: %s\n' "$(jq -er '.access_token' "$SHARE_META")" > "$SHARE_ACCESS_HEADER"
else
  cp "$SHARE_HEADER" "$SHARE_ACCESS_HEADER"
fi

# 2. Folder → read each file entry by its relative path
curl -s -b "$COOKIE_JAR" --header @"$SHARE_ACCESS_HEADER" \
  "$BASE/pub/shares/$ID/content?path=docs/readme.txt" -o readme.txt

# 2'. File share → just GET the content route (no path)
curl -s -b "$COOKIE_JAR" --header @"$SHARE_ACCESS_HEADER" "$BASE/pub/shares/$ID/content" -o file.bin
```

## Comments

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/files/{file_id}/comments` | List comment threads for a file. |
| POST | `/files/{file_id}/comments` | Add a comment thread. |
| PATCH | `/comments/{comment_id}` | Edit a live comment as its author or an admin and record `edited_at`. |
| DELETE | `/comments/{comment_id}` | Replace a comment body with a durable tombstone as its author or an admin. Replies and audit context remain. |
| POST | `/comments/{comment_id}/replies` | Add a reply to a comment. |
| PATCH | `/comment-replies/{reply_id}` | Edit a live reply as its author or an admin and record `edited_at`. |
| DELETE | `/comment-replies/{reply_id}` | Replace a reply body with a durable tombstone as its author or an admin. |
| POST | `/comments/{comment_id}/resolve` | Resolve a comment thread. |

Comments are workspace-role aware and actor attributed. New comments and
replies plus edit/delete lifecycle changes queue bounded email and in-app
notices for active direct or group-derived workspace members except the actor.
Each live body is limited to 8,000 characters and 32 KiB of UTF-8. Growth of a
source body, its notices, and its receipt commits in one transaction only when
the workspace's separate 64 MiB metadata-and-collaboration allocation admits
the complete change; tombstoning and other shrinking operations remain
available when an older workspace is already over that allocation. Delete
notices are best-effort: a full allocation or delivery queue suppresses only
the optional notice, never the tombstone or its receipt. Returned threads carry
`created_at`, `updated_at`, optional `edited_at`, optional `deleted_at`, and
nested replies so clients can display chronology without losing deleted-thread
context.

Group grants participate in effective workspace permissions for file, sync,
search, shared, and activity routes. Direct user membership wins only when it is
the highest role; otherwise the highest group-derived role is used.

## Folder Templates

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/workspaces/{workspace_id}/folder-templates` | List folder templates for a workspace. |
| POST | `/workspaces/{workspace_id}/folder-templates` | Create a workspace folder template. |
| POST | `/workspaces/{workspace_id}/folder-templates/{template_id}/apply` | Apply a template and create folders/files under a root folder. |
| DELETE | `/workspaces/{workspace_id}/folder-templates/{template_id}` | Delete one template with workspace Write authority. Returns `{ "receipt": Receipt }`; files created by an earlier apply are not affected. |

Template item paths must be relative, non-empty, and cannot contain dot or
dot-dot segments.

## Office Edit Bridge

**v0.1.1 scope:** Online Office editing is post-v0.1.1. The launch provider is
unconfigured and the web affordance is hidden. The preparatory routes below
define the later integration contract; they are not v0.1.1 launch behavior or
acceptance evidence.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/office/status` | Lightweight, file-independent probe reporting whether an online-editing provider is configured (`configured`, `name`). The web UI calls it once after sign-in to decide whether to surface the "Edit online" affordance at all. |
| POST | `/office/files/{file_id}/open` | Return file metadata, `base_revision`, `save_url`, optimistic locking mode, office provider status, and an edit session when a provider is configured. |
| GET | `/office/launch/{handoff}` | Redeem the short-lived one-use browser handoff. Returns a no-store, CSP-restricted form that POSTs the durable session capability and provider routes to the configured editor; the session bearer never enters a launch URL. |
| POST | `/office/files/{file_id}/save` | Save edited content with optimistic revision conflict handling. |
| GET | `/office/sessions/{token}` | Token-scoped provider manifest. Returns file metadata, actor email, provider name, base revision, expiry, lock mode, workspace storage mode, `package_url`, and `commit_url`. Requires no server bearer token. |
| GET | `/office/sessions/{token}/package` | Token-scoped disk-streamed raw package download for the current Drive file bytes; supports HTTP `Range` and requires no server bearer token. |
| PUT | `/office/sessions/{token}/package?base_revision=N` | Token-scoped raw package commit. Body is native package bytes; Drive atomically claims the single-use token before writing, then stores them with the existing optimistic revision writer and returns `FileMutationResponse` or stale-revision `409`. |
| POST | `/office/sessions/{token}/save` | Backward-compatible token-scoped text save for an external editor provider. It atomically claims the same single-use token before writing, preserves optimistic revision conflict handling, and never requires the server bearer token. |

Drive supplies the storage, authorization, revision, and session-launch bridge;
it is not the document editor. A configured provider owns rendering and editing.
Without one, these routes support manual API saves. Configure a provider with
`SHELLX_DRIVE_OFFICE_PROVIDER_NAME`, `SHELLX_DRIVE_OFFICE_PROVIDER_URL`, and
`SHELLX_DRIVE_OFFICE_SESSION_TTL_SECONDS`. Without
`SHELLX_DRIVE_OFFICE_PROVIDER_URL`, ShellX Drive reports no provider and keeps
manual API save controls available; there is no built-in editor dependency.
When a provider is configured, `POST /office/files/{file_id}/open` returns a
same-origin `/office/launch/{handoff}` URL and non-secret session metadata. The
one-use handoff POSTs the durable token-scoped edit session capability and session/package/commit
routes to the configured provider, keeping the bearer out of URL queries, browser history,
provider access-log queries, and the main Drive application DOM. Raw
edit-session tokens, token hashes, server bearer tokens, and package bodies are
not exposed in debug routes.
Office edit sessions are limited to one hour and remain bound to the exact
login session, app token, or operator credential generation that created them.
Revoking or expiring a session/app token or rotating the operator credential
invalidates the corresponding derived Office capability; every class also
requires the named actor to retain current workspace Write authority.
Password change/reset, account disablement, role change, and 2FA reset revoke
that actor's outstanding Office edit sessions together with ordinary sessions
and app tokens.

## Import And Export

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/workspaces/{workspace_id}/export/rclone` | Legacy `shellx-rclone-v1` JSON compatibility bundle for active workspace files. It refuses more than 10,000 active entries or more than 8 MiB aggregate raw file-body bytes before opening bodies. Its `content` field is text-shaped and is not a binary-safe or large-workspace export mechanism. Valid UTF-8 bodies within both limits retain their wire-compatible string form; non-UTF-8, size-mismatched, or over-limit bodies fail closed with HTTP 400 `validation_error`. Use native streamed file APIs for binary or larger exports. |
| POST | `/workspaces/{workspace_id}/import/rclone/preview` | Dry-run an import and report its planned actions without changing the file tree. Import-run tracking is still recorded. |
| POST | `/workspaces/{workspace_id}/import/rclone` | Import an rclone-style bundle into a workspace. |

Import requests accept `folder_collision_policy`: `keep_both` (the default) or
`cancel`. An explicit folder entry represents an incoming folder: if its name
is occupied, Keep both creates a separate folder such as `Docs (copy)` and
routes that incoming folder's descendants into it. Cancel rejects the whole
import with HTTP 409 before publishing changes. Folders are never silently
merged or replaced. This also applies when descendants precede their explicit
folder entry in the bundle.

An implicit path prefix remains destination navigation. A file-only entry for
`Docs/readme.txt` uses the existing `Docs` folder; an existing file at that path
is a protocol update preserving its file ID and revision history. To import a
separate incoming `Docs` tree, include its explicit folder entry. This
distinction leaves existing file-update clients working without treating every
path component as a new folder.

Preview and apply return `actions` with the input `path`, `resolved_path`,
`file_id` and action, including `keep_both` for a renamed incoming folder.
Preview destinations and IDs are provisional: apply recomputes the plan inside
its transaction and returns the authoritative mapping, so a concurrent import
can change the selected suffix. The optional request policy is omitted from
ordinary export bundles.

The legacy v1 bundle embeds readable file bodies as JSON strings. It remains
wire-compatible for existing UTF-8 text clients but is deliberately not
suitable for arbitrary binary content or large exports. A non-UTF-8 body is
rejected with HTTP 400 `validation_error`, never replacement-character
converted. A binary-safe stream requires a versioned snapshot/entry contract
rather than lossy UTF-8 conversion or unbounded Base64 JSON. The 8 MiB cap is
the sum of raw file bytes, checked from metadata before blob reads and repeated
against physical body sizes; JSON escaping can make the legacy response wire
larger than that raw budget. This endpoint is compatibility-only, not a
workspace export path.

## Google Drive API Subset

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/drive/v3/files` | List non-trashed visible files in a Google Drive v3-shaped response. |
| POST | `/drive/v3/files` | Create a text file in a workspace and index its content. |
| GET | `/drive/v3/files/{file_id}` | Read Google Drive-shaped metadata for one file. |
| GET | `/drive/v3/files/{file_id}?alt=media` | Disk-stream file content as media; supports HTTP `Range`. |

The subset is intentionally small and exists to support adapters, tests, and
future compatibility work. It is not a full Google Drive implementation.
`GET /drive/v3/files` is an unpaged compatibility list: it returns HTTP 413
`payload_too_large` if more than 10,000 visible items would be returned,
including item-shared roots. It does not return a Google `nextPageToken`.
It accepts no list query parameters; unsupported Google options such as `q`,
`pageSize`, `pageToken`, and `fields` return HTTP 400 `validation_error` instead
of being silently ignored. The single-file GET accepts only `alt=media` as an
optional query parameter. Use the native `GET /browse/files` endpoint for paged
browsing.

## WebDAV

| Method | Route | Purpose |
| --- | --- | --- |
| OPTIONS | `/dav/{workspace_id}` or `/dav/{workspace_id}/{path}` | Return WebDAV capability headers. |
| PROPFIND | `/dav/{workspace_id}` | Return the workspace root; `Depth: 1` adds active direct children, and `Depth: infinity` adds bounded descendants. |
| PROPFIND | `/dav/{workspace_id}/{path}` | Return nested file/folder metadata; `Depth: 1` adds a folder's direct children, and `Depth: infinity` adds bounded descendants. |
| MKCOL | `/dav/{workspace_id}/{path}` | Create a nested folder under an existing folder. |
| GET | `/dav/{workspace_id}/{path}` | Disk-stream one nested regular file; supports HTTP `Range`. |
| PUT | `/dav/{workspace_id}/{path}` | Create or overwrite one nested regular file. |
| DELETE | `/dav/{workspace_id}/{path}` | Trash a nested file or folder through the normal Drive trash path. |
| MOVE | `/dav/{workspace_id}/{path}` | Rename or move a nested file/folder. `Destination` must stay inside the same WebDAV workspace. |
| COPY | `/dav/{workspace_id}/{path}` | Copy a nested file/folder. Folder copies use the normal recursive Drive copy behavior. |
| LOCK | `/dav/{workspace_id}` or `/dav/{workspace_id}/{path}` | Create or refresh a persistent exclusive write lock on an existing workspace root, folder, or file. |
| UNLOCK | `/dav/{workspace_id}` or `/dav/{workspace_id}/{path}` | Remove the submitted lock when the `Lock-Token` and request URI are inside the same lock scope. |

WebDAV uses the same bearer-token auth and optional `X-ShellX-Actor` header as
the native API. Reads require workspace read permission; writes require write
permission. `MOVE` and `COPY` reject cross-workspace `Destination` headers in
this version.

For `PROPFIND`, `Depth: 0` returns only the requested root, folder, or file;
the default depth is `1`. Both root and nested `Depth: infinity` requests
traverse descendants. The workspace inventory and returned tree are bounded
to 10,000 active items, with at most 256 descendant levels. Parent cycles and
duplicate sibling names fail closed rather than producing an ambiguous tree.

The supported locking subset is exclusive write locks on existing resources.
A new lock requires a bounded XML `lockinfo` body, supports `Depth: 0` and
`Depth: infinity` (the default), and returns its opaque token in `Lock-Token`.
The server selects a timeout between one second and 24 hours; omitted timeout
defaults to one hour and `Infinite` is capped to 24 hours. A bodyless `LOCK`
refresh requires exactly one current token in `If`. Shared locks return `501`
instead of being silently treated as exclusive, unsupported depth returns
`400`, and locking an unmapped URL is not supported.

Mutation requests submit tokens in `If`. A depth-zero folder lock protects the
folder and direct membership changes (create, remove, move, rename, or copy a
member), while a depth-infinity folder lock additionally protects all
descendant writes. `DELETE` and `MOVE` require every applicable source,
collection, and descendant token; `COPY` reads the source without its lock token
but requires applicable destination-collection tokens. Missing/conflicting
tokens return `423`. Locks follow stable file identity across `MOVE`, expire
automatically, and are destroyed with deleted resources. `UNLOCK` requires the
lock owner (or an admin), a matching token, and a URI in that lock scope;
mismatches return `409`.

Active locks are SQLite-backed and survive a process restart. They are runtime
coordination state and are intentionally not restored from `.sxdbackup`
archives, preventing stale historical locks from reappearing. **A WebDAV lock
only constrains WebDAV requests.** Native JSON writes and office-editor package
saves do not consume DAV lock tokens; they use their required optimistic
`base_revision` and return a stale-revision conflict when the file changed.
WebDAV locks therefore complement rather than replace ShellX Drive's
cross-protocol optimistic revision conflict model.

## Hosted Mode

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/hosted/status` | Public hosted posture: hosted mode, public base URL, billing provider label, signup policy, public rate limit, backup scheduler posture, and drop-scanning posture. |
| POST | `/hosted/signup` | Reserved compatibility route. Returns `403` in v0.1; public hosted enrollment remains unavailable until verified-email identity binding is implemented. |

Hosted mode is disabled by default. Enable it with `SHELLX_DRIVE_HOSTED_MODE`
or `--hosted`. `SHELLX_DRIVE_PUBLIC_ORIGIN`,
`SHELLX_DRIVE_HOSTED_BILLING_PROVIDER`, and
`SHELLX_DRIVE_HOSTED_PUBLIC_RATE_LIMIT_PER_MINUTE` only describe hosted posture
inside the OSS binary. Billing provider `none`/`manual`, backup scheduler
`admin_policy`, and drop malware scanning `not_configured` are explicit status
values rather than fake integrations. When hosted mode is enabled, workspace
creation requires `tenant_id`; self-host mode keeps `tenant_id` optional.

## Local Auth And 2FA

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/auth/bootstrap/status` | Public check for whether first-admin bootstrap is required. |
| POST | `/auth/bootstrap` | Create the first local admin account when no local account exists. Requires `Authorization: Bearer <SHELLX_DRIVE_BOOTSTRAP_TOKEN>` when that separate setup credential is configured; legacy installations fall back to the operator token. Loopback and `--e2e` do not bypass authorization. Returns a revocable session; `cookie_only:true` omits bearer material from JSON. |
| POST | `/auth/bootstrap/wizard` | First-run setup wizard route with the same setup-authority rule. Creates the first local admin, first workspace, and a revocable session in one flow; `cookie_only:true` omits bearer material from JSON. |
| GET | `/auth/registration/status` | Public self-registration status. Returns `enabled:false` in v0.1. |
| POST | `/auth/register` | Reserved compatibility route. Returns `403` in v0.1; administrators create accounts and verified invitation links bind existing accounts to workspaces. |
| POST | `/auth/login` | Email/password login. If TOTP is enabled and no second factor is supplied, returns `202` with `requires_2fa=true`. Send `cookie_only:true` for a browser session whose bearer stays only in the HttpOnly cookie; omit/false preserves the API-client token response. |
| POST | `/auth/logout` | Revoke the current local session and write `auth.logout`. An account-wide delegated agent instead revokes its exact delegated bearer and returns `delegated_agent` plus the receipt. |
| GET | `/auth/me` | Return the current actor, its own `totp_enabled` state when account security applies, plus UI-safe capability flags (`account_security_available`, `session_management_available`, `notifications_available`, and `admin_tools_available`). This self-scoped endpoint avoids requiring the admin account directory in ordinary settings. `auth_mode=delegated_agent` identifies account-wide delegation; `auth_mode=operator` remains true when the server token uses `X-ShellX-Actor`. |
| GET | `/auth/sessions` | List only the signed-in local actor's currently valid, non-revoked sessions, including server-observed browser/IP/sign-in/last-seen metadata. Another account's network metadata is never returned. An account-wide delegated caller has `current_session_id:null` because it is not a browser session. Issuance retains at most 16 currently valid sessions for an actor; the oldest is revoked atomically with its derived Office sessions. Expired and revoked history remains debug-only and excludes raw network metadata. |
| GET | `/auth/security-events` | List only the signed-in local actor's own recent sign-in events, including outcome, browser, and server-observed IP. An account-wide delegated caller is bound to that same actor and cannot select another account. No guest-link visitor appears in this response. |
| POST | `/auth/sessions/revoke-others` | Revoke every other currently valid session owned by the signed-in local actor while retaining the current browser. A delegated caller has no browser session to retain, so it revokes the owner's currently valid human sessions. Derived Office sessions for each revoked browser are invalidated in the same transaction. |
| POST | `/auth/sessions/{session_id}/revoke` | Revoke one of the signed-in actor's sessions. |
| POST | `/auth/password/change` | Change the signed-in local account password after current-password and optional 2FA verification. |
| POST | `/auth/password/reset/request` | Public, generic password reset request. If an enabled account has no active reset token, queues one `password_reset` email and returns `202`; production never returns its token or link. In isolated `--e2e` testing only, a current administrator credential may receive `debug_token`. A duplicate request retains the active token and returns the same generic `202` without minting, publishing, or emailing another token. |
| GET | `/reset-password` | Browser password-reset page. Reset emails carry the one-time token only in `#token=...`, which is never sent in the page request, browser referrer, or asset requests. |
| POST | `/auth/password/reset/consume` | Consume a one-time reset token and set a new password. The browser page submits JSON `{ "token": "<one-time token>", "new_password": "..." }`; token hashes are stored separately from email bodies. Invalid, expired, and already-used links share one neutral browser result. |
| POST | `/auth/2fa/setup` | Start TOTP setup for the signed-in local account and return the one-time secret, server-issued otpauth URI, `qr_size`, compact row-major `qr_modules` (`0` light, `1` dark), and replacement-session fields. QR encoding and matrix validation occur before the security mutation. Password is required; replacing an enabled factor additionally requires its current TOTP or a recovery code. |
| POST | `/auth/2fa/enable` | Verify a TOTP code, enable 2FA, and return one-time recovery codes plus replacement-session fields. |
| POST | `/auth/2fa/disable` | Disable TOTP after second-factor verification and return the account plus replacement-session fields. |
| POST | `/auth/recovery-codes/rotate` | Verify TOTP or a recovery code and return a new one-time recovery-code set plus replacement-session fields. |

Local account passwords and new public share/drop passwords are stored as
Argon2id PHC hashes. Legacy salted SHA-256 share/drop hashes remain verifiable
for migration. Local login mints the same revocable `sso.v1` bearer token shape
used by the admin-token identity session bridge, with `issuer=local-password`. Recovery codes are
returned once, stored only as hashes, and consumed through one immediate
transaction so concurrent requests cannot both redeem the same code. Password
reset uses at most one active hashed token per account and the email outbox;
denied account-budget requests do not extend the fixed issuance window, and
normal reset responses are generic to avoid account enumeration. Administrators
create accounts; public registration remains disabled. Email is the account
identity key, and invitation links bind the already signed-in account addressed
by the invitation. Verify recipient identity through the trusted delivery
channel. Failed password and second-factor attempts are counted and can temporarily lock the
relevant login scope. Login, share, and drop throttles are partitioned by a
keyed client fingerprint; throttle records do not store raw network addresses.
Account-session metadata and the administrator security ledger separately retain
server-observed addresses under the audience and retention rules in SECURITY.md.
Failures decay after 15 minutes, and lockouts back off from 30 seconds to a
five-minute cap. Password-protected shares and Drops also have durable
capability-wide budgets across client partitions. Durable account-wide password
and TOTP rows prevent rotating-client login guessing. During one active shared
penalty, exactly one password, TOTP, or recovery-code verification may be
reserved; a correct proof
atomically clears the shared penalty and reservation, while a wrong proof or
any later denied request cannot extend the shared window. Password reset and
an administrator's exact-attempt unlock remain out-of-band recovery paths if
that bounded verification is unavailable or fails.
A TOTP counter accepted for enrollment, login, password change, factor
replacement/disablement, or recovery-code rotation is consumed transactionally
with that operation and cannot authorize a second route. Every self-service
TOTP lifecycle change atomically revokes all prior account sessions and
outstanding Office edit capabilities, then inserts exactly one replacement
local session in the same transaction. Independently managed app and folder-agent
credentials are unchanged by a human-session TOTP rotation. An account-wide
delegated caller uses the same password/second-factor evidence but its acting
delegation is revoked instead of receiving a replacement human session.
Cookie-authenticated callers receive the replacement through `Set-Cookie` and
omit bearer material from JSON. Explicit-Bearer callers receive no session
cookie and instead get `replacement_token_type`, `replacement_token`,
`replacement_session_id`, and `replacement_expires_at`; they must replace the
old bearer before the next authenticated request.
WebAuthn/passkeys, LDAP/SCIM, and enterprise identity lifecycle sync are outside
this slice.
The bundled web UI always requests `cookie_only:true`; explicit API clients keep
the backward-compatible bearer response by omitting that field.
Admin routes return `401` for missing or invalid session/bearer credentials and
`403` for valid non-admin local or SSO sessions.

## OIDC Bridge

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/auth/oidc/config` | Public metadata for the admin-token identity session bridge. A trusted external component verifies OIDC identity first; the administrator then submits those verified claims. |
| POST | `/auth/oidc/exchange` | Admin-token-protected exchange for already verified OIDC claims. |

The exchange records an issued session id and mints a short-lived `sso.v1`
bearer token after the external identity provider's verification.
Revoked or expired SSO sessions are rejected before route-level workspace
permissions run.

## Admin

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/admin/summary` | Token-protected operational totals, job totals, recent receipts, and recent activity. |
| GET | `/admin/canonical-content?limit=&cursor=&query=` | List active canonical files once each, never once per recipient or grant. Current administrator only. `limit` defaults to 50 (1–100); `cursor` is a canonical file UUID; `query` is a trimmed name search of at most 120 bytes. Returns `CanonicalContentResponse { items, next_cursor?, access_generation }`. |
| GET | `/admin/canonical-content/{file_id}/share-details?kind=human\|guest\|ai&limit=&cursor=` | Return one canonical item and one bounded sharing detail kind. Current administrator only. `kind` is required; `limit` defaults to 25 (1–50); `cursor` is a canonical UUID. Returns `CanonicalShareDetailsResponse { item, kind, entries, next_cursor?, access_generation }`. |
| GET | `/admin/workspaces` | List every server workspace with archived state, member count, storage mode, and current/revision/trash usage. Server admin only. |
| DELETE | `/admin/workspaces/{workspace_id}` | Permanently delete one archived workspace only when its file tree is empty. Active or non-empty workspaces are rejected; success writes `workspace.delete.empty_archived`. Server admin only. |
| GET | `/admin/hosted/tenants` | List hosted tenant metadata without billing secrets. |
| POST | `/admin/hosted/tenants` | Create hosted tenant metadata with plan and billing status labels. No external billing call is made. |
| GET | `/admin/auth/users` | List local auth accounts with redacted password, TOTP, and recovery-code state. |
| POST | `/admin/auth/users` | Create a local user or admin account after bootstrap. |
| PATCH | `/admin/auth/users/{email}` | Disable/enable an account, promote/demote admin, reset password, or reset 2FA. A current administrator disabling or demoting their own account must also supply `confirm_email` equal to that exact account email and `current_password`; the same rule applies to an account-wide delegated administrator. Drive rejects either change when it would remove the final enabled local administrator. |
| POST | `/admin/auth/users/{email}/password-reset-link` | Server-admin-only manual recovery. Creates a replacement one-time password-reset link for an enabled account and returns the link exactly in that authenticated response, with an optional `expires_in_seconds` of 300–86400 (default 3600). The link token is kept in the URL fragment, only its hash is stored, and receipts/security events omit the token and link. Deliver it through a trusted out-of-band channel and confirm delivery there. |
| DELETE | `/admin/auth/users/{email}/password-reset-link` | Server-admin-only manual-recovery revocation. Invalidates the selected account's active, unexpired recovery link. Returns `404` if there is no revocable link and never returns a token or link. |
| GET | `/admin/auth/attempts` | List redacted, client-partitioned login/share/drop attempt counters without raw client addresses. Share/drop capability keys and actors are opaque references. |
| POST | `/admin/auth/attempts/unlock` | Remove the exact attempt key supplied in `{ "key": "..." }` and write `auth.attempt.unlock`. The opaque key returned for a share/drop attempt is resolved only inside the server. |
| GET | `/admin/email` | Return email outbox status and redacted message metadata for password reset, invitation, share, and comment notices. Email and relation ids are opaque `email_ref`/`related_ref` values; raw share/drop capability relations and message bodies are omitted. |
| POST | `/admin/email` | Process the local capture queue immediately and return the same redacted status. Server admin only. A processed row records capture for inspection/testing; recipient delivery uses the trusted manual channel. |
| GET | `/admin/registration-policy` | Return the v0.1 public registration posture (`enabled:false`). |
| PATCH | `/admin/registration-policy` | Persist the disabled posture and write `registration.policy.update`; attempts to enable registration return `400` until verified-email enrollment exists. |
| GET | `/admin/sessions` | List currently valid, non-revoked local and OIDC/SSO sessions server-wide with server-observed browser/IP/sign-in/last-seen metadata, but without raw token values or token hashes. It returns `total` and an opaque `next_cursor`; use `limit` (1–100) and that cursor to manage every valid session rather than assuming an implicit fixed listing cap. |
| POST | `/admin/sessions/{session_id}/revoke` | Revoke an issued session before expiry and write `session.revoke`. |
| GET | `/admin/security-events` | Server-admin-only, searchable security ledger for sign-ins, guest-link access, file/content access, authenticated commands, and rejected/failed requests. Failed access to this ledger is itself audited; successful polling is suppressed to avoid recursive noise. Filters: `category`, `outcome`, `query`, `before`, and bounded `limit`. The ledger stores route templates and opaque target references rather than raw capability URLs; it never stores credentials, request bodies, or file content. Successful logins are retained; failed/blocked logins and successful guest requests retain one representative per target/outcome in each 15-minute process-local window (up to 512 partitions). Low-authority rows are capped at 20,000 within the 100,000-row, 90-day ledger. |
| GET | `/admin/app-tokens` | List app/device credential metadata without raw tokens or token hashes. |
| POST | `/admin/app-tokens` | Create a one-time app token bound to an actor and explicit workspace allowlist. The plaintext token is returned only in this response; the database stores its SHA-256 hash. |
| POST | `/admin/app-tokens/{token_id}/revoke` | Revoke an app token before expiry and write `app_token.revoke`. |
| GET | `/ready` | Public readiness report with `live`, `ready`, `state`, and check rows. A healthy service reports `state:"ready"`; an assessed non-critical failure reports `state:"degraded"`; a critical storage/restore problem reports `state:"not_ready"`. Host Ubuntu Pro posture is explicitly `unassessed` in the current binary because Drive does not run host probes, so it does not by itself degrade readiness. |
| GET | `/admin/backups?limit=50&cursor=...` | List complete v1/v2 metadata and pending/failed create jobs, newest first, with cursor pagination (maximum page 100). Freshly imported self-contained v2 archives expose bounded embedded metadata. A generation recorded as locally managed always requires its authenticated sidecar and is never silently reclassified as portable. |
| POST | `/admin/backups` | Queue durable v2 generation and return HTTP 202 with `BackupJobResponse { job, backup? }`; `job.id` and `job.backup_id` identify the job and generation. Export uses one SQLite read transaction, bounded JSONL staging, raw streamed blobs, available-space and `SHELLX_DRIVE_BACKUP_MAX_ARCHIVE_BYTES` preflight, atomic archive publication, a self-contained private restore-integrity envelope, local catalog caching, retention, and a completion receipt. Explicit v1 creation is disabled. |
| GET | `/admin/backups/{backup_id}` | Return the latest durable job and v2 metadata. Locally managed generations require their authenticated sidecar; only fresh imports without local managed provenance use the portable archive envelope. |
| GET | `/admin/backup-jobs/{job_id}` | Return `BackupJobResponse { job, backup? }`. Poll `job.status`: `queued` and `running` are pending; `succeeded`, `failed`, and `interrupted` are terminal. Completed metadata is included when available. |
| GET | `/admin/backups/{backup_id}/download` | Stream one complete self-contained v2 `.sxdbackup` with exact length, attachment disposition, and `no-store`; bounded v1 retains its JSON response. Writes `backup.download`. |
| POST | `/admin/backups/{backup_id}/validate` | Queue streamed v2 validation and return HTTP 202. A copied new v2 artifact needs no source-host sidecar/key; malformed, wrong-format, truncated, and ordinarily corrupted archives fail before restore. Its embedded portable-integrity envelope is not an externally trusted provenance signature; use protected storage or an externally trusted signature/checksum against an archive modifier. Bounded v1 validation remains synchronous; oversized v1 fails fast with HTTP 413. |
| DELETE | `/admin/backups/{backup_id}` | Delete a verified v2 archive (and its local sidecar when present) or a v1 bundle and write `backup.delete`; exact v1 deletion remains available for oversized generations. |
| GET | `/admin/backup-policy` | Return the persisted backup schedule policy. |
| PATCH | `/admin/backup-policy` | Update enabled/schedule/retention_count and write `backup.policy.update`. Enabled hourly/daily/weekly policies are executed by the durable worker; each scheduled generation queues a full integrity validation. |
| POST | `/admin/backups/{backup_id}/restore` | Queue a v2 restore and return HTTP 202. Restore verifies the archive envelope and hashes, performs digest-checked disposable extraction, installs blobs non-destructively, streams rows into one SQLite transaction, and safely re-admits supported queued preview/index work through current queue limits. Ordinary writes receive HTTP 503 while maintenance is active. It restores content/catalog data while preserving the target instance's current security authority: historical passwords, reset tokens, sessions, memberships, policies, app/agent credentials, shares, drops, and capabilities are not reinstated. Current security rows survive only where they still reference restored workspaces/files. Current human item grants replace archived grants, are filtered to restored workspace/root and extant account/group principals, and advance the live access epoch; current private-workspace mappings are reconciled transactionally. Current email-outbox delivery state stays with that live authority; archived reset, invitation, share, and other capability-bearing messages are not reinstated. Bootstrap and explicitly grant new authority on a fresh target. New v2 archives are unencrypted, operator-readable restore material and must be protected by deployment storage controls. Bounded v1 remains synchronous. |
| POST | `/admin/retention/preview` | Dry-run recovery cleanup for trashed files and old unpinned revisions. Body may include `workspace_id`. |
| POST | `/admin/retention/apply` | Apply retention cleanup and write `retention.prune` with counts and candidates. |
| GET | `/admin/sandbox` | Return the current sandbox profile intent and status. |
| PATCH | `/admin/sandbox` | Update sandbox profile intent such as bind address, data directory, and writable paths. Writes a receipt. |
| POST | `/admin/sandbox/preview` | Return rendered install commands and systemd unit preview without mutating the host. |
| POST | `/admin/sandbox/apply-intent` | Record an operator-approved sandbox apply intent. The normal Drive process does not mutate `/etc`, users, firewall, or systemd directly. |
| GET | `/admin/maintenance` | Return redacted maintenance configuration labels and policy status and write `maintenance.check`. `host_posture:"unassessed"` and `ubuntu_pro_attached:null` mean Drive did not run an Ubuntu Pro/host probe; they are not a claim that the host is detached. |
| POST | `/admin/maintenance/blobs/gc` | Reference-counted garbage-collection sweep of the blob store: permanently removes content and thumbnail blobs no longer referenced by any file or revision, and reaps stale upload temp files. Query `min_age_seconds` (default `3600`; `0` = stop-the-world, reap immediately) bounds which candidates are old enough to collect. Admin only; writes a maintenance receipt. |
| GET | `/admin/support-bundle` | Create a support bundle from a strict operational allowlist, plus logs metadata and `support_bundle.create`. User-authored content, names, paths, identities, and secrets are excluded; the richer Debug export is not embedded. |

Canonical-content routes are privileged product-management reads, not Debug
diagnostics: they return canonical file, owner, path, and current sharing
metadata needed by a current administrator, while omitting passwords, token
hashes, and agent plaintext tokens. The route revalidates current administrator
authority immediately before it publishes the buffered response, so a concurrent
session revoke or role loss denies that response.

Backup, sandbox, and maintenance routes are admin surfaces for binary-first
local/VPS operation. Backup creation includes only blob objects referenced by
exported database rows; orphaned blob files are not included. Backup bundles are
private server-side restore material and may contain historical password hashes;
online restore preserves the target instance's live authority and keeps
historical credentials inactive. Debug/admin list responses
only return metadata. Backup policy records the enabled schedule and retention
count. The durable background worker executes scheduled backups and queues
validation of each generated archive. Retention routes are recovery hygiene
only: they prune trashed files and unpinned revision rows by workspace policy.
Use a separate compliance system when legal hold, immutable records, eDiscovery,
or compliance exports are required. Support bundles include an operational
allowlist and logs metadata;
they exclude the richer Debug export and backup blob payloads. Secrets such as
Ubuntu Pro tokens, sudo passwords, SSH keys, and raw
server bearer tokens are never returned.

## Debug

The full debug route catalog is in [DEBUG_API.md](DEBUG_API.md).
