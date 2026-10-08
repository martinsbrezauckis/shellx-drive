# ShellX Drive — endpoint reference

Maintained per-endpoint request/response argument tables, derived from the
structs in `src/model.rs` and the route modules. When this file and the code
disagree, the code wins — report the drift. The public prose catalog is
[docs/public/API.md](../../docs/public/API.md); the debug catalog is
[docs/public/DEBUG_API.md](../../docs/public/DEBUG_API.md).

## Conventions

- **Auth.** Send `Authorization: Bearer <token>` unless a route is marked Public.
  Ordinary user clients use their current local/SSO session or an account-wide
  delegated `sxd_agent_` credential, which is rechecked as that owner's current
  authority. The configured server token is an operator credential for
  `system@local`; `x-shellx-actor: <email>` is an operator-controlled
  multi-actor test/admin mechanism. A folder-scoped `sxd_agent_` credential uses
  `/agent/v1/access` and `/agent/v1/grants/{grant_id}/...` within its View/Edit
  subtree grant. An app token uses workspace-scoped APIs within its role;
  account, delegation, and admin routes use the appropriate owner or operator
  credential described in their Auth column.
- **First-account setup.** `GET /auth/bootstrap/status` is public. The two POST
  bootstrap routes require the separately configured setup token when present;
  otherwise existing installations fall back to the operator token. The setup
  credential authorizes first-account creation while the account database is empty.
- **Permission levels** (workspace role → capability): `viewer`=Read,
  `editor`=Read+Write, `owner`=Read+Write+Manage.
- **`Receipt`** (returned by most mutations): `{ id, kind, actor, target_id?,
  created_at }`. Immutable; an ordinary client verifies its own mutation with
  that receipt and authorized product readback. `/debug/receipts` is an
  administrator diagnostic, not a universal verification prerequisite.
- **`DriveFile`**: `{ id, workspace_id, parent_id?, name, kind:"file"|"folder",
  revision, trashed, starred, content_hash?, created_at, updated_at, size_bytes?
  (stored content byte length; `null` for folders), has_cover (folder has a custom
  cover image; always `false` for files) }`.
- **`Workspace`**: `{ id, name, storage_mode:"open", created_at,
  updated_at, archived, archived_at?, tenant_id?, role? }`.
- Times are RFC3339 strings. `Option<T>` fields may be absent/null.

## Health and readiness

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/health` | Public | `HealthResponse { ok, service }` |
| GET | `/ready` | Public | `ReadinessResponse { live, ready, state, checks:[{name,status,critical,message}] }`; intentionally omits debug mode, host paths, raw failures, and restore-job identity. |
| GET | `/version` | Public | `VersionInfo { service, version, build, commit, built_at }` — `build` = `version+shortsha`, changes per deploy. Read this to report the exact running build. |
| GET | `/update/check` | Admin | `UpdateStatus { kind(current\|available\|unconfigured\|error), current_version, repo?, latest_version?, release_url?, release_name?, published_at?, body?, download_url?, checksum_url?, checked_at, reason? }` — administrator-only server-release check, cached 30m; links the exact official Linux package/checksum when published and never installs automatically. |

## Workspaces

| Method | Path | Auth / perm | Request | Response |
|---|---|---|---|---|
| POST | `/workspaces` | Current administrator or operator (including a currently authorized local admin delegation) | `CreateWorkspaceRequest { name, owner_email, storage_mode?("open" only), tenant_id?(required in hosted mode) }` | `CreateWorkspaceResponse { workspace, owner:DriveUser, receipt }` |
| PATCH | `/workspaces/{id}` | Manage | `UpdateWorkspaceRequest { name? }` | `WorkspaceMutationResponse { workspace, receipt }` |
| GET | `/workspaces/{id}/members` | Manage | — | `[WorkspaceMember { workspace_id, user_id, email, role, created_at }]` |
| POST | `/workspaces/{id}/members` | Manage | `UpsertWorkspaceMemberRequest { email, role("owner"\|"editor"\|"viewer") }` | `WorkspaceMemberResponse { member, receipt }` |
| DELETE | `/workspaces/{id}/members` | Manage | `RemoveWorkspaceMemberRequest { email }` | `WorkspaceMemberResponse` |
| POST | `/workspaces/{id}/leave` | Bearer (self) | — | `WorkspaceLeaveResponse { receipt }` |
| POST | `/workspaces/{id}/transfer-owner` | Owner | `TransferWorkspaceOwnerRequest { email }` | `TransferWorkspaceOwnerResponse { old_owner, new_owner, receipt }` |
| POST | `/workspaces/{id}/archive` \| `/unarchive` | Manage | — | `WorkspaceMutationResponse` |
| GET | `/workspaces/{id}/usage` | Read | — | `WorkspaceUsage { workspace_id, quota_bytes?, current_file_bytes, revision_bytes, trashed_file_bytes, remaining_bytes? }` |
| GET | `/workspaces/{id}/policy` | Read | — | `WorkspacePolicyReadResponse { policy }` |
| PATCH | `/workspaces/{id}/policy` | Manage | `UpdateWorkspacePolicyRequest { quota_bytes?, public_links_enabled?, link_password_required?, allow_never_expire?, max_link_ttl_seconds?, drop_password_required?, max_drop_ttl_seconds?, trash_retention_days?, revision_retention_days? }` | `WorkspacePolicyMutationResponse { policy, receipt }` |

`WorkspacePolicy`: `{ workspace_id, quota_bytes?, public_links_enabled,
link_password_required, allow_never_expire, max_link_ttl_seconds,
drop_password_required, max_drop_ttl_seconds, trash_retention_days,
revision_retention_days, updated_at }`. Fresh and migrated workspaces default
`allow_never_expire` to `false`.

### Invitations

| Method | Path | Auth / perm | Request | Response |
|---|---|---|---|---|
| GET | `/workspaces/{id}/invitations` | Manage | — | `WorkspaceInvitationListResponse { invitations }` (accept tokens never listed) |
| POST | `/workspaces/{id}/invitations` | Manage | `CreateWorkspaceInvitationRequest { email, role }` | `WorkspaceInvitationMutationResponse { invitation, token?(one-time), receipt }` |
| POST | `/workspaces/{id}/invitations/{invitation_id}/resend` | Manage | — | `WorkspaceInvitationMutationResponse` (rotates token) |
| POST | `/workspaces/{id}/invitations/{invitation_id}/cancel` | Manage | — | `WorkspaceInvitationMutationResponse` |
| GET | `/pub/invitations/accept` | Public | The invitation URL carries `#token=<token>` for the browser. | Invitation landing page; acceptance requires the addressed signed-in account. |
| POST | `/pub/invitations/accept` | Addressed account's session or account-wide delegation | `{ token }`; cookie requests require the configured same Origin; manual clients send an explicit bearer | `WorkspaceInvitationAcceptResponse { invitation, member, receipt }`; operator, app and folder-agent credentials are rejected. |

`WorkspaceInvitation`: `{ id, workspace_id, email, role, status, invited_by,
expires_at, accepted_at?, canceled_at?, created_at, updated_at }`.

## Groups

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/groups` | Admin | — | groups + members + workspace grants visible to the current administrator |
| POST | `/groups` | Admin | `CreateGroupRequest { name }` | `GroupResponse { group, receipt }` |
| POST | `/groups/{group_id}/members` | Admin | `UpsertGroupMemberRequest { email }` | `GroupMemberResponse { member, receipt }` |
| DELETE | `/groups/{group_id}/members` | Admin | `UpsertGroupMemberRequest { email }` | `{ receipt }` |
| POST | `/workspaces/{id}/group-grants` | Manage | `UpsertWorkspaceGroupGrantRequest { group_id, role("viewer"\|"editor") }` | `WorkspaceGroupGrantResponse { grant, receipt }` |
| DELETE | `/workspaces/{id}/group-grants/{group_id}` | Manage | — | `WorkspaceGroupGrantResponse` |

## Account-wide delegated agents

Account-wide delegation is distinct from the no-login folder-agent surface.
Its `sxd_agent_` bearer acts as its owner through the ordinary Drive and account
routes, subject to the owner's current workspace and administrator authority.
The token is returned once at issuance/rotation. Transfer it through the caller's
approved secret channel into protected credential storage, keeping browser state
and logs limited to redacted metadata. Use the owner credential classes listed
below for these lifecycle routes.

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/agent-delegations` | User or current account-wide delegation; operator only as `system@local` | — | `DelegatedAgentListResponse { agents }` (no token values/hashes) |
| POST | `/agent-delegations` | User or current account-wide delegation; operator only as `system@local` | `CreateDelegatedAgentRequest { name, expires_in_seconds? }` (1 hour–365 days; default 30 days) | `201 CreateDelegatedAgentResponse { agent, token(one-time), receipt }` |
| POST | `/agent-delegations/{principal_id}/rotate` | Same owner (or `system@local` operator) | `RotateAgentPrincipalRequest { expires_in_seconds? }` | `CreateDelegatedAgentResponse { agent, token(one-time), receipt }` |
| POST | `/agent-delegations/{principal_id}/revoke` | Same owner (or `system@local` operator) | — | `DelegatedAgentMutationResponse { agent, receipt }` |

External SSO delegation is additionally bound to its exact live parent session
and remains ordinary-user authority. A local delegation follows its owner's
current administrator role. Folder grants retain their separate `/agent/v1`
subtree authority.

## Remote desktop actions

After the user locally enables control on their paired desktop, their current
account-wide delegation can operate that device through Drive's outbound-poll
broker. Use the same owner credential for these routes:

| Method | Path | Request / result |
|---|---|---|
| GET | `/desktop-agent/devices` | List the owner's enrolled device metadata. |
| POST | `/desktop-agent/commands` | `{ request_id, device_id, kind, payload, expires_in_seconds? }`; use a new UUID for a new action and the identical request for a retry. |
| GET | `/desktop-agent/commands/{command_id}` | Read lifecycle status, fixed terminal code and bounded action result. Queued, acknowledged, running and relaunch-pending states do not prove success. |
| POST | `/desktop-agent/commands/{command_id}/cancel` | Request cancellation; already performed effects may remain. |

Use `desktop_view` and `discover_roots` paging for actionable location/review
IDs. `select_pair` preserves enrollment within the same server/account.
`start_pair` with `{ workspace_id }` can refresh usable roots under an existing
locally chosen base; its `roots_refreshed` result counts only that workspace.
Initial local setup still requires a local gesture. Remote Disconnect uses a
device-owned recovery capability internally; an owner agent must read the
command's terminal result rather than treating device disappearance as success.
An active synchronization run is stopped cooperatively before Disconnect
retires the connection. A queued command or progress update is not completion;
keep observing its terminal result, including any recovery or retry requirement.
The claim, progress, terminal and Disconnect-continuation endpoints are desktop
protocol routes, not substitutes for an owner's delegation. Their full schemas
and guards are in [the broker contract](../../docs/public/API.md#desktop-agent-control-broker).

## Human item sharing

Only a whole-workspace owner or administrator may manage a human item grant;
an item Editor may edit content but cannot delegate access. Item grants confer
Viewer or Editor access to an account, group, or an administrator-policy-gated
`everyone` principal without creating workspace membership or WebDAV access.

| Method | Path | Auth / perm | Request | Response |
|---|---|---|---|---|
| GET | `/share-principals?file_id=&kind=account\|group&query=&limit=` | Item Manage | — | `SharePrincipalListResponse { principals }`; only enabled accounts can receive an account grant |
| GET | `/files/{id}/human-grants` | Item Manage | — | `HumanItemGrantListResponse { grants, action_capabilities, everyone_policy_enabled }` |
| POST | `/files/{id}/human-grants` | Whole-workspace owner/admin | `CreateHumanItemGrantRequest { principal_kind(account\|group\|everyone), principal_ref?, role(viewer\|editor), expires_at? }` | `201 HumanItemGrantResponse { grant, receipt }` |
| GET | `/files/{id}/action-capabilities` | Item Read | — | `ItemActionCapabilitiesResponse { file_id, workspace_id, action_capabilities, access_generation }` |
| PATCH | `/human-grants/{grant_id}` | Whole-workspace owner/admin | `UpdateHumanItemGrantRequest { role?, expires_at? }` | `HumanItemGrantResponse { grant, receipt }` |
| DELETE | `/human-grants/{grant_id}` | Whole-workspace owner/admin | — | `204` |
| GET | `/sharing/shared-with-me?limit=` | User | — | `SharedItemRootsResponse { roots }` |
| GET | `/sharing/shared-by-me?limit=` | User | — | `SharedByMeResponse { roots }` |
| GET / PATCH | `/admin/human-sharing-policy` | Admin | `UpdateEveryoneGrantPolicyRequest { everyone_grants_enabled }` for PATCH | policy, plus receipt for PATCH |

## Files

| Method | Path | Auth / perm | Request | Response |
|---|---|---|---|---|
| GET | `/files` | Bearer | — | `{ files:[DriveFile] }` (actor-visible) |
| POST | `/files` | Write | `CreateFileRequest { workspace_id, parent_id?, name, kind("file"\|"folder"), content? }` | `201 FileMutationResponse { file, receipt }` |
| PATCH | `/files/{id}` | Write | `UpdateFileRequest { base_revision?, name?, parent_id?, move_to_root?, collision_policy?(keep_both\|cancel\|replace), replace_target_id?, replace_target_revision?, labels?, custom_metadata? }`; omitted policy is `keep_both`. `cancel` returns 409 without mutation; file-on-file `replace` needs both exact replacement fields plus `base_revision`, retains the destination ID/history, and trashes the source. | `FileOperationResponse { file, metadata, receipt }`; returned `file` is authoritative |
| GET | `/files/{id}/content` | Read | — | file bytes; **NEW**: `Content-Type` by extension, `Content-Disposition: inline`, `Accept-Ranges: bytes`, `Range`→`206` |
| PUT | `/files/{id}/content` | Write | `PutContentRequest { base_revision, content }` | match→`FileMutationResponse`; stale→`409 StaleRevisionResponse { error, file_id, attempted_base_revision, current_revision, conflict_file_id, receipt }` |
| GET | `/files/{id}/download` | Read | — | **NEW**: attachment (`Content-Disposition: attachment; filename*=…`) |
| POST | `/files/{id}/download` | Read | — | Mint a short-lived one-use file capability: `{ download_url, expires_in_seconds }` |
| DELETE | `/files/{id}` | Write | — | **NEW**: `204`; permanent, recursive for folders, ref-counted blob cleanup |
| GET | `/files/{id}/preview` | Read | — | `FilePreviewResponse { preview }` |
| POST | `/files/{id}/preview` | Read | — | Mint a short-lived reusable range-preview capability: `{ content_url, expires_in_seconds }` |
| GET | `/files/{id}/thumbnail` | Read | — | preview PNG (`image/png`); `404` when none |
| PUT | `/files/{id}/cover` | Write | raw image bytes (PNG/JPEG/GIF/WebP, signature-validated, ≤8 MiB) | **NEW**: `FileMutationResponse` (folder now `has_cover:true`); non-folder / empty / unsupported → `400` |
| GET | `/files/{id}/cover` | Read | — | **NEW**: cover image bytes with detected type + `nosniff`; `404` when no cover |
| DELETE | `/files/{id}/cover` | Write | — | **NEW**: `FileMutationResponse` (clears cover, ref-counts the blob); idempotent |
| GET | `/files/{id}/metadata` | Read | — | `FileMetadata { labels:[String], custom_metadata:Json, size_bytes? }` |
| POST | `/files/{id}/copy` | Write | `CopyFileRequest { name?, parent_id? }`: omit `parent_id` to retain the source parent; use JSON `null` for the workspace root; use a string for that destination folder. An occupied name is atomically derived as `name (copy).ext`, then `name (copy2).ext`. | `201 FileOperationResponse`; returned `file.name` and `file.parent_id` are final |
| GET | `/files/{id}/revisions` | Read | — | `FileRevisionsResponse { revisions:[FileRevision] }` |
| POST | `/files/{id}/revisions/{rev}/restore` | Write | — | `FileMutationResponse` (new current revision) |
| POST | `/files/{id}/revisions/{rev}/pin` \| `/unpin` | Write | — | `FileRevisionMutationResponse { revisions, receipt }` |
| POST | `/files/{id}/revisions/prune` | Manage | — | Prune unpinned non-current revisions and return storage totals + receipt |
| DELETE | `/files/{id}/revisions/{rev}` | Write | — | Delete one non-current, unpinned revision; returns remaining revisions + receipt |
| POST | `/files/{id}/revisions/{rev}/download` | Read | — | Mint a one-use revision download capability |
| POST | `/files/{id}/download-zip` | Read | — | Mint a 120-second, one-use ZIP capability: `{ download_url, expires_in_seconds }`; redeem with `GET /downloads/{ticket}` |
| POST | `/files/download-zip` | Read | `{ "file_ids": [...] }` | Mint a one-use ZIP capability for selected files/folders |
| GET | `/workspaces/{id}/tree` | Read | — | `FileTreeResponse { workspace_id, nodes:[FileTreeNode] }` |
| POST | `/files/bulk` | Write | `BulkFileActionRequest { action("trash"\|"restore"\|"star"\|"unstar"), file_ids:[String] }` | `BulkFileActionResponse { files, receipt }` |
| POST | `/files/{id}/trash` \| `/restore` | Write | — | `FileMutationResponse` |
| POST | `/files/{id}/star` \| `/unstar` | Write | — | `FileMutationResponse` |
| POST | `/workspaces/{id}/trash/empty` | Write | — | **NEW**: permanently purges only subtrees past workspace retention; returns `{ deleted:N, retained:N, retained_items:[{file_id,name}] }` |

`FileRevision`: `{ file_id, revision, has_content, content_bytes, created_at,
conflict_of_revision?, pinned }`. `FileTreeNode`: `{ id, workspace_id, parent_id?,
name, path, kind, revision, trashed, starred, updated_at, size_bytes?, has_cover }`.
`FilePreview`:
`{ file_id, workspace_id, revision, kind, content, thumbnail_hash?,
thumbnail_content_type?, width?, height?, status, updated_at }`.

### Capability download redemption

The POST mint routes authorize the actor before returning an unguessable,
short-lived URL. Redeem `GET /downloads/files/{ticket}` for a file, revision, or
media preview, and `GET /downloads/{ticket}` for a ZIP archive. Redemption is
public by capability. Keep the URL in the requesting client's temporary secret
handling and redeem it promptly. Download and ZIP tickets are one-use; preview
tickets allow only a bounded number of range requests.

## Resumable uploads

| Method | Path | Auth / perm | Request | Response |
|---|---|---|---|---|
| POST | `/uploads/resumable` | Write | `CreateUploadSessionRequest { workspace_id?, parent_id?, name?, path?, total_size(REQUIRED, 0..=2GiB), duplicate_policy?(keep_both\|cancel\|replace), target_file_id?, base_revision? }`; new files require workspace/name; replacements require the exact target/revision pair and derive their destination from it. | `201 UploadSessionResponse { session }` |
| POST | `/uploads/preflight` | Write | `UploadPreflightRequest { workspace_id, parent_id?, files:[{name,size,path?}] }` (max 512 files) | Quota fit + duplicate/path conflicts before session creation |
| GET | `/uploads/resumable/{id}` | Read (session actor) | — | `UploadSessionResponse` |
| PUT | `/uploads/resumable/{id}` | Write (session actor) | `UploadChunkRequest { offset, content? \| content_base64?, finish? }` | `UploadChunkResponse { session, file?, receipt? }`; wrong offset→`409` |
| GET | `/workspaces/{id}/uploads` | Read | Caller-owned sessions, or all sessions for an administrator | `UploadSessionListResponse { sessions }` |
| POST | `/uploads/resumable/{id}/cancel` | Write (session actor) | — | `UploadSessionMutationResponse { session, receipt }` |
| POST | `/admin/uploads/cleanup` | Admin | `UploadCleanupRequest { older_than_seconds?(default 86400) }` | `UploadCleanupResponse { cleaned_sessions, receipt }` |

`UploadSession`: `{ id, workspace_id, actor_email, parent_id?, name, total_size?,
received_bytes, completed, canceled, file_id?, upload_url, created_at, updated_at,
canceled_at?, path?, duplicate_policy, target_file_id?, base_revision? }`.
Preflight is advisory. A new-file session retains `keep_both` (default) or
`cancel` through terminal completion, including concurrent uploads. `skip` is a
legacy alias for `cancel`. Replacement requires a live regular file and both
`target_file_id` and `base_revision`; when supplied, policy is omitted or
`replace`. A stale target at terminal completion returns 409 with a conflict
copy; it never silently overwrites the newer revision. Terminal retries return
the recorded completion outcome without creating another mutation.
`offset` must equal `received_bytes`; a chunk supplies **either**
`content` (text) **or** `content_base64`, not both; `finish:true` requires
`received_bytes == total_size` and creates the file.

## Search and listing

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/search?q=` | Bearer | `SearchResponse { query, files:[DriveFile], results:[SearchResult { file, rank, matched_fields, snippet? }] }` |
| GET | `/recent` | Bearer | `{ files:[DriveFile] }` |
| GET | `/shared` | Bearer | `{ files:[DriveFile] }` (workspaces where actor is a non-owner member) |
| GET | `/starred` | Bearer | `{ files:[DriveFile] }` |
| GET | `/activity` | Bearer | **CHANGED**: `{ activity:[Activity { id, kind, actor, target_id?, created_at }] }`, now scoped to the actor's visible workspaces |

## Notifications

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/notifications` (+`?unread_only=true`) | Bearer | — | `NotificationListResponse { unread_count, notifications:[Notification] }` |
| POST | `/notifications/{id}/read` | Bearer | — | `NotificationMutationResponse { notification?, receipt }` |
| POST | `/notifications/read-all` | Bearer | — | `NotificationMutationResponse` |

`Notification`: `{ id, recipient_email, workspace_id?, file_id?, kind, title, body,
related_type?, related_id?, read_at?, created_at }`.

## Sync

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/sync/workspaces` | Bearer | actor-visible workspaces incl. `role` |
| GET | `/sync/health` | Bearer | `SyncHealthResponse { mode, generated_at, actor?, totals, workspaces:[SyncWorkspaceHealth] }` |
| GET | `/sync/workspaces/{id}/manifest` | Read | full desktop manifest |
| GET | `/sync/mobile/workspaces` | Bearer | `MobileWorkspacesResponse { mode, workspaces }` |
| GET | `/sync/mobile/workspaces/{id}/manifest` | Read | `MobileManifestResponse` (metadata-only, no hashes) |
| GET/POST | `/sync/mobile/offline` | Bearer | list / `MobileOfflineRequest { file_id, offline }` → `MobileOfflineMutationResponse` |
| GET | `/sync/mobile/files/{id}/content` | Read | marked open file bytes, disk-streamed with `Range` support |
| GET | `/sync/files/{id}/chunks` (`?chunk_size=`) | Read | `FileChunkManifestResponse { file_id, workspace_id, revision, content_bytes, chunk_size, content_sha256, chunks:[{index,offset,length,sha256}] }`; the current bounded in-memory manifest path accepts at most 32 MiB |
| PUT | `/sync/files/{id}/delta` | Write | `DeltaContentRequest { base_revision, chunk_size, operations:[Copy{source_index} \| Data{content?,content_base64?}], expected_content_sha256? }` → `DeltaContentResponse { file, receipt, delta }`; stale base → `409` conflict copy; current in-memory base/reconstruction cap is 32 MiB, so use resumable full-content upload for larger files |
| GET | `/sync/changes`, `/sync/workspaces/{id}/changes` | Bearer | `SyncChangesResponse { cursor, next_cursor, changes:[SyncChange] }` |
| GET | `/sync/conflicts` | Bearer | `SyncConflictsResponse { conflicts:[SyncConflict] }` |
| GET | `/sync/roots` | Bearer | `SyncRootsResponse { roots:[SyncRoot] }`; each current full-workspace or item-grant root includes opaque `id`, role, action capabilities, and `access_generation` |
| GET | `/sync/roots/{root_id}/manifest?access_generation=N` | Bearer | `SyncRootManifestResponse { root, mode, next_cursor, files }`; `N` is required, canonical positive unsigned integer with no leading zero, taken from the listed root's `access_generation`; mode is `scoped_desktop_sync` for an item-grant root or `full_desktop_sync` otherwise |

Root discovery is an authenticated ordinary-actor view: it includes only roots
currently resolved for that actor, never public share or Drop grants. Treat
`access_generation` as an authority epoch, not a cursor. A stale value returns
`412 precondition_failed`; a revoked or expired root no longer resolves. In
either case, discard cached root/manifest data, list `/sync/roots`, and retry
only with the fresh generation.

`SyncChange`: `{ id, workspace_id, kind, entity_type, entity_id, actor, receipt_id,
created_at }`. `DeltaWriteStats`: `{ id, file_id, workspace_id, actor_email,
base_revision, new_revision, chunk_size, chunks_total, chunks_reused,
uploaded_bytes, reconstructed_bytes, content_sha256, created_at }`.

## Sharing and drops

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| POST | `/shares` | Write | `CreateShareRequest { file_id, password, expires_in_seconds, notify_email? }` (`file_id` = file OR folder id; `password:""` = none — default policy `link_password_required:false` ALLOWS passwordless links; an admin can PATCH it to `true`, which then rejects empty with 400; `expires_in_seconds<=0` = **never expires** only when workspace policy explicitly has `allow_never_expire:true`, otherwise the request is rejected; permanent links are not capped by `max_link_ttl_seconds`). `notify_email` records legacy capture-outbox metadata; deliver the share link through an approved channel and confirm recipient delivery there. | `CreateShareResponse { share:ShareLink, receipt }` |
| GET | `/files/{id}/shares` | Write | — | `ShareListResponse { shares }` |
| GET | `/workspaces/{id}/shares` | Write | — | `ShareListResponse` |
| PATCH | `/shares/{id}` | Write | `UpdateShareRequest { password?, expires_in_seconds? }` | share mutation |
| POST | `/shares/{id}/revoke` | Write | — | share mutation |
| GET | `/pub/shares/{id}` | Public | `Accept: text/html` → guest page; `Accept: application/json` or `?format=json` → `PublicShareMetadata`; password via `X-Share-Password` | dual-use view; finite-use metadata claims one visit and returns a bound `access_token` |
| GET | `/pub/shares/{id}/content` | Public | `?path=<relpath>` (folder shares); finite-use links require metadata `access_token` in `X-Share-Access-Token` plus its bound client cookie or `X-ShellX-Public-Client-Secret`; unlimited links accept direct `X-Share-Password` | raw bytes (XSS-safe + `Range`); wrong/missing proof → 401; when `allow_download=false`, only safe inline preview types are served |
| GET | `/pub/shares/{id}/thumbnail` | Public | `?path=<relpath>` (folder shares); same finite-use token/client binding or unlimited password proof as content | capability-scoped PNG thumbnail or 404 |
| POST | `/pub/shares/{id}/content` | Public | `SharePasswordRequest { password, path? }` | disk-streamed, range-capable file content (password-gated); wrong pw → 403 (legacy contract) |
| POST | `/drops` | Write | `CreateDropRequest { workspace_id, name, password, expires_in_seconds }` | `CreateDropResponse { drop:DropLink, receipt }` |
| GET | `/workspaces/{id}/drops` | Read | — | `DropListResponse { drops }` |
| PATCH | `/drops/{id}` | Write | `UpdateDropRequest { name?, password?, expires_in_seconds? }` | drop mutation |
| POST | `/drops/{id}/revoke` | Write | — | drop mutation |
| GET | `/pub/drops/{id}` | Public | — | guest upload HTML page |
| POST | `/pub/drops/{id}/preflight` | Drop password header | — | HMAC-signed one-hour client/Drop authorization-bound grant for `X-ShellX-Drop-Access-Token`; no session or Drop metadata |
| POST | `/pub/drops/{id}/uploads` | Drop password header | `CreatePublicDropUploadRequest { name, total_size, path?, content_type? }` | `201 PublicDropUploadResponse { session, receipt? }` |
| PUT | `/pub/drops/{id}/uploads/{session_id}?offset=N&finish=bool` | Drop password header + bound client | `application/octet-stream` chunk (max 8 MiB) | `PublicDropUploadResponse { session, receipt? }` |
| POST | `/pub/drops/{id}/uploads/{session_id}/cancel` | Drop password header + bound client | — | `PublicDropUploadResponse { session, receipt? }` |

`ShareLink`: `{ id, file_id, kind ("file"|"folder"), expires_at (null = never
expires), revoked, created_at, access_count, last_accessed_at? }`.
`PublicShareMetadata`: `{ kind, name, size_bytes, updated_at, permission:"read",
expires_at (null = never expires), requires_password, entries? }` where each `entries[]` is
`{ path, name, kind, size_bytes, updated_at }`.
Entries are present for folder shares once the caller is entitled (no password,
or correct password), and paths are relative to the shared folder root.
Folder-share content paths resolve strictly inside the subtree (traversal /
out-of-subtree → 404); revoked / expired shares → 404.
`DropLink`: `{ id, workspace_id, name, expires_at, revoked,
created_at, upload_count, last_uploaded_at? }`. Creation is validated against the
workspace policy; a policy rejection writes no receipt.

## Comments

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/files/{id}/comments` | Read | — | `[CommentThread { id, file_id, author_email, body, resolved, created_at, updated_at, replies:[CommentReply] }]` |
| POST | `/files/{id}/comments` | Write | `CreateCommentRequest { body }` | `CommentMutationResponse { comment, receipt }` |
| POST | `/comments/{id}/replies` | Write | `CreateCommentReplyRequest { body }` | `CommentReplyMutationResponse { reply, receipt }` |
| POST | `/comments/{id}/resolve` | Write | — | `CommentMutationResponse` |

## Folder templates

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/workspaces/{id}/folder-templates` | Read | — | `[FolderTemplate]` |
| POST | `/workspaces/{id}/folder-templates` | Write | `CreateFolderTemplateRequest { name, description?, items:[{ path, kind, content? }] }` | `FolderTemplateMutationResponse { template, receipt }` |
| POST | `/workspaces/{id}/folder-templates/{tid}/apply` | Write | `ApplyFolderTemplateRequest { root_name? }` | `ApplyFolderTemplateResponse { template, created_files, receipt }` |
| DELETE | `/workspaces/{id}/folder-templates/{tid}` | Write | — | `{ receipt:Receipt }`; deletes the template only, not files created by an earlier apply |

Item paths must be relative, non-empty, and free of `.`/`..` segments.

## Office edit bridge

**v0.1.1 scope:** Online Office editing is post-v0.1.1. Leave the provider
unconfigured and the web affordance hidden for launch. The preparatory routes
below define later integration; they are not v0.1.1 behavior or acceptance
evidence.

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/office/status` | Bearer | — | `OfficeProviderStatus { configured, name, launch_url? }` |
| POST | `/office/files/{id}/open` | Read | — | `OfficeOpenResponse { file, base_revision, save_url, locking, provider:{configured,name,launch_url?}, edit_session? }` |
| GET | `/office/launch/{handoff}` | One-use handoff | — | No-store CSP-restricted HTML form; POSTs the durable session capability to the configured provider without a token-bearing URL |
| POST | `/office/files/{id}/save` | Write | `PutContentRequest { base_revision, content }` | `FileMutationResponse`; stale→`409` |
| GET | `/office/sessions/{token}` | Session token | — | `OfficeSessionManifest { file, actor_email, provider_name, base_revision, expires_at, locking, workspace_storage_mode, package_url, commit_url }` |
| GET | `/office/sessions/{token}/package` | Session token | — | disk-streamed raw package bytes; `Range` → `206` |
| PUT | `/office/sessions/{token}/package?base_revision=N` | Session token | raw package bytes | `FileMutationResponse`; stale→`409`; needs no server token |
| POST | `/office/sessions/{token}/save` | Session token | `PutContentRequest` | Backward-compatible text save; `FileMutationResponse`; needs no server token |

`OfficeEditSession`: `{ file_id, actor_email, base_revision, expires_at,
launch_url }` (only when `SHELLX_DRIVE_OFFICE_PROVIDER_URL` is configured).
`launch_url` is a one-use same-origin handoff; the durable session token and
session/package/commit routes are POSTed to the configured provider and are not
returned to the Drive application DOM.

## Import / export (rclone-style)

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/workspaces/{id}/export/rclone` | Read | — | Legacy `RcloneBundle { format, workspace_id?, entries:[{path,kind,mime_type?,content?,size?}] }`. v1 embeds text-shaped bodies in JSON; it remains wire-compatible for existing text clients but is not binary-safe or suitable for large exports. |
| POST | `/workspaces/{id}/import/rclone/preview` | Write | `RcloneBundle` | `RcloneImportPreviewResponse { dry_run, summary, actions:[{path,kind,action,bytes,message?}], receipt }` |
| POST | `/workspaces/{id}/import/rclone` | Write | `RcloneBundle` | `RcloneImportResponse { imported:[DriveFile], summary, receipt }` |

## Google Drive API subset

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/drive/v3/files` | Bearer | list non-trashed visible files (Drive v3 shape) |
| POST | `/drive/v3/files` | Write | create a text file + index it |
| GET | `/drive/v3/files/{id}` | Read | Drive-shaped metadata for one file |
| GET | `/drive/v3/files/{id}?alt=media` | Read | disk-stream content as media; `Range` → `206` |

## WebDAV

Single handler at `/dav/{workspace_id}` and `/dav/{workspace_id}/{path}` accepting:
`OPTIONS` (capability headers), `PROPFIND` (`Depth: 0` returns the target only;
the default `Depth: 1` adds direct children; `Depth: infinity` recurses through
descendants for both workspace roots and nested folders), `GET`, `PUT`, `MKCOL`, `DELETE` (trashes),
`MOVE`, `COPY`, `LOCK`/`UNLOCK` (exclusive write locks are enforced by both
token and lock owner). Same bearer +
`x-shellx-actor`; Read for reads, Write for writes. `MOVE`/`COPY` reject a
cross-workspace `Destination`. `GET` streams disk-backed file bytes and honors
one HTTP `Range` request. `PROPFIND` bounds the workspace inventory and tree
to 10,000 active items and descendant traversal to 256 levels; parent cycles
and duplicate sibling names fail closed.

## Hosted mode

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/hosted/status` | Public | `HostedStatusResponse { hosted_mode, public_base_url, billing_provider, public_rate_limit_per_minute, public_signup_enabled, backup_scheduler, drop_malware_scanning }` |
| POST | `/hosted/signup` | Public | Reserved compatibility route; returns HTTP `403` in v0.1. Public hosted enrollment is unavailable until verified-email identity binding exists. |

## Local auth and 2FA

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/auth/bootstrap/status` | Public | — | `BootstrapStatusResponse { required }` |
| POST | `/auth/bootstrap` | Setup authority (until first account) | `BootstrapRequest { email, password, cookie_only? }` | `201 LoginResponse` |
| POST | `/auth/bootstrap/wizard` | Setup authority (until first account) | `BootstrapWizardRequest { email, password, workspace_name, storage_mode?, cookie_only? }` | `BootstrapWizardResponse { login, account, workspace, owner, receipt }` |
| GET | `/auth/registration/status` | Public | — | `RegistrationStatusResponse { enabled:false }` in v0.1 |
| POST | `/auth/register` | Public | `RegisterRequest { email, password }` | Reserved compatibility route; returns HTTP `403` in v0.1. Administrators create accounts; verified invitation links bind existing accounts to workspaces. |
| POST | `/auth/login` | Public | `LoginRequest { email, password, totp_code?, recovery_code? }` | `LoginResponse`; 2FA-needed → `202` with `requires_2fa=true` |
| POST | `/auth/logout` | Session | — | logout receipt |
| GET | `/auth/me` | Session | — | `MeResponse { actor, is_admin }` |
| GET | `/auth/sessions` | Session | — | `AuthSessionListResponse { sessions }` (own sessions only) |
| POST | `/auth/sessions/{id}/revoke` | Session | — | `AuthSessionMutationResponse` |
| POST | `/auth/password/change` | Session | `ChangePasswordRequest { current_password, new_password, totp_code?, recovery_code? }` | ok/receipt |
| POST | `/auth/password/reset/request` | Public | `PasswordResetRequest { email }` | Generic `202 PasswordResetResponse`; at most one active token/email per enabled account, with `debug_token` only for a newly published e2e token |
| POST | `/auth/password/reset/consume` | Public | `PasswordResetConsumeRequest { token, new_password }` | ok/receipt |
| POST | `/auth/2fa/setup` | Session | `TotpSetupRequest { password }` | `TotpSetupResponse { secret, otpauth_uri, qr_size, qr_modules, replacement_* }`; `qr_modules` is validated row-major `0`/`1` module data |
| POST | `/auth/2fa/enable` | Session | `TotpCodeRequest { code?, recovery_code?, password? }` | `RecoveryCodesResponse { recovery_codes, replacement_* }` |
| POST | `/auth/2fa/disable` | Session | `TotpCodeRequest` | account plus `replacement_*` |
| POST | `/auth/recovery-codes/rotate` | Session | `TotpCodeRequest` | `RecoveryCodesResponse { recovery_codes, replacement_* }` |

`LoginResponse`: `{ token_type, token?, session_id?, actor, is_admin,
requires_2fa, expires_at? }`. Passwords: min 12 chars, Argon2id-hashed.
Password and TOTP login enforce client and account-wide budgets. One verifier
pass is reserved during each active shared penalty; a correct proof clears it,
while a wrong reserved proof or later denial cannot extend the deadline.
Password reset and exact administrator unlock are the recovery paths.

Every successful self-service TOTP lifecycle mutation replaces the source
session atomically while revoking sibling sessions and Office capabilities.
Cookie callers adopt the new HttpOnly cookie. Explicit-Bearer callers receive no
session cookie and must adopt `replacement_token`; the other `replacement_*`
fields describe that session.

### Admin-token identity session bridge

A trusted external component verifies identity first, then an administrator
credential submits the resulting issuer, subject, and email claims to mint a
bounded Drive session.

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/auth/oidc/config` | Public | — | `OidcConfigResponse { enabled, flow, token_type, max_expires_in_seconds }` |
| POST | `/auth/oidc/exchange` | Admin token | `OidcExchangeRequest { email, issuer, subject, expires_in_seconds? }` | `OidcExchangeResponse { token_type, sso_token, session_id, actor, issuer, subject, expires_at }` |

## Admin

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/admin/summary` | Admin | — | `AdminSummary { service, totals, job_totals, recent_receipts, recent_activity }` |
| GET | `/admin/canonical-content?limit=&cursor=&query=` | Admin | — | `CanonicalContentResponse { items:[CanonicalContentItem], next_cursor?, access_generation }`; active canonical files appear once, never once per recipient/grant. `limit`: 1–100 (default 50); `cursor`: canonical file UUID; trimmed `query`: at most 120 bytes |
| GET | `/admin/canonical-content/{file_id}/share-details?kind=human\|guest\|ai&limit=&cursor=` | Admin | — | `CanonicalShareDetailsResponse { item, kind, entries, next_cursor?, access_generation }`; required `kind`; `limit`: 1–50 (default 25); `cursor`: canonical UUID |
| GET | `/admin/hosted/tenants` | Admin | — | `HostedTenantListResponse { tenants }` |
| POST | `/admin/hosted/tenants` | Admin | `CreateHostedTenantRequest { name, owner_email, plan?, billing_status? }` | `HostedTenantResponse { tenant, receipt }` |
| GET | `/admin/auth/users` | Admin | — | `AuthAccountListResponse { accounts }` (redacted) |
| POST | `/admin/auth/users` | Admin | `CreateAuthAccountRequest { email, password, is_admin? }` | `AuthAccountMutationResponse { account, receipt }` |
| PATCH | `/admin/auth/users/{email}` | Admin | `UpdateAuthAccountRequest { disabled?, is_admin?, reset_password?, reset_2fa? }` | `AuthAccountMutationResponse` |
| GET | `/admin/email` | Admin | — | outbox status with opaque `email_ref`/`related_ref`; raw capability relations and bodies omitted |
| GET | `/admin/registration-policy` | Admin | — | `RegistrationPolicyResponse { enabled:false, receipt? }` in v0.1 |
| PATCH | `/admin/registration-policy` | Admin | `RegistrationPolicyRequest { enabled }` | Persist the disabled posture; attempts to enable return HTTP `400` until verified-email enrollment exists |
| GET | `/admin/sessions` | Admin | — | `AuthSessionListResponse` (all issued SSO sessions) |
| POST | `/admin/sessions/{id}/revoke` | Admin | — | `AuthSessionMutationResponse` |
| GET | `/admin/app-tokens` | Admin | — | `AppTokenListResponse` (metadata only; no token or hash) |
| POST | `/admin/app-tokens` | Admin | `CreateAppTokenRequest { label, actor_email, workspace_ids, expires_in_seconds? }` | `CreateAppTokenResponse { app_token, token, receipt }` (plaintext token returned once) |
| POST | `/admin/app-tokens/{id}/revoke` | Admin | — | `AppTokenMutationResponse` |

Canonical-content routes are privileged product-management reads, not Debug
diagnostics: they return canonical file, owner, path, and current sharing
metadata needed by a current administrator, while omitting passwords, token
hashes, and agent plaintext tokens. Current administrator authority is
revalidated immediately before the buffered response is published, so a
concurrent session revoke or role loss denies that response.

### Backups, retention, sandbox, maintenance, support

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/admin/backups?limit=&cursor=` | Admin | Optional page limit (default 50, maximum 100) and returned cursor | `BackupListResponse { backups:[BackupMetadata], next_cursor? }`; complete generations and pending/failed create jobs |
| POST | `/admin/backups` | Admin | Optional `?format=v2`; v2 is the default and v1 creation is rejected | HTTP `202` with `BackupJobResponse { job, backup? }`; generation is queued, not complete |
| GET | `/admin/backups/{id}` | Admin | — | `BackupJobResponse { job, backup? }` for the latest durable job and available v2 metadata |
| GET | `/admin/backup-jobs/{job_id}` | Admin | — | Poll a durable create/validate/restore job: `BackupJobResponse { job, backup? }` |
| GET | `/admin/backups/{id}/download` | Admin | — | V2 binary `.sxdbackup` stream with `Content-Type: application/x-shellx-drive-backup`, exact `Content-Length`, attachment disposition, and `Cache-Control: no-store`; bounded v1 returns `BackupDownloadResponse { bundle, receipt }` JSON |
| POST | `/admin/backups/{id}/validate` | Admin | — | V2: HTTP `202` with `BackupJobResponse { job, backup? }`; bounded v1: synchronous `BackupValidationResponse { valid, backup, issues, receipt }` |
| DELETE | `/admin/backups/{id}` | Admin | — | `BackupMutationResponse` |
| GET | `/admin/backup-policy` | Admin | — | `BackupPolicyResponse { policy:{ enabled, schedule, retention_count, updated_at } }` |
| PATCH | `/admin/backup-policy` | Admin | `UpdateBackupPolicyRequest { enabled?, schedule?, retention_count? }` | `BackupPolicyMutationResponse` |
| POST | `/admin/backups/{id}/restore` | Admin | — | V2: HTTP `202` with `BackupJobResponse { job, backup? }`; bounded v1: synchronous `BackupMutationResponse { backup, receipt }` |
| POST | `/admin/retention/preview` | Admin | `RetentionRequest { workspace_id? }` | `RetentionPreviewResponse { dry_run:true, trash, revisions, totals, receipt? }` |
| POST | `/admin/retention/apply` | Admin | `RetentionRequest { workspace_id? }` | `RetentionPreviewResponse` (writes `retention.prune`) |
| GET | `/admin/sandbox` | Admin | — | `SandboxProfileResponse { profile }` |
| PATCH | `/admin/sandbox` | Admin | `UpdateSandboxProfileRequest { mode?, data_dir?, bind?, read_write_paths?, read_only_paths?, network_policy? }` | `SandboxProfileMutationResponse` |
| POST | `/admin/sandbox/preview` | Admin | — | `SandboxPreviewResponse { profile, commands, unit_preview }` |
| POST | `/admin/sandbox/apply-intent` | Admin | — | `SandboxApplyIntentResponse { profile, commands, unit_preview, receipt }` (records intent; does not mutate the host) |
| GET | `/admin/maintenance` | Admin | — | `MaintenanceStatusResponse { maintenance, receipt }` |
| POST | `/admin/maintenance/blobs/gc?min_age_seconds=` | Admin | — | Reference-aware orphan/temp blob sweep with counts, reclaimed bytes, and receipt |
| GET | `/admin/support-bundle` | Admin | — | `SupportBundleResponse { bundle, receipt }` (strict operational allowlist and log metadata; excludes user content, names, paths, identities, secrets, and the richer Debug export) |

`BackupMetadata`: `{ backup_id, format, created_at, table_count, row_count,
blob_count, content_bytes, archive_bytes?, job_id?, status?, phase?, last_error? }`.

`BackupJob`: `{ id, backup_id, kind, format, status, phase, actor,
archive_sha256, last_error, created_at, updated_at, started_at, finished_at }`.
The nullable job fields remain present; optional `BackupMetadata` fields and
`BackupJobResponse.backup` are omitted when unavailable. Poll
`GET /admin/backup-jobs/{job_id}` until the job reaches `succeeded`, `failed`,
or `interrupted`; `queued` and `running` are pending. A completed v2 archive is
unencrypted private restore material. Protect its storage and use an externally
trusted signature or checksum for origin/tamper evidence; the portable integrity
envelope validates structure and ordinary corruption. Restore recovers
content/catalog data while preserving the target instance's current security
authority, with historical credentials and grants kept inactive.

## Debug API

All routes require administrator authority: the configured operator credential,
or a current local/SSO/account-wide delegated actor whose authority is currently
administrator. App tokens and legacy folder agents are rejected. `/debug/e2e/*`
also require `--e2e`; ordinary agents use product receipts and readback instead.
Responses are redacted per the contract in
[docs/public/DEBUG_API.md](../../docs/public/DEBUG_API.md).

| Method | Path | Response focus |
|---|---|---|
| GET | `/debug/state` | `DebugState { service, data_dir, e2e_enabled }` |
| GET | `/debug/receipts` | receipts with opaque receipt/actor/target refs |
| GET | `/debug/activity` | paginated activity audit rows |
| GET | `/debug/agent-access?limit=` | bounded redacted agent-principal, current-token, and grant-health snapshot; accepts `limit` only (1–200, default 50) |
| GET | `/debug/app-tokens` | paginated app-token metadata without credentials |
| GET | `/debug/capabilities?workspace_id=` | server and effective workspace feature matrix |
| GET | `/debug/comments` | all comment threads + replies |
| GET | `/debug/folder-templates` | template metadata, opaque refs, and content presence/size; no item bodies |
| GET | `/debug/jobs` | background jobs + `BackgroundJobTotals { queued, running, succeeded, failed, skipped }` |
| POST | `/debug/jobs/run` | `BackgroundJobRunResponse { processed, succeeded, failed, skipped, jobs }` |
| GET | `/debug/previews/{id}` | preview status/dimensions/presence metadata; no preview or thumbnail body |
| GET | `/debug/downloads` | bounded file/preview/archive capability health and counters |
| GET | `/debug/browse` | bounded browse, page, and large-folder diagnostics without paths |
| GET | `/debug/search?q=` | `DebugSearchResponse { service, query, using_fts, query_plan, results }` |
| GET | `/debug/email` / POST `/debug/email/run` | outbox status with opaque email/relation refs / process capture queue once |
| GET | `/debug/sync` / `/debug/sync/changes` / `/debug/delta-sync` / `/debug/mobile-sync` | sync health / opaque-ref change feed / delta stats / mobile markers |
| GET | `/debug/notifications` | notification rows with opaque notification/relation refs and redacted bodies |
| GET | `/debug/office-sessions` | office session metadata (no raw tokens) |
| GET | `/debug/groups` | groups, members, grants, effective permissions |
| GET | `/debug/invitations` / `/debug/shares` / `/debug/drops` | rows + redacted attempt counters; share/drop capabilities use opaque refs |
| GET | `/debug/drops/{drop_id}` | bounded upload-session health with opaque `drop_ref`, without capability or file identity |
| GET | `/debug/imports` | paginated rclone import/export run state |
| GET | `/debug/storage-integrity` | bounded missing/orphan/corrupt blob-reference scan |
| GET | `/debug/sync/conflicts` | paginated sync-conflict backlog |
| GET | `/debug/webdav` | redacted lock capability and active-lock summaries |
| GET | `/debug/workspaces` | paginated redacted workspace inventory |
| GET | `/debug/file-access?limit=` | bounded redacted server-wide workspace access/download and tracked-file snapshot; accepts `limit` only (1–200, default 50) |
| GET | `/debug/file-tree` / `/debug/uploads` / `/debug/usage` / `/debug/policies` | tree snapshots / upload sessions / usage / policies |
| GET | `/debug/auth` / `/debug/auth-attempts` / `/debug/registration` / `/debug/sessions` | account+session metadata / failure counters / registration state / SSO sessions (all redacted) |
| GET | `/debug/hosted` / `/debug/backups` / `/debug/support-bundle` / `/debug/sandboxes` / `/debug/maintenance` | hosted posture / backup metadata / support-bundle metadata / sandbox previews / maintenance state |
| GET | `/debug/export` | redacted diagnostic snapshot (`token` always `null`) |
| POST | `/debug/retention/preview` | dry-run cleanup candidates (never writes) |
| POST | `/debug/e2e/seed` / `/debug/e2e/reset` | deterministic workspace+file / clear test data (**`--e2e`**) |
| POST | `/debug/e2e/expire-capability` | expire exactly one disposable `{ invitation_id }` or `{ password_reset_token }`; current administrator plus `--e2e`, returns `{ expired:true }` |
| GET | `/debug/e2e/human-sharing/cleanup?run_id=&actor_ids=&actor_emails=` | read-only exact-ID fixture cleanup probe; operator credential plus `--e2e`; `root_file_id`, `group_id`, and `actor_cleanup` are optional; returns `{ clean }` |
| DELETE | `/debug/e2e/human-sharing/groups/{group_id}?run_id=` | delete one named disposable group only after its fixture references are absent; operator credential plus `--e2e`; `204` |
| DELETE | `/debug/e2e/human-sharing/actors/{actor_id}?run_id=` | delete one run-marked disposable account only after fixture authority is absent; operator credential plus `--e2e`; `204` |
| GET | `/debug/twin/scenarios` | `TwinScenarioCatalog { scenarios, faults }` |
| POST | `/debug/twin/run` | `RunTwinScenarioRequest { scenario, faults?[] }` → `TwinScenarioRunResponse { scenario, faults, passed, workspace_id, file_id, assertions, receipt }` |

Cursor-paginated debug routes accept `limit` (`1..=200`, default `50`) plus
opaque `before`; routes with multiple event types may also accept `kind`.
Follow the returned page metadata until no next cursor remains.
`GET /debug/agent-access` and `GET /debug/file-access` are bounded snapshots:
they accept `limit` only, reject cursor/filter parameters, and report
`truncated:true` when additional aggregate rows were omitted. `POST /debug/twin/run` is a mutation and, like `/debug/e2e/*`, requires server `--e2e` mode.
