# ShellX Drive Debug API

The Debug API is the administrator diagnostics and automation-testability
surface for ShellX Drive. It is designed for authorized HTTP tooling, local
automation, release verification, and service-twin checks. It is intentionally
absent from the human Drive UI; account settings, workspace settings, and the
server-admin center expose supported operator workflows rather than raw protocol
exercisers.

Use the configured operator credential or a currently authorized administrator
session/account-wide delegation for these routes. Ordinary agents use their
authorized response receipt and product readback to verify product actions;
app and folder-scoped tokens retain their separate workspace or `/agent/v1`
scope. E2E mutation routes additionally require `--e2e` at server start.
Service-twin scenario execution additionally requires the configured operator
token. Use administrator sessions to inspect the catalog and the operator
credential to run the disposable fixture mutations.

`DEBUG_SURFACES.json` is the machine-readable source ledger for every
registered product, admin, debug, agent-safe, and intentionally excluded route.
Private maintainer checks extract literal Axum route registrations and fail
when the source inventory, this route index, or an oracle mapping drifts from
that ledger.

## Debug Route Index

```text
GET /debug/state
GET /debug/receipts
GET /debug/activity
GET /debug/agent-access
GET /debug/app-tokens
GET /debug/capabilities
GET /debug/comments
GET /debug/folder-templates
GET /debug/jobs
POST /debug/jobs/run
GET /debug/previews/{file_id}
GET /debug/downloads
GET /debug/browse
GET /debug/search?q=
GET /debug/email
POST /debug/email/run
GET /debug/sync
GET /debug/sync/changes
GET /debug/delta-sync
GET /debug/mobile-sync
GET /debug/notifications
GET /debug/office-sessions
GET /debug/groups
GET /debug/invitations
GET /debug/shares
GET /debug/drops
GET /debug/drops/{drop_id}
GET /debug/imports
GET /debug/storage-integrity
GET /debug/sync/conflicts
GET /debug/workspaces
GET /debug/file-access
GET /debug/file-tree
GET /debug/uploads
GET /debug/usage
GET /debug/policies
GET /debug/auth
GET /debug/auth-attempts
GET /debug/registration
GET /debug/hosted
GET /debug/backups
GET /debug/support-bundle
POST /debug/retention/preview
GET /debug/sessions
GET /debug/sandboxes
GET /debug/maintenance
GET /debug/webdav
GET /debug/export
POST /debug/e2e/seed
POST /debug/e2e/reset
POST /debug/e2e/expire-capability
GET /debug/e2e/human-sharing/cleanup?run_id=&actor_ids=
DELETE /debug/e2e/human-sharing/groups/{group_id}?run_id=
DELETE /debug/e2e/human-sharing/actors/{actor_id}?run_id=
GET /debug/twin/scenarios
POST /debug/twin/run
```

## Full debug API

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/debug/state` | Return service name, redacted data-directory posture, and whether e2e mode is enabled. |
| GET | `/debug/receipts` | Return mutation receipts in insertion order using opaque receipt, actor, and target references. |
| GET | `/debug/activity` | Return a bounded page of activity rows for audit-trail inspection. |
| GET | `/debug/agent-access` | Return a bounded agent-principal, current-token, and grant-health page. Principal, token, and actor ids are stable opaque references; names, paths, token values, and token hashes are omitted. Active-grant counts recheck current creator authority. |
| GET | `/debug/app-tokens` | Return a bounded page of app-token metadata without token values or hashes. |
| GET | `/debug/capabilities` | Return the server capability matrix; optional `?workspace_id=` adds the effective workspace capability matrix. |
| GET | `/debug/comments` | Return a bounded recent sample of up to 200 comment threads and 200 replies within a 1 MiB response budget for lifecycle inspection. `total_threads`, `total_replies`, and `truncated` describe omitted rows. Edited/deleted timestamps and tombstones are included. |
| GET | `/debug/folder-templates` | Return templates with opaque template/item/creator references plus content-presence and byte-count metadata; item bodies are omitted. |
| GET | `/debug/jobs` | Return background jobs and aggregate job totals. |
| POST | `/debug/jobs/run` | Drain the queued background jobs once on demand and return processed/succeeded/failed/skipped counts. Supplements the always-on in-process worker (which drains every ~4s in production); use this for deterministic, immediate assertions in tests and release gates. |
| GET | `/debug/previews/{file_id}` | Return preview status, dimensions, content-presence/byte-count, and thumbnail-presence metadata; preview text/body and thumbnail bytes are omitted. |
| GET | `/debug/downloads` | Return bounded capability health for single-file downloads, reusable media previews, and ZIP archives: active counts, source-byte/entry totals, capacity, expiry horizon, and aggregate issue/redeem/expire/reject counters. Raw tickets, names, paths, actors, and content are never returned. |
| GET | `/debug/browse` | Return the 100-item browser page contract, supported sort/filter keys, aggregate live/trashed counts, current file bytes, per-workspace maximum direct-child counts, and at most 50 large-folder summaries. Folder names and paths are omitted; folder ids are represented by stable hashed references. |
| GET | `/debug/search?q=` | Return ranked search results, matched fields, snippets, and SQLite query-plan evidence for one query. |
| GET | `/debug/email` | Return email outbox transport status and redacted message metadata with opaque email and relation references; bodies, reset tokens, raw capability ids, and SMTP secrets are omitted. |
| POST | `/debug/email/run` | Process queued email once for the capture transport and return the same redacted email outbox state. |
| GET | `/debug/sync` | Return service sync health plus background job totals. |
| GET | `/debug/sync/changes` | Return cursor-based sync changes with opaque entity, actor, and receipt references. |
| GET | `/debug/delta-sync` | Return delta sync write stats with sizes, hashes, chunk counts, and no raw chunk bytes. |
| GET | `/debug/mobile-sync` | Return mobile sync mode and offline-file markers. |
| GET | `/debug/notifications` | Return notification rows with opaque notification and relation references, redacted bodies, and read/unread state; raw share/drop capability ids are omitted. |
| GET | `/debug/office-sessions` | Return redacted office session metadata without raw session tokens or token hashes. |
| GET | `/debug/groups` | Return group, group member, workspace group grant, and effective permission state without bearer tokens or credentials. |
| GET | `/debug/invitations` | Return redacted pending/accepted/canceled invitation rows and collaborator-duration metadata without accept tokens or token hashes. |
| GET | `/debug/shares` | Return managed share lifecycle through opaque share references, download policy, note/limit presence, access counters, and redacted password-attempt counters without raw capability ids, passwords, password hashes, access-grant values, or grant hashes. |
| GET | `/debug/drops` | Return managed drop rows through opaque drop references and redacted password-attempt counters without raw capability ids, drop passwords, or password hashes. |
| GET | `/debug/drops/{drop_id}` | Return bounded Drop upload health with an opaque `drop_ref`: non-capability session references, states, byte counters, chunk counts, and error codes. It omits the raw drop id, raw session ids, file names, paths, MIME declarations, fingerprints, file ids, passwords, capability values, and body bytes. |
| GET | `/debug/imports` | Return a bounded page of rclone import/export run metadata, phases, and aggregate counts without file bodies. |
| GET | `/debug/storage-integrity` | Scan a bounded portion of blob references and disk entries for missing, orphaned, or corrupt blobs. Supports bounded `scan_limit`, `hash_bytes`, and `issue_limit` query controls. |
| GET | `/debug/sync/conflicts` | Return a bounded page of sync conflicts without raw file bodies. |
| GET | `/debug/workspaces` | Return a bounded page of redacted workspace inventory and aggregate membership/file state. |
| GET | `/debug/file-access` | Return a bounded server-wide page of workspace access/download totals and tracked-file counts. Workspace ids are stable opaque references; file ids, names, and paths are omitted. The manage-permission `GET /workspaces/{workspace_id}/file-statistics` route remains the detailed workspace oracle. |
| GET | `/debug/file-tree` | Return file tree snapshots for all workspaces without file bodies. |
| GET | `/debug/uploads` | Return resumable upload sessions as metadata plus aggregate states/bytes for offset, completion, cancellation, and cleanup assertions. It never returns part-file bodies, raw browser `File` objects, or paths outside the server data directory. |
| GET | `/debug/usage` | Return workspace quota/accounting state without content bodies or credentials. |
| GET | `/debug/policies` | Return workspace quota, sharing default, and retention policy state without credentials. |
| GET | `/debug/auth` | Return local account and session metadata without password hashes, TOTP secrets, recovery-code hashes, raw tokens, or token hashes. |
| GET | `/debug/auth-attempts` | Return login/2FA/share/drop failure counters and lockout timestamps without submitted secrets. |
| GET | `/debug/registration` | Return registration policy enabled state and local account count without passwords, password hashes, or bearer tokens. |
| GET | `/debug/hosted` | Return hosted posture and tenant metadata without billing secrets, passwords, tokens, or scanner credentials. |
| GET | `/debug/backups` | Return backup bundle metadata without blob bodies, base64 payloads, password hashes, or credentials. |
| GET | `/debug/support-bundle` | Return support bundle metadata without embedding full bundle payloads. |
| POST | `/debug/retention/preview` | Dry-run retention cleanup candidates without mutating files, revisions, or receipts. |
| GET | `/debug/sessions` | Return complete issued local and OIDC/SSO session history, including expired/revoked rows, without raw session tokens, server bearer tokens, token hashes, client IPs, or user-agent strings. Human account/admin session lists intentionally expose active rows only; raw network metadata is confined to the account's own session list and admin product surfaces. |
| GET | `/debug/sandboxes` | Return redacted sandbox profile state and install command previews. |
| GET | `/debug/maintenance` | Return redacted maintenance source labels and no-restart update policy state. `host_posture:"unassessed"` means Drive did not run an Ubuntu Pro/OS probe. |
| GET | `/debug/webdav` | Return the supported lock subset and at most 200 active-lock summaries. Lock tokens, token hashes, owner emails, and resource paths are replaced by bounded hashed references or aggregate metadata. |
| GET | `/debug/export` | Return a redacted diagnostic snapshot for tests and support. |
| POST | `/debug/e2e/seed` | Create a deterministic workspace and seed file. This requires --e2e. |
| POST | `/debug/e2e/reset` | Delete test metadata and blobs. This requires --e2e. |
| POST | `/debug/e2e/expire-capability` | Expire exactly one disposable invitation ID or raw password-reset capability for expiry-path tests. This requires admin auth and `--e2e`; normal servers return 403. |
| GET | `/debug/e2e/human-sharing/cleanup` | Read-only exact-ID cleanup probe for the private human-sharing harness. It requires the operator credential, `--e2e`, a `human-share-` run marker, and matching explicit disposable actor IDs/emails; it never enumerates or mutates ordinary accounts. |
| DELETE | `/debug/e2e/human-sharing/groups/{group_id}` | Delete exactly one named `{run_id}-group` only after its member, workspace-grant, and active human-grant references are absent. Requires operator admin auth and `--e2e`. |
| DELETE | `/debug/e2e/human-sharing/actors/{actor_id}` | Delete exactly one run-marked disposable account only after its private workspace is empty and it owns or receives no active fixture authority. Browser sessions and exact recipient-local evidence are removed first. Requires operator admin auth and `--e2e`. |
| GET | `/debug/twin/scenarios` | Return service twin scenario and fault catalog. |
| POST | `/debug/twin/run` | Execute a deterministic service twin scenario. |

## Pagination Contract

The cursor-paginated debug routes use `limit` (default `50`, allowed
`1..=200`) and an opaque `before` cursor. Routes that expose multiple event
kinds also accept a `kind` filter. Responses include `page` metadata with the
effective limit, whether more rows exist, and the next cursor. Treat cursors as
opaque and stop when the next cursor is absent.

`GET /debug/agent-access` and `GET /debug/file-access` are bounded health
snapshots rather than event streams. They accept `limit` only, reject cursor or
filter parameters, and set `truncated:true` when additional aggregate rows were
omitted. Callers should raise the limit up to 200 when they need a wider
snapshot.

Google Drive-compatible operations intentionally have no separate protocol counters.
They use the same file, content, receipt, download, and access-counter paths as
native Drive operations, so separate counters would duplicate state without
creating an independent oracle. Verify their effects indirectly through
`GET /debug/receipts`, `GET /debug/file-tree`, `GET /debug/downloads`, and
`GET /debug/file-access`.

Workspace access/download statistics now have two deliberate views:

- `GET /debug/file-access` is bounded, server-wide, aggregate-only evidence for
  agents, tests, and operators.
- `GET /workspaces/{workspace_id}/file-statistics` requires workspace Manage
  permission and remains the detailed product view with per-file names.

## Redaction Contract

Use `GET /debug/export` for test evidence and support diagnostics. The server
applies the following redaction contract before returning it:

- `token` is always `null`.
- Receipts, shares, drops, sync changes, email outbox rows, and notifications
  use opaque `*_ref` fields instead of raw capability or record ids. Email and
  notification relation ids are also opaque, so share/drop capabilities cannot
  be reconstructed. Capability-scoped attempt keys/actors are opaque; the
  admin unlock route accepts the returned opaque key.
- Preview and folder-template sections expose content presence and byte counts,
  keeping preview text, template item bodies, and thumbnail bytes private.
- Receipts, comments, folder templates, group state, workspace usage and policy
  state, file tree snapshots, backup metadata, backup policy, support bundle
  metadata, readiness state, maintenance history, redacted auth account
  metadata, auth attempt counters, session metadata, effective workspace
  permission explanations, file metadata, thumbnail metadata, ranked search
  evidence, opaque-ref email outbox metadata, opaque-ref notifications with
  redacted notification bodies, registration
  policy metadata, hosted posture and tenant metadata, office session metadata, file revision rows (including current/pinned state and byte counts), upload
  sessions, sync changes, delta sync stats, background jobs, previews, mobile offline markers,
  and bounded aggregate-only browse diagnostics,
  sandbox previews, WebDAV capability/active-lock summaries, and maintenance policy state may be included because they
  are needed for deterministic tests.
- Backup blob payloads, backup table rows, account password hashes, share/drop
  password hashes, limited-share access-grant values/hashes, invitation token hashes, reset tokens, submitted passwords,
  TOTP secrets, recovery-code hashes, raw session tokens, token hashes, raw
  chunk bytes, delta patch bodies, WebDAV lock tokens/hashes, lock-owner emails,
  lock resource paths, billing secrets, scanner credentials, and
  base64 content are not exposed through debug routes.
- Agent principal names, creator emails, raw principal/grant/token ids, token
  values, token hashes, workspace ids in access statistics, file names, file
  ids, and file paths are omitted or replaced by stable opaque references in
  the new health views.
- Debug retention preview is a dry run; `retention.prune` records an applied
  cleanup.
- Keep deployment-specific host names, SSH details, release evidence, and local
  credentials in private operator records outside debug responses.
- Use the documented redacted source/presence metadata for diagnostic credential
  status. Keep Ubuntu Pro tokens, sudo passwords, SSH private keys, SSO and
  local-account tokens, operator bearers, and token hashes private.

## E2E Contract

`POST /debug/e2e/seed`, `POST /debug/e2e/reset`, `POST /debug/e2e/expire-capability`, the three `/debug/e2e/human-sharing/*` routes, and `POST /debug/twin/run` are
disabled unless the server starts with `--e2e`. This keeps test mutations out
of normal server operation while preserving a fast local acceptance path.

## Service Twin Contract

The service twin route exposes these scenarios:

- `workspace_roundtrip`: creates a workspace and file, indexes content, drains
  queued jobs, then checks sync health and search.
- `preview_download_roundtrip`: creates a unique image, drains its preview job,
  and validates the immutable source plus one-use download and reusable preview
  capabilities.
- `browse_scale_roundtrip`: creates a nested folder tree and validates recursive
  logical sizes plus bounded aggregate browse diagnostics.
- `upload_roundtrip`: exercises resumable upload offsets, interruption, and
  finalization.
- `share_lifecycle_roundtrip`: exercises share access and its password/expiry
  faults.
- `collaboration_revision_roundtrip`: exercises comments, replies, and
  optimistic collaboration revisions.
- `webdav_lock_roundtrip`: exercises lock ownership, refresh, mutation, and
  unlock behavior.
- `backup_readiness_roundtrip`: exercises isolated backup-job lifecycle and
  readiness maintenance state.

The current supported faults are:

- `trash_before_assertions`: trashes the scenario file before assertions so the
  test can prove failures are surfaced correctly.
- `remove_blob_before_assertions`: temporarily removes a preview source blob.
- `truncate_blob_before_assertions`: temporarily truncates a preview source
  blob. Both source-blob injections restore the exact bytes before returning.
- `stale_revision_before_assertions`: attempts a stale update and proves the
  current revision is preserved while the write is isolated as a conflict.
- `trash_nested_before_assertions`: trashes the nested browse fixture before
  assertions so recursive-size and diagnostic failures are visible.

The preview/download scenario accepts at most one injected fault per run so a
failed assertion has one unambiguous cause. Responses contain scenario object
identifiers and assertion state, keeping capability tokens and blob paths private.

The service twin API is deliberately deterministic. Add new scenarios only when
they can be run in local and remote release gates without private context.
