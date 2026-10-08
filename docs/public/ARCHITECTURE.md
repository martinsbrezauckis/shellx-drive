# ShellX Drive Architecture

ShellX Drive is a Binary-first server built around SQLite metadata, filesystem
blob storage, and HTTP APIs for the headless reference SyncClient, the web UI,
and the current Windows, macOS, and Linux desktop applications.

## Storage Model

- SQLite metadata stores workspaces, users, membership roles, files, labels,
  custom file metadata, revision rows, upload sessions, receipts, activity,
  shares, drops, comments, folder templates, background jobs, file previews,
  mobile offline markers, invitation lifecycle rows, email outbox rows, hashed
  password reset tokens, auth attempt counters, cursor-based sync changes,
  notifications with read/unread state, backup policy, and support bundle
  metadata. Active WebDAV locks are SQLite-backed runtime coordination rows so
  they survive process restarts without being restored from historical backup
  archives.
- File bodies live in blob storage under the configured data directory.
- Every normal file-body delivery adapter (native content/download, WebDAV,
  Google-compatible media, Office package reads, mobile offline, share content,
  thumbnails, and covers) delegates to one disk-streaming response boundary.
  The boundary preserves `Range`/`206`, content length, and response hardening
  without allocating an entire Drive object in the server process. The current
  JSON delta manifest/reconstruction path is intentionally capped at 32 MiB;
  larger content uses resumable full-content upload until that algorithm is
  redesigned around disk-backed reconstruction.
- The legacy rclone v1 JSON exporter is the one intentionally bounded
  whole-object compatibility path. It fetches at most 10,000 active rows with
  a one-extra-row refusal query, then admits at most 8 MiB aggregate raw body
  bytes from metadata before reading blobs. Physical reads repeat the remaining
  cap and reject metadata/size mismatches. It preserves valid UTF-8 text and
  rejects non-UTF-8 bodies rather than converting bytes lossily. JSON escaping
  can expand the legacy wire response beyond the raw cap; it is not a binary or
  workspace-scale export path and does not add an unbounded Base64 alternative.
- Files reference blobs by content hash. Metadata changes and blob writes stay
  explicit so tests can inspect both layers.

One Drive service process owns a data directory, enforced by an exclusive
data-root instance lock before SQLite is opened. SQLite serializes metadata
transactions, and a cross-process blob lifecycle lock prevents a cleaner from
unlinking an object while a publisher is committing its reference, but the
request-admission, restore, resumable-session, and download/archive-ticket
coordinators are intentionally process-local. Running two Drive processes
against the same data directory is not a supported availability or restore
topology. Interrupted derived jobs are safely requeued within the same count,
byte, and terminal-history bounds as live admission. In v0.1, ticket capacity is per process and has no global fairness or
cross-instance admission scheduler; deployment must retain the one-process
topology instead of treating local ticket limits as a distributed control.

## Workspace Storage

ShellX Drive has one ordinary, server-readable workspace storage model. That
enables full-text search, previews, Office saves, WebDAV, the Google Drive API
subset, rclone-style export, and guest sharing. The persisted `storage_mode`
field remains `open` for wire/database compatibility; creation accepts only
that value and startup normalizes older experimental values to `open`.

For content privacy from the server or VPS operator, encrypt the payload locally
before upload and keep the encryption keys with the client. Drive stores the
resulting ciphertext bytes like any other file; ordinary uploads remain
server-readable.

## Client Model

The Drive-side `SyncClient` is a headless reference implementation of the
desktop-sync protocol, not an installed desktop application. It supports
multi-workspace clients by
filtering selected workspaces locally after actor-scoped `/sync/workspaces`
visibility, writing manifests under one cache root per workspace, downloading
file bodies, and uploading local changes. Manifests contain no more than 10,000
active rows. Both bundled clients stream each download into private staging,
enforce the manifest size plus a 2 GiB per-file ceiling, and verify the content
hash before publishing local bytes. New files and fully changed existing
binary files use resumable sessions; replacement intent persists the exact file
and optimistic base revision, and a stale terminal write preserves the uploaded
bytes as a conflict file rather than overwriting the newer target. Selected Drive workspaces can be
marked locally as not visible to an agent by writing safe-space metadata with
`local_agent_visible=false`; actual AI-worker authority is enforced by
no-login Drive principals and folder grants, not by a storage-encryption mode.
The first Share with AI action creates a named principal and reveals its one
key once. Later shares select that principal and add independent View/Edit
folder grants without minting another key. Removing one grant leaves the
principal's other folders intact. Account Settings rotates the principal-wide
key, invalidating the old key for every assigned folder. Principal inventory,
per-principal grant inventory, per-folder grant inventory, and the agent's own
grant discovery all use bounded keyset pages backed by cursor-aligned indexes;
the web UI loads additional folder grants only on request. Each reference-client
sync also reads conflict visibility from `/sync/conflicts`. The headless
`SyncClient` optionally attempts debug receipt correlation through the
administrator-only `/debug/receipts` route. If its credentials cannot read that
route, it omits the receipt summary and continues syncing. Ordinary desktop
authentication and verification do not require administrator credentials.

The desktop keeps bearer sessions only in the current user's protected
operating-system credential store: Windows Credential Manager, macOS Keychain,
or the Linux Secret Service. Its ordinary state may retain a bounded non-secret
session inventory containing only canonical server/account identity, session
ID, and expiry. Candidate credentials use a separate fixed platform store until
exact readback proves canonical publication; bearer values never enter
serializable state. Startup reconciles an interrupted candidate before polling,
and ambiguous reads fail closed without deleting either possible authorizer.

One signed-in server/account has one local Drive base folder. The user pages
through available roots and explicitly selects a first root and any later
additions. Up to 100 configured roots have safely named child folders beneath
that base. Each configured root has its own baseline, activity, reviews, access
state, and local directory identity. Refresh revalidates configured roots only;
new shares do not create local folders until selected. The root whose details
are currently shown in the desktop UI is not a sync selector. Duplicate remote
roots, overlapping local paths, and reuse of one v0.1 connection state with
another server or account are rejected. Named multi-Drive profiles for separate
cloud or local-network servers/accounts, each with its own named local base,
are planned after v0.1.1 and are not implied by this automatic-root model.

Disconnect first persists a bounded, non-secret journal of every configured
location marker and the typed canonical/candidate credential slots. If remote retirement
cannot be confirmed, the pair and credentials remain intact, sync/setup are
blocked, and the desktop shows one explicit remote-retirement retry. Only after
every known remote session is revoked or already invalid does Drive persist the
disconnected projection and remove the exact marker and credential slots. Each
local cleanup acknowledgement is saved independently, so a crash resumes only
the unfinished exact operations. Disconnect preserves the sync root and
ordinary user files.

The first-release principal is creator-owned and portable across the folders
that creator is allowed to share. Human workspace membership and the worker's
folder grants are separate lifecycles: removing the creator from a workspace
does not silently remove the worker. Any human with Write authority on a shared
folder can remove that one grant. The creator can globally remove the worker in
Account Settings; Drive then atomically disables the principal, revokes all of
its keys and grants, hides it from normal selection, and retains audit history.

Client-encrypted files need no dedicated Drive integration. A user may place an
encrypted archive anywhere in Drive as an ordinary file. Drive stores and
transfers those opaque bytes without encryption-specific folders, keys,
validation, or restore behavior.

Mobile clients use metadata-first sync. They list workspaces and files, mark
specific files for mobile download, then download only those marked files while
online. That keeps mobile storage predictable and avoids background conflict
churn.

The web UI is also an installable PWA. Its service worker caches the app shell
and static assets only; authenticated API responses stay out of Cache Storage.
For phone offline browsing, the app writes metadata-only mobile manifest snapshots
scoped by actor and workspace into browser storage after successful
`/sync/mobile/*` loads. This web build never stores marked file bodies: a
mobile client downloads each marked file while online. The camera upload path is
not a separate mobile backend: capture input feeds the existing resumable upload
path, preserving upload receipts, debug visibility, and background
preview/search processing. Browser upload orchestration lives in
`web/drive-uploads.js`, not the main controller. It preflights duplicate/path
and capacity conflicts, schedules at most three files, sends bounded raw binary
chunks, and persists only session, fingerprint, and progress metadata. File
bodies remain in the browser `File` object and are never written to local
storage; after reload, the user reselects a file and a bounded first/last-chunk
fingerprint plus declared size prevents resuming with different bytes.

Browser collaboration orchestration lives in `web/drive-collaboration.js`.
That module owns comment/reply lifecycle, revision-history controls, the single
guest-link settings source, and invitation expiry presentation; `web/drive.js`
retains only shared session/navigation composition. The same domain split is
enforced server-side through `src/storage/{comments,revisions,shares}.rs`,
`src/routes/files/revisions.rs`, and `src/routes/shares/management.rs` so new
collaboration behavior does not grow the legacy storage and route roots.

WebDAV remains an adapter over the normal file tree rather than a second
filesystem model. `src/routes/webdav.rs` composes operations,
`src/routes/webdav/paths.rs` owns path/destination resolution, and
`src/routes/webdav/locks.rs` owns the supported exclusive-lock protocol and XML
contract. Persistent lock scope/conflict/expiry logic lives in
`src/storage/webdav.rs`; redacted capability and active-lock diagnostics live in
`src/routes/debug/webdav.rs`. Lock rows bind to stable file identity, so a lock
continues to protect a moved resource while current lock-discovery XML derives
its new path from the file tree. These locks constrain DAV requests only.
Native JSON writers and configured office editors use the ordinary optimistic revision
writer, so clients must provide `base_revision` and handle stale-revision
conflicts across protocol boundaries.

The sync change feed is cursor-based. Receipts are mapped into workspace/file,
comment, share/drop, upload, import, invitation, retention, and admin event rows
so desktop and future mobile clients can ask for incremental changes instead of
polling complete manifests after every action.

Drive owns authorization, package storage, revisions/conflicts, edit-session
tokens, and provider launch. The configured provider owns the editor.
Drive launches it through a bounded one-use same-origin handoff that POSTs the
durable capability instead of placing it in a URL. Once the Office engine is
available, it renders and edits native packages through a token-scoped Drive session, and Drive commits the returned
bytes with its ordinary optimistic revision writer. Until then, Drive provides
the storage/session bridge and manual API saves only. Drive has no built-in editor dependency.
Debug routes expose only office session metadata, never raw
edit-session tokens, token hashes, bearer tokens, or package bodies.
Terminal Office saves atomically claim their single-use token before writing,
and account security events revoke all outstanding edit sessions for that actor.

Notifications provide a user-facing inbox. Collaboration
events create recipient-scoped notification rows with read/unread state for
comments, shares, invitations, drop uploads, and sync conflicts. Debug routes
redact notification bodies and replace notification and relation ids with opaque
correlation references, because the raw context can include share/drop
capabilities; receipts and activity remain the durable operator evidence.

Comment deletion is logical: bodies become tombstones with `deleted_at`, while
thread/reply structure and receipts remain for chronology and audit. Guest links
are always read-only and may independently disable downloads, show a recipient
note, or limit fresh visits. Every successful metadata visit mints a one-hour
opaque access grant (bounded by link expiry) so the browser can load thumbnails,
previews, and downloads without repeating expensive password checks. A limited
visit uses that same grant so the browser that consumed the use can continue
reading while new sessions are denied after exhaustion. Workspace viewer/editor invitations remain a separate
collaboration contract, and Upload Drops remain the separate guest-upload
contract. Accepted finite invitations become direct memberships with an
absolute expiry that is filtered during effective-permission checks.

## Editing And Conflicts

The primary write model is optimistic revision control:

- `PUT /files/{file_id}/content` and `POST /office/files/{file_id}/save`
  require a `base_revision`.
- `PUT /sync/files/{file_id}/delta` reconstructs fixed-size delta sync writes
  from chunk copy/data operations and then uses the same optimistic revision
  commit path.
- Matching revisions update the file and create a receipt.
- Stale revisions create a conflict copy and return HTTP 409.
- Rename, move, label, and custom metadata updates also advance the file
  revision so sync clients see metadata-only changes.
- Restoring an older content revision creates a new current revision rather
  than rewriting history.
- Revision pinning protects selected historical rows from retention cleanup.
- Historical revision downloads use short-lived one-use capabilities. Explicit
  delete and policy prune refuse current or pinned rows and report stored plus
  reclaimable bytes before and after mutation.
- Folder copy/trash/restore operations are recursive, and bulk actions operate
  over explicit file id lists. Trash, restore, star, and unstar are strict
  transitions: Drive validates the complete selected set in one immediate
  storage transaction before it changes a row or creates a receipt. Mixed or
  already-target-state requests fail with validation and preserve revisions,
  timestamps, and receipts.

Agents and manual editors can both use the same save path.

Public Drop uploads use the same reservation-first principle as authenticated
resumable uploads. Session creation transactionally counts the declared bytes
against client, Drop, workspace, and server-wide limits before any body is
accepted. Cancelled, failed, and stale sessions release their reservation;
completed sessions continue to consume the public-upload budget while their
created file remains stored, independently of the optional general workspace
quota.

## Operations

Self-hosted operation is binary-first. The server persists sandbox intent,
backup policy, maintenance check receipts, and support bundle metadata in
SQLite so an admin can inspect and test the deployment without SSHing into the
data directory for common tasks.

The email subsystem provides a capture outbox. Password resets, invitations,
share notices, and comment notices write redacted-inspectable rows during user
actions; the debug/admin queue runner processes them deterministically for
inspection. Its `sent` status records capture processing rather than recipient
delivery. Deliver invitation and share links through a trusted channel. For
password recovery, an authenticated server administrator creates a one-time,
short-lived manual link for an existing account and delivers it through that
channel. Only its hash is stored, and the link is returned once to that
administrator. SMTP settings appear as source labels in debug/admin responses;
the supported delivery workflow is manual.

First-run onboarding is a local-auth extension rather than a separate identity
system. Both bootstrap routes require explicit server authority before they
accept the first administrator credentials. When configured, the separate
bootstrap token is accepted only by those routes; legacy installations fall
back to the operator bearer. Every mode, including loopback and `--e2e`, requires
that authority. The wizard route creates the first admin and first workspace,
then uses the same revocable local session path as normal login. Subsequent
accounts are administrator-created. Email is the account identity key;
invitation capabilities bind the signed-in existing account whose normalized
email matches the invitation.

Browser-session network metadata follows a strict audience split. An account
may list IP/browser metadata only for its own active sessions and sign-in
history; a server admin may list all active sessions and the separate
server-wide security-event ledger. Workspace
owners and share owners receive aggregate access/download statistics, never
guest identities or IP addresses. Debug and support exports continue to use the
redacted session model and do not inherit raw network metadata.

The security ledger records bounded route templates, outcomes, status codes,
credential classes, and optional opaque HMAC target references. It never stores
raw capability URLs, credentials, query strings, request bodies, or file
content. Unmatched-route scanner noise is not persisted. Matched requests with
no resolved identity retain one representative event per client, route,
method, and status in each 60-second window, with a process-wide ceiling of 256
partitions. Invalid app/agent prefixes remain anonymous and use the same
admission policy; only active credentials retain their app/agent class.
Successful logins are retained. Failed/blocked logins and successful guest
capability requests retain one representative per target/outcome in each
15-minute process-local window, with a ceiling of 512 partitions. Low-authority
rows have a 20,000-row sub-cap within the 100,000-row total. Count-based pruning runs once
per bounded insertion batch and prunes to one-batch headroom, avoiding both
sparse-rowid over-deletion and an unbounded per-event scan. Failed access to the
admin ledger is audited, while successful polling is suppressed. Rows are
retained for 90 days; completed session network metadata ages out on the same
window.

Hosted mode adds an optional metadata layer to self-host mode and is disabled
by default. When enabled, tenants are explicit rows above
workspaces and workspaces require a `tenant_id`; public hosted signup remains a
disabled compatibility route until verified-email enrollment exists. Billing provider, backup scheduler, drop malware scanning, and
public rate-limit posture are reported as configuration/status labels. Billing
and scanner operations remain operator-managed outside the binary.

Backups default to deterministic `.sxdbackup` v2 archives under the configured
data directory. Durable single-lease jobs stream transactional SQLite rows as
JSONL and raw content-addressed blobs. New archives include a bounded private
restore-integrity envelope, so the one downloaded artifact can be copied to a
fresh Drive data directory and validated/restored without a source-host
sidecar/key. Authenticated bounded sidecars remain a local catalog cache and
support the pre-portability v2 compatibility lane. Durable instance-local
provenance prevents a managed generation from becoming a portable import merely
because its sidecar disappeared. Validation and restore are
streamed jobs; restore holds a generation-wide write gate and commits all
database rows atomically. Archives are unencrypted and operator-readable, so
deployment storage controls protect every copy. The self-contained envelope
detects ordinary corruption and is never treated as trusted authorization or an
attacker-resistant provenance signature; protected storage or an externally
trusted signature/checksum supplies that stronger property. Bounded v1 JSON
read/delete compatibility remains during migration, but v1 creation is disabled.
Debug routes return metadata only. Support bundles never include backup blob
payloads or raw credentials.

The backup implementation is split by responsibility: `routes/backups.rs`
owns HTTP contracts, `routes/backups/catalog.rs` owns local catalog sidecars and
portable archive identity, `routes/backups/worker.rs` owns durable scheduling
and state machines, and `routes/backups/legacy.rs` contains the bounded v1
migration lane. SQLite backup methods live in `storage/backups.rs`; the hostile
v2 fixture corpus is isolated from the production reader/writer. The web shell
loads its backup controller as a separate same-origin asset instead of growing
the main Drive controller. TOTP setup receives a bounded, validated QR module
matrix generated by the server with the registry-pinned `qrcodegen` crate; the
browser only paints that matrix and ships no independent QR encoder.

Resumable uploads use the same split. `routes/uploads.rs` owns session lifecycle
and the compatibility JSON contract, while `routes/uploads/binary.rs` owns the
raw octet-stream boundary and `routes/uploads/preflight.rs` owns bounded batch
planning. `routes/uploads/locking.rs` isolates crash-recoverable per-session
serialization. SQLite session and preflight queries live in `storage/uploads.rs`.
Per-session locks serialize chunk writes with cancel, acknowledged offsets are
checked against the partial file before each append, and failed finalization
rolls back unacknowledged bytes. The preferred browser path uses raw chunks;
the bounded JSON/Base64 route remains available for older clients.

The same boundary rule applies to daily-use browsing. Recursive folder
aggregates and bounded browse diagnostics live in `storage/files.rs`; browser
ordering, filters, persisted preferences, and paging live in
`web/drive-browser.js`; browse-specific service-twin behavior lives under
`routes/service_twin/`.

Service readiness is separate from liveness. `GET /health` answers whether the process
is alive; `GET /ready` reports live/ready/degraded state, storage reachability,
backup policy state, and restore maintenance. Host Ubuntu Pro/package posture is
shown as `unassessed` because the binary does not run a host probe; it is
informational and does not falsely degrade readiness.

## Background Work

Background jobs exist for derived server-side data such as previews, thumbnails,
and search-index refresh. A background worker runs inside the server process and
drains the queued-jobs table automatically on a fixed ~4-second interval; its
first tick fires immediately after boot, so any backlog left by a prior run
clears shortly after startup. No cron or external trigger is needed in
production — uploading a file and waiting a few seconds is enough for its
preview/thumbnail to appear.

The text-derived path recognizes UTF-8 text, Office Open XML packages
(`.docx`, `.xlsx`, `.pptx`), and OpenDocument packages (`.odt`, `.ods`, `.odp`).
It extracts bounded text from their XML package entries for search and an
inspector excerpt; it does not render document layout or act as an editor.
Legacy binary Office names (`.doc`, `.xls`, `.ppt`) are classified separately so
their arbitrary binary bodies are neither parsed as ZIP/XML packages nor treated
as plain text. They receive an explicit unsupported preview state.

The Debug API can still list jobs, drain queued work once on demand
(`POST /debug/jobs/run`), and inspect generated previews. That manual drain is
what makes background processing deterministic in local and remote release
gates: a test drains the queue itself and asserts immediately instead of waiting
on the timed worker.

## Source Distribution

The published source contains product code, public guides, packaging inputs,
build and dependency verification scripts, and web assets. An explicit file
list defines the public export for each source snapshot. Maintainer test
suites, fixtures, and acceptance harnesses are maintained privately.

Public CI covers formatting, compilation, linting, dependency audits, retained
backport verification, and SBOM generation and scanning. Release qualification
additionally uses private feature tests, packaging and installer checks,
publisher and signature verification, and installed application evidence.
