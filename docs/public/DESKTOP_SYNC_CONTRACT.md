# ShellX Drive — Desktop Sync Protocol Contract

**Status:** protocol, headless reference-client, and shared desktop-source
contract maintained with the current source tree. Each release candidate binds
this contract to an exact commit in its identity manifest; release qualification
also verifies the signed installed client separately.

This generic desktop-sync contract transfers every payload under the same
ordinary Drive file rules.

This document is self-contained: a fresh engineer can implement a two-way
desktop sync client from it alone, without reading the Drive server source. It
covers auth, every route a sync client needs (request/response shapes), the
content-hash algorithm, folder/path representation, revision and conflict
semantics, size thresholds, and the exact rules the bundled reference client
(`src/sync_client.rs`, `shellx-drive-sync`) implements so a second
implementation can match its behavior byte-for-byte where it matters.

All JSON. All timestamps RFC 3339 strings. Identifiers are opaque protocol
strings: preserve the returned values and apply each field's current
type-specific validation. UUID requirements apply only where that identifier's
contract explicitly requires them. Shared-root identifiers can use other
protocol forms, such as `item-grant:<grant-id>`. Treat identifiers as identity
values and validate filesystem locations with the path rules below. Keep path,
capability, and UUID validation specific to each field's contract.

---

## 1. Authentication

Every route below (unless marked public) requires an authorization bearer.
Normal user-scoped clients send:

```
Authorization: Bearer <current-user-session-or-account-wide-delegation>
```

Normal user-scoped sync accepts either of these credential shapes:

- An **SSO/local-login token** (`sso.v1`, minted by `POST /auth/login` or
  `POST /auth/oidc/exchange`). It carries its own actor identity.
- An account-wide delegated **`sxd_agent_` token**. It is revalidated as its
  owner's current authority on every request; a local owner can retain current
  administrator authority, while an external SSO delegation remains bound to
  its exact live ordinary-user parent session.

The configured **server bearer token** (`SHELLX_DRIVE_TOKEN`) is an operator
credential. With no actor header it runs as
`system@local`. An operator-controlled test or server-admin invocation may add:

```
x-shellx-actor: user@example.test
```

The request is then evaluated with that user's workspace roles (owner / editor /
viewer). Reserve this credential and header for operator work. A desktop client
that backs a specific user uses that user's session or an account-wide
delegation, so `/sync/workspaces` returns
only the authority's visible workspaces and writes are attributed correctly.

Use a user session or account-wide delegation for account-wide sync discovery.
Folder-scoped `sxd_agent_` bearers retain their `/agent/v1` subtree scope, and
workspace app tokens retain their explicit workspace allowlist.

`Read` permission is required for manifest + download routes; `Write`
(editor/owner) for create/update/upload routes.

---

## 2. Content hash — the change-detection primitive

The single hash used everywhere the sync client compares content is:

```
content_hash = lowercase_hex( SHA-256( raw_file_bytes ) )
```

- 64 lowercase hex characters.
- Computed over the **exact stored bytes** of the file body. Drive can read
  ordinary file bodies. If a caller uploads client-encrypted content, the hash
  covers those ciphertext bytes without Drive becoming the encryption owner.
- Exposed on every file in the sync manifest as `content_hash` (`null` for
  folders and for a zero-length/never-written file).
- The same hash is used by the resumable blob store, the delta chunk manifest
  (`content_sha256`), and delta validation (`expected_content_sha256`).

A sync client detects a **remote change** by comparing a file's manifest
`content_hash` against the hash it recorded at the last successful sync. It
detects a **local change** by re-hashing the local file and comparing against the
same recorded value. No mtime/etag is needed or exposed for content comparison —
the hash is the source of truth. (`created_at` / `updated_at` are server wall
clocks for display; use revisions and content hashes for conflict decisions.)

---

## 3. Data shapes

### 3.1 Workspace

```jsonc
{
  "id": "0192...-7...",
  "name": "Personal",
  "storage_mode": "open",
  "created_at": "2026-07-09T12:00:00+00:00",
  "updated_at": "2026-07-09T12:00:00+00:00",
  "archived": false,
  "archived_at": null,            // present only when archived
  "tenant_id": null,              // hosted mode only
  "role": "owner" | "editor" | "viewer"  // present on actor-scoped listings
}
```

- `storage_mode: "open"` is retained for compatibility. Drive has one ordinary,
  server-readable workspace storage model.

### 3.2 DriveFile (manifest entry)

```jsonc
{
  "id": "0192...-7...",
  "workspace_id": "0192...-7...",
  "parent_id": "0192...-7..." | null,   // null = workspace root
  "name": "report.txt",
  "kind": "file" | "folder",
  "revision": 3,                        // monotonic per file; see §6
  "trashed": false,
  "starred": false,
  "content_hash": "<64 hex>" | null,    // see §2; null for folders
  "created_at": "...",
  "updated_at": "...",
  "size_bytes": 1234 | null,            // stored byte length; null for folders
  "has_cover": false                    // folder cover image present (ignore for sync)
}
```

---

## 4. Folders and paths

Drive represents hierarchy by **parent id**, not by path string:

- Every file/folder has `parent_id`. `null` means the workspace root.
- A folder is a `DriveFile` with `kind: "folder"` (no `content_hash`).
- To place a new file inside folders that may not exist yet, you have two
  options:
  1. **Create the folders explicitly** (`POST /files` with `kind: "folder"`,
     supplying `parent_id`) and then create the file under the resulting folder id.
  2. **Supply a relative `path`** on the create/upload request (see below). The
     server materialises the intermediate folders idempotently under the target
     `parent_id` and lands the file at the leaf segment. Each path segment is
     validated: no `..`, no absolute paths, no empty segments, no path separators
     inside a segment, no control characters — traversal is rejected with `400`.

`path` uses forward slashes, e.g. `docs/2026/report.txt` (mirrors a browser
`webkitRelativePath`). When `path` is set, the request's `name`/`parent_id`
become the leaf name and the resolved leaf parent.

A client that wants a faithful local tree mirror should walk the manifest by
`parent_id` to reconstruct paths. The bundled reference client intentionally
mirrors bodies **flat by file id** (see §9) and uploads new local files to the
workspace root; a production Drive client should use `parent_id`/`path` to
preserve the tree.

---

## 5. Reading the remote state (download)

### 5.1 List workspaces

```
GET /sync/workspaces
```

Response:

```jsonc
{ "mode": "multi_workspace", "workspaces": [ Workspace, ... ] }
```

Actor-scoped: with `x-shellx-actor`, only that actor's workspaces (each with its
`role`).

### 5.2 Workspace manifest (full desktop sync)

```
GET /sync/workspaces/{workspace_id}/manifest
```

Requires `Read`. Response:

```jsonc
{
  "workspace_id": "...",
  "mode": "full_desktop_sync",
  "files": [ DriveFile, ... ]   // active files and folders only
}
```

The manifest is the authoritative active remote snapshot. Trashed rows are
excluded; use the change feed to reconcile deletions. Filter to
`kind == "file" && content_hash != null` for downloadable bodies.

### 5.3 Download a file body

```
GET /files/{file_id}/content     // inline; honors Range, 206 Partial Content
GET /files/{file_id}/download    // same bytes, forced attachment
```

Requires `Read`. Returns raw bytes (`application/octet-stream` on the download
path). The bytes hash to the file's `content_hash` (§2).

### 5.4 Incremental change feed (optional)

```
GET /sync/changes?cursor=<n>                       // across visible workspaces
GET /sync/workspaces/{workspace_id}/changes?cursor=<n>
```

Response:

```jsonc
{ "cursor": 0, "next_cursor": 42, "changes": [
  { "id": 42, "workspace_id": "...", "kind": "...", "entity_type": "file",
    "entity_id": "...", "actor": "...", "receipt_id": "...", "created_at": "..." } ] }
```

Poll with the last `next_cursor` to page forward. This is an optimization for
large workspaces; a correct client can also just diff the full manifest against
its recorded state each pass (the reference client does the latter).

---

## 6. Revisions

- Each file has a monotonically increasing integer `revision`, starting at `1`
  on create.
- **Any** content write bumps the revision by 1 and appends a `file_revisions`
  row. A rename/move (`PATCH /files/{id}`) also bumps the revision **without**
  changing `content_hash`. Therefore: to compare *content*, compare
  `content_hash`; use `revision` only as the optimistic-concurrency base for a
  write (§7). Always take the `base_revision` for an update from the **current
  manifest** value, not from an older recorded revision, so a remote rename does
  not falsely trip a conflict.

---

## 7. Writing to the remote (upload / update)

### 7.1 Create a new file — simple path

```
POST /files
Content-Type: application/json

{ "workspace_id": "...", "name": "note.txt", "kind": "file",
  "content": "<utf-8 string>", "parent_id": "..."|null, "path": "a/b/note.txt"|null }
```

- `content` is a JSON string → **UTF-8 only**. Use the resumable path (§7.2)
  for binary or large content.
- `201 Created` → `{ "file": DriveFile, "receipt": Receipt }`. The returned
  `file.content_hash` equals `SHA-256` of the bytes you sent.
- Rejected when over quota.

### 7.2 Create a new file — resumable path (binary-safe, large)

Use when the content is **not valid UTF-8** or exceeds the simple-path size
threshold (§8). This create form opens a new file; the same resumable route can
replace an existing file with `target_file_id` and `base_revision` (see §10).

Step 1 — open a session:

```
POST /uploads/resumable
{ "workspace_id": "...", "name": "photo.jpg", "total_size": 1500000,
  "parent_id": "..."|null, "path": "album/photo.jpg"|null }
```

`total_size` is **required** (declared full byte length, `0..=2 GiB`).
`201 Created` → `{ "session": UploadSession }` with `session.id` = `upload_id`.

Step 2 — append chunks in order:

```
PUT /uploads/resumable/{upload_id}
{ "offset": 0, "content_base64": "<base64 of chunk>", "finish": false }
```

- `offset` must equal the session's current `received_bytes` (else `409`).
- Send either `content` (UTF-8 text chunk) **or** `content_base64` (binary),
  never both.
- Set `"finish": true` on the last chunk; then `received_bytes` must equal the
  declared `total_size`.
- Non-final chunk → `{ "session": UploadSession, "file": null, "receipt": null }`.
- Final chunk → `{ "session": ..., "file": DriveFile, "receipt": Receipt }`; the
  new file id is `file.id`, its content hashes to `file.content_hash`.

Keep each chunk comfortably under the global request body limit (§8). The
reference client uses 512 KiB raw chunks.

Other session routes: `GET /uploads/resumable/{upload_id}` (inspect),
`POST /uploads/resumable/{upload_id}/cancel`,
`GET /workspaces/{workspace_id}/uploads` (list the caller's sessions; administrators can list all sessions).

### 7.3 Update an existing file's content — simple path

```
PUT /files/{file_id}/content
{ "base_revision": <int>, "content": "<utf-8 string>" }
```

- **UTF-8 only** (JSON string), like §7.1.
- `base_revision` = the file's current `revision` from the manifest.
- `200 OK` → `{ "file": DriveFile, "receipt": Receipt }` with `revision`
  bumped by 1 and the new `content_hash`.
- `409 Conflict` (stale base) → see §7.5.
- Uploading identical bytes still creates a new revision. Compare `content_hash`
  first and call this route only when the content has changed.

### 7.4 Update an existing file's content — delta path (binary-safe, incremental)

Use when the new content is not valid UTF-8, or is large but only partially
changed. Both this route and the resumable replacement route in §10 accept
binary content.

Step 1 — fetch the current chunk manifest:

```
GET /sync/files/{file_id}/chunks?chunk_size=<bytes>   // default 1 MiB, max 16 MiB
```

Response:

```jsonc
{ "file_id": "...", "workspace_id": "...", "revision": 3,
  "content_bytes": 4194304, "chunk_size": 262144,
  "content_sha256": "<64 hex>",
  "chunks": [ { "index": 0, "offset": 0, "length": 262144, "sha256": "<64 hex>" }, ... ] }
```

Step 2 — build an ordered operation list that reconstructs the **new** content
out of `copy` (reuse an unchanged base chunk by index) and `data` (send changed
bytes) operations, then:

```
PUT /sync/files/{file_id}/delta
{ "base_revision": 3, "chunk_size": 262144,
  "operations": [
    { "kind": "copy", "source_index": 0 },
    { "kind": "data", "content_base64": "<base64 of changed chunk>" }
  ],
  "expected_content_sha256": "<sha256 of full new content>" }
```

- A `data` op may carry `content` (UTF-8) **or** `content_base64` (binary), not
  both.
- The server reconstructs the full blob, verifies `expected_content_sha256` if
  supplied, and commits it through the **same** optimistic-revision writer as
  §7.3.
- `200 OK` → `{ "file": DriveFile, "receipt": Receipt, "delta": DeltaWriteStats }`.
- `409 Conflict` (stale base) → see §7.5.
- Limits: `operations` ≤ 2048; `chunk_size` 1..=16 MiB; reconstructed ≤ 32 MiB;
  **and** the whole request body ≤ the global limit (§8). A full-replacement of
  a large file whose bytes all changed uses the resumable replacement path in
  §10 instead of embedding all changed bytes in one delta request.

A simple aligned differ (chunk the new content by `chunk_size`; `copy` when new
chunk `i`'s SHA-256 equals base chunk `i`'s, else `data`) is sufficient and is
what the reference client uses.

### 7.5 Conflict semantics (stale base revision)

If `base_revision` != the file's current server revision (another writer moved it
first), the write does **not** overwrite the current content. Instead the server:

1. Creates a **new** file named `"<name> (conflict <timestamp>)"` (revision 1)
   holding the bytes you submitted,
2. leaves the original file untouched,
3. notifies workspace members, and
4. returns `409 Conflict` with:

```jsonc
{ "error": "stale_revision", "file_id": "<original id>",
  "attempted_base_revision": 3, "current_revision": 5,
  "conflict_file_id": "<new conflict copy id>", "receipt": Receipt }
```

These conflict copies are listed by `GET /sync/conflicts`:

```jsonc
{ "conflicts": [ { "workspace_id": "...", "file_id": "<conflict copy id>",
  "conflict_of_file_id": "<original>", "name": "...",
  "conflict_of_revision": 3, "created_at": "..." } ] }
```

A well-behaved client avoids server-side conflicts by (a) taking `base_revision`
from the freshest manifest and (b) not uploading when it has already detected
that both sides changed (it resolves that locally — see §9). If a `409` still
occurs (a race), treat it as a conflict: the server kept a copy of your bytes;
re-fetch the manifest and reconcile.

---

## 8. Size thresholds and the request body limit

- The server applies the framework default **request body limit of 2 MiB** to
  every JSON route (`POST /files`, `PUT …/content`, `PUT …/delta`, each resumable
  chunk). There is no per-route raise for these.
- Therefore a client must:
  - Use `POST /files` / `PUT …/content` only for **valid UTF-8** content up to a
    conservative size. The reference client's threshold is **1 MiB**; above it,
    or for any non-UTF-8 bytes, it switches to the chunked paths.
  - Keep each **resumable chunk** and each **delta request** under 2 MiB
    (base64 inflates ~1.37×, so cap raw chunks near 512 KiB–1 MiB).
- Resumable `total_size` hard cap: **2 GiB**. Delta reconstructed hard cap:
  **32 MiB** (and further bounded in practice by the per-request body limit unless most
  chunks are reused via `copy`).

---

## 9. Reference two-way client behavior (`src/sync_client.rs`)

The bundled `SyncClient` / `shellx-drive-sync sync-once` is the proven Drive-side
reference. Its resolution rules define the conservative v1 semantics a Drive
client should match:

**Local layout** (under the configured `cache_dir`):

```
.shellx-drive-sync-profile.json     # canonical server URL + verified actor + optional CA digest; never a token
workspaces/<id>/workspace.json      # workspace snapshot
workspaces/<id>/files.json          # manifest snapshot
workspaces/<id>/safe-space.json     # written for safe-space workspaces
workspaces/<id>/sync-state.json     # { "files": { "<file_id>": {content_hash, revision} } }
workspaces/<id>/content/<file_id>                       # downloaded/tracked body (flat by id)
workspaces/<id>/content/<file_id>.remote-r<revision>-<sha256>.remote-conflict
                                                        # remote copy kept on conflict
workspaces/<id>/content/<file_id>.local-<uuid>.remote-conflict
                                                        # local race recovery copy
```

Before reading manifests, baselines, or bodies, the headless client resolves
`GET /auth/me` with the configured credential and requires the cache marker to
match both the canonical server URL and the server-verified actor. A mismatch,
malformed marker, or linked marker fails before any sync mutation. A non-empty
cache created before this marker existed is refused unless the operator uses
`--adopt-existing-cache` once after checking its server/account origin.

For a private Drive whose HTTPS proxy uses a private certificate authority,
`--ca-file <pem>` adds that authority only to this client process, preserving
the macOS Keychain, Windows certificate store, and Linux system roots.
Certificate-chain and hostname verification remain enabled. The
bounded CA file must be a real, non-replaceable regular file. Its SHA-256 digest
is bound into the cache profile and checked before the client sends its token,
so a profile cannot silently move to a different private trust root.

`--profile <name>` stores an independent cache below
`<cache_dir>/profiles/<name>`. Profile names are bounded lowercase path-safe
labels; this lets one installation manage several Drive servers or accounts
without allowing their baselines and bodies to mix. This is a headless CLI
capability, not the v0.1 desktop application's user-facing connection model.
The later desktop `+ Add Drive` flow will provide named, independently managed
connections and a native-folder-picker setup for each server/account.

On Unix, the effective cache root and all managed directories are accepted only
when they are owned by the current user with owner-only `0700` access bits. An
inherited setgid flag is allowed because it grants no group access; other
special bits are rejected. Unsafe existing objects fail closed and are not
repaired in place. A local file is eligible for upload only when it is a
regular file owned by the current user, has one hard link, and has no
group/other write bit. Owner-created `0644` editor output is therefore
supported, while peer-writable or hard-linked leaves are rejected. Admission
is descriptor-based after a no-follow open.

`sync-state.json` records, per tracked file, the `content_hash` and `revision`
observed at the last successful sync — the common baseline used to classify
local vs remote change.

**Per open workspace, one `sync_once()` pass:**

1. **Reconcile each remote file** against the local body + recorded baseline:
   - no local copy → download (fresh, or re-pull a locally-deleted tracked file;
     v1 does **not** propagate deletes), record baseline.
   - local unchanged, remote changed → download, update baseline.
   - local changed, remote unchanged → queue a content **update** upload.
   - both unchanged → skip.
   - both changed to the **same** bytes → converged, just update baseline.
   - both changed to **different** bytes → **conflict**: keep the local file
     untouched, write the remote bytes under the content-bound
     `content/<id>.remote-r<revision>-<sha256>.remote-conflict` name, count it,
     upload nothing. An identical retained copy is reused; a different file at
     that reserved name is never replaced.
   - a tracked remote-only replacement first moves the current local leaf to a
     collision-resistant recovery name and publishes the verified remote body
     only if the main destination is still absent. The displaced leaf is always
     retained because no portable compare-and-unlink operation can safely
     discard it while a same-user writer may race cleanup. If its bytes differ
     from the baseline it is counted as a conflict.
     The client counts retained `.remote-conflict` bodies across the cache and
     refuses a new recovery publication above 4 GiB. Review and move recovery
     files out of the cache before resuming; the client never deletes them.
2. **Upload queued updates** via §7.3 (small UTF-8) or §7.4 (binary/large),
   using `base_revision` = current manifest revision. On success, record the new
   hash+revision. On a `409` race, count a conflict and leave local state.
3. **Upload new local files** — any regular file in `content/` whose name is not
   a known remote file id (and not a `*.remote-conflict`) is created via §7.1
   (small UTF-8) or §7.2 (binary/large), then renamed to `content/<new_id>` and
   recorded, so it is not re-uploaded next pass. A create response that reuses
   a known file ID is rejected; the local rename cannot replace an existing
   destination.

**Guarantees:**
- **Idempotent:** a second `sync_once()` with no local or remote changes uploads
  nothing, downloads nothing, creates no new revision (prevents re-upload loops).
- **Non-destructive:** delete propagation is disabled in both directions
  (report-only); a both-changed conflict never overwrites either side (remote is
  preserved locally as `.remote-conflict`, local is left in place, remote server
  content is untouched). Fresh downloads and conflict publications are
  non-replacing, and every tracked replacement preserves the displaced local
  bytes under a recovery name so a cleanup race cannot delete a late edit.

The `WorkspaceSyncReport` returned per workspace carries: `downloaded_files`,
`uploaded_new`, `uploaded_updated`, `resumable_uploads`, `skipped_conflicts`
(plus the pre-existing `file_count`, `storage_mode`, `safe_space`).

---

## 10. Resumable full-content replacement

Large, binary, or wholly changed existing files use the same bounded resumable
transport as large creates, but start the session with both immutable target
fields:

```json
{
  "target_file_id": "file-id",
  "base_revision": 7,
  "total_size": 1572864
}
```

Both `target_file_id` and `base_revision` are required together. The server
derives workspace, parent, and name from the live target, verifies actor and
credential authority when the session is created and again at terminal
publication, enforces the 2 GiB resumable ceiling, and completes through the
optimistic existing-file writer. A stale revision produces the same preserved
conflict outcome as §7.5 rather than overwriting either copy.

The bundled desktop client chooses the transfer as follows:

- creating large or binary files: resumable create;
- updating small UTF-8 files: `PUT …/content`;
- updating bounded files where chunk reuse is useful: delta copy/data;
- updating large, binary, or wholly changed files: resumable replacement.

When a server lacks the target-bound resumable contract, the client reports an
explicit `UnsupportedTransfer` review and preserves the existing file. Resolve
that review with a server that supports version-bound replacement.
