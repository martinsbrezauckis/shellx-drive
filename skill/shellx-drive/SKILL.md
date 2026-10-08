---
name: shellx-drive
description: >-
  Operate ShellX Drive through its authenticated REST API: workspaces, files,
  sharing, uploads, sync, delegated agents, desktop control and supported admin
  operations. Verify returned receipts and authorized readbacks. Use for Drive
  API tasks; administrator diagnostics require current administrator authority.
---

# ShellX Drive — agent-first file workspace server

ShellX Drive is a single-binary, self-hosted cloud drive: a Rust/Axum server over
SQLite metadata + filesystem blob storage. **The HTTP API is the primary surface;
the bundled web app is just another client of it.** Server workflows — create
workspaces, upload/download files, share, sync, comment, and run backups — use
authenticated HTTP calls. Native desktop connection setup uses the local app
and operating-system folder picker; read [Desktop connections](reference.md#desktop-connections)
when helping with that workflow. Your job as the driving agent: make the call,
read the returned JSON, and **verify the returned receipt and authorized product
readback**. An ordinary
user's agent uses that user's delegated credential; administrator diagnostics
are a separate surface.

Two facts shape every decision:

1. **Drive storage is server-readable.** The server indexes content for search,
   generates previews/thumbnails, and serves WebDAV, the Google Drive subset,
   rclone export, and guest shares. For content privacy from the server or VPS
   operator, encrypt locally before upload, keep the keys with the client, and
   store the resulting ciphertext in Drive.
2. **Use receipts and activity for the audit log.** Every
   mutation appends an immutable `Receipt` (`/debug/receipts`, `/admin/summary`)
   and, where relevant, an `Activity` row. The notification inbox is user-facing
   read/unread state and is redacted in debug.

## Connect

For a new host, follow `docs/public/FIRST_INSTALL.md` in the admitted package.
It defines the read-only preflight, existing-proxy coexistence boundary, TLS
verification, and first-admin acceptance evidence. Use the host's confirmed DNS,
proxy, tunnel, and Drive configuration, preserving existing state.

For a release package, follow `packaging/README.md`: authenticate the publisher
with the archive's GitHub attestation against the pinned official repository and
signer workflow, and verify the checksum. Copy it into a fresh root-private
directory before verification, extraction, and execution. Run the checked
`install.sh` from that directory. The admitted installer checks the
complete package manifest, generates independent operator and setup-only
credentials in `/etc/shellx-drive.env` (root-owned mode `0600`), and starts a
loopback-bound systemd service without replacing an existing environment file or
data directory. Configure TLS before browser setup, then use the setup token to
authorize creation of the first administrator.

For a disposable local-source server, use a fresh private run directory.
Persistent service startup belongs to the admitted installer path above.

```bash
umask 077
DRIVE_RUN_DIR=$(mktemp -d)
TOKEN_FILE="$DRIVE_RUN_DIR/operator-token"
SETUP_TOKEN_FILE="$DRIVE_RUN_DIR/setup-token"
SECRET_HELPER=./scripts/curl_secret_config.sh # reviewed source or admitted package
openssl rand -hex 32 >"$TOKEN_FILE"
openssl rand -hex 32 >"$SETUP_TOKEN_FILE"
CURL_CONFIG="$(bash "$SECRET_HELPER" --bearer-file "$TOKEN_FILE")"
trap 'rm -f -- "$CURL_CONFIG" "$TOKEN_FILE" "$SETUP_TOKEN_FILE"' EXIT
SHELLX_DRIVE_BOOTSTRAP_TOKEN="$(<"$SETUP_TOKEN_FILE")" \
  shellx-drive --bind 127.0.0.1:5758 --data-dir "$DRIVE_RUN_DIR/data" --token-file "$TOKEN_FILE"
#   --bind        listen address (default 127.0.0.1:5758)
#   --data-dir    SQLite db + blob store + upload scratch (default .shellx-drive-data)
#   --token-file  mode-0600 server bearer file; keeps the secret out of argv
#   --e2e         enable loopback-only /debug/e2e/seed + /debug/e2e/reset helpers
#   --hosted      enable hosted (multi-tenant) mode
```

The exit trap removes only this run's credential/configuration files. Retain
`DRIVE_RUN_DIR/data` for inspection until the test server has stopped, then
remove that exact disposable run directory when its evidence is no longer needed.

**Boot guard (verified in `src/config.rs`):** the server refuses to start when the
token is unset (it would default to `dev-token`), empty, a known placeholder
(`dev-token`, `change-me`/`changeme`, or `replace_with`/`your-token`-style
markers), or shorter than 16 characters. `--e2e` does not weaken that guard and
also requires a loopback bind. Every run must supply a strong, random,
non-placeholder token of at least 16 characters (`openssl rand -hex 32`); the
guard is a floor, so it is still on the operator to make it genuinely
high-entropy.

Base URL below: `B=http://127.0.0.1:5758`. Send `Authorization: Bearer <token>` on
everything except the public routes.

### Authentication — credential classes

| How | Who you are | Use when |
|---|---|---|
| `Authorization: Bearer <server-token>` | **local admin actor** `system@local` (`is_admin=true`), bypasses workspace roles | You are the operator/agent doing admin + setup work |
| `Authorization: Bearer <server-token>` **+** `x-shellx-actor: user@example.test` | **that user** (`is_admin=false`), workspace owner/editor/viewer roles enforced | You are acting *on behalf of* a user and want real permission checks |
| `Authorization: Bearer <sso.v1 token>` | a logged-in human/OIDC actor | Driving as an end user who bootstrapped/logged in |
| `Authorization: Bearer <account-wide sxd_agent_ token>` | one local-auth owner or exact external SSO parent session, `auth_mode=delegated_agent` | A revocable delegated agent using the owner's current ordinary Drive/account authority; local delegations may use supported admin/debug when currently admin, external SSO delegations remain ordinary-user only |

Use an account-wide delegated credential for an ordinary user's agent. The
`x-shellx-actor` downshift is an operator testing tool: an operator already
holding the server token can exercise user-scoped permission checks. Verify
ordinary actions through the user's delegated credential and authorized
product readbacks; reserve the server token for operator work.

### Delegated agents: choose the smallest authority

Choose credentials by their issued scope: the `sxd_agent_` prefix is shared by
folder-agent and account-wide tokens. A folder-agent token uses `/agent/v1/access`
and `/agent/v1/grants/{grant_id}/...`; every request is bounded by its explicit
View/Edit subtree grant. Use an account-wide delegation for ordinary Drive,
account, sharing, sync, Office, WebDAV, and search routes, subject to current
owner permissions; admin/debug routes additionally require current
administrator authority as described below.

An account-wide delegated token is issued and managed through
`GET/POST /agent-delegations`,
`POST /agent-delegations/{principal_id}/rotate`, and
`POST /agent-delegations/{principal_id}/revoke`. A local delegation acts as the
live local-auth owner. A supported external SSO delegation binds to its exact
live parent session and is ordinary-user only; its expiry cannot outlive that
parent. The token is returned once; transfer it through the caller's approved
secret channel into protected credential storage. Keep transcripts and receipts
limited to redacted credential metadata.

For a delegated request, use the existing human route and verify its returned
receipt/readback. Current owner account state, administrator status, workspace
membership and item roles, token/principal revocation, and expiry remain
authoritative at admission and terminal publication. A non-admin delegated owner
cannot enter admin/debug routes. Password, TOTP, recovery-code, typed-email, and
existing action-specific confirmation requirements still apply; a delegated
bearer is not password or MFA proof. A delegated `POST /auth/logout` revokes its
exact bearer rather than a human browser session.

Account-wide delegation can submit and inspect the owner's bounded
`/desktop-agent` broker commands. Enroll the device through the owner's current
local-password session; the one-time `sxd_device_` credential belongs in that
desktop's protected OS credential store. Each independently configured
server/account connection maintains up to 100 accessible owned and shared roots
below its own local base and retains its own enrollment. Adding another
connection or viewing another root preserves the existing connection's sync
and device identity. The broker is device-pulled; it does not
accept a listener address, a filesystem path, shell text, arbitrary native-command payload, or free-form
desktop result. Confirm completion through the command's terminal result;
report offline, pending-disconnect, candidate-recovery, revoked, or authority-lost
states with their recovery or retry requirement.

For actionable broker readback, submit `desktop_view` with strict
`section` (`pairs` or `reviews`), optional opaque `after`, and `limit` 1–50
(default `pairs`/25); submit `discover_roots` with optional opaque `after` and
the same limit (default 25). A new successful result must include its full
bounded `page` and `next_after`, echo the submitted section/cursor/limit, and
sort rows by their stable pair, `pair_id/review_id`, or sync-root cursor.
Pair/review/root rows expose the documented bounded authorized names and typed
identifiers/actions/statuses, keeping local paths, raw logs, and credentials
private. `page: null` is legacy count-only command history, not proof of a
current actionable readback. Progress normally renews 45 seconds; only an
`install_desktop_update` already in `updating` may report `relaunch_pending`,
which has at most 300 seconds and never means the update installed. Wait for
the exact post-restart `update_install` terminal result.

Externally authenticated SSO sessions and their parent-bound delegations cannot
enroll a device: enrollment still requires a local-password session. The SSO
delegation kind remains explicit and fails closed if its parent binding is
missing, restored, revoked, expired, or identity/token-hash rebound; it never
falls back to a matching local email. Server broker source is not proof of a
Windows, macOS, or Linux desktop command completing; require the device's
bounded acknowledgement/progress/terminal result and native-host qualification.

**Human login path** (mints an `sso.v1` bearer + session cookie):

```bash
# First run only — status is public, but account creation always requires
# explicit server authority. Prefer the browser wizard for a human operator.
curl -s $B/auth/bootstrap/status                       # {"required":true}
read -r -s -p 'Server setup token: ' SETUP_TOKEN; echo
SETUP_CONFIG="$(printf '%s' "$SETUP_TOKEN" | bash "$SECRET_HELPER" --bearer-stdin)"
unset SETUP_TOKEN
AUTH_BODY=$(mktemp); chmod 600 "$AUTH_BODY"
trap 'rm -f -- "$SETUP_CONFIG" "$AUTH_BODY" "${AUTH_CONFIG:-}"' EXIT
read -r -p 'Email: ' AUTH_EMAIL; read -r -s -p 'Password: ' AUTH_PASSWORD; echo
printf '%s\0%s' "$AUTH_EMAIL" "$AUTH_PASSWORD" | python3 -c \
  'import json,sys; e,p=sys.stdin.buffer.read().split(b"\0",1); print(json.dumps({"email":e.decode(),"password":p.decode()}))' \
  >"$AUTH_BODY"
unset AUTH_PASSWORD
# Pipe the returned bearer directly into the reviewed secret receiver so
# later commands use its private config path.
set -o pipefail
AUTH_CONFIG="$(curl -fsS -K "$SETUP_CONFIG" -H 'Content-Type: application/json' "$B/auth/bootstrap" --data-binary @"$AUTH_BODY" |
  python3 -c 'import json,sys; token=json.load(sys.stdin).get("token"); assert isinstance(token,str) and token, "login did not return a bearer"; sys.stdout.write(token)' |
  bash "$SECRET_HELPER" --bearer-stdin)"
# Use curl -K "$AUTH_CONFIG" for subsequent calls in this session.

# Later logins use the same private body-file pattern with /auth/login. If TOTP
# is enabled, rebuild the private JSON body with a prompted totp_code or
# recovery_code. Remove the file when the authentication flow is complete:
rm -f -- "$AUTH_BODY" "$SETUP_CONFIG"
```

Feed account passwords, recovery codes, and TOTP values through a mode-0600 body
file as above. Keep the returned bearer inside the secret receiver's private
config, and use that file's path for subsequent requests. Delete the body file
after authentication and remove `AUTH_CONFIG` when the session is finished;
retain only redacted authentication metadata in transcripts.

`POST /auth/bootstrap/wizard` does admin + first workspace + session in one call
and requires the same setup authority. When
`SHELLX_DRIVE_BOOTSTRAP_TOKEN` is configured, neither the general operator token
nor a browser session can replace it. Both bootstrap routes permanently return
conflict after the first account exists.
OIDC: `POST /auth/oidc/exchange` (admin-token-gated; you supply already-verified
claims) mints a short-lived `sso.v1` actor token — Drive is not the IdP.

Public (no bearer): `GET /health`, `GET /ready`, `GET /hosted/status`, `GET /`
and the PWA asset routes, `GET /favicon.ico`, and the `/pub/*` share/drop/invite
paths (they use the per-link password, never the server token).

## Operational environment

Runtime knobs the **binary** reads from the environment (all optional; the binary
otherwise takes `--bind`, `--data-dir`, and the argv-safe `--token-file` flag). See
[docs/public/CONFIG.md](../../docs/public/CONFIG.md) for the exhaustive table with defaults.

| Env var | Default | Purpose |
|---|---|---|
| `SHELLX_DRIVE_TOKEN` | `dev-token` (refused even with `--e2e`) | Server bearer token. Treat as a password. A private `--token-file` is the argv-safe file alternative. |
| `SHELLX_DRIVE_BOOTSTRAP_TOKEN` | unset | Optional setup-only credential for the two first-account routes. Package installs generate it independently. |
| `SHELLX_DRIVE_EMAIL_TRANSPORT` | `capture` | Processes queued notices for inspection; `sent` means capture processing. Deliver links through an approved channel. Other transport values are posture labels only. |
| `SHELLX_DRIVE_EMAIL_FROM` | `ShellX Drive <noreply@shellx.local>` | From address on outbox notices. |
| `SHELLX_DRIVE_PUBLIC_ORIGIN` | `http://127.0.0.1:5758` | Canonical public origin for browser checks, hosted status, and links (reset, invite). |
| `SHELLX_DRIVE_SMTP_HOST` / `_PORT` / `_USERNAME` | unset | SMTP posture settings. Debug/admin responses expose host/username presence as `configured`/`not_configured` labels and the numeric port. |
| `SHELLX_DRIVE_LOCAL_SESSION_TTL_SECONDS` | `2592000` | Local email/password session lifetime and browser cookie Max-Age. Clamped to 1 hour..365 days. |
| `SHELLX_DRIVE_OFFICE_PROVIDER_NAME` | `Office editor` | Post-v0.1.1 label for the office edit provider. |
| `SHELLX_DRIVE_OFFICE_PROVIDER_URL` | unset | Post-v0.1.1 integration only. Leave unset at v0.1.1 launch; when configured later, `/office/.../open` mints a token-scoped edit session plus a one-use same-origin handoff URL, and non-loopback providers require HTTPS. |
| `SHELLX_DRIVE_OFFICE_SESSION_TTL_SECONDS` | `900` (60..3600) | Post-v0.1.1 office edit-session lifetime; every token remains bound to its source credential. |
| `SHELLX_DRIVE_HOSTED_MODE` | off | Enable hosted/multi-tenant metadata layer (same as `--hosted`). |
| `SHELLX_DRIVE_HOSTED_BILLING_PROVIDER` | `none` | Posture label only; the OSS binary makes no billing call. |
| `SHELLX_DRIVE_HOSTED_PUBLIC_RATE_LIMIT_PER_MINUTE` | `60` (min 1) | Posture label reported by `/hosted/status`. |
| `SHELLX_DRIVE_UBUNTU_PRO_TOKEN_SOURCE` / `SHELLX_DRIVE_SUDO_SOURCE` | unset | Maintenance secret *sources* (surfaced only as `configured`/`not_configured`). |

> Note: `SHELLX_DRIVE_BIND` and `SHELLX_DRIVE_DATA_DIR` appear in the packaging
> env file but are consumed by the installed **systemd unit**: systemd expands
> them into the unit's `--bind` / `--data-dir` arguments. The binary itself
> reads the two token variables from the environment.

Password-reset requests create capture outbox records for operator inspection.
To complete recovery, an authenticated server administrator uses
`POST /admin/auth/users/{email}/password-reset-link` and delivers the returned
one-time link through the caller's approved secret channel. Handle that response
as temporary secret material and retain only redacted metadata in transcripts.
The token is stored as a hash and can be revoked through the matching `DELETE`
route.

Workspace member and invitation emails are normalized account/login identifiers.
Deliver invitation or recovery links through a caller-approved out-of-band
channel, and confirm recipient delivery through that channel. Drive binds
invitations to the signed-in account with the matching normalized email.
Verify recipient identity through the delivery channel. Captured outbox rows
record queue processing.

## Workflow

The loop for every mutation: **call → read the returned file/receipt → verify
through an authorized metadata, content, activity, or settings readback**.
Current administrators can additionally use the Debug API. IDs below (`WS`,
`FID`, `UP`) are captured from prior responses.
Validate every server-returned object id before interpolating it into a later
request, and quote the complete URL:

```bash
require_drive_uuid() {
  [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
    printf 'Drive returned an invalid %s id\n' "$2" >&2; return 2;
  }
}
```

### 1. Create a workspace

Workspace creation requires current administrator or operator authority. A
currently authorized local administrator delegation may create one. Ordinary
agents work within existing accessible workspaces; ask an administrator to
create a workspace when needed.

```bash
curl -s -K "$CURL_CONFIG" -H 'Content-Type: application/json' $B/workspaces \
  -d '{"name":"Team Docs","owner_email":"admin@example.test"}'
# The compatibility storage_mode field, when supplied, accepts only "open".
# Hosted mode: also pass "tenant_id".
```

Members/roles: `POST /workspaces/{WS}/members` with `{email, role}` where role is
`owner|editor|viewer`. Read = viewer+, Write = editor+, Manage = owner. Groups
(`/groups`, `/workspaces/{WS}/group-grants`) grant roles to a set of users; the
highest of direct role vs group-derived role wins.

### 2. File CRUD

```bash
# Create a file (small inline content) or a folder (kind:"folder", no content):
curl -s -K "$CURL_CONFIG" -H 'Content-Type: application/json' $B/files \
  -d '{"workspace_id":"'$WS'","name":"notes.txt","kind":"file","content":"hello"}'   # 201

# Read content / replace content (optimistic concurrency — base_revision REQUIRED):
curl -s -K "$CURL_CONFIG" "$B/files/$FID/content"
curl -s -K "$CURL_CONFIG" -H 'Content-Type: application/json' -X PUT "$B/files/$FID/content" \
  -d '{"base_revision":1,"content":"hello v2"}'
#   match → 200 new revision + receipt;  stale base_revision → 409 + a conflict copy (409 body names conflict_file_id)
```

- **Metadata / move / rename:** `PATCH /files/{FID}` with any of `name`,
  `parent_id`, `move_to_root`, `labels`, `custom_metadata`. Use `move_to_root:true`
  for the workspace root; `parent_id:null` does not move. Send `base_revision`
  for optimistic protection. Collision default is `keep_both`, deriving
  `photo (copy).png`, then `photo (copy2).png` in the selected destination
  folder; `cancel` returns 409 unchanged.
  File-on-file `replace` also needs exact `replace_target_id` and
  `replace_target_revision`: it preserves the destination ID/history and moves
  the source to Trash. Folder collisions support Keep Both or Cancel. Use the
  returned `file` identity/name; every metadata change advances its revision.
- **Copy:** `POST /files/{FID}/copy`. Omit `parent_id` to keep the source parent,
  send `parent_id:null` for the workspace root, or send a destination folder id.
  Collisions keep both in that destination folder; use returned `file.name` and
  `file.parent_id` rather than predicting the derived `copy`/`copy2` name.
  **Trash / restore:** `POST
  /files/{FID}/trash` | `/restore` (recoverable). **Star:** `/star` | `/unstar`.
  **Bulk:** `POST /files/bulk` `{action:"trash|restore|star|unstar", file_ids:[…]}`.
- **Permanent delete (NEW this release):** `DELETE /files/{FID}` — irreversible,
  requires Write (editor+), recurses into folders, and ref-count-cleans the
  underlying blob; returns `204`. Distinct from trash (which is recoverable).
- **Revisions:** `GET /files/{FID}/revisions`; restore an old one with
  `POST /files/{FID}/revisions/{rev}/restore` (creates a *new* current revision,
  never rewrites history); `pin`/`unpin` protects a revision from retention.
- **Empty trash (NEW this release):** `POST /workspaces/{WS}/trash/empty`
  permanently purges only trashed subtrees whose full contents passed the
  workspace retention cutoff (Write). Recent items remain in Trash. Returns
  `{deleted: N, retained: N, retained_items: [{file_id, name}]}`.

### 3. Resumable upload (large files, camera capture, drag-drop)

`total_size` is **REQUIRED** on session creation (`src/routes/uploads.rs` rejects a
missing one with a validation error) and is the declared full byte length; chunks
must not exceed it and the finishing chunk must total exactly it. Max 2 GiB.
Before creating a browser batch, call `POST /uploads/preflight` with up to 512
`{name,size,path?}` entries to surface quota and duplicate/path conflicts. Active
sessions reserve their declared bytes; abandoned sessions are canceled after 24
hours, and admission is bounded per actor, workspace, and server.
Preflight is advisory: send `duplicate_policy:"cancel"` to retain Cancel through
finalization; omitted policy is Keep Both. To replace existing bytes, send the
exact `target_file_id` and `base_revision` together, optionally with
`duplicate_policy:"replace"`. The server derives that file's workspace/name;
a stale final revision preserves conflicting bytes as a conflict copy and
returns 409. Read the returned file/conflict identity rather than assuming the
preflight name won a race. See [reference.md](reference.md#resumable-uploads).

```bash
UP=$(curl -s -K "$CURL_CONFIG" -H 'Content-Type: application/json' $B/uploads/resumable \
  -d '{"workspace_id":"'$WS'","name":"clip.bin","total_size":12}' | jq -r .session.id)
require_drive_uuid "$UP" upload
# Append chunks at the current offset. Wrong offset → 409. Text or base64 (not both):
curl -s -K "$CURL_CONFIG" -H 'Content-Type: application/json' -X PUT "$B/uploads/resumable/$UP" \
  -d '{"offset":0,"content":"hello ","finish":false}'
curl -s -K "$CURL_CONFIG" -H 'Content-Type: application/json' -X PUT "$B/uploads/resumable/$UP" \
  -d '{"offset":6,"content_base64":"d29ybGQh","finish":true}'   # finish → creates the file, returns it + receipt
# GET /uploads/resumable/{UP} inspects received_bytes/completed; POST /uploads/resumable/{UP}/cancel aborts.
```

### 4. Download, preview, thumbnail

- `GET /files/{FID}/content` — inline serving (NEW this release): correct
  `Content-Type` by extension, `Content-Disposition: inline`, `Accept-Ranges:
  bytes`, and honors a `Range` header → `206 Partial Content`. Auth: Read.
- `GET /files/{FID}/download` (NEW this release) — attachment serving: forces a
  save with `Content-Disposition: attachment; filename*=...`. Auth: Read.
- `GET /files/{FID}/preview` — generated preview metadata (image dims, thumbnail
  info, or an explicit unsupported-format fallback).
- `GET /files/{FID}/thumbnail` — the generated preview PNG (`image/png`); `404`
  when no thumbnail exists. Auth: Read.
- `POST /files/{FID}/download-zip` — mint a 120-second, one-use
  `/downloads/{ticket}` URL for a folder ZIP attachment; redeem it with `GET`.

For large browser downloads, use the capability flow so JavaScript never buffers
the body: `POST /files/{FID}/download` mints a one-use
`/downloads/files/{ticket}` URL; `POST /files/{FID}/preview` mints a bounded,
range-reusable media URL; and `POST /files/download-zip` with
`{"file_ids":[...]}` mints `/downloads/{ticket}` for a multi-selection archive.
Treat every returned URL as a secret and redeem it promptly. See
[reference.md](reference.md#capability-download-redemption) for the complete
ticket and revision-download contract.

**Folder cover images (NEW this release).** A folder can carry a custom cover
image (Google-Drive-style grid tile). `PUT /files/{FID}/cover` sets it from raw
image bytes (PNG/JPEG/GIF/WebP, signature-validated, ~8 MiB cap; Write);
`GET /files/{FID}/cover` serves it (Read); `DELETE /files/{FID}/cover` clears it
(Write, idempotent). A non-folder is `400`. Whether a folder has one is
surfaced as `has_cover` on its `DriveFile`/`FileTreeNode`.

```bash
curl -s -K "$CURL_CONFIG" -X PUT "$B/files/$FOLDER/cover" \
  -H 'Content-Type: image/png' --data-binary @cover.png    # 200 → file with has_cover:true
```

### 5. Search

```bash
curl -s -K "$CURL_CONFIG" "$B/search?q=quarterly"
# {"query":"quarterly","files":[…], "results":[{"file":{…},"rank":…,"matched_fields":[…],"snippet":"…"}]}
```

Ranked full-text over server-readable bodies plus names, labels, and custom
metadata. Results are filtered to the actor's visible workspaces.

### 6. Share links and upload drops

```bash
# Optional-password guest read-only link for one file OR folder (expiry in seconds required).
# file_id is the target file OR folder id — a folder share exposes its subtree:
SHARE_BODY=$(mktemp); chmod 600 "$SHARE_BODY"
read -r -s -p 'Share password: ' PW; echo
printf '%s\0%s' "$FID" "$PW" | python3 -c \
  'import json,sys; f,p=sys.stdin.buffer.read().split(b"\0",1); print(json.dumps({"file_id":f.decode(),"password":p.decode(),"expires_in_seconds":86400}))' \
  >"$SHARE_BODY"
curl -s -K "$CURL_CONFIG" -H 'Content-Type: application/json' $B/shares --data-binary @"$SHARE_BODY"
rm -f -- "$SHARE_BODY"

# Upload drop (guests upload INTO a workspace): POST /drops, then public
# preflight + resumable session/chunk routes under /pub/drops/{id}/uploads
```

One link is created and serves BOTH a human (browser → HTML guest page) and an
agent (JSON + raw bytes) off the same id — see "Reading a shared link as an
agent" below.

Share/drop creation obeys the workspace policy (`GET /workspaces/{WS}/policy`):
`public_links_enabled` can block new links, and max-TTL settings reject over-long
expiries. `link_password_required` defaults to **false** (passwordless share links
allowed, Google-Drive style); an admin can PATCH it to `true`, which then rejects
empty link passwords. A policy rejection is a validation error and writes **no**
`share.create`/`drop.create` receipt.

Public share links remain read-only. Signed-in workspace Editors handle editing
and comments; public write access is only the separate upload-only Drop contract.

### 6a. Reading a shared link as an agent

Given a share link `$B/pub/shares/$SID` (+ optional link password), read it
headless. The link is **dual-use**: content-negotiate the same id — request JSON
to get machine-readable metadata, or fetch raw bytes from the content route. All
access is **read-only**. Supply the password (if any) via the
`X-Share-Password:` header for metadata; wrong/missing → `401`. A finite-use
link claims a visit there and returns an `access_token` bound to the response
cookie (or `X-ShellX-Public-Client-Secret`). Send that token as
`X-Share-Access-Token` on content and thumbnail reads. Unlimited links also
accept the password directly on those reads. Passwords in URLs are ignored.

```bash
SID=<share id>
[[ "$SID" =~ ^[0-9a-f]{64}$ ]] || { echo 'invalid share id' >&2; exit 2; }
read -r -s -p 'Share password: ' SHARE_PASSWORD; echo
SHARE_HEADER="$(printf '%s' "$SHARE_PASSWORD" | bash "$SECRET_HELPER" --share-password-stdin)"
unset SHARE_PASSWORD
trap 'rm -f -- "$SHARE_HEADER"' EXIT

# 1. Discover file vs folder; finite-use metadata claims one visit:
COOKIE_JAR=$(mktemp); chmod 600 "$COOKIE_JAR"
SHARE_META=$(mktemp); chmod 600 "$SHARE_META"
SHARE_ACCESS_HEADER=$(mktemp); chmod 600 "$SHARE_ACCESS_HEADER"
trap 'rm -f -- "$SHARE_HEADER" "$COOKIE_JAR" "$SHARE_META" "$SHARE_ACCESS_HEADER"' EXIT
curl -fsS --header @"$SHARE_HEADER" -H 'Accept: application/json' \
  -c "$COOKIE_JAR" "$B/pub/shares/$SID" -o "$SHARE_META"
# Finite-use: send the claimed access token. Unlimited: keep using the password.
if [ "$(jq -r '.max_uses // empty' "$SHARE_META")" ]; then
  printf 'X-Share-Access-Token: %s\n' "$(jq -er '.access_token' "$SHARE_META")" > "$SHARE_ACCESS_HEADER"
else
  cp "$SHARE_HEADER" "$SHARE_ACCESS_HEADER"
fi
#   file   → {"kind":"file","name":"report.pdf","permission":"read","expires_at":...,"requires_password":true}
#   folder → adds "entries":[{"path":"docs/readme.txt","name":"readme.txt","kind":"file","size_bytes":12,"updated_at":"..."}, ...]
#            paths are RELATIVE to the shared folder root.

# 2a. FILE share → GET the content route (no path):
curl -s -b "$COOKIE_JAR" --header @"$SHARE_ACCESS_HEADER" "$B/pub/shares/$SID/content" -o out.bin

# 2b. FOLDER share → read each file entry by its relative path:
curl -s -b "$COOKIE_JAR" --header @"$SHARE_ACCESS_HEADER" \
  "$B/pub/shares/$SID/content?path=docs/readme.txt" -o readme.txt

# Generated image thumbnail for a shared file (404 when unavailable)
curl -s -b "$COOKIE_JAR" --header @"$SHARE_ACCESS_HEADER" \
  "$B/pub/shares/$SID/thumbnail?path=images/cover.png" -o cover-thumb.png
```

Scoping: a folder share serves ONLY files inside its subtree — `..`, absolute, or
out-of-subtree paths return `404`. Revoked and expired shares return `404`.

### 7. Sync and delta

- Desktop sync protocol: `GET /sync/workspaces` (actor-visible + role), then
  `GET /sync/workspaces/{WS}/manifest` for the full manifest; `GET /sync/changes`
  is a cursor-based change feed. `GET /sync/conflicts` lists stale-write conflict
  copies. The bundled `shellx-drive-sync sync-once --base-url … --token-file … --cache-dir …
  [--profile …] [--adopt-existing-cache] --actor … [--workspace …] [--safe-space …]`
  binary is a headless reference engine, not an installed desktop client.
  Named profiles keep different Drive server/account caches separate; legacy
  cache adoption must be explicit.
- Mobile: `GET /sync/mobile/workspaces` + `/manifest` (metadata-only, no hashes);
  mark files offline (`POST /sync/mobile/offline`) then download only those.
- Delta sync (large-file updates): `GET /sync/files/{FID}/chunks` returns the
  fixed-size SHA-256 chunk manifest; `PUT /sync/files/{FID}/delta` reconstructs a
  new revision from ordered `copy` (reuse chunk) + `data`/`content_base64` (changed
  bytes) ops through the same optimistic-revision path (stale base → conflict copy).

### 8. Comments, deferred Office, interop

- **Comments:** `GET/POST /files/{FID}/comments`, `POST /comments/{id}/replies`,
  `POST /comments/{id}/resolve`. Authorized collaboration produces in-app
  notifications. Optional email metadata records capture-outbox processing;
  deliver any separate message through the caller's approved channel and
  confirm delivery there.
- **Office integration (post-v0.1.1):** The provider/session bridge is
  preparatory only. v0.1.1 launch leaves the provider unconfigured and hides
  **Edit online**. Use ordinary file content, format, and preview operations at
  launch; configure the provider/session handoff when the later integration is
  available.
- **WebDAV:** `/dav/{WS}` and `/dav/{WS}/{path}` — `OPTIONS`, `PROPFIND`, `GET`,
  `PUT`, `MKCOL`, `DELETE`, `MOVE`, `COPY`, `LOCK`, `UNLOCK`. Same bearer +
  `x-shellx-actor`; reads need Read, writes need Write. `MOVE`/`COPY` refuse a
  cross-workspace `Destination`.
- **Google Drive subset:** `GET/POST /drive/v3/files`, `GET /drive/v3/files/{id}`,
  `GET /drive/v3/files/{id}?alt=media`. Small compatibility surface, not a full
  Drive.
- **rclone import/export:** `GET /workspaces/{WS}/export/rclone`,
  `POST /workspaces/{WS}/import/rclone/preview` (dry run) then `.../import/rclone`.
  Incoming explicit folder entries use `folder_collision_policy: "keep_both"`
  by default, or `"cancel"` to reject the whole import on an occupied folder
  name. Keep both creates a separate numbered folder and routes its imported
  descendants there; it never silently merges folders. An implicit path prefix
  still navigates an existing destination, and a file-only same-path entry
  remains an update preserving file ID and revision history. Read the apply
  response's `actions` (`path`, `resolved_path`, `file_id`) for final destinations;
  preview IDs and suffixes are provisional until the transaction applies.

### 9. Notifications and read state

`GET /notifications` (+ `?unread_only=true`), mark one read
(`POST /notifications/{id}/read`) or all (`/notifications/read-all`). Generated for
invitations, shares, comments/replies, drop uploads, and sync conflicts. It is
recipient-scoped inbox state. Use receipts and activity for mutation evidence.

### 10. Backups (operator)

`POST /admin/backups` queues durable v2 generation of a self-contained
`.sxdbackup` archive under the data directory and returns HTTP 202;
the response is `BackupJobResponse { job, backup? }`, not a completed archive.
Poll `GET /admin/backup-jobs/{job_id}` using `job.id`; `queued` and `running`
are pending, while `succeeded`, `failed`, and `interrupted` are terminal.
Successful creation writes a `backup.create` receipt. `GET /admin/backups`
lists complete generations and pending/failed create jobs with `next_cursor?`.
For v2, `POST /admin/backups/{id}/validate` and `/restore` also return HTTP 202
jobs. `GET /admin/backups/{id}/download` streams binary `.sxdbackup` bytes with
exact length, attachment disposition, and `Cache-Control: no-store`; it is
not a JSON bundle. `DELETE /admin/backups/{id}` deletes the selected archive.
Archives are private restore material and may contain historical
password hashes, although online restore never reinstates them; only metadata
is exposed through debug. Restore recovers content/catalog data
but preserves the target instance's current security authority; on a fresh
target, bootstrap and explicitly grant new authority rather than trusting
historical credentials, memberships, shares, or drops. Current email-outbox
delivery state remains live; archived capability-bearing messages are not
reinstated. See
[docs/public/OPERATIONS.md](../../docs/public/OPERATIONS.md).

## Verify with the Debug API

The Debug API provides administrator diagnostics. A current administrator's
delegated credential may use supported debug routes; an ordinary delegated
credential cannot. Ordinary agents verify returned receipts and permitted
product readbacks, including scoped `GET /activity`, metadata, content, and
settings. Debug routes require administrator authentication; the mutating E2E
helpers additionally require the operator credential and `--e2e`.

Debug evidence uses opaque references for capability-bearing records and
presence/byte-count metadata for preview or template content. Use authorized
product routes for content readback; debug keeps capability-bearing ids,
receipt actors/targets, preview text, and template item bodies redacted.

| Route | Use it to prove |
|---|---|
| `GET /version` | The exact running build (`{version, build, commit, built_at}`, `build` = `version+shortsha`). Public — cite this instead of guessing the version. |
| `GET /debug/state` | Server identity, redacted data-dir posture, whether e2e is on. |
| `GET /debug/receipts` | The immutable mutation log — confirm your write actually landed and in what order. |
| `POST /debug/jobs/run` | Drain queued background work (preview/thumbnail/search-index) **once**; returns processed/succeeded/failed/skipped. In production an in-process worker already drains the queue every ~4s, so derived data appears on its own — call this to assert deterministically **now** instead of waiting on the timer. |
| `GET /debug/previews/{FID}` | The generated preview record + thumbnail metadata for one file. |
| `GET /debug/search?q=` | Ranked results **plus** the SQLite query-plan evidence. |
| `GET /debug/sync`, `/debug/delta-sync`, `/debug/sync/changes` | Sync health, delta-write stats (sizes/hashes/chunk counts, never raw bytes), change feed. |
| `POST /debug/e2e/seed` / `POST /debug/e2e/reset` | Create a deterministic workspace+file / clear test metadata+blobs. **Requires `--e2e`.** |
| `GET /debug/twin/scenarios`, `POST /debug/twin/run` | Run the deterministic service-twin scenario (`workspace_roundtrip`) with an optional fault (`trash_before_assertions`) to prove the assertion battery catches failures. |

Debug responses are redacted (no tokens, password/secret hashes, raw chunk bytes,
or delta patch bodies) — see the redaction contract in
[docs/public/DEBUG_API.md](../../docs/public/DEBUG_API.md).

## Worked example — seed, verify, upload, download

This operator example uses the server credential created in Connect, including
administrator-only job and receipt inspection. Ordinary agents use their own
delegated credential, wait for derived product readbacks, and omit debug calls.
The JSON below shows the **response shapes** (fields), not byte-exact values —
counts, ids, and ranks vary per run. Search indexing on `POST /files` is
synchronous (the hit is available immediately); the background jobs you drain with
`/debug/jobs/run` are the derived preview/thumbnail work. For the complete
paginated diagnostics inventory—including capabilities, downloads, storage
integrity, imports, WebDAV locks, workspaces, and sync conflicts—use the
[endpoint reference](reference.md#debug-api).

```bash
B=http://127.0.0.1:5758
# CURL_CONFIG is the private mode-0600 config created in Connect. It carries the
# server bearer without exposing it in curl's process arguments.
CURL=(-sS -K "$CURL_CONFIG")

# 1. Create an open workspace
WS=$(curl "${CURL[@]}" -H 'Content-Type: application/json' $B/workspaces \
  -d '{"name":"launch","owner_email":"admin@example.test","storage_mode":"open"}' | jq -r .workspace.id)
require_drive_uuid "$WS" workspace
# {"workspace":{"id":"...","name":"launch","storage_mode":"open","archived":false,...},"owner":{...},"receipt":{"kind":"workspace.create",...}}

# 2. Create a file with inline content
FID=$(curl "${CURL[@]}" -H 'Content-Type: application/json' $B/files \
  -d '{"workspace_id":"'$WS'","name":"notes.txt","kind":"file","content":"quarterly plan"}' | jq -r .file.id)
require_drive_uuid "$FID" file
# 201 {"file":{"id":"...","name":"notes.txt","kind":"file","revision":1,...},"receipt":{"kind":"file.create",...}}

# 3. Drain any queued background (preview/thumbnail) work, then confirm search
curl "${CURL[@]}" -H 'Content-Type: application/json' $B/debug/jobs/run -d '{}'
# {"processed":N,"succeeded":N,"failed":0,"skipped":0,"jobs":[...]}
curl "${CURL[@]}" "$B/search?q=quarterly"
# {"query":"quarterly","files":[{"id":"...","name":"notes.txt",...}],"results":[{"file":{...},"rank":-1.2,"matched_fields":["content"],"snippet":"...quarterly plan..."}]}

# 4. Resumable upload a 12-byte file
UP=$(curl "${CURL[@]}" -H 'Content-Type: application/json' $B/uploads/resumable \
  -d '{"workspace_id":"'$WS'","name":"clip.bin","total_size":12}' | jq -r .session.id)
require_drive_uuid "$UP" upload
curl "${CURL[@]}" -H 'Content-Type: application/json' -X PUT "$B/uploads/resumable/$UP" -d '{"offset":0,"content":"hello ","finish":false}'
UFID=$(curl "${CURL[@]}" -H 'Content-Type: application/json' -X PUT "$B/uploads/resumable/$UP" \
  -d '{"offset":6,"content_base64":"d29ybGQh","finish":true}' | jq -r .file.id)
require_drive_uuid "$UFID" file
# {"session":{"completed":true,"received_bytes":12,...},"file":{"id":"...","name":"clip.bin",...},"receipt":{"kind":"upload.complete",...}}

# 5. Download it back (attachment), and confirm the receipts trail
DOWNLOAD_DIR=$(mktemp -d); chmod 700 "$DOWNLOAD_DIR"
DOWNLOAD_FILE="$DOWNLOAD_DIR/clip.bin"
curl "${CURL[@]}" "$B/files/$UFID/download" -o "$DOWNLOAD_FILE"      # 'hello world!'
curl "${CURL[@]}" $B/debug/receipts | jq '.receipts[-3:] | .[].kind'
rm -f -- "$DOWNLOAD_FILE"
rmdir -- "$DOWNLOAD_DIR"
# "file.create"  "upload.complete"  ...   ← the immutable proof your writes landed
```

Honest completion report: *"Created workspace `launch` (open), indexed `notes.txt`
(search hit `quarterly`, rank present), uploaded `clip.bin` via resumable session
(12/12 bytes, finish receipt `upload.complete`), downloaded it back byte-exact.
Verified against `/debug/receipts` — 3 matching receipts in order."*

## Working practices

- **Declare the upload size.** Supply the full `total_size` when creating a
  resumable session. Keep cumulative chunks within it and finish at exactly
  that byte count.
- **Resolve optimistic conflicts.** `PUT .../content` and Office/delta saves use
  `base_revision`; a stale value returns `409` and creates a conflict copy.
  Read the conflict, fetch the current revision, and reapply the intended
  change. Confirm the successful receipt and readback before reporting it saved.
- **Choose content privacy deliberately.** Ordinary Drive files are
  server-readable, indexed, previewed, and served through the supported APIs.
  For privacy from the operator, encrypt locally before upload and keep the
  keys with the client.
- **Configure a strong operator token.** Generate a random token such as
  `openssl rand -hex 32` for every mode. The boot guard rejects missing, short,
  and placeholder values. Use `--e2e` only with disposable loopback test data;
  it enables destructive `/debug/e2e/*` routes.
- **Verify with receipts and activity.** Cite these durable records for
  mutations; use notifications for the user's read/unread inbox.
- **Wait for background results.** A background-derived result (preview,
  thumbnail, search index) may still be queued. The in-process worker drains it
  within ~4s on its own. Poll the authorized product preview/search endpoint
  with a bounded wait and report pending or failed work truthfully. Current
  administrators can also run `POST /debug/jobs/run` and inspect debug results.
- **Use the caller's authority.** A user's agent uses that user's delegated
  credential. The raw server token acts as `system@local` administrator and
  bypasses workspace roles; operator permission tests explicitly downshift
  with `x-shellx-actor: <email>`.

## Reference

Maintained per-endpoint request/response argument tables, checked against the
real structs and route modules during release review: [reference.md](reference.md).
Full public route catalog: [docs/public/API.md](../../docs/public/API.md). Debug catalog +
redaction contract: [docs/public/DEBUG_API.md](../../docs/public/DEBUG_API.md). Config + ops:
[docs/public/CONFIG.md](../../docs/public/CONFIG.md), [docs/public/OPERATIONS.md](../../docs/public/OPERATIONS.md).
