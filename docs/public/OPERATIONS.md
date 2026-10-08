# ShellX Drive Operations

Runbooks for running ShellX Drive as a self-hosted, binary-first service. Pair
this with [CONFIG.md](CONFIG.md) (every setting) and
[packaging/README.md](../../packaging/README.md) (systemd install). For a new
host, follow [FIRST_INSTALL.md](FIRST_INSTALL.md) first; it owns the preflight,
existing-proxy coexistence, and first-administrator sequence.

## Deployment topology

ShellX Drive is one process that binds to loopback by default
(`127.0.0.1:5758`). The intended shape is:

```
client ──TLS──▶ reverse proxy (Caddy / nginx / Cloudflare Tunnel) ──HTTP──▶ 127.0.0.1:5758  shellx-drive
```

Terminate TLS at the reverse proxy. Keep the loopback bind and let the proxy
own certificates, HTTP/2, and public exposure. Binding the server publicly is an
explicit operator decision that also requires firewalling and token review.

### Data layout

Everything lives under `--data-dir` (default `.shellx-drive-data`, production
typically `/var/lib/shellx-drive`):

| Path | Contents |
| --- | --- |
| `drive.db` | SQLite metadata: workspaces, files, revisions, receipts, sessions, policies, etc. |
| `blobs/` | Content-addressed file bodies, sharded by the first two hex chars of the hash. |
| `backups/` | V2 `.sxdbackup` archives, optional local metadata sidecars/key used for cataloging legacy/local generations, private staging, and retained v1 JSON bundles. |
| `uploads/` | Resumable-upload `.part` scratch files (created `0600`). |

Drive uses SQLite's default **rollback-journal** mode. For a filesystem-level
snapshot, stop or otherwise quiesce the service, then capture the entire
`--data-dir` together so the database, journal, and blobs form one consistent
copy. Use the backup API (below) for a self-describing generation while the
service runs.

The database also contains the admin-only security ledger and active browser
session IP/user-agent metadata. Treat database copies and backups as private
operator artifacts. Security events are automatically limited to 90 days and
100,000 rows. Share owners do not receive guest IPs or identities; their product
surface remains aggregate access/download statistics.

## First administrator setup

The authenticated package flow in `packaging/README.md` first verifies publisher
provenance over a root-private archive and executes only its root-private checked
closure. That installer generates two independent root-owned secrets: a
long-lived operator token and a setup-only bootstrap token. Extract and execute
the checked installer inside that root-private directory. The setup token
authorizes creation of the first administrator.

1. Install the package and keep Drive on its default loopback bind.
2. Configure the HTTPS reverse proxy below and confirm `GET /ready` reports
   `"ready":true` through the public hostname.
3. On the server, run the setup-token retrieval command printed by the
   installer. Enter the retrieved secret directly into the HTTPS setup form.
4. Open the HTTPS Drive URL, enter the setup token, administrator email, password
   twice, and first workspace name.
5. Sign out and sign back in with the new administrator account. A second
   bootstrap attempt must return `409 Conflict` because the account database is
   no longer empty.

If the page is reachable before step 3, an anonymous visitor can see that setup
is required but cannot create an account without the server-generated token.

## Reverse proxy + TLS

Raise the proxy request-body limit: WebDAV `PUT` and resumable-upload chunk bodies
can be large (resumable sessions allow up to 2 GiB total).

### Caddy

```caddy
drive.example.com {
    reverse_proxy 127.0.0.1:5758
    request_body {
        max_size 2GB
    }
}
```

Caddy provisions and renews certificates automatically. Set
`SHELLX_DRIVE_PUBLIC_ORIGIN=https://drive.example.com` so browser checks and
links use the same final origin.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name drive.example.com;

    ssl_certificate     /etc/letsencrypt/live/drive.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/drive.example.com/privkey.pem;

    client_max_body_size 2g;          # WebDAV PUT + resumable chunks

    location / {
        proxy_pass         http://127.0.0.1:5758;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        # Overwrite rather than append so a caller cannot inject an arbitrary
        # client identity into Drive's abuse-control partition.
        proxy_set_header   X-Forwarded-For   $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;      # allow slow large downloads/uploads
    }
}
```

nginx does not forward non-standard WebDAV methods by default in every build, but
`proxy_pass` passes through `PROPFIND`, `MKCOL`, `MOVE`, `COPY`, `LOCK`, `UNLOCK`,
and `OPTIONS` as opaque methods to the upstream — no `dav_methods` directive is
needed because ShellX Drive implements WebDAV itself, not nginx.

Drive trusts `X-Forwarded-For`, `CF-Connecting-IP`, or `X-Real-IP` only when the
direct TCP peer is loopback. Abuse controls use a server-keyed fingerprint of the
right-most valid forwarded address. Account-session metadata and the admin
security ledger also retain the server-observed IP under their audience and
retention rules described in `SECURITY.md`. Keep the application on loopback and
make the final local proxy overwrite the client-address header. If another CDN/proxy
sits in front, configure its published address ranges as trusted in nginx/Caddy
first so `$remote_addr` is the verified originating client; do not accept a
public caller-supplied forwarding header unchanged.

### Cloudflare Tunnel

Expose the loopback service without opening an inbound port:

```yaml
# ~/.cloudflared/config.yml
tunnel: <tunnel-uuid>
credentials-file: /etc/cloudflared/<tunnel-uuid>.json
ingress:
  - hostname: drive.example.com
    service: http://127.0.0.1:5758
  - service: http_status:404
```

```bash
cloudflared tunnel route dns <tunnel-uuid> drive.example.com
systemctl enable --now cloudflared
```

Cloudflare terminates TLS at the edge. If you enable Cloudflare's upload size
limits, ensure they exceed your expected file sizes.

## Health and readiness

| Endpoint | Meaning | Use for |
| --- | --- | --- |
| `GET /health` | Process is alive (`{"ok":true,...}`). | Load-balancer liveness / restart checks. |
| `GET /ready` | Aggregate readiness: storage reachability, backup policy, restore maintenance, and informational host-maintenance posture. Returns `live`, `ready`, `state` (`ready`, `degraded`, or `not_ready`), and per-check rows. Drive does not run an Ubuntu Pro/OS probe, so that row is `unassessed` and does not by itself degrade readiness. | Deploy verification and monitoring. |

Both are public (no bearer). A green deploy = `/health` returns `ok:true` **and**
`/ready` reports `ready:true`.

## Logs and operational events

Drive defaults to `RUST_LOG=shellx_drive=info` when `RUST_LOG` is absent or
invalid. The shipped systemd unit supplies that same fallback, and the checked-in
`/etc/shellx-drive.env` example sets it explicitly. This keeps Drive INFO, WARN,
and ERROR operational events visible without enabling noisy dependency logs.

For a systemd installation, inspect the journal with:

```bash
journalctl -u shellx-drive -f
```

To raise detail during a bounded investigation, set
`RUST_LOG=shellx_drive=debug` in `/etc/shellx-drive.env` and restart only the
Drive service. The environment-file value overrides the unit fallback; return it
to `shellx_drive=info` after triage.

## Background processing

Derived data (image thumbnails, file previews, search-index refresh) is produced
by background jobs. A worker runs **inside the server process** and drains the job
queue automatically every ~4 seconds, with its first tick immediately after boot.
There is **nothing to schedule** — no cron, no sidecar, no manual trigger. After a
restart, any backlog from before the restart clears within a few seconds. If
the service stopped after claiming derived work, startup requeues it within the
normal per-workspace/global count and byte bounds; repeatedly interrupted work
eventually fails instead of retrying forever. The data-root instance lock rejects
a second concurrent Drive process. If thumbnails/previews are not appearing,
check that the process is actually running
(`systemctl status shellx-drive`) and inspect `GET /debug/jobs` for stuck jobs; a
one-shot on-demand drain is available via `POST /debug/jobs/run`.

## Backup and restore runbook

Backups default to deterministic, uncompressed v2 archives under
`<data-dir>/backups/<id>.sxdbackup`. They contain bounded JSONL database catalogs
and raw content-addressed blobs. Each newly-created archive also contains a
bounded, versioned private restore-integrity envelope that binds its identity to
the manifest, so one `.sxdbackup` can validate and restore on a fresh Drive
instance; copying a `.meta.json` sidecar or `.metadata-key` is not required. The
embedded envelope detects ordinary corruption and invalid archive structure; it
is not an externally trusted signature, so it cannot prove provenance against
someone who can rewrite the whole artifact. An authenticated private
`<id>.meta.json` remains a local catalog cache and stronger local authenticator
when its original `.metadata-key` is available; it also preserves restore
compatibility for pre-portability v2 generations. A generation created or
registered as managed on this instance always requires that sidecar; portable
fallback is reserved for a fresh imported archive. These files are **private
restore material** and can contain password hashes and recovery state; protect
them like the live database.

Drive does **not** encrypt `.sxdbackup` archives. They are explicitly
operator-readable: the host/VPS operator can read their database rows and
ordinary file blobs just as they can read the live data directory. Protect every
copy using deployment storage controls, such as encrypted host disks and an
operator-controlled encrypted off-host destination. Individually encrypted
Drive files remain ciphertext, but that does not encrypt the rest of a Drive
server backup.

Create, validate, and restore are durable single-lease jobs. The worker recovers
running jobs as `interrupted` after restart, removes only server-named disposable
staging, enforces the configured archive ceiling, preflights available disk
space, and atomically publishes the archive before maintaining its local catalog
cache. Restore validates the archive envelope plus every table/blob entry into a
private disposable directory before installation, then streams rows into one
SQLite transaction while ordinary writes receive HTTP 503 maintenance responses.
`GET /ready` reports the active restore job without paths or archive contents.

Restore recovers the archived content and catalog graph, but the target
instance's current security authority remains authoritative. Historical
passwords, reset tokens, sessions, memberships, policies, app/agent
credentials, shares, drops, and other capabilities are not reinstated. Current
rows are retained only while they still reference restored workspaces or files.
Current email-outbox delivery state is retained with that live authority;
archived reset, invitation, share, and other capability-bearing messages are
not reinstated.
Human item grants follow the same rule: current grants, including revocations,
replace every archived grant and survive only for a restored workspace/root and
an extant account or group principal. Restore then advances the live item-access
generation so a capability manifest issued before restore cannot be reused.
Current account-to-private-workspace mappings are retained where their restored
workspace and owner membership remain valid. Missing mappings are reconciled in
the restore transaction, creating an empty collision-safe `My files` workspace
when no current owned workspace survives; no server restart is required.
On a fresh target, bootstrap new administrator authority and explicitly grant
new workspace access after restoring content.

V1 JSON creation is disabled. Existing v1 files remain listable and deletable;
download/validate/restore are bounded at 128 MiB and fail fast with HTTP 413
above that migration envelope.

All routes below require an admin bearer (`Authorization: Bearer <server-token>` or
an admin session). `B=https://drive.example.com`. When using a bearer, read it
through the reviewed source or admitted-package helper, using its stdin or
private-file input. It rejects CR/LF and emits a private mode-0600 curl-config
path, keeping the bearer out of arguments and output. The trap removes that
generated config when this shell exits.

```bash
SECRET_HELPER=./scripts/curl_secret_config.sh # reviewed source or admitted package
read -r -s -p 'Admin bearer: ' OPERATOR_TOKEN; printf '\n' >&2
CURL_CONFIG="$(printf '%s' "$OPERATOR_TOKEN" | bash "$SECRET_HELPER" --bearer-stdin)"
unset OPERATOR_TOKEN
trap 'rm -f -- "$CURL_CONFIG"' EXIT

# 1. Queue a v2 backup; save job.id and job.backup_id from the HTTP 202 response
curl -s -K "$CURL_CONFIG" -X POST "$B/admin/backups"
# → {"job":{"id":"...","backup_id":"...","status":"queued",...}}

# 2. Poll the durable job, or fetch the latest state by generation id
curl -s -K "$CURL_CONFIG" "$B/admin/backup-jobs/$JOB"
curl -s -K "$CURL_CONFIG" "$B/admin/backups/$BID"

# 3. Page metadata, newest first
curl -s -K "$CURL_CONFIG" "$B/admin/backups?limit=50"

# 4. Stream one complete, self-contained archive off-box (store securely)
curl -s -K "$CURL_CONFIG" "$B/admin/backups/$BID/download" -o "backup-$BID.sxdbackup"

# 5. Queue full archive/schema/blob validation and poll its returned job id
curl -s -K "$CURL_CONFIG" -X POST "$B/admin/backups/$BID/validate"

# 6. Queue restore; writes pause until its job reaches succeeded/failed
curl -s -K "$CURL_CONFIG" -X POST "$B/admin/backups/$BID/restore"

# 7. Delete an old generation
curl -s -K "$CURL_CONFIG" -X DELETE "$B/admin/backups/$BID"
```

### Off-host restore drill

For a newly-created v2 generation, copy the downloaded `<id>.sxdbackup` alone
into `<fresh-data-dir>/backups/` with its original filename, leaving local
`.meta.json` sidecars and `.metadata-key` on the source instance. Start the fresh
instance, then queue `POST /admin/backups/<id>/validate` and wait for success before
queueing `POST /admin/backups/<id>/restore`. Validation rejects malformed,
wrong-format, truncated, and ordinarily corrupted archives before any
database/blob installation. The portable envelope is not a provenance signature:
for attacker-resistant origin/tamper evidence, retain an externally trusted
signature or checksum and protect the storage path. Older local v2 archives
remain supported when their original authenticated sidecar and local key are
still present.

Backup policy (`GET`/`PATCH /admin/backup-policy`) is executed by the durable
worker. Enabled `hourly`, `daily`, and `weekly` policies enqueue a generation
when due, enforce `retention_count`, then enqueue an independent full integrity
validation. `manual` never schedules work.

Retention hygiene (`POST /admin/retention/preview` then `/admin/retention/apply`)
prunes trashed files and old unpinned revisions per workspace policy. Preview is
always a dry run. This is recovery hygiene, not legal hold or eDiscovery.

For an off-host copy, stream the completed `.sxdbackup` to storage protected by
deployment controls and retain its job/archive hash receipt. Configure the
destination and credential in your deployment workflow, then verify recovery
with a restore drill.

## Upgrade procedure

Migrations run automatically on startup (`storage.migrate()` in `AppState::open`).
Production upgrades use the authenticated, root-private package lane in
[packaging/README.md](../../packaging/README.md#install-an-authenticated-release-package).
A reviewed locally built package remains a non-release route only when it is
staged, hash-bound, and extracted into the
root-private closure described in the
[local package procedure](../../packaging/README.md#install-a-locally-built-binary).
Keep `B` and the trap-managed `CURL_CONFIG` from the backup setup above available
for the backup request in this procedure.

```bash
# 1. Queue a backup first and wait for its durable job to succeed.
curl -s -K "$CURL_CONFIG" -X POST "$B/admin/backups"

# 2. Complete provenance verification and root-private staging exactly as in
#    packaging/README.md. Immediately before its admitted install command,
#    stop the active service so no process uses the binary being replaced. The
#    installer refuses to upgrade while the pre-lock service is still active.
sudo systemctl stop shellx-drive.service

# 3. From the verified root-private $stage/root assembled by that package lane:
sudo "$stage/root/install.sh"

# 4. The admitted installer starts the service; migrations apply on boot against
#    the same --data-dir. Verify the resulting service and build identity.
curl -fsS http://127.0.0.1:5758/health   # {"ok":true,...}
curl -fsS http://127.0.0.1:5758/ready     # expect "ready":true
curl -fsS http://127.0.0.1:5758/version   # {"version":...,"build":"x.y.z+sha",...}
sudo systemctl status shellx-drive.service --no-pager
```

Each build reports a unique id via `GET /version` (`version+shortsha`). After the
restart, **already-open server-administrator tabs detect the new build within
about 60 seconds and show a "new version available — reload" banner**. Ordinary
users are not shown server update notices. The separate administrator-only
Settings ▸ About control queries GitHub for a newer *published release* and can
open the exact Linux package and checksum. The administrator completes the
update: review the release, take a backup, verify the checksum, and run the
documented upgrade steps to install and restart the service. Configure the check
with `SHELLX_DRIVE_UPDATE_REPO` (see [CONFIG.md](CONFIG.md)); leave it empty to
disable the outbound check.

Roll back by reinstalling the previous binary and, if a migration changed the
schema incompatibly, restoring the pre-upgrade backup generation. Because the data
directory is the single source of truth, keep it on durable storage and snapshot
it (or a fresh completed backup generation) before every upgrade.

## Server maintenance

Keep deployment-specific host settings, credentials, and update scripts in
private operator configuration. `GET /admin/maintenance` returns redacted source
labels and policy intent. Perform live Ubuntu Pro/OS assessment through the
host-maintenance workflow; Drive reports `host_posture:"unassessed"`.

## v0.1 process-local limits

Run one Drive process for each data directory. Download/archive ticket capacity
and its admission order are in-memory per-process bounds, not a global
fairness scheduler across instances. Multiple Drive processes pointing at the
same data directory are unsupported for availability, tickets, restores, and
resumable uploads.

The legacy rclone v1 JSON export is separate from the streamed native download
path. It refuses workspaces above 10,000 active entries and exports at most 8
MiB aggregate raw UTF-8 file bytes. The JSON response can be larger because of
escaping, so use the native streamed file APIs for ordinary or large exports.
