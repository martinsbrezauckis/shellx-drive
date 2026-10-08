# ShellX Drive Configuration

Every runtime knob for the `shellx-drive` server, verified against
`src/config.rs`. Configuration is split two ways:

- **CLI flags** — `--bind`, `--data-dir`, `--token-file`, `--e2e`, `--hosted`,
  `--help`, and `--version`.
- **Application environment variables** — named `SHELLX_DRIVE_*`. The binary
  reads only the variables listed below; everything else is a CLI flag.
- **Logging** — standard `RUST_LOG`, described below, controls tracing output.

> Configuration precedence: the binary reads `SHELLX_DRIVE_TOKEN` and
> optional `SHELLX_DRIVE_BOOTSTRAP_TOKEN` from the
> environment but reads the bind address and data directory **only** from the
> `--bind` / `--data-dir` flags. The `SHELLX_DRIVE_BIND` and `SHELLX_DRIVE_DATA_DIR`
> names that appear in `packaging/shellx-drive.env.example` are loaded by the
> installed systemd unit and expanded into its `ExecStart` arguments.

## CLI flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--bind <addr>` | `127.0.0.1:5758` | Listen socket address. Keep the loopback default and put a reverse proxy in front for TLS; binding publicly is an explicit operator decision. |
| `--data-dir <path>` | `.shellx-drive-data` | Root for the SQLite database (`drive.db`), the blob store, and resumable-upload scratch. Use a persistent path outside the source tree in production. |
| `--token-file <path>` | none | Read the server bearer token from a private, owner-owned regular file. On Unix the file must grant no group/other permissions. The path may appear in process arguments; the secret value never does. This overrides `SHELLX_DRIVE_TOKEN`. |
| `--e2e` | off | Enables the destructive `/debug/e2e/seed` and `/debug/e2e/reset` routes. It accepts only loopback `--bind` addresses (`127.0.0.1` or `::1`) and requires the same non-placeholder, minimum-length operator token as production. Use only for local/CI testing. |
| `--hosted` | off | Enables hosted (multi-tenant) mode (same as `SHELLX_DRIVE_HOSTED_MODE`). Workspace creation then requires a `tenant_id`. |
| `-h`, `--help` | n/a | Print operator-safe usage without requiring a configured token or data directory. |
| `-V`, `--version` | n/a | Print the binary version without starting the server. |

## Logging

| Variable | Default | Purpose |
| --- | --- | --- |
| `RUST_LOG` | `shellx_drive=info` | Standard `tracing` filter. When it is absent or invalid, Drive emits its own INFO, WARN, and ERROR operational events while suppressing dependency noise. Set `shellx_drive=debug` temporarily for more Drive detail. |

The checked-in systemd unit provides the same default, and
`/etc/shellx-drive.env` can override it. Service output is written to the
system journal; see [OPERATIONS.md](OPERATIONS.md#logs-and-operational-events).

## Core

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `SHELLX_DRIVE_TOKEN` | string | unset (startup refused) | The server bearer token. A private `--token-file` takes precedence when both are present. **Treat this as a password** — anyone holding it acts as the local admin actor `system@local` unless they also send an `x-shellx-actor` header or use an OIDC/SSO token. |
| `SHELLX_DRIVE_BOOTSTRAP_TOKEN` | string | unset | Optional authority accepted only by `POST /auth/bootstrap` and `POST /auth/bootstrap/wizard`. When configured, the operator token and browser sessions cannot substitute for it. The packaged installer generates an independent 256-bit value. Bootstrap is rejected after the first account exists. |
| `SHELLX_DRIVE_BACKUP_MAX_ARCHIVE_BYTES` | u64 | `9895604649984` (9 TiB; clamped to 1 MiB..9 TiB) | Maximum accepted or produced v2 archive size. Creation also preflights available filesystem space plus a fixed reserve before opening the archive partial. |
| `SHELLX_DRIVE_TRUST_PROXY_HEADERS` | bool | off | Honor `X-Forwarded-For`, `CF-Connecting-IP`, or `X-Real-IP` only when the direct peer is loopback. Enable this only when a trusted local reverse proxy is the sole process able to connect to Drive; otherwise leave it off so clients cannot choose their rate-limit identity. The standardized `Forwarded` header is not parsed. |

### Configure the operator and setup tokens

Supply a strong random operator token in every mode. Startup validation in
`src/config.rs` rejects values that are:

- **unset** — no `--token-file` and no `SHELLX_DRIVE_TOKEN`;
- **empty**;
- a **known placeholder** — `dev-token`, `change-me`/`changeme`, or anything
  containing `replace_with` / `replace-with` / `your-token` / `example-token`
  (matched case-insensitively, so the shipped `REPLACE_WITH_A_STRONG_RANDOM_TOKEN`
  is rejected); or
- **shorter than 16 characters**.

The error names the reason (unset / empty / placeholder / too short) and never
echoes the token value, for example:

```
SHELLX_DRIVE_TOKEN is set to a known placeholder value. Set SHELLX_DRIVE_TOKEN
(or pass --token-file pointing to a private secret file) to a strong random
secret of at least 16 characters, for
example: `openssl rand -hex 32`. Pass --e2e only for local testing.
```

Generate a strong random secret with `openssl rand -hex 32` and supply it through
a private token file or the protected service environment. The 16-character
minimum is a validation floor; random generation supplies the required entropy.

When `SHELLX_DRIVE_BOOTSTRAP_TOKEN` is configured, the same placeholder and
minimum-length guard applies to it in every mode. Keep it distinct from the
operator token. Its authority covers first-account creation only, which storage
permanently refuses after one account exists. Existing installations that omit
it retain the legacy operator-token bootstrap path.

`--e2e` remains local-only: it rejects every non-loopback `--bind` address and
also rejects empty, short, or placeholder operator tokens. Supply a strong random token
for E2E through `SHELLX_DRIVE_TOKEN` or `--token-file`, and keep the bind on
`127.0.0.1` or `::1`. Weak test tokens are rejected in every mode.

## Session cookies

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `SHELLX_DRIVE_SECURE_COOKIES` | bool | **on in production, off under `--e2e`** | Uses the production `__Host-shellx_drive_session` cookie with browser-enforced `Secure; Path=/` and no `Domain` attribute, so browsers send it only over HTTPS and sibling subdomains cannot set a competing cookie. Gated on config rather than the request scheme because Drive sits behind a TLS-terminating reverse proxy (the request reaching the app is plain HTTP). Accepts `1/true/yes/on` and `0/false/no/off`; an explicit value overrides the default, and any other non-empty value fails startup. Keep it on in production. `false` is accepted only under `--e2e` or when **both** `--bind` and `SHELLX_DRIVE_PUBLIC_ORIGIN` are loopback. The insecure mode uses the distinct `shellx_drive_session_dev` cookie name so it cannot collide with the production cookie. Both variants are always `HttpOnly; SameSite=Lax`. |
| `SHELLX_DRIVE_LOCAL_SESSION_TTL_SECONDS` | i64 | `2592000` (30 days; clamped to 1 hour..365 days) | Lifetime for local email/password browser sessions and the matching production `__Host-shellx_drive_session` cookie (or the `shellx_drive_session_dev` cookie in intentionally insecure loopback/e2e mode). Increase/decrease this for private deployments that should stay signed in longer or enforce shorter admin sessions. |

## Public origin

Drive has one canonical browser origin for reset and invitation links, browser
write-origin checks, and hosted status. It must be an `https://` origin in
production; `http://` is accepted only for `localhost`, `127.0.0.1`, or `::1`
development addresses. It has no credentials, path, query, or fragment. This
prevents a link generator, CSRF check, or hosted response from silently using a
different authority. A network-reachable production bind requires a
non-loopback public origin; keep the bind on loopback when a local TLS proxy
serves the final external origin.

Cookie-authenticated mutations require an exact `Origin` match. When an
ordinary same-origin browser omits that header, Drive accepts only a parseable,
credential-free `Referer` whose origin exactly matches this value; a present
invalid or foreign `Origin`, a foreign `Referer`, and absent provenance remain
forbidden. Bearer-authenticated API clients retain their explicit credential
contract.

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `SHELLX_DRIVE_PUBLIC_ORIGIN` | strict origin URL | `http://127.0.0.1:5758` | Canonical public browser origin. Host case and default ports are normalized before comparison. |
| `SHELLX_DRIVE_EMAIL_BASE_URL` | legacy strict origin URL | unset | Compatibility alias for `SHELLX_DRIVE_PUBLIC_ORIGIN`. It is accepted only when it resolves to the same canonical origin as every other configured alias. Migrate new and existing configuration to `SHELLX_DRIVE_PUBLIC_ORIGIN`. |
| `SHELLX_DRIVE_HOSTED_PUBLIC_BASE_URL` | legacy strict origin URL | unset | Compatibility alias for `SHELLX_DRIVE_PUBLIC_ORIGIN`, with the same equality requirement. |

## Email outbox and manual delivery

User actions (password reset, invitation, share notice, comment notice) write
redacted rows to an inspectable outbox. Use the debug/admin runner to process
the `capture` transport for inspection; its `sent` status means capture processing
rather than recipient delivery. Deliver invitation and share links through a
trusted channel. The SMTP variables below describe configuration posture;
capture inspection and manual delivery are the supported workflow. Status
responses represent secret-bearing SMTP settings as `configured` /
`not_configured` source labels.

The browser labels password recovery as a queued operator request. To complete
recovery, a server administrator selects an existing account in
**Admin center → Accounts** and creates a manual recovery link. The
link is returned once to that authenticated administrator, expires after one
hour by default (5 minutes to 24 hours can be requested through the API), and
is invalidated after use, replacement, password change, or explicit revocation.
Copy it through a trusted out-of-band channel. Drive stores only the manual
link's hash; no outbox, account list, receipt, or security event contains that
link or token. Confirm recipient delivery through the chosen trusted channel.

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `SHELLX_DRIVE_UPDATE_REPO` | string (`owner/repo`) | disabled | Public GitHub repository that the administrator-only `GET /update/check` queries for a newer server release. Must be a bare `owner/repo` slug — URLs, `github.com/...`, and paths are rejected so the update check can never be pointed at an arbitrary host. Configure the official release repository after your deployment has deliberately assigned one; leave it unset or empty to keep the outbound check disabled. Ordinary users never see server update notifications or controls. The administrator-only in-app reload banner is local and independent of this setting. |
| `SHELLX_DRIVE_EMAIL_TRANSPORT` | string | `capture` | Outbox transport. `capture` queues + marks-sent for inspection (`/debug/email`, `POST /debug/email/run`). Any other value is recorded but is not processed by the capture runner. |
| `SHELLX_DRIVE_EMAIL_FROM` | string | `ShellX Drive <noreply@shellx.local>` | From header written onto queued outbox messages. |
| `SHELLX_DRIVE_SMTP_HOST` | string (label) | not_configured | SMTP host posture. Debug/admin responses show its presence as a `configured`/`not_configured` **source label**, keeping the value private. |
| `SHELLX_DRIVE_SMTP_PORT` | u16 | none | SMTP port. Parsed as a number and surfaced verbatim in email status (it is not a secret). |
| `SHELLX_DRIVE_SMTP_USERNAME` | string (label) | not_configured | SMTP username. Stored only as a source label, like the host. |

## Office provider

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `SHELLX_DRIVE_OFFICE_PROVIDER_NAME` | string | `Office editor` | Display name for the external office editor provider. |
| `SHELLX_DRIVE_OFFICE_PROVIDER_URL` | string (URL) | none | When set, `POST /office/files/{id}/open` mints a token-scoped edit session and returns a one-use same-origin handoff URL. The handoff POSTs session/package routes to the configured provider without putting the bearer in a URL. Non-loopback providers must use HTTPS; loopback HTTP is allowed for local development. Remote provider handoff is allowed only for open workspaces. When unset, Drive reports no provider and keeps the manual/agent save path available — there is no built-in editor dependency. |
| `SHELLX_DRIVE_OFFICE_SESSION_TTL_SECONDS` | i64 | `900` (clamped to 60..3600) | Lifetime of a minted office edit-session token. Derived Office capabilities remain bound to the exact source login session or app token and stop working when that credential is revoked or expires. |

## Hosted mode

Hosted mode is a metadata layer above self-host mode and is **off by default**.
The OSS binary makes no billing or scanner network calls; the variables below only
describe posture reported by `GET /hosted/status`.

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `SHELLX_DRIVE_HOSTED_MODE` | bool | off | Enable hosted mode (same as `--hosted`). Accepts `1`, `true`, `yes`, `on`. When enabled, `POST /workspaces` requires `tenant_id`. |
| `SHELLX_DRIVE_HOSTED_BILLING_PROVIDER` | string | `none` | Billing posture label (e.g. `none`, `manual`). No integration is called. |
| `SHELLX_DRIVE_HOSTED_PUBLIC_RATE_LIMIT_PER_MINUTE` | i64 | `60` (minimum 1) | Public rate-limit posture value reported by `/hosted/status`. The v0.1 public hosted-signup compatibility route remains disabled pending verified-email enrollment. |

## Maintenance secret sources (Ubuntu Pro / sudo)

Use these settings to document **where** operator secrets come from for private
server-maintenance work. Responses show `configured` / `not_configured` source
labels. Perform host commands and Ubuntu Pro assessment through the operator's
host-maintenance workflow; Drive reports maintenance `host_posture:"unassessed"`.

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `SHELLX_DRIVE_UBUNTU_PRO_TOKEN_SOURCE` | string (label) | not_configured | Records that an Ubuntu Pro/ESM token source is configured for operator maintenance documentation; it is not read or probed by Drive. |
| `SHELLX_DRIVE_SUDO_SOURCE` | string (label) | not_configured | Records that a sudo-password source is configured for operator maintenance documentation; it is not read or used by Drive. |

## Minimal production example

```bash
# /etc/shellx-drive.env  (mode 0600, owned by root:root)
SHELLX_DRIVE_BIND=127.0.0.1:5758          # consumed by the systemd install script → --bind
SHELLX_DRIVE_DATA_DIR=/var/lib/shellx-drive  # consumed by the systemd install script → --data-dir
SHELLX_DRIVE_TOKEN=<output of: openssl rand -hex 32>   # REQUIRED — replace any placeholder
SHELLX_DRIVE_BOOTSTRAP_TOKEN=<independent output of: openssl rand -hex 32>
SHELLX_DRIVE_TRUST_PROXY_HEADERS=true        # trusted local TLS reverse proxy is the only peer
SHELLX_DRIVE_PUBLIC_ORIGIN=https://drive.example.com
SHELLX_DRIVE_LOCAL_SESSION_TTL_SECONDS=2592000
RUST_LOG=shellx_drive=info
```

Run behind a reverse proxy that terminates TLS and forwards to the loopback bind
address. See [OPERATIONS.md](OPERATIONS.md) for proxy, backup, and upgrade runbooks.
