# Security Policy

## Reporting a vulnerability

Email security disclosures to <martins.brezauckis@gmail.com> with the subject
line `[ShellX Drive security]`. Use that private channel for the initial sensitive
report, allowing time for coordinated disclosure before public discussion.

I aim to acknowledge valid reports within 72 hours and prioritize fixes based
on exploitability, data exposure, and whether the issue affects default
deployment.

## Scope

In scope:

- The ShellX Drive Rust server, web UI assets, and packaging scripts in
  this repository.
- Workspace authorization, including `Authorization: Bearer <token>`,
  `x-shellx-actor`, OIDC exchange tokens, and owner/editor/viewer role checks.
- Server-readable workspace storage, file-content authorization, and truthful
  confidentiality boundaries.
- guest shares and upload drops, including password verification, expiry, and
  revoke behavior.
- Debug API routes, redaction behavior, e2e guards, and service twin scenarios.
- Local package and systemd installer behavior.

Out of scope:

- Bugs in external reverse proxies, operating systems, browsers, WebDAV
  clients, or identity providers.
- Secrets or host credentials that operators store outside ShellX Drive.
- Data exposure caused by intentionally binding the service publicly without
  TLS, firewalling, and token handling reviewed.

## Trust model

ShellX Drive is a server component. Anyone with the configured bearer token can
act as the local admin unless an actor header or OIDC actor token is used to
enter workspace-role checks. Treat the token like a password.

Drive workspaces are server-readable by design. They enable indexing, previews,
WebDAV, Google Drive API subset downloads, rclone-style export, and guest
sharing. Organization owners/operators and administrators of the host or VPS
can technically access stored file bodies. For content privacy from those
operators, encrypt locally before upload, keep the encryption keys with the
client, and store the resulting ciphertext in Drive.

Drive server backups contain operator-readable, unencrypted restore material.
Protect backup media with encrypted host storage or an encrypted off-host
destination when required. Client encryption protects the uploaded file's bytes;
the remaining database and backup metadata retain their ordinary storage form.

The Debug API is intentionally powerful for local and release testing. Keep it
behind the same bearer-token controls as the rest of the server. The e2e seed
and reset helpers require `--e2e`. Use current administrator authority for seed
and the operator credential for reset, with disposable loopback test data.

Drive records server-observed IP and browser metadata for account-session
security and a bounded server-admin security ledger. Accounts can see only
their own active session metadata and sign-in history. Workspace/share owners receive aggregate
guest statistics, with visitor identities and IPs kept private. Debug/support
exports omit raw network metadata, credentials, request bodies, file content, and raw capability
URLs. Configure trusted proxy headers only when the documented loopback reverse
proxy boundary is enforced; otherwise clients could influence the recorded IP.

Password-derived public Share grants, Drop grants/sessions, and prepared Share
downloads are proof-of-possession bound to a separate random browser/native
client secret. IP fingerprints remain abuse-control and audit partitions only.
Copying a capability without its client secret must fail without consuming the
authorized client's bounded ticket. Passwordless Share URLs remain
intentionally transferable link capabilities.
