# ShellX Drive First Install

This is the supported first-install path for a self-hosted ShellX Drive server.
It is written for both a person and an automation agent. The current package
lane needs an x86-64 Linux host with systemd, Bash, and standard GNU command-line
and system-account tools. Compatibility follows these host capabilities.
Use the authenticated release package, follow its installer, and check the
service and health endpoints below. The package and service checks cover a
normal installation. Use source builds for development and authenticated
release packages for production.

## What the installer guarantees

The admitted package installer:

- verifies every file in the extracted package before elevation crosses into
  the install helper;
- installs one binary and one hardened systemd service, bound to
  `127.0.0.1:5758` by default;
- creates a private service account, data directory, and root-owned mode-`0600`
  environment file;
- generates independent random operator and first-admin setup tokens; and
- requires the setup token for first-administrator creation and closes
  bootstrap permanently after the first account exists.

Configure DNS, TLS, firewall access, and the dedicated proxy route through their
owning services. The installer provides the loopback Drive service.

## 1. Freeze the intended topology

Before copying an artifact, decide and record:

- the final dedicated HTTPS origin, for example
  `https://drive.example.com` (scheme, hostname, and optional port);
- who owns DNS and TLS for that hostname;
- which existing reverse proxy or tunnel will route only that hostname to
  `http://127.0.0.1:5758`; and
- whether `/var/lib/shellx-drive` or `/srv/shellx-drive` will hold persistent
  data.

Choose a dedicated hostname for Drive. When Apache, nginx, Caddy, or
Cloudflare Tunnel already exists, add a host-specific route through that
service's maintained configuration, preserving its other routes and settings.

## 2. Read-only host preflight

Run these checks before root installation:

```bash
uname -m
cat /etc/os-release
systemctl --version
test -d /proc/self/fd
test -r /dev/urandom
systemctl is-active apache2 nginx caddy cloudflared 2>/dev/null || true
ss -ltn
test ! -e /etc/shellx-drive.env
test ! -e /var/lib/shellx-drive
test ! -e /srv/shellx-drive
```

For a fresh install, stop if a Drive environment file, selected data directory,
service unit, or listener on port 5758 already exists. Treat that host as an
upgrade or recovery investigation instead. Also stop if root access, the final
hostname, or permission to change the owning proxy/tunnel is unresolved.

## 3. Authenticate and stage the package

Choose a release that publishes its exact archive, pinned source revision,
repository, signer workflow, and publisher attestation. Verify package bytes
with the adjacent `.sha256` and authenticate the publisher through its
attestation before installation.

Follow the root-private verification and extraction sequence in
[`packaging/README.md`](../../packaging/README.md). That sequence is canonical:
it verifies the GitHub attestation, copies the archive to a new root-only stage,
checks `PACKAGE_CONTENTS.sha256`, and binds `RELEASE_PROVENANCE.json` to the
approved full source commit. Run the privileged installer only from that
verified root-private stage.

## 4. Dry-run, then install

From the verified root-private package stage:

```bash
sudo "$stage/root/install.sh" --dry-run \
  --public-base-url https://drive.example.com
sudo "$stage/root/install.sh" \
  --public-base-url https://drive.example.com
sudo systemctl is-active shellx-drive.service
```

The public origin is required on a first install and rejected on an upgrade.
The dry-run shows the planned paths and configuration. Installation must finish
with an active service and successful installation and sandbox setup. For a
startup failure, use the failure and recovery guidance below.
The installer prints the service bind and a root-only command that retrieves the
setup token. Keep generated tokens in the protected server configuration and
enter the setup token directly in the HTTPS setup form.

## 5. Add the HTTPS route

Use the matching example in [`OPERATIONS.md`](OPERATIONS.md#reverse-proxy--tls).
The route must terminate TLS and forward only to the loopback listener. Raise
the request-body limit for expected uploads. If proxy-derived client IP logging
is enabled, the final local proxy must overwrite the client-address header and
be the only process able to connect to Drive; see
[`CONFIG.md`](CONFIG.md#core).

For an existing Cloudflare Tunnel, add one ingress entry above its terminal
catch-all. For an existing Apache/nginx/Caddy installation, add a dedicated
virtual host/site. Verify that the other hostnames retain their existing routes
before reloading the owning service.

Verify both public endpoints:

```bash
curl --fail --silent --show-error https://drive.example.com/health
curl --fail --silent --show-error https://drive.example.com/ready
```

Successful installation requires health to report `ok:true` and readiness to
report `ready:true`.

## 6. Create the first administrator

1. On the server console, run the root-only setup-token retrieval command that
   the installer printed.
2. Open the final HTTPS origin in a browser.
3. Enter that setup token, the administrator email, a strong password twice,
   and the first workspace name.
4. Sign out, sign in again, and enable 2FA from the account security flow.
5. Confirm a second bootstrap attempt is rejected because an account now
   exists.

The setup token is requested only during bootstrap. Normal sign-in asks for a
TOTP or recovery code only when 2FA policy requires it.

## 7. Acceptance checklist

Before giving users the URL, record non-secret evidence for:

- exact package SHA-256, full source revision, and publisher-attestation result;
- service status and public `/health` plus `/ready` responses;
- the hostname, local upstream, and owning proxy/tunnel configuration identity;
- first-admin bootstrap closure and a new authenticated sign-in;
- an ordinary-user workspace upload, preview, download, share, and revoke; and
- backup creation, validation, off-host copy, and restore policy.

Keep these records limited to non-secret metadata, with credentials, session
values, recovery codes, and share capabilities removed.

## Failure and recovery boundary

- Resolve a failed dry-run's named precondition and complete the dry-run before
  proceeding with installation.
- If installation fails after it starts, preserve `/etc/shellx-drive.env`, the
  selected data directory, the verified package stage, and the service journal
  for diagnosis. Keep the configured data root and partial state intact while
  following the recovery procedure.
- If TLS or routing fails, leave Drive on loopback and repair only the
  host-specific proxy/tunnel route.
- If the wrong public origin was installed before any account exists, stop and
  correct the root-owned environment deliberately; upgrades preserve it.
- Service removal and persistent-data deletion are separate operator actions;
  preserve backups and require an exact deletion scope before removing data.

## Optional runtime diagnostics for operators

If a loader or library error prevents startup, retain the exact message and
package identity for support. Release operators can inspect an authenticated
binary's interpreter, needed libraries, and symbol requirements with binutils
when available. The normal installation procedure uses the package, service,
and health checks above:

```bash
sudo readelf --program-headers --dynamic --version-info /usr/local/bin/shellx-drive
sudo /usr/local/bin/shellx-drive --version
```

The selected binary determines its minimum loader and library ABI, and those
package requirements determine host compatibility. A successful `--version`
confirms loading; complete the service and health checks to verify operation.
Run diagnostics against the authenticated installed binary.

The installer uses Bash dynamic file descriptors, GNU coreutils
and findutils, `awk`, `grep`, `getent`, `useradd`, `groupadd`,
`/usr/sbin/nologin`, Linux `/proc/self/fd`, and `/dev/urandom`. Package staging
uses the attestation-capable GitHub CLI and GNU tar in the packaging guide.
The systemd manager and kernel must enforce the generated unit's filesystem,
process, namespace, syscall, and cgroup restrictions. Unknown or ignored
sandbox directives and sandbox failures need operator resolution with the unit's
protections retained. The dry-run checks paths and package identity; startup and
service checks verify runtime and sandbox support.
