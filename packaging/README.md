# ShellX Drive Service Packaging

ShellX Drive is packaged as a binary-first Linux service that runs directly
under systemd.
For the complete host preflight, proxy-coexistence, first-admin, and health-check
sequence, start with [`docs/public/FIRST_INSTALL.md`](../docs/public/FIRST_INSTALL.md).

This directory packages the self-hosted server. For the Linux desktop, choose
the AppImage or .deb and verify its Tauri/minisign signature against the
authenticated Drive updater public key. See the
[Linux desktop guide](../docs/public/LINUX_DESKTOP.md) for installation,
runtime requirements, and recovery.

## Build

```bash
cargo build --release --bin shellx-drive
```

## Create A Local Package

```bash
binary_sha256="$(sha256sum target/release/shellx-drive | awk '{print $1}')"
./scripts/package_binary.sh \
  --binary target/release/shellx-drive \
  --sha256 "$binary_sha256" \
  --out-dir target/package
```

The packager opens and hashes the binary plus every support input before it
starts staging. It then copies only from those pinned descriptors, verifies the
staged bytes, and includes `SOURCE_INPUTS.sha256` in the archive so the exact
binary, installer, service, documentation, license, and skill inputs are
auditable after packaging. `PACKAGE_CONTENTS.sha256` covers every shipped file,
and `RELEASE_PROVENANCE.json` records the version, binary hash, package identity,
and source revision when the release lane supplies one. Local packages record
a null source revision for development; release packages record the approved
source revision.

The archive keeps public guides and their linked resources at their
source-relative paths, so the bundled agent skill and documentation work
offline.

The release SBOM catalogs the root and desktop product lockfiles. The retained
updater's standalone upstream `Cargo.lock` is kept in source provenance but
excluded from dependency cataloging because the desktop workspace resolves
that path dependency through `desktop/Cargo.lock`. All vendor sources and
resolved product dependencies remain included. Download the SBOM, source-input
receipt, source provenance, and `SHA256SUMS` into one directory; its relative
checksum entries can be verified there with `sha256sum --check --strict SHA256SUMS`.

## Install An Authenticated Release Package

Use the adjacent `.sha256` to verify package bytes and the GitHub artifact
attestation to authenticate the publisher. A release-qualified archive must
come from the manual `release-candidate-attestation` workflow dispatched by the
repository owner on the official `main` branch and must pass GitHub
artifact-attestation verification for the exact official repository and
`.github/workflows/release-candidate.yml` signer workflow.

The official repository coordinate is
`martinsbrezauckis/shellx-drive`. A Linux archive qualifies as a ShellX Drive
release only when its manual candidate workflow and publisher attestation bind
it to the approved full source revision in that repository. Verify both the
official repository identity and the publisher attestation.

To install an attested release package, use a GitHub CLI version whose
`gh attestation verify --help` command succeeds, then copy the downloaded archive
into a fresh root-private directory **before** verification or extraction:

```bash
archive=/absolute/path/to/downloaded-server-archive.tar.gz
RELEASE_REPOSITORY=martinsbrezauckis/shellx-drive
RELEASE_SOURCE_REF=refs/heads/main # official owner-dispatched release branch
RELEASE_SOURCE_DIGEST=0123456789abcdef0123456789abcdef01234567 # approved full commit SHA
stage="$(sudo mktemp -d /var/tmp/shellx-drive-install.XXXXXXXX)"

sudo install -m 0600 -- "$archive" "$stage/package.tar.gz"
sudo -H gh attestation verify "$stage/package.tar.gz" \
  --repo "$RELEASE_REPOSITORY" \
  --signer-workflow "$RELEASE_REPOSITORY/.github/workflows/release-candidate.yml" \
  --source-ref "$RELEASE_SOURCE_REF" \
  --source-digest "$RELEASE_SOURCE_DIGEST" \
  --deny-self-hosted-runners

sudo install -d -m 0700 "$stage/root"
sudo tar --extract --gzip --file "$stage/package.tar.gz" \
  --directory "$stage/root" --strip-components=1 \
  --no-same-owner --no-same-permissions
sudo /bin/sh -c 'cd "$1" && /usr/bin/sha256sum --check --strict PACKAGE_CONTENTS.sha256' \
  sh "$stage/root"
sudo /bin/sh -c 'cd "$1" && expected="$2"; grep -F "\"source_revision\":\"$expected\"" RELEASE_PROVENANCE.json >/dev/null' \
  sh "$stage/root" "$RELEASE_SOURCE_DIGEST"
sudo "$stage/root/install.sh" --dry-run --public-base-url https://drive.example.com
# On a fresh installation, use the final public HTTPS origin.
sudo "$stage/root/install.sh" --public-base-url https://drive.example.com
# On an upgrade, stop an active service immediately before the admitted install,
# then omit --public-base-url so the existing policy remains unchanged. The
# installer refuses an upgrade while the pre-lock service is still active.
# sudo systemctl stop shellx-drive.service
# sudo "$stage/root/install.sh"
sudo rm -rf --one-file-system -- "$stage"
```

Run the privileged installer only from the verified root-private package stage.
The root-private sequence prevents another process owned by the downloading user
from racing a helper or binary replacement after provenance verification. If an
install fails, retain the root-only stage for investigation or remove only the
exact path returned by `sudo mktemp`.

The admitted package-root installer verifies `PACKAGE_CONTENTS.sha256`, reads
the binary digest from `SOURCE_INPUTS.sha256`, and prevents callers from
replacing its `--binary` or `--sha256`.
On a fresh install, `--public-base-url` is required and must be the final HTTPS
origin (for example `https://drive.example.com`). The
privileged installer writes it as `SHELLX_DRIVE_PUBLIC_ORIGIN` in a new
root-owned mode-`0600` `/etc/shellx-drive.env`, alongside independently
generated 256-bit operator and first-admin setup tokens. It creates the private
data directory and starts the loopback-bound service. An upgrade preserves the
existing environment file and all data; omit `--public-base-url` for an upgrade.
It reads the existing `SHELLX_DRIVE_DATA_DIR` and preserves the same
data root in the systemd write allowance, including `/srv/shellx-drive`.
An explicit `--data-dir` must match that existing value; changing storage roots
requires a separate storage migration.

The final output gives a root-only command for retrieving the setup token.
Retrieve it on the server console and enter it directly in the HTTPS setup form;
keep it confined to that setup flow. Configure a trusted TLS reverse proxy, open
Drive through that HTTPS address, and create the first administrator. Bootstrap
requires the setup token, and the setup endpoint closes permanently as soon as
the first account exists.

Configure DNS and TLS through their owning services. The admitted installer
produces a secure loopback service; remote access uses the Caddy/nginx/Cloudflare
TLS step in
[the operations runbook](../docs/public/OPERATIONS.md#reverse-proxy--tls).

## Install A Locally Built Binary

Use this route for a reviewed development installation. Production release
installation uses the publisher-attestation procedure above. Package the local
build as an ordinary user, then execute the verified installer and its helpers
from the same root-private stage used by the release package procedure.

```bash
git diff --quiet
cargo build --locked --release --bin shellx-drive
binary_sha256="$(sha256sum target/release/shellx-drive | awk '{print $1}')"
out_dir="$(mktemp -d target/shellx-drive-local-package.XXXXXXXX)"
package_output="$(./scripts/package_binary.sh \
  --binary target/release/shellx-drive \
  --sha256 "$binary_sha256" \
  --out-dir "$out_dir")"
archive="$(printf '%s\n' "$package_output" | awk -F= '/^PACKAGE=/{print $2; exit}')"
test -n "$archive" && test -f "$archive"
archive_sha256="$(sha256sum -- "$archive" | awk '{print $1}')"

stage="$(sudo mktemp -d /var/tmp/shellx-drive-local-install.XXXXXXXX)"
sudo install -m 0600 -- "$archive" "$stage/package.tar.gz"
staged_archive_sha256="$(sudo sha256sum -- "$stage/package.tar.gz" | awk '{print $1}')"
test "$staged_archive_sha256" = "$archive_sha256"
sudo install -d -m 0700 "$stage/root"
sudo tar --extract --gzip --file "$stage/package.tar.gz" \
  --directory "$stage/root" --strip-components=1 \
  --no-same-owner --no-same-permissions
sudo /bin/sh -c 'cd "$1" && /usr/bin/sha256sum --check --strict PACKAGE_CONTENTS.sha256' \
  sh "$stage/root"
sudo "$stage/root/install.sh" --dry-run \
  --public-base-url https://drive.example.com
sudo "$stage/root/install.sh" \
  --public-base-url https://drive.example.com
sudo rm -rf --one-file-system -- "$stage"
```

Create the package as the reviewed, unprivileged build user; its closure records
the binary and each installer input in `SOURCE_INPUTS.sha256`, then records every
archive entry in `PACKAGE_CONTENTS.sha256`. Before root extracts it, copy the
archive into the newly created root-only stage and compare its root-read digest
with the digest captured before elevation. Root then verifies the extracted
closure and executes only `$stage/root/install.sh` and its root-private helpers.
This procedure verifies the selected local build. Use GitHub publisher
attestation to authenticate a release package.

The admitted installer rejects links and special files, copies the verified
binary into a protected staging file, checks the staged bytes, and publishes the
binary with an atomic rename. Every real install requires `--sha256`, pinning
the exact build selected before privilege elevation; only `--dry-run` permits
omitting it. The privileged script uses a fixed `/bin/bash` interpreter and a
trusted system search path for resolving root helpers.

The privileged installer's `--data-dir` accepts only
`/var/lib/shellx-drive` (the default) or `/srv/shellx-drive`. The server binary's
general `--data-dir` CLI supports its own path selection. On a first install,
leave the selected leaf directory absent so the installer can create it for
`shellx-drive:shellx-drive`. On an upgrade, an existing data directory must
already have that ownership. The installer admits physical directories with
that ownership and ordinary directory ancestry, preserving operator-owned paths.

The environment file and every existing directory above it must be root-owned
with write access restricted to root. Existing files must be regular `root:root`
files with mode `0600` or compatible legacy `0640`; links and special files are
rejected. New environment files are created as `root:root 0600`, and the full
path is revalidated immediately before the service is started.

The install destinations are held to the same ancestry rule: every existing
component of `--prefix/bin` and `--service-dir` must be a physical root-owned
directory with write access restricted to root. Missing components are created
one at a time only below a verified parent. The binary and unit are
staged and published through verified directory descriptors, with staged-file
identity and checksum checks before the final atomic rename. For a custom
destination, create and secure its intended parent hierarchy before invoking
the installer.

For a locally built package install, the same installer generates both secrets
and records the explicit HTTPS browser origin when `/etc/shellx-drive.env` is
absent. Upgrades preserve the existing environment file and reject
`--public-base-url`, keeping browser Origin/email-link policy stable while
replacing the binary.

The systemd unit reads `SHELLX_DRIVE_TOKEN` and the setup-only
`SHELLX_DRIVE_BOOTSTRAP_TOKEN` from that protected env file, keeping their values
within the protected service environment.

The unit defaults `RUST_LOG` to `shellx_drive=info`, and the environment example
sets the same value explicitly. This selects Drive INFO, WARN, and ERROR events
for the system journal. An operator can override the unit fallback in
`/etc/shellx-drive.env`; see
[the operations log runbook](../docs/public/OPERATIONS.md#logs-and-operational-events).

The default bind address is `127.0.0.1:5758`. Keep that loopback default when
placing ShellX Drive behind a reverse proxy. Configure the TLS proxy for the
exact `--public-base-url` before first browser use. Configure the proxy's
listener and certificate to provide the public HTTPS endpoint. Binding publicly
should be an explicit operator decision with TLS, firewalling, and token
handling reviewed.

The strict service profile also applies `MemoryHigh=512M` and `MemoryMax=768M`.
Large file bodies remain storable, while previews/search extraction use smaller
application-level budgets that bound derived-data memory independently of
the 2 GiB resumable-upload ceiling. Adjust the unit limits deliberately for a
larger installation and rerun the archive/image adversarial tests afterward.
