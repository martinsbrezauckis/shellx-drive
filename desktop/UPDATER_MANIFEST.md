# Cross-platform updater manifest

`latest.json` combines the completed native candidate lanes for one exact
source commit, source tree, desktop version, and chosen publication timestamp.

Each native signing lane emits one local candidate witness after its own
identity checks have succeeded:

- Windows: `windows-updater-candidate.json`, after Tauri signature verification
  and the authenticated Windows signing receipt are present.
- macOS arm64: `macos-updater-candidate.json`, after Developer ID,
  notarization, stapling, Gatekeeper, and Tauri signature checks are present.
- Linux x86_64: `linux-updater-candidate.json`, after OpenPGP package,
  AppImage, candidate-manifest, and Tauri signature checks are present.

Linux admission checks GTK 3, WebKitGTK 4.1, the compatible AppIndicator tray
runtime, and an ordinary-user Secret Service session. Compatibility follows
required runtime capabilities and the candidate's dependencies and ABI. Follow
the [Linux desktop guide](../docs/public/LINUX_DESKTOP.md) for installation and
verification.

Before installing the Linux candidate, run the public-source
`verify-linux-trusted-release.py` with a caller-supplied keyring and full pinned
fingerprint obtained outside the candidate. Its signed terminal attestation
binds the Linux updater witness and artifact bytes. Reuse that same external
verifier after installation with `--installed-root /`; it checks the exact
packaged `/usr/bin/shellx-drive-desktop` identity and verifier closure. The
verifier bundled in the Debian package is convenience tooling, not a bootstrap
trust anchor.

The witness records the exact source, target, platform-specific identity
evidence digest, updater archive digest, and signature digest. The compiler
reopens each file without following links; it rejects path traversal,
symlinks, duplicate or missing platforms, source/version/target drift,
malformed Tauri signatures, unexpected fields, and any changed evidence or
artifact bytes.

From a private release staging area, compile the manifest with all three
witness paths. The publication timestamp is explicit so the output is
deterministic for the exact candidate.

```sh
node desktop/scripts/generate-updater-manifest.mjs \
  --version 0.1.1 \
  --source-commit <40-lowercase-hex> \
  --source-tree <40-lowercase-hex> \
  --pub-date 2026-09-02T12:00:00.000Z \
  --repository martinsbrezauckis/shellx-drive \
  --candidate /private/windows/windows-updater-candidate.json \
  --candidate /private/macos/macos-updater-candidate.json \
  --candidate /private/linux/linux-updater-candidate.json \
  --candidate /private/linux/linux-deb-updater-candidate.json \
  --out /private/release/latest.json
```

The result contains exactly `windows-x86_64`, `darwin-aarch64`,
`linux-x86_64`, and `linux-x86_64-deb`. Its URLs reference the corresponding
signed updater inputs. The compiler does not replace native identity verification:
the Windows, macOS, and Linux candidate receipts must each be independently
validated on their native release host before this local assembly step.

The compiler accepts only `martinsbrezauckis/shellx-drive` and emits the exact
HTTPS GitHub release-asset URL for each signed filename and version. The client
rejects any other feed or initial artifact URL before requesting it. GitHub may
redirect an admitted request only to the exact same GitHub asset URL or the
official GitHub release-CDN hosts over HTTPS; redirects are limited to three,
do not send a referrer, and reject credentials, non-default ports, and fragments.

Publish `latest.json` together with the four updater artifacts. Store candidate
witnesses and native verification receipts in protected staging.

Each updater signature must authenticate the following exact artifact filename
in its Minisign trusted comment, with the admitted package version substituted:

| Platform | Signed filename |
| --- | --- |
| Windows x64 NSIS | `ShellX Drive Desktop_<version>_x64-setup.exe` |
| macOS arm64 | `ShellX Drive Desktop_<version>_aarch64.app.tar.gz` |
| Linux x64 AppImage | `ShellX_Drive_<version>_amd64.AppImage` |
| Linux x64 Debian | `shellx-drive_<version>_amd64.deb` |

The native signer uses Tauri's exact `timestamp:<digits>\tfile:<filename>`
trusted-comment format. The version comes from the admitted package identity;
the signature is made after Authenticode, Apple, or Linux package signing has
finished changing the bytes. The compiler rejects mismatched names/comments.
At runtime the client verifies both Minisign signatures before reading the
comment, checks its own OS/architecture/package type and selected URL filename,
and requires the authenticated version to equal the advertised version and
advance the running version. Direct installation repeats these checks. An
unsigned `latest.json` announcement alone therefore cannot authorize an older
signed installer. Manual operator downgrade or uninstall/reinstall resets this
running-version boundary; it is separate from feed-driven updating.

Run the collect-all static/adversarial gates before native qualification:

```sh
pnpm --dir desktop test:windows-updater
pnpm --dir desktop test:macos-packaging
pnpm --dir desktop test:linux-packaging
```
