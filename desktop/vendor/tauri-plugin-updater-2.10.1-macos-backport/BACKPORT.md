# macOS and Linux updater replacement backport provenance

This directory retains the complete crates.io `tauri-plugin-updater` 2.10.1
source archive for the desktop workspace.

- Base archive: `tauri-plugin-updater-2.10.1.crate` from the existing Cargo
  registry cache.
- Verified SHA-256:
  `806d9dac662c2e4594ff03c647a552f2c9bd544e7d0f683ec58f872f952ce4af`.
- Base source VCS revision: `d6a3898001a4bcc659e045f9501498751b77dbe6`,
  retained in `.cargo_vcs_info.json`.
- Upstream source checked: the official
  [plugins-workspace `v2` updater](https://github.com/tauri-apps/plugins-workspace/blob/v2/plugins/updater/src/updater.rs)
  still carries the same macOS privileged replacement at 2.11.0; no fixed
  upstream release was available on 2026-09-08. The retained directory name
  preserves the original macOS backport provenance while this reviewed closure
  also fixes the Linux AppImage replacement path.

The package changes beyond the complete upstream archive are exactly:

- modified upstream files `Cargo.lock`, `Cargo.toml`, `Cargo.toml.orig`, `src/error.rs`, and
  `src/updater.rs`;
- this `BACKPORT.md` and the retained integrity inventory `SHA256SUMS`;
- update response bounds in `src/updater/download_bounds.rs` with regressions
  in `src/updater/download_bounds_tests.rs`;
- installed-package classification in `src/updater/installed_package.rs` with
  regressions in `src/updater/installed_package_tests.rs`;
- Linux replacement and privilege helpers in
  `src/updater/linux_replacement.rs` and `src/updater/linux_privileges.rs`,
  with their respective `_tests.rs` children, plus `linux_privileges/` modules
  `sealed_package.rs` and `command_environment.rs` and their `_tests.rs` children;
- macOS replacement in `src/updater/macos_replacement.rs`, its
  `macos_replacement_tests.rs` child, shared
  `macos_replacement.applescript`, and the no-harness main-thread probe
  `tests/macos_replacement_osakit.rs`; and
- signed release identity in `src/updater/signed_release.rs`, with
  `src/updater/signed_release/tests.rs` and its `fixtures.json`; and
- fixed-origin release transport in `src/updater/release_url_policy.rs`, with
  native unit tests and desktop static wiring tests.

The direct macOS `libc` declaration supports atomic `RENAME_EXCL` moves;
the Linux declaration supports sealed in-memory package descriptors.
`libc` was already present in the locked dependency graph, so this adds no new
resolved crate or feature.

1. The privileged fallback passes source, incoming bundle, staging, backup,
   and a fixed shell program as `OSAKit` handler values. Its fixed AppleScript
   uses `quoted form of` for every positional shell argument, so no local path
   is interpolated into AppleScript or shell source.
2. Both paths stage the verified replacement as a sibling on the destination
   filesystem before moving the installed bundle. The unprivileged path uses
   atomic `RENAME_EXCL` moves. The privileged fallback uses `mv -n` only with
   source/destination device-and-inode identity checks and fails closed on a
   competing path; it does not treat that shell primitive as atomic. Both paths
   restore the prior bundle if moving the staged replacement fails, retain the
   recovery backup until success, and drop an unmoved owned staging directory
   after a pre-move error or authorization cancellation. The privileged branch
   keeps its native administrator prompt.
3. macOS-only regressions cover apostrophes, double quotes, backslashes,
   newlines, Unicode, and spaces through an actual unprivileged OSAKit command
   round-trip on the process main thread; staged-copy failure; destination
   occupancy; and rollback. No test invokes an administrator prompt.
4. The Linux AppImage path writes and validates all incoming bytes in an owned
   sibling staging file before its single replacement commit. It verifies the
   ELF/AppImage header, drains compressed archive input through its gzip trailer,
   preserves the installed mode, syncs the staged bytes, and replaces the old
   regular file only with `persist`. A malformed or truncated payload leaves the
   installed AppImage untouched and drops only the owned staging file.
5. The Linux `.deb` and `.rpm` privilege path treats a started `pkexec`,
   `zenity`, or `kdialog` process as terminal: cancellation or non-success
   never opens another credential prompt. Only an `ENOENT` command lookup
   permits the next fallback. Dialog output removes its final LF delimiter
   only, preserves password whitespace, rejects invalid or multi-line output,
   and sends GUI-sudo output to null descriptors before waiting. The terminal
   fallback retains interactive `sudo` when a terminal exists and uses `sudo
   -n` otherwise, avoiding a headless prompt that cannot be answered.

6. ShellX Drive authenticates the advertised update version using the artifact
   filename in Minisign's globally signed trusted comment. Both download and
   direct install verify bytes and the global signature before interpreting the
   comment; require an exact product/version/platform/package filename and an
   admitted release URL; and require a semantic version strictly above the
   running version. The signed comment retains the original package filename;
   the transport also accepts its exact GitHub space-to-dot filename mapping.
   A public-feed publisher cannot replay an older signed artifact by changing
   its advertised version. The four admitted packages are Windows x64 NSIS,
   macOS arm64 app archive, Linux x64 AppImage, and Linux x64 Debian. Other
   package types and custom comparator downgrade attempts fail closed.
   The ordinary upstream `timestamp:<u64>\tfile:<leaf>` comment format is an
   explicit release contract; native signers derive the leaf from admitted
   package identity and the manifest compiler checks the same contract.
   Tests use a disposable fixture key and inert bytes. No fixture private key
   is retained. Manual operator downgrades or uninstall/reinstall establish a
   new running-version boundary; this does not impose a persistent recovery
   version floor.

7. Separately signed raw Windows/Linux executables retain Tauri's unknown
   bundle marker. All updater selection and installation paths use the same
   local package classifier: the sole Windows format is NSIS; the fixed Debian
   executable selects Debian only when no AppImage replacement path overrides
   it; AppImage requires the running payload under a live FUSE mount and a
   distinct regular, executable, owner-safe Type-2 AppImage. An arbitrary raw
   Linux build is not treated as an installed package. Known Tauri bundle
   markers retain their existing meaning. This does not infer platform or
   package type from the unsigned feed, alter signed raw executable bytes, or
   relax artifact/version signature verification.

8. Update-feed responses are limited to 1 MiB and downloaded compressed
   installers are limited to 512 MiB. Both declared `Content-Length` and the
   checked cumulative streamed byte count are rejected before the receiving
   buffer grows past its limit. Installer progress callbacks run only after an
   accepted chunk is retained, and the completion callback still runs only
   after a complete bounded download. The 512 MiB ceiling leaves more than 100
   times the size of the retained 4,564,847-byte Windows 0.1.0 NSIS updater
   artifact while bounding unsigned network bytes before signature
   verification. Unit regressions cover exact limits, declared overflow,
   cumulative overflow, and rejection without buffer growth. Archive
   extraction remains downstream of signature verification and is unchanged.
   Limit failures use the dedicated `ResponseTooLarge` error.

9. Linux Debian/RPM installation retains verified bytes in a sealed memfd until
   the privilege helper finishes. After applying and checking seals, it compares
   the full sealed length and bytes with the signed input before exposing the
   descriptor path. This rejects same-user writes during the pre-seal interval.
   Privilege and password-dialog helpers use absolute system paths and a
   restricted environment; package-manager lookup does not use ambient PATH.
   Native module tests cover pre/post-seal tampering and helper behavior. They
   do not replace elevated installed-update and relaunch qualification.

10. The fixed feed endpoint and each initial package URL are checked before
    their respective requests. Artifact URLs must be the canonical HTTPS
    GitHub release asset for the signed platform and advertised version. The
    legacy asset leaf uses the same component encoding as the manifest compiler
    (including `%2B` for SemVer build metadata), while the release tag retains
    literal build metadata. The request policy is applied after an optional
    client hook, disables referrer forwarding, allows no more than three
    redirects, and admits only the exact GitHub asset or the official GitHub
    release-CDN hosts. CDN query strings are accepted because GitHub uses them
    for signed delivery; credentials, non-default ports, and fragments are
    rejected. `Update::download` repeats artifact validation because its public
    URL can be changed after an update check. Minisign byte, trusted-comment,
    and version-advance checks remain mandatory after the bounded download.
    The exact GitHub transport filename is derived from that same signed
    platform and version using the publisher's ASCII filename grammar,
    128-character bound, and space-to-dot mapping. Prerelease text is retained;
    build-metadata filenames retain their legacy URL because the publisher's
    admitted filename grammar excludes `+`.

The package name, version, resolved dependency set, and licenses are unchanged.
`Update::install` now verifies the signed release independently;
`InvalidSignedRelease` reports rejected release identity and
`InvalidReleaseUrl` reports rejected release transport; `ResponseTooLarge`
reports a response-body limit failure.
`LICENSE_APACHE-2.0` and `LICENSE_MIT` are retained from the upstream
dual-licensed archive.
