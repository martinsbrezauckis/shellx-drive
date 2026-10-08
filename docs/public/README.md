# ShellX Drive public documentation

<span data-app-version="0.1.13">ShellX Drive v0.1.13</span>

Use the [product manual](https://docs.theshellx.com/manual/drive/) and these guides
to install, configure, and operate ShellX Drive. The server and package are
versioned from the root `Cargo.toml`.

- [API](API.md) — authenticated and public HTTP route catalog.
- [Debug API](DEBUG_API.md) — deterministic automation and redaction contract.
- [Architecture](ARCHITECTURE.md) — storage model, service boundaries, sync, and conflicts.
- [Configuration](CONFIG.md) — command-line flags and `SHELLX_DRIVE_*` variables.
- [First install](FIRST_INSTALL.md) — safe package admission, host preflight, TLS routing, and first-admin setup.
- [Operations](OPERATIONS.md) — reverse proxy, backups, upgrades, and runtime runbooks.
- [Windows desktop](WINDOWS_DESKTOP.md) — signed-installer verification, one connection, managed roots, and recovery.
- [macOS desktop](MACOS_DESKTOP.md) — installation, one connection, managed roots, and recovery.
- [Linux desktop](LINUX_DESKTOP.md) — installation, one connection, managed roots, and recovery.
- [Desktop sync protocol](DESKTOP_SYNC_CONTRACT.md) — server contract for sync clients.
- [Support and compatibility](SUPPORT_AND_COMPATIBILITY.md) — supported features, preview formats, runtime requirements, and safe issue reporting.
- [File preview formats](SUPPORT_AND_COMPATIBILITY.md#extracted-text-and-preview-formats) — file viewer, inspector excerpts, guest media, and size limits.
- [Third-party notices](../../NOTICE) — vendored component attribution and regeneration rules.

Product screenshots used by the root README live in
[`assets/screenshots`](assets/screenshots). They are real browser captures from
a disposable instance with synthetic data and an `example.test` account.

Use the Windows, macOS, or Linux desktop guide above to install and connect
your desktop client.
