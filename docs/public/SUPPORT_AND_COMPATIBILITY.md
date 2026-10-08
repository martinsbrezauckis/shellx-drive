# ShellX Drive v0.1 support and compatibility

Use the signed artifacts attached to a published ShellX Drive GitHub Release
and follow the platform's installation guide. Source builds support development
and evaluation.

## Supported features and runtime requirements

| Area | Included in v0.1.11 | Requirements and actions |
| --- | --- | --- |
| Server | One self-hosted Linux x86-64 server managed with systemd. | Use the authenticated release package and follow [First install](FIRST_INSTALL.md). The host needs standard installer tools and a compatible system runtime. Keep the server on loopback behind an HTTPS reverse proxy that you administer. |
| Browser app | File management, previews, guest links, guest uploads, account security, backups, and server administration. | Files are server-readable to support these features. Encrypt locally before upload when you want to keep a payload confidential from the host. |
| Desktop sync | One signed-in server/account connection with one chosen local base folder and up to 100 accessible roots below it. | Use **Disconnect this PC** before changing server or account. |
| Windows desktop | The shared desktop application has an NSIS package for Windows x86-64. | Verify the signed release installer against its release manifest and publisher identity. |
| macOS desktop | The shared desktop application has macOS arm64 package, signing, notarization, and updater routes. | Use only a Developer-ID-signed, notarized, and stapled release package. |
| Linux desktop | The shared desktop application has Linux x86-64 AppImage/Debian package and updater routes. | Use a signed release package with GTK 3, WebKitGTK 4.1, an AppIndicator tray runtime, and a Secret Service desktop session. |
| Human sharing | Account/group Viewer or Editor grants, an explicit administrator-controlled Everyone policy, guest links, upload drops, owner/recipient views, and scoped desktop roots preserve one canonical file entity. | Item grants authorize the shared item; workspace membership supplies workspace and WebDAV access. Revocation stops future server access and retains bytes already downloaded to recipient devices. |
| WebDAV and adapters | Nested WebDAV, a limited Google Drive API subset, and office-provider handoff routes are included. | Use the routes and supported operations described in [API.md](API.md). |
| Hosted mode | Optional administrator-provisioned tenant metadata is available on the self-hosted server. | Administrators provision tenant access. |

## Deployment and data boundaries

- Use the signed release archive and its published provenance for production.
  Use source builds for development and evaluation.
- Bind the server to loopback and terminate HTTPS in a proxy or tunnel that you
  control.
- Server operators and host administrators can read stored file bodies and
  backups. Encrypt a file locally before upload to keep its contents confidential
  from the host.
- Run one Drive process for each data directory. Active request, backup, and
  restore limits are process-local in v0.1.1.
- Review and approve a signed desktop update locally. An authenticated account
  owner or their account-wide delegated agent can also command an enrolled desktop to install
  an exact checked, signed candidate through their authenticated authorization.
  Grant desktop-agent access only to operators you trust with that choice.
  A server administrator separately reviews and applies a server update.

## Compatibility expectations

- Workspace names support up to **255 UTF-8 bytes** after surrounding whitespace
  is trimmed. Browsing keeps each accepted name intact across page cursors.
- Use a current, standards-compliant browser for the web interface.
- The server package targets Linux x86-64 with systemd and standard installer
  tools. Follow the authenticated installer, service, and health checks in
  [First install](FIRST_INSTALL.md). If a host lacks a required runtime, retain
  the startup error for support. Distribution
  compatibility follows the package's loader, library, and service requirements.
- The initial desktop targets are Windows x86-64, macOS arm64, and Linux
  x86-64 with the required runtime APIs. Follow the platform installation guide
  to verify the signed package and configure the required runtime.
- Keep local sync roots on ordinary local filesystems. The client deliberately
  rejects or reviews symbolic links, reparse points, hard links, and ambiguous
  paths, keeping ordinary files as the sync inputs.

## Extracted-text and preview formats

The browser app provides a file viewer, generated inspector previews, and a
guest-link media viewer. Each view supports the formats listed below.

### Signed-in file viewer

| File type | Extensions | Preview |
| --- | --- | --- |
| Images | `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.bmp`, `.ico` | Image view |
| PDF | `.pdf` | Browser PDF viewer |
| Video | `.mp4`, `.webm`, `.mov` | Video player |
| Audio | `.mp3`, `.wav`, `.ogg` | Audio player |
| Markdown | `.md`, `.markdown` | Formatted Markdown |
| Text, data, and source code | `.txt`, `.log`, `.rtf`, `.csv`, `.tsv`, `.json`, `.xml`, `.yaml`, `.yml`, `.toml`, `.js`, `.ts`, `.py`, `.rs`, `.go`, `.sh`, `.css` | Plain-text view; RTF source and CSV/TSV data appear as text |

Drive selects the viewer from the file extension, ignoring letter case. Text
and Markdown previews accept files up to **256 KiB (262,144 bytes)** and decode
their contents as UTF-8. Markdown uses Drive's supported formatting subset.
PDF rendering uses the browser's PDF viewer. Images, audio, and video use the
browser's decoders; media playback depends on the file's encoding and the
browser's codec support.

### Inspector sidebar and search

| Generated preview | Formats | Display |
| --- | --- | --- |
| Image thumbnail | `.gif`, `.jpg`, `.jpeg`, `.png`, `.webp` | Thumbnail up to 512 × 512 pixels |
| Text excerpt | UTF-8 text; Office Open XML (`.docx`, `.xlsx`, `.pptx`); OpenDocument (`.odt`, `.ods`, `.odp`) | First 240 characters of extracted text |

Generated previews process files up to **32 MiB**, with additional image
decoding and Office extraction limits. Drive also indexes bounded extracted
text from UTF-8 text and these Office packages for search. Text-bearing PDFs
provide best-effort extracted-text search. Open PDFs and videos in the file
viewer; use the sidebar for the generated previews listed above.

Office excerpts provide text for search and inspection. Open the original
document in its application or a configured office provider for layout,
formulas, comments, embedded media, and editing. Legacy binary Office files
(`.doc`, `.xls`, `.ppt`) are available for download and handoff to a configured
office provider. Use an Open XML or OpenDocument package for Drive's
extracted-text previews and search.

### Guest-link media viewer

| File type | Extensions | Preview |
| --- | --- | --- |
| Images | `.bmp`, `.gif`, `.jpeg`, `.jpg`, `.png`, `.webp` | Image view |
| Video | `.mov`, `.mp4`, `.webm` | Video player |

Guest video playback uses the recipient's browser and its supported codecs.

## Getting help and reporting issues

Reproduce a problem against the installed release or an identified development
build and include the version, platform, non-secret status message, and safe
reproduction steps. Use the repository issue templates for
ordinary bugs and feature requests. Share only non-secret metadata and redact
passwords, two-factor and recovery codes, bearer or session values,
credential-store contents, and share URLs from diagnostics.

For a security vulnerability, follow [SECURITY.md](../../SECURITY.md) instead
of opening a public issue.
