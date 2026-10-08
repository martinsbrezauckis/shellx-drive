# ShellX Drive Desktop for Windows

Install the signed Windows x64 desktop package using its published release
manifest and publisher identity. Follow the installation and recovery steps
below and the [runtime requirements](SUPPORT_AND_COMPATIBILITY.md).

## Before installation

Obtain these items from the Drive service owner or the official release:

- the public Drive HTTPS origin: scheme, hostname, and optional port;
- the signed NSIS installer and its release manifest;
- the expected installer SHA-256, exact source revision, publisher subject, and
  publisher certificate thumbprint; and
- an existing Drive account, with first-administrator setup completed in the
  browser when setting up a new server.

Prepare one dedicated empty ordinary local folder (the **Drive folder**),
separate from other sync tools' folders. Drive creates safely named owned and
shared-root folders below this one base. Pairing requires an empty base,
preserving pre-existing data. Files inside managed roots must be independent
regular files. Symbolic links, reparse points, and filesystem hard links remain
in **Needs review** until replaced with ordinary copied files for syncing.

## Verify and install

1. Compare the installer SHA-256 with the independently obtained release
   manifest.
2. In Windows Explorer, open **Properties → Digital Signatures**. The signature
   must be valid and its publisher subject and thumbprint must match the release
   manifest. Stop if any identity is missing or different.
3. Run the installer. It can download the Microsoft WebView2 bootstrapper when
   WebView2 is absent, so initial installation may need network access.
4. Launch **ShellX Drive Desktop** from the installed shortcut.

## Connect and pair

1. Enter the server's HTTPS URL and select **Validate**. If Drive says owner
   setup is required, complete first-administrator setup in the browser before
   continuing.
2. Enter email and password. A TOTP or recovery-code field appears only when the
   account requires it.
3. Browse the owned and shared Drive roots by page and select the first root
   to sync. Additional roots require an explicit **Add Drive root** choice.
4. Select the prepared empty local Drive folder with **Choose folder** and
   confirm pairing. Choose the path through the native folder picker.
5. Wait for **Synced**, then create one small test file on each side and verify
   both arrive with the expected name and bytes.

Use the HTTPS origin as the server URL. Enter credentials only in the sign-in
fields and share only the non-secret support information listed below.

## One connection and managed Drive roots

v0.1 connects one signed-in server and account to one local Drive folder. Browse
available owned and shared roots by page, select the first root, then use
**Add Drive root** for more. Up to 100 selected locations have non-overlapping
child folders, each with its own baseline, activity, review state, and access
status. **Current status details** shows one configured root; all configured
roots continue syncing.

- Select a new grant in the root picker to create its local folder. Revoked
  configured roots stop syncing and retain local bytes.
- Drive creates each shared root's safe child folder below the one local Drive
  folder chosen during setup.
- Use **Disconnect this PC** before connecting the client to another
  server/account.

## Understand status

| Status | Meaning and action |
| --- | --- |
| **Synced** | The last complete comparison converged. |
| **Syncing** | A serialized sync pass is active; wait for it to finish. |
| **Paused** | Automatic transfers are paused; select **Resume** when ready. |
| **Offline** | Local edits remain local; restore network and use **Retry now**. |
| **Needs reconnect** | Sign in again. Pairing and local files are retained. |
| **Needs review** | Drive detected a conflict, deletion, or unsafe path. Choose the explicit review action. |
| **Error** | Follow the displayed bounded recovery step. Destructive choices require explicit review confirmation. |

Drive polls conservatively. Use **Sync now** and
wait for the terminal status before shutting down or editing the same file on a
second device.

## Desktop updates

The desktop app checks the official signed update manifest after launch. A
new version is shown in **Settings → Desktop update**. Select **Review update**
to see the target version and signature trust guidance, then select
**Download and install** to approve that exact
update. An authenticated account owner or their account-wide delegated agent
can also request installation of an exact checked, signed candidate through an
enrolled desktop agent. The owner's or delegate's authenticated request
authorizes installation on that device, so grant agent access only to operators
you trust with updates. The app reports download progress and closes only after
the signed package has been verified
and handed to the installer.

Install updates after signature verification succeeds and the publisher
identity matches the installed release. Server software updates are separate: a
server administrator can see the server release notice and package links, and
applying a server update remains an explicit backup, checksum, and maintenance
operation. Server-update controls are reserved for server administrators.

## Conflicts, deletion, and offline work

Simultaneous edits preserve both bodies and enter **Needs review**. Deletions
require explicit confirmation, including folder deletion. While
offline, keep edits inside the managed local root, reconnect, and let Drive compare
before editing the same paths elsewhere. Use the app's reconnect, review, or
disconnect flow while preserving client state and Credential Manager entries.

## Disconnect and uninstall

If synchronization is active, Disconnect first asks it to stop and waits for
the current operation to finish safely before retiring the connection.

**Disconnect this PC** revokes the desktop session and removes Drive's saved
credential only after remote retirement is confirmed. It retains the paired
files. If the UI reports that retirement is unconfirmed, use its retry action
while preserving the saved state.

The NSIS uninstaller invokes Drive's credential cleanup and aborts if that
cleanup fails. Uninstall is intended to retain sync-root files and
non-secret Drive state while removing `com.shellx.drive.desktop` Windows
Credential Manager secrets.

## Safe support information

Provide only the app version, status/error wording, timestamp with time zone,
and server hostname. Keep passwords, two-factor and recovery codes, session
values, Credential Manager contents, and share capabilities confined to their
account and credential flows. Operator debug/support
exports must follow Drive's redaction contract in
[`DEBUG_API.md`](DEBUG_API.md).
