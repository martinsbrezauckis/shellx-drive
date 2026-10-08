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

Prepare a dedicated empty ordinary local folder (the **Drive folder**) for each
connection, separate from other connections and other sync tools' folders.
Drive creates safely named owned and shared-root folders below each base.
Pairing requires an empty base, preserving pre-existing data. Files inside
managed roots must be independent
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

## Add a server connection

1. On first launch, choose **App preferences**: appearance, **Launch at login**,
   and the **Default sync check interval**. Select **Save and continue**.
2. In **Servers**, select **Add server**. Enter a friendly name and the server's
   HTTPS URL, then select **Validate server**. If Drive says owner setup is
   required, complete first-administrator setup in the browser before continuing.
3. Enter **Account email** and **Server password**. Use your current password,
   including the new password after a change or reset on the server. A TOTP or
   recovery-code field appears only when the account requires it.
4. Browse the owned and shared Drive roots by page and select the first root
   to sync. Additional roots require an explicit **Add Drive root** choice.
5. Select **Browse…** to choose the prepared empty local Drive folder through
   the native folder picker. Choose a **Sync check interval** or **Use app
   default**, then select **Connect and start syncing**.
6. Wait for **Synced**, then check a small file's name and bytes. Viewer roots
   support downloads; editable roots support both directions.

Use the HTTPS origin as the server URL. Enter credentials only in the sign-in
fields and share only the non-secret support information listed below.

## Manage connections and Drive roots

Connect multiple servers, including distinct accounts on the same server. Each
connection has its own friendly name, local Drive folder, sign-in, sync settings,
and status. Signing in to an already connected server/account offers **Open
existing connection**.

Select a server to manage it. Use **Edit server** to rename it, change its sync
check interval, or choose a new empty local folder with **Browse…**. Confirm the
fresh sync before saving: files stay in the old folder, and Drive starts syncing
in the new folder. Resolve pending file reviews before replacing a folder. Use
**Update sign-in** to renew that same account's session while retaining its
folder and sync settings.

Each connection supports up to 100 selected locations with non-overlapping
child folders, each with its own baseline, activity, review state, and access
status. Use **Add Drive root** for more. Selecting a server or a root changes the
displayed details; all configured, unpaused connections continue syncing.

- Select a new grant in the root picker to create its local folder. Revoked
  configured roots stop syncing and retain local bytes.
- Click a folder path in **Servers** to open that connection's local folder,
  including while paused or awaiting sign-in. **Open folder** in the details
  opens the same local Drive folder, containing its managed root folders.
- Upgrading an existing setup retains its sign-in, local folders, history,
  pause state, launch preference, and remote-agent enrollment.

## App settings and history

**App settings** controls appearance, **Launch at login**, and the default sync
check interval. The initial interval is **20 seconds**; choose 20 seconds,
1 minute, 5 minutes, 15 minutes, 30 minutes, or 1 hour. A connection using
**Use app default** follows later default changes; an explicit override keeps
its own value. The interval is the delay between sync checks after a pass
finishes. Offline retries wait at least one minute.

The third tab, **History**, combines activity across connections. Filter by
connection and account, time frame, or search text, and use the page controls
to browse retained activity.

## Understand status

| Status | Meaning and action |
| --- | --- |
| **Synced** | The last complete comparison converged. |
| **Syncing** | A serialized sync pass is active; wait for it to finish. |
| **Paused** | Automatic transfers are paused; select **Resume sync** when ready. |
| **Offline** | Local edits remain local; restore network and use **Retry now**. |
| **Needs reconnect** | Select **Reconnect** to sign in again. Pairing and local files are retained. |
| **Needs review** | Drive detected a conflict, deletion, or unsafe path. Choose the explicit review action. |
| **Error** | Follow the displayed bounded recovery step. Destructive choices require explicit review confirmation. |

Use **Sync now** and wait for the terminal status before shutting down or
editing the same file on a
second device.

## Desktop updates

The desktop app checks the official signed update manifest after launch. A
new version, release notes, and signature trust guidance appear in **App
settings**. Select **Download and install** there to approve the exact displayed
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
removal flow while preserving client state and Credential Manager entries.

## Remove a server and uninstall

Open the selected server's details and choose **Remove server**. Confirm the
named server, account, and folder. Drive stops that connection's active sync
safely before retiring its saved session.

Removal revokes that desktop session and removes its saved credential only
after remote retirement is confirmed. Local files stay in their folders;
other connections and app preferences remain available. If the UI reports
that retirement is unconfirmed, use its retry action while preserving the saved
state. Remove each connection through this flow when retiring the whole app.

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
