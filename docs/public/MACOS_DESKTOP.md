# ShellX Drive Desktop for macOS

Install the macOS arm64 release package with its published manifest and
Developer ID identity. Verify its signature, notarization, staple, and
Gatekeeper acceptance before launching.

## Add a server connection

1. Install and launch **ShellX Drive Desktop** from **Applications**.
2. On first launch, choose appearance, **Launch at login**, and the **Default
   sync check interval** in **App preferences**, then **Save and continue**.
3. In **Servers**, select **Add server**, enter a friendly name and the server's
   HTTPS URL, and select **Validate server**. Complete first-administrator setup
   in the browser first if the server requests it.
4. Enter **Account email** and **Server password**. Use the current password,
   including the new password after changing or resetting it on the server.
   TOTP or a recovery code is requested only when the account requires it.
5. Browse the owned and shared roots by page and select the first root to sync.
6. Use **Browse…** to choose a dedicated empty ordinary local Drive folder in
   the native folder picker. Keep it separate from other connections and sync
   tools. Choose a **Sync check interval** or **Use app default**, then confirm
   **Connect and start syncing**.

The selected root appears in a safe child folder below the local Drive folder.
Use **Add Drive root** to select more, up to 100 roots per connection.

The selected root shown as **Current status details** is only the root whose
summary is visible in the main panel; all configured roots continue syncing.
Viewer roots download only. If access is revoked, Drive stops remote access and
retains local bytes for review.

## Manage connections

Connect multiple servers and distinct accounts on the same server. Each
connection retains its own sign-in, local folder, roots, status, and settings.
Signing in to an existing server/account offers **Open existing connection**.
All configured, unpaused connections keep syncing as you browse their details.
Click a folder path in **Servers** to open that connection's folder, including
while paused or awaiting sign-in.

In a server's details, choose **Edit server** to change its friendly name or
sync check interval. **Update sign-in** renews the same account's session and
retains its folder and settings. To replace the local folder, use **Browse…**
in the editor, select a new separate empty folder, confirm the fresh sync, and
choose **Save server**. Resolve pending reviews first. The old files stay in
place while Drive starts syncing in the new folder.

Upgrading an existing setup retains its sign-in, local paths, history, pause
state, launch preference, and remote-agent enrollment.

## App settings, history, and updates

**App settings** controls appearance, **Launch at login**, and the **Default
sync check interval**. The initial default is **20 seconds**; choices are
20 seconds, 1 minute, 5 minutes, 15 minutes, 30 minutes, and 1 hour. Connections
using **Use app default** follow default changes; explicit overrides retain
their value. Checks wait for the chosen delay after a pass finishes. Offline
retries wait at least one minute. Use **Sync now** for an immediate request, or
**Pause sync** and **Resume sync** for the selected connection.

The third tab, **History**, combines connection activity with connection/account
and time-frame filters, search, and paging. **App settings** also shows the exact
available desktop update, release notes, signature trust guidance, and progress.
Select **Download and install** to authorize that displayed update. The app
verifies the signed package before handing it to the installer and restarting.

## Remove a server and recover safely

The saved session is protected by the current user's macOS Keychain. Use the
app's **Reconnect**, **Update sign-in**, and review controls while preserving
Keychain entries and Drive state during recovery.

Choose **Remove server** in the selected server's details and confirm its name,
account, and folder. Drive safely stops that connection's active sync, retires
its session, and removes its saved credential and connection metadata. Local
files stay in place, and other connections and app preferences remain
available. Keep the server reachable during retirement and use the displayed
retry action if completion needs attention.

See [Support and compatibility](https://github.com/martinsbrezauckis/shellx-drive/blob/main/docs/public/SUPPORT_AND_COMPATIBILITY.md) for runtime
requirements and safe issue reporting.
