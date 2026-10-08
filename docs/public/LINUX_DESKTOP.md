# ShellX Drive Desktop for Linux

Use the signed Linux x86_64 desktop package from ShellX Drive's authenticated
release channel. Choose either the Debian package or the AppImage.

The desktop requires GTK 3, WebKitGTK 4.1, an Ayatana or compatible AppIndicator
tray runtime, and an ordinary-user graphical session with Secret Service for
saved credentials. The selected package must support your host's runtime
libraries. Support depends on these runtime capabilities. A Debian package also
needs a compatible package manager; an AppImage
needs working AppImage mounting support.

## Verify and install one package

Download your chosen package and its matching `.sig`. Before running or
installing it, verify that package's Tauri/minisign updater signature using the
verification instructions and Drive public key from the authenticated release
channel. Proceed once the signature verifies against that authenticated key.
Use the published SHA-256 checksum to confirm package bytes and the signature
to authenticate their origin.

For the verified Debian package, install it with your normal package manager.
On an apt-based system, run this from the download directory:

```bash
sudo apt install ./shellx-drive_0.1.1_amd64.deb
```

Then launch **ShellX Drive** from the application menu as your ordinary user.

Alternatively, keep the verified AppImage in a stable folder owned by your user,
make it executable, and launch it there:

```bash
chmod u+x ./ShellX_Drive_0.1.1_amd64.AppImage
./ShellX_Drive_0.1.1_amd64.AppImage
```

Run the desktop as your ordinary user, including when the Debian installer
needed administrator privileges.

## Add a server connection

1. On first launch, choose appearance, **Launch at login**, and the **Default
   sync check interval** in **App preferences**, then **Save and continue**.
2. In **Servers**, select **Add server**, enter a friendly name and your server's
   HTTPS URL, and select **Validate server**. Complete first-administrator setup
   in the browser first if the server requests it.
3. Enter **Account email** and **Server password**. Use your current password,
   including the new password after a change or reset on the server. Enter a
   TOTP or recovery code only when the account requires it.
4. Browse the owned and shared roots and select one to sync.
5. Use **Browse…** to select an existing empty ordinary local Drive folder in
   the native folder dialog. Choose a separate folder for each connection,
   outside other connections and other sync tools' folders.
6. Choose a **Sync check interval** or **Use app default**, then confirm
   **Connect and start syncing**. Your selected root appears in a child
   folder below the chosen local Drive folder.

Drive syncs configured roots automatically. Use **Sync now** to request a pass,
or **Pause sync** and **Resume sync** to control the selected connection.
Click a folder path in **Servers** to open that connection's local folder,
including while paused or awaiting sign-in. Use **Open folder** in the details
to open the same local Drive folder, containing its managed root folders. Use
**Add Drive root** to select another owned or shared root, up to 100 roots per
connection.
The current root's status details summarize that root; all configured roots
continue syncing. Viewer roots download only, and local changes stay for review.

## Manage connections

Connect multiple servers and distinct accounts on the same server. Each has
its own name, sign-in, folder, sync settings, and status. Signing in to a saved
server/account offers **Open existing connection**. All configured, unpaused
connections keep syncing while you browse their details.

Choose **Edit server** in the selected server's details to rename it or change
its sync check interval. Use **Update sign-in** with that same account's current
server password to renew its session and keep its folder and settings. To
replace the folder, resolve pending file reviews, choose a new separate empty
folder with **Browse…**, confirm the fresh sync, and choose **Save server**.
Your old files stay in place while Drive starts syncing in the new folder.

Upgrading an existing setup retains its sign-in, local paths, history, pause
state, launch preference, and remote-agent enrollment.

## App settings, history, and updates

**App settings** controls appearance, **Launch at login**, and the **Default
sync check interval**. The initial default is **20 seconds**; choose 20 seconds,
1 minute, 5 minutes, 15 minutes, 30 minutes, or 1 hour. Connections using **Use
app default** follow later default changes; explicit overrides retain their
value. The interval is the delay between checks after a pass finishes. Offline
retries wait at least one minute.

The third tab, **History**, combines activity with connection/account and
time-frame filters, search, and paging. **App settings** also shows the exact
available desktop update, release notes, signature trust guidance, and progress.
Select **Download and install** to approve that update. Drive verifies the
signed package before handing it to the installer and restarting.

## Remove a server and recover safely

Choose **Remove server** in the selected server's details and confirm its name,
account, and folder. Keep that server reachable while Drive retires the session.
Drive safely stops the selected connection's active sync, then removes its
saved credentials and connection metadata after confirmed retirement. Your
files stay in their folders; other connections and app preferences remain
available. Use the displayed retry action if retirement needs attention.

Use **Reconnect**, **Update sign-in**, or the file review controls when requested. If
access is revoked, Drive stops remote access and retains local files for review.
Keep credential-store entries and Drive state intact while using these recovery
controls.
