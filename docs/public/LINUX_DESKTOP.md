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

## Connect and sync

1. Enter and validate your Drive server's HTTPS URL.
2. Sign in to your Drive account. Enter a TOTP or recovery code only when the
   account requires it.
3. Browse the owned and shared roots and select one to sync.
4. Use **Choose folder** to select one existing empty local Drive folder in the
   native folder dialog.
5. Confirm **Connect and start syncing**. Your selected root appears in a child
   folder below the chosen local Drive folder.

Drive syncs configured roots automatically. Use **Sync now** to request a pass,
or **Pause** and **Resume** to control syncing. Open the local folder to work with
your files and use **Add Drive root** to select another owned or shared root.
The current root's status details summarize that root; all configured roots
continue syncing. Viewer roots download only, and local changes stay for review.

## Disconnect and recovery

v0.1 supports one Drive server/account connection and up to 100 selected roots
below one local Drive folder. New grants require explicit selection.

Before changing server or account, open **Settings**, choose **Disconnect**,
and confirm **Disconnect this PC**. This also ends a saved sign-in before you
have chosen a local folder. Keep the server reachable while Drive retires the
saved sessions. If sync is active, Drive waits for the current operation to stop
safely first. Disconnect removes saved credentials and connection metadata;
your synced files stay on this PC.

Follow any recovery action shown by the app before setting up another
connection. Use **Reconnect** or the file review controls when requested. If
access is revoked, Drive stops remote access and retains local files for review.
Keep credential-store entries and Drive state intact while using these recovery
controls.
