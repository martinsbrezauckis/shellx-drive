# ShellX Drive Desktop for macOS

Install the macOS arm64 release package with its published manifest and
Developer ID identity. Verify its signature, notarization, staple, and
Gatekeeper acceptance before launching.

## Connect one Drive account

1. Install and launch **ShellX Drive Desktop** from **Applications**.
2. Validate the Drive server's HTTPS URL, then sign in. TOTP or a recovery code
   is requested only when the account requires it.
3. Browse the owned and shared roots by page and select the first root to sync.
4. Use the native **Choose folder** dialog to select one empty local Drive
   folder. Choose the path through the native folder picker.
5. Confirm pairing. The selected root appears in a safe child folder below
   that local Drive folder. Use **Add Drive root** to select more.

The selected root shown as **Current status details** is only the root whose
summary is visible in the main panel; all configured roots continue syncing.
Viewer roots download only. If access is revoked, Drive stops remote access and
retains local bytes for review.

## Scope and safe recovery

v0.1 supports one Drive server/account connection and up to 100 selected roots
below its one local Drive folder. New grants require explicit selection. Use
**Disconnect this PC** before connecting a different server or account.

The saved session is protected by the current user's macOS Keychain. Use the
app's reconnect, review, or disconnect flow while preserving Keychain entries
and Drive state during recovery. Disconnect retains synced
user files while removing Drive's saved session and local connection metadata.
If synchronization is active, Disconnect first asks it to stop and waits for
the current operation to finish safely before retiring the connection.

See [Support and compatibility](https://github.com/martinsbrezauckis/shellx-drive/blob/main/docs/public/SUPPORT_AND_COMPATIBILITY.md) for runtime
requirements and safe issue reporting.
