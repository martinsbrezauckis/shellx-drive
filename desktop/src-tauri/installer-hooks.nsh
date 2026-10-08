; Tauri invokes this macro before it removes installed files, registry values,
; or shortcuts. Keep the installed executable available until it confirms that
; the user already finished in-app Disconnect and no Drive credential remains.
!macro NSIS_HOOK_PREUNINSTALL
  ; Tauri also invokes this hook while replacing an older installation.  In
  ; that path its generated uninstaller has already parsed /UPDATE into
  ; $UpdateMode, and credentials must remain available to the replacement.
  ; Only a true uninstall checks the completed Disconnect state.
  StrCmp $UpdateMode 1 shellx_drive_credential_cleanup_done

  ClearErrors
  ExecWait '"$INSTDIR\shellx-drive-desktop.exe" --uninstall-cleanup' $0
  IfErrors shellx_drive_credential_cleanup_failed
  StrCmp $0 0 shellx_drive_credential_cleanup_done shellx_drive_credential_cleanup_failed

  shellx_drive_credential_cleanup_failed:
    MessageBox MB_ICONSTOP|MB_OK "Uninstall was cancelled. Open ShellX Drive, finish Disconnect (or Change setup after sign-in) and any pending recovery, close the app, then retry. Synced files are kept."
    Abort

  shellx_drive_credential_cleanup_done:
!macroend
