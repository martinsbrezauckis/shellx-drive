#!/usr/bin/env bash
# Sourced only by linux-sign-candidate.sh after it has admitted an exact Git
# archive. It checks the Linux-native shell before any build tool or signer
# receives control. This static contract is not installed-user acceptance.
set -euo pipefail

linux_runtime_contract_require() {
  local file="$1" needle="$2" missing="$3"
  [[ -f "$file" ]] \
    || linux_release_fail "Linux desktop shared-runtime contract is not complete: missing ${missing}"
  grep -Fq -- "$needle" "$file" \
    || linux_release_fail "Linux desktop shared-runtime contract is not complete: ${missing}"
}

linux_desktop_runtime_contract() {
  local source_root="$1"
  local main="$source_root/desktop/src-tauri/src/main.rs"
  local shell="$source_root/desktop/src-tauri/src/application/linux/shell.rs"
  local linux_module="$source_root/desktop/src-tauri/src/application/linux/mod.rs"
  local sync="$source_root/desktop/src-tauri/src/application/linux/sync.rs"
  local all_roots="$source_root/desktop/src-tauri/src/application/linux/sync/all_roots.rs"
  local reconcile="$source_root/desktop/src-tauri/src/application/linux/reconcile.rs"
  local transfers="$source_root/desktop/src-tauri/src/application/linux/reconcile/transfers.rs"
  local operations="$source_root/desktop/src-tauri/src/application/linux/reconcile/operations.rs"
  local moves="$source_root/desktop/src-tauri/src/application/linux/reconcile/operations/moves.rs"
  local restore="$source_root/desktop/src-tauri/src/application/linux/sync/restore.rs"
  local replacement="$source_root/desktop/src-tauri/src/platform/unix/filesystem/mutation/linux.rs"
  linux_runtime_contract_require "$main" '#[cfg(target_os = "linux")]' "main.rs does not admit Linux"
  linux_runtime_contract_require "$shell" 'UnixDesktopInstanceLease::acquire' "Linux shell is not the native entry point"
  linux_runtime_contract_require "$source_root/desktop/mirror-core/src/credentials/unix.rs" 'LinuxCredentialStore' "Secret Service credential adapter is missing"
  linux_runtime_contract_require "$shell" 'UnixDesktopInstanceLease' "single-instance adapter is missing"
  linux_runtime_contract_require "$source_root/desktop/src-tauri/src/platform/unix.rs" 'set_unix_launch_at_login' "per-user autostart adapter is missing"
  linux_runtime_contract_require "$shell" 'run_uninstall_cleanup_with_lease' "fail-closed uninstall cleanup is missing"
  linux_runtime_contract_require "$source_root/desktop/src-tauri/src/application/unix_uninstall/remote.rs" 'PendingLinuxCredentialStore' "pending Secret Service cleanup is missing"
  linux_runtime_contract_require "$source_root/desktop/src-tauri/src/application/unix_uninstall.rs" 'remove_owned_launch_at_login' "owned autostart cleanup is missing"
  linux_runtime_contract_require "$source_root/desktop/src-tauri/src/platform/unix/autostart.rs" 'select_stable_executable' "AppImage autostart admission is missing"
  linux_runtime_contract_require "$source_root/desktop/src-tauri/src/platform/unix/autostart/executable.rs" '.mount_' "AppImage autostart safety is missing"

  # Reconciliation may be split into focused modules, but the package gate must
  # retain the complete route from Tauri command admission to descriptor-bound
  # terminal mutations.  Do not replace these with a broad text search: each
  # edge is explicit so moving one requires a deliberate contract update.
  linux_runtime_contract_require "$linux_module" 'mod reconcile;' "Linux reconciliation module is not admitted"
  linux_runtime_contract_require "$linux_module" 'mod sync;' "Linux sync command module is not admitted"
  linux_runtime_contract_require "$sync" 'mod all_roots;' "all-root reconciliation module is not admitted"
  linux_runtime_contract_require "$sync" 'use all_roots::reconcile_all_roots;' "sync command does not select all-root reconciliation"
  linux_runtime_contract_require "$sync" 'reconcile_all_roots(runtime, &mut run, recheck).await' "sync command does not invoke all-root reconciliation"
  linux_runtime_contract_require "$all_roots" 'use super::super::reconcile;' "all-root reconciliation is disconnected from the guarded executor"
  linux_runtime_contract_require "$all_roots" 'match reconcile::reconcile(' "all-root reconciliation does not invoke the guarded executor"
  linux_runtime_contract_require "$all_roots" '&mut cycle_budget,' "all-root reconciliation does not share its cycle budget"
  linux_runtime_contract_require "$all_roots" '&mut local_reads,' "all-root reconciliation does not share its local-read budget"
  linux_runtime_contract_require "$reconcile" 'UnixRootGuard::acquire' "reconciliation does not acquire a descriptor-bound root guard"
  linux_runtime_contract_require "$reconcile" 'require_exact_pair_marker' "reconciliation does not verify its paired-root marker"
  linux_runtime_contract_require "$reconcile" 'execute_actions(' "reconciliation does not route actions through the guarded executor"
  linux_runtime_contract_require "$transfers" 'guard.publish_staged_file' "download publication bypasses the descriptor-bound root guard"
  linux_runtime_contract_require "$transfers" 'guard.prepare_staged_file_replacement' "replacement publication bypasses private guarded recovery"
  linux_runtime_contract_require "$transfers" 'fresh_remote_file_matches' "replacement publication lacks a fresh remote witness"
  linux_runtime_contract_require "$transfers" 'prepared.publish' "prepared replacement is not published through its guarded exchange"
  linux_runtime_contract_require "$replacement" 'rename_exchange_at' "replacement publication lacks an atomic native exchange"
  linux_runtime_contract_require "$operations" 'mod moves;' "move execution module is not admitted"
  linux_runtime_contract_require "$moves" 'guard.move_entry_noreplace' "local moves bypass the descriptor-bound root guard"
  linux_runtime_contract_require "$moves" 'compatible_destination_is_absent' "local moves omit Windows-compatible destination collision checks"
  linux_runtime_contract_require "$moves" 'capture_folder_remote_witness' "folder moves omit their terminal remote subtree witness"
  linux_runtime_contract_require "$moves" 'destination_is_available' "remote moves omit destination collision checks"
  linux_runtime_contract_require "$moves" '.move_remote_file' "remote moves bypass the revision-checked server contract"
  linux_runtime_contract_require "$restore" 'reviewed_remote_subtree_matches_baseline' "reviewed folder restore is not bound to the complete remote subtree"
  linux_runtime_contract_require "$restore" 'guard.publish_staged_entry_noreplace' "reviewed restore bypasses atomic no-replace publication"
  linux_runtime_contract_require "$all_roots" 'run.finalize_all_roots_state' "inactive-root failures are not surfaced after the all-root cycle"
}

linux_build_signed_artifacts() {
  local source_root="$1" output="$2" appimage_dir deb_dir appimage deb version
  : "${TOOL_TAURI_CLI:?controller must admit tauri-cli}"
  : "${TOOL_INSTALL:?controller must admit install}"
  : "${TOOL_FIND:?controller must admit find}"
  linux_desktop_runtime_contract "$source_root"
  (cd -- "$source_root/desktop"
    CARGO_TARGET_DIR="$output/build-target" SIGN=1 APPIMAGETOOL_FORCE_SIGN=1 SIGN_KEY="$SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT" \
      "$TOOL_TAURI_CLI" build --features desktop-shell \
        --config "$GENERATED_TAURI_CONFIG" --bundles deb,appimage)
  appimage_dir="$output/build-target/release/bundle/appimage"
  deb_dir="$output/build-target/release/bundle/deb"
  mapfile -t appimages < <("$TOOL_FIND" "$appimage_dir" -maxdepth 1 -type f -name '*.AppImage' -print)
  mapfile -t debs < <("$TOOL_FIND" "$deb_dir" -maxdepth 1 -type f -name '*.deb' -print)
  [[ ${#appimages[@]} == 1 && ${#debs[@]} == 1 ]] \
    || linux_release_fail "Tauri must produce exactly one AppImage and one Debian package"
  appimage="${appimages[0]}"
  deb="${debs[0]}"
  linux_release_require_regular "$appimage" "AppImage"
  linux_release_require_regular "$deb" "Debian package"
  version="$("$TOOL_NODE" -e 'const fs = require("node:fs"); const v = JSON.parse(fs.readFileSync("/dev/fd/110", "utf8")).version; if (typeof v !== "string" || !/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(v)) process.exit(1); process.stdout.write(v);')" \
    || linux_release_fail "admitted desktop version is invalid"
  # The final signer authenticates these names after package signing. Reusing
  # Tauri's earlier .sig would both omit this identity and precede dpkg-sig.
  "$TOOL_INSTALL" -m 0700 -- "$appimage" "$output/ShellX_Drive_${version}_amd64.AppImage"
  "$TOOL_INSTALL" -m 0600 -- "$deb" "$output/shellx-drive_${version}_amd64.deb"
}
