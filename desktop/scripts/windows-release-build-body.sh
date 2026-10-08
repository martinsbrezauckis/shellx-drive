#!/bin/bash
set -euo pipefail
umask 077

# Private updater values never enter a compiler, source CLI or packaging hook.
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD

# Build the Windows x64 NSIS installer after release-entry admission.
# Signed callers supply the commit-bound source and helper identities. Unsigned
# development callers resolve the adjacent checkout helpers directly.
script_path="${BASH_SOURCE[0]}"
[[ "$script_path" == /* ]] || script_path="$PWD/$script_path"
script_dir="$(cd -- "${script_path%/*}" && pwd -P)"
target="x86_64-pc-windows-msvc"
signing_required="${SHELLX_DRIVE_WINDOWS_SIGNING_REQUIRED:-0}"
if [[ ! "$signing_required" =~ ^[01]$ ]]; then
  echo "FAIL: SHELLX_DRIVE_WINDOWS_SIGNING_REQUIRED must be 0 or 1" >&2
  exit 2
fi
if [[ "$signing_required" == "1" ]]; then
  release_helper_stage="${SHELLX_DRIVE_RELEASE_HELPER_STAGE:-}"
  # shellcheck source=windows-release-helper-closure.sh
  source "$release_helper_stage/windows-release-helper-closure.sh"
  release_helper_import
  release_helper_verify_all
  source_context_helper="$(release_helper_path SOURCE_CONTEXT)"
  updater_helper="$(release_helper_path UPDATER)"
else
  source_context_helper="$script_dir/windows-release-source-context.sh"
  updater_helper="$script_dir/windows-release-updater.sh"
fi
if [[ -L "$source_context_helper" || ! -f "$source_context_helper" \
  || -L "$updater_helper" || ! -f "$updater_helper" ]]; then
  echo "FAIL: trusted release source context helper is missing or unsafe" >&2
  exit 1
fi
# shellcheck source=windows-release-source-context.sh
source "$source_context_helper"
# shellcheck source=windows-release-updater.sh
source "$updater_helper"
if [[ "$signing_required" == "1" ]]; then
  release_source_context_signed "$script_path" || exit 1
else
  release_source_context_unsigned "$script_dir"
fi
readonly revision
if [[ -L "$toolchain_helper" || ! -f "$toolchain_helper" \
  || -L "$candidate_output_helper" || ! -x "$candidate_output_helper" \
  || -L "$signed_candidate_helper" || ! -x "$signed_candidate_helper" ]]; then
  echo "FAIL: trusted release toolchain helper is missing or unsafe" >&2
  exit 1
fi
# shellcheck source=windows-release-toolchain.sh
source "$toolchain_helper"
release_tool_init "$signing_required"
release_tool_register CANDIDATE_OUTPUT "$candidate_output_helper" "candidate output helper"
release_tool_register SIGNED_CANDIDATE "$signed_candidate_helper" "signed candidate helper"
# shellcheck source=windows-candidate-output.sh
source "$CANDIDATE_OUTPUT_RESOLVED"
candidate_output_init
# shellcheck source=windows-signed-candidate.sh
source "$SIGNED_CANDIDATE_RESOLVED"
# shellcheck source=windows-release-cleanup.sh
source "$cleanup_helper"
release_tool_resolve GIT git
release_tool_resolve CARGO_XWIN cargo-xwin
release_tool_resolve NODE node
release_tool_resolve PNPM pnpm
release_tool_resolve POWERSHELL powershell.exe
release_tool_resolve SHA256SUM /usr/bin/sha256sum
release_tool_resolve TEE tee
release_tool_resolve WSLPATH wslpath
release_tool_resolve DATE date
release_tool_resolve TAIL tail
release_tool_resolve TR tr
release_tool_resolve RM rm
release_tool_resolve RMDIR rmdir
release_tool_resolve MKTEMP mktemp
release_tool_resolve CHMOD chmod
release_tool_resolve MKDIR mkdir
release_tool_resolve GREP grep
release_tool_resolve FIND find
release_tool_resolve CP cp
release_tool_resolve MV mv
release_tool_resolve BASENAME basename
release_tool_resolve STAT /usr/bin/stat
release_tool_resolve ID /usr/bin/id
release_tool_resolve READLINK /usr/bin/readlink
release_tool_resolve DIRNAME dirname
if [[ "$signing_required" == "1" ]]; then
  release_tool_register WINDOWS_SIGNING_ADMISSION "${SHELLX_DRIVE_WINDOWS_SIGNING_ADMISSION:?}" "shared Windows-local source admission"
  release_tool_resolve MAKENSIS makensis
  release_tool_resolve AWK awk
  release_tool_resolve HEAD head
  release_tool_resolve LN ln
  release_tool_resolve UNLINK unlink
  release_tool_use_pinned_path
fi
desktop_dir="$repo_root/desktop"
build_log=""
callback_log=""
nsis_signing_stage_root=""
signing_receipt=""
output_dir=""
trap cleanup_build_state EXIT
if [[ "$signing_required" == "1" ]]; then
  release_helper_stage_windows
fi
release_security_helper="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_RELEASE_SECURITY_PATH:-$script_dir/windows-release-security.ps1}"
signing_components_helper="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_SIGNING_COMPONENTS_PATH:-$script_dir/windows-signing-components.ps1}"
artifact_identity_helper="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_ARTIFACT_IDENTITY_PATH:-$script_dir/windows-artifact-identity.ps1}"
if ! "$CARGO_XWIN_BIN" --version >/dev/null 2>&1; then
  echo "FAIL: cargo-xwin is required (cargo install cargo-xwin)" >&2
  exit 1
fi
if [[ ! -f "$desktop_dir/package.json" || ! -f "$desktop_dir/pnpm-lock.yaml" ]]; then
  echo "FAIL: desktop package metadata and lockfile are required" >&2
  exit 1
fi
cd "$repo_root"
if [[ "$signing_required" == "1" ]]; then
  release_source_stage_verify || exit 1
elif [[ -n "$("$GIT_BIN" status --porcelain)" || "$revision" != "$("$GIT_BIN" rev-parse HEAD)" ]]; then
  echo "FAIL: build from an unchanged clean checkout so the artifact has one source identity" >&2
  exit 1
fi
prepare_windows_candidate_guide
short_revision="${revision:0:12}"
version="$("$NODE_BIN" -p 'require(process.argv[1]).version' "$desktop_dir/src-tauri/tauri.conf.json")"
started="$("$DATE_BIN" +%s)"
output_dir="${SHELLX_DRIVE_WINDOWS_OUTPUT_DIR:-}"
if [[ -z "$output_dir" ]]; then
  output_dir="$(release_windows_profile_wsl)/shellx-builds/drive-v${version}-${short_revision}/windows"
else
  output_dir="$(release_to_wsl_path "$output_dir")"
fi
claim_candidate_output_directory
if [[ "$signing_required" == "1" && "$output_dir_is_windows" != "1" ]]; then
  echo "FAIL: signed candidates require a private Windows/NTFS output directory" >&2
  exit 1
fi
echo "[build-windows] source revision: $revision"
echo "[build-windows] target: $target"
echo "[build-windows] output: $output_dir"
echo "[build-windows] installing locked Tauri CLI dependency"
cd "$desktop_dir"
release_pnpm_run install --frozen-lockfile --force --verify-store-integrity --ignore-scripts
release_pnpm_run store status
release_pnpm_run rebuild
release_source_context_checkpoint || exit 1
tauri_cli="$desktop_dir/node_modules/@tauri-apps/cli/tauri.js"
if [[ ! -x "$tauri_cli" || -L "$tauri_cli" ]]; then
  echo "FAIL: the locked Tauri CLI entry point is missing or unsafe" >&2
  exit 1
fi
if [[ "$signing_required" == "1" ]]; then
  release_tool_register TAURI "$tauri_cli" "locked Tauri CLI"
  release_tool_export_manifest
  release_tool_use_pinned_path
fi
release_source_context_checkpoint || exit 1
release_source_context_prepare_build_workspace || exit 1
artifact_root="$CARGO_TARGET_DIR/$target/release"
"$MKDIR_BIN" -p -- "$artifact_root"
callback_log="$artifact_root/windows-signing-callback.log"
bundle_dir="$artifact_root/bundle"
installer="$bundle_dir/nsis/ShellX Drive Desktop_${version}_x64-setup.exe"
executable="$artifact_root/shellx-drive-desktop.exe"
tauri_config='{"bundle":{"createUpdaterArtifacts":false}}'
drive_updater_init
"$RM_BIN" -rf -- "$bundle_dir"
if [[ "$signing_required" == "1" ]]; then
  "$RM_BIN" -f -- "$callback_log"
  : > "$callback_log"
  "$CHMOD_BIN" 0600 "$callback_log"
  export SHELLX_DRIVE_RELEASE_CALLBACK_LOG="$callback_log"
  metadata_path="${SHELLX_WINDOWS_SIGNING_METADATA_PATH:-}"
  if [[ -z "$metadata_path" ]]; then
    echo "FAIL: signed builds require SHELLX_WINDOWS_SIGNING_METADATA_PATH" >&2
    exit 1
  fi
  metadata_path="$(release_to_wsl_path "$metadata_path")"
  if [[ -L "$metadata_path" || ! -f "$metadata_path" ]]; then
    echo "FAIL: signing metadata must be a regular non-symlink file" >&2
    exit 1
  fi
  release_tool_admit_data_file "$metadata_path" SHELLX_DRIVE_RELEASE_METADATA_SHA256 "signing metadata"
  sign_command="$(release_helper_path SIGN_COMMAND)"
  sign_script="$SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_SIGNER_PATH"
  release_helper_verify_all
  release_helper_verify_windows_stage
  if [[ ! -x "$sign_command" || -L "$sign_command" || ! -f "$sign_script" || -L "$sign_script" \
    || ! -f "$release_security_helper" || -L "$release_security_helper" \
    || ! -f "$signing_components_helper" || -L "$signing_components_helper" \
    || ! -f "$artifact_identity_helper" || -L "$artifact_identity_helper" ]]; then
    echo "FAIL: trusted Drive signing helpers are missing or unsafe" >&2
    exit 1
  fi
  nsis_executable="$MAKENSIS_RESOLVED"
  if [[ ! -x "$nsis_executable" || -L "$nsis_executable" ]]; then
    echo "FAIL: makensis must resolve to an executable regular file" >&2
    exit 1
  fi
  # makensis creates its transient uninstaller under /tmp. Keep the private
  # byte-distinct signing copy there so the callback can enforce the ordinary
  # WSL ownership and mode checks before and after signing.
  nsis_signing_stage_root="$("$MKTEMP_BIN" -d "/tmp/shellx-drive-nsis-signing-${short_revision}.XXXXXX")"
  "$CHMOD_BIN" 700 "$nsis_signing_stage_root"
  signing_receipt="$artifact_root/windows-signing-components.jsonl"
  "$RM_BIN" -f -- "$signing_receipt"
  export SHELLX_WINDOWS_SIGNING_METADATA_PATH="$metadata_path"
  export SHELLX_DRIVE_RELEASE_SOURCE_REPO="$source_repo"
  export SHELLX_DRIVE_EXPECTED_SOURCE_COMMIT="$revision"
  export SHELLX_DRIVE_RELEASE_ARTIFACT_ROOT="$artifact_root"
  export SHELLX_DRIVE_RELEASE_NSIS_EXECUTABLE="$nsis_executable"
  export SHELLX_DRIVE_RELEASE_NSIS_EXECUTABLE_SHA256="$MAKENSIS_SHA256"
  export SHELLX_DRIVE_RELEASE_BUILD_STARTED="$started"
  export SHELLX_DRIVE_RELEASE_NSIS_SIGNING_STAGE_ROOT="$nsis_signing_stage_root"
  export SHELLX_DRIVE_RELEASE_SIGNING_STAGE_PARENT="$output_dir"
  export SHELLX_WINDOWS_SIGNING_RECEIPT_PATH="$signing_receipt"
  export SHELLX_DRIVE_SIGN_COMMAND_PATH="$sign_command"
  tauri_config="$("$NODE_BIN" -e 'process.stdout.write(JSON.stringify({bundle:{createUpdaterArtifacts:false,windows:{signCommand:{cmd:process.env.SHELLX_DRIVE_SIGN_COMMAND_PATH,args:["%1"]}}}}))')"
fi
"$MKDIR_BIN" -p -m 0700 "$release_build_root/windows-build-logs"
build_log="$("$MKTEMP_BIN" "$release_build_root/windows-build-logs/nsis-${short_revision}.XXXXXX.log")"
echo "[build-windows] packaging the completed Windows binary"
raw_binary="${SHELLX_DRIVE_WINDOWS_RAW_BINARY:-}"
raw_sha256="${SHELLX_DRIVE_WINDOWS_RAW_BINARY_SHA256:-}"
if [[ "$signing_required" == "1" ]]; then
  [[ -f "$raw_binary" && ! -L "$raw_binary" && "$raw_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || { echo 'FAIL: signed packaging requires the verified unsigned build result' >&2; exit 1; }
  observed="$("$SHA256SUM_BIN" -- "$raw_binary")"
  [[ "${observed%% *}" == "$raw_sha256" ]] || { echo 'FAIL: unsigned Windows binary changed' >&2; exit 1; }
  "$CP_BIN" --no-dereference -- "$raw_binary" "$executable"
  observed="$("$SHA256SUM_BIN" -- "$executable")"
  [[ "${observed%% *}" == "$raw_sha256" ]] || { echo 'FAIL: staged unsigned Windows binary changed' >&2; exit 1; }
  "$MKDIR_BIN" -p -- "$artifact_root/deps"
  "$LN_BIN" -- "$executable" "$artifact_root/deps/shellx_drive_desktop.exe"
  tauri_operation=bundle
else
  tauri_operation=build
fi
tauri_args=()
[[ "$tauri_operation" == bundle ]] || tauri_args=(--runner "$CARGO_XWIN_BIN" --no-sign)
release_source_context_checkpoint || exit 1
if ! "$NODE_BIN" "$tauri_cli" "$tauri_operation" "${tauri_args[@]}" \
  --target "$target" \
  --bundles nsis \
  --ci \
  --features desktop-shell \
  --config "$tauri_config" 2>&1 | "$TEE_BIN" "$build_log"; then
  echo "FAIL: Tauri Windows build failed" >&2
  exit 1
fi
release_source_context_checkpoint after-bundle | "$TEE_BIN" -a "$build_log" || exit 1
if [[ ! -f "$installer" || ! -f "$executable" ]]; then
  echo "FAIL: Tauri did not produce the expected x64 executable and NSIS installer" >&2
  exit 1
fi
if [[ "$signing_required" == "1" ]]; then
  if ! "$GREP_BIN" -Fq "NSIS uninstaller signing callback accepted from pinned makensis" "$build_log"; then
    echo "FAIL: the generated NSIS uninstaller did not pass the provenance-bound signing callback" >&2
    exit 1
  fi
  if "$FIND_BIN" "$nsis_signing_stage_root" -mindepth 1 -maxdepth 1 -print -quit | "$GREP_BIN" -q .; then
    echo "FAIL: NSIS signing stage retained a callback artifact" >&2
    exit 1
  fi
  "$RMDIR_BIN" -- "$nsis_signing_stage_root"
  nsis_signing_stage_root=""
fi
executable_leaf="$("$BASENAME_BIN" -- "$executable")"
installer_leaf="$("$BASENAME_BIN" -- "$installer")"
receipt_leaf=""
executable_output_sha256=""
installer_output_sha256=""
receipt_output_sha256=""
if [[ "$signing_required" == "1" ]]; then
  echo "[build-windows] privately staging, signing, verifying, and publishing final artifacts"
  for artifact_spec in "$installer|$installer_leaf"; do
    artifact_source="${artifact_spec%%|*}"
    artifact_leaf="${artifact_spec#*|}"
    artifact_pre_sign_sha256="$("$SHA256SUM_BIN" -- "$artifact_source")"
    artifact_pre_sign_sha256="${artifact_pre_sign_sha256%% *}"
    release_tool_verify_all
    release_helper_verify_all
    release_helper_verify_windows_stage
    "$POWERSHELL_BIN" -NoProfile -NonInteractive -WindowStyle Hidden \
      -File "$("$WSLPATH_BIN" -w "$sign_script")" \
      -MetadataPath "$("$WSLPATH_BIN" -w "$metadata_path")" \
      -ReceiptPath "$("$WSLPATH_BIN" -w "$signing_receipt")" \
      -ExpectedArtifactSha256 "$artifact_pre_sign_sha256" \
      -ExpectedMetadataSha256 "$SHELLX_DRIVE_RELEASE_METADATA_SHA256" \
      -ExpectedSignerSha256 "$(release_helper_digest SIGNER)" \
      -ExpectedSecurityHelperSha256 "$(release_helper_digest RELEASE_SECURITY)" \
      -ExpectedComponentsHelperSha256 "$(release_helper_digest SIGNING_COMPONENTS)" \
      -ExpectedIdentityHelperSha256 "$(release_helper_digest ARTIFACT_IDENTITY)" \
      -SigningStageParentPath "$("$WSLPATH_BIN" -w "$output_dir")" \
      -VerifyOnly \
      -PublishDirectoryPath "$("$WSLPATH_BIN" -w "$output_dir")" \
      -PublishLeafName "$artifact_leaf" \
      -Artifacts "$("$WSLPATH_BIN" -w "$artifact_source")"
  done
  admit_signed_candidate_artifact "$signing_receipt" "$executable_leaf" executable_output_sha256
  admit_signed_candidate_artifact "$signing_receipt" "$installer_leaf" installer_output_sha256
  if [[ ! -s "$signing_receipt" ]]; then
    echo "FAIL: signing identity receipt was not written" >&2
    exit 1
  fi
  receipt_leaf="$("$BASENAME_BIN" -- "$signing_receipt")"
  receipt_expected_sha256="$("$SHA256SUM_BIN" -- "$signing_receipt")"
  receipt_expected_sha256="${receipt_expected_sha256%% *}"
  publish_candidate_artifact \
    "$signing_receipt" "$receipt_leaf" receipt_output_sha256 "$receipt_expected_sha256"
  drive_updater_sign_final
  drive_updater_assert_artifact_mode
  drive_updater_publish
  publish_windows_candidate_guide
  publish_signed_candidate_provenance
else
  publish_candidate_artifact "$executable" "$executable_leaf" executable_output_sha256
  publish_candidate_artifact "$installer" "$installer_leaf" installer_output_sha256
  publish_windows_candidate_guide
fi
echo "[build-windows] verifying release executable uses the Windows GUI subsystem"
"$NODE_BIN" "$desktop_dir/scripts/verify-windows-gui-subsystem.mjs" \
  --source "$desktop_dir/src-tauri/src/main.rs" \
  --exe "$output_dir/$executable_leaf"
finalize_candidate_output

if [[ "$signing_required" == "1" ]]; then
  echo "[build-windows] artifact hashes (signed release candidate)"
else
  echo "[build-windows] artifact hashes (unsigned development artifacts)"
fi
printf '%s  %s\n' "$executable_output_sha256" "$output_dir/$executable_leaf"
printf '%s  %s\n' "$installer_output_sha256" "$output_dir/$installer_leaf"
printf '%s  %s\n' "$guide_output_sha256" "$output_dir/$guide_leaf"
if [[ "$signing_required" == "1" ]]; then
  printf '%s  %s\n' "$receipt_output_sha256" "$output_dir/$receipt_leaf"
  drive_updater_print_hashes
fi
cleanup_build_state
build_log=""
trap - EXIT
echo "[build-windows] OK: $output_dir"
