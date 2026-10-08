#!/bin/bash
# Signed-updater preparation and publication for the Windows release builder.

drive_updater_init() {
  installer_signature="$installer.sig"
  updater_candidate="$artifact_root/.windows-updater-candidate-${short_revision}.json"
  updater_signature_leaf=""
  updater_signature_output_sha256=""
  updater_candidate_leaf=""
  updater_candidate_output_sha256=""
}

drive_updater_sign_final() {
  # The trusted Studio receiver reads the named key only after Authenticode
  # verification. Neither this shell nor the product CLI receives its value.
  local receiver="${SHELLX_DRIVE_WINDOWS_UPDATER_RECEIVER:?}" digest
  release_tool_check_path "$receiver" || return 1
  digest="$("$SHA256SUM_BIN" -- "$receiver")"; digest="${digest%% *}"
  [[ "$digest" == "${SHELLX_DRIVE_WINDOWS_UPDATER_RECEIVER_SHA256:?}" ]] || return 1
  /usr/bin/prlimit --core=0 -- "$NODE_BIN" "$receiver" \
    --installer "$installer" --sha256 "$installer_output_sha256" \
    --config "$desktop_dir/src-tauri/tauri.conf.json"
}

drive_updater_assert_artifact_mode() {
  if [[ "$signing_required" == "1" ]]; then
    if [[ -L "$installer_signature" || ! -s "$installer_signature" ]]; then
      echo "FAIL: signed release did not produce the installer updater signature" >&2
      return 1
    fi
    # Verify the final Tauri installer before any candidate publication.
    drive_updater_verify_artifact
  elif [[ -e "$installer_signature" || -L "$installer_signature" ]]; then
    echo "FAIL: unsigned development build unexpectedly produced an updater signature" >&2
    return 1
  fi
}

drive_updater_verify_artifact() {
  if [[ "$signing_required" != "1" ]]; then
    return 0
  fi
  /usr/bin/prlimit --core=0 -- "$NODE_BIN" "$SHELLX_DRIVE_WINDOWS_UPDATER_RECEIVER" --verify-only \
    --sha256 "$installer_output_sha256" \
    --config "$desktop_dir/src-tauri/tauri.conf.json" \
    --installer "$installer"
}

drive_updater_publish() {
  local source_tree writer
  updater_signature_leaf="$installer_leaf.sig"
  publish_candidate_artifact \
    "$installer_signature" "$updater_signature_leaf" updater_signature_output_sha256
  if [[ -e "$updater_candidate" || -L "$updater_candidate" ]]; then
    echo "FAIL: updater candidate staging path is not fresh" >&2
    return 1
  fi
  source_tree="$("$GIT_BIN" -C "$source_repo" rev-parse "${revision}^{tree}")" || return 1
  writer="${SHELLX_DRIVE_RELEASE_HELPER_UPDATER_CANDIDATE_WRITER_PATH:-$desktop_dir/scripts/write-updater-candidate.mjs}"
  "$NODE_BIN" "$writer" \
    --platform windows-x86_64 \
    --version "$version" \
    --source-commit "$revision" --source-tree "$source_tree" \
    --artifact "$output_dir/$installer_leaf" --signature "$output_dir/$updater_signature_leaf" \
    --identity-kind authenticode --identity-evidence "$output_dir/$receipt_leaf" \
    --candidate-root "$output_dir" --out "$updater_candidate"
  updater_candidate_leaf="windows-updater-candidate.json"
  publish_candidate_artifact \
    "$updater_candidate" "$updater_candidate_leaf" updater_candidate_output_sha256
  "$RM_BIN" -f -- "$updater_candidate"
}

drive_updater_print_hashes() {
  printf '%s  %s\n' "$updater_signature_output_sha256" "$output_dir/$updater_signature_leaf"
  printf '%s  %s\n' "$updater_candidate_output_sha256" "$output_dir/$updater_candidate_leaf"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-release-build-body.sh" >&2
  exit 2
fi
