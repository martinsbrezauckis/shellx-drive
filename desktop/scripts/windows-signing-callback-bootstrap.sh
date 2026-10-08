#!/bin/bash
# Enter the staged callback closure and pinned tool manifest before signing.
release_callback_bootstrap() {
  callback_path="$1"
  artifact_path="$2"
  [[ "$callback_path" == /* ]] || callback_path="$PWD/$callback_path"
  callback_dir="$(cd -- "${callback_path%/*}" && pwd -P)"
  callback_path="$callback_dir/${callback_path##*/}"
  local closure_helper="$callback_dir/windows-release-helper-closure.sh"
  local callback_log_helper="$callback_dir/windows-signing-callback-log.sh"
  if [[ -L "$closure_helper" || ! -f "$closure_helper" \
    || -L "$callback_log_helper" || ! -f "$callback_log_helper" ]]; then
    echo "trusted release callback closure is missing or unsafe" >&2
    return 1
  fi
  source "$callback_log_helper"
  release_callback_log_start_early "$artifact_path"
  source "$closure_helper"
  release_helper_import
  release_helper_verify_all
  toolchain_helper="$(release_helper_path TOOLCHAIN)"
  source "$toolchain_helper"
  release_tool_init 1
  release_tool_import_manifest
  release_tool_use_pinned_path
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-artifact-sign-command.sh" >&2
  exit 2
fi
