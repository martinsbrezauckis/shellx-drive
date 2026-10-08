#!/bin/bash
# Select the source and helper context for signed and unsigned Windows builds.
# Signed callers source this only after the private helper closure is verified.

release_source_context_signed() {
  local build_body_path="$1" source_stage_helper
  source_repo="${SHELLX_DRIVE_RELEASE_ORIGINAL_SOURCE_REPO:-}"
  repo_root="${SHELLX_DRIVE_RELEASE_SOURCE_STAGE:-}"
  revision="${SHELLX_DRIVE_EXPECTED_SOURCE_COMMIT:-}"
  source_stage_helper="$(release_helper_path SOURCE_STAGE)"
  # shellcheck source=windows-release-source-stage.sh
  source "$source_stage_helper"
  trap 'release_source_stage_remove >/dev/null 2>&1 || true; release_helper_remove_stage >/dev/null 2>&1 || true' EXIT
  if [[ "$("$RELEASE_HELPER_READLINK" -f -- "$build_body_path")" \
    != "$(release_helper_path BUILD_BODY)" ]]; then
    echo "FAIL: signed release build body was not entered from its staged identity" >&2
    return 1
  fi
  release_helper_source_is_exact "$source_repo" "$revision" || return 1
  toolchain_helper="$(release_helper_path TOOLCHAIN)"
  cleanup_helper="$(release_helper_path CLEANUP)"
  candidate_output_helper="$(release_helper_path CANDIDATE_OUTPUT)"
  signed_candidate_helper="$(release_helper_path SIGNED_CANDIDATE)"
}

release_source_context_unsigned() {
  local build_script_dir="$1"
  repo_root="$(cd -- "$build_script_dir/../.." && pwd -P)"
  source_repo=""
  revision="$(/usr/bin/git -C "$repo_root" rev-parse HEAD)"
  release_helper_stage=""
  toolchain_helper="$build_script_dir/windows-release-toolchain.sh"
  cleanup_helper="$build_script_dir/windows-release-cleanup.sh"
  candidate_output_helper="$build_script_dir/windows-candidate-output.sh"
  signed_candidate_helper="$build_script_dir/windows-signed-candidate.sh"
}

release_source_context_checkpoint() {
  if [[ "$signing_required" == "1" ]]; then
    release_source_stage_checkpoint "${1:-exact}"
  elif [[ -n "$("$GIT_BIN" status --porcelain)" || "$revision" != "$("$GIT_BIN" rev-parse HEAD)" ]]; then
    echo "FAIL: unsigned release source changed after admission" >&2
    return 1
  fi
}

release_source_context_prepare_build_workspace() {
  if [[ "$signing_required" == "1" ]]; then
    release_source_stage_prepare_build_workspace
  else
    release_build_root="$repo_root/.scratch"
    : "${CARGO_TARGET_DIR:=$desktop_dir/target}"
    export CARGO_TARGET_DIR
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-release-build-body.sh" >&2
  exit 2
fi
