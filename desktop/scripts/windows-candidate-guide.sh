#!/bin/bash
# Pin and publish the Windows end-user guide beside the exact candidate.

prepare_windows_candidate_guide() {
  local current_sha256 guide_git_repo
  guide_relative="docs/public/WINDOWS_DESKTOP.md"
  guide_source="$repo_root/$guide_relative"
  guide_leaf="WINDOWS_DESKTOP.md"
  guide_output_sha256=""
  if [[ -L "$guide_source" || ! -f "$guide_source" ]]; then
    echo "FAIL: Windows candidate guide is missing or unsafe" >&2
    return 1
  fi
  guide_git_repo="${source_repo:-$repo_root}"
  guide_expected_sha256="$("$GIT_BIN" -C "$guide_git_repo" show "$revision:$guide_relative" | "$SHA256SUM_BIN")" \
    || return 1
  guide_expected_sha256="${guide_expected_sha256%% *}"
  current_sha256="$("$SHA256SUM_BIN" -- "$guide_source")"
  current_sha256="${current_sha256%% *}"
  if [[ ! "$guide_expected_sha256" =~ ^[0-9a-f]{64}$ \
    || "$current_sha256" != "$guide_expected_sha256" ]]; then
    echo "FAIL: Windows candidate guide differs from the exact source commit" >&2
    return 1
  fi
}

publish_windows_candidate_guide() {
  publish_candidate_artifact \
    "$guide_source" "$guide_leaf" guide_output_sha256 "$guide_expected_sha256"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-candidate-provenance.sh" >&2
  exit 2
fi
