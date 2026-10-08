#!/bin/bash
set -euo pipefail
umask 077

# Signed releases enter as exact Git object bytes (see windows-acceptance).
# This dispatcher privately stages and re-enters itself before any build or
# signing operation. Direct checkout execution remains unsigned-only.

signing_required="${SHELLX_DRIVE_WINDOWS_SIGNING_REQUIRED:-0}"
if [[ ! "$signing_required" =~ ^[01]$ ]]; then
  echo "FAIL: SHELLX_DRIVE_WINDOWS_SIGNING_REQUIRED must be 0 or 1" >&2
  exit 2
fi
if [[ "$signing_required" == "0" ]]; then
  script_path="${BASH_SOURCE[0]}"
  [[ "$script_path" == /* ]] || script_path="$PWD/$script_path"
  script_dir="$(cd -- "${script_path%/*}" && pwd -P)"
  exec /usr/bin/bash "$script_dir/windows-release-build-body.sh" "$@"
fi

release_entry_assert_private_stage() {
  local stage="${1:-}" current="$HOME" identity owner mode kind uid root_owner
  uid="$(/usr/bin/id -u)"
  root_owner="$(/usr/bin/stat -c '%u' -- /)" || return 1
  [[ "$HOME" == /* && ! -L "$HOME" && -d "$HOME" \
    && "$HOME" == "$(cd -- "$HOME" && pwd -P)" ]] || return 1
  while :; do
    identity="$(/usr/bin/stat -c '%u %a %F' -- "$current")" || return 1
    read -r owner mode kind <<< "$identity"
    [[ "$kind" == directory && "$mode" =~ ^[0-7]{3,4}$ \
      && ( "$owner" == "$root_owner" || "$owner" == "$uid" ) \
      && ( "$current" != "$HOME" || "$owner" == "$uid" ) ]] || return 1
    (( (8#$mode & 0022) == 0 )) || return 1
    [[ "$current" == / ]] && break
    current="${current%/*}"; [[ -n "$current" ]] || current=/
  done
  [[ -z "$stage" ]] && return 0
  [[ "${stage%/*}" == "$HOME" \
    && "${stage##*/}" =~ ^\.shellx-drive-release-helpers-[A-Za-z0-9._-]+$ \
    && ! -L "$stage" && -d "$stage" \
    && "$(/usr/bin/stat -c '%u:%a:%F' -- "$stage")" == "$uid:700:directory" ]]
}

repo_root="${SHELLX_DRIVE_RELEASE_SOURCE_REPO:-}"
revision="${SHELLX_DRIVE_EXPECTED_SOURCE_COMMIT:-}"
if [[ "${SHELLX_DRIVE_RELEASE_ENTRY_STAGED:-0}" != "1" ]]; then
  if [[ -n "${BASH_SOURCE[0]-}" ]]; then
    echo "FAIL: signed builds must load the release entry from exact Git object bytes" >&2
    exit 1
  fi
  if ! release_entry_assert_private_stage; then
    echo "FAIL: signed release home or its parents are untrusted" >&2
    exit 1
  fi
  if [[ ! "$revision" =~ ^[0-9a-f]{40}$ || -z "$repo_root" ]]; then
    echo "FAIL: commit-derived release entry requires an exact source repository and commit" >&2
    exit 1
  fi
  repo_root="$(cd -- "$repo_root" && pwd -P)"
  if [[ "$(/usr/bin/git -C "$repo_root" rev-parse HEAD)" != "$revision" \
    || -n "$(/usr/bin/git -C "$repo_root" status --porcelain --untracked-files=all)" ]]; then
    echo "FAIL: signed build source changed before release entry admission" >&2
    exit 1
  fi
  release_entry_stage="$(/usr/bin/mktemp -d "$HOME/.shellx-drive-release-helpers-${revision:0:12}.XXXXXX")"
  /usr/bin/chmod 0700 "$release_entry_stage"
  trap '/usr/bin/rm -rf -- "$release_entry_stage"' EXIT
  release_entry_assert_private_stage "$release_entry_stage" \
    || { echo "FAIL: signed release helper stage is untrusted" >&2; exit 1; }
  for entry_spec in \
    'desktop/scripts/build-windows-nsis-from-wsl.sh build-windows-nsis-from-wsl.sh' \
    'desktop/scripts/windows-release-helper-closure.sh windows-release-helper-closure.sh'; do
    relative="${entry_spec%% *}"; leaf="${entry_spec#* }"
    expected="$(/usr/bin/git -C "$repo_root" show "$revision:$relative" | /usr/bin/sha256sum)"
    expected="${expected%% *}"
    /usr/bin/git -C "$repo_root" show "$revision:$relative" > "$release_entry_stage/$leaf"
    /usr/bin/chmod 0500 "$release_entry_stage/$leaf"
    actual="$(/usr/bin/sha256sum "$release_entry_stage/$leaf")"; actual="${actual%% *}"
    [[ "$actual" == "$expected" ]] \
      || { echo "FAIL: commit-derived release entry staging drifted: $leaf" >&2; exit 1; }
  done
  export SHELLX_DRIVE_RELEASE_SOURCE_REPO="$repo_root"
  export SHELLX_DRIVE_EXPECTED_SOURCE_COMMIT="$revision"
  export SHELLX_DRIVE_RELEASE_HELPER_STAGE="$release_entry_stage"
  export SHELLX_DRIVE_RELEASE_ENTRY_STAGED=1
  exec /usr/bin/bash "$release_entry_stage/build-windows-nsis-from-wsl.sh" "$@"
fi

release_entry_stage="${SHELLX_DRIVE_RELEASE_HELPER_STAGE:-}"
release_entry_assert_private_stage "$release_entry_stage" \
  || { echo "FAIL: signed release helper stage is untrusted" >&2; exit 1; }
[[ "${BASH_SOURCE[0]}" == "$release_entry_stage/build-windows-nsis-from-wsl.sh" \
  && "$revision" =~ ^[0-9a-f]{40}$ && -n "$repo_root" \
  && "$(/usr/bin/git -C "$repo_root" rev-parse HEAD)" == "$revision" \
  && -z "$(/usr/bin/git -C "$repo_root" status --porcelain --untracked-files=all)" ]] \
  || { echo "FAIL: signed release entry source identity changed" >&2; exit 1; }
for entry_spec in \
  'desktop/scripts/build-windows-nsis-from-wsl.sh build-windows-nsis-from-wsl.sh' \
  'desktop/scripts/windows-release-helper-closure.sh windows-release-helper-closure.sh'; do
  relative="${entry_spec%% *}"; leaf="${entry_spec#* }"
  expected="$(/usr/bin/git -C "$repo_root" show "$revision:$relative" | /usr/bin/sha256sum)"
  expected="${expected%% *}"
  actual="$(/usr/bin/sha256sum -- "$release_entry_stage/$leaf")"; actual="${actual%% *}"
  [[ ! -L "$release_entry_stage/$leaf" \
    && "$(/usr/bin/stat -c '%u:%a:%F' -- "$release_entry_stage/$leaf")" \
      == "$(/usr/bin/id -u):500:regular file" && "$actual" == "$expected" ]] \
    || { echo "FAIL: signed release entry helper identity changed: $leaf" >&2; exit 1; }
done
trap '/usr/bin/rm -rf -- "$release_entry_stage"' EXIT
closure_helper="$release_entry_stage/windows-release-helper-closure.sh"
[[ ! -L "$closure_helper" && -f "$closure_helper" ]] \
  || { echo "FAIL: staged release helper closure is missing" >&2; exit 1; }
# shellcheck source=windows-release-helper-closure.sh
source "$closure_helper"
release_helper_stage_all "$repo_root" "$revision" "$release_entry_stage"
entry_path="$("$RELEASE_HELPER_READLINK" -f -- "${BASH_SOURCE[0]}")"
if [[ "$entry_path" != "$(release_helper_path BUILD_ENTRY)" ]]; then
  echo "FAIL: signed release entry did not preserve its staged identity" >&2
  exit 1
fi
if [[ "${1:-}" == "--verify-signed-entry" ]]; then
  printf 'SIGNED_RELEASE_ENTRY_OK commit=%s path=%s sha256=%s\n' \
    "$revision" "$entry_path" "$(release_helper_digest BUILD_ENTRY)"
  release_helper_remove_stage
  trap - EXIT
  exit 0
fi
source_stage_helper="$(release_helper_path SOURCE_STAGE)"
[[ ! -L "$source_stage_helper" && -f "$source_stage_helper" ]] \
  || { echo "FAIL: staged release source helper is missing" >&2; exit 1; }
# shellcheck source=windows-release-source-stage.sh
source "$source_stage_helper"
release_source_stage_create "$repo_root" "$revision"
export SHELLX_DRIVE_RELEASE_ORIGINAL_SOURCE_REPO="$repo_root"
exec /usr/bin/bash "$(release_helper_path BUILD_BODY)" "$@"
