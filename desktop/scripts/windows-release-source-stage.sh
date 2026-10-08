#!/bin/bash
# Create and verify the private, exact-Git-object input tree for signed builds.
# This helper deliberately uses only bootstrap tools from the staged release
# closure. The normal unsigned developer lane never calls it.

readonly RELEASE_SOURCE_STAGE_TAR=/usr/bin/tar
readonly RELEASE_SOURCE_STAGE_MKTEMP=/usr/bin/mktemp
release_source_stage_fail() {
  echo "FAIL: $*" >&2
  return 1
}
release_source_stage_assert_private() {
  local stage="$1" identity
  release_helper_assert_private_home || return 1
  if [[ "${stage%/*}" != "$HOME" \
    || ! "${stage##*/}" =~ ^\.shellx-drive-release-source-[A-Za-z0-9._-]+$ \
    || -L "$stage" || ! -d "$stage" ]]; then
    release_source_stage_fail "release source stage is not a private absolute Drive path"
    return 1
  fi
  identity="$("$RELEASE_HELPER_STAT" -c '%u:%a:%F' -- "$stage")"
  if [[ "$identity" != "$("$RELEASE_HELPER_ID" -u):700:directory" ]]; then
    release_source_stage_fail "release source stage failed ownership or mode checks"
    return 1
  fi
}

release_source_stage_manifest_digest() {
  local repo="$1" commit="$2" digest
  digest="$("$RELEASE_HELPER_GIT" -C "$repo" ls-tree -r -z --full-tree "$commit" | "$RELEASE_HELPER_SHA256SUM")" \
    || return 1
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

release_source_stage_validate_tree() {
  local repo="$1" commit="$2" entry header relative mode type object
  while IFS= read -r -d '' entry; do
    header="${entry%%$'\t'*}"; relative="${entry#*$'\t'}"
    read -r mode type object <<< "$header"
    if [[ ( "$mode" != "100644" && "$mode" != "100755" ) || "$type" != "blob" \
      || ! "$object" =~ ^[0-9a-f]{40}$ || -z "$relative" ]]; then
      release_source_stage_fail "signed source stage refuses non-regular tracked input: $relative"
      return 1
    fi
  done < <("$RELEASE_HELPER_GIT" -C "$repo" ls-tree -r -z --full-tree "$commit")
}

release_source_stage_verify() {
  local stage="${SHELLX_DRIVE_RELEASE_SOURCE_STAGE:-}" phase="${1:-exact}" manifest entry header relative mode type object actual
  [[ "$phase" == exact || "$phase" == after-bundle ]] || { release_source_stage_fail "invalid source checkpoint phase"; return 1; }
  release_source_stage_assert_private "$stage" || return 1
  manifest="$stage/.source-tree-manifest.z"
  if [[ -L "$manifest" || ! -f "$manifest" \
    || "$("$RELEASE_HELPER_STAT" -c '%u:%a:%F' -- "$manifest")" \
      != "$("$RELEASE_HELPER_ID" -u):400:regular file" ]]; then
    release_source_stage_fail "release source manifest is missing or unsafe"
    return 1
  fi
  actual="$("$RELEASE_HELPER_SHA256SUM" -- "$manifest")"; actual="${actual%% *}"
  [[ "$actual" == "$SHELLX_DRIVE_RELEASE_SOURCE_MANIFEST_SHA256" ]] \
    || { release_source_stage_fail "release source manifest bytes drifted"; return 1; }
  while IFS= read -r -d '' entry; do
    header="${entry%%$'\t'*}"; relative="${entry#*$'\t'}"
    read -r mode type object <<< "$header"
    [[ "$mode" =~ ^100(644|755)$ && "$type" == "blob" && "$object" =~ ^[0-9a-f]{40}$ ]] \
      || { release_source_stage_fail "release source manifest is invalid"; return 1; }
    if [[ -L "$stage/$relative" || ! -f "$stage/$relative" ]]; then
      release_source_stage_fail "private source input is missing or linked: $relative"
      return 1
    fi
    actual="$(env -u GIT_DIR -u GIT_WORK_TREE "$RELEASE_HELPER_GIT" hash-object --no-filters -- "$stage/$relative")" \
      || return 1
    if [[ "$actual" != "$object" ]]; then
      if [[ "$phase" == after-bundle && "$relative" == desktop/src-tauri/Cargo.toml ]] \
        && release_helper_verify_identity SOURCE_MANIFEST \
        && "$NODE_BIN" "$(release_helper_path SOURCE_MANIFEST)" "$stage/$relative" \
          "$SHELLX_DRIVE_RELEASE_ORIGINAL_SOURCE_REPO" "$object"; then
        continue
      fi
      release_source_stage_fail "private source input bytes drifted: $relative"
      return 1
    fi
  done < "$manifest"
}

release_source_stage_create() {
  local repo="$1" commit="$2" stage manifest actual_manifest
  [[ -z "${SHELLX_DRIVE_RELEASE_SOURCE_STAGE:-}" ]] \
    || { release_source_stage_fail "release source stage is already set"; return 1; }
  release_helper_assert_private_home || return 1
  release_helper_source_is_exact "$repo" "$commit" || return 1
  release_source_stage_validate_tree "$repo" "$commit" || return 1
  stage="$("$RELEASE_SOURCE_STAGE_MKTEMP" -d "$HOME/.shellx-drive-release-source-${commit:0:12}.XXXXXX")" \
    || return 1
  "$RELEASE_HELPER_CHMOD" 0700 "$stage" || return 1
  manifest="$stage/.source-tree-manifest.z"
  if ! "$RELEASE_HELPER_GIT" -C "$repo" ls-tree -r -z --full-tree "$commit" > "$manifest" \
    || ! "$RELEASE_HELPER_CHMOD" 0400 "$manifest" \
    || ! "$RELEASE_HELPER_GIT" -C "$repo" archive --format=tar "$commit" \
      | "$RELEASE_SOURCE_STAGE_TAR" -xf - -C "$stage"; then
    "$RELEASE_HELPER_RM" -rf -- "$stage"
    return 1
  fi
  SHELLX_DRIVE_RELEASE_SOURCE_STAGE="$stage"
  SHELLX_DRIVE_RELEASE_SOURCE_MANIFEST_SHA256="$(release_source_stage_manifest_digest "$repo" "$commit")" \
    || { "$RELEASE_HELPER_RM" -rf -- "$stage"; return 1; }
  export SHELLX_DRIVE_RELEASE_SOURCE_STAGE SHELLX_DRIVE_RELEASE_SOURCE_MANIFEST_SHA256
  actual_manifest="$("$RELEASE_HELPER_SHA256SUM" -- "$manifest")"; actual_manifest="${actual_manifest%% *}"
  [[ "$actual_manifest" == "$SHELLX_DRIVE_RELEASE_SOURCE_MANIFEST_SHA256" ]] \
    || { "$RELEASE_HELPER_RM" -rf -- "$stage"; return 1; }
  release_source_stage_verify || { "$RELEASE_HELPER_RM" -rf -- "$stage"; return 1; }
  release_helper_source_is_exact "$repo" "$commit"
}

release_source_stage_remove() {
  local stage="${SHELLX_DRIVE_RELEASE_SOURCE_STAGE:-}"
  [[ -z "$stage" ]] && return 0
  release_source_stage_assert_private "$stage" || return 1
  "$RELEASE_HELPER_RM" -rf -- "$stage"
  SHELLX_DRIVE_RELEASE_SOURCE_STAGE=""
  SHELLX_DRIVE_RELEASE_SOURCE_MANIFEST_SHA256=""
}

release_source_stage_checkpoint() {
  [[ "${signing_required:-0}" != "1" ]] || release_source_stage_verify "${1:-exact}"
}

release_source_stage_prepare_build_workspace() {
  release_build_root="$SHELLX_DRIVE_RELEASE_SOURCE_STAGE/.release-build"
  /usr/bin/mkdir -p -m 0700 -- "$release_build_root" || return 1
  CARGO_TARGET_DIR="$release_build_root/cargo-target"
  export CARGO_TARGET_DIR
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-release-build-body.sh" >&2
  exit 2
fi
