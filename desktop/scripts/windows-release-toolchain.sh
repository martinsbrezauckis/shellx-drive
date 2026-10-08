#!/bin/bash
# Shared by the WSL release builder and the Tauri signing callback. Callers
# resolve tools once; signed builds also bind every tool to protected path
# components and export its selected path, resolved path, and SHA-256.

readonly RELEASE_BOOTSTRAP_ID=/usr/bin/id
readonly RELEASE_BOOTSTRAP_READLINK=/usr/bin/readlink
readonly RELEASE_BOOTSTRAP_SHA256SUM=/usr/bin/sha256sum
readonly RELEASE_BOOTSTRAP_STAT=/usr/bin/stat
declare -ag RELEASE_TOOL_KEYS=()
RELEASE_TOOL_SIGNED=0

release_tool_fail() {
  echo "FAIL: $*" >&2
  return 1
}

release_tool_read_id_map() {
  local path="$1" inside outside length extra second
  {
    IFS=' ' read -r inside outside length extra || return 1
    [[ -z "$extra" ]] || return 1
    if IFS= read -r second; then return 1; fi
  } < "$path"
  [[ "$inside" =~ ^[0-9]+$ && "$outside" =~ ^[0-9]+$ && "$length" =~ ^[0-9]+$ ]] \
    || return 1
  printf '%s:%s:%s\n' "$inside" "$outside" "$length"
}

release_tool_id_maps_are_initial() {
  [[ "$1" == "0:0:4294967295" && "$2" == "0:0:4294967295" ]]
}

release_tool_assert_initial_id_namespace() {
  local uid_map gid_map
  uid_map="$(release_tool_read_id_map /proc/self/uid_map)" \
    || { release_tool_fail "cannot read the signing process UID map"; return 1; }
  gid_map="$(release_tool_read_id_map /proc/self/gid_map)" \
    || { release_tool_fail "cannot read the signing process GID map"; return 1; }
  if ! release_tool_id_maps_are_initial "$uid_map" "$gid_map"; then
    echo "SIGNED_BUILD_ENVIRONMENT_BLOCKED uid_map=$uid_map gid_map=$gid_map" >&2
    echo "ACTION: run the signed build from an ordinary WSL shell outside the managed sandbox" >&2
    return 1
  fi
}

release_tool_diagnose_environment() {
  local uid_map gid_map owner mode status="eligible" reason="initial-id-namespace"
  uid_map="$(release_tool_read_id_map /proc/self/uid_map 2>/dev/null || echo unreadable)"
  gid_map="$(release_tool_read_id_map /proc/self/gid_map 2>/dev/null || echo unreadable)"
  read -r owner mode < <("$RELEASE_BOOTSTRAP_STAT" -c '%u %a' -- "$RELEASE_BOOTSTRAP_ID")
  if ! release_tool_id_maps_are_initial "$uid_map" "$gid_map"; then
    status="blocked"; reason="non-initial-id-namespace"
  fi
  echo "WINDOWS_RELEASE_ENVIRONMENT status=$status reason=$reason"
  echo "uid_map=$uid_map gid_map=$gid_map current_uid=$("$RELEASE_BOOTSTRAP_ID" -u)"
  echo "system_tool=$RELEASE_BOOTSTRAP_ID owner=$owner mode=$mode"
  if [[ "$status" == "blocked" ]]; then
    echo "ACTION: run the signed build from an ordinary WSL shell outside the managed sandbox"
    return 3
  fi
}

release_tool_check_component() {
  local path="$1" follow="${2:-0}" owner mode kind current_uid numeric
  if [[ "$follow" == "1" ]]; then
    read -r owner mode kind < <("$RELEASE_BOOTSTRAP_STAT" -Lc '%u %a %F' -- "$path") \
      || { release_tool_fail "could not inspect release tool path: $path"; return 1; }
  else
    read -r owner mode kind < <("$RELEASE_BOOTSTRAP_STAT" -c '%u %a %F' -- "$path") \
      || { release_tool_fail "could not inspect release tool path: $path"; return 1; }
  fi
  current_uid="$("$RELEASE_BOOTSTRAP_ID" -u)"
  if [[ "$owner" != "0" && "$owner" != "$current_uid" ]]; then
    release_tool_fail "release tool path has an untrusted owner: $path"
    return 1
  fi
  numeric=$((8#$mode))
  if [[ "$kind" != "symbolic link" ]] && (( (numeric & 8#22) != 0 )); then
    release_tool_fail "release tool path is group- or other-writable: $path"
    return 1
  fi
}

release_tool_check_parents() {
  local path="${1%/*}"
  while [[ -n "$path" && "$path" != "/" ]]; do
    # WSL reports synthetic 0777 permissions on the Windows mount root. The
    # Windows subtree itself is still checked from its first component down.
    [[ "$path" =~ ^/mnt/[[:alpha:]]$ ]] && break
    release_tool_check_component "$path" || return 1
    path="${path%/*}"
  done
  [[ "$path" != "/" ]] || release_tool_check_component "/"
}

release_tool_check_path() {
  local selected="$1" resolved
  if [[ ! "$selected" =~ ^/[^[:cntrl:]]+$ || ! -f "$selected" || ! -x "$selected" ]]; then
    release_tool_fail "release tool must be an absolute executable file: $selected"
    return 1
  fi
  resolved="$("$RELEASE_BOOTSTRAP_READLINK" -f -- "$selected")"
  if [[ ! "$resolved" =~ ^/[^[:cntrl:]]+$ || ! -f "$resolved" || ! -x "$resolved" ]]; then
    release_tool_fail "release tool target is not an absolute executable file: $selected"
    return 1
  fi
  release_tool_check_component "$selected" || return 1
  release_tool_check_parents "$selected" || return 1
  release_tool_check_component "$resolved" 1 || return 1
  release_tool_check_parents "$resolved" || return 1
}

release_tool_init() {
  RELEASE_TOOL_SIGNED="$1"
  if [[ ! "$RELEASE_TOOL_SIGNED" =~ ^[01]$ ]]; then
    release_tool_fail "release tool mode must be 0 or 1"
    return 1
  fi
  if [[ "$RELEASE_TOOL_SIGNED" == "1" ]]; then
    release_tool_assert_initial_id_namespace || return 1
    for bootstrap in "$RELEASE_BOOTSTRAP_ID" "$RELEASE_BOOTSTRAP_READLINK" \
      "$RELEASE_BOOTSTRAP_SHA256SUM" "$RELEASE_BOOTSTRAP_STAT"; do
      release_tool_check_path "$bootstrap" || return 1
    done
  fi
}

release_tool_register() {
  local key="$1" selected="$2" label="$3" resolved digest prefix
  if [[ ! "$key" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    release_tool_fail "invalid release tool key: $key"
    return 1
  fi
  if [[ "$selected" != /* || ! -f "$selected" || ! -x "$selected" ]]; then
    release_tool_fail "$label is required as an absolute executable"
    return 1
  fi
  resolved="$("$RELEASE_BOOTSTRAP_READLINK" -f -- "$selected")"
  digest=""
  if [[ "$RELEASE_TOOL_SIGNED" == "1" ]]; then
    release_tool_check_path "$selected" || return 1
    digest="$("$RELEASE_BOOTSTRAP_SHA256SUM" -- "$resolved")"
    digest="${digest%% *}"
    if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
      release_tool_fail "could not hash $label"
      return 1
    fi
  fi
  printf -v "${key}_BIN" '%s' "$selected"
  printf -v "${key}_RESOLVED" '%s' "$resolved"
  printf -v "${key}_SHA256" '%s' "$digest"
  RELEASE_TOOL_KEYS+=("$key")
  if [[ "$RELEASE_TOOL_SIGNED" == "1" ]]; then
    prefix="SHELLX_DRIVE_RELEASE_TOOL_${key}"
    printf -v "${prefix}_PATH" '%s' "$selected"
    printf -v "${prefix}_RESOLVED_PATH" '%s' "$resolved"
    printf -v "${prefix}_SHA256" '%s' "$digest"
    export "${prefix}_PATH" "${prefix}_RESOLVED_PATH" "${prefix}_SHA256"
  fi
}

release_tool_admit_data_file() {
  local path="$1" result_variable="$2" label="$3" digest
  if [[ -L "$path" || ! -f "$path" ]]; then
    release_tool_fail "$label must be a regular non-link file"; return 1
  fi
  release_tool_check_component "$path" || return 1
  release_tool_check_parents "$path" || return 1
  digest="$("$RELEASE_BOOTSTRAP_SHA256SUM" -- "$path")"; digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
    || { release_tool_fail "could not hash $label"; return 1; }
  printf -v "$result_variable" '%s' "$digest"
  export "$result_variable"
}

release_tool_resolve() {
  local key="$1" command_name="$2" selected
  selected="$(command -v -- "$command_name" 2>/dev/null || true)"
  release_tool_register "$key" "$selected" "$command_name"
}

release_tool_export_manifest() {
  local IFS=' ' key prefix variable
  SHELLX_DRIVE_RELEASE_TOOL_NAMES="${RELEASE_TOOL_KEYS[*]}"
  export SHELLX_DRIVE_RELEASE_TOOL_NAMES
  release_tool_bridge_windows_env SHELLX_DRIVE_RELEASE_TOOL_NAMES
  release_tool_bridge_windows_env SHELLX_DRIVE_EXPECTED_SOURCE_COMMIT
  for key in "${RELEASE_TOOL_KEYS[@]}"; do
    prefix="SHELLX_DRIVE_RELEASE_TOOL_${key}"
    for variable in "${prefix}_PATH" "${prefix}_RESOLVED_PATH" "${prefix}_SHA256"; do
      release_tool_bridge_windows_env "$variable"
    done
  done
}

release_tool_bridge_windows_env() {
  local variable="$1"
  case ":${WSLENV:-}:" in
    *":$variable:"*|*":$variable/"*) ;;
    *) WSLENV="${WSLENV:+$WSLENV:}$variable" ;;
  esac
  export WSLENV
}

release_tool_verify_identity() {
  local key="$1" prefix path_name resolved_name hash_name selected expected_resolved expected_hash
  prefix="SHELLX_DRIVE_RELEASE_TOOL_${key}"
  path_name="${prefix}_PATH"; resolved_name="${prefix}_RESOLVED_PATH"; hash_name="${prefix}_SHA256"
  selected="${!path_name:-}"; expected_resolved="${!resolved_name:-}"; expected_hash="${!hash_name:-}"
  if [[ ! "$expected_hash" =~ ^[0-9a-f]{64}$ ]]; then
    release_tool_fail "release tool identity is missing: $key"
    return 1
  fi
  release_tool_check_path "$selected" || return 1
  if [[ "$("$RELEASE_BOOTSTRAP_READLINK" -f -- "$selected")" != "$expected_resolved" ]]; then
    release_tool_fail "release tool target drifted: $key"
    return 1
  fi
  local actual_hash
  actual_hash="$("$RELEASE_BOOTSTRAP_SHA256SUM" -- "$expected_resolved")"
  if [[ "${actual_hash%% *}" != "$expected_hash" ]]; then
    release_tool_fail "release tool bytes drifted: $key"
    return 1
  fi
  printf -v "${key}_BIN" '%s' "$selected"
  printf -v "${key}_RESOLVED" '%s' "$expected_resolved"
  printf -v "${key}_SHA256" '%s' "$expected_hash"
}

release_tool_import_manifest() {
  local key
  if [[ -z "${SHELLX_DRIVE_RELEASE_TOOL_NAMES:-}" ]]; then
    release_tool_fail "release tool identity manifest is missing"
    return 1
  fi
  read -r -a RELEASE_TOOL_KEYS <<< "$SHELLX_DRIVE_RELEASE_TOOL_NAMES"
  for key in "${RELEASE_TOOL_KEYS[@]}"; do
    if [[ ! "$key" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
      release_tool_fail "invalid release tool key: $key"
      return 1
    fi
    release_tool_verify_identity "$key" || return 1
  done
}

release_tool_verify_all() {
  local key
  for key in "${RELEASE_TOOL_KEYS[@]}"; do release_tool_verify_identity "$key" || return 1; done
}

release_tool_use_pinned_path() {
  local key variable tool directory pinned=""
  for key in "${RELEASE_TOOL_KEYS[@]}"; do
    for variable in "${key}_BIN" "${key}_RESOLVED"; do
      tool="${!variable}"; directory="${tool%/*}"
      case ":$pinned:" in *":$directory:"*) ;; *) pinned="${pinned:+$pinned:}$directory" ;; esac
    done
  done
  PATH="$pinned"
  export PATH
}

release_pnpm_run() {
  local prefix
  IFS= read -r -N 4 prefix < "$PNPM_RESOLVED" || return 1
  if [[ "$prefix" == $'\177ELF' ]]; then "$PNPM_RESOLVED" "$@";
  else "$NODE_BIN" "$PNPM_RESOLVED" "$@"; fi
}

release_windows_profile_wsl() {
  local profile_win profile_wsl
  profile_win="$("$POWERSHELL_BIN" -NoProfile -Command '[Environment]::GetFolderPath("UserProfile")' \
    | "$TR_BIN" -d '\r' | "$TAIL_BIN" -n 1)"
  profile_wsl="$("$WSLPATH_BIN" -u "$profile_win" 2>/dev/null || true)"
  if [[ -z "$profile_wsl" || ! -d "$profile_wsl" ]]; then
    release_tool_fail "unable to resolve the Windows user profile from WSL"
    return 1
  fi
  printf '%s\n' "$profile_wsl"
}

release_to_wsl_path() {
  local path="$1"
  if [[ "$path" =~ ^[A-Za-z]:\\ ]]; then
    "$WSLPATH_BIN" -u "$path"
  else
    printf '%s\n' "$path"
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if [[ "$#" == "1" && "$1" == "--diagnose" ]]; then
    release_tool_diagnose_environment
    exit $?
  fi
  echo "usage: bash $0 --diagnose" >&2
  exit 2
fi
