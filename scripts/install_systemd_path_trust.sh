#!/bin/bash

# Root-anchored pathname validation shared by the privileged installer helpers.
# Tests patch only a copied helper, so production always anchors at real root.
trusted_env_root="/"
trusted_env_uid="$(stat -c '%u' -- "$trusted_env_root")"
trusted_env_gid="$(stat -c '%g' -- "$trusted_env_root")"

env_trust_error() {
  echo "unsafe --env-file path: $1" >&2
  return 1
}

trusted_path_error() {
  local label="$1"
  local message="$2"
  echo "unsafe $label path: $message" >&2
  return 1
}

validate_trusted_directory() {
  local label="$1"
  local path="$2"
  local type=""
  local uid=""
  local mode=""
  if [[ -L "$path" ]]; then
    trusted_path_error "$label" "symbolic-link directory component $path"
    return
  fi
  type="$(stat -c '%F' -- "$path" 2>/dev/null || true)"
  uid="$(stat -c '%u' -- "$path" 2>/dev/null || true)"
  mode="$(stat -c '%a' -- "$path" 2>/dev/null || true)"
  if [[ "$type" != "directory" || "$uid" != "$trusted_env_uid" ]]; then
    trusted_path_error "$label" "directory components must be root-owned directories: $path"
    return
  fi
  if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 0022) != 0 )); then
    trusted_path_error "$label" "directory components must not be group/world writable: $path"
    return
  fi
}

validate_trusted_directory_path() {
  local label="$1"
  local path="$2"
  local allow_absent="${3:-0}"
  local relative=""
  local current="$trusted_env_root"
  local component=""
  local IFS=/
  local -a components=()

  if [[ "$trusted_env_root" == "/" ]]; then
    [[ "$path" == /* ]] || { trusted_path_error "$label" "path is outside the trusted root"; return; }
  elif [[ "$path" != "$trusted_env_root" && "$path" != "$trusted_env_root"/* ]]; then
    trusted_path_error "$label" "path is outside the trusted root"
    return
  fi
  validate_trusted_directory "$label" "$trusted_env_root" || return
  relative="${path#"$trusted_env_root"}"
  read -r -a components <<< "${relative#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current="${current%/}/$component"
    if [[ ! -e "$current" && ! -L "$current" ]]; then
      [[ "$allow_absent" == 1 ]] || { trusted_path_error "$label" "directory is absent: $current"; return; }
      return
    fi
    validate_trusted_directory "$label" "$current" || return
  done
}

validate_trusted_parent_directory_path() {
  local label="$1"
  local path="$2"
  local allow_absent="${3:-0}"
  local parent="${path%/*}"
  [[ -n "$parent" ]] || parent="/"
  validate_trusted_directory_path "$label" "$parent" "$allow_absent"
}

validate_trusted_env_path() {
  local path="$1"
  local allow_absent="${2:-0}"
  local parent="${path%/*}"
  local type=""
  local uid=""
  local gid=""
  local mode=""

  validate_trusted_directory_path "--env-file" "$parent" 1 || return
  if [[ -L "$path" ]]; then
    env_trust_error "environment file must not be a symbolic link: $path"
    return
  fi
  if [[ ! -e "$path" ]]; then
    [[ "$allow_absent" == 1 ]] || env_trust_error "environment file is absent: $path"
    return
  fi
  type="$(stat -c '%F' -- "$path" 2>/dev/null || true)"
  uid="$(stat -c '%u' -- "$path" 2>/dev/null || true)"
  gid="$(stat -c '%g' -- "$path" 2>/dev/null || true)"
  mode="$(stat -c '%a' -- "$path" 2>/dev/null || true)"
  if [[ "$type" != "regular file" || "$uid" != "$trusted_env_uid" || "$gid" != "$trusted_env_gid" ]]; then
    env_trust_error "environment file must be a root:root regular file: $path"
    return
  fi
  if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 0137) != 0 )); then
    env_trust_error "environment file mode must be 0600 or compatible root:root 0640: $path"
    return
  fi
}
