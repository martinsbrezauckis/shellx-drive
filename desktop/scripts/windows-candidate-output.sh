#!/bin/bash
# Handle-bound candidate-output claim and publication for the Windows builder.
# The caller supplies pinned tool variables from windows-release-toolchain.sh.
candidate_output_init() {
  output_dir_fd=""
  output_dir_fd_path=""
  output_dir_identity=""
  output_dir_claimed=0
  output_dir_is_windows=0
  output_temporary=""
  output_published_leaves=()
}
close_candidate_output_fd() {
  if [[ -n "$output_dir_fd" ]]; then
    exec {output_dir_fd}<&-
    output_dir_fd=""
    output_dir_fd_path=""
  fi
}
cleanup_candidate_output() {
  local leaf=""
  if [[ -n "$output_temporary" ]]; then
    "$RM_BIN" -f -- "$output_temporary" 2>/dev/null || true
    output_temporary=""
  fi
  if [[ "$output_dir_claimed" == "1" && -n "$output_dir_fd_path" ]]; then
    for leaf in "${output_published_leaves[@]}"; do
      "$RM_BIN" -f -- "$output_dir_fd_path/$leaf" 2>/dev/null || true
    done
  fi
  close_candidate_output_fd
  if [[ "$output_dir_claimed" == "1" && -n "$output_dir" \
    && -d "$output_dir" && ! -L "$output_dir" \
    && "$("$STAT_BIN" -Lc '%d:%i' -- "$output_dir" 2>/dev/null || true)" == "$output_dir_identity" ]]; then
    "$RMDIR_BIN" -- "$output_dir" 2>/dev/null || true
  fi
}
validate_candidate_output_path() {
  local path="$1"
  if [[ "$path" != /* || "$path" == "/" || "$path" =~ [[:cntrl:]] \
    || "$path" == *"//"* || "$path" == *"/./"* || "$path" == *"/../"* \
    || "$path" == */. || "$path" == */.. || "$path" == */ ]]; then
    echo "FAIL: candidate output must be a normalized absolute path" >&2
    return 1
  fi
}
reject_output_link_components() {
  local path="$1" component="" current="" IFS=/
  local -a components=()
  read -r -a components <<< "${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current="$current/$component"
    if [[ -L "$current" ]]; then
      echo "FAIL: candidate output traverses a symbolic link: $current" >&2
      return 1
    fi
  done
}
check_unsigned_output_parent_components() {
  local path="$1" component="" current="" owner mode kind numeric
  local -a components=()
  IFS=/ read -r -a components <<< "${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current="$current/$component"
    read -r owner mode kind < <("$STAT_BIN" -c '%u %a %F' -- "$current")
    numeric=$((8#$mode))
    if [[ "$kind" != "directory" \
      || ( "$owner" != "0" && "$owner" != "$("$ID_BIN" -u)" && "$owner" != "65534" ) ]] \
      || (( (numeric & 8#022) != 0 )); then
      echo "FAIL: candidate output parent is writable or owned by an untrusted user: $current" >&2
      return 1
    fi
  done
}
claim_candidate_output_directory() {
  local parent leaf owner mode kind
  validate_candidate_output_path "$output_dir" || return 1
  parent="$("$DIRNAME_BIN" -- "$output_dir")"
  leaf="$("$BASENAME_BIN" -- "$output_dir")"
  if [[ ! "$leaf" =~ ^[^/]+$ ]]; then
    echo "FAIL: candidate output leaf is invalid" >&2
    return 1
  fi
  case "$output_dir" in
    /mnt/[A-Za-z]/*)
      output_dir_is_windows=1
      if [[ -L "$release_security_helper" || ! -f "$release_security_helper" ]]; then
        echo "FAIL: Windows release security helper is missing or unsafe" >&2
        return 1
      fi
      if [[ "$signing_required" == "1" ]]; then
        release_helper_verify_windows_stage || return 1
        release_tool_verify_all || return 1
      fi
      "$POWERSHELL_BIN" -NoProfile -NonInteractive -WindowStyle Hidden \
        -File "$("$WSLPATH_BIN" -w "$release_security_helper")" \
        -ClaimPrivateDirectoryPath "$("$WSLPATH_BIN" -w "$output_dir")" || return 1
      ;;
    *)
      "$MKDIR_BIN" -p -m 0700 -- "$parent"
      reject_output_link_components "$parent" || return 1
      if [[ "$signing_required" == "1" ]]; then
        release_tool_check_component "$parent" || return 1
        release_tool_check_parents "$parent" || return 1
      else
        check_unsigned_output_parent_components "$parent" || return 1
      fi
      if ! "$MKDIR_BIN" -m 0700 -- "$output_dir"; then
        echo "FAIL: candidate output directory could not be claimed exclusively: $output_dir" >&2
        return 1
      fi
      read -r owner mode kind < <("$STAT_BIN" -c '%u %a %F' -- "$output_dir")
      if [[ "$owner" != "$("$ID_BIN" -u)" || "$mode" != "700" || "$kind" != "directory" ]]; then
        echo "FAIL: candidate output directory is not private to the current user" >&2
        return 1
      fi
      ;;
  esac
  if [[ -L "$output_dir" || ! -d "$output_dir" ]]; then
    echo "FAIL: claimed candidate output is not a real directory" >&2
    return 1
  fi
  if ! exec {output_dir_fd}<"$output_dir"; then
    echo "FAIL: claimed candidate output could not be opened" >&2
    return 1
  fi
  output_dir_fd_path="/proc/self/fd/$output_dir_fd"
  if [[ ! -e "$output_dir_fd_path" ]]; then
    echo "FAIL: candidate publication requires Linux /proc file descriptors" >&2
    return 1
  fi
  output_dir_identity="$("$STAT_BIN" -Lc '%d:%i' -- "$output_dir_fd_path")"
  if [[ "$("$STAT_BIN" -Lc '%d:%i' -- "$output_dir")" != "$output_dir_identity" ]]; then
    echo "FAIL: candidate output changed while it was being opened" >&2
    return 1
  fi
  output_dir_claimed=1
}
verify_candidate_output_identity() {
  if [[ -z "$output_dir_fd_path" \
    || "$("$STAT_BIN" -Lc '%d:%i' -- "$output_dir" 2>/dev/null || true)" != "$output_dir_identity" \
    || "$("$STAT_BIN" -Lc '%F' -- "$output_dir_fd_path" 2>/dev/null || true)" != "directory" ]]; then
    echo "FAIL: candidate output directory identity drifted" >&2
    return 1
  fi
}
publish_candidate_artifact() {
  local source="$1" leaf="$2" result_variable="$3"
  local expected_sha256="${4:-}" staged_sha256 destination destination_type path_identity fd_identity published_fd reopened_sha256
  if [[ ! -f "$source" || -L "$source" || "$leaf" == */* || -z "$leaf" ]]; then
    echo "FAIL: candidate publication source must be a regular non-link file" >&2
    return 1
  fi
  verify_candidate_output_identity || return 1
  if [[ -z "$expected_sha256" ]]; then
    expected_sha256="$("$SHA256SUM_BIN" -- "$source")"
    expected_sha256="${expected_sha256%% *}"
  elif [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "FAIL: candidate publication expected SHA-256 is invalid: $leaf" >&2
    return 1
  fi
  output_temporary="$("$MKTEMP_BIN" "$output_dir_fd_path/.${leaf}.XXXXXX")"
  "$CP_BIN" --no-dereference -- "$source" "$output_temporary"
  "$CHMOD_BIN" 0600 "$output_temporary"
  staged_sha256="$("$SHA256SUM_BIN" -- "$output_temporary")"
  staged_sha256="${staged_sha256%% *}"
  if [[ "$staged_sha256" != "$expected_sha256" ]]; then
    echo "FAIL: staged candidate artifact hash mismatch: $leaf" >&2
    return 1
  fi
  destination="$output_dir_fd_path/$leaf"
  if [[ -e "$destination" || -L "$destination" ]]; then
    echo "FAIL: candidate output appeared concurrently: $leaf" >&2
    return 1
  fi
  "$MV_BIN" -nT -- "$output_temporary" "$destination"
  if [[ -e "$output_temporary" ]]; then
    echo "FAIL: candidate output could not be published without replacement: $leaf" >&2
    return 1
  fi
  output_temporary=""
  output_published_leaves+=("$leaf")
  destination_type="$("$STAT_BIN" -c '%F' -- "$destination" 2>/dev/null || true)"
  if [[ "$destination_type" != "regular file" ]]; then
    echo "FAIL: published candidate artifact is not a regular non-link file: $leaf" >&2
    return 1
  fi
  if ! exec {published_fd}<"$destination"; then
    echo "FAIL: published candidate artifact could not be reopened: $leaf" >&2
    return 1
  fi
  path_identity="$("$STAT_BIN" -Lc '%d:%i' -- "$destination")"
  fd_identity="$("$STAT_BIN" -Lc '%d:%i' -- "/proc/self/fd/$published_fd")"
  if [[ "$path_identity" != "$fd_identity" ]]; then
    exec {published_fd}<&-
    echo "FAIL: published candidate artifact changed while it was reopened: $leaf" >&2
    return 1
  fi
  reopened_sha256="$("$SHA256SUM_BIN" -- "/proc/self/fd/$published_fd")"
  reopened_sha256="${reopened_sha256%% *}"
  exec {published_fd}<&-
  if [[ "$reopened_sha256" != "$expected_sha256" ]]; then
    echo "FAIL: published candidate artifact hash mismatch: $leaf" >&2
    return 1
  fi
  verify_candidate_output_identity || return 1
  printf -v "$result_variable" '%s' "$reopened_sha256"
}
verify_candidate_output_privacy() {
  local output_owner output_mode output_kind
  verify_candidate_output_identity || return 1
  if [[ "$output_dir_is_windows" == "1" ]]; then
    if [[ "$signing_required" == "1" ]]; then
      release_tool_verify_all || return 1
    fi
    "$POWERSHELL_BIN" -NoProfile -NonInteractive -WindowStyle Hidden \
      -File "$("$WSLPATH_BIN" -w "$release_security_helper")" \
      -VerifyPrivateDirectoryPath "$("$WSLPATH_BIN" -w "$output_dir")"
  else
    read -r output_owner output_mode output_kind < <("$STAT_BIN" -c '%u %a %F' -- "$output_dir")
    if [[ "$output_owner" != "$("$ID_BIN" -u)" || "$output_mode" != "700" || "$output_kind" != "directory" ]]; then
      echo "FAIL: candidate output directory privacy drifted before success" >&2
      return 1
    fi
  fi
}
finalize_candidate_output() {
  verify_candidate_output_privacy || return 1
  output_dir_claimed=0
  close_candidate_output_fd
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from build-windows-nsis-from-wsl.sh" >&2
  exit 2
fi
