#!/usr/bin/env bash
# Shared fail-closed primitives for native Linux release helpers. These tools
# deliberately do not locate credentials or keys; an approved native operator
# supplies only the maintained logical key references and signer identities.
set -euo pipefail

linux_release_fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

linux_release_require_regular() {
  local value="$1" label="$2"
  [[ -n "$value" && ! -L "$value" && -f "$value" ]] \
    || linux_release_fail "$label must be a regular non-symlink file"
}

linux_release_require_signing_authority() {
  [[ "${SHELLX_DRIVE_LINUX_RELEASE_KEY_REF:-}" == "release-studio:shellx-drive/linux-release-key/v1" ]] \
    || linux_release_fail "SHELLX_DRIVE_LINUX_RELEASE_KEY_REF must name the maintained Linux release key"
  [[ "${SHELLX_DRIVE_TAURI_UPDATER_KEY_REF:-}" == "release-studio:shellx-drive/tauri-updater-key/v1" ]] \
    || linux_release_fail "SHELLX_DRIVE_TAURI_UPDATER_KEY_REF must name the maintained Tauri updater key"
  [[ "${SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT:-}" =~ ^[A-F0-9]{40}$ ]] \
    || linux_release_fail "SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT must be a full uppercase public fingerprint"
  [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]] \
    || linux_release_fail "TAURI_SIGNING_PRIVATE_KEY must be supplied by the approved updater-key authority"
}

linux_release_require_clean_output() {
  local output="$1"
  : "${TOOL_MKDIR:?controller must admit mkdir}"
  : "${TOOL_STAT:?controller must admit stat}"
  [[ "$output" == /* && ! -e "$output" && ! -L "$output" ]] \
    || linux_release_fail "candidate output must be a fresh absolute path"
  "$TOOL_MKDIR" -m 0700 -- "$output"
  [[ ! -L "$output" && "$("$TOOL_STAT" -c '%a' -- "$output")" == "700" ]] \
    || linux_release_fail "candidate output directory must be private and non-symlinked"
}

linux_release_require_linux_x86_64() {
  : "${TOOL_UNAME:?controller must admit uname}"
  [[ "$("$TOOL_UNAME" -s)" == "Linux" && "$("$TOOL_UNAME" -m)" == "x86_64" ]] \
    || linux_release_fail "native Linux x86_64 execution is required"
}

linux_release_private_copy() {
  local source="$1" destination="$2" identity
  : "${TOOL_STAT:?stat identity is required}" "${TOOL_INSTALL:?install identity is required}" "${TOOL_CMP:?cmp identity is required}"
  linux_release_require_regular "$source" "candidate input"
  exec {source_fd}<"$source"
  identity="$("$TOOL_STAT" -Lc '%d:%i:%s' -- "/proc/self/fd/$source_fd")"
  "$TOOL_INSTALL" -m 0600 -- "/proc/self/fd/$source_fd" "$destination"
  [[ "$("$TOOL_STAT" -Lc '%d:%i:%s' -- "$source")" == "$identity" ]] \
    || linux_release_fail "candidate input identity changed during private copy"
  "$TOOL_CMP" -s -- "/proc/self/fd/$source_fd" "$destination" \
    || linux_release_fail "candidate input bytes changed during private copy"
}

linux_release_run_dpkg_sig_staged() (
  local operation="$1" dpkg_sig_bin="$2" package="$3" fingerprint="${4:-}"
  local package_dir mode identity stage staged replacement="" result=0
  : "${TOOL_STAT:?}" "${TOOL_MKTEMP:?}" "${TOOL_CHMOD:?}" "${TOOL_INSTALL:?}" "${TOOL_RM:?}" "${TOOL_MV:?}" "${TOOL_CMP:?}"
  : "${LINUX_RELEASE_TEMP_ROOT:?controller-admitted generated state root is required}"
  [[ "$operation" == "sign" || "$operation" == "verify" ]] \
    || linux_release_fail "unsupported Debian signature operation"
  [[ "$dpkg_sig_bin" =~ ^/dev/fd/[0-9]+$ && -f "$dpkg_sig_bin" && -x "$dpkg_sig_bin" ]] \
    || linux_release_fail "dpkg-sig must remain an admitted executable descriptor"
  linux_release_require_regular "$package" "Debian package"
  package_dir="$(cd -- "${package%/*}" && pwd -P)"
  if [[ "$operation" == "sign" ]]; then
    [[ ! -L "$package_dir" && -d "$package_dir" ]] \
      || linux_release_fail "Debian signing directory must be a real directory"
    mode="$("$TOOL_STAT" -c '%a' -- "$package_dir")"
    [[ $((8#$mode & 077)) == 0 ]] \
      || linux_release_fail "Debian signing directory must be private"
    [[ "$fingerprint" =~ ^[A-F0-9]{40}$ ]] \
      || linux_release_fail "Debian signer fingerprint must be full uppercase hexadecimal"
  fi
  exec {package_fd}<"$package"
  identity="$("$TOOL_STAT" -Lc '%d:%i' -- "/proc/self/fd/$package_fd")"
  [[ "$("$TOOL_STAT" -Lc '%d:%i' -- "$package")" == "$identity" ]] \
    || linux_release_fail "Debian package identity changed before staging"
  stage="$("$TOOL_MKTEMP" -d "$LINUX_RELEASE_TEMP_ROOT/deb-sign.XXXXXX")"
  "$TOOL_CHMOD" 0700 -- "$stage"
  staged="$stage/candidate.deb"
  trap '[[ -z "$replacement" ]] || "$TOOL_RM" -f -- "$replacement"; "$TOOL_RM" -rf -- "$stage"' EXIT
  "$TOOL_INSTALL" -m 0600 -- "/proc/self/fd/$package_fd" "$staged"
  if [[ "$operation" == "verify" ]]; then
    "$dpkg_sig_bin" --verify "$staged" || result=$?
    [[ "$("$TOOL_STAT" -Lc '%d:%i' -- "$package")" == "$identity" ]] \
      || linux_release_fail "Debian package identity changed during verification"
    exit "$result"
  fi
  "$dpkg_sig_bin" --sign builder -k "$fingerprint" "$staged"
  linux_release_require_regular "$staged" "staged signed Debian package"
  [[ "$("$TOOL_STAT" -Lc '%d:%i' -- "$package")" == "$identity" ]] \
    || linux_release_fail "Debian package identity changed during signing"
  replacement="$("$TOOL_MKTEMP" "$package_dir/.shellx-drive-deb-signed.XXXXXX")"
  "$TOOL_INSTALL" -m 0600 -- "$staged" "$replacement"
  linux_release_require_regular "$replacement" "signed Debian replacement"
  "$TOOL_MV" -Tf -- "$replacement" "$package"
  replacement=""
  linux_release_require_regular "$package" "signed Debian package"
  "$TOOL_CMP" -s -- "$staged" "$package" \
    || linux_release_fail "signed Debian bytes changed during publication"
)

linux_release_sign_debian_package() {
  linux_release_run_dpkg_sig_staged sign "$1" "$2" "$3"
}

linux_release_verify_debian_package() {
  linux_release_run_dpkg_sig_staged verify "$1" "$2"
}

linux_release_require_exact_validsig() {
  local status="$1" expected="$2" label="$3" line
  local -a fields
  local total=0 matched=0 malformed=0 failed=0
  [[ "$expected" =~ ^[A-F0-9]{40,64}$ ]] \
    || linux_release_fail "$label signer identity drifted"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == "[GNUPG:] "* ]] || continue
    read -r -a fields <<<"$line"
    [[ ${fields[0]:-} == "[GNUPG:]" ]] || continue
    case ${fields[1]:-} in
      BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|FAILURE|NODATA|NO_PUBKEY|REVKEYSIG) failed=1 ;;
      VALIDSIG)
        (( total += 1 ))
        if (( ${#fields[@]} != 12 )) \
          || [[ ! ${fields[2]:-} =~ ^[A-F0-9]{40,64}$ ]] \
          || [[ ! ${fields[11]:-} =~ ^[A-F0-9]{40,64}$ ]]; then
          malformed=1
        elif [[ ${fields[11]} == "$expected" ]]; then
          (( matched += 1 ))
        fi
        ;;
    esac
  done <<<"$status"
  (( !failed && !malformed && total == 1 && matched == 1 )) \
    || linux_release_fail "$label signer identity drifted"
}
