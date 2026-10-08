#!/bin/bash
# Bind callback diagnostics to the exact build target without weakening stderr.
release_callback_log_start_early() {
  RELEASE_CALLBACK_LOG_PATH="${SHELLX_DRIVE_RELEASE_CALLBACK_LOG:-}"
  if [[ -z "$RELEASE_CALLBACK_LOG_PATH" ]]; then
    echo "Windows signing callback log path is missing" >&2
    return 1
  fi
  if [[ -L "$RELEASE_CALLBACK_LOG_PATH" || ! -f "$RELEASE_CALLBACK_LOG_PATH" ]]; then
    echo "Windows signing callback log is missing or linked" >&2
    return 1
  fi
  exec 2>> "$RELEASE_CALLBACK_LOG_PATH"
  echo "WINDOWS_SIGNING_CALLBACK_START artifact=$1" >&2
}

release_callback_log_assert() {
  local path="$1" artifact_root="$2" identity
  if [[ "$path" != "$RELEASE_CALLBACK_LOG_PATH" \
    || "$path" != "$artifact_root/windows-signing-callback.log" \
    || -L "$path" || ! -f "$path" ]]; then
    echo "Windows signing callback log identity is invalid" >&2
    return 1
  fi
  identity="$("$STAT_BIN" -c '%u:%a:%F' -- "$path")"
  if [[ "$identity" != "$("$ID_BIN" -u):600:regular file" ]]; then
    echo "Windows signing callback log is not private" >&2
    return 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-artifact-sign-command.sh" >&2
  exit 2
fi
