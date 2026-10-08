#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
  cat <<'USAGE'
Usage:
  scripts/curl_secret_config.sh --bearer-stdin
  scripts/curl_secret_config.sh --bearer-file <private-file>
  scripts/curl_secret_config.sh --share-password-stdin
  scripts/curl_secret_config.sh --share-password-file <private-file>

Reads one secret only from standard input or a current-user private regular file.
Prints the path of a newly created mode-0600 curl config/header file to stdout.
The caller owns cleanup, for example: trap 'rm -f -- "$CURL_CONFIG"' EXIT
USAGE
}

kind=""
input=""
secret_file=""

case "${1:-}" in
  --bearer-stdin)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    kind="bearer"
    input="stdin"
    ;;
  --bearer-file)
    [[ $# -eq 2 ]] || { usage >&2; exit 2; }
    kind="bearer"
    input="file"
    secret_file="$2"
    ;;
  --share-password-stdin)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    kind="share-password"
    input="stdin"
    ;;
  --share-password-file)
    [[ $# -eq 2 ]] || { usage >&2; exit 2; }
    kind="share-password"
    input="file"
    secret_file="$2"
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [[ "$input" == "file" ]]; then
  if [[ -L "$secret_file" || ! -f "$secret_file" ]]; then
    echo "secret file must be a regular file, not a link or special file" >&2
    exit 1
  fi
  if ! exec {secret_fd}<"$secret_file"; then
    echo "secret file could not be opened" >&2
    exit 1
  fi
  secret_fd_path="/proc/self/fd/$secret_fd"
  if [[ ! -e "$secret_fd_path" ]]; then
    echo "secret helper requires Linux /proc file descriptors" >&2
    exit 1
  fi
  file_type="$(stat -Lc '%F' -- "$secret_fd_path")"
  owner="$(stat -Lc '%u' -- "$secret_fd_path")"
  mode="$(stat -Lc '%a' -- "$secret_fd_path")"
  path_identity="$(stat -Lc '%d:%i' -- "$secret_file" 2>/dev/null || true)"
  fd_identity="$(stat -Lc '%d:%i' -- "$secret_fd_path")"
  if [[ "$file_type" != "regular file" || -z "$path_identity" || "$path_identity" != "$fd_identity" ]]; then
    echo "secret file changed while it was being opened" >&2
    exit 1
  fi
  if [[ "$owner" != "$(id -u)" || ! "$mode" =~ ^[0-7]{3,4}$ || $((8#$mode & 8#077)) -ne 0 ]]; then
    echo "secret file must be owned by the current user and private to that user" >&2
    exit 1
  fi
  secret="$(cat -- "$secret_fd_path"; printf x)"
  exec {secret_fd}<&-
else
  secret="$(cat; printf x)"
fi
secret="${secret%x}"

if [[ "$secret" == *$'\r'* || "$secret" == *$'\n'* ]]; then
  echo "secret contains forbidden CR or LF characters" >&2
  exit 1
fi
if [[ "$kind" == "bearer" && -z "$secret" ]]; then
  echo "bearer secret must not be empty" >&2
  exit 1
fi

umask 077
output="$(mktemp "${TMPDIR:-/tmp}/shellx-drive-curl-secret.XXXXXXXX")"
cleanup() {
  rm -f -- "$output"
}
trap cleanup EXIT
chmod 0600 -- "$output"

case "$kind" in
  bearer)
    escaped_secret="$(printf '%s' "$secret" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
    printf 'header = "Authorization: Bearer %s"\n' "$escaped_secret" >"$output"
    ;;
  share-password)
    printf 'X-Share-Password: %s\n' "$secret" >"$output"
    ;;
esac

trap - EXIT
printf '%s\n' "$output"
