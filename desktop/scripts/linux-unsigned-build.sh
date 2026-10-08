#!/usr/bin/env bash
# Linux raw-ELF builder. The controller admits an external builder-isolation
# receipt before opening this descriptor; the worker receives neither signing
# material nor package/update authority. FD 3 is the immutable unsigned-build
# admission, FD 111 the Linux Tauri config, and FD 115 the handoff writer.
set -euo pipefail
umask 077

fail() { printf 'FAIL: Linux unsigned build: %s\n' "$*" >&2; exit 1; }
usage() { printf '%s\n' 'Usage: linux-unsigned-build.sh --admission /dev/fd/3 --out <fresh-absolute-directory>'; }

for unsafe in BASH_ENV ENV NODE_OPTIONS PYTHONHOME PYTHONPATH LD_PRELOAD LD_LIBRARY_PATH \
  RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_TARGET_DIR \
  GNUPGHOME GPG_AGENT_INFO SSH_AUTH_SOCK \
  TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD \
  TAURI_PRIVATE_KEY TAURI_PRIVATE_KEY_PASSWORD CSC_LINK CSC_KEY_PASSWORD; do
  [[ -z "${!unsafe:-}" ]] || fail "credential or unsafe ambient environment: $unsafe"
done
while IFS= read -r variable; do
  case "$variable" in
    LD_*|DYLD_*|TAURI_SIGNING_*|TAURI_PRIVATE_*|CSC_*|GPG_*|GNUPG*|NOTARY_*|APPLE_*|DEVELOPER_ID_*)
      fail "credential or unsafe ambient environment: $variable" ;;
  esac
done < <(compgen -v)

[[ "${BASH_SOURCE[0]}" == /dev/fd/4 ]] || fail "worker descriptor was not externally admitted"
[[ "${PATH:-}" == /* && "${PATH:-}" != *:* && "${HOME:-}" == /* && "${LANG:-}" == C && "${LC_ALL:-}" == C && "${TZ:-}" == UTC ]] \
  || fail "controller did not provide the signing-excluded build environment"
[[ "${CARGO_HOME:-}" == /* && "${RUSTUP_HOME:-}" == /* && "${TMPDIR:-}" == /* ]] \
  || fail "controller did not provide immutable Cargo/Rustup build roots"
[[ -n "${SHELLX_DRIVE_ADMITTED_STAGE_ROOT:-}" && "$SHELLX_DRIVE_ADMITTED_STAGE_ROOT" == /* ]] \
  || fail "admitted stage root is absent"
if [[ $# -ne 4 || "$1" != --admission || "$2" != /dev/fd/3 || "$3" != --out || "$4" != /* ]]; then
  usage >&2
  exit 2
fi
out="$4"
[[ "$out" != / ]] || fail "handoff output path is not normalized"
case "$out" in
  /|*/|*/.|*/..|*//*|*/./*|*/../*) fail "handoff output path is not normalized" ;;
esac
[[ -r /dev/fd/3 && -r /dev/fd/111 && -r /dev/fd/115 ]] \
  || fail "controller did not retain the admission, Linux config, and writer descriptors"

target_dir="${out}.cargo-target"
[[ ! -e "$out" && ! -L "$out" && ! -e "$target_dir" && ! -L "$target_dir" ]] \
  || fail "handoff output and its sibling target directory must both be fresh"
cd "$SHELLX_DRIVE_ADMITTED_STAGE_ROOT/desktop"
mkdir "$target_dir"
chmod 700 "$target_dir"
config_path="$target_dir/tauri.linux.conf.json"
# The held config is JSON (therefore contains no NUL).  Keep this copy inside
# Bash so the raw plan needs no ambient `cat` binary beyond its sealed tool set.
config_contents=""
if IFS= read -r -d '' config_contents < /dev/fd/111; then
  fail "Tauri config contains a NUL byte"
fi
printf '%s' "$config_contents" > "$config_path"
chmod 600 "$config_path"
export CARGO_TARGET_DIR="$target_dir"
tauri build --config "$config_path" --features desktop-shell --no-bundle
raw="$CARGO_TARGET_DIR/release/shellx-drive-desktop"
[[ -f "$raw" && ! -L "$raw" ]] || fail "Tauri did not produce exactly the raw Linux desktop executable"
IFS= read -r -N 4 magic < "$raw" || fail "Tauri raw desktop executable is too short"
[[ "$magic" == $'\x7fELF' ]] || fail "Tauri raw desktop executable is not ELF"
mkdir "$out"
chmod 700 "$out"
mkdir "$out/payload"
chmod 700 "$out/payload"
install -m 0755 "$raw" "$out/payload/shellx-drive-desktop"
node /dev/fd/115 --admission /dev/fd/3 --out "$out"
printf 'LINUX_UNSIGNED_BUILD_COMPLETE status=pass\n'
