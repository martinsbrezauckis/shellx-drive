#!/usr/bin/env bash
# macOS raw-Mach-O builder. The controller admits an external builder-isolation
# receipt before opening this held descriptor; this signing-excluded environment
# alone is not an isolation boundary. FD 3 holds the immutable unsigned-build
# admission, FD 104 the immutable Tauri config, and FD 107 the immutable
# handoff writer.
set -euo pipefail
umask 077

fail() { printf 'FAIL: macOS unsigned build: %s\n' "$*" >&2; exit 1; }
usage() { printf '%s\n' 'Usage: macos-unsigned-build.sh --admission /dev/fd/3 --out <fresh-absolute-directory>'; }

for unsafe in BASH_ENV ENV PYTHONHOME PYTHONPATH LD_PRELOAD LD_LIBRARY_PATH \
  TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD \
  APPLE_ID APPLE_APP_SPECIFIC_PASSWORD APPLE_TEAM_ID NOTARY_PROFILE \
  CSC_LINK CSC_KEY_PASSWORD; do
  [[ -z "${!unsafe:-}" ]] || fail "credential or unsafe ambient environment: $unsafe"
done
while IFS= read -r variable; do
  [[ "$variable" != DYLD_* && "$variable" != APPLE_* && "$variable" != NOTARY_* && "$variable" != DEVELOPER_ID_* ]] || fail "credential or unsafe ambient environment: $variable"
done < <(compgen -v)

[[ "${BASH_SOURCE[0]}" == /dev/fd/4 ]] || fail "worker descriptor was not externally admitted"
[[ "${PATH:-}" == /* && "${HOME:-}" == /* && "${LANG:-}" == C && "${LC_ALL:-}" == C && "${TZ:-}" == UTC ]] || fail "controller did not provide the signing-excluded build environment"
[[ -n "${SHELLX_DRIVE_ADMITTED_STAGE_ROOT:-}" && "$SHELLX_DRIVE_ADMITTED_STAGE_ROOT" == /* ]] || fail "admitted stage root is absent"
if [[ $# -eq 3 && "$1" == --admission-stdin && "$2" == --out && "$3" == /* ]]; then
  exec 3<&0
  out="$3"
elif [[ $# -eq 4 && "$1" == --admission && "$2" == /dev/fd/3 && "$3" == --out && "$4" == /* ]]; then
  out="$4"
else
  usage >&2; exit 2
fi
[[ -r /dev/fd/3 && -r /dev/fd/104 && -r /dev/fd/107 ]] || fail "controller did not retain the admission, config, and writer descriptors"
[[ "${SHELLX_DRIVE_ADMITTED_NODE:-}" == /* && "${SHELLX_DRIVE_ADMITTED_TAURI:-}" == /* ]] || fail "controller did not provide admitted native build tools"

target_dir="${out}.cargo-target"
[[ ! -e "$out" && ! -e "$target_dir" ]] || fail "handoff output and its sibling target directory must both be fresh"
mkdir "$target_dir"
chmod 700 "$target_dir"
workspace="$target_dir/workspace"
"$SHELLX_DRIVE_ADMITTED_NODE" --input-type=module --eval 'import {cpSync,lstatSync} from "node:fs"; const [source,destination]=process.argv.slice(-2); const sourceStat=lstatSync(source); if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) throw new Error("protected desktop source is not a physical directory"); try { lstatSync(destination); throw new Error("private desktop workspace already exists"); } catch (error) { if (error?.code !== "ENOENT") throw error; } cpSync(source,destination,{dereference:false,errorOnExist:true,force:false,preserveTimestamps:false,recursive:true,verbatimSymlinks:true}); const copied=lstatSync(destination); if (!copied.isDirectory() || copied.isSymbolicLink()) throw new Error("private desktop workspace was not created as a physical directory");' -- "$SHELLX_DRIVE_ADMITTED_STAGE_ROOT/desktop" "$workspace"
config_path="$target_dir/tauri.conf.json"
"$SHELLX_DRIVE_ADMITTED_NODE" --input-type=module --eval 'import {readFileSync,writeFileSync} from "node:fs"; writeFileSync(process.argv[1],readFileSync("/dev/fd/104"),{flag:"wx",mode:0o600})' -- "$config_path"
chmod 600 "$config_path"
export CARGO_TARGET_DIR="$target_dir"
cd "$workspace"
"$SHELLX_DRIVE_ADMITTED_TAURI" build --config "$config_path" --target aarch64-apple-darwin --features desktop-shell --no-bundle
raw="$CARGO_TARGET_DIR/aarch64-apple-darwin/release/shellx-drive-desktop"
[[ -f "$raw" && ! -L "$raw" ]] || fail "Tauri did not produce exactly the raw arm64 Mach-O application"
"$SHELLX_DRIVE_ADMITTED_NODE" --input-type=module --eval 'import {readFileSync} from "node:fs"; const source=readFileSync("/dev/fd/107"); process.argv.splice(1,0,"/dev/fd/107"); await import(`data:text/javascript;base64,${source.toString("base64")}`)' -- \
  --admission /dev/fd/3 --raw "$raw" --out "$out" \
  --tauri-config "$config_path" \
  --package-cargo-manifest "$SHELLX_DRIVE_ADMITTED_STAGE_ROOT/desktop/src-tauri/Cargo.toml" \
  --workspace-cargo-manifest "$SHELLX_DRIVE_ADMITTED_STAGE_ROOT/desktop/Cargo.toml"
printf 'MACOS_UNSIGNED_BUILD_COMPLETE status=pass\n'
