#!/bin/bash
# Compile the frozen public source without invoking signing or bundling.
set -euo pipefail
umask 077
[[ "$#" == 3 && "$2" =~ ^[0-9a-f]{40}$ ]] || { echo 'usage: windows-standard-build.sh SOURCE COMMIT OUT' >&2; exit 2; }
source_root="$(cd -- "$1" && pwd -P)"; revision="$2"; out="$(cd -- "$3" && pwd -P)"
for name in $(compgen -e); do
  case "$name" in TAURI_SIGNING_*|AZURE_*|CSC_*|SIGNTOOL_*|SHELLX_WINDOWS_*|SHELLX_DRIVE_RELEASE_*) unset "$name" ;; esac
done
checkpoint() {
  [[ "$(git -C "$source_root" rev-parse HEAD)" == "$revision" && -z "$(git -C "$source_root" status --porcelain --untracked-files=all)" ]] \
    || { echo 'FAIL: frozen public source changed' >&2; return 1; }
}
checkpoint
workspace="$out/workspace"
mkdir -m 0700 -- "$workspace"
manifest="$out/.source-tree-manifest.z"
trap 'rm -rf -- "$workspace"; rm -f -- "$manifest"' EXIT
(set -o noclobber; git -C "$source_root" ls-tree -r -z --full-tree "$revision" > "$manifest")
chmod 0400 -- "$manifest"; manifest_sha="$(sha256sum -- "$manifest")"
workspace_checkpoint() {
  [[ -f "$manifest" && ! -L "$manifest" && "$(sha256sum -- "$manifest")" == "$manifest_sha" ]] || return 1
  local entry header relative mode type object
  while IFS= read -r -d '' entry; do
    header="${entry%%$'\t'*}"; relative="${entry#*$'\t'}"; read -r mode type object <<< "$header"
    [[ "$mode" =~ ^100(644|755)$ && "$type" == blob && "$object" =~ ^[0-9a-f]{40}$ ]] || { echo 'FAIL: non-regular tracked build input' >&2; return 1; }
    [[ "${1:-}" == validate ]] && continue
    [[ -f "$workspace/$relative" && ! -L "$workspace/$relative" && "$(readlink -f -- "$workspace/$relative")" == "$workspace/$relative" \
      && "$(git hash-object --no-filters -- "$workspace/$relative")" == "$object" ]] || { echo 'FAIL: tracked build input changed' >&2; return 1; }
  done < "$manifest"
}
workspace_checkpoint validate
git -C "$source_root" archive --format=tar "$revision" | tar -xf - -C "$workspace"
workspace_checkpoint
desktop="$workspace/desktop"
cd -- "$desktop"
pnpm_path="$(readlink -f -- "$(command -v pnpm)")"
[[ -f "$pnpm_path" && ! -L "$pnpm_path" && -x "$pnpm_path" ]] || { echo 'FAIL: physical pnpm executable required' >&2; exit 1; }
pnpm_run() {
  local prefix
  IFS= read -r -N 4 prefix < "$pnpm_path" || return 1
  if [[ "$prefix" == $'\177ELF' ]]; then "$pnpm_path" "$@";
  else node "$pnpm_path" "$@"; fi
}
pnpm_run install --frozen-lockfile --force --verify-store-integrity --ignore-scripts
pnpm_run store status
pnpm_run rebuild
checkpoint; workspace_checkpoint
# Reuse the ordinary build cache; only the completed binary enters the result.
export CARGO_TARGET_DIR="${SHELLX_DRIVE_WINDOWS_CARGO_TARGET_DIR:-$HOME/shellx-drive/.scratch/build/windows-cargo-target}"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$HOME=/shellx/build"$'\x1f'"--remap-path-prefix=$CARGO_TARGET_DIR=/shellx/drive/target"
config='{"bundle":{"createUpdaterArtifacts":false,"windows":{"signCommand":null}}}'
node "$desktop/node_modules/@tauri-apps/cli/tauri.js" build \
  --runner "$(command -v cargo-xwin)" --target x86_64-pc-windows-msvc \
  --features desktop-shell --ci --no-bundle --no-sign --config "$config" -- --locked --offline
checkpoint; workspace_checkpoint
mkdir -m 0700 -- "$out/raw"
raw="$CARGO_TARGET_DIR/x86_64-pc-windows-msvc/release/shellx-drive-desktop.exe"
[[ -f "$raw" && ! -L "$raw" ]] || { echo 'FAIL: unsigned Windows binary missing' >&2; exit 1; }
cp --no-dereference -- "$raw" "$out/raw/shellx-drive-desktop.exe"
chmod 0600 -- "$out/raw/shellx-drive-desktop.exe"
node "$desktop/scripts/verify-windows-gui-subsystem.mjs" --source "$desktop/src-tauri/src/main.rs" --exe "$out/raw/shellx-drive-desktop.exe"
node - "$out/raw/shellx-drive-desktop.exe" "$HOME" "$source_root" "$workspace" "$CARGO_TARGET_DIR" <<'NODE'
const bytes = require('node:fs').readFileSync(process.argv[2]);
for (const path of process.argv.slice(3)) {
  if (path.length > 1 && ['utf8','utf16le'].some(encoding => bytes.includes(Buffer.from(path,encoding)))) {
    process.stderr.write('FAIL: raw Windows binary contains a private build path\n'); process.exit(1);
  }
}
NODE
