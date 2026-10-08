#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: scripts/public_export.sh --out <export-dir>

Creates a release-safe ShellX Drive public export from the exact Git HEAD.
The exporter starts from an empty staging directory and copies only the
machine-readable paths in the frozen scripts/public_export_allowlist.txt.

The exporter never initializes or commits Git history. Commit the generated
public-export snapshot deliberately, after its release gates pass.
USAGE
}

out_dir=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      out_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --git)
      echo "--git is no longer supported: public export commits must be deliberate" >&2
      exit 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$out_dir" ]; then
  echo "--out is required" >&2
  usage >&2
  exit 2
fi

source_dir="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source_commit="$(git -C "$source_dir" rev-parse HEAD)"
exporter_script="$(readlink -f -- "${BASH_SOURCE[0]}")"
expected_exporter_script="$source_dir/scripts/public_export.sh"
if [[ "$exporter_script" != "$expected_exporter_script" ]] ||
   ! git -C "$source_dir" diff --quiet "$source_commit" -- scripts/public_export.sh; then
  echo "executing public exporter script does not match frozen source commit" >&2
  exit 1
fi

reject_link_components() {
  local candidate="$1"
  local current
  case "$candidate" in
    /*) current="$candidate" ;;
    *) current="$PWD/$candidate" ;;
  esac
  case "/$current/" in
    */../*)
      echo "refusing export destination containing a parent traversal: $candidate" >&2
      exit 2
      ;;
  esac
  while [[ "$current" != / && "$current" != . ]]; do
    if [ -L "$current" ]; then
      echo "refusing export destination with a symbolic-link component: $current" >&2
      exit 2
    fi
    current="$(dirname -- "$current")"
  done
}

require_private_directory() {
  local directory="$1"
  local label="$2"
  local owner mode
  owner="$(stat -Lc '%u' "$directory")"
  mode="$(stat -Lc '%a' "$directory")"
  if [[ "$owner" != "$EUID" ]]; then
    echo "$label must be owned by the invoking user: $directory" >&2
    exit 2
  fi
  if (( (8#$mode & 0022) != 0 )); then
    echo "$label must not be group- or other-writable: $directory" >&2
    exit 2
  fi
}

requested_out_dir="$out_dir"
reject_link_components "$requested_out_dir"
requested_parent="$(dirname -- "$requested_out_dir")"
if [ ! -d "$requested_parent" ]; then
  echo "export destination parent must already exist: $requested_parent" >&2
  exit 2
fi
reject_link_components "$requested_out_dir"
out_parent="$(cd -P "$requested_parent" && pwd -P)"
out_name="$(basename -- "$requested_out_dir")"
if [[ -z "$out_name" || "$out_name" == . || "$out_name" == .. ]]; then
  echo "refusing unsafe export destination name: $requested_out_dir" >&2
  exit 2
fi
if [ ! -d "/proc/$$/fd" ]; then
  echo "public export requires descriptor-pinned /proc filesystem support" >&2
  exit 1
fi
exec {out_parent_fd}<"$out_parent"
pinned_parent="/proc/$$/fd/$out_parent_fd"
if [[ "$(stat -Lc '%d:%i' "$out_parent")" != "$(stat -Lc '%d:%i' "$pinned_parent")" ]]; then
  echo "export destination parent changed during validation: $out_parent" >&2
  exit 2
fi
require_private_directory "$pinned_parent" "export destination parent"
pinned_parent_path="$(readlink -f -- "$pinned_parent")"
if [[ -z "$pinned_parent_path" ]] ||
   [[ "$(stat -Lc '%d:%i' "$pinned_parent")" != "$(stat -Lc '%d:%i' "$pinned_parent_path")" ]]; then
  echo "could not establish the export destination parent identity: $out_parent" >&2
  exit 2
fi
out_display="$pinned_parent_path/$out_name"
if [[ "$out_display" == / || "$out_display" == "$source_dir" ]]; then
  echo "refusing unsafe export destination: $out_display" >&2
  exit 2
fi
if [[ "$out_display" == "$source_dir"/* && "$out_display" != "$source_dir"/target/public-export-test/* ]]; then
  echo "refusing source-tree export destination outside target/public-export-test: $out_display" >&2
  exit 2
fi

frozen_input_dir="$(mktemp -d "$pinned_parent/.shellx-drive-export-input.XXXXXX")"
tmp_dir=""
cleanup() {
  if [ -n "$tmp_dir" ] && [ -d "$tmp_dir" ]; then
    rm -rf -- "$tmp_dir"
  fi
  if [ -d "$frozen_input_dir" ]; then
    rm -rf -- "$frozen_input_dir"
  fi
}
trap cleanup EXIT
require_private_directory "$frozen_input_dir" "frozen public export input staging"

allowlist="$frozen_input_dir/public_export_allowlist.txt"
allowlist_blob="$(git -C "$source_dir" rev-parse "$source_commit:scripts/public_export_allowlist.txt" 2>/dev/null || true)"
allowlist_type="$(git -C "$source_dir" cat-file -t "$allowlist_blob" 2>/dev/null || true)"
if [[ "$allowlist_type" != "blob" ]]; then
  echo "public export allowlist is not a regular file in $source_commit" >&2
  exit 1
fi
if ! git -C "$source_dir" show "$allowlist_blob" > "$allowlist"; then
  echo "could not materialize public export allowlist from $source_commit" >&2
  exit 1
fi

reject_private_development_path() {
  local path="$1"
  case "$path" in
    tests|tests/*|*.test.*|\
    package.json|package-lock.json|\
    .github/workflows/ci-private.yml|.github/workflows/release-candidate-private.yml|\
    scripts/*_check.mjs|scripts/test_orchestration*.mjs|scripts/test_runtime_policy.mjs|\
    scripts/source_size_guard.sh|scripts/e2e_local.sh|scripts/e2e_remote.sh|\
    scripts/drive_ui_smoke.mjs|scripts/drive_mobile_navigation_browser.mjs|\
    scripts/drive_mobile_navigation_diagnostics.mjs|scripts/drive_offline_reload_diagnostics.mjs|\
    scripts/drive_rclone_import_protocol.mjs|scripts/live_collaboration_environment.mjs|\
    scripts/private_stage_checked.mjs|scripts/private_stage_checked_windows.ps1|\
    scripts/private_secret_file.mjs|desktop/scripts/desktop-updater-service-contract.mjs|\
    desktop/scripts/windows-disconnect-contract-sources.mjs)
      echo "standalone development test or harness is private: $path" >&2
      exit 1
      ;;
  esac
}

declare -a public_paths=()
while IFS= read -r entry || [ -n "$entry" ]; do
  entry="${entry%%#*}"
  entry="${entry#"${entry%%[![:space:]]*}"}"
  entry="${entry%"${entry##*[![:space:]]}"}"
  [ -z "$entry" ] && continue
  case "$entry" in
    /*|*..*|*'//'*)
      echo "invalid public export path: $entry" >&2
      exit 1
      ;;
  esac
  reject_private_development_path "$entry"
  if ! git -C "$source_dir" cat-file -e "$source_commit:$entry"; then
    echo "allowlisted path is absent from $source_commit: $entry" >&2
    exit 1
  fi
  public_paths+=("$entry")
done < "$allowlist"

if [ "${#public_paths[@]}" -eq 0 ]; then
  echo "public export allowlist is empty" >&2
  exit 1
fi

out_dir="$pinned_parent/$out_name"
if [ -L "$out_dir" ] || { [ -e "$out_dir" ] && [ ! -d "$out_dir" ]; }; then
  echo "refusing linked or non-directory export destination: $out_display" >&2
  exit 2
fi
if [ ! -d "$out_dir" ]; then
  if ! mkdir -m 700 -- "$out_dir"; then
    echo "could not reserve export destination: $out_display" >&2
    exit 2
  fi
fi
require_private_directory "$out_dir" "existing export destination"
expected_out_identity="$(stat -Lc '%d:%i' "$out_dir")"
exec {out_fd}<"$out_dir"
pinned_out="/proc/$$/fd/$out_fd"
if [[ "$(stat -Lc '%d:%i' "$pinned_out")" != "$expected_out_identity" ]]; then
  echo "export destination changed before descriptor acquisition: $out_display" >&2
  exit 2
fi
require_private_directory "$pinned_out" "opened export destination"

preserve_git=0
if [ -e "$pinned_out/.git" ]; then
  if [ -L "$pinned_out/.git" ]; then
    echo "refusing export destination with linked Git metadata: $out_display" >&2
    exit 2
  fi
  git_root="$(git -C "$pinned_out" rev-parse --show-toplevel 2>/dev/null)" || {
    echo "existing export destination is not a valid Git worktree: $out_display" >&2
    exit 2
  }
  if [[ "$(stat -Lc '%d:%i' "$git_root")" != "$expected_out_identity" ]]; then
    echo "Git worktree root does not match export destination: $out_display" >&2
    exit 2
  fi
  preserve_git=1
fi

tmp_dir="$(mktemp -d "$pinned_parent/.shellx-drive-export.XXXXXX")"
require_private_directory "$tmp_dir" "public export staging"

git -C "$source_dir" archive --format=tar "$source_commit" -- "${public_paths[@]}" \
  | tar -C "$tmp_dir" -xf -

node - "$tmp_dir/desktop/package.json" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const filename = process.argv[2];
const metadata = JSON.parse(fs.readFileSync(filename, "utf8"));
const privateHelpers = new Set([
  "test_runtime_policy.mjs", "source_size_guard.sh", "e2e_local.sh", "e2e_remote.sh",
  "drive_ui_smoke.mjs", "drive_mobile_navigation_browser.mjs",
  "drive_mobile_navigation_diagnostics.mjs", "drive_offline_reload_diagnostics.mjs",
  "drive_rclone_import_protocol.mjs", "live_collaboration_environment.mjs",
  "private_stage_checked.mjs", "private_stage_checked_windows.ps1", "private_secret_file.mjs",
  "desktop-updater-service-contract.mjs", "windows-disconnect-contract-sources.mjs",
  "ci-private.yml", "release-candidate-private.yml",
]);
if (metadata.scripts !== undefined) {
  if (!metadata.scripts || typeof metadata.scripts !== "object" || Array.isArray(metadata.scripts)) {
    throw new Error("desktop build scripts must be an object");
  }
  for (const [name, command] of Object.entries(metadata.scripts)) {
    if (name === "test" || name.startsWith("test:")) {
      delete metadata.scripts[name];
      continue;
    }
    if (typeof command !== "string") throw new Error(`desktop build script is invalid: ${name}`);
    const privateReference = (command.match(/[A-Za-z0-9_.\/-]+/g) || []).some((token) => {
      const relative = path.posix.normalize(path.posix.join("desktop", token));
      const basename = path.posix.basename(token);
      return token === "--test" || token.includes(".test.") || basename.endsWith("_check.mjs") ||
        basename.startsWith("test_orchestration") || privateHelpers.has(basename) ||
        relative === "tests" || relative.startsWith("tests/") ||
        relative === "package.json" || relative === "package-lock.json";
    });
    if (privateReference || /(?:npm|pnpm)\s+(?:run\s+)?test(?::|\s|$)/.test(command)) {
      throw new Error(`desktop build script references a private test or harness: ${name}`);
    }
  }
  if (Object.keys(metadata.scripts).length === 0) delete metadata.scripts;
}
fs.writeFileSync(filename, JSON.stringify(metadata, null, 2) + "\n");
NODE

for forbidden_path in \
  .git \
  .playwright-cli \
  .project \
  .scratch \
  .worktrees \
  target \
  output \
  node_modules \
  tests \
  docs/private \
  .shellx-drive-data \
  release-evidence; do
  if [ -e "$tmp_dir/$forbidden_path" ]; then
    echo "forbidden public export path survived: $forbidden_path" >&2
    exit 1
  fi
done

while IFS= read -r -d '' staged_path; do
  reject_private_development_path "${staged_path#"$tmp_dir/"}"
done < <(find "$tmp_dir" -type f -print0)

if [ -d "$tmp_dir/docs" ] && find "$tmp_dir/docs" -mindepth 1 -maxdepth 1 ! -name public -print -quit | grep -q .; then
  echo "public export contains a non-public documentation subtree" >&2
  exit 1
fi

for required_path in desktop docs/public skill scripts/sbom.sh; do
  if [ ! -e "$tmp_dir/$required_path" ]; then
    echo "required public export path is absent: $required_path" >&2
    exit 1
  fi
done

cat >"$tmp_dir/PUBLIC_EXPORT_MANIFEST.txt" <<MANIFEST
ShellX Drive public export
Selection policy: exact files named by scripts/public_export_allowlist.txt
Payload scope: server source, public documentation, packaging and installer
inputs, skill documentation, and desktop source for Linux, macOS, and Windows.
Desktop build metadata preserves toolchain fields and omits private test aliases.

This tree was generated from an empty staging directory using only the explicit
selection above. It does not contain source Git history or source object
identifiers, and does not claim an installed desktop release has been qualified.
MANIFEST

password_store_scheme='pass'
ipv4_left_boundary='(^|[^0-9.])'
ipv4_right_boundary='([^0-9.]|$)'
private_ipv4="(10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3})"
unix_user_home="(/home/[[:alnum:]_.-]+/|/Users/[[:alnum:]_.-]+/)"
wsl_user_home="/mnt/[[:alpha:]]/Users/[[:alnum:]_.-]+/"
forbidden_regex="(${unix_user_home}|${wsl_user_home}|${ipv4_left_boundary}${private_ipv4}${ipv4_right_boundary}|${password_store_scheme}:[[:alnum:]_.-]+/)"
if grep -RInE --binary-files=without-match "$forbidden_regex" "$tmp_dir"; then
  echo "public export contains a local user path, private-network address, or secret-store reference" >&2
  exit 1
fi

if [ -L "$out_dir" ] || [ ! -d "$out_dir" ] ||
   [[ "$(stat -Lc '%d:%i' "$out_dir")" != "$expected_out_identity" ]]; then
  echo "export destination changed during staging: $out_display" >&2
  exit 2
fi
require_private_directory "$out_dir" "export destination"

if (( preserve_git )); then
  if [ ! -e "$pinned_out/.git" ] || [ -L "$pinned_out/.git" ]; then
    echo "export destination Git metadata changed during staging: $out_display" >&2
    exit 2
  fi
  find "$pinned_out/" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf -- {} +
else
  find "$pinned_out/" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi
tar -C "$tmp_dir" -cf - . | tar -C "$pinned_out" -xf -

echo "SHELLX_DRIVE_PUBLIC_EXPORT_OK $out_display"
