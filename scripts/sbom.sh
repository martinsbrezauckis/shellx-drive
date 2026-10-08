#!/usr/bin/env bash
set -euo pipefail

out_dir="target/sbom"
fail_on="high"

usage() {
  cat <<'USAGE'
Usage: scripts/sbom.sh [--out DIR] [--fail-on SEVERITY]

Generates a CycloneDX source SBOM with Syft, writes source provenance and
SHA-256 metadata, and scans the SBOM with Grype. The source scope includes the
root server and desktop Cargo/JavaScript dependency inputs. Build output,
private operational material, worktrees, and installed JavaScript dependencies
are excluded.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      out_dir="${2:?--out requires a directory}"
      shift 2
      ;;
    --fail-on)
      fail_on="${2:?--fail-on requires a severity}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$out_dir" != /* ]]; then
  out_dir="$PWD/$out_dir"
fi

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
cd "$repo_root"

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is unavailable: $command_name" >&2
    exit 127
  fi
}

for required_command in syft grype sha256sum python3; do
  require_command "$required_command"
done

assert_no_symlink_path_components() {
  local path="$1"
  local current="/"
  local component=""
  local -a components=()

  IFS=/ read -r -a components <<< "${path#/}"
  for component in "${components[@]}"; do
    case "$component" in
      ''|.)
        continue
        ;;
      ..)
        current="$(dirname -- "$current")"
        [[ -n "$current" ]] || current="/"
        continue
        ;;
      *)
        if [[ "$current" == / ]]; then
          current="/$component"
        else
          current="$current/$component"
        fi
        if [[ -L "$current" ]]; then
          echo "SBOM output path has a symbolic-link ancestor: $current" >&2
          exit 1
        fi
        ;;
    esac
  done
}

claim_private_output_directory() {
  local parent="$(dirname -- "$out_dir")"
  local leaf="$(basename -- "$out_dir")"
  local canonical_parent=""
  local parent_owner=""
  local parent_mode=""
  local output_owner=""
  local output_mode=""

  if [[ "$leaf" == . || "$leaf" == .. ]]; then
    echo "SBOM output directory must name a new child directory" >&2
    exit 2
  fi
  assert_no_symlink_path_components "$parent"
  if [[ -L "$parent" || ! -d "$parent" ]]; then
    echo "SBOM output parent must be an existing non-symlink directory: $parent" >&2
    exit 1
  fi
  canonical_parent="$(realpath -e -- "$parent")"
  parent_owner="$(stat -c '%u' -- "$canonical_parent")"
  parent_mode="$(stat -c '%a' -- "$canonical_parent")"
  # A root-owned sticky parent such as /tmp safely admits an exclusive child
  # claim; every other parent must be writable only by the invoking user.
  if { [[ "$parent_owner" != "$(id -u)" ]] || (( (8#$parent_mode & 8#022) != 0 )); } \
     && { [[ "$parent_owner" != 0 ]] || (( (8#$parent_mode & 8#1000) == 0 )); }; then
    echo "SBOM output parent must be owned by the current user and not group/other writable: $canonical_parent" >&2
    exit 1
  fi
  out_dir="$canonical_parent/$leaf"
  if [[ -e "$out_dir" || -L "$out_dir" ]]; then
    echo "SBOM output directory must be newly claimed and must not already exist: $out_dir" >&2
    exit 1
  fi
  if ! mkdir -m 0700 -- "$out_dir"; then
    echo "failed to exclusively claim SBOM output directory: $out_dir" >&2
    exit 1
  fi
  output_owner="$(stat -c '%u' -- "$out_dir")"
  output_mode="$(stat -c '%a' -- "$out_dir")"
  if { [[ -L "$out_dir" || "$(stat -c '%F' -- "$out_dir")" != directory \
       || "$output_owner" != "$(id -u)" || "$output_mode" != 700 ]]; }; then
    echo "SBOM output directory claim did not produce a private regular directory" >&2
    exit 1
  fi
}

create_exclusive_output_file() {
  local output="$1"
  local output_owner=""
  local output_mode=""

  if [[ -e "$output" || -L "$output" ]]; then
    echo "SBOM output already exists; refusing to replace it: $output" >&2
    exit 1
  fi
  if ! (set -C; : > "$output"); then
    echo "failed to exclusively create SBOM output: $output" >&2
    exit 1
  fi
  output_owner="$(stat -c '%u' -- "$output")"
  output_mode="$(stat -c '%a' -- "$output")"
  if [[ -L "$output" || "$(stat -c '%F' -- "$output")" != "regular empty file" \
     || "$output_owner" != "$(id -u)" || "$output_mode" != 600 ]]; then
    echo "SBOM output must be a newly created private regular file: $output" >&2
    exit 1
  fi
}

require_private_regular_output() {
  local output="$1"
  local output_owner=""
  local output_mode=""

  output_owner="$(stat -c '%u' -- "$output" 2>/dev/null || true)"
  output_mode="$(stat -c '%a' -- "$output" 2>/dev/null || true)"
  if { [[ -L "$output" || "$(stat -c '%F' -- "$output" 2>/dev/null || true)" != "regular file" \
       || "$output_owner" != "$(id -u)" ]]; } || (( (8#$output_mode & 8#077) != 0 )); then
    echo "SBOM output is not a private regular file: $output" >&2
    exit 1
  fi
}

source_root="$repo_root"
source_stage=""
source_commit="unavailable"
source_tree="unavailable"
cleanup_source_stage() {
  if [[ -n "$source_stage" && -d "$source_stage" ]]; then
    rm -rf -- "$source_stage"
  fi
}
trap cleanup_source_stage EXIT

# A Git-qualified SBOM must scan the exact Git object it names, not mutable or
# ignored working-tree bytes. Non-Git source archives retain the explicit
# `unavailable` provenance and are scanned in place for compatibility.
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  require_command tar
  require_command mktemp
  require_command find
  source_commit="$(git rev-parse HEAD)"
  source_tree="$(git rev-parse HEAD^{tree})"
  source_stage="$(mktemp -d "${TMPDIR:-/tmp}/shellx-drive-sbom-source.XXXXXXXX")"
  chmod 0700 "$source_stage"
  git archive --format=tar "$source_commit" | tar -x -C "$source_stage"
  # Syft and the dependency-input readers may dereference links. Refuse every
  # archived symbolic link so a Git-qualified receipt cannot consume bytes
  # outside the exact tree named by source_commit/source_tree.
  linked_source_path="$(find "$source_stage" -type l -print -quit)"
  if [[ -n "$linked_source_path" ]]; then
    echo "Git-qualified SBOM source contains a symbolic link" >&2
    exit 1
  fi
  source_root="$source_stage"
fi

required_source_inputs=(
  Cargo.toml
  Cargo.lock
)
# Root npm metadata belongs to private maintainer test tooling. Bind the pair
# when present in a private source tree; public distributions omit both files.
if [[ -e "$source_root/package.json" || -e "$source_root/package-lock.json" ]]; then
  required_source_inputs+=(package.json package-lock.json)
fi
required_source_inputs+=(
  desktop/Cargo.toml
  desktop/Cargo.lock
  # Bind the compatibility backport manifest, provenance, full-file inventory,
  # patched source, and verifier into the compact receipt alongside the desktop
  # dependency resolution.
  desktop/vendor/glib-0.18.5-rustsec-2024-0429/Cargo.toml
  desktop/vendor/glib-0.18.5-rustsec-2024-0429/BACKPORT.md
  desktop/vendor/glib-0.18.5-rustsec-2024-0429/SHA256SUMS
  desktop/vendor/glib-0.18.5-rustsec-2024-0429/src/variant_iter.rs
  desktop/package.json
  desktop/pnpm-lock.yaml
  scripts/verify_glib_backport.py
  desktop/vendor/tauri-plugin-updater-2.10.1-macos-backport/Cargo.toml
  desktop/vendor/tauri-plugin-updater-2.10.1-macos-backport/Cargo.lock
  desktop/vendor/tauri-plugin-updater-2.10.1-macos-backport/SHA256SUMS
  scripts/verify_tauri_updater_macos_backport.py
)
for input in "${required_source_inputs[@]}"; do
  if [[ ! -f "$source_root/$input" ]]; then
    echo "required source dependency input is absent: $input" >&2
    exit 1
  fi
done

version="$(awk -F'"' '/^version =/ { print $2; exit }' "$source_root/Cargo.toml")"
if [[ -z "$version" ]]; then
  echo "failed to read package version from Cargo.toml" >&2
  exit 1
fi

claim_private_output_directory
sbom="$out_dir/shellx-drive.cdx.json"
input_hashes="$out_dir/source-inputs.sha256"
provenance="$out_dir/source-provenance.json"
checksums="$out_dir/SHA256SUMS"
for output in "$sbom" "$input_hashes" "$provenance" "$checksums"; do
  create_exclusive_output_file "$output"
done

# This ordered input receipt is stable for an unchanged source tree. Syft's
# CycloneDX serial and generation time can vary, so consumers should use this
# digest to bind a generated SBOM to the exact dependency-source inputs.
(cd "$source_root" && sha256sum "${required_source_inputs[@]}") >"$input_hashes"
source_inputs_sha256="$(sha256sum "$input_hashes" | awk '{print $1}')"

syft_binary_sha256="$(sha256sum "$(command -v syft)" | awk '{print $1}')"
grype_binary_sha256="$(sha256sum "$(command -v grype)" | awk '{print $1}')"

private_project_dir='.project'

# The retained updater is a path dependency excluded from desktop workspace
# membership. Supported builds resolve desktop/Cargo.lock; its upstream
# standalone lock is provenance, not a second dependency resolution. Preserve
# that file in the exact source tree and input receipt, while excluding only
# its catalog entries. All vendor source and both product locks remain scanned.
syft scan "dir:$source_root" \
  --source-name shellx-drive \
  --source-version "$version" \
  --exclude './.git/**' \
  --exclude './target/**' \
  --exclude "./${private_project_dir}/**" \
  --exclude './.worktrees/**' \
  --exclude './node_modules/**' \
  --exclude './**/node_modules/**' \
  --exclude './docs/private/**' \
  --exclude './release-evidence/**' \
  --exclude './output/**' \
  --exclude './.scratch/**' \
  --exclude './.shellx-drive-data/**' \
  --exclude './desktop/vendor/tauri-plugin-updater-2.10.1-macos-backport/Cargo.lock' \
  -o "cyclonedx-json=$sbom"
require_private_regular_output "$sbom"

# Syft's CycloneDX file components retain absolute directory-source names even
# with --base-path. Keep their identities/hashes and publish source-relative
# names only; reject names outside the exact scanned tree.
python3 - "$sbom" "$source_root" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.PurePosixPath(sys.argv[2])
with path.open("r+", encoding="utf-8") as output:
    document = json.load(output)
    for component in document.get("components", []):
        if component.get("type") != "file":
            continue
        name = pathlib.PurePosixPath(component["name"])
        if name.is_absolute():
            try:
                name = name.relative_to(root)
            except ValueError:
                raise SystemExit("SBOM file component is outside the scanned source tree")
        if not name.parts or ".." in name.parts:
            raise SystemExit("SBOM file component has an unsafe source-relative name")
        component["name"] = name.as_posix()
    output.seek(0)
    json.dump(document, output, separators=(",", ":"))
    output.write("\n")
    output.truncate()
PY
require_private_regular_output "$sbom"

{
  printf '{\n'
  printf '  "schema": 1,\n'
  printf '  "source_name": "shellx-drive",\n'
  printf '  "source_version": "%s",\n' "$version"
  printf '  "source_commit": "%s",\n' "$source_commit"
  printf '  "source_tree": "%s",\n' "$source_tree"
  printf '  "source_inputs_sha256": "%s",\n' "$source_inputs_sha256"
  printf '  "syft_binary_sha256": "%s",\n' "$syft_binary_sha256"
  printf '  "grype_binary_sha256": "%s",\n' "$grype_binary_sha256"
  printf '  "resolved_cargo_lockfiles": ["Cargo.lock", "desktop/Cargo.lock"],\n'
  printf '  "catalog_excluded_lockfiles": ["desktop/vendor/tauri-plugin-updater-2.10.1-macos-backport/Cargo.lock"],\n'
  printf '  "source_inputs": [\n'
  for index in "${!required_source_inputs[@]}"; do
    comma=','
    if (( index + 1 == ${#required_source_inputs[@]} )); then
      comma=''
    fi
    printf '    "%s"%s\n' "${required_source_inputs[$index]}" "$comma"
  done
  printf '  ]\n'
  printf '}\n'
} >"$provenance"
require_private_regular_output "$input_hashes"
require_private_regular_output "$provenance"

(cd "$out_dir" && sha256sum shellx-drive.cdx.json source-inputs.sha256 source-provenance.json) >"$checksums"
require_private_regular_output "$checksums"
grype "sbom:$sbom" --fail-on "$fail_on"

printf 'SBOM=%s\n' "$sbom"
printf 'SOURCE_INPUTS_SHA256=%s\n' "$source_inputs_sha256"
printf 'PROVENANCE=%s\n' "$provenance"
printf 'SHA256SUMS=%s\n' "$checksums"
