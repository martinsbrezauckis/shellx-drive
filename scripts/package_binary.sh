#!/bin/bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
  cat <<'USAGE'
Usage: scripts/package_binary.sh --binary <path> --out-dir <path> [options]

Options:
  --sha256 <digest>          Require this SHA-256 for the opened binary
  --source-revision <commit> Bind a full 40-character source commit
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
running_script="$(realpath -e -- "${BASH_SOURCE[0]}")"
binary=""
out_dir=""
expected_sha256=""
source_revision=""
source_root="$repo_root"
source_stage=""
binary_fd=""
out_dir_fd=""
support_fds=()
support_digests=()
stage=""
temporary_package=""
temporary_checksum=""

close_support_fds() {
  local fd
  for fd in "${support_fds[@]}"; do
    exec {fd}<&-
  done
  support_fds=()
}

close_fds() {
  if [[ -n "$binary_fd" ]]; then
    exec {binary_fd}<&-
    binary_fd=""
  fi
  if [[ -n "$out_dir_fd" ]]; then
    exec {out_dir_fd}<&-
    out_dir_fd=""
  fi
  close_support_fds
}

cleanup() {
  close_fds || true
  [[ -z "$temporary_package" ]] || rm -f -- "$temporary_package"
  [[ -z "$temporary_checksum" ]] || rm -f -- "$temporary_checksum"
  [[ -z "$stage" ]] || rm -rf -- "$stage"
  [[ -z "$source_stage" ]] || rm -rf -- "$source_stage"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary="${2:-}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    --sha256)
      expected_sha256="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    -h|--help)
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

if [[ -z "$binary" || -z "$out_dir" ]]; then
  usage >&2
  exit 2
fi
if [[ -n "$expected_sha256" && ! "$expected_sha256" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "--sha256 must be exactly 64 hexadecimal characters" >&2
  exit 2
fi
expected_sha256="${expected_sha256,,}"
if [[ -n "$source_revision" && ! "$source_revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "--source-revision must be a full lowercase 40-character Git commit" >&2
  exit 2
fi

require_exact_git_source_closure() {
  local expected_script="$repo_root/scripts/package_binary.sh"
  local resolved_revision=""
  local linked_source_path=""

  for required_command in git tar cmp mktemp find; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      echo "Git-qualified packaging requires $required_command" >&2
      exit 127
    fi
  done
  if [[ -L "${BASH_SOURCE[0]}" || "$running_script" != "$expected_script" \
     || "$(stat -c '%F' -- "$expected_script" 2>/dev/null || true)" != "regular file" ]]; then
    echo "Git-qualified packaging must run the canonical regular package script" >&2
    exit 1
  fi
  if ! resolved_revision="$(git -C "$repo_root" rev-parse --verify "${source_revision}^{commit}")" \
     || [[ "$resolved_revision" != "$source_revision" ]]; then
    echo "--source-revision is not an available exact Git commit: $source_revision" >&2
    exit 1
  fi
  if ! git -C "$repo_root" show "${source_revision}:scripts/package_binary.sh" \
      | cmp -s - "$expected_script"; then
    echo "running package script does not match --source-revision" >&2
    exit 1
  fi

  source_stage="$(mktemp -d "${TMPDIR:-/tmp}/shellx-drive-package-source.XXXXXXXX")"
  chmod 0700 "$source_stage"
  git -C "$repo_root" archive --format=tar "$source_revision" -- scripts/package_binary_support.sh \
    | tar -x -C "$source_stage"
  source_root="$source_stage"
}

if [[ -n "$source_revision" ]]; then
  require_exact_git_source_closure
fi

support_manifest="$source_root/scripts/package_binary_support.sh"
if [[ -L "$support_manifest" || "$(stat -c '%F' -- "$support_manifest" 2>/dev/null || true)" != "regular file" ]]; then
  echo "package support manifest must be a regular file, not a link" >&2
  exit 1
fi
# shellcheck source=scripts/package_binary_support.sh
source "$support_manifest"
if [[ ${#support_sources[@]} -eq 0 \
   || ${#support_sources[@]} -ne ${#support_targets[@]} \
   || ${#support_sources[@]} -ne ${#support_modes[@]} ]]; then
  echo "package support manifest arrays must be non-empty and have equal lengths" >&2
  exit 1
fi

if [[ -n "$source_revision" ]]; then
  stage_exact_git_support_sources
fi

for index in "${!support_sources[@]}"; do
  source_path="$source_root/${support_sources[$index]}"
  support_fd=""
  if ! exec {support_fd}<"$source_path"; then
    echo "package support input could not be opened: ${support_sources[$index]}" >&2
    exit 1
  fi
  support_fd_path="/proc/self/fd/$support_fd"
  if [[ ! -e "$support_fd_path" ]]; then
    echo "packaging requires Linux /proc file descriptors" >&2
    exit 1
  fi
  support_path_type="$(stat -c '%F' -- "$source_path" 2>/dev/null || true)"
  support_fd_type="$(stat -Lc '%F' -- "$support_fd_path" 2>/dev/null || true)"
  support_path_identity="$(stat -Lc '%d:%i' -- "$source_path" 2>/dev/null || true)"
  support_fd_identity="$(stat -Lc '%d:%i' -- "$support_fd_path" 2>/dev/null || true)"
  if [[ "$support_path_type" != "regular file" || "$support_fd_type" != "regular file" ]]; then
    echo "package support input must be a regular file, not a link or special file: ${support_sources[$index]}" >&2
    exit 1
  fi
  if [[ -z "$support_path_identity" || "$support_path_identity" != "$support_fd_identity" ]]; then
    echo "package support input changed while it was being opened: ${support_sources[$index]}" >&2
    exit 1
  fi
  support_fds+=("$support_fd")
  support_digests+=("$(sha256sum "$support_fd_path" | awk '{print $1}')")
done

if ! exec {binary_fd}<"$binary"; then
  echo "binary could not be opened: $binary" >&2
  exit 1
fi
binary_fd_path="/proc/self/fd/$binary_fd"
if [[ ! -e "$binary_fd_path" ]]; then
  echo "packaging requires Linux /proc file descriptors" >&2
  exit 1
fi
binary_path_type="$(stat -c '%F' -- "$binary" 2>/dev/null || true)"
binary_fd_type="$(stat -Lc '%F' -- "$binary_fd_path" 2>/dev/null || true)"
binary_path_identity="$(stat -Lc '%d:%i' -- "$binary" 2>/dev/null || true)"
binary_fd_identity="$(stat -Lc '%d:%i' -- "$binary_fd_path" 2>/dev/null || true)"
if [[ "$binary_path_type" != "regular file" || "$binary_fd_type" != "regular file" ]]; then
  echo "binary must be a regular file, not a link or special file: $binary" >&2
  exit 1
fi
if [[ -z "$binary_path_identity" || "$binary_path_identity" != "$binary_fd_identity" ]]; then
  echo "binary path changed while it was being opened: $binary" >&2
  exit 1
fi
binary_sha256="$(sha256sum "$binary_fd_path" | awk '{print $1}')"
if [[ -n "$expected_sha256" && "$binary_sha256" != "$expected_sha256" ]]; then
  echo "binary SHA-256 mismatch: expected $expected_sha256, opened $binary_sha256" >&2
  exit 1
fi

umask 077
mkdir -p -- "$out_dir"
if [[ -L "$out_dir" || "$(stat -c '%F' -- "$out_dir" 2>/dev/null || true)" != "directory" ]]; then
  echo "output directory must be a real directory, not a link: $out_dir" >&2
  exit 1
fi
out_dir="$(realpath -e -- "$out_dir")"
out_owner="$(stat -c '%u' -- "$out_dir")"
out_mode="$(stat -c '%a' -- "$out_dir")"
if [[ "$out_owner" != "$(id -u)" ]] || (( (8#$out_mode & 8#022) != 0 )); then
  echo "output directory must be owned by the current user and not group/other writable: $out_dir" >&2
  exit 1
fi
if ! exec {out_dir_fd}<"$out_dir"; then
  echo "output directory could not be opened: $out_dir" >&2
  exit 1
fi
out_dir_fd_path="/proc/self/fd/$out_dir_fd"
out_path_identity="$(stat -Lc '%d:%i' -- "$out_dir")"
out_fd_identity="$(stat -Lc '%d:%i' -- "$out_dir_fd_path")"
if [[ "$out_path_identity" != "$out_fd_identity" ]]; then
  echo "output directory changed while it was being opened: $out_dir" >&2
  exit 1
fi

version="$(awk -F '"' '/^version =/ { print $2; exit }' "/proc/self/fd/${support_fds[0]}")"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] \
  || [[ ! "$os" =~ ^[a-z0-9._-]+$ ]] || [[ ! "$arch" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "package identity contains unsupported characters" >&2
  exit 1
fi
package_name="shellx-drive-${version}-${os}-${arch}"
package_name_file="${package_name}.tar.gz"
checksum_name_file="${package_name_file}.sha256"
package_fd_path="$out_dir_fd_path/$package_name_file"
checksum_fd_path="$out_dir_fd_path/$checksum_name_file"
if [[ -e "$package_fd_path" || -L "$package_fd_path" || -e "$checksum_fd_path" || -L "$checksum_fd_path" ]]; then
  echo "package output already exists; refusing to replace it: $out_dir/$package_name_file" >&2
  exit 1
fi

stage="$(mktemp -d)"
mkdir -p "$stage/$package_name/bin"
mkdir -p "$stage/$package_name/docs/public/assets/screenshots"
mkdir -p "$stage/$package_name/packaging/systemd"
mkdir -p "$stage/$package_name/scripts"
mkdir -p "$stage/$package_name/skill/shellx-drive"

install -m 0755 "$binary_fd_path" "$stage/$package_name/bin/shellx-drive"
staged_binary_sha256="$(sha256sum "$stage/$package_name/bin/shellx-drive" | awk '{print $1}')"
if [[ "$staged_binary_sha256" != "$binary_sha256" ]]; then
  echo "staged binary SHA-256 mismatch" >&2
  exit 1
fi
exec {binary_fd}<&-
binary_fd=""

for index in "${!support_sources[@]}"; do
  target="${support_targets[$index]}"
  [[ -n "$target" ]] || continue
  source_fd_path="/proc/self/fd/${support_fds[$index]}"
  install -m "${support_modes[$index]}" "$source_fd_path" "$stage/$package_name/$target"
  staged_support_sha256="$(sha256sum "$stage/$package_name/$target" | awk '{print $1}')"
  if [[ "$staged_support_sha256" != "${support_digests[$index]}" ]]; then
    echo "staged support input SHA-256 mismatch: ${support_sources[$index]}" >&2
    exit 1
  fi
done

source_manifest="$stage/$package_name/SOURCE_INPUTS.sha256"
printf '%s  %s\n' "$binary_sha256" "binary:shellx-drive" >"$source_manifest"
for index in "${!support_sources[@]}"; do
  printf '%s  source:%s\n' "${support_digests[$index]}" "${support_sources[$index]}" >>"$source_manifest"
done
chmod 0644 "$source_manifest"
close_support_fds

source_manifest_sha256="$(sha256sum "$source_manifest" | awk '{print $1}')"
release_provenance="$stage/$package_name/RELEASE_PROVENANCE.json"
if [[ -n "$source_revision" ]]; then
  revision_json="\"$source_revision\""
  qualified_json="true"
else
  revision_json="null"
  qualified_json="false"
fi
printf '{"schema":"shellx-drive.release-provenance/v1","version":"%s","source_revision":%s,"package_name":"%s","binary_sha256":"%s","source_inputs_sha256":"%s","release_candidate":%s,"publisher_attestation_required":true}\n' \
  "$version" "$revision_json" "$package_name" "$binary_sha256" \
  "$source_manifest_sha256" "$qualified_json" >"$release_provenance"
chmod 0644 "$release_provenance"

package_contents_manifest="$stage/$package_name/PACKAGE_CONTENTS.sha256"
(
  cd "$stage/$package_name"
  while IFS= read -r -d '' entry; do
    sha256sum -- "${entry#./}"
  done < <(find . -type f ! -name PACKAGE_CONTENTS.sha256 -print0 | LC_ALL=C sort -z)
) >"$package_contents_manifest"
chmod 0644 "$package_contents_manifest"

temporary_package="$(mktemp "$out_dir_fd_path/.${package_name_file}.XXXXXX")"
tar -czf "$temporary_package" -C "$stage" "$package_name"
package_sha256="$(sha256sum "$temporary_package" | awk '{print $1}')"
temporary_checksum="$(mktemp "$out_dir_fd_path/.${checksum_name_file}.XXXXXX")"
printf '%s  %s\n' "$package_sha256" "$package_name_file" >"$temporary_checksum"

mv -nT -- "$temporary_checksum" "$checksum_fd_path"
if [[ -e "$temporary_checksum" ]]; then
  echo "checksum output appeared concurrently; refusing to replace it" >&2
  exit 1
fi
temporary_checksum=""
mv -nT -- "$temporary_package" "$package_fd_path"
if [[ -e "$temporary_package" ]]; then
  rm -f -- "$checksum_fd_path"
  echo "package output appeared concurrently; refusing to replace it" >&2
  exit 1
fi
temporary_package=""

if [[ "$(stat -Lc '%d:%i' -- "$out_dir")" != "$out_fd_identity" ]]; then
  echo "output directory path changed before publication completed" >&2
  exit 1
fi
echo "BINARY_SHA256=$binary_sha256"
echo "PACKAGE_SHA256=$package_sha256"
echo "PACKAGE=$out_dir/$package_name_file"
