#!/bin/bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

package_root="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
manifest="$package_root/SOURCE_INPUTS.sha256"
closure_manifest="$package_root/PACKAGE_CONTENTS.sha256"
provenance="$package_root/RELEASE_PROVENANCE.json"
binary="$package_root/bin/shellx-drive"
installer="$package_root/scripts/install_systemd.sh"

require_root_private_package() {
  local current="/"
  local component=""
  local relative="${package_root#/}"
  local type=""
  local uid=""
  local mode=""
  local IFS=/
  local -a components=()
  read -r -a components <<< "$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current="${current%/}/$component"
    if [[ -L "$current" ]]; then
      echo "package stage contains a symbolic-link directory: $current" >&2
      return 1
    fi
    type="$(stat -c '%F' -- "$current" 2>/dev/null || true)"
    uid="$(stat -c '%u' -- "$current" 2>/dev/null || true)"
    mode="$(stat -c '%a' -- "$current" 2>/dev/null || true)"
    if [[ "$type" != "directory" || "$uid" != 0 || ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
      echo "package stage must contain only root-owned directory components: $current" >&2
      return 1
    fi
    if (( (8#$mode & 0022) != 0 && (8#$mode & 01000) == 0 )); then
      echo "package stage has a replaceable directory component: $current" >&2
      return 1
    fi
  done
  while IFS= read -r -d '' path; do
    type="$(stat -c '%F' -- "$path")"
    uid="$(stat -c '%u' -- "$path")"
    mode="$(stat -c '%a' -- "$path")"
    if [[ ( "$type" != "directory" && "$type" != "regular file" ) || "$uid" != 0 || ! "$mode" =~ ^[0-7]{3,4}$ || $((8#$mode & 0022)) -ne 0 ]]; then
      echo "package entries must be regular root-owned directories or files and not group/world writable: $path" >&2
      return 1
    fi
  done < <(find "$package_root" -xdev -print0)
}

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  require_root_private_package || {
    echo "refusing direct elevation from a user-controlled extraction; use packaging/README.md" >&2
    exit 1
  }
fi

for path in "$manifest" "$closure_manifest" "$provenance" "$binary" "$installer"; do
  if [[ -L "$path" || ! -f "$path" ]]; then
    echo "package input is missing or not a regular file: $path" >&2
    exit 1
  fi
done

if ! (cd "$package_root" && sha256sum --check --strict --status PACKAGE_CONTENTS.sha256); then
  echo "package closure does not match PACKAGE_CONTENTS.sha256" >&2
  exit 1
fi
for required in \
  bin/shellx-drive \
  install.sh \
  scripts/install_systemd.sh \
  scripts/install_systemd_path_trust.sh \
  scripts/install_systemd_destination_trust.sh \
  scripts/install_systemd_secrets.sh \
  scripts/install_systemd_service_config.sh \
  scripts/install_systemd_lifecycle.sh \
  scripts/install_systemd_data_dir.sh \
  scripts/curl_secret_config.sh \
  SOURCE_INPUTS.sha256 \
  RELEASE_PROVENANCE.json; do
  if ! grep -Eq "^[0-9a-f]{64}  ${required//\//\\/}$" "$closure_manifest"; then
    echo "package closure does not pin required input: $required" >&2
    exit 1
  fi
done

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  allow_unprivileged=0
  for argument in "$@"; do
    [[ "$argument" == "--dry-run" || "$argument" == "--help" || "$argument" == "-h" ]] \
      && allow_unprivileged=1
    if [[ "$argument" == "--binary" || "$argument" == "--sha256" ]]; then
      echo "$argument is fixed by the verified package and cannot be overridden" >&2
      exit 2
    fi
  done
  if [[ "$allow_unprivileged" -eq 0 ]]; then
    echo "real installation requires the attested root-private staging procedure in packaging/README.md" >&2
    exit 1
  fi
fi

for argument in "$@"; do
  if [[ "$argument" == "--binary" || "$argument" == "--sha256" ]]; then
    echo "$argument is fixed by the verified package and cannot be overridden" >&2
    exit 2
  fi
done

binary_sha256=""
while IFS= read -r line; do
  suffix="  binary:shellx-drive"
  [[ "$line" == *"$suffix" ]] || continue
  digest="${line%"$suffix"}"
  if [[ -n "$binary_sha256" || ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "package manifest has an invalid or duplicate binary digest" >&2
    exit 1
  fi
  binary_sha256="$digest"
done < "$manifest"

if [[ -z "$binary_sha256" ]]; then
  echo "package manifest does not pin the Drive binary" >&2
  exit 1
fi
exec "$installer" --binary "$binary" --sha256 "$binary_sha256" "$@"
