#!/bin/bash
set -euo pipefail
# Root installer: never resolve privileged helpers through a caller-controlled path.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
installer_entry="${BASH_SOURCE[0]}"
if [[ -L "$installer_entry" || ! -f "$installer_entry" ]]; then
  echo "installer entry point must be a regular file, not a symbolic link: $installer_entry" >&2
  exit 1
fi
installer_path="$(readlink -f -- "$installer_entry")"
installer_dir="$(dirname -- "$installer_path")"

# A checkout is normally writable by the invoking user. Do not let a root
# invocation source the installer closure from it: after admission every
# executable or sourced input must already live below root-owned, non-replaceable
# directories. A sticky root-owned ancestor (for example /var/tmp) is safe for
# a root-owned private child, because an unprivileged user cannot replace it.
require_root_private_installer_closure() {
  local input="" current="" type="" uid="" mode=""
  local -a closure_inputs=(
    "$installer_path"
    "$installer_dir/install_systemd_path_trust.sh"
    "$installer_dir/install_systemd_destination_trust.sh"
    "$installer_dir/install_systemd_secrets.sh"
    "$installer_dir/install_systemd_service_config.sh"
    "$installer_dir/install_systemd_lifecycle.sh"
    "$installer_dir/install_systemd_data_dir.sh"
  )

  for input in "${closure_inputs[@]}"; do
    if [[ -L "$input" || ! -f "$input" ]]; then
      echo "root-private installer closure is missing a regular input: $input" >&2
      exit 1
    fi
    type="$(stat -c '%F' -- "$input" 2>/dev/null || true)"
    uid="$(stat -c '%u' -- "$input" 2>/dev/null || true)"
    mode="$(stat -c '%a' -- "$input" 2>/dev/null || true)"
    if [[ "$type" != "regular file" || "$uid" != 0 || ! "$mode" =~ ^[0-7]{3,4}$ ]] \
      || (( (8#$mode & 0022) != 0 )); then
      echo "root-private installer closure contains an untrusted input: $input" >&2
      exit 1
    fi

    current="$(dirname -- "$input")"
    while :; do
      if [[ -L "$current" ]]; then
        echo "root-private installer closure has a symbolic-link directory: $current" >&2
        exit 1
      fi
      type="$(stat -c '%F' -- "$current" 2>/dev/null || true)"
      uid="$(stat -c '%u' -- "$current" 2>/dev/null || true)"
      mode="$(stat -c '%a' -- "$current" 2>/dev/null || true)"
      if [[ "$type" != "directory" || "$uid" != 0 || ! "$mode" =~ ^[0-7]{3,4}$ ]] \
        || { (( (8#$mode & 0022) != 0 )) && (( (8#$mode & 01000) == 0 )); }; then
        echo "root-private installer closure has a replaceable directory: $current" >&2
        exit 1
      fi
      [[ "$current" == "/" ]] && break
      current="$(dirname -- "$current")"
    done
  done
}

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  require_root_private_installer_closure
fi

source_trusted_helper() {
  local helper="$1"
  local helper_fd=""
  local helper_fd_path=""
  if [[ -L "$helper" || ! -f "$helper" ]]; then
    echo "trusted installer helper is missing or not a regular file: $helper" >&2
    exit 1
  fi
  exec {helper_fd}<"$helper"
  helper_fd_path="/proc/self/fd/$helper_fd"
  if [[ "$(stat -c '%F:%d:%i' -- "$helper")" != "$(stat -Lc '%F:%d:%i' -- "$helper_fd_path")" ]]; then
    echo "trusted installer helper changed while it was being opened: $helper" >&2
    exit 1
  fi
  source "$helper_fd_path"
  exec {helper_fd}<&-
}
source_trusted_helper "$installer_dir/install_systemd_path_trust.sh"
source_trusted_helper "$installer_dir/install_systemd_destination_trust.sh"
source_trusted_helper "$installer_dir/install_systemd_secrets.sh"
source_trusted_helper "$installer_dir/install_systemd_service_config.sh"
source_trusted_helper "$installer_dir/install_systemd_lifecycle.sh"
source_trusted_helper "$installer_dir/install_systemd_data_dir.sh"
usage() {
  cat <<'USAGE'
Usage: scripts/install_systemd.sh --binary <path> [options]

Options:
  --dry-run
  --sha256 <digest>     Required for installs; optional with --dry-run
  --prefix <path>        Default: /usr/local
  --service-dir <path>   Default: /etc/systemd/system
  --env-file <path>      Default: /etc/shellx-drive.env
  --data-dir <path>      Fresh default: /var/lib/shellx-drive; preserved from the environment on upgrades
  --bind <addr>          Default: 127.0.0.1:5758
  --public-base-url <https-origin>  Required on a fresh environment for browser Origin checks and email links
  --sandbox-profile <p>  strict or local-dev. Default: strict
USAGE
}

binary=""
expected_sha256=""
prefix="/usr/local"
service_dir="/etc/systemd/system"
env_file="/etc/shellx-drive.env"
data_dir="/var/lib/shellx-drive"
data_dir_explicit=0
bind_addr="127.0.0.1:5758"
public_base_url=""
sandbox_profile="strict"
dry_run=0
service_user="shellx-drive"
service_group="shellx-drive"
binary_fd=""
data_dir_fd=""
data_dir_fd_path=""
binary_dir_fd=""
binary_dir_fd_path=""
service_dir_fd=""
service_dir_fd_path=""
data_dir_exists=0
staged_binary=""
tmp_service=""
tmp_env=""
INITIAL_OPERATOR_TOKEN="DRY_RUN_GENERATED_OPERATOR_TOKEN"
INITIAL_BOOTSTRAP_TOKEN="DRY_RUN_GENERATED_SETUP_TOKEN"
initial_env_created=0
env_file_exists=0
close_binary_fd() {
  if [[ -n "$binary_fd" ]]; then
    exec {binary_fd}<&-
    binary_fd=""
  fi
}

close_data_dir_fd() {
  if [[ -n "$data_dir_fd" ]]; then
    exec {data_dir_fd}<&-
    data_dir_fd=""
    data_dir_fd_path=""
  fi
}

cleanup() {
  close_binary_fd || true
  close_data_dir_fd || true
  cleanup_destination_publication || true
  [[ -z "$staged_binary" ]] || rm -f -- "$staged_binary"
  [[ -z "$tmp_service" ]] || rm -f -- "$tmp_service"
  [[ -z "$tmp_env" ]] || rm -f -- "$tmp_env"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary="${2:-}"
      shift 2
      ;;
    --sha256)
      expected_sha256="${2:-}"
      shift 2
      ;;
    --prefix)
      prefix="${2:-}"
      shift 2
      ;;
    --service-dir)
      service_dir="${2:-}"
      shift 2
      ;;
    --env-file)
      env_file="${2:-}"
      shift 2
      ;;
    --data-dir)
      data_dir="${2:-}"
      data_dir_explicit=1
      shift 2
      ;;
    --bind)
      bind_addr="${2:-}"
      shift 2
      ;;
    --public-base-url)
      public_base_url="${2:-}"
      shift 2
      ;;
    --sandbox-profile)
      sandbox_profile="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
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

if [[ -z "$binary" ]]; then
  usage >&2
  exit 2
fi

if [[ -n "$expected_sha256" && ! "$expected_sha256" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "--sha256 must be exactly 64 hexadecimal characters" >&2
  exit 2
fi
expected_sha256="${expected_sha256,,}"
if [[ "$dry_run" -eq 0 && -z "$expected_sha256" ]]; then
  echo "--sha256 is required for every non-dry-run install" >&2
  exit 2
fi

validate_install_path() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^/[A-Za-z0-9._/+@:-]+$ ]] \
    || [[ "$value" == *"//"* || "$value" == *"/./"* || "$value" == *"/../"* ]] \
    || [[ "$value" == */. || "$value" == */.. ]]; then
    echo "$label must be a normalized absolute path using only safe system-path characters" >&2
    exit 2
  fi
}

validate_install_path "--prefix" "$prefix"
validate_install_path "--service-dir" "$service_dir"
validate_install_path "--env-file" "$env_file"
if [[ "$data_dir_explicit" -eq 1 ]]; then
  validate_install_path "--data-dir" "$data_dir"
  validate_data_dir "$data_dir"
  validate_trusted_parent_directory_path "--data-dir" "$data_dir" 1
fi
validate_bind_address "$bind_addr"
if [[ -n "$public_base_url" ]]; then
  validate_public_base_url "$public_base_url"
fi
validate_trusted_env_path "$env_file" 1
validate_trusted_installation_destinations

if [[ -e "$env_file" ]]; then
  env_file_exists=1
  preserve_existing_data_dir
fi
validate_install_path "--data-dir" "$data_dir"
validate_data_dir "$data_dir"
validate_trusted_parent_directory_path "--data-dir" "$data_dir" 1
if [[ "$env_file_exists" -eq 0 && -z "$public_base_url" ]]; then
  echo "--public-base-url is required before a fresh install can start; supply the final HTTPS browser origin" >&2
  exit 2
fi
if [[ "$env_file_exists" -eq 1 && -n "$public_base_url" ]]; then
  echo "--public-base-url applies only to a fresh environment; preserve the existing root-owned env file on upgrades" >&2
  exit 2
fi

if ! exec {binary_fd}<"$binary"; then
  echo "binary could not be opened: $binary" >&2
  exit 1
fi

binary_fd_path="/proc/self/fd/$binary_fd"
if [[ ! -e "$binary_fd_path" ]]; then
  echo "the installer requires Linux /proc file descriptors" >&2
  exit 1
fi

binary_path_type="$(stat -c '%F' -- "$binary" 2>/dev/null || true)"
binary_fd_type="$(stat -Lc '%F' -- "$binary_fd_path" 2>/dev/null || true)"
if [[ "$binary_path_type" != "regular file" || "$binary_fd_type" != "regular file" ]]; then
  echo "binary must be a regular file, not a link or special file: $binary" >&2
  exit 1
fi

binary_path_identity="$(stat -Lc '%d:%i' -- "$binary" 2>/dev/null || true)"
binary_fd_identity="$(stat -Lc '%d:%i' -- "$binary_fd_path" 2>/dev/null || true)"
if [[ -z "$binary_path_identity" || "$binary_path_identity" != "$binary_fd_identity" ]]; then
  echo "binary path changed while it was being opened: $binary" >&2
  exit 1
fi

binary_sha256="$(sha256sum "$binary_fd_path" | awk '{print $1}')"
if [[ -n "$expected_sha256" && "$binary_sha256" != "$expected_sha256" ]]; then
  echo "binary SHA-256 mismatch: expected $expected_sha256, opened $binary_sha256" >&2
  exit 1
fi

if [[ "$sandbox_profile" != "strict" && "$sandbox_profile" != "local-dev" ]]; then
  echo "sandbox profile must be strict or local-dev" >&2
  exit 2
fi

install_path="$prefix/bin/shellx-drive"
service_path="$service_dir/shellx-drive.service"

render_service() {
  local protect_home="true"
  local protect_system="strict"
  if [[ "$sandbox_profile" == "local-dev" ]]; then
    protect_home="read-only"
    protect_system="full"
  fi
  # The complete privileged unit schema is generated here. No package-owned
  # template line can become a systemd directive under root authority.
  cat <<SERVICE
[Unit]
Description=ShellX Drive
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=shellx-drive
Group=shellx-drive
Environment=RUST_LOG=shellx_drive=info
EnvironmentFile=$env_file
ExecStart=$install_path --bind \${SHELLX_DRIVE_BIND} --data-dir \${SHELLX_DRIVE_DATA_DIR}
Restart=on-failure
RestartSec=5s
MemoryHigh=512M
MemoryMax=768M
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=$protect_system
ProtectHome=$protect_home
PrivateDevices=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
ProtectHostname=true
SystemCallFilter=@system-service
ReadWritePaths=$data_dir

[Install]
WantedBy=multi-user.target
SERVICE
}

render_env() {
  # Keep the initial environment file schema fixed for the same reason as the
  # unit. Operators may edit this root-owned file after installation.
  cat <<ENVIRONMENT
SHELLX_DRIVE_BIND=$bind_addr
SHELLX_DRIVE_DATA_DIR=$data_dir
# Exact HTTPS browser origin; configure its TLS reverse proxy before opening Drive.
SHELLX_DRIVE_PUBLIC_ORIGIN=$public_base_url
# Generated independently during first install. This long-lived operator token
# authorizes server administration; protect it like a root password.
SHELLX_DRIVE_TOKEN=$INITIAL_OPERATOR_TOKEN
# First-admin setup authority only. It cannot authorize normal admin routes and
# bootstrap permanently closes after the first account exists.
SHELLX_DRIVE_BOOTSTRAP_TOKEN=$INITIAL_BOOTSTRAP_TOKEN
SHELLX_DRIVE_BACKUP_MAX_ARCHIVE_BYTES=9895604649984
# Set to true only when a trusted reverse proxy is the sole loopback peer.
SHELLX_DRIVE_TRUST_PROXY_HEADERS=false
SHELLX_DRIVE_LOCAL_SESSION_TTL_SECONDS=2592000
RUST_LOG=shellx_drive=info
ENVIRONMENT
}

if [[ "$dry_run" -eq 1 ]]; then
  echo "DRY RUN: no changes will be made"
  echo "SANDBOX_PROFILE=$sandbox_profile"
  echo "BINARY_SHA256=$binary_sha256"
  echo "SERVICE_SCHEMA=embedded-v1 ENVIRONMENT_SCHEMA=embedded-v4"
  echo "PUBLIC_BASE_URL=$public_base_url"
  echo "+ atomically install opened $binary as $install_path"
  echo "+ atomically publish embedded shellx-drive.service as $service_path"
  echo "+ create embedded initial environment at $env_file when absent"
  echo "+ install -d -m 0700 -o $service_user -g $service_group $data_dir"
  echo "+ systemctl daemon-reload"
  echo "+ systemctl enable --now shellx-drive.service"
  echo "--- rendered shellx-drive.env ---"
  render_env
  echo "--- rendered shellx-drive.service ---"
  render_service
  exit 0
fi

require_stopped_upgrade_service "$env_file_exists"
# Reject an existing non-Drive-owned root before copying the binary, creating
# accounts, or changing any installation path. Dry-run intentionally stops
# above: it validates the allowlist and link components without requiring a
# service account or mutating an existing installation.
preflight_existing_data_dir

publish_trusted_binary
install_data_dir

publish_trusted_service

if [[ ! -e "$env_file" && ! -L "$env_file" ]]; then
  prepare_initial_drive_secrets
  initial_env_created=1
  env_dir="$(dirname "$env_file")"
  ensure_trusted_destination_directory "--env-file" "$env_dir"
  validate_trusted_env_path "$env_file" 1
  tmp_env="$(mktemp "$env_dir/.shellx-drive.env.XXXXXX")"
  render_env > "$tmp_env"
  chown root:root -- "$tmp_env"
  chmod 0600 "$tmp_env"
  mv -nT -- "$tmp_env" "$env_file"
  if [[ -e "$tmp_env" ]]; then
    rm -f -- "$tmp_env"
  fi
  tmp_env=""
  rendered_env_sha256="$(render_env | sha256sum | awk '{print $1}')"
  installed_env_sha256="$(sha256sum "$env_file" | awk '{print $1}')"
  if [[ "$installed_env_sha256" != "$rendered_env_sha256" ]]; then
    echo "installed environment schema SHA-256 mismatch" >&2
    exit 1
  fi
fi
validate_trusted_env_path "$env_file" 0
systemctl daemon-reload
validate_trusted_env_path "$env_file" 0
verify_data_dir_for_service_start
systemctl enable --now shellx-drive.service

echo "ShellX Drive is installed and bound to $bind_addr."
if [[ "$initial_env_created" -eq 1 ]]; then
  echo "Public browser origin is $public_base_url; configure its TLS reverse proxy before first browser use."
  echo "First-admin setup is locked to the generated setup token; opening the site grants nothing."
  echo "Read it when ready: sudo sed -n 's/^SHELLX_DRIVE_BOOTSTRAP_TOKEN=//p' $env_file"
fi
