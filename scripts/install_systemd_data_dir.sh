#!/bin/bash

# Sourced by install_systemd.sh after its root-private closure admission.
# These are the only data roots the privileged systemd installer may create or
# take over. Keeping the policy separate lets the entry point admit every
# helper before it evaluates installer-specific logic.
supported_data_dirs=(
  "/var/lib/shellx-drive"
  "/srv/shellx-drive"
)

validate_data_dir() {
  local value="$1"
  local allowed=""
  local component=""
  local current=""
  local IFS=/
  local -a components=()

  for allowed in "${supported_data_dirs[@]}"; do
    if [[ "$value" == "$allowed" ]]; then
      break
    fi
  done
  if [[ "$value" != "$allowed" ]]; then
    echo "--data-dir must be exactly /var/lib/shellx-drive or /srv/shellx-drive" >&2
    exit 2
  fi

  read -r -a components <<< "${value#/}"
  for component in "${components[@]}"; do
    current="$current/$component"
    if [[ -L "$current" ]]; then
      echo "--data-dir must not contain a symbolic-link component: $current" >&2
      exit 1
    fi
  done
}

open_data_dir_fd() {
  if ! exec {data_dir_fd}<"$data_dir"; then
    echo "--data-dir could not be opened as a directory: $data_dir" >&2
    exit 1
  fi
  data_dir_fd_path="/proc/self/fd/$data_dir_fd"
  if [[ ! -e "$data_dir_fd_path" ]]; then
    echo "the installer requires Linux /proc file descriptors" >&2
    exit 1
  fi
}

verify_open_data_dir() {
  local path_type=""
  local fd_type=""
  local path_identity=""
  local fd_identity=""

  # Recheck components immediately before a privileged operation. The
  # descriptor is used below so a later pathname swap cannot redirect chmod or
  # chown to a different directory.
  validate_data_dir "$data_dir"
  path_type="$(stat -c '%F' -- "$data_dir" 2>/dev/null || true)"
  fd_type="$(stat -Lc '%F' -- "$data_dir_fd_path" 2>/dev/null || true)"
  if [[ "$path_type" != "directory" || "$fd_type" != "directory" ]]; then
    echo "--data-dir must be a directory, not a link or special file: $data_dir" >&2
    exit 1
  fi
  path_identity="$(stat -Lc '%d:%i' -- "$data_dir" 2>/dev/null || true)"
  fd_identity="$(stat -Lc '%d:%i' -- "$data_dir_fd_path" 2>/dev/null || true)"
  if [[ -z "$path_identity" || "$path_identity" != "$fd_identity" ]]; then
    echo "--data-dir changed while it was being opened: $data_dir" >&2
    exit 1
  fi
}

preflight_existing_data_dir() {
  local expected_uid=""
  local expected_gid=""
  local actual_uid=""
  local actual_gid=""

  if [[ ! -e "$data_dir" ]]; then
    return
  fi
  data_dir_exists=1

  # A preexisting root must already belong to this service. In particular,
  # never use install -d -o/-g on an existing operator-owned directory.
  expected_uid="$(id -u "$service_user" 2>/dev/null || true)"
  expected_gid="$(getent group "$service_group" 2>/dev/null | awk -F: 'NR == 1 { print $3 }')"
  if [[ ! "$expected_uid" =~ ^[0-9]+$ || ! "$expected_gid" =~ ^[0-9]+$ ]]; then
    echo "existing --data-dir requires the $service_user service account and group: $data_dir" >&2
    exit 1
  fi

  open_data_dir_fd
  verify_open_data_dir
  actual_uid="$(stat -Lc '%u' -- "$data_dir_fd_path" 2>/dev/null || true)"
  actual_gid="$(stat -Lc '%g' -- "$data_dir_fd_path" 2>/dev/null || true)"
  if [[ "$actual_uid" != "$expected_uid" || "$actual_gid" != "$expected_gid" ]]; then
    echo "existing --data-dir must already be owned by $service_user:$service_group: $data_dir" >&2
    exit 1
  fi
}

install_data_dir() {
  local parent_dir="${data_dir%/*}"

  if [[ "$data_dir_exists" -eq 1 ]]; then
    # Ownership was checked through this descriptor before any installer file
    # mutation. Revalidate the configured pathname before publishing a mode
    # change, then do not chown an existing directory; only restore its mode.
    verify_open_data_dir
    chmod 0700 -- "$data_dir_fd_path"
    close_data_dir_fd
    return
  fi

  # /var/lib normally exists, while minimal systems may not create /srv until
  # it is first used. The parent is fixed by the allowlist and is only created
  # when absent; no existing parent permissions or ownership are changed.
  if [[ ! -e "$parent_dir" ]] && ! mkdir -m 0755 -- "$parent_dir"; then
    echo "could not create the allowed --data-dir parent: $parent_dir" >&2
    exit 1
  fi
  validate_trusted_parent_directory_path "--data-dir" "$data_dir" 0
  validate_data_dir "$data_dir"

  # mkdir succeeds only for a directory created by this invocation. If a
  # competing preexisting path appears, fail closed instead of taking it over.
  if ! mkdir -m 0700 -- "$data_dir"; then
    echo "could not create --data-dir without reusing an existing directory: $data_dir" >&2
    exit 1
  fi
  open_data_dir_fd
  verify_open_data_dir
  chown "$service_user:$service_group" -- "$data_dir_fd_path"
  chmod 0700 -- "$data_dir_fd_path"
  close_data_dir_fd
}

preserve_existing_data_dir() {
  # Read only the data-root assignment from the already trusted environment.
  # Never source/eval an EnvironmentFile: its syntax is not shell code.
  local line="" value="" matches=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:blank:]]*SHELLX_DRIVE_DATA_DIR[[:blank:]]*=(.*)$ ]]; then
      matches=$((matches + 1))
      value="${BASH_REMATCH[1]}"
      value="${value#"${value%%[![:blank:]]*}"}"
      value="${value%"${value##*[![:blank:]]}"}"
      if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
        value="${value:1:${#value}-2}"
      fi
    fi
  done < "$env_file"
  if [[ "$matches" -ne 1 || -z "$value" ]]; then
    echo "existing environment must contain exactly one nonempty SHELLX_DRIVE_DATA_DIR assignment" >&2
    return 1
  fi
  validate_install_path "existing SHELLX_DRIVE_DATA_DIR" "$value"
  if [[ "$data_dir_explicit" -eq 1 && "$data_dir" != "$value" ]]; then
    echo "--data-dir differs from the existing environment; an upgrade cannot move the data root" >&2
    return 1
  fi
  data_dir="$value"
}
