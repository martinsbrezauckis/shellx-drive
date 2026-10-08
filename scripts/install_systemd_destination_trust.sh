#!/bin/bash

# Destination publication uses root-anchored validation from path_trust.sh.
destination_trust_error() { trusted_path_error "$1" "$2"; }

ensure_trusted_destination_directory() {
  local label="$1" path="$2" relative="" current="$trusted_env_root" parent="" component=""
  local IFS=/
  local -a components=()
  validate_trusted_directory_path "$label" "$path" 1 || return
  relative="${path#"$trusted_env_root"}"
  read -r -a components <<< "${relative#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current="${current%/}/$component"
    if [[ ! -e "$current" && ! -L "$current" ]]; then
      parent="${current%/*}"; [[ -n "$parent" ]] || parent="/"
      validate_trusted_directory_path "$label" "$parent" 0 || return
      if ! mkdir -m 0755 -- "$current"; then
        validate_trusted_directory_path "$label" "$current" 0 || return
      fi
    fi
    validate_trusted_directory_path "$label" "$current" 0 || return
  done
}

verify_open_trusted_destination_directory() {
  local label="$1" path="$2" fd_path="$3" path_type="" fd_type="" path_identity="" fd_identity=""
  validate_trusted_directory_path "$label" "$path" 0 || return
  path_type="$(stat -Lc '%F' -- "$path" 2>/dev/null || true)"
  fd_type="$(stat -Lc '%F' -- "$fd_path" 2>/dev/null || true)"
  path_identity="$(stat -Lc '%d:%i' -- "$path" 2>/dev/null || true)"
  fd_identity="$(stat -Lc '%d:%i' -- "$fd_path" 2>/dev/null || true)"
  if [[ "$path_type" != "directory" || "$fd_type" != "directory" || -z "$path_identity" || "$path_identity" != "$fd_identity" ]]; then
    destination_trust_error "$label" "directory changed while it was being opened: $path"
    return
  fi
}

open_trusted_destination_directory_fd() {
  local label="$1" path="$2" fd_variable="$3" fd_path_variable="$4" opened_fd="" opened_fd_path=""
  validate_trusted_directory_path "$label" "$path" 0 || return
  if ! exec {opened_fd}<"$path"; then
    destination_trust_error "$label" "directory could not be opened: $path"
    return
  fi
  opened_fd_path="/proc/self/fd/$opened_fd"
  if [[ ! -e "$opened_fd_path" ]] || ! verify_open_trusted_destination_directory "$label" "$path" "$opened_fd_path"; then
    exec {opened_fd}<&-
    return 1
  fi
  printf -v "$fd_variable" '%s' "$opened_fd"
  printf -v "$fd_path_variable" '%s' "$opened_fd_path"
}

capture_trusted_staged_file_identity() {
  local label="$1" path="$2" type="" uid="" identity=""
  if [[ -L "$path" ]]; then
    destination_trust_error "$label" "staged file must not be a symbolic link: $path"
    return
  fi
  type="$(stat -Lc '%F' -- "$path" 2>/dev/null || true)"
  uid="$(stat -Lc '%u' -- "$path" 2>/dev/null || true)"
  identity="$(stat -Lc '%d:%i' -- "$path" 2>/dev/null || true)"
  if [[ "$type" != "regular file" || "$uid" != "$trusted_env_uid" || -z "$identity" ]]; then
    destination_trust_error "$label" "staged file must be a trusted regular file: $path"
    return
  fi
  printf '%s\n' "$identity"
}

verify_trusted_staged_file() {
  local label="$1" path="$2" expected_identity="$3" expected_sha256="$4" actual_identity="" actual_sha256=""
  actual_identity="$(capture_trusted_staged_file_identity "$label" "$path")" || return
  if [[ "$actual_identity" != "$expected_identity" ]]; then
    destination_trust_error "$label" "staged file changed before publication: $path"
    return
  fi
  actual_sha256="$(sha256sum "$path" | awk '{print $1}')"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    destination_trust_error "$label" "staged file SHA-256 mismatch before publication: $path"
    return
  fi
}

validate_trusted_installation_destinations() {
  validate_trusted_directory_path "--prefix" "$prefix/bin" 1
  validate_trusted_directory_path "--service-dir" "$service_dir" 1
}

verify_data_dir_for_service_start() {
  local expected_uid="" expected_gid="" actual_uid="" actual_gid="" actual_mode=""
  validate_trusted_parent_directory_path "--data-dir" "$data_dir" 0
  open_data_dir_fd
  verify_open_data_dir
  expected_uid="$(id -u "$service_user" 2>/dev/null || true)"
  expected_gid="$(getent group "$service_group" 2>/dev/null | awk -F: 'NR == 1 { print $3 }')"
  actual_uid="$(stat -Lc '%u' -- "$data_dir_fd_path" 2>/dev/null || true)"
  actual_gid="$(stat -Lc '%g' -- "$data_dir_fd_path" 2>/dev/null || true)"
  actual_mode="$(stat -Lc '%a' -- "$data_dir_fd_path" 2>/dev/null || true)"
  if [[ ! "$expected_uid" =~ ^[0-9]+$ || ! "$expected_gid" =~ ^[0-9]+$ ]] \
    || [[ "$actual_uid" != "$expected_uid" || "$actual_gid" != "$expected_gid" ]] \
    || [[ "$actual_mode" != "700" ]]; then
    echo "--data-dir must remain a shellx-drive:shellx-drive mode-0700 directory before service start: $data_dir" >&2
    exit 1
  fi
  close_data_dir_fd
}

publish_trusted_binary() {
  local staged_binary_identity="" installed_binary_sha256=""
  ensure_trusted_destination_directory "--prefix" "$prefix/bin"
  open_trusted_destination_directory_fd "--prefix" "$prefix/bin" binary_dir_fd binary_dir_fd_path
  staged_binary="$(mktemp "$binary_dir_fd_path/.shellx-drive.install.XXXXXX")"
  install -m 0755 "$binary_fd_path" "$staged_binary"
  staged_binary_identity="$(capture_trusted_staged_file_identity "--prefix" "$staged_binary")"
  verify_trusted_staged_file "--prefix" "$staged_binary" "$staged_binary_identity" "$binary_sha256"
  close_binary_fd
  if ! getent group "$service_group" >/dev/null; then groupadd --system "$service_group"; fi
  if ! id -u "$service_user" >/dev/null 2>&1; then
    useradd --system --gid "$service_group" --home-dir "$data_dir" --shell /usr/sbin/nologin "$service_user"
  fi
  verify_open_trusted_destination_directory "--prefix" "$prefix/bin" "$binary_dir_fd_path"
  verify_trusted_staged_file "--prefix" "$staged_binary" "$staged_binary_identity" "$binary_sha256"
  mv -fT -- "$staged_binary" "$binary_dir_fd_path/shellx-drive"
  staged_binary=""
  installed_binary_sha256="$(sha256sum "$binary_dir_fd_path/shellx-drive" | awk '{print $1}')"
  [[ "$installed_binary_sha256" == "$binary_sha256" ]] || { echo "installed binary SHA-256 mismatch" >&2; return 1; }
  exec {binary_dir_fd}<&-
  binary_dir_fd=""; binary_dir_fd_path=""
}

publish_trusted_service() {
  local tmp_service_identity="" rendered_service_sha256="" installed_service_sha256=""
  ensure_trusted_destination_directory "--service-dir" "$service_dir"
  open_trusted_destination_directory_fd "--service-dir" "$service_dir" service_dir_fd service_dir_fd_path
  tmp_service="$(mktemp "$service_dir_fd_path/.shellx-drive.service.XXXXXX")"
  render_service > "$tmp_service"
  chmod 0644 "$tmp_service"
  tmp_service_identity="$(capture_trusted_staged_file_identity "--service-dir" "$tmp_service")"
  rendered_service_sha256="$(sha256sum "$tmp_service" | awk '{print $1}')"
  verify_trusted_staged_file "--service-dir" "$tmp_service" "$tmp_service_identity" "$rendered_service_sha256"
  verify_open_trusted_destination_directory "--service-dir" "$service_dir" "$service_dir_fd_path"
  mv -fT -- "$tmp_service" "$service_dir_fd_path/shellx-drive.service"
  tmp_service=""
  installed_service_sha256="$(sha256sum "$service_dir_fd_path/shellx-drive.service" | awk '{print $1}')"
  [[ "$installed_service_sha256" == "$rendered_service_sha256" ]] || { echo "installed service schema SHA-256 mismatch" >&2; return 1; }
  exec {service_dir_fd}<&-
  service_dir_fd=""; service_dir_fd_path=""
}

cleanup_destination_publication() {
  [[ -z "${binary_dir_fd:-}" ]] || exec {binary_dir_fd}<&-
  [[ -z "${service_dir_fd:-}" ]] || exec {service_dir_fd}<&-
}
