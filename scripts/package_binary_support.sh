#!/bin/bash

# Static package closure. This file is sourced by package_binary.sh and is also
# copied into the archive so the documentation/installer input map is auditable.
support_sources=(
  "Cargo.toml"
  "scripts/package_binary_support.sh"
  "scripts/install_systemd.sh"
  "scripts/install_systemd_path_trust.sh"
  "scripts/install_systemd_destination_trust.sh"
  "scripts/install_systemd_secrets.sh"
  "scripts/install_systemd_service_config.sh"
  "scripts/install_systemd_lifecycle.sh"
  "scripts/install_systemd_data_dir.sh"
  "scripts/curl_secret_config.sh"
  "scripts/install_package.sh"
  "packaging/systemd/shellx-drive.service"
  "packaging/shellx-drive.env.example"
  "packaging/README.md"
  "README.md"
  "LICENSE"
  "NOTICE"
  "docs/public/DEBUG_API.md"
  "docs/public/DEBUG_SURFACES.json"
  "docs/public/CONFIG.md"
  "docs/public/FIRST_INSTALL.md"
  "docs/public/OPERATIONS.md"
  "docs/public/SUPPORT_AND_COMPATIBILITY.md"
  "docs/public/WINDOWS_DESKTOP.md"
  "docs/public/assets/screenshots/admin-center.png"
  "docs/public/assets/screenshots/guest-link-settings.png"
  "docs/public/assets/screenshots/image-preview.png"
  "docs/public/assets/screenshots/workspace-files.png"
  "skill/shellx-drive/SKILL.md"
  "skill/shellx-drive/reference.md"
  "CHANGELOG.md"
  "SECURITY.md"
  "docs/public/API.md"
  "docs/public/ARCHITECTURE.md"
  "docs/public/DESKTOP_SYNC_CONTRACT.md"
  "docs/public/LINUX_DESKTOP.md"
  "docs/public/MACOS_DESKTOP.md"
)

support_targets=("${support_sources[@]}")
support_modes=()
for index in "${!support_sources[@]}"; do
  support_modes+=("0644")
  case "${support_sources[$index]}" in
    scripts/install_package.sh)
      support_targets[$index]="install.sh"
      support_modes[$index]="0755"
      ;;
    scripts/install_systemd.sh|scripts/curl_secret_config.sh)
      support_modes[$index]="0755"
      ;;
  esac
done

stage_exact_git_support_sources() {
  local source_path linked_source_path
  for source_path in "${support_sources[@]}"; do
    case "$source_path" in
      ''|/*|.|..|../*|*/../*|*//*)
        echo "package support manifest has an unsafe source path: $source_path" >&2
        exit 1
        ;;
    esac
  done
  git -C "$repo_root" archive --format=tar "$source_revision" -- "${support_sources[@]}" \
    | tar -x -C "$source_stage"
  linked_source_path="$(find "$source_stage" -type l -print -quit)"
  [[ -z "$linked_source_path" ]] || { echo "Git-qualified package source closure contains a symbolic link" >&2; exit 1; }
}
