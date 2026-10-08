#!/bin/bash

# Sourced by install_systemd.sh after it has pinned a trusted system PATH.
require_stopped_upgrade_service() {
  local existing_environment="$1"
  if [[ "$existing_environment" -eq 1 ]] \
    && systemctl is-active --quiet shellx-drive.service; then
    echo "stop shellx-drive.service and wait for it to exit before upgrading" >&2
    exit 1
  fi
}
