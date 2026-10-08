#!/bin/bash

# Sourced by install_systemd.sh after it has pinned a trusted system PATH.
# Keep generation independent of OpenSSL so minimal Linux hosts can install.
generate_drive_secret() {
  local secret=""
  secret="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  if [[ ! "$secret" =~ ^[0-9a-f]{64}$ ]]; then
    echo "could not generate a 256-bit Drive secret" >&2
    return 1
  fi
  printf '%s' "$secret"
}

prepare_initial_drive_secrets() {
  INITIAL_OPERATOR_TOKEN="$(generate_drive_secret)"
  INITIAL_BOOTSTRAP_TOKEN="$(generate_drive_secret)"
  if [[ "$INITIAL_OPERATOR_TOKEN" == "$INITIAL_BOOTSTRAP_TOKEN" ]]; then
    echo "generated Drive secrets unexpectedly matched; refusing installation" >&2
    return 1
  fi
}
