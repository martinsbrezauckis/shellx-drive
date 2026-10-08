#!/bin/bash

# Sourced by install_systemd.sh after it has pinned a trusted system PATH.
validate_bind_address() {
  local value="$1"
  if [[ "$value" =~ [[:cntrl:][:space:]] ]] || [[ "$value" != *:* ]]; then
    echo "--bind must be a host or IP address followed by a numeric port" >&2
    exit 2
  fi
  local host="${value%:*}"
  local port="${value##*:}"
  if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] \
    || { [[ ! "$host" =~ ^[A-Za-z0-9.-]+$ ]] && [[ ! "$host" =~ ^\[[0-9A-Fa-f:.%]+\]$ ]]; }; then
    echo "--bind must be a host or IP address followed by a numeric port" >&2
    exit 2
  fi
  local port_number=$((10#$port))
  if (( port_number < 1 || port_number > 65535 )); then
    echo "--bind port must be between 1 and 65535" >&2
    exit 2
  fi
}

validate_public_base_url() {
  local value="$1" port="" authority="" host="" label=""
  local IFS=.
  local -a labels=()
  local port=""
  if [[ "$value" =~ [[:cntrl:][:space:]] ]] \
    || [[ ! "$value" =~ ^https://([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$ ]]; then
    echo "--public-base-url must be an HTTPS origin with host and optional numeric port; do not include a path, query, fragment, or credentials" >&2
    exit 2
  fi
  port="${value##*:}"
  if [[ "$port" =~ ^[0-9]+$ ]] && (( 10#$port < 1 || 10#$port > 65535 )); then
    echo "--public-base-url port must be between 1 and 65535" >&2
    exit 2
  fi
  [[ "$value" == https://\[* ]] && return
  authority="${value#https://}"
  host="${authority%%:*}"
  read -r -a labels <<< "$host"
  for label in "${labels[@]}"; do
    if [[ ! "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]; then
      echo "--public-base-url host labels must start and end with an alphanumeric character" >&2
      exit 2
    fi
  done
}
