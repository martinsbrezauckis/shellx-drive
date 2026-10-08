#!/usr/bin/env bash
set -uo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <Cargo.lock>" >&2
  exit 2
fi

lockfile="$1"
if [[ ! -f "$lockfile" ]]; then
  echo "RustSec lockfile is missing: $lockfile" >&2
  exit 2
fi

# cargo-audit resolves the crates.io index layout by invoking cargo even when
# CARGO_AUDIT_BIN points directly at the audit executable.
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required on PATH for crates.io yank verification" >&2
  exit 2
fi

if [[ -n "${CARGO_AUDIT_BIN:-}" ]]; then
  audit=("$CARGO_AUDIT_BIN" audit)
else
  audit=(cargo audit)
fi

help="$("${audit[@]}" --help 2>&1)" || {
  echo "cargo-audit could not report its supported options" >&2
  exit 2
}

advisory_status=0
if grep -q -- '--no-yanked' <<<"$help"; then
  echo "RustSec advisory pass (independent of crates.io yank availability): $lockfile"
  "${audit[@]}" --no-yanked --file "$lockfile" || advisory_status=$?
fi

yank_status=1
yank_index_warning=0
for attempt in 1 2 3; do
  echo "RustSec full advisory + yank pass $attempt/3: $lockfile"
  full_args=(--deny yanked --file "$lockfile")
  if [[ "$attempt" -gt 1 ]]; then
    full_args=(--no-fetch "${full_args[@]}")
  fi

  full_output="$("${audit[@]}" "${full_args[@]}" 2>&1)"
  full_status=$?
  printf '%s\n' "$full_output"

  if grep -Eq "couldn't (update|open) crates\.io index|couldn't check if (the )?package is yanked|Data may be missing or stale when checking for yanked packages" <<<"$full_output"; then
    echo "RustSec did not verify crates.io yank status on attempt $attempt" >&2
    yank_index_warning=1
    [[ "$full_status" -ne 0 ]] && yank_status="$full_status" || yank_status=1
  elif [[ "$full_status" -eq 0 && "$yank_index_warning" -eq 0 ]]; then
    yank_status=0
    break
  elif [[ "$full_status" -eq 0 ]]; then
    yank_status=1
  else
    yank_status="$full_status"
  fi
  if [[ "$attempt" -lt 3 ]]; then
    sleep $((attempt * 2))
  fi
done

if [[ "$advisory_status" -ne 0 ]]; then
  echo "RustSec advisory scan failed for $lockfile" >&2
fi
if [[ "$yank_status" -ne 0 ]]; then
  echo "RustSec full scan, including crates.io yank status, failed after 3 attempts for $lockfile" >&2
fi
if [[ "$advisory_status" -ne 0 || "$yank_status" -ne 0 ]]; then
  exit 1
fi
