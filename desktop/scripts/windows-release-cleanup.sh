#!/bin/bash
# Best-effort release cleanup. Every subsection runs even if another fails.
cleanup_build_state() {
  local exit_status=$? failed=0
  if [[ -n "$build_log" && -f "$build_log" || -n "$callback_log" && -f "$callback_log" ]]; then
    local evidence_root="${SHELLX_DRIVE_WINDOWS_EVIDENCE_ROOT:-${source_repo:-$repo_root}/.release/evidence/windows-build}" evidence_dir=""
    if [[ -L "$evidence_root" || ( -z "${SHELLX_DRIVE_WINDOWS_EVIDENCE_ROOT:-}" && \
        ( -L "${source_repo:-$repo_root}/.release" || -L "${source_repo:-$repo_root}/.release/evidence" ) ) || ( -n "${SHELLX_DRIVE_WINDOWS_EVIDENCE_ROOT:-}" && \
        ( "$evidence_root" != /* || "$(readlink -f -- "${evidence_root%/*}")" != "${evidence_root%/*}" ) ) ]] \
      || ! "$MKDIR_BIN" -p -m 0700 -- "$evidence_root"; then
      echo "WARN: Windows build evidence directory is unavailable: $evidence_root" >&2
      failed=1
    else
      evidence_dir="$("$MKTEMP_BIN" -d "$evidence_root/${short_revision}.XXXXXX")" || failed=1
      if [[ -n "$evidence_dir" ]]; then
        local log label digest retained_digest retained_log
        for label in build signing-callback; do
          [[ "$label" == build ]] && log="$build_log" || log="$callback_log"
          [[ -n "$log" && -f "$log" ]] || continue
          retained_log="$evidence_dir/$label.log"
          if [[ -L "$log" ]] || ! digest="$("$SHA256SUM_BIN" -- "$log")" \
            || ! "$CP_BIN" --no-dereference -- "$log" "$retained_log" || [[ -L "$retained_log" || ! -f "$retained_log" ]] \
            || ! "$CHMOD_BIN" 0600 -- "$retained_log" || ! retained_digest="$("$SHA256SUM_BIN" -- "$retained_log")" \
            || [[ "${digest%% *}" != "${retained_digest%% *}" ]] \
            || ! printf 'result=%s\nsha256=%s\n' "$([[ "$exit_status" == 0 ]] && echo passed || echo failed)" "${retained_digest%% *}" > "$evidence_dir/$label.status" || ! "$CHMOD_BIN" 0600 -- "$evidence_dir/$label.status"; then
            echo "WARN: Windows $label log retention failed; original retained" >&2
            failed=1
            continue
          fi
          "$RM_BIN" -f -- "$log" || failed=1
        done
        echo "Windows build evidence ($([[ "$exit_status" == "0" ]] && echo passed || echo failed)): $evidence_dir" >&2
      fi
    fi
  fi
  if [[ -n "$nsis_signing_stage_root" && -d "$nsis_signing_stage_root" ]]; then "$RMDIR_BIN" -- "$nsis_signing_stage_root" 2>/dev/null || failed=1; fi
  if [[ "$signing_required" == "1" && -n "$release_helper_stage" ]]; then
    release_helper_remove_windows_stage || { echo "WARN: private Windows release helper stage cleanup failed" >&2; failed=1; }
  fi
  cleanup_candidate_output || { echo "WARN: Windows candidate output cleanup failed" >&2; failed=1; }
  if [[ "$failed" == "0" && "$signing_required" == "1" && -n "${SHELLX_DRIVE_RELEASE_SOURCE_STAGE:-}" ]]; then
    release_source_stage_remove || { echo "WARN: private Windows release source stage cleanup failed" >&2; failed=1; }
  fi
  if [[ "$signing_required" == "1" && -n "$release_helper_stage" ]]; then
    release_helper_remove_stage || { echo "WARN: private WSL release helper stage cleanup failed" >&2; failed=1; }
    release_helper_stage=""
  fi
  return "$failed"
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-release-build-body.sh" >&2; exit 2
fi
