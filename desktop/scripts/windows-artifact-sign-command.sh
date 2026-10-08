#!/bin/bash
set -euo pipefail
if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <windows-artifact>" >&2
  exit 2
fi
artifact_path="$1"
bootstrap_helper="${BASH_SOURCE[0]%/*}/windows-signing-callback-bootstrap.sh"
[[ ! -L "$bootstrap_helper" && -f "$bootstrap_helper" ]] \
  || { echo "trusted callback bootstrap is missing or unsafe" >&2; exit 1; }
source "$bootstrap_helper"
release_callback_bootstrap "${BASH_SOURCE[0]}" "$artifact_path"
callback_artifact_helper="$(release_helper_path CALLBACK_ARTIFACT)"
[[ ! -L "$callback_artifact_helper" && -f "$callback_artifact_helper" ]] \
  || { echo "trusted callback artifact helper is missing or unsafe" >&2; exit 1; }
source "$callback_artifact_helper"
metadata_path="${SHELLX_WINDOWS_SIGNING_METADATA_PATH:-}"
expected_metadata_sha256="${SHELLX_DRIVE_RELEASE_METADATA_SHA256:-}"
source_repo="${SHELLX_DRIVE_RELEASE_SOURCE_REPO:-}"
expected_commit="${SHELLX_DRIVE_EXPECTED_SOURCE_COMMIT:-}"
artifact_root="${SHELLX_DRIVE_RELEASE_ARTIFACT_ROOT:-}"
nsis_executable="${SHELLX_DRIVE_RELEASE_NSIS_EXECUTABLE:-}"
nsis_executable_sha256="${SHELLX_DRIVE_RELEASE_NSIS_EXECUTABLE_SHA256:-}"
release_build_started="${SHELLX_DRIVE_RELEASE_BUILD_STARTED:-}"
nsis_signing_stage_root="${SHELLX_DRIVE_RELEASE_NSIS_SIGNING_STAGE_ROOT:-}"
signing_receipt_path="${SHELLX_WINDOWS_SIGNING_RECEIPT_PATH:-}"
signing_stage_parent="${SHELLX_DRIVE_RELEASE_SIGNING_STAGE_PARENT:-}"
sign_command="$(release_helper_path SIGN_COMMAND)"
sign_script="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_SIGNER_PATH:-}"
release_security_helper="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_RELEASE_SECURITY_PATH:-}"
signing_components_helper="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_SIGNING_COMPONENTS_PATH:-}"
artifact_identity_helper="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_ARTIFACT_IDENTITY_PATH:-}"
release_callback_log_assert "${SHELLX_DRIVE_RELEASE_CALLBACK_LOG:-}" "$artifact_root"
callback_path="$("$READLINK_BIN" -f -- "$callback_path")"
if [[ "$callback_path" != "$sign_command" ]]; then
  echo "signing callback was not invoked from its admitted staged identity" >&2
  exit 1
fi

for required in metadata_path expected_metadata_sha256 source_repo expected_commit artifact_root signing_receipt_path signing_stage_parent sign_script release_security_helper signing_components_helper artifact_identity_helper; do
  if [[ -z "${!required}" ]]; then
    echo "canonical Drive release identity is missing: $required" >&2
    exit 1
  fi
done
if [[ ! "$expected_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected source commit must be a full lowercase Git object id" >&2
  exit 1
fi
callback_source_alias="-"
if [[ "$artifact_path" == "$artifact_root/shellx-drive-desktop.exe" ]]; then
  callback_source_alias="$artifact_root/deps/shellx_drive_desktop.exe"
fi
release_callback_capture_source_artifact "$artifact_path" "$callback_source_alias" || exit 1
if [[ ! -f "$metadata_path" || -L "$metadata_path" ]]; then
  echo "signing metadata must be a regular non-symlink file" >&2
  exit 1
fi

source_repo="$(cd "$source_repo" && pwd -P)"
artifact_root="$(cd "$artifact_root" && pwd -P)"
artifact_directory="$(cd "$("$DIRNAME_BIN" "$artifact_path")" && pwd -P)"
artifact_real="$artifact_directory/$("$BASENAME_BIN" "$artifact_path")"
receipt_directory="$(cd "$("$DIRNAME_BIN" "$signing_receipt_path")" && pwd -P)"
signing_receipt_real="$receipt_directory/$("$BASENAME_BIN" "$signing_receipt_path")"
signing_stage_parent="$(cd "$signing_stage_parent" && pwd -P)"
case "$signing_receipt_real" in
  "$artifact_root"/*) ;;
  *) echo "Windows signing receipt escaped the exact release target" >&2; exit 1 ;;
esac
if [[ -L "$signing_receipt_path" || ( -e "$signing_receipt_path" && ! -f "$signing_receipt_path" ) ]]; then
  echo "Windows signing receipt must be a regular non-symlink file" >&2
  exit 1
fi

verify_source_identity() {
  if [[ "$("$GIT_BIN" -C "$source_repo" rev-parse HEAD)" != "$expected_commit" \
    || -n "$("$GIT_BIN" -C "$source_repo" status --porcelain --untracked-files=all)" ]]; then
    echo "Drive source identity changed before an Authenticode operation" >&2
    exit 1
  fi
  release_helper_verify_all
  release_helper_verify_windows_stage
}

verify_source_identity
approved_nsis_uninstaller=0
staged_callback_artifact=""
callback_source_artifact=""
callback_label=""

cleanup_staged_callback_artifact() {
  if [[ -n "$staged_callback_artifact" && -f "$staged_callback_artifact" ]]; then
    "$UNLINK_BIN" -- "$staged_callback_artifact"
  fi
}
trap cleanup_staged_callback_artifact EXIT

case "$artifact_real" in
  "$artifact_root"/*) ;;
  *)
    if [[ "$artifact_directory" != "/tmp" \
      || ! "$("$BASENAME_BIN" "$artifact_real")" =~ ^makensis[A-Za-z0-9]{6}$ ]]; then
      echo "Windows signing artifact escaped the exact release target: $artifact_path" >&2
      exit 1
    fi
    if [[ ! "$release_build_started" =~ ^[0-9]{10}$ \
      || ! "$nsis_executable_sha256" =~ ^[0-9a-f]{64}$ \
      || -L "$nsis_executable" || ! -x "$nsis_executable" \
      || "$nsis_executable" != "$MAKENSIS_RESOLVED" \
      || "$nsis_executable_sha256" != "$MAKENSIS_SHA256" ]]; then
      echo "NSIS uninstaller signer identity is missing or drifted" >&2
      exit 1
    fi
    artifact_stat="$("$STAT_BIN" -c '%u:%a:%h:%Y' "$artifact_real")"
    if [[ "$artifact_stat" != "$("$ID_BIN" -u):600:1:"* \
      || "${artifact_stat##*:}" -lt "$release_build_started" \
      || "$(LC_ALL=C "$HEAD_BIN" -c 2 "$artifact_real")" != "MZ" ]]; then
      echo "NSIS uninstaller callback failed ownership, freshness, or PE checks" >&2
      exit 1
    fi
    signer_shell_pid="$PPID"
    makensis_pid="$("$AWK_BIN" '/^PPid:/{print $2}' "/proc/$signer_shell_pid/status" 2>/dev/null || true)"
    if [[ ! "$makensis_pid" =~ ^[0-9]+$ \
      || "$("$READLINK_BIN" -f "/proc/$makensis_pid/exe" 2>/dev/null || true)" != "$nsis_executable" ]]; then
      echo "NSIS uninstaller callback is not owned by the pinned makensis process" >&2
      exit 1
    fi
    nsis_cwd="$("$READLINK_BIN" -f "/proc/$makensis_pid/cwd" 2>/dev/null || true)"
    installer_script_found=0
    installer_script_count=0
    while IFS= read -r argument; do
      case "$argument" in
        /*) candidate_script="$argument" ;;
        *) candidate_script="$nsis_cwd/$argument" ;;
      esac
      case "$candidate_script" in
        *.nsi) installer_script_count=$((installer_script_count + 1)) ;;
        *) continue ;;
      esac
      if [[ -L "$candidate_script" || ! -f "$candidate_script" ]]; then
        continue
      fi
      candidate_script="$("$READLINK_BIN" -f "$candidate_script" 2>/dev/null || true)"
      case "$candidate_script" in
        "$artifact_root"/nsis/*/installer.nsi)
          candidate_script_stat="$("$STAT_BIN" -c '%u:%Y' "$candidate_script")"
          if [[ "$candidate_script_stat" == "$("$ID_BIN" -u):"* \
            && "${candidate_script_stat##*:}" -ge "$release_build_started" \
            && $("$GREP_BIN" -Fc '!uninstfinalize' "$candidate_script") -eq 1 \
            && $("$GREP_BIN" -Fc "$sign_command" "$candidate_script") -eq 1 ]]; then
            installer_script_found=1
          fi
          ;;
      esac
    done < <("$TR_BIN" '\0' '\n' < "/proc/$makensis_pid/cmdline")
    if [[ "$installer_script_count" != "1" || "$installer_script_found" != "1" ]]; then
      echo "NSIS uninstaller callback is not building the contained installer script" >&2
      exit 1
    fi
    case "$nsis_signing_stage_root" in
      /tmp/shellx-drive-nsis-signing-*) ;;
      *) echo "NSIS signing stage must be a private Drive directory under /tmp" >&2; exit 1 ;;
    esac
    if [[ -L "$nsis_signing_stage_root" || ! -d "$nsis_signing_stage_root" \
      || "$("$STAT_BIN" -c '%u:%a' "$nsis_signing_stage_root")" != "$("$ID_BIN" -u):700" ]]; then
      echo "NSIS signing stage failed ownership or mode checks" >&2
      exit 1
    fi
    nsis_signing_stage_root="$(cd "$nsis_signing_stage_root" && pwd -P)"
    if [[ "$("$DIRNAME_BIN" "$nsis_signing_stage_root")" != "/tmp" ]]; then
      echo "NSIS signing stage resolved outside /tmp" >&2
      exit 1
    fi
    staged_callback_artifact="$nsis_signing_stage_root/uninstaller-$makensis_pid-$("$BASENAME_BIN" "$artifact_real").exe"
    if [[ -e "$staged_callback_artifact" ]]; then
      echo "NSIS signing stage path is not fresh" >&2
      exit 1
    fi
    callback_source_artifact="$artifact_real"
    callback_label="NSIS uninstaller"
    release_callback_stage_artifact "$callback_source_artifact" "$staged_callback_artifact" || exit 1
    artifact_real="$staged_callback_artifact"
    echo "NSIS uninstaller signing callback accepted from pinned makensis"
    approved_nsis_uninstaller=1
    ;;
esac

# Every Tauri artifact is signed through a private byte-distinct copy. The
# original inode remains unsigned until the verified signed bytes are copied
# back; the special uninstaller path above retains its stronger provenance.
if [[ "$approved_nsis_uninstaller" != "1" \
  && ! "$artifact_real" =~ /[nN][sS][iI][sS]/.*/[pP][lL][uU][gG][iI][nN][sS]/ ]]; then
  case "$nsis_signing_stage_root" in
    /tmp/shellx-drive-nsis-signing-*) ;;
    *) echo "Tauri signing stage must be a private Drive directory under /tmp" >&2; exit 1 ;;
  esac
  if [[ -L "$nsis_signing_stage_root" || ! -d "$nsis_signing_stage_root" \
    || "$("$STAT_BIN" -c '%u:%a' "$nsis_signing_stage_root")" != "$("$ID_BIN" -u):700" ]]; then
    echo "Tauri signing stage failed ownership or mode checks" >&2
    exit 1
  fi
  callback_source_artifact="$artifact_real"
  callback_label="Tauri"
  staged_callback_artifact="$nsis_signing_stage_root/artifact-$PPID-$("$BASENAME_BIN" "$artifact_real")"
  if [[ -e "$staged_callback_artifact" ]]; then
    echo "Tauri signing stage path is not fresh" >&2
    exit 1
  fi
  release_callback_stage_artifact "$callback_source_artifact" "$staged_callback_artifact" || exit 1
  artifact_real="$staged_callback_artifact"
fi

case "$artifact_real" in
  *.[eE][xX][eE]|*.[mM][sS][iI]) ;;
  "$artifact_root"/[nN][sS][iI][sS]/*/[pP][lL][uU][gG][iI][nN][sS]/*/*.[dD][lL][lL]) ;;
  *)
    if [[ "$approved_nsis_uninstaller" != "1" ]]; then
      echo "unsupported Windows signing artifact type: $artifact_path" >&2
      exit 1
    fi
    ;;
esac

verify_source_identity
release_tool_verify_all
if [[ -n "$callback_source_artifact" ]]; then
  artifact_expected_sha256="$RELEASE_CALLBACK_UNSIGNED_SHA256"
  release_callback_assert_unsigned_stage "$artifact_real" || exit 1
else
  artifact_expected_sha256="$("$SHA256SUM_BIN" -- "$artifact_real")"
  artifact_expected_sha256="${artifact_expected_sha256%% *}"
fi
capture_args=()
if [[ "$callback_source_artifact" == "$artifact_root/shellx-drive-desktop.exe" ]]; then
  capture_args=(
    -CaptureDirectoryPath "$("$WSLPATH_BIN" -w "$signing_stage_parent")"
    -CaptureLeafName "shellx-drive-desktop.exe"
  )
fi
"$POWERSHELL_BIN" -NoProfile -NonInteractive -WindowStyle Hidden \
  -File "$("$WSLPATH_BIN" -w "$sign_script")" \
  -MetadataPath "$("$WSLPATH_BIN" -w "$metadata_path")" \
  -ReceiptPath "$("$WSLPATH_BIN" -w "$signing_receipt_real")" \
  -ExpectedArtifactSha256 "$artifact_expected_sha256" \
  -ExpectedMetadataSha256 "$expected_metadata_sha256" \
  -ExpectedSignerSha256 "$(release_helper_digest SIGNER)" \
  -ExpectedSecurityHelperSha256 "$(release_helper_digest RELEASE_SECURITY)" \
  -ExpectedComponentsHelperSha256 "$(release_helper_digest SIGNING_COMPONENTS)" \
  -ExpectedIdentityHelperSha256 "$(release_helper_digest ARTIFACT_IDENTITY)" \
  -SigningStageParentPath "$("$WSLPATH_BIN" -w "$signing_stage_parent")" \
  "${capture_args[@]}" \
  -Artifacts "$("$WSLPATH_BIN" -w "$artifact_real")"

if [[ -n "$callback_source_artifact" ]]; then
  release_callback_restore_artifact "$callback_source_artifact" "$staged_callback_artifact" "$callback_label" || exit 1
fi

cleanup_staged_callback_artifact
staged_callback_artifact=""
