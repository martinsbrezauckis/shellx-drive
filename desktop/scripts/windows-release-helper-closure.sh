#!/bin/bash
# Commit-bound admission and private staging for the Windows release helpers.
# The release entry point copies this file before sourcing it; every subsequent
# helper is then loaded or executed only from the protected stage.

readonly RELEASE_HELPER_GIT=/usr/bin/git
readonly RELEASE_HELPER_SHA256SUM=/usr/bin/sha256sum
readonly RELEASE_HELPER_STAT=/usr/bin/stat
readonly RELEASE_HELPER_ID=/usr/bin/id
readonly RELEASE_HELPER_CP=/usr/bin/cp
readonly RELEASE_HELPER_CHMOD=/usr/bin/chmod
readonly RELEASE_HELPER_READLINK=/usr/bin/readlink
readonly RELEASE_HELPER_RM=/usr/bin/rm
declare -ag RELEASE_HELPER_KEYS=()

release_helper_fail() {
  echo "FAIL: $*" >&2
  return 1
}

release_helper_specs() {
  printf '%s\n' \
    'BUILD_ENTRY desktop/scripts/build-windows-nsis-from-wsl.sh build-windows-nsis-from-wsl.sh' \
    'BUILD_BODY desktop/scripts/windows-release-build-body.sh windows-release-build-body.sh' \
    'CLOSURE desktop/scripts/windows-release-helper-closure.sh windows-release-helper-closure.sh' \
    'SOURCE_STAGE desktop/scripts/windows-release-source-stage.sh windows-release-source-stage.sh' \
    'SOURCE_MANIFEST desktop/scripts/windows-release-build-manifest.mjs windows-release-build-manifest.mjs' \
    'SOURCE_CONTEXT desktop/scripts/windows-release-source-context.sh windows-release-source-context.sh' \
    'UPDATER desktop/scripts/windows-release-updater.sh windows-release-updater.sh' \
    'UPDATER_CANDIDATE_WRITER desktop/scripts/write-updater-candidate.mjs write-updater-candidate.mjs' \
    'UPDATER_CANDIDATE_CORE desktop/scripts/updater-candidate-core.mjs updater-candidate-core.mjs' \
    'TOOLCHAIN desktop/scripts/windows-release-toolchain.sh windows-release-toolchain.sh' \
    'CLEANUP desktop/scripts/windows-release-cleanup.sh windows-release-cleanup.sh' \
    'CANDIDATE_OUTPUT desktop/scripts/windows-candidate-output.sh windows-candidate-output.sh' \
    'SIGNED_CANDIDATE desktop/scripts/windows-signed-candidate.sh windows-signed-candidate.sh' \
    'CANDIDATE_PROVENANCE desktop/scripts/windows-candidate-provenance.sh windows-candidate-provenance.sh' \
    'CANDIDATE_GUIDE desktop/scripts/windows-candidate-guide.sh windows-candidate-guide.sh' \
    'SIGN_COMMAND desktop/scripts/windows-artifact-sign-command.sh windows-artifact-sign-command.sh' \
    'CALLBACK_BOOTSTRAP desktop/scripts/windows-signing-callback-bootstrap.sh windows-signing-callback-bootstrap.sh' \
    'CALLBACK_LOG desktop/scripts/windows-signing-callback-log.sh windows-signing-callback-log.sh' \
    'CALLBACK_ARTIFACT desktop/scripts/windows-signing-callback-artifact.sh windows-signing-callback-artifact.sh' \
    'CALLBACK_FILE desktop/scripts/windows-signing-callback-file.mjs windows-signing-callback-file.mjs' \
    'PS_STAGE desktop/scripts/windows-release-helper-stage.ps1 windows-release-helper-stage.ps1' \
    'SIGNER desktop/scripts/windows-artifact-sign.ps1 windows-artifact-sign.ps1' \
    'RELEASE_SECURITY desktop/scripts/windows-release-security.ps1 windows-release-security.ps1' \
    'SIGNING_COMPONENTS desktop/scripts/windows-signing-components.ps1 windows-signing-components.ps1' \
    'ARTIFACT_IDENTITY desktop/scripts/windows-artifact-identity.ps1 windows-artifact-identity.ps1'
}

release_helper_expected_names() {
  local key relative leaf names=""
  while read -r key relative leaf; do names="${names:+$names }$key"; done < <(release_helper_specs)
  printf '%s\n' "$names"
}

release_helper_assert_private_home() {
  local current="$HOME" owner mode kind numeric uid root_owner
  uid="$("$RELEASE_HELPER_ID" -u)"; root_owner="$("$RELEASE_HELPER_STAT" -c '%u' -- /)" || return 1
  [[ "$current" == /* && ! -L "$current" && -d "$current" \
    && "$current" == "$(cd -- "$current" && pwd -P)" ]] \
    || { release_helper_fail "release home is not a real absolute directory"; return 1; }
  while :; do
    read -r owner mode kind < <("$RELEASE_HELPER_STAT" -c '%u %a %F' -- "$current") || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    numeric=$((8#$mode))
    if [[ "$kind" != directory || ! "$owner" =~ ^[0-9]+$ \
      || ( "$owner" != "$root_owner" && "$owner" != "$uid" ) \
      || ( "$current" == "$HOME" && "$owner" != "$uid" ) ]] \
      || (( (numeric & 0022) != 0 )); then
      release_helper_fail "release home parent is writable or untrusted: $current"
      return 1
    fi
    [[ "$current" == / ]] && return 0
    current="${current%/*}"; [[ -n "$current" ]] || current=/
  done
}

release_helper_assert_stage() {
  local stage="$1" identity
  release_helper_assert_private_home || return 1
  if [[ "${stage%/*}" != "$HOME" \
    || ! "${stage##*/}" =~ ^\.shellx-drive-release-helpers-[A-Za-z0-9._-]+$ \
    || -L "$stage" || ! -d "$stage" ]]; then
    release_helper_fail "release helper stage is not a private absolute Drive path"
    return 1
  fi
  identity="$("$RELEASE_HELPER_STAT" -c '%u:%a:%F' -- "$stage")"
  if [[ "$identity" != "$("$RELEASE_HELPER_ID" -u):700:directory" ]]; then
    release_helper_fail "release helper stage failed ownership or mode checks"
    return 1
  fi
}

release_helper_source_is_exact() {
  local repo="$1" commit="$2"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] \
    || { release_helper_fail "release helper source commit is invalid"; return 1; }
  if [[ "$("$RELEASE_HELPER_GIT" -C "$repo" rev-parse HEAD)" != "$commit" \
    || -n "$("$RELEASE_HELPER_GIT" -C "$repo" status --porcelain --untracked-files=all)" ]]; then
    release_helper_fail "Drive source identity changed from the selected exact commit"
    return 1
  fi
}

release_helper_commit_digest() {
  local repo="$1" commit="$2" relative="$3" digest
  digest="$("$RELEASE_HELPER_GIT" -C "$repo" show "$commit:$relative" | "$RELEASE_HELPER_SHA256SUM")" \
    || return 1
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

release_helper_stage_all() {
  local repo="$1" commit="$2" stage="$3" key relative leaf source destination expected actual
  repo="$(cd -- "$repo" && pwd -P)"
  stage="$(cd -- "$stage" && pwd -P)"
  release_helper_assert_stage "$stage" || return 1
  release_helper_source_is_exact "$repo" "$commit" || return 1
  RELEASE_HELPER_KEYS=()
  while read -r key relative leaf; do
    source="$repo/$relative"; destination="$stage/$leaf"
    if [[ -L "$source" || ! -f "$source" ]]; then
      release_helper_fail "release helper source is missing or linked: $relative"; return 1
    fi
    expected="$(release_helper_commit_digest "$repo" "$commit" "$relative")" \
      || { release_helper_fail "could not derive committed helper digest: $relative"; return 1; }
    actual="$("$RELEASE_HELPER_SHA256SUM" -- "$source")"; actual="${actual%% *}"
    if [[ "$actual" != "$expected" ]]; then
      release_helper_fail "release helper source differs from the exact commit: $relative"; return 1
    fi
    if [[ "$key" != "CLOSURE" && ( "$key" != "BUILD_ENTRY" || ! -e "$destination" ) ]]; then
      [[ ! -e "$destination" && ! -L "$destination" ]] \
        || { release_helper_fail "release helper staging path already exists: $leaf"; return 1; }
      "$RELEASE_HELPER_CP" --no-dereference -- "$source" "$destination"
      "$RELEASE_HELPER_CHMOD" 0500 "$destination"
    fi
    actual="$("$RELEASE_HELPER_SHA256SUM" -- "$destination")"; actual="${actual%% *}"
    if [[ -L "$destination" || ! -f "$destination" || "$actual" != "$expected" ]]; then
      release_helper_fail "private staged helper identity mismatch: $leaf"; return 1
    fi
    printf -v "SHELLX_DRIVE_RELEASE_HELPER_${key}_PATH" '%s' "$destination"
    printf -v "SHELLX_DRIVE_RELEASE_HELPER_${key}_SHA256" '%s' "$expected"
    export "SHELLX_DRIVE_RELEASE_HELPER_${key}_PATH" \
      "SHELLX_DRIVE_RELEASE_HELPER_${key}_SHA256"
    RELEASE_HELPER_KEYS+=("$key")
  done < <(release_helper_specs)
  SHELLX_DRIVE_RELEASE_HELPER_STAGE="$stage"
  SHELLX_DRIVE_RELEASE_HELPER_NAMES="$(release_helper_expected_names)"
  export SHELLX_DRIVE_RELEASE_HELPER_STAGE SHELLX_DRIVE_RELEASE_HELPER_NAMES
  release_helper_source_is_exact "$repo" "$commit" || return 1
  release_helper_verify_all
}

release_helper_verify_identity() {
  local key="$1" relative leaf path_name hash_name selected expected actual stage
  while read -r relative _ leaf; do [[ "$relative" == "$key" ]] && break; done < <(release_helper_specs)
  [[ "$relative" == "$key" ]] || { release_helper_fail "unknown release helper identity: $key"; return 1; }
  stage="${SHELLX_DRIVE_RELEASE_HELPER_STAGE:-}"
  release_helper_assert_stage "$stage" || return 1
  path_name="SHELLX_DRIVE_RELEASE_HELPER_${key}_PATH"
  hash_name="SHELLX_DRIVE_RELEASE_HELPER_${key}_SHA256"
  selected="${!path_name:-}"; expected="${!hash_name:-}"
  if [[ "$selected" != "$stage/$leaf" || ! "$expected" =~ ^[0-9a-f]{64}$ \
    || -L "$selected" || ! -f "$selected" \
    || "$("$RELEASE_HELPER_STAT" -c '%u:%a:%F' -- "$selected")" \
      != "$("$RELEASE_HELPER_ID" -u):500:regular file" ]]; then
    release_helper_fail "release helper staged path or protection drifted: $key"; return 1
  fi
  actual="$("$RELEASE_HELPER_SHA256SUM" -- "$selected")"; actual="${actual%% *}"
  [[ "$actual" == "$expected" ]] \
    || { release_helper_fail "release helper staged bytes drifted: $key"; return 1; }
}

release_helper_import() {
  local expected key
  expected="$(release_helper_expected_names)"
  [[ "${SHELLX_DRIVE_RELEASE_HELPER_NAMES:-}" == "$expected" ]] \
    || { release_helper_fail "release helper identity manifest is incomplete"; return 1; }
  read -r -a RELEASE_HELPER_KEYS <<< "$expected"
  for key in "${RELEASE_HELPER_KEYS[@]}"; do release_helper_verify_identity "$key" || return 1; done
}

release_helper_verify_all() {
  local key
  for key in "${RELEASE_HELPER_KEYS[@]}"; do release_helper_verify_identity "$key" || return 1; done
}

release_helper_path() {
  local variable="SHELLX_DRIVE_RELEASE_HELPER_${1}_PATH"
  printf '%s\n' "${!variable}"
}

release_helper_digest() {
  local variable="SHELLX_DRIVE_RELEASE_HELPER_${1}_SHA256"
  printf '%s\n' "${!variable}"
}

release_helper_verify_windows_stage() {
  local key path variable actual
  for key in SIGNER RELEASE_SECURITY SIGNING_COMPONENTS ARTIFACT_IDENTITY; do
    variable="SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_${key}_PATH"; path="${!variable:-}"
    [[ "$path" == "${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE:-}/"* \
      && ! -L "$path" && -f "$path" ]] \
      || { release_helper_fail "Windows private helper path is missing: $key"; return 1; }
    actual="$("$RELEASE_HELPER_SHA256SUM" -- "$path")"; actual="${actual%% *}"
    [[ "$actual" == "$(release_helper_digest "$key")" ]] \
      || { release_helper_fail "Windows private helper bytes drifted: $key"; return 1; }
  done
}

release_helper_stage_windows() {
  local staging_helper result windows_stage admission
  release_helper_verify_all || return 1
  admission="$("$NODE_BIN" "$WINDOWS_SIGNING_ADMISSION_RESOLVED" admit \
    --kind release-helpers --source-root "$SHELLX_DRIVE_RELEASE_HELPER_STAGE")" || return 1
  staging_helper="$("$NODE_BIN" -e '
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(0, "utf8"));
    const specs = {"windows-release-helper-stage.ps1":"PS_STAGE", "windows-release-security.ps1":"RELEASE_SECURITY", "windows-signing-components.ps1":"SIGNING_COMPONENTS", "windows-artifact-identity.ps1":"ARTIFACT_IDENTITY", "windows-artifact-sign.ps1":"SIGNER"};
    if (value.kind !== "release-helpers" || value.host?.policy !== "RemoteSigned" || value.files?.length !== 5) process.exit(2);
    for (const [name, key] of Object.entries(specs)) {
      const file = value.files.find(entry => entry.name === name);
      if (!file || file.sha256 !== process.env[`SHELLX_DRIVE_RELEASE_HELPER_${key}_SHA256`]) process.exit(2);
    }
    process.stdout.write(value.executable);
  ' <<< "$admission")" || return 1
  SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_PS_STAGE_PATH="$("$WSLPATH_BIN" -u "$staging_helper")"
  export SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_PS_STAGE_PATH
  staging_helper="$SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_PS_STAGE_PATH"
  result="$("$POWERSHELL_BIN" -NoProfile -NonInteractive -WindowStyle Hidden \
    -File "$("$WSLPATH_BIN" -w "$staging_helper")" \
    -SourceDirectoryPath "$("$WSLPATH_BIN" -w "${staging_helper%/*}")" \
    -ExpectedStageHelperSha256 "$(release_helper_digest PS_STAGE)" \
    -ExpectedSecurityHelperSha256 "$(release_helper_digest RELEASE_SECURITY)" \
    -ExpectedComponentsHelperSha256 "$(release_helper_digest SIGNING_COMPONENTS)" \
    -ExpectedIdentityHelperSha256 "$(release_helper_digest ARTIFACT_IDENTITY)" \
    -ExpectedSignerSha256 "$(release_helper_digest SIGNER)")" || return 1
  windows_stage="$("$NODE_BIN" -e '
    const fs = require("node:fs");
    const lines = fs.readFileSync(0, "utf8").trim().split(/\r?\n/);
    const value = JSON.parse(lines.at(-1));
    if (typeof value.stage_path !== "string" || !value.stage_path) process.exit(2);
    process.stdout.write(value.stage_path);
  ' <<< "$result")" || return 1
  SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE="$("$WSLPATH_BIN" -u "$windows_stage")"
  SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_SIGNER_PATH="$SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE/windows-artifact-sign.ps1"
  SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_RELEASE_SECURITY_PATH="$SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE/windows-release-security.ps1"
  SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_SIGNING_COMPONENTS_PATH="$SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE/windows-signing-components.ps1"
  SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_ARTIFACT_IDENTITY_PATH="$SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE/windows-artifact-identity.ps1"
  export SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE \
    SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_SIGNER_PATH \
    SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_RELEASE_SECURITY_PATH \
    SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_SIGNING_COMPONENTS_PATH \
    SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_ARTIFACT_IDENTITY_PATH
  release_helper_verify_windows_stage
}

release_helper_remove_windows_stage() {
  local stage="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE:-}" staging_helper
  [[ -n "$stage" ]] || return 0
  staging_helper="${SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_PS_STAGE_PATH:?}"
  release_helper_verify_all || return 1
  local actual
  actual="$("$RELEASE_HELPER_SHA256SUM" -- "$staging_helper")"; actual="${actual%% *}"
  [[ ! -L "$staging_helper" && "$actual" == "$(release_helper_digest PS_STAGE)" ]] || return 1
  "$POWERSHELL_BIN" -NoProfile -NonInteractive -WindowStyle Hidden \
    -File "$("$WSLPATH_BIN" -w "$staging_helper")" \
    -SourceDirectoryPath "$("$WSLPATH_BIN" -w "${staging_helper%/*}")" \
    -ExpectedStageHelperSha256 "$(release_helper_digest PS_STAGE)" \
    -ExpectedSecurityHelperSha256 "$(release_helper_digest RELEASE_SECURITY)" \
    -RemovePrivateDirectoryPath "$("$WSLPATH_BIN" -w "$stage")"
  SHELLX_DRIVE_RELEASE_HELPER_WINDOWS_STAGE=""
}

release_helper_remove_stage() {
  local stage="${SHELLX_DRIVE_RELEASE_HELPER_STAGE:-}"
  [[ -z "$stage" ]] || { release_helper_assert_stage "$stage" && "$RELEASE_HELPER_RM" -rf -- "$stage"; }
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from a privately staged release entry" >&2
  exit 2
fi
