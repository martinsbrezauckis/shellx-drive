#!/usr/bin/env bash
# Externally admitted staged worker. The release controller owns source/tool admission.
set -euo pipefail
umask 077
bootstrap_fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for unsafe in BASH_ENV ENV PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH; do
  [[ -z "${!unsafe:-}" ]] || bootstrap_fail "unsafe ambient environment: $unsafe"
done
[[ "${LANG:-}" == C && "${LC_ALL:-}" == C && "${TZ:-}" == UTC && "${PATH:-}" == /* && "${GNUPGHOME:-}" == /* ]] \
  || bootstrap_fail "controller did not supply the admitted minimal environment"
[[ "${BASH_SOURCE[0]}" == /dev/fd/4 && "${SHELLX_DRIVE_ADMITTED_STAGE_ROOT:-}" == /* ]] || bootstrap_fail "worker and stage descriptors were not externally admitted"
stage="$SHELLX_DRIVE_ADMITTED_STAGE_ROOT"
admission=""; output=""
while [[ $# -gt 0 ]]; do case "$1" in
  --admission) admission="${2:-}"; shift 2;; --out) output="${2:-}"; shift 2;;
  *) bootstrap_fail "usage: $0 --admission /dev/fd/3 --out <fresh-absolute-directory>";; esac; done
[[ "$admission" == /dev/fd/3 && -e /dev/fd/3 && "$output" == /* ]] || bootstrap_fail "descriptor-bound admission and absolute output are required"
[[ -e /dev/fd/5 ]] || bootstrap_fail "controller did not retain the admitted parser descriptor"
assignments="$(python3 -I /dev/fd/5 verify-admission --admission "$admission" --stage-root "$stage" --output-root "$output" --format shell)" || bootstrap_fail "controller admission did not validate"
while IFS='=' read -r name value; do
  case "$name" in ADMISSION_*|TOOL_*) printf -v "$name" '%s' "$value";; *) bootstrap_fail "unexpected admission assignment";; esac
done <<<"$assignments"
[[ "$output" == "$ADMISSION_OUTPUT_ROOT" && "$PATH" == "$ADMISSION_TOOL_PATH_ROOT" ]] || bootstrap_fail "runtime escaped admitted roots"
source /dev/fd/100
source /dev/fd/101
linux_release_require_linux_x86_64
linux_release_require_signing_authority
[[ "$SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT" == "$ADMISSION_RELEASE_FINGERPRINT" ]] || linux_release_fail "signing fingerprint does not match admitted release identity"
linux_release_require_clean_output "$output"
LINUX_RELEASE_TEMP_ROOT="$output"; export LINUX_RELEASE_TEMP_ROOT
trap '"${TOOL_RM:-/bin/false}" -rf -- "$output"' ERR INT TERM
linux_release_private_copy "$ADMISSION_RELEASE_KEYRING" "$output/linux-release-keyring.gpg"
linux_release_require_regular "$output/linux-release-keyring.gpg" "packaged release public keyring"
GENERATED_TAURI_CONFIG="$output/tauri.linux.generated.json"; export GENERATED_TAURI_CONFIG
"$TOOL_PYTHON3" -I /dev/fd/102 --stage "$stage" --linux-config /dev/fd/111 --keyring "$output/linux-release-keyring.gpg" --out "$GENERATED_TAURI_CONFIG"
linux_build_signed_artifacts "$stage" "$output"
mapfile -t appimages < <("$TOOL_FIND" "$output" -maxdepth 1 -type f -name '*.AppImage' -print)
mapfile -t debs < <("$TOOL_FIND" "$output" -maxdepth 1 -type f -name '*.deb' -print)
[[ ${#appimages[@]} == 1 && ${#debs[@]} == 1 ]] || linux_release_fail "output must have one AppImage and one Debian package"
appimage="${appimages[0]}"; deb="${debs[0]}"; appimage_updater_signature="$appimage.sig"; deb_updater_signature="$deb.sig"
linux_release_sign_debian_package "$TOOL_DPKG_SIG" "$deb" "$SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT"
deb_status="$(linux_release_verify_debian_package "$TOOL_DPKG_SIG" "$deb" 2>&1)" || linux_release_fail "Debian signature did not verify"
"$TOOL_GREP" -Fqi "$SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT" <<<"$deb_status" || linux_release_fail "Debian signer identity drifted"
appimage_status="$("$TOOL_APPIMAGE_VALIDATOR" "$appimage" 2>&1)" || linux_release_fail "AppImage signature did not verify"
"$TOOL_GREP" -Fq 'Validation result: validation successful' <<<"$appimage_status" || linux_release_fail "AppImage validator did not report success"
"$TOOL_GREP" -Fqi "$SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT" <<<"$appimage_status" || linux_release_fail "AppImage signer identity drifted"
# Sign only the final package bytes under their admitted version/platform names.
"$TOOL_TAURI_CLI" signer sign "$appimage"
"$TOOL_TAURI_CLI" signer sign "$deb"
linux_release_require_regular "$appimage_updater_signature" "AppImage Tauri updater signature"
linux_release_require_regular "$deb_updater_signature" "Debian Tauri updater signature"
"$TOOL_TAURI_UPDATER_VERIFIER" --config /dev/fd/110 --installer "$appimage" --signature "$appimage_updater_signature"
"$TOOL_TAURI_UPDATER_VERIFIER" --config /dev/fd/110 --installer "$deb" --signature "$deb_updater_signature"
layout_observation="$output/linux-package-layout-observation.v1.json"
"$TOOL_PYTHON3" -I /dev/fd/103 --deb "$deb" --appimage "$appimage" --dpkg-deb "$TOOL_DPKG_DEB" --unsquashfs "$TOOL_UNSQUASHFS" --work-root "$output" --out "$layout_observation"
"$TOOL_RM" -rf -- "$output/build-target" "$output/debian-verifier-resources" "$GENERATED_TAURI_CONFIG"
manifest="$output/linux-candidate-manifest.v1.json"
"$TOOL_NODE" /dev/fd/104 --source-commit "$ADMISSION_SOURCE_COMMIT" --source-tree "$ADMISSION_SOURCE_TREE" --appimage "$appimage" --deb "$deb" --appimage-updater-signature "$appimage_updater_signature" --deb-updater-signature "$deb_updater_signature" --release-key-fingerprint "$SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT" --out "$manifest"
"$TOOL_NODE" /dev/fd/105 --platform linux-x86_64 --version-config /dev/fd/110 --source-commit "$ADMISSION_SOURCE_COMMIT" --source-tree "$ADMISSION_SOURCE_TREE" --artifact "$appimage" --signature "$appimage_updater_signature" --identity-kind openpgp --identity-evidence "$manifest" --out "$output/linux-updater-candidate.json"
"$TOOL_NODE" /dev/fd/105 --platform linux-x86_64-deb --version-config /dev/fd/110 --source-commit "$ADMISSION_SOURCE_COMMIT" --source-tree "$ADMISSION_SOURCE_TREE" --artifact "$deb" --signature "$deb_updater_signature" --identity-kind openpgp --identity-evidence "$manifest" --out "$output/linux-deb-updater-candidate.json"
"$TOOL_GPG" --batch --yes --armor --local-user "$SHELLX_DRIVE_LINUX_RELEASE_KEY_FINGERPRINT" --detach-sign --output "$manifest.asc" "$manifest"
observation="$output/linux-release-worker-observation.v1.json"
"$TOOL_PYTHON3" -I /dev/fd/5 verify-continuity --admission "$admission" --stage-root "$stage" --output-root "$output" --format shell >/dev/null
"$TOOL_PYTHON3" -I /dev/fd/106 --post-continuity-pass --admission "$admission" --candidate-dir "$output" --manifest "$manifest" --layout "$layout_observation" --out "$observation"
trap - ERR INT TERM
printf 'LINUX_RELEASE_WORKER_COMPLETE source_commit=%s source_tree=%s observation=%s\n' "$ADMISSION_SOURCE_COMMIT" "$ADMISSION_SOURCE_TREE" "$observation"
