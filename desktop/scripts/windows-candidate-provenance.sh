#!/bin/bash
# Create and U1C-sign a detached candidate manifest that authenticates the
# source revision, artifact digests, and the operational signing receipt.
candidate_guide_helper="${BASH_SOURCE[0]%/*}/windows-candidate-guide.sh"
if [[ -L "$candidate_guide_helper" || ! -f "$candidate_guide_helper" ]]; then
  echo "FAIL: candidate guide helper is missing or unsafe" >&2
  return 1 2>/dev/null || exit 1
fi
# shellcheck source=windows-candidate-guide.sh
source "$candidate_guide_helper"
publish_signed_candidate_provenance() {
  local payload_path operation_receipt payload_sha256 receipt_sha256 source_manifest_sha256
  local provenance_pre_sign_sha256 provenance_output_sha256
  local provenance_leaf="windows-candidate-provenance.ps1"
  payload_path="$artifact_root/.windows-candidate-provenance-${short_revision}.ps1"
  operation_receipt="$artifact_root/.windows-candidate-provenance-operation.jsonl"
  if [[ -e "$payload_path" || -L "$payload_path" \
    || -e "$operation_receipt" || -L "$operation_receipt" ]]; then
    echo "FAIL: Windows candidate provenance staging paths are not fresh" >&2
    return 1
  fi
  receipt_sha256="$($SHA256SUM_BIN -- "$signing_receipt")"
  receipt_sha256="${receipt_sha256%% *}"
  source_manifest_sha256="${SHELLX_DRIVE_RELEASE_SOURCE_MANIFEST_SHA256:-}"
  if [[ ! "$source_manifest_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "FAIL: signed candidate provenance requires the exact source manifest digest" >&2
    return 1
  fi
  "$NODE_BIN" -e '
    const fs = require("node:fs");
    const [path, source, sourceManifestHash, receiptHash, desktopLeaf, desktopHash, installerLeaf, installerHash, updaterSignatureLeaf, updaterSignatureHash, updaterCandidateLeaf, updaterCandidateHash, guideLeaf, guideHash] = process.argv.slice(1);
    const payload = {
      schema: "shellx-drive.windows-candidate-provenance/v3",
      source_commit: source,
      source_manifest_sha256: sourceManifestHash,
      signing_receipt_sha256: receiptHash,
      artifacts: [
        { kind: "desktop", leaf: desktopLeaf, sha256: desktopHash },
        { kind: "installer", leaf: installerLeaf, sha256: installerHash },
        { kind: "updater-signature", leaf: updaterSignatureLeaf, sha256: updaterSignatureHash },
        { kind: "updater-candidate", leaf: updaterCandidateLeaf, sha256: updaterCandidateHash },
        { kind: "guide", leaf: guideLeaf, sha256: guideHash },
      ],
    };
    const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
    fs.writeFileSync(path, `# shellx-drive.windows-candidate-provenance/v3:${encoded}\r\n$null = $null\r\n`, { flag: "wx", mode: 0o600 });
  ' "$payload_path" "$revision" "$source_manifest_sha256" "$receipt_sha256" \
    "$executable_leaf" "$executable_output_sha256" \
    "$installer_leaf" "$installer_output_sha256" \
    "$updater_signature_leaf" "$updater_signature_output_sha256" \
    "$updater_candidate_leaf" "$updater_candidate_output_sha256" \
    "$guide_leaf" "$guide_output_sha256" || return 1
  provenance_pre_sign_sha256="$($SHA256SUM_BIN -- "$payload_path")"
  provenance_pre_sign_sha256="${provenance_pre_sign_sha256%% *}"

  "$POWERSHELL_BIN" -NoProfile -NonInteractive -WindowStyle Hidden \
    -File "$($WSLPATH_BIN -w "$sign_script")" \
    -MetadataPath "$($WSLPATH_BIN -w "$metadata_path")" \
    -ReceiptPath "$($WSLPATH_BIN -w "$operation_receipt")" \
    -ExpectedArtifactSha256 "$provenance_pre_sign_sha256" \
    -ExpectedMetadataSha256 "$SHELLX_DRIVE_RELEASE_METADATA_SHA256" \
    -ExpectedSignerSha256 "$(release_helper_digest SIGNER)" \
    -ExpectedSecurityHelperSha256 "$(release_helper_digest RELEASE_SECURITY)" \
    -ExpectedComponentsHelperSha256 "$(release_helper_digest SIGNING_COMPONENTS)" \
    -ExpectedIdentityHelperSha256 "$(release_helper_digest ARTIFACT_IDENTITY)" \
    -SigningStageParentPath "$($WSLPATH_BIN -w "$output_dir")" \
    -PublishDirectoryPath "$($WSLPATH_BIN -w "$output_dir")" \
    -PublishLeafName "$provenance_leaf" \
    -Artifacts "$($WSLPATH_BIN -w "$payload_path")" || return 1
  admit_signed_candidate_artifact \
    "$operation_receipt" "$provenance_leaf" provenance_output_sha256 || return 1
  "$RM_BIN" -f -- "$payload_path" "$operation_receipt"
  printf '%s  %s\n' "$provenance_output_sha256" "$output_dir/$provenance_leaf"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-release-build-body.sh" >&2
  exit 2
fi
