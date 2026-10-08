#!/bin/bash
# Admit an artifact already published by windows-artifact-sign.ps1. The signer
# records the signed digest before its same-file move; this helper reopens the
# final leaf through the retained candidate-directory identity and requires the
# evidence and published bytes to agree.
candidate_provenance_helper="${BASH_SOURCE[0]%/*}/windows-candidate-provenance.sh"
if [[ -L "$candidate_provenance_helper" || ! -f "$candidate_provenance_helper" ]]; then
  echo "FAIL: candidate provenance helper is missing or unsafe" >&2
  return 1 2>/dev/null || exit 1
fi
# shellcheck source=windows-candidate-provenance.sh
source "$candidate_provenance_helper"

admit_signed_candidate_artifact() {
  local receipt="$1" leaf="$2" result_variable="$3"
  local destination expected_sha256 path_identity fd_identity published_fd reopened_sha256
  if [[ ! -f "$receipt" || -L "$receipt" || "$leaf" == */* || -z "$leaf" ]]; then
    echo "FAIL: signed candidate admission input is invalid" >&2
    return 1
  fi
  verify_candidate_output_identity || return 1
  destination="$output_dir_fd_path/$leaf"
  if [[ -L "$destination" || "$("$STAT_BIN" -c '%F' -- "$destination" 2>/dev/null || true)" != "regular file" ]]; then
    echo "FAIL: signer did not publish a regular candidate artifact: $leaf" >&2
    return 1
  fi
  output_published_leaves+=("$leaf")
  expected_sha256="$("$NODE_BIN" -e '
    const fs = require("node:fs");
    const [receipt, leaf, commit] = process.argv.slice(1);
    const rows = fs.readFileSync(receipt, "utf8").split(/\r?\n/).filter(Boolean)
      .map((line) => JSON.parse(line))
      .filter((row) => row.schema === "shellx-drive.windows-signed-artifact/v2" && row.artifact_leaf === leaf);
    if (rows.length !== 1) throw new Error(`expected one signed-artifact identity for ${leaf}`);
    const row = rows[0];
    const auth = row.authenticode, publisher = auth?.publisher;
    const certificateOk = (certificate) => certificate &&
      typeof certificate.subject === "string" && typeof certificate.issuer === "string" &&
      /^[0-9a-f]{40}$/.test(certificate.thumbprint) && /^[0-9a-f]+$/.test(certificate.serial_number) &&
      Number.isFinite(Date.parse(certificate.not_before)) && Number.isFinite(Date.parse(certificate.not_after));
    if (row.source_commit !== commit || row.publication !== "private-stage-file-move" ||
        !/^[0-9a-f]{64}$/.test(row.pre_sign_sha256) || !/^[0-9a-f]{64}$/.test(row.signed_sha256) ||
        auth?.status !== "Valid" || publisher?.common_name !== "U1C" ||
        publisher?.organization !== "U1C" || publisher?.country !== "LV" ||
        publisher?.signer_issuer_organization !== "Microsoft Corporation" ||
        publisher?.timestamp_issuer_organization !== "Microsoft Corporation" ||
        !certificateOk(auth.signer_certificate) || !certificateOk(auth.timestamp_certificate)) {
      throw new Error(`invalid signed-artifact identity for ${leaf}`);
    }
    process.stdout.write(row.signed_sha256);
  ' "$receipt" "$leaf" "$revision")"
  if ! exec {published_fd}<"$destination"; then
    echo "FAIL: signed candidate artifact could not be reopened: $leaf" >&2
    return 1
  fi
  path_identity="$("$STAT_BIN" -Lc '%d:%i' -- "$destination")"
  fd_identity="$("$STAT_BIN" -Lc '%d:%i' -- "/proc/self/fd/$published_fd")"
  reopened_sha256="$("$SHA256SUM_BIN" -- "/proc/self/fd/$published_fd")"
  reopened_sha256="${reopened_sha256%% *}"
  exec {published_fd}<&-
  if [[ "$path_identity" != "$fd_identity" || "$reopened_sha256" != "$expected_sha256" ]]; then
    echo "FAIL: signed candidate artifact identity mismatch: $leaf" >&2
    return 1
  fi
  verify_candidate_output_identity || return 1
  printf -v "$result_variable" '%s' "$reopened_sha256"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from build-windows-nsis-from-wsl.sh" >&2
  exit 2
fi
