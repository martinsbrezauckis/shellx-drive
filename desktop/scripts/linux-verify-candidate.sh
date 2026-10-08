#!/usr/bin/env bash
# Verify a controller-signed canonical attestation against descriptor-copied
# candidate bytes. A receipt is atomically published only after every check.
set -euo pipefail
umask 077
script_dir="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)"; source "$script_dir/linux-release-common.sh"
TOOL_STAT=/usr/bin/stat; TOOL_INSTALL=/usr/bin/install; TOOL_CMP=/usr/bin/cmp
candidate_dir=""; attestation=""; attestation_signature=""; keyring=""; receipt=""
while [[ $# -gt 0 ]]; do case "$1" in
 --candidate-dir) candidate_dir="${2:-}";shift 2;; --attestation) attestation="${2:-}";shift 2;;
 --attestation-signature) attestation_signature="${2:-}";shift 2;; --keyring) keyring="${2:-}";shift 2;;
 --output-receipt) receipt="${2:-}";shift 2;; *) linux_release_fail "usage: $0 --candidate-dir DIR --attestation FILE --attestation-signature FILE --keyring FILE --output-receipt FILE";; esac; done
[[ "$candidate_dir" == /* && -d "$candidate_dir" && ! -L "$candidate_dir" && "$receipt" == /* && ! -e "$receipt" ]] || linux_release_fail "unsafe candidate directory or receipt path"
installed_keyring="$script_dir/release-keyring.gpg"
[[ "$keyring" == "$installed_keyring" ]] || linux_release_fail "verification requires the installed release keyring"
installed_suffix="/usr/lib/shellx-drive/verification"
case "$script_dir" in
 "$installed_suffix") installed_root="/";;
 *"$installed_suffix") installed_root="${script_dir%"$installed_suffix"}";;
 *) linux_release_fail "verifier is not installed at the packaged path";;
esac
[[ "$installed_root" == /* && -d "$installed_root" && ! -L "$installed_root" ]] || linux_release_fail "installed verifier root is unsafe"
for file in "$attestation" "$attestation_signature" "$keyring"; do linux_release_require_regular "$file" "verifier input"; done
snapshot="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/shellx-drive-verify.XXXXXX")"; /usr/bin/chmod 0700 "$snapshot"; trap '/usr/bin/rm -rf -- "$snapshot"' EXIT
linux_release_private_copy "$attestation" "$snapshot/linux-verifier-attestation.v1.json"
linux_release_private_copy "$attestation_signature" "$snapshot/linux-verifier-attestation.v1.json.asc"
linux_release_private_copy "$keyring" "$snapshot/release-keyring.gpg"
attestation_status="$(/usr/bin/gpgv --status-fd 1 --keyring "$snapshot/release-keyring.gpg" "$snapshot/linux-verifier-attestation.v1.json.asc" "$snapshot/linux-verifier-attestation.v1.json" 2>&1)" || linux_release_fail "verifier attestation signature did not verify"
PYTHON=(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I)
"${PYTHON[@]}" - "$snapshot/linux-verifier-attestation.v1.json" "$candidate_dir" "$snapshot" <<'PY'
import json,os,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text()); root=pathlib.Path(sys.argv[2]); out=pathlib.Path(sys.argv[3])
entries=[
 (d["signedManifest"]["name"],d["signedManifest"]["sha256"],None),
 (d["signedManifest"]["signatureName"],d["signedManifest"]["signatureSha256"],None),
 (d["signatures"]["updaterAppimage"]["signatureName"],d["signatures"]["updaterAppimage"]["signatureSha256"],None),
 (d["signatures"]["updaterDeb"]["signatureName"],d["signatures"]["updaterDeb"]["signatureSha256"],None),
]+[(d["artifacts"][kind]["name"],d["artifacts"][kind]["sha256"],d["artifacts"][kind]["size"]) for kind in ("appimage","deb","updaterAppimage","updaterDeb")]
seen={}
for name,digest,size in entries:
 if pathlib.PurePath(name).name!=name: raise SystemExit("FAIL: unsafe attested candidate name")
 if name in seen:
  old_digest,old_size=seen[name]
  if digest!=old_digest or (size is not None and old_size is not None and size!=old_size): raise SystemExit("FAIL: conflicting attested candidate name")
  continue
 seen[name]=(digest,size)
 source=root/name; target=out/name
 fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW); before=os.fstat(fd)
 with os.fdopen(fd,"rb") as src,open(target,"xb") as dst:
  while chunk:=src.read(1024*1024): dst.write(chunk)
 after=source.stat()
 if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size): raise SystemExit("FAIL: candidate changed during snapshot")
PY
manifest="$snapshot/linux-candidate-manifest.v1.json"
fingerprint="$("${PYTHON[@]}" - "$snapshot/linux-verifier-attestation.v1.json" <<'PY'
import json,pathlib,sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text());print(d["signatures"]["manifest"]["signerFingerprint"])
PY
)"
[[ "$fingerprint" =~ ^[A-F0-9]{40,64}$ ]] || linux_release_fail "terminal signer fingerprint is invalid"
linux_release_require_exact_validsig "$attestation_status" "$fingerprint" "terminal attestation"
manifest_status="$(/usr/bin/gpgv --status-fd 1 --keyring "$snapshot/release-keyring.gpg" "$manifest.asc" "$manifest" 2>&1)" || linux_release_fail "signed candidate manifest did not verify"
linux_release_require_exact_validsig "$manifest_status" "$fingerprint" "candidate manifest"
"${PYTHON[@]}" "$script_dir/verify-linux-candidate-manifest.py" --candidate-dir "$snapshot" --manifest "$manifest" --expected-fingerprint "$fingerprint"
temporary_receipt="$snapshot/verification-receipt.json"
"${PYTHON[@]}" "$script_dir/verify-linux-verifier-attestation.py" --candidate-dir "$snapshot" --attestation "$snapshot/linux-verifier-attestation.v1.json" --verification-keyring "$snapshot/release-keyring.gpg" --installed-root "$installed_root" --receipt "$temporary_receipt"
"${PYTHON[@]}" - "$temporary_receipt" "$receipt" <<'PY'
import os,pathlib,stat,sys
source=pathlib.Path(sys.argv[1]); destination=pathlib.Path(sys.argv[2]); parent=destination.parent.resolve(strict=True); meta=parent.stat()
if stat.S_IMODE(meta.st_mode)&0o077 or meta.st_uid!=os.getuid(): raise SystemExit("FAIL: receipt parent must be private and caller-owned")
fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with source.open("rb") as src,os.fdopen(fd,"wb") as dst:
 while chunk:=src.read(1024*1024): dst.write(chunk)
PY
printf 'LINUX_CANDIDATE_ATTESTATION_OK receipt=%s\n' "$receipt"
