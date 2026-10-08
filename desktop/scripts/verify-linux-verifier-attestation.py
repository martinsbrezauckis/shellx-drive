#!/usr/bin/env python3
"""Strictly bind a signed Linux verifier attestation to a private candidate copy."""
import argparse, hashlib, json, pathlib, re, stat

def fail(message): raise SystemExit(f"FAIL: {message}")
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
parser = argparse.ArgumentParser()
parser.add_argument("--candidate-dir", required=True); parser.add_argument("--attestation", required=True)
parser.add_argument("--verification-keyring", required=True); parser.add_argument("--installed-root", default="/")
parser.add_argument("--receipt", required=True); args = parser.parse_args()
root = pathlib.Path(args.candidate_dir).resolve(strict=True); attestation = pathlib.Path(args.attestation)
installed_input=pathlib.Path(args.installed_root)
if installed_input.is_symlink() or not installed_input.is_dir(): fail("installed verifier root is unsafe")
installed_root=installed_input.resolve(strict=True)
data = json.loads(attestation.read_text(encoding="utf-8"))
required = {"schema", "status", "project", "version", "platform", "source", "fullStageDigest", "releaseStudio", "toolchainManifest", "externalVerificationBundle", "signedManifest", "artifacts", "signatures", "packageLayout", "packageFiles", "tools"}
if set(data) != required or data["schema"] != "shellx-drive.linux-verifier-attestation/v1" or data["status"] != "pass" or data["project"] != "shellx-drive" or data["platform"] != "linux-x86_64": fail("attestation schema or terminal identity is invalid")
if set(data["releaseStudio"]) != {"commit","tree","controllerSha256","admissionHelperSha256","admissionSha256"} or set(data["toolchainManifest"]) != {"sha256"}: fail("controller identity shape is invalid")
external=data["externalVerificationBundle"];external_names={"verify-linux-trusted-release.py","verify-linux-trusted-common.py","verify-linux-trusted-candidate.py","shellx-drive-linux-release-keyring.gpg"}
if set(external)!=external_names: fail("external verification bundle shape is invalid")
for name,item in external.items():
    if set(item)!={"sha256","size","mode"} or not re.fullmatch(r"[a-f0-9]{64}",item.get("sha256","")) or not isinstance(item.get("size"),int) or isinstance(item.get("size"),bool) or item["size"]<0 or item["mode"]!="0644": fail(f"external verification bundle identity is invalid: {name}")
if data["signatures"].keys() != {"manifest","appimage","deb","updaterAppimage","updaterDeb"} or any(data["signatures"][key].get("result") != "pass" for key in data["signatures"]): fail("signature evidence is incomplete")
fingerprints={data["signatures"][key].get("signerFingerprint") for key in ("manifest","appimage","deb")}
fingerprint=next(iter(fingerprints),"")
if len(fingerprints)!=1 or not isinstance(fingerprint,str) or not fingerprint.isalnum(): fail("release signer identities do not cross-bind")
manifest = data["signedManifest"]
for key in ("name", "signatureName"):
    if pathlib.PurePath(manifest.get(key, "")).name != manifest.get(key): fail("unsafe signed manifest name")
layout=data["packageLayout"]
if layout != {"desktopBinaryPath":"/usr/bin/shellx-drive-desktop","desktopEntryPath":"/usr/share/applications/shellx-drive.desktop","desktopIconPath":"/usr/share/icons/hicolor/256x256/apps/shellx-drive.png","acceptanceRunnerPath":"/usr/lib/shellx-drive/acceptance/run-linux-desktop-acceptance.sh","acceptanceStateVerifierPath":"/usr/lib/shellx-drive/acceptance/verify-linux-acceptance-state.py","controlResultLedgerPath":"/usr/lib/shellx-drive/acceptance/CONTROL_RESULT_LEDGER.tsv","linuxControlLedgerPath":"/usr/lib/shellx-drive/acceptance/linux-control-ledger.py","verifierPath":"/usr/lib/shellx-drive/verification/linux-verify-candidate.sh","commonHelperPath":"/usr/lib/shellx-drive/verification/linux-release-common.sh","manifestVerifierPath":"/usr/lib/shellx-drive/verification/verify-linux-candidate-manifest.py","attestationVerifierPath":"/usr/lib/shellx-drive/verification/verify-linux-verifier-attestation.py","releaseKeyringPath":"/usr/lib/shellx-drive/verification/release-keyring.gpg","desktopBinaryMode":"0755","desktopEntryMode":"0644","desktopIconMode":"0644","acceptanceRunnerMode":"0755","acceptanceStateVerifierMode":"0644","controlResultLedgerMode":"0644","linuxControlLedgerMode":"0644","verifierMode":"0755","helperMode":"0644","manifestVerifierMode":"0644","attestationVerifierMode":"0644","keyringMode":"0644","appImageHostVerifierCopies":0}: fail("package verifier layout is invalid")
package_files=data["packageFiles"]
paths={layout["desktopBinaryPath"]:layout["desktopBinaryMode"],layout["desktopEntryPath"]:layout["desktopEntryMode"],layout["desktopIconPath"]:layout["desktopIconMode"],layout["acceptanceRunnerPath"]:layout["acceptanceRunnerMode"],layout["acceptanceStateVerifierPath"]:layout["acceptanceStateVerifierMode"],layout["controlResultLedgerPath"]:layout["controlResultLedgerMode"],layout["linuxControlLedgerPath"]:layout["linuxControlLedgerMode"],layout["verifierPath"]:layout["verifierMode"],layout["commonHelperPath"]:layout["helperMode"],layout["manifestVerifierPath"]:layout["manifestVerifierMode"],layout["attestationVerifierPath"]:layout["attestationVerifierMode"],layout["releaseKeyringPath"]:layout["keyringMode"]}
if set(package_files)!={"deb","appImageHostVerifierCopies"} or package_files["appImageHostVerifierCopies"]!=0 or set(package_files["deb"])!=set(paths): fail("package file proof is incomplete")
trusted_keyring=pathlib.Path(args.verification_keyring)
keyring_proof=package_files["deb"][layout["releaseKeyringPath"]]
if trusted_keyring.is_symlink() or not trusted_keyring.is_file() or sha(trusted_keyring)!=keyring_proof.get("sha256") or trusted_keyring.stat().st_size!=keyring_proof.get("size"): fail("verification keyring differs from signed package proof")
acceptance=installed_root/"usr/lib/shellx-drive/acceptance";expected_acceptance={pathlib.PurePosixPath(name).name for name in paths if name.startswith("/usr/lib/shellx-drive/acceptance/")}
if acceptance.is_symlink() or acceptance.resolve(strict=True)!=acceptance or {entry.name for entry in acceptance.iterdir()}!=expected_acceptance: fail("installed acceptance subtree contains unexpected or case-variant entries")
for name,mode in paths.items():
    item=package_files["deb"][name];target=installed_root.joinpath(*pathlib.PurePosixPath(name).parts[1:])
    if target.resolve(strict=True)!=target: fail("installed verifier closure contains a symlink")
    metadata=target.lstat()
    if set(item)!={"sha256","size","mode"} or item["mode"]!=mode or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or f"{stat.S_IMODE(metadata.st_mode):04o}"!=mode or sha(target)!=item["sha256"] or metadata.st_size!=item["size"]: fail("installed verifier closure differs from signed package proof")
if set(data["tools"]) != {"digest","continuity"} or data["tools"]["continuity"] != "pass": fail("tool continuity is invalid")
for role in ("appimage", "deb", "updaterAppimage", "updaterDeb"):
    item = data["artifacts"].get(role, {})
    name = item.get("name", "")
    if pathlib.PurePath(name).name != name or name in ("", ".", ".."): fail(f"unsafe {role} artifact name")
    target = root / name
    if not target.is_file() or target.is_symlink() or sha(target) != item.get("sha256") or target.stat().st_size != item.get("size"): fail(f"{role} artifact identity changed")
for name, expected in ((manifest["name"], manifest.get("sha256")), (manifest["signatureName"], manifest.get("signatureSha256"))):
    target = root / name
    if not target.is_file() or target.is_symlink() or sha(target) != expected: fail("signed manifest identity changed")
candidate=json.loads((root/manifest["name"]).read_text(encoding="utf-8"))
if candidate.get("source")!=data.get("source"): fail("manifest source does not match terminal attestation")
for role,key in (("appimage","appimage"),("deb","deb")):
    if candidate["artifacts"][key]["file"]!=data["artifacts"][role]["name"] or candidate["artifacts"][key]["sha256"]!=data["artifacts"][role]["sha256"]: fail("manifest artifact does not match terminal attestation")
if set(candidate.get("updaters", {})) != {"linux-x86_64", "linux-x86_64-deb"}: fail("candidate updater type map is incomplete")
for platform, artifact, signature in (("linux-x86_64", "updaterAppimage", "updaterAppimage"), ("linux-x86_64-deb", "updaterDeb", "updaterDeb")):
    updater=candidate["updaters"][platform]
    signed=data["signatures"][signature]
    if updater.get("artifact")!=data["artifacts"][artifact].get("name") or updater.get("artifact_sha256")!=data["artifacts"][artifact].get("sha256") or updater.get("signature")!=signed.get("signatureName") or updater.get("signature_sha256")!=signed.get("signatureSha256"): fail(f"{platform} updater does not match terminal attestation")
if data["signatures"]["updaterAppimage"].get("publicKeySha256") != data["signatures"]["updaterDeb"].get("publicKeySha256"): fail("updater types do not use one public key")
receipt = pathlib.Path(args.receipt)
receipt.write_text(json.dumps({"schema":"shellx-drive.linux-candidate-verification/v1", "status":"pass", "attestationSha256":sha(attestation), "source":data["source"], "artifacts":data["artifacts"], "installedBinary":package_files["deb"][layout["desktopBinaryPath"]]}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
