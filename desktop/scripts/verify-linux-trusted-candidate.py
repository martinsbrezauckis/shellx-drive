"""Exact Linux terminal-attestation, candidate, and installed-closure checks."""
import pathlib
import re

ATTESTATION_SCHEMA = "shellx-drive.linux-verifier-attestation/v1"
MANIFEST_SCHEMA = "shellx-drive.linux-candidate/v1"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GIT_OID = re.compile(r"^[a-f0-9]{40}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
FINGERPRINT = re.compile(r"^[A-F0-9]{40,64}$")
EXTERNAL_BUNDLE_FILES = (
    "verify-linux-trusted-release.py",
    "verify-linux-trusted-common.py",
    "verify-linux-trusted-candidate.py",
    "shellx-drive-linux-release-keyring.gpg",
)
LAYOUT = {
    "desktopBinaryPath": "/usr/bin/shellx-drive-desktop",
    "desktopEntryPath": "/usr/share/applications/shellx-drive.desktop", "desktopIconPath": "/usr/share/icons/hicolor/256x256/apps/shellx-drive.png",
    "acceptanceRunnerPath": "/usr/lib/shellx-drive/acceptance/run-linux-desktop-acceptance.sh",
    "acceptanceStateVerifierPath": "/usr/lib/shellx-drive/acceptance/verify-linux-acceptance-state.py",
    "controlResultLedgerPath": "/usr/lib/shellx-drive/acceptance/CONTROL_RESULT_LEDGER.tsv",
    "linuxControlLedgerPath": "/usr/lib/shellx-drive/acceptance/linux-control-ledger.py",
    "verifierPath": "/usr/lib/shellx-drive/verification/linux-verify-candidate.sh",
    "commonHelperPath": "/usr/lib/shellx-drive/verification/linux-release-common.sh",
    "manifestVerifierPath": "/usr/lib/shellx-drive/verification/verify-linux-candidate-manifest.py",
    "attestationVerifierPath": "/usr/lib/shellx-drive/verification/verify-linux-verifier-attestation.py",
    "releaseKeyringPath": "/usr/lib/shellx-drive/verification/release-keyring.gpg",
    "desktopBinaryMode": "0755", "desktopEntryMode": "0644", "desktopIconMode": "0644", "acceptanceRunnerMode": "0755", "acceptanceStateVerifierMode": "0644",
    "controlResultLedgerMode": "0644", "linuxControlLedgerMode": "0644", "verifierMode": "0755",
    "helperMode": "0644", "manifestVerifierMode": "0644", "attestationVerifierMode": "0644",
    "keyringMode": "0644", "appImageHostVerifierCopies": 0,
}


def require_sha(value, label, trust):
    trust.require_pattern(value, SHA256, f"{label} SHA-256")


def validate_attestation(value, fingerprint, trust):
    required = ("schema", "status", "project", "version", "platform", "source", "fullStageDigest", "releaseStudio", "toolchainManifest", "externalVerificationBundle", "signedManifest", "artifacts", "signatures", "packageLayout", "packageFiles", "tools")
    trust.exact(value, required, "terminal attestation")
    valid_identity = value["schema"] == ATTESTATION_SCHEMA and value["status"] == "pass" and value["project"] == "shellx-drive" and value["platform"] == "linux-x86_64" and isinstance(value["version"], str) and VERSION.fullmatch(value["version"])
    if not valid_identity:
        trust.fail("terminal attestation identity is invalid")
    trust.exact(value["source"], ("commit", "tree"), "source")
    for key in ("commit", "tree"):
        trust.require_pattern(value["source"][key], GIT_OID, f"source {key}")
    require_sha(value["fullStageDigest"], "fullStageDigest", trust)
    trust.exact(value["releaseStudio"], ("commit", "tree", "controllerSha256", "admissionHelperSha256", "admissionSha256"), "release controller")
    for key in ("commit", "tree"):
        trust.require_pattern(value["releaseStudio"][key], GIT_OID, f"release controller {key}")
    for key in ("controllerSha256", "admissionHelperSha256", "admissionSha256"):
        require_sha(value["releaseStudio"][key], f"release controller {key}", trust)
    trust.exact(value["toolchainManifest"], ("sha256",), "toolchain manifest")
    require_sha(value["toolchainManifest"]["sha256"], "toolchain manifest", trust)
    trust.exact(value["externalVerificationBundle"], EXTERNAL_BUNDLE_FILES, "external verification bundle")
    for name, item in value["externalVerificationBundle"].items():
        trust.exact(item, ("sha256", "size", "mode"), f"external verification bundle {name}")
        require_sha(item["sha256"], f"external verification bundle {name}", trust)
        trust.require_integer(item["size"], f"external verification bundle {name}")
        if item["mode"] != "0644":
            trust.fail(f"external verification bundle mode drifted for {name}")
    manifest = value["signedManifest"]
    trust.exact(manifest, ("name", "sha256", "signatureName", "signatureSha256"), "signed manifest")
    for key in ("name", "signatureName"):
        trust.safe_leaf(manifest[key], f"signed manifest {key}")
    for key in ("sha256", "signatureSha256"):
        require_sha(manifest[key], f"signed manifest {key}", trust)
    trust.exact(value["artifacts"], ("appimage", "deb", "updaterAppimage", "updaterDeb"), "artifacts")
    for role, item in value["artifacts"].items():
        trust.exact(item, ("name", "sha256", "size"), f"{role} artifact")
        trust.safe_leaf(item["name"], f"{role} name")
        require_sha(item["sha256"], f"{role} hash", trust)
        trust.require_integer(item["size"], f"{role} size")
    trust.exact(value["signatures"], ("manifest", "appimage", "deb", "updaterAppimage", "updaterDeb"), "signatures")
    for role in ("manifest", "appimage", "deb"):
        item = value["signatures"][role]
        trust.exact(item, ("result", "signerFingerprint"), f"{role} signature")
        if item != {"result": "pass", "signerFingerprint": fingerprint}:
            trust.fail(f"{role} signature is not bound to the pinned fingerprint")
    updater_keys = ("result", "signatureName", "signatureSha256", "publicKeySha256")
    updater_key_hashes = set()
    for role in ("updaterAppimage", "updaterDeb"):
        updater = value["signatures"][role]
        trust.exact(updater, updater_keys, f"{role} signature")
        if updater["result"] != "pass":
            trust.fail(f"{role} signature did not pass")
        trust.safe_leaf(updater["signatureName"], f"{role} signature name")
        for key in ("signatureSha256", "publicKeySha256"):
            require_sha(updater[key], f"{role} {key}", trust)
        updater_key_hashes.add(updater["publicKeySha256"])
    if len(updater_key_hashes) != 1:
        trust.fail("updater types do not use one public key")
    if value["packageLayout"] != LAYOUT:
        trust.fail("package layout drifted")
    trust.exact(value["packageFiles"], ("deb", "appImageHostVerifierCopies"), "package files")
    if value["packageFiles"]["appImageHostVerifierCopies"] != 0:
        trust.fail("AppImage contains host verifier copies")
    expected = {
        LAYOUT["desktopBinaryPath"]: LAYOUT["desktopBinaryMode"], LAYOUT["desktopEntryPath"]: LAYOUT["desktopEntryMode"], LAYOUT["desktopIconPath"]: LAYOUT["desktopIconMode"],
        LAYOUT["acceptanceRunnerPath"]: LAYOUT["acceptanceRunnerMode"], LAYOUT["acceptanceStateVerifierPath"]: LAYOUT["acceptanceStateVerifierMode"],
        LAYOUT["controlResultLedgerPath"]: LAYOUT["controlResultLedgerMode"], LAYOUT["linuxControlLedgerPath"]: LAYOUT["linuxControlLedgerMode"],
        LAYOUT["verifierPath"]: LAYOUT["verifierMode"], LAYOUT["commonHelperPath"]: LAYOUT["helperMode"],
        LAYOUT["manifestVerifierPath"]: LAYOUT["manifestVerifierMode"], LAYOUT["attestationVerifierPath"]: LAYOUT["attestationVerifierMode"],
        LAYOUT["releaseKeyringPath"]: LAYOUT["keyringMode"],
    }
    trust.exact(value["packageFiles"]["deb"], expected, "Debian verifier closure")
    for path, mode in expected.items():
        item = value["packageFiles"]["deb"][path]
        trust.exact(item, ("sha256", "size", "mode"), f"package file {path}")
        require_sha(item["sha256"], f"package file {path}", trust)
        trust.require_integer(item["size"], f"package file {path}")
        if item["mode"] != mode:
            trust.fail(f"package file mode drifted for {path}")
    trust.exact(value["tools"], ("digest", "continuity"), "tools")
    require_sha(value["tools"]["digest"], "tools digest", trust)
    if value["tools"]["continuity"] != "pass":
        trust.fail("tool continuity did not pass")


def verify_candidate(value, root, keyring, fingerprint, trust):
    identities = {}
    entries = [value["signedManifest"], {"name": value["signedManifest"]["signatureName"], "sha256": value["signedManifest"]["signatureSha256"]}, value["signatures"]["updaterAppimage"], value["signatures"]["updaterDeb"], *value["artifacts"].values()]
    for item in entries:
        name = item.get("name", item.get("signatureName"))
        digest = item.get("sha256", item.get("signatureSha256"))
        size = item.get("size")
        trust.safe_leaf(name, "candidate file")
        require_sha(digest, f"candidate {name}", trust)
        if name in identities and identities[name] != (digest, size):
            trust.fail(f"candidate name {name} has conflicting identities")
        identities[name] = (digest, size)
    for name, (digest, size) in identities.items():
        observed = trust.stable_hash(str(root / name), f"candidate {name}")
        if observed["sha256"] != digest or size is not None and observed["size"] != size:
            trust.fail(f"candidate {name} bytes differ from attestation")
    manifest_path = root / value["signedManifest"]["name"]
    manifest_body = trust.stable_bytes(str(manifest_path), "candidate manifest", trust.MAX_DOCUMENT)
    signature = trust.stable_bytes(str(root / value["signedManifest"]["signatureName"]), "candidate manifest signature", trust.MAX_SIGNATURE)
    trust.verify_signature(manifest_body, signature, keyring, fingerprint, "candidate manifest")
    manifest = trust.parse_json(manifest_body, "candidate manifest")
    trust.exact(manifest, ("schema", "source", "signer", "artifacts", "updaters"), "candidate manifest")
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["source"] != value["source"]:
        trust.fail("candidate manifest source differs from terminal attestation")
    trust.exact(manifest["signer"], ("release_key_fingerprint", "identity"), "candidate signer")
    if manifest["signer"]["release_key_fingerprint"] != fingerprint:
        trust.fail("candidate signer differs from pinned fingerprint")
    trust.exact(manifest["artifacts"], ("appimage", "deb"), "candidate artifacts")
    for role in ("appimage", "deb"):
        trust.exact(manifest["artifacts"][role], ("file", "sha256"), f"candidate {role}")
        expected = {"file": value["artifacts"][role]["name"], "sha256": value["artifacts"][role]["sha256"]}
        if manifest["artifacts"][role] != expected:
            trust.fail(f"candidate {role} differs from terminal attestation")
    trust.exact(manifest["updaters"], ("linux-x86_64", "linux-x86_64-deb"), "candidate updater type map")
    for platform, artifact_role, signature_role in (("linux-x86_64", "updaterAppimage", "updaterAppimage"), ("linux-x86_64-deb", "updaterDeb", "updaterDeb")):
        trust.exact(manifest["updaters"][platform], ("artifact", "signature", "artifact_sha256", "signature_sha256"), f"candidate {platform} updater")
        updater = value["signatures"][signature_role]
        expected = {"artifact": value["artifacts"][artifact_role]["name"], "signature": updater["signatureName"], "artifact_sha256": value["artifacts"][artifact_role]["sha256"], "signature_sha256": updater["signatureSha256"]}
        if manifest["updaters"][platform] != expected:
            trust.fail(f"candidate {platform} updater differs from terminal attestation")


def verify_installed(value, installed_root, trust):
    root = trust.normalized(installed_root, "installed root", True)
    acceptance = trust.normalized(str(root / "usr/lib/shellx-drive/acceptance"), "installed acceptance directory", True)
    expected = {pathlib.PurePosixPath(path).name for path in value["packageFiles"]["deb"] if path.startswith("/usr/lib/shellx-drive/acceptance/")}
    if {item.name for item in acceptance.iterdir()} != expected:
        trust.fail("installed acceptance subtree contains unexpected or case-variant entries")
    for absolute, expected in value["packageFiles"]["deb"].items():
        target = root.joinpath(*pathlib.PurePosixPath(absolute).parts[1:])
        if trust.stable_hash(str(target), f"installed {absolute}") != expected:
            trust.fail(f"installed verifier closure differs at {absolute}")
