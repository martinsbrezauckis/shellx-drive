"""Canonical macOS terminal-attestation parsing and exact schema validation."""
import json
import os
import re
import unicodedata

SCHEMA = "release-studio.shellx-drive-macos-terminal-attestation.v1"
DOMAIN = "shellx-drive.macos-terminal-attestation.v1"
ATTESTATION_NAME = "macos-terminal-attestation.v1.json"
SIGNATURE_NAME = f"{ATTESTATION_NAME}.asc"
WORKER_OBSERVATION_NAME = "worker-observation.json"
SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GIT_OID = re.compile(r"^[a-f0-9]{40}$")
FINGERPRINT = re.compile(r"^[A-F0-9]{40,64}$")
BUNDLE_IDENTIFIER = "com.shellx.drive.desktop"
TEAM_IDENTIFIER = "4M329JW6R4"
SIGNER_FINGERPRINT = "11BE2A1FCEC2B6E5395C42173CB4CFFA574A853B"
IDENTIFIER_ANCHOR = re.compile(r'(?<![A-Za-z0-9_.-])identifier\s+"?com\.shellx\.drive\.desktop"?(?![A-Za-z0-9_.-])')
TEAM_ANCHOR = re.compile(r'certificate\s+leaf\[subject\.OU\]\s*=\s*"?4M329JW6R4"?')
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
UUID = re.compile(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
EVIDENCE_FILES = {
    "codesign": "codesign.txt", "entitlements": "signed-entitlements.plist",
    "gatekeeper": "gatekeeper.txt", "notarytool": "notarytool-result.json",
    "stapler": "stapler.txt", "updaterVerifier": "updater-verifier.txt",
    "workerComplete": "worker-complete.json",
}
SAFE_INTEGER = 9007199254740991


class VerificationError(Exception):
    pass


def fail(message):
    raise VerificationError(message)


def exact_keys(value, label, keys):
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    expected, actual = set(keys), set(value)
    if actual != expected:
        fail(f"{label} keys drifted; missing={sorted(expected - actual)} extra={sorted(actual - expected)}")


def string(value, label):
    if not isinstance(value, str) or not value or any(ch in value for ch in "\0\r\n"):
        fail(f"{label} must be a non-empty single-line string")


def sha256(value, label):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256")


def integer(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > SAFE_INTEGER:
        fail(f"{label} must be a non-negative safe integer")


def safe_file(value, label):
    if not isinstance(value, str) or not SAFE_FILE.fullmatch(value):
        fail(f"{label} must be a safe ASCII basename")


def canonical_string(value, label):
    if not isinstance(value, str) or unicodedata.normalize("NFC", value) != value or any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        fail(f"{label} must be NFC Unicode without lone surrogates")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonical_json(value, label="canonical JSON"):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return canonical_string(value, label)
    if isinstance(value, int):
        if value < -SAFE_INTEGER or value > SAFE_INTEGER:
            fail(f"{label} numbers must be safe integers")
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item, f"{label}[{index}]") for index, item in enumerate(value)) + "]"
    if isinstance(value, dict):
        pairs = []
        for key in value:
            canonical_string(key, f"{label} key")
            pairs.append((key, value[key]))
        pairs.sort(key=lambda item: item[0].encode("utf-8"))
        return "{" + ",".join(f"{canonical_string(key, f'{label} key')}:{canonical_json(item, f'{label}.{key}')}" for key, item in pairs) + "}"
    fail(f"{label} contains unsupported {type(value).__name__}")


def _parse_int(token):
    if token == "-0":
        fail("canonical JSON must not contain -0")
    value = int(token)
    if value < -SAFE_INTEGER or value > SAFE_INTEGER:
        fail("canonical JSON numbers must be safe integers")
    return value


def _reject_float(_token):
    fail("canonical JSON must not contain floating-point numbers")


def _reject_constant(_token):
    fail("canonical JSON must not contain non-finite numbers")


def _object_pairs(pairs):
    result = {}
    for raw_key, value in pairs:
        canonical_string(raw_key, "canonical JSON key")
        normalized = unicodedata.normalize("NFC", raw_key)
        if normalized in result:
            fail("canonical JSON must not contain duplicate keys after NFC")
        result[normalized] = value
    return result


def parse_canonical_document(bytes_, label):
    try:
        text = bytes_.decode("utf-8", "strict")
    except UnicodeDecodeError:
        fail(f"{label} must be valid UTF-8")
    if text.startswith("\ufeff") or not text.endswith("\n"):
        fail(f"{label} must be BOM-free canonical UTF-8 ending in one newline")
    try:
        value = json.loads(text, object_pairs_hook=_object_pairs, parse_int=_parse_int, parse_float=_reject_float, parse_constant=_reject_constant)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        fail(f"{label} is not JSON: {error}")
    canonical = f"{canonical_json(value)}\n".encode("utf-8")
    if canonical != bytes_:
        fail(f"{label} is not canonical JSON")
    return value, canonical


def _artifact(value, label):
    exact_keys(value, label, ["name", "sha256", "size"])
    safe_file(value["name"], f"{label}.name")
    sha256(value["sha256"], f"{label}.sha256")
    integer(value["size"], f"{label}.size")


def validate_attestation(value):
    exact_keys(value, "macOS terminal attestation", ["artifacts", "checks", "continuity", "fullStageDigest", "identity", "notarization", "platform", "project", "rawEvidence", "releaseStudio", "schema", "signatureDomain", "source", "status", "toolchainManifest", "version", "workerObservation"])
    if value["schema"] != SCHEMA or value["status"] != "pass" or value["project"] != "shellx-drive" or value["platform"] != "macos-arm64" or value["signatureDomain"] != DOMAIN:
        fail("terminal attestation schema or identity drifted")
    if not isinstance(value["version"], str) or not VERSION.fullmatch(value["version"]):
        fail("terminal attestation version is malformed")
    exact_keys(value["source"], "terminal attestation source", ["commit", "tree"])
    for key in ("commit", "tree"):
        if not isinstance(value["source"][key], str) or not GIT_OID.fullmatch(value["source"][key]):
            fail(f"terminal attestation source.{key} is malformed")
    sha256(value["fullStageDigest"], "terminal attestation fullStageDigest")
    exact_keys(value["releaseStudio"], "terminal attestation releaseStudio", ["admissionHelperSha256", "admissionSha256", "commit", "controllerSha256", "tree"])
    for key in ("commit", "tree"):
        if not isinstance(value["releaseStudio"][key], str) or not GIT_OID.fullmatch(value["releaseStudio"][key]):
            fail(f"terminal attestation releaseStudio.{key} is malformed")
    for key in ("admissionHelperSha256", "admissionSha256", "controllerSha256"):
        sha256(value["releaseStudio"][key], f"terminal attestation releaseStudio.{key}")
    exact_keys(value["toolchainManifest"], "terminal attestation toolchainManifest", ["sha256", "toolsDigest"])
    sha256(value["toolchainManifest"]["sha256"], "terminal attestation toolchainManifest.sha256")
    sha256(value["toolchainManifest"]["toolsDigest"], "terminal attestation toolchainManifest.toolsDigest")
    exact_keys(value["workerObservation"], "terminal attestation workerObservation", ["name", "sha256"])
    if value["workerObservation"]["name"] != WORKER_OBSERVATION_NAME:
        fail("terminal attestation worker observation name drifted")
    sha256(value["workerObservation"]["sha256"], "terminal attestation workerObservation.sha256")
    exact_keys(value["artifacts"], "terminal attestation artifacts", ["app", "dmg", "updaterArchive", "updaterSignature"])
    app = value["artifacts"]["app"]
    exact_keys(app, "terminal attestation app", ["cdHash", "executableRelativePath", "executableSha256", "name", "treeDigest"])
    safe_file(app["name"], "terminal attestation app.name")
    sha256(app["treeDigest"], "terminal attestation app.treeDigest")
    sha256(app["executableSha256"], "terminal attestation app.executableSha256")
    string(app["executableRelativePath"], "terminal attestation app.executableRelativePath")
    parts = app["executableRelativePath"].split("/")
    if os.path.isabs(app["executableRelativePath"]) or any(part in ("", ".", "..") for part in parts):
        fail("terminal attestation app executable path escapes the bundle")
    if not isinstance(app["cdHash"], str) or not re.fullmatch(r"[A-Fa-f0-9]{40,64}", app["cdHash"]):
        fail("terminal attestation app.cdHash is malformed")
    dmg = value["artifacts"]["dmg"]
    exact_keys(dmg, "terminal attestation dmg", ["mountedAppTreeDigest", "mountedCdHash", "mountedExecutableSha256", "name", "sha256", "size"])
    safe_file(dmg["name"], "terminal attestation dmg.name")
    integer(dmg["size"], "terminal attestation dmg.size")
    for key in ("sha256", "mountedAppTreeDigest", "mountedExecutableSha256"):
        sha256(dmg[key], f"terminal attestation dmg.{key}")
    if not isinstance(dmg["mountedCdHash"], str) or not re.fullmatch(r"[A-Fa-f0-9]{40,64}", dmg["mountedCdHash"]):
        fail("terminal attestation dmg.mountedCdHash is malformed")
    for role in ("updaterArchive", "updaterSignature"):
        _artifact(value["artifacts"][role], f"terminal attestation {role}")
    exact_keys(value["identity"], "terminal attestation identity", ["bundleIdentifier", "designatedRequirement", "signerFingerprint", "teamIdentifier"])
    for key in ("bundleIdentifier", "designatedRequirement", "teamIdentifier"):
        string(value["identity"][key], f"terminal attestation identity.{key}")
    identity = value["identity"]
    if identity["bundleIdentifier"] != BUNDLE_IDENTIFIER or identity["teamIdentifier"] != TEAM_IDENTIFIER or identity["signerFingerprint"] != SIGNER_FINGERPRINT:
        fail("terminal attestation identity is not the official ShellX Drive signer")
    if not IDENTIFIER_ANCHOR.search(identity["designatedRequirement"]) or not TEAM_ANCHOR.search(identity["designatedRequirement"]):
        fail("terminal attestation designated requirement lacks the official identifier/team anchor")
    exact_keys(value["notarization"], "terminal attestation notarization", ["status", "submissionId"])
    if value["notarization"]["status"] != "Accepted" or not isinstance(value["notarization"]["submissionId"], str) or not UUID.fullmatch(value["notarization"]["submissionId"]):
        fail("terminal attestation notarization drifted")
    exact_keys(value["checks"], "terminal attestation checks", ["codesign", "gatekeeper", "notary", "staple", "updater"])
    if any(result != "pass" for result in value["checks"].values()):
        fail("terminal attestation checks are incomplete")
    exact_keys(value["continuity"], "terminal attestation continuity", ["artifacts", "mountedDmg", "source", "stage", "tools"])
    if any(result != "pass" for result in value["continuity"].values()):
        fail("terminal attestation continuity is incomplete")
    exact_keys(value["rawEvidence"], "terminal attestation rawEvidence", EVIDENCE_FILES.keys())
    for key, name in EVIDENCE_FILES.items():
        _artifact(value["rawEvidence"][key], f"terminal attestation rawEvidence.{key}")
        if value["rawEvidence"][key]["name"] != name:
            fail(f"terminal attestation rawEvidence.{key} name drifted")
    if dmg["mountedAppTreeDigest"] != app["treeDigest"] or dmg["mountedExecutableSha256"] != app["executableSha256"] or dmg["mountedCdHash"] != app["cdHash"]:
        fail("terminal attestation mounted DMG identity differs from the app")
