#!/usr/bin/env node
import { createHash } from "node:crypto";
import { chmodSync, lstatSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

const SCHEMA = "release-studio.shellx-drive-unsigned-handoff/v1";
const APPLICATION_PATH = "payload/shellx-drive-desktop";
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_OID = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const LINUX_NATIVE_BUILDER_ID = "linux-native";

function fail(message) { throw new Error(message); }
function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has unexpected or missing fields`);
}
function canonicalJson(value, seen = new Set()) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    if (value.normalize("NFC") !== value || /[\uD800-\uDFFF]/u.test(value)) fail("canonical JSON contains non-canonical text");
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail("canonical JSON number is invalid");
    return String(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value) || Object.keys(value).length !== value.length) fail("canonical JSON array is invalid");
    seen.add(value);
    try { return `[${value.map((item) => canonicalJson(item, seen)).join(",")}]`; }
    finally { seen.delete(value); }
  }
  if (value && typeof value === "object" && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    if (seen.has(value)) fail("canonical JSON is cyclic");
    seen.add(value);
    try {
      return `{${Object.keys(value).sort((left, right) => Buffer.from(left).compare(Buffer.from(right))).map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], seen)}`).join(",")}}`;
    } finally { seen.delete(value); }
  }
  fail("canonical JSON contains an unsupported value");
}
function argumentValue(arguments_, name) {
  const positions = arguments_.flatMap((value, index) => value === name ? [index] : []);
  if (positions.length !== 1 || positions[0] === arguments_.length - 1) fail(`expected one ${name} argument`);
  return arguments_[positions[0] + 1];
}
function parseArguments(arguments_) {
  if (arguments_.length !== 4 || !arguments_.every((value, index) => index % 2 === 0 ? ["--admission", "--out"].includes(value) : true)) fail("usage: write-linux-unsigned-handoff.mjs --admission <canonical-admission> --out <fresh-absolute-directory>");
  const admission = argumentValue(arguments_, "--admission");
  const output = argumentValue(arguments_, "--out");
  if (!isAbsolute(admission) || !isAbsolute(output)) fail("admission and output paths must be absolute");
  return { admission, output: resolve(output) };
}
function validateBaselineRuntime(runtime) {
  const selected = Object.hasOwn(runtime, "publicBaseline");
  if (!selected) {
    if (Object.hasOwn(runtime.dependencyRoots, "publicBaseline") || Object.hasOwn(runtime.sourceDescriptors, "verify-linux-public-baseline")) fail("unsigned baseline selection is partial");
    return;
  }
  const baseline = runtime.publicBaseline;
  exactKeys(baseline, ["schema", "root", "baseImage", "imageDigest", "compilerRuntimeMountPath", "packageInventory", "exportReceipt"], "unsigned baseline");
  exactKeys(runtime.dependencyRoots, ["cargoHome", "compilerRuntime", "rustupHome", "publicBaseline"], "unsigned baseline dependency roots");
  exactKeys(runtime.sourceDescriptors, ["tauri-linux-config", "write-linux-unsigned-handoff", "verify-linux-public-baseline"], "unsigned baseline source descriptors");
  exactKeys(baseline.root, ["path", "treeDigest", "descriptorDigest", "dev", "inode", "uid", "mode"], "unsigned baseline root");
  if (canonicalJson(baseline.root) !== canonicalJson(runtime.dependencyRoots.publicBaseline) || baseline.schema !== "release-studio.shellx-drive-linux-public-baseline/v1" ||
      baseline.baseImage !== "ubuntu@sha256:b1066385161d28ddf6bc7e7b28a9170eec11484c821d1a5150d176cbde41d7f7" || !/^sha256:[0-9a-f]{64}$/.test(baseline.imageDigest) ||
      !["/usr/lib/gcc/x86_64-linux-gnu/11", "/usr/libexec/gcc/x86_64-linux-gnu/13"].includes(baseline.compilerRuntimeMountPath)) fail("unsigned baseline provenance is invalid");
  for (const role of ["packageInventory", "exportReceipt"]) exactKeys(baseline[role], ["path", "sha256", "size", "dev", "inode", "uid", "mode"], `unsigned baseline ${role}`);
  const helper = runtime.sourceDescriptors["verify-linux-public-baseline"];
  exactKeys(helper, ["fd", "path", "sha256", "dev", "inode", "uid", "mode"], "unsigned baseline helper");
  if (helper.fd !== 117 || helper.path !== runtime.admissionParser.path?.replace(/verify-linux-unsigned-admission\.py$/, "verify-linux-public-baseline.py")) fail("unsigned baseline helper descriptor is invalid");
}
function readCanonicalAdmission(path) {
  const bytes = readFileSync(path);
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { fail("unsigned build admission is not UTF-8 JSON"); }
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) fail("unsigned build admission is not canonical JSON");
  exactKeys(value, ["builder", "candidateRoot", "platform", "project", "releaseStudio", "runtime", "schema", "source", "tools", "version"], "unsigned build admission");
  if (value.schema !== "release-studio.shellx-drive-unsigned-build-admission/v1" || value.project !== "shellx-drive" || value.platform !== "linux-x86_64" || typeof value.candidateRoot !== "string" || !isAbsolute(value.candidateRoot) || !VERSION.test(value.version)) fail("unsigned build admission identity is invalid");
  exactKeys(value.source, ["commit", "fullStageDigest", "tree"], "unsigned build admission.source");
  if (!GIT_OID.test(value.source.commit) || !GIT_OID.test(value.source.tree) || !SHA256.test(value.source.fullStageDigest)) fail("unsigned build admission source is invalid");
  exactKeys(value.builder, ["hostId", "toolchainManifestSha256"], "unsigned build admission.builder");
  if (value.builder.hostId !== LINUX_NATIVE_BUILDER_ID || !SHA256.test(value.builder.toolchainManifestSha256)) fail("unsigned build admission builder is invalid");
  exactKeys(value.releaseStudio, ["collectorSha256", "commit", "tree"], "unsigned build admission.releaseStudio");
  if (!GIT_OID.test(value.releaseStudio.commit) || !GIT_OID.test(value.releaseStudio.tree) || !SHA256.test(value.releaseStudio.collectorSha256)) fail("unsigned build admission controller identity is invalid");
  exactKeys(value.runtime, ["admissionParser", "dependencyRoots", "sourceDescriptors", "toolDescriptors", "toolPath", "worker", ...(Object.hasOwn(value.runtime ?? {}, "publicBaseline") ? ["publicBaseline"] : [])], "unsigned build admission.runtime");
  validateBaselineRuntime(value.runtime);
  if (Object.hasOwn(value.runtime, "gnupgHome") || Object.hasOwn(value, "releaseIdentity") || !value.tools || typeof value.tools !== "object" || Array.isArray(value.tools)) fail("unsigned build admission must remain free of signer authority");
  return { bytes, value };
}
function requireRawApplication(output) {
  if (resolve(output) !== output) fail("unsigned handoff output is not normalized");
  if (readdirSync(output).length !== 1 || readdirSync(output)[0] !== "payload") fail("unsigned handoff output contains build residue");
  const payload = `${output}/payload`;
  const payloadStat = lstatSync(payload);
  if (!payloadStat.isDirectory() || payloadStat.isSymbolicLink() || readdirSync(payload).length !== 1 || readdirSync(payload)[0] !== "shellx-drive-desktop") fail("unsigned handoff payload must contain only the desktop binary");
  const application = `${output}/${APPLICATION_PATH}`;
  const stat = lstatSync(application);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o755 || stat.size < 4 || stat.size > 2 * 1024 * 1024 * 1024) fail("unsigned handoff application identity is invalid");
  const bytes = readFileSync(application);
  if (!bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) fail("unsigned handoff application is not raw ELF bytes");
  return { path: APPLICATION_PATH, role: "application-binary", mode: "0755", size: bytes.length, sha256: sha256(bytes) };
}
function writeHandoff({ admissionBytes, admission, output }) {
  if (resolve(admission.candidateRoot) !== output) fail("unsigned build admission candidate root does not match output");
  const files = [requireRawApplication(output)];
  const handoff = {
    builder: { hostId: admission.builder.hostId, isolationReceiptSha256: sha256(admissionBytes), toolchainManifestSha256: admission.builder.toolchainManifestSha256 },
    files,
    payloadTreeDigest: sha256(Buffer.from(`${canonicalJson(files)}\n`)),
    platform: admission.platform,
    project: admission.project,
    releaseStudio: admission.releaseStudio,
    schema: SCHEMA,
    source: admission.source,
    status: "pass",
    version: admission.version,
  };
  const path = `${output}/unsigned-handoff.json`;
  writeFileSync(path, `${canonicalJson(handoff)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  chmodSync(path, 0o600);
  if (readdirSync(output).sort().join("\0") !== "payload\0unsigned-handoff.json") fail("unsigned handoff output contains unexpected files");
}

try {
  const { admission: admissionPath, output } = parseArguments(process.argv.slice(2));
  const { bytes, value } = readCanonicalAdmission(admissionPath);
  writeHandoff({ admissionBytes: bytes, admission: value, output });
  process.stdout.write("LINUX_UNSIGNED_HANDOFF_COMPLETE status=pass\n");
} catch (error) {
  process.stderr.write(`FAIL: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
