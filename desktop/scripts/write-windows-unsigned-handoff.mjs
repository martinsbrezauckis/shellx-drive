#!/usr/bin/env node
import { createHash } from "node:crypto";
import { chmodSync, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, closeSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";

const CONFIG = Object.freeze({
  platform: "windows-x86_64",
  admissionSchema: "release-studio.shellx-drive-windows-unsigned-build-admission/v1",
  applicationPath: "payload/shellx-drive-desktop.exe",
  applicationMode: 0o600,
  applicationModeText: "0600",
  completion: "WINDOWS_UNSIGNED_HANDOFF_COMPLETE",
});
const SCHEMA = "release-studio.shellx-drive-unsigned-handoff/v1";
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_OID = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
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
    try { return `[${value.map((item) => canonicalJson(item, seen)).join(",")}]`; } finally { seen.delete(value); }
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
function parseArguments(args) {
  if (args.length !== 12 || !["--admission", "--admission-file"].includes(args[0]) || args[2] !== "--raw" || args[4] !== "--out" || args[6] !== "--tauri-config" || args[8] !== "--package-cargo-manifest" || args[10] !== "--workspace-cargo-manifest") {
    fail("usage: write-windows-unsigned-handoff.mjs (--admission /dev/fd/3 | --admission-file <sealed-absolute-file>) --raw <absolute-raw-PE> --out <fresh-absolute-directory> --tauri-config <exact-build-config> --package-cargo-manifest <src-tauri-Cargo.toml> --workspace-cargo-manifest <desktop-Cargo.toml>");
  }
  const [admission, raw, output, tauriConfig, packageCargoManifest, workspaceCargoManifest] = [args[1], args[3], args[5], args[7], args[9], args[11]];
  if (![raw, output, tauriConfig, packageCargoManifest, workspaceCargoManifest].every(isAbsolute)) fail("raw/output/config/Cargo paths must be absolute");
  if (args[0] === "--admission" && admission !== "/dev/fd/3") fail("descriptor admission must be /dev/fd/3");
  if (args[0] === "--admission-file" && !isAbsolute(admission)) fail("native admission file must be absolute");
  return { admission, raw: resolve(raw), output: resolve(output), tauriConfig: resolve(tauriConfig), packageCargoManifest: resolve(packageCargoManifest), workspaceCargoManifest: resolve(workspaceCargoManifest), nativeAdmissionFile: args[0] === "--admission-file" };
}
function readCanonicalAdmission(path, { nativeAdmissionFile = false } = {}) {
  let expectedNativeHash;
  if (nativeAdmissionFile) {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (process.platform !== "win32" && (stat.mode & 0o022) !== 0)) fail("native admission file must be a private physical regular file");
    expectedNativeHash = process.env.SHELLX_DRIVE_NATIVE_ADMISSION_SHA256;
    if (!SHA256.test(expectedNativeHash ?? "")) fail("native admission file requires its controller-provided SHA-256");
  }
  const bytes = readFileSync(path);
  if (expectedNativeHash && sha256(bytes) !== expectedNativeHash) fail("native admission file differs from its controller-provided SHA-256");
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { fail("unsigned build admission is not UTF-8 JSON"); }
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) fail("unsigned build admission is not canonical JSON");
  exactKeys(value, ["builder", "candidateRoot", "platform", "project", "releaseStudio", "schema", "source", "version"], "unsigned build admission");
  if (value.schema !== CONFIG.admissionSchema || value.project !== "shellx-drive" || value.platform !== CONFIG.platform || typeof value.candidateRoot !== "string" || !isAbsolute(value.candidateRoot) || resolve(value.candidateRoot) !== value.candidateRoot || !VERSION.test(value.version)) fail("unsigned build admission identity is invalid");
  exactKeys(value.source, ["commit", "fullStageDigest", "tree"], "unsigned build admission.source");
  if (!GIT_OID.test(value.source.commit) || !GIT_OID.test(value.source.tree) || !SHA256.test(value.source.fullStageDigest)) fail("unsigned build admission source is invalid");
  exactKeys(value.builder, ["hostId", "toolchainManifestSha256"], "unsigned build admission.builder");
  if (typeof value.builder.hostId !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(value.builder.hostId) || !SHA256.test(value.builder.toolchainManifestSha256)) fail("unsigned build admission builder is invalid");
  exactKeys(value.releaseStudio, ["collectorSha256", "commit", "tree"], "unsigned build admission.releaseStudio");
  if (!GIT_OID.test(value.releaseStudio.commit) || !GIT_OID.test(value.releaseStudio.tree) || !SHA256.test(value.releaseStudio.collectorSha256)) fail("unsigned build admission controller identity is invalid");
  return { bytes, value };
}
function readRawPe(path) {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 0x40 || before.size > 512 * 1024 * 1024) fail("raw Windows application must be a bounded physical regular file");
  const fd = openSync(path, "r");
  try {
    const opened = fstatSync(fd);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size || opened.nlink !== 1) fail("raw Windows application changed before it was opened");
    const bytes = readFileSync(fd);
    const after = lstatSync(path);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size || after.mtimeMs !== before.mtimeMs) fail("raw Windows application changed while it was read");
    if (bytes.toString("ascii", 0, 2) !== "MZ") fail("raw Windows application is not PE bytes");
    const pe = bytes.readUInt32LE(0x3c);
    if (pe + 6 > bytes.length || bytes.toString("ascii", pe, pe + 4) !== "PE\0\0" || bytes.readUInt16LE(pe + 4) !== 0x8664) fail("raw Windows application is not x86_64 PE bytes");
    return bytes;
  } finally { closeSync(fd); }
}
function readUtf8File(path, label) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) fail(`${label} must be a bounded physical regular file`);
  try { return new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(path)); } catch { fail(`${label} is not UTF-8 text`); }
}
function tauriConfigVersion(path) {
  const text = readUtf8File(path, "Tauri config");
  let value;
  try { value = JSON.parse(text); } catch { fail("Tauri config is not JSON"); }
  const occurrences = [...text.matchAll(/(?:^|[,{]\s*)"version"\s*:/gm)];
  if (!value || typeof value !== "object" || Array.isArray(value) || occurrences.length !== 1 || typeof value.version !== "string" || !VERSION.test(value.version)) fail("Tauri config version is missing, malformed, or ambiguous");
  return value.version;
}
function tomlSection(text, name, label) {
  let sections = 0;
  let active = false;
  const lines = [];
  for (const line of text.split(/\r?\n/u)) {
    const header = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/u.exec(line);
    if (header) { active = header[1] === name; if (active) sections += 1; continue; }
    if (active) lines.push(line.replace(/\s+#.*$/u, ""));
  }
  if (sections !== 1) fail(`${label} is missing or ambiguous`);
  return lines;
}
function cargoPackageVersion(packagePath, workspacePath) {
  const packageLines = tomlSection(readUtf8File(packagePath, "Cargo package manifest"), "package", "Cargo package section");
  const declarations = packageLines.filter((line) => /^\s*version(?:\.[A-Za-z0-9_-]+)?(?:\s|=|$)/u.test(line));
  const direct = packageLines.map((line) => /^\s*version\s*=\s*"([^"]+)"\s*$/u.exec(line)).filter(Boolean);
  const inherited = packageLines.filter((line) => /^\s*version\.workspace\s*=\s*true\s*$/u.test(line));
  if (declarations.length !== 1 || direct.length + inherited.length !== 1) fail("Cargo package version is missing, malformed, or ambiguous");
  const version = direct.length === 1
    ? direct[0][1]
    : (() => {
      const workspaceLines = tomlSection(readUtf8File(workspacePath, "Cargo workspace manifest"), "workspace.package", "Cargo workspace package section");
      const workspaceDeclarations = workspaceLines.filter((line) => /^\s*version(?:\.[A-Za-z0-9_-]+)?(?:\s|=|$)/u.test(line));
      const workspaceVersions = workspaceLines.map((line) => /^\s*version\s*=\s*"([^"]+)"\s*$/u.exec(line)).filter(Boolean);
      if (workspaceDeclarations.length !== 1 || workspaceVersions.length !== 1) fail("Cargo workspace version is missing, malformed, or ambiguous");
      return workspaceVersions[0][1];
    })();
  if (!VERSION.test(version)) fail("Cargo package version is malformed");
  return version;
}
function validateVersionBinding(admission, paths) { if (tauriConfigVersion(paths.tauriConfig) !== admission.version) fail("Tauri config version does not match unsigned build admission"); if (cargoPackageVersion(paths.packageCargoManifest, paths.workspaceCargoManifest) !== admission.version) fail("Cargo package version does not match unsigned build admission"); }
function writeHandoff({ admissionBytes, admission, raw, output, nativeWindows }) {
  if (admission.candidateRoot !== output) fail("unsigned build admission candidate root does not match output");
  if (existsSync(output)) fail("unsigned handoff output must be fresh");
  const parent = lstatSync(dirname(output));
  if (!parent.isDirectory() || parent.isSymbolicLink() || (!nativeWindows && (parent.mode & 0o022) !== 0)) fail("unsigned handoff output parent must be a private physical directory");
  mkdirSync(output, { mode: 0o700 }); chmodSync(output, 0o700);
  const payload = `${output}/payload`; mkdirSync(payload, { mode: 0o700 }); chmodSync(payload, 0o700);
  const application = `${output}/${CONFIG.applicationPath}`;
  writeFileSync(application, raw, { flag: "wx", mode: CONFIG.applicationMode }); chmodSync(application, CONFIG.applicationMode);
  const files = [{ path: CONFIG.applicationPath, role: "application-binary", mode: CONFIG.applicationModeText, size: raw.length, sha256: sha256(raw) }];
  const handoff = {
    builder: { hostId: admission.builder.hostId, isolationReceiptSha256: sha256(admissionBytes), toolchainManifestSha256: admission.builder.toolchainManifestSha256 },
    files,
    payloadTreeDigest: sha256(Buffer.from(`${canonicalJson(files)}\n`)),
    platform: admission.platform, project: admission.project, releaseStudio: admission.releaseStudio,
    schema: SCHEMA, source: admission.source, status: "pass", version: admission.version,
  };
  writeFileSync(`${output}/unsigned-handoff.json`, `${canonicalJson(handoff)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  chmodSync(`${output}/unsigned-handoff.json`, 0o600);
  if (readdirSync(output).sort().join("\0") !== "payload\0unsigned-handoff.json" || readdirSync(payload).join("\0") !== "shellx-drive-desktop.exe") fail("unsigned handoff output contains unexpected files");
}
try {
  const paths = parseArguments(process.argv.slice(2));
  const { admission: admissionPath, raw: rawPath, output, nativeAdmissionFile } = paths;
  const { bytes, value } = readCanonicalAdmission(admissionPath, { nativeAdmissionFile });
  validateVersionBinding(value, paths);
  writeHandoff({ admissionBytes: bytes, admission: value, raw: readRawPe(rawPath), output, nativeWindows: nativeAdmissionFile && process.platform === "win32" });
  process.stdout.write(`${CONFIG.completion} status=pass\n`);
} catch (error) {
  process.stderr.write(`FAIL: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
