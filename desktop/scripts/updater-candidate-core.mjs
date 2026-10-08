import { createHash } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";

export const PLATFORM_SPECS = Object.freeze({
  "windows-x86_64": { target: "x86_64-pc-windows-msvc", identity: "authenticode" },
  "darwin-aarch64": { target: "aarch64-apple-darwin", identity: "developer-id-notarized" },
  "linux-x86_64": { target: "x86_64-unknown-linux-gnu", identity: "openpgp" },
  // Tauri resolves this exact platform before the generic Linux key for a
  // Debian install, so it must have its own signed archive witness.
  "linux-x86_64-deb": { target: "x86_64-unknown-linux-gnu", identity: "openpgp" },
});

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const GIT_ID = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const REPOSITORY = "martinsbrezauckis/shellx-drive";
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function fail(message) { throw new Error(message); }
function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}
function exactKeys(value, keys, label) {
  const actual = Object.keys(object(value, label)).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has unexpected or missing fields`);
  }
}
function text(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) fail(`${label} is malformed`);
  return value;
}
function regular(file, label) {
  const stat = lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${label} must be a regular non-link file`);
  return stat;
}
function realDirectory(directory, label) {
  const absolute = resolve(directory);
  const root = resolve(sep);
  let current = root;
  for (const part of relative(root, absolute).split(sep)) {
    if (!part) continue;
    current = resolve(current, part);
    const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} has a symlinked directory component`);
  }
  return absolute;
}
function under(root, candidate, label) {
  const rootPath = realDirectory(root, label);
  const candidatePath = resolve(candidate);
  const rel = relative(rootPath, candidatePath);
  if (!rel || isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`)) fail(`${label} escapes its candidate directory`);
  let current = rootPath;
  for (const part of rel.split(sep)) {
    if (!part || part === "." || part === "..") fail(`${label} has an unsafe path component`);
    current = resolve(current, part);
    if (lstatSync(current).isSymbolicLink()) fail(`${label} has a symlinked path component`);
  }
  return rel.split(sep).join("/");
}
function digest(file, label) {
  regular(file, label);
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}
function safeRef(root, ref, label) {
  if (typeof ref !== "string" || !ref || ref.includes("\\") || ref.includes("\0") || isAbsolute(ref)) {
    fail(`${label} has an unsafe path`);
  }
  const pieces = ref.split("/");
  if (pieces.some((piece) => !piece || piece === "." || piece === "..")) fail(`${label} has an unsafe path`);
  const target = resolve(root, ...pieces);
  under(root, target, label);
  regular(target, label);
  return target;
}
function rfc3339(value) {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value)
    || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail("pub_date must be canonical RFC 3339 UTC");
  }
  return value;
}
export function updaterArtifactName(platform, version) {
  text(version, SEMVER, "version");
  switch (platform) {
    case "windows-x86_64": return `ShellX Drive Desktop_${version}_x64-setup.exe`;
    case "darwin-aarch64": return `ShellX Drive Desktop_${version}_aarch64.app.tar.gz`;
    case "linux-x86_64": return `ShellX_Drive_${version}_amd64.AppImage`;
    case "linux-x86_64-deb": return `shellx-drive_${version}_amd64.deb`;
    default: fail("platform is unsupported");
  }
}
function signature(file, platform, version, artifact) {
  const value = readFileSync(file, "utf8").trim();
  if (value.length < 80 || value.length % 4 !== 0 || !BASE64.test(value)) fail("updater signature is missing or malformed");
  const leaf = updaterArtifactName(platform, version);
  if (basename(artifact) !== leaf) fail("updater artifact name does not bind its platform and version");
  const decoded = Buffer.from(value, "base64");
  const lines = decoded.toString("utf8").split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length !== 4 || !lines[0].startsWith("untrusted comment: ")
    || !BASE64.test(lines[1]) || Buffer.from(lines[1], "base64").length !== 74
    || !BASE64.test(lines[3]) || Buffer.from(lines[3], "base64").length !== 64) fail("updater signature is missing or malformed");
  const comment = lines[2].match(/^trusted comment: timestamp:([0-9]+)\tfile:(.+)$/);
  if (!comment || BigInt(comment[1]) > 18446744073709551615n || comment[2] !== leaf) {
    fail("updater signed comment does not bind its platform and version");
  }
  // This compiler checks the signed identity contract. The native verifier and
  // installed updater authenticate both artifact and trusted comment signatures.
  return value;
}
function freshOutput(output) {
  const parent = dirname(resolve(output));
  realDirectory(parent, "output parent");
  try { lstatSync(output); fail("output path must be fresh"); } catch (error) { if (error.code !== "ENOENT") throw error; }
}
function requiredArgument(arguments_, name) {
  const index = arguments_.indexOf(name);
  const value = index >= 0 ? arguments_[index + 1] : "";
  if (!value || value.startsWith("--")) fail(`${name} is required`);
  return value;
}
function repeatedArgument(arguments_, name) {
  const values = [];
  for (let index = 0; index < arguments_.length; index += 1) {
    if (arguments_[index] !== name) continue;
    const value = arguments_[index + 1];
    if (!value || value.startsWith("--")) fail(`${name} is required`);
    values.push(value);
  }
  return values;
}
function onlyArguments(arguments_, allowed, repeated = new Set()) {
  for (let index = 0; index < arguments_.length; index += 1) {
    const value = arguments_[index];
    if (!value.startsWith("--")) fail(`unexpected positional argument: ${value}`);
    if (!allowed.has(value)) fail(`unknown argument: ${value}`);
    if (index + 1 >= arguments_.length || arguments_[index + 1].startsWith("--")) fail(`${value} is required`);
    if (!repeated.has(value) && arguments_.indexOf(value) !== index) fail(`${value} must not be repeated`);
    index += 1;
  }
}

export function writeCandidate(arguments_) {
  const allowed = new Set(["--platform", "--version", "--version-config", "--source-commit", "--source-tree", "--artifact", "--signature", "--identity-kind", "--identity-evidence", "--candidate-root", "--out"]);
  onlyArguments(arguments_, allowed);
  const platform = requiredArgument(arguments_, "--platform");
  const spec = PLATFORM_SPECS[platform];
  if (!spec) fail("platform is unsupported");
  const fromConfig = arguments_.includes("--version-config");
  if (fromConfig && arguments_.includes("--version")) fail("--version and --version-config are mutually exclusive");
  // Signers pass the already admitted Tauri config descriptor, keeping the
  // updater version bound to the same configuration used for the package.
  const version = text(fromConfig
    ? JSON.parse(readFileSync(requiredArgument(arguments_, "--version-config"), "utf8")).version
    : requiredArgument(arguments_, "--version"), SEMVER, "version");
  const sourceCommit = text(requiredArgument(arguments_, "--source-commit"), GIT_ID, "source commit");
  const sourceTree = text(requiredArgument(arguments_, "--source-tree"), GIT_ID, "source tree");
  const output = resolve(requiredArgument(arguments_, "--out"));
  freshOutput(output);
  const rootIndex = arguments_.indexOf("--candidate-root");
  const root = rootIndex < 0 ? dirname(output) : resolve(arguments_[rootIndex + 1]);
  realDirectory(root, "candidate root");
  const artifact = resolve(requiredArgument(arguments_, "--artifact"));
  const signatureFile = resolve(requiredArgument(arguments_, "--signature"));
  const evidence = resolve(requiredArgument(arguments_, "--identity-evidence"));
  const identityKind = requiredArgument(arguments_, "--identity-kind");
  if (identityKind !== spec.identity) fail("identity kind does not match platform");
  const artifactRef = under(root, artifact, "updater artifact");
  const signatureRef = under(root, signatureFile, "updater signature");
  const evidenceRef = under(root, evidence, "identity evidence");
  regular(artifact, "updater artifact");
  regular(signatureFile, "updater signature");
  signature(signatureFile, platform, version, artifact);
  regular(evidence, "identity evidence");
  const candidate = {
    schema: "shellx-drive.updater-candidate/v1",
    version,
    source: { commit: sourceCommit, tree: sourceTree },
    platform,
    target: spec.target,
    identity: { kind: identityKind, evidence: evidenceRef, evidence_sha256: digest(evidence, "identity evidence") },
    updater: {
      artifact: artifactRef,
      artifact_sha256: digest(artifact, "updater artifact"),
      signature: signatureRef,
      signature_sha256: digest(signatureFile, "updater signature"),
    },
  };
  writeFileSync(output, `${JSON.stringify(candidate, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
}

function readCandidate(file, expected) {
  regular(file, "candidate witness");
  const root = dirname(resolve(file));
  let candidate;
  try { candidate = JSON.parse(readFileSync(file, "utf8")); } catch { fail("candidate witness is not valid JSON"); }
  exactKeys(candidate, ["schema", "version", "source", "platform", "target", "identity", "updater"], "candidate witness");
  if (candidate.schema !== "shellx-drive.updater-candidate/v1") fail("candidate witness schema is unsupported");
  const spec = PLATFORM_SPECS[candidate.platform];
  if (!spec || candidate.target !== spec.target) fail("candidate platform or architecture is wrong");
  if (candidate.version !== expected.version) fail("candidate version does not match");
  exactKeys(candidate.source, ["commit", "tree"], "candidate source");
  if (candidate.source.commit !== expected.sourceCommit || candidate.source.tree !== expected.sourceTree
    || !GIT_ID.test(candidate.source.commit) || !GIT_ID.test(candidate.source.tree)) fail("candidate source identity does not match");
  exactKeys(candidate.identity, ["kind", "evidence", "evidence_sha256"], "candidate identity");
  if (candidate.identity.kind !== spec.identity || !SHA256.test(candidate.identity.evidence_sha256)) fail("candidate identity is wrong");
  const evidence = safeRef(root, candidate.identity.evidence, "identity evidence");
  if (digest(evidence, "identity evidence") !== candidate.identity.evidence_sha256) fail("identity evidence digest does not match");
  exactKeys(candidate.updater, ["artifact", "artifact_sha256", "signature", "signature_sha256"], "candidate updater");
  if (!SHA256.test(candidate.updater.artifact_sha256) || !SHA256.test(candidate.updater.signature_sha256)) fail("candidate updater digest is malformed");
  const artifact = safeRef(root, candidate.updater.artifact, "updater artifact");
  const signatureFile = safeRef(root, candidate.updater.signature, "updater signature");
  if (digest(artifact, "updater artifact") !== candidate.updater.artifact_sha256
    || digest(signatureFile, "updater signature") !== candidate.updater.signature_sha256) fail("candidate updater digest does not match");
  return { platform: candidate.platform, artifact: basename(artifact), signature: signature(signatureFile, candidate.platform, candidate.version, artifact) };
}

export function generateManifest(arguments_) {
  const allowed = new Set(["--version", "--source-commit", "--source-tree", "--repository", "--pub-date", "--candidate", "--out"]);
  onlyArguments(arguments_, allowed, new Set(["--candidate"]));
  const expected = {
    version: text(requiredArgument(arguments_, "--version"), SEMVER, "version"),
    sourceCommit: text(requiredArgument(arguments_, "--source-commit"), GIT_ID, "source commit"),
    sourceTree: text(requiredArgument(arguments_, "--source-tree"), GIT_ID, "source tree"),
  };
  const repository = requiredArgument(arguments_, "--repository");
  if (repository !== REPOSITORY) fail("repository must be the fixed ShellX Drive GitHub repository");
  const pubDate = rfc3339(requiredArgument(arguments_, "--pub-date"));
  const output = resolve(requiredArgument(arguments_, "--out"));
  freshOutput(output);
  const candidates = repeatedArgument(arguments_, "--candidate");
  const wanted = Object.keys(PLATFORM_SPECS);
  if (candidates.length !== wanted.length) fail("exactly one candidate is required for every supported platform");
  const seen = new Set();
  const parsed = candidates.map((file) => {
    const candidate = readCandidate(resolve(file), expected);
    if (seen.has(candidate.platform)) fail("duplicate platform candidate");
    seen.add(candidate.platform);
    return candidate;
  });
  if (wanted.some((platform) => !seen.has(platform))) fail("updater manifest would be partial");
  const assets = new Set();
  for (const candidate of parsed) {
    if (assets.has(candidate.artifact)) fail("platform candidates reuse an updater artifact name");
    assets.add(candidate.artifact);
  }
  const tag = `v${expected.version}`;
  const byPlatform = Object.fromEntries(parsed.map((candidate) => [candidate.platform, {
    signature: candidate.signature,
    url: `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(candidate.artifact)}`,
  }]));
  const platforms = Object.fromEntries(wanted.map((platform) => [platform, byPlatform[platform]]));
  writeFileSync(output, `${JSON.stringify({ version: expected.version, notes: `ShellX Drive Desktop ${expected.version}`, pub_date: pubDate, platforms }, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
}

if (process.argv[1]?.startsWith("/dev/fd/")) {
  try { writeCandidate(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`FAIL: ${error.message}\n`); process.exitCode = 1; }
}
