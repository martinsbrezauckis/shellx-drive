#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";

function value(name) {
  const index = process.argv.indexOf(name);
  const result = index >= 0 ? process.argv[index + 1] : "";
  if (!result || result.startsWith("--")) throw new Error(`${name} is required`);
  return result;
}
function regular(file, label) {
  const metadata = lstatSync(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    throw new Error(`${label} must be a single-link regular file`);
  }
}
function digest(file) {
  regular(file, basename(file));
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}
const commit = value("--source-commit");
const tree = value("--source-tree");
const appimage = value("--appimage");
const deb = value("--deb");
const appimageUpdaterSignature = value("--appimage-updater-signature");
const debUpdaterSignature = value("--deb-updater-signature");
const releaseFingerprint = value("--release-key-fingerprint");
const output = value("--out");
if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("source commit must be a full lowercase Git object id");
if (!/^[A-F0-9]{40}$/.test(releaseFingerprint)) throw new Error("release key fingerprint must be uppercase hexadecimal");
try {
  lstatSync(output);
  throw new Error("candidate manifest output path must be fresh");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
const candidate = {
  schema: "shellx-drive.linux-candidate/v1",
  source: {
    commit,
    tree,
  },
  signer: {
    release_key_fingerprint: releaseFingerprint,
    identity: "OpenPGP release signature; SHA-256 values below are integrity checks only",
  },
  artifacts: {
    appimage: { file: basename(appimage), sha256: digest(appimage) },
    deb: { file: basename(deb), sha256: digest(deb) },
  },
  updaters: {
    "linux-x86_64": {
      artifact: basename(appimage),
      signature: basename(appimageUpdaterSignature),
      artifact_sha256: digest(appimage),
      signature_sha256: digest(appimageUpdaterSignature),
    },
    "linux-x86_64-deb": {
      artifact: basename(deb),
      signature: basename(debUpdaterSignature),
      artifact_sha256: digest(deb),
      signature_sha256: digest(debUpdaterSignature),
    },
  },
};
if (!/^[0-9a-f]{40}$/.test(candidate.source.commit) || !/^[0-9a-f]{40}$/.test(candidate.source.tree)) {
  throw new Error("source tree identity is malformed");
}
for (const file of [appimage, deb, appimageUpdaterSignature, debUpdaterSignature]) {
  if (resolve(file) === resolve(output)) throw new Error("candidate manifest must not overwrite an artifact");
}
writeFileSync(output, `${JSON.stringify(candidate, null, 2)}\n`, { flag: "wx", mode: 0o600 });
