#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";

const { O_CLOEXEC, O_CREAT, O_EXCL, O_NOFOLLOW, O_RDONLY, O_RDWR } = fs.constants;
const BUFFER_BYTES = 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function identity(stat) {
  return `${stat.dev}:${stat.ino}`;
}

function requireRegular(stat, label, expectedIdentity = null, expectedMode = null, expectedLinks = 1n) {
  if (!stat.isFile() || stat.nlink !== expectedLinks || stat.uid !== BigInt(process.getuid())) {
    fail(`${label} is not an expected-link regular file owned by the release user`);
  }
  if (expectedIdentity !== null && identity(stat) !== expectedIdentity) {
    fail(`${label} identity changed`);
  }
  if (expectedMode !== null && Number(stat.mode & 0o777n) !== expectedMode) {
    fail(`${label} mode is not ${expectedMode.toString(8)}`);
  }
}

function requirePathIdentity(path, expectedIdentity, label, expectedLinks = 1n) {
  const stat = fs.lstatSync(path, { bigint: true });
  requireRegular(stat, label, expectedIdentity, null, expectedLinks);
}

function requireSourcePaths(source, sourceStat, alias, label) {
  const expectedLinks = alias === "-" ? 1n : 2n;
  requireRegular(sourceStat, label, null, null, expectedLinks);
  const sourceIdentity = identity(sourceStat);
  requirePathIdentity(source, sourceIdentity, `${label} path`, expectedLinks);
  if (alias !== "-") {
    const aliasFd = openNoFollow(alias, O_RDONLY);
    try {
      requireRegular(fs.fstatSync(aliasFd, { bigint: true }), `${label} alias`, sourceIdentity, null, 2n);
      requirePathIdentity(alias, sourceIdentity, `${label} alias path`, 2n);
    } finally {
      fs.closeSync(aliasFd);
    }
  }
  return sourceIdentity;
}

function openNoFollow(path, flags, mode) {
  if (typeof O_NOFOLLOW !== "number") fail("O_NOFOLLOW is unavailable");
  return fs.openSync(path, flags | O_NOFOLLOW | O_CLOEXEC, mode);
}

function hashFd(fd) {
  const hash = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(BUFFER_BYTES);
  let position = 0;
  while (true) {
    const read = fs.readSync(fd, buffer, 0, buffer.length, position);
    if (read === 0) break;
    hash.update(buffer.subarray(0, read));
    position += read;
  }
  return hash.digest("hex");
}

function copyFd(sourceFd, destinationFd) {
  fs.ftruncateSync(destinationFd, 0);
  const buffer = Buffer.allocUnsafe(BUFFER_BYTES);
  let position = 0;
  while (true) {
    const read = fs.readSync(sourceFd, buffer, 0, buffer.length, position);
    if (read === 0) break;
    let written = 0;
    while (written < read) {
      written += fs.writeSync(destinationFd, buffer, written, read - written, position + written);
    }
    position += read;
  }
}

function inspect(source, alias = "-") {
  const sourceFd = openNoFollow(source, O_RDONLY);
  try {
    const sourceStat = fs.fstatSync(sourceFd, { bigint: true });
    const sourceIdentity = requireSourcePaths(source, sourceStat, alias, "callback source");
    const unsignedDigest = hashFd(sourceFd);
    if (hashFd(sourceFd) !== unsignedDigest) fail("callback source changed during admission");
    requireSourcePaths(source, fs.fstatSync(sourceFd, { bigint: true }), alias, "callback source");
    process.stdout.write(`${sourceIdentity} ${unsignedDigest}\n`);
  } finally {
    fs.closeSync(sourceFd);
  }
}

function stage(source, destination, expectedIdentity, expectedDigest, alias = "-") {
  const sourceFd = openNoFollow(source, O_RDONLY);
  let destinationFd;
  try {
    const sourceStat = fs.fstatSync(sourceFd, { bigint: true });
    const sourceIdentity = requireSourcePaths(source, sourceStat, alias, "callback source");
    if (sourceIdentity !== expectedIdentity) fail("callback source identity changed");
    const unsignedDigest = hashFd(sourceFd);
    if (unsignedDigest !== expectedDigest) fail("callback source changed after admission");
    destinationFd = openNoFollow(destination, O_RDWR | O_CREAT | O_EXCL, 0o600);
    copyFd(sourceFd, destinationFd);
    fs.fsyncSync(destinationFd);
    const stageStat = fs.fstatSync(destinationFd, { bigint: true });
    requireRegular(stageStat, "callback stage", null, 0o600);
    const stageIdentity = identity(stageStat);
    if (stageIdentity === sourceIdentity) fail("callback stage aliases the source inode");
    if (hashFd(sourceFd) !== unsignedDigest || hashFd(destinationFd) !== unsignedDigest) {
      fail("callback source changed while entering the private stage");
    }
    requireSourcePaths(source, fs.fstatSync(sourceFd, { bigint: true }), alias, "callback source");
    requirePathIdentity(destination, stageIdentity, "callback stage path");
    process.stdout.write(`${sourceIdentity} ${unsignedDigest} ${stageIdentity}\n`);
  } finally {
    if (destinationFd !== undefined) fs.closeSync(destinationFd);
    fs.closeSync(sourceFd);
  }
}

function verifyStage(path, expectedDigest, expectedIdentity) {
  const fd = openNoFollow(path, O_RDONLY);
  try {
    requireRegular(fs.fstatSync(fd, { bigint: true }), "callback stage", expectedIdentity, 0o600);
    requirePathIdentity(path, expectedIdentity, "callback stage path");
    if (hashFd(fd) !== expectedDigest) fail("callback stage digest changed");
  } finally {
    fs.closeSync(fd);
  }
}

function restore(source, stagePath, sourceIdentity, unsignedDigest, stageIdentity, alias = "-") {
  const stageFd = openNoFollow(stagePath, O_RDONLY);
  let sourceFd;
  try {
    requireRegular(fs.fstatSync(stageFd, { bigint: true }), "signed callback stage", stageIdentity, 0o600);
    requirePathIdentity(stagePath, stageIdentity, "signed callback stage path");
    const signedDigest = hashFd(stageFd);
    sourceFd = openNoFollow(source, O_RDWR);
    if (requireSourcePaths(source, fs.fstatSync(sourceFd, { bigint: true }), alias, "callback source") !== sourceIdentity) {
      fail("callback source identity changed");
    }
    if (hashFd(sourceFd) !== unsignedDigest) fail("callback source bytes changed during signing");
    copyFd(stageFd, sourceFd);
    fs.fsyncSync(sourceFd);
    if (requireSourcePaths(source, fs.fstatSync(sourceFd, { bigint: true }), alias, "restored callback source") !== sourceIdentity) {
      fail("restored callback source identity changed");
    }
    if (hashFd(sourceFd) !== signedDigest || hashFd(stageFd) !== signedDigest) {
      fail("verified signed bytes were not restored through the pinned source handle");
    }
    process.stdout.write(`${signedDigest}\n`);
  } finally {
    if (sourceFd !== undefined) fs.closeSync(sourceFd);
    fs.closeSync(stageFd);
  }
}

try {
  const [command, ...args] = process.argv.slice(2);
  if (command === "inspect" && [1, 2].includes(args.length)) inspect(...args);
  else if (command === "stage" && [4, 5].includes(args.length)) stage(...args);
  else if (command === "verify-stage" && args.length === 3) verifyStage(args[0], args[1], args[2]);
  else if (command === "restore" && [5, 6].includes(args.length)) restore(...args);
  else fail("usage: windows-signing-callback-file.mjs inspect|stage|verify-stage|restore ...");
} catch (error) {
  process.stderr.write(`callback file boundary rejected the artifact: ${error.message}\n`);
  process.exitCode = 1;
}
