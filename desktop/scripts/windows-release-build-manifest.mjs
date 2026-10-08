import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const gitBlob = (bytes) => createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
const same = (left, right) => ["dev", "ino", "mode", "uid", "gid", "size", "nlink", "mtimeNs", "ctimeNs"].every((key) => left[key] === right[key]);

function emptyBuildFeatures(original) {
  const text = original.toString("utf8"); assert(Buffer.from(text).equals(original), "build manifest is not UTF-8");
  const lines = text.split("\n"); const sections = lines.flatMap((line, index) => line.replace(/\r$/, "") === "[build-dependencies]" ? [index] : []);
  assert.equal(sections.length, 1, "build dependency section is ambiguous");
  let end = sections[0] + 1; while (end < lines.length && !/^\s*\[/.test(lines[end])) end++;
  const dependencies = [];
  for (let index = sections[0] + 1; index < end; index++) if (/^\s*tauri-build\s*=/.test(lines[index])) dependencies.push(index);
  assert.equal(dependencies.length, 1, "tauri-build dependency is ambiguous");
  const index = dependencies[0];
  assert(/^tauri-build = \{ version = "[^"\\\r\n]+", optional = true \}\r?$/.test(lines[index]), "tauri-build is not the optional literal dependency");
  lines[index] = lines[index].replace(/ \}(\r?)$/, " , features = [] }$1");
  return Buffer.from(lines.join("\n"));
}

function verifyManifest(path, repo, object) {
  assert(isAbsolute(path) && resolve(path) === path && /^[0-9a-f]{40}$/.test(object), "invalid build manifest input");
  const parents = [];
  for (let parent = dirname(path);; parent = dirname(parent)) {
    const before = lstatSync(parent, { bigint: true });
    assert(before.isDirectory() && !before.isSymbolicLink() && (before.mode & 0o022n) === 0n, "build manifest ancestry is unsafe");
    parents.push([parent, before]); if (parent === dirname(parent)) break;
  }
  assert.equal(realpathSync(path), path, "build manifest path is not physical");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    assert(before.isFile() && before.nlink === 1n && before.uid === BigInt(process.geteuid()) && before.size > 0n && before.size <= 65536n && (before.mode & 0o022n) === 0n, "build manifest file is unsafe");
    assert(same(before, lstatSync(path, { bigint: true })), "build manifest file changed");
    const produced = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < produced.length) {
      const count = readSync(fd, produced, offset, produced.length - offset, offset);
      assert(count > 0, "build manifest shortened during verification"); offset += count;
    }
    assert.equal(readSync(fd, Buffer.alloc(1), 0, 1, offset), 0, "build manifest grew during verification");
    const original = spawnSync("/usr/bin/git", ["--no-replace-objects", "-C", repo, "cat-file", "blob", object], {
      env: { PATH: "/usr/bin:/bin", HOME: process.env.HOME, LANG: "C", LC_ALL: "C" }, maxBuffer: 65536,
    });
    assert.equal(original.status, 0, "frozen build manifest is unavailable");
    assert.equal(gitBlob(original.stdout), object, "frozen build manifest object changed");
    assert(same(before, fstatSync(fd, { bigint: true })) && same(before, lstatSync(path, { bigint: true })) && produced.length === Number(before.size), "build manifest changed during verification");
    for (const [parent, identity] of parents) {
      const after = lstatSync(parent, { bigint: true });
      assert(after.isDirectory() && !after.isSymbolicLink() && ["dev", "ino", "mode", "uid", "gid"].every((key) => after[key] === identity[key]), "build manifest ancestry changed");
    }
    const observed = (bytes) => ({ sha256: sha256(bytes), size: bytes.length, base64: bytes.toString("base64") });
    process.stdout.write(`${JSON.stringify({ observation: "tauri-build-manifest", frozenGitBlob: object, frozen: observed(original.stdout), produced: observed(produced) })}\n`);
    assert(produced.equals(original.stdout) || produced.equals(emptyBuildFeatures(original.stdout)), "produced build manifest differs beyond empty tauri-build features");
  } finally { closeSync(fd); }
}

try {
  assert.equal(process.argv.length, 5, "build manifest verifier requires exact arguments");
  verifyManifest(...process.argv.slice(2));
} catch {
  process.stderr.write("FAIL: produced build manifest is not the exact admitted Tauri normalization\n"); process.exitCode = 1;
}
