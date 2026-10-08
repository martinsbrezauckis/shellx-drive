#!/usr/bin/env node
/**
 * Verify the release shell's Windows PE subsystem without executing it.
 *
 * WINDOWS_GUI (2) tells the Windows loader that a normal launch must not
 * allocate a console for this executable. This is deliberately an artifact
 * header check, not a replacement for installed-Windows launch observation.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const WINDOWS_GUI = 2;
const PE32_MAGIC = 0x10b;
const PE32_PLUS_MAGIC = 0x20b;
const SUBSYSTEM_OFFSET = 68;

const here = path.dirname(fileURLToPath(import.meta.url));
const defaultSourcePath = path.resolve(here, "../src-tauri/src/main.rs");

export function assertReleaseWindowsGuiSource(sourceText, sourcePath = "desktop/src-tauri/src/main.rs") {
  const releaseWindowsGuiAttribute = /^\s*#!\[cfg_attr\s*\(\s*all\s*\(\s*target_os\s*=\s*"windows"\s*,\s*not\s*\(\s*debug_assertions\s*\)\s*\)\s*,\s*windows_subsystem\s*=\s*"windows"\s*,?\s*\)\s*\]/ms;
  if (!releaseWindowsGuiAttribute.test(sourceText)) {
    throw new Error(
      `${sourcePath} must retain the release-only Windows GUI subsystem attribute ` +
        "(target_os = \"windows\", not(debug_assertions), windows_subsystem = \"windows\").",
    );
  }
}

function requireRange(bytes, offset, length, field) {
  if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length) || length < 0 || offset + length > bytes.length) {
    throw new Error(`invalid or truncated PE header while reading ${field}.`);
  }
}

export function inspectPeSubsystem(bytes) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  requireRange(bytes, 0, 2, "DOS signature");
  if (bytes.toString("ascii", 0, 2) !== "MZ") {
    throw new Error("file is not a PE executable: missing MZ DOS signature.");
  }

  requireRange(bytes, 0x3c, 4, "PE header offset");
  const peOffset = bytes.readUInt32LE(0x3c);
  requireRange(bytes, peOffset, 24, "PE and COFF headers");
  if (bytes.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") {
    throw new Error("file is not a PE executable: missing PE signature.");
  }

  const coffOffset = peOffset + 4;
  const optionalHeaderSize = bytes.readUInt16LE(coffOffset + 16);
  const optionalHeaderOffset = coffOffset + 20;
  requireRange(bytes, optionalHeaderOffset, optionalHeaderSize, "optional header");
  if (optionalHeaderSize < SUBSYSTEM_OFFSET + 2) {
    throw new Error("invalid PE optional header: it is too small to contain Subsystem.");
  }

  const optionalHeaderMagic = bytes.readUInt16LE(optionalHeaderOffset);
  let peKind;
  if (optionalHeaderMagic === PE32_MAGIC) peKind = "PE32";
  else if (optionalHeaderMagic === PE32_PLUS_MAGIC) peKind = "PE32+";
  else throw new Error(`unsupported PE optional-header magic 0x${optionalHeaderMagic.toString(16)}.`);

  const subsystem = bytes.readUInt16LE(optionalHeaderOffset + SUBSYSTEM_OFFSET);
  return { peKind, subsystem };
}

export function subsystemName(subsystem) {
  if (subsystem === WINDOWS_GUI) return "WINDOWS_GUI";
  if (subsystem === 3) return "WINDOWS_CUI";
  return `UNKNOWN(${subsystem})`;
}

export function assertWindowsGuiPe(bytes, executablePath = "shellx-drive-desktop.exe") {
  const inspection = inspectPeSubsystem(bytes);
  if (inspection.subsystem !== WINDOWS_GUI) {
    throw new Error(
      `${executablePath} has PE subsystem ${subsystemName(inspection.subsystem)}; expected WINDOWS_GUI (2).`,
    );
  }
  return inspection;
}

function usage() {
  console.log(`Usage: node desktop/scripts/verify-windows-gui-subsystem.mjs [--source <main.rs>] [--exe <shellx-drive-desktop.exe>]

Checks the release-only Rust subsystem attribute. When --exe is supplied, also
checks IMAGE_OPTIONAL_HEADER.Subsystem in that built PE artifact. The check does
not launch the app; installed-Windows launch observation remains required.`);
}

export function parseArguments(args) {
  const options = { sourcePath: defaultSourcePath, executablePath: null };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--source") {
      const value = args[++index];
      if (!value) throw new Error("--source requires a path.");
      options.sourcePath = path.resolve(value);
    } else if (argument === "--exe") {
      const value = args[++index];
      if (!value) throw new Error("--exe requires a path.");
      options.executablePath = path.resolve(value);
    } else if (argument === "--help" || argument === "-h") {
      options.help = true;
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  return options;
}

export function runGuard(options) {
  assertReleaseWindowsGuiSource(fs.readFileSync(options.sourcePath, "utf8"), options.sourcePath);
  if (!options.executablePath) {
    return { sourcePath: options.sourcePath, executablePath: null, inspection: null };
  }
  const inspection = assertWindowsGuiPe(fs.readFileSync(options.executablePath), options.executablePath);
  return { sourcePath: options.sourcePath, executablePath: options.executablePath, inspection };
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    usage();
    return;
  }
  const result = runGuard(options);
  if (result.inspection) {
    console.log(
      `WINDOWS_GUI_PE_GUARD_OK source=${result.sourcePath} exe=${result.executablePath} ` +
        `pe_kind=${result.inspection.peKind} subsystem=${subsystemName(result.inspection.subsystem)}(${result.inspection.subsystem})`,
    );
  } else {
    console.log(`WINDOWS_GUI_SOURCE_GUARD_OK source=${result.sourcePath}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(`WINDOWS_GUI_PE_GUARD_FAIL: ${error.message}`);
    process.exitCode = 1;
  }
}
