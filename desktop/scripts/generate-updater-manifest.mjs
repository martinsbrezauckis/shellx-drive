#!/usr/bin/env node
import { generateManifest } from "./updater-candidate-core.mjs";

try {
  generateManifest(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`FAIL: ${error.message}\n`);
  process.exitCode = 1;
}
