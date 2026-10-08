#!/usr/bin/env node
import { writeCandidate } from "./updater-candidate-core.mjs";

try {
  writeCandidate(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`FAIL: ${error.message}\n`);
  process.exitCode = 1;
}
