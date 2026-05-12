#!/usr/bin/env node
// capsule — command-line entry point.
//
// Exit codes:
//   0  success / verification passed
//   1  verification failed / vectors mismatch / data violation
//   2  I/O, argument, or environment error
//
// Note: we set process.exitCode and return rather than calling
// process.exit(). When stdout is a pipe (e.g. captured by spawnSync or
// piped to another command), process.exit() can truncate the buffered
// write before it flushes. Letting the event loop drain naturally is
// the only reliable way to emit large JSON output without truncation.

import { run } from "../src/index.mjs";

run(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = typeof code === "number" ? code : 0;
  },
  (err) => {
    process.stderr.write(`capsule: ${err?.stack || err?.message || String(err)}\n`);
    process.exitCode = 2;
  },
);
