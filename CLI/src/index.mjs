// capsule CLI dispatcher.

import { verifyCmd } from "./commands/verify.mjs";
import { inspectCmd } from "./commands/inspect.mjs";
import { chainCmd } from "./commands/chain.mjs";
import { manifestCmd } from "./commands/manifest.mjs";
import { envelopeCmd } from "./commands/envelope.mjs";
import { extractCmd } from "./commands/extract.mjs";
import { programCmd } from "./commands/program.mjs";
import { agentsCmd } from "./commands/agents.mjs";
import { keygenCmd } from "./commands/keygen.mjs";
import { vectorsCmd } from "./commands/vectors.mjs";
import { CLIError, err } from "./format.mjs";

const COMMANDS = {
  verify: { fn: verifyCmd, summary: "verify a capsule's signatures, hashes, and chain" },
  inspect: { fn: inspectCmd, summary: "one-screen overview of a capsule (header + counts)" },
  chain: { fn: chainCmd, summary: "list chain events" },
  manifest: { fn: manifestCmd, summary: "print manifest.json" },
  envelope: { fn: envelopeCmd, summary: "print provenance/envelope.json" },
  program: { fn: programCmd, summary: "print program.md" },
  agents: { fn: agentsCmd, summary: "print agents.md" },
  extract: { fn: extractCmd, summary: "unpack a capsule into a directory" },
  keygen: { fn: keygenCmd, summary: "generate an Ed25519 originator keypair" },
  vectors: { fn: vectorsCmd, summary: "verify cross-implementation parity vectors" },
};

const VERSION = "0.6.0";

function help() {
  err("capsule — command-line tool for Capsule v0.6 files");
  err("");
  err("usage:  capsule <command> [args...]");
  err("");
  err("commands:");
  const w = Math.max(...Object.keys(COMMANDS).map((k) => k.length));
  for (const [name, { summary }] of Object.entries(COMMANDS)) {
    err(`  ${name.padEnd(w)}  ${summary}`);
  }
  err("");
  err("global flags:");
  err("  -V, --version       print version and exit");
  err("  -h, --help          show this help");
  err("");
  err("exit codes:");
  err("  0  success / verification passed");
  err("  1  verification failed / vectors mismatch");
  err("  2  I/O, argument, or environment error");
}

export async function run(argv) {
  if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help" || argv[0] === "help") {
    help();
    return argv.length === 0 ? 2 : 0;
  }
  if (argv[0] === "-V" || argv[0] === "--version" || argv[0] === "version") {
    process.stdout.write(`capsule ${VERSION}\n`);
    return 0;
  }
  const [cmd, ...rest] = argv;
  const handler = COMMANDS[cmd];
  if (!handler) {
    err(`capsule: unknown command "${cmd}"`);
    err("run `capsule help` for usage.");
    return 2;
  }
  try {
    return await handler.fn(rest);
  } catch (e) {
    if (e instanceof CLIError) {
      err(`capsule: ${e.message}`);
      return e.exitCode;
    }
    throw e;
  }
}
