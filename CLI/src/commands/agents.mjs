// `capsule agents <file>` — print agents.md (or "(absent)" if not in capsule).

import { CapsuleReader } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, readBytes } from "../format.mjs";

const USAGE = "usage: capsule agents <file>\n";

export async function agentsCmd(argv) {
  const args = parseArgs(argv, {});
  const file = args._[0];
  if (!file) { process.stderr.write(USAGE); return 2; }
  const bytes = await readBytes(file);
  const reader = await CapsuleReader.fromBytes(bytes);
  if (reader.isEncrypted()) {
    throw new CLIError("capsule is encrypted; agents.md unavailable without decryption.", 2);
  }
  const md = typeof reader.agents === "function" ? reader.agents() : null;
  if (md == null || md.length === 0) {
    process.stderr.write("(no agents.md in this capsule)\n");
    return 0;
  }
  process.stdout.write(md);
  if (!md.endsWith("\n")) process.stdout.write("\n");
  return 0;
}
