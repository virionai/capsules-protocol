// `capsule program <file>` — print program.md to stdout.

import { CapsuleReader } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, readBytes } from "../format.mjs";

const USAGE = "usage: capsule program <file>\n";

export async function programCmd(argv) {
  const args = parseArgs(argv, {});
  const file = args._[0];
  if (!file) { process.stderr.write(USAGE); return 2; }
  const bytes = await readBytes(file);
  const reader = await CapsuleReader.fromBytes(bytes);
  if (reader.isEncrypted()) {
    throw new CLIError("capsule is encrypted; program.md unavailable without decryption.", 2);
  }
  process.stdout.write(reader.program());
  if (!reader.program().endsWith("\n")) process.stdout.write("\n");
  return 0;
}
