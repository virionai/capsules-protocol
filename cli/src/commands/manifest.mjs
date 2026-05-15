// `capsule manifest <file>` — print manifest.json (the parsed JSON, pretty).

import { CapsuleReader } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { out, readBytes } from "../format.mjs";

const USAGE = "usage: capsule manifest <file>\n";

export async function manifestCmd(argv) {
  const args = parseArgs(argv, {});
  const file = args._[0];
  if (!file) { process.stderr.write(USAGE); return 2; }
  const bytes = await readBytes(file);
  const reader = await CapsuleReader.fromBytes(bytes);
  out(JSON.stringify(reader.manifest(), null, 2));
  return 0;
}
