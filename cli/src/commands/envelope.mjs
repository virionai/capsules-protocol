// `capsule envelope <file>` — print provenance/envelope.json (parsed, pretty).

import { CapsuleReader } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { out, readBytes } from "../format.mjs";

const USAGE = "usage: capsule envelope <file>\n";

export async function envelopeCmd(argv) {
  const args = parseArgs(argv, {});
  const file = args._[0];
  if (!file) { process.stderr.write(USAGE); return 2; }
  const bytes = await readBytes(file);
  const reader = await CapsuleReader.fromBytes(bytes);
  out(JSON.stringify(reader.envelope(), null, 2));
  return 0;
}
