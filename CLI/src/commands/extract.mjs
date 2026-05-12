// `capsule extract <file> <out-dir>`
//
// Unpack the capsule's files into a directory tree:
//   manifest.json, provenance/envelope.json, program.md, agents.md,
//   chain/events.jsonl, skills/<id>/*, payload/*
//
// Refuses to write into a non-empty directory unless --force.

import { mkdir, writeFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { CapsuleReader } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, bytesText, out, readBytes } from "../format.mjs";

const USAGE = "usage: capsule extract <file> <out-dir> [--force]\n";

export async function extractCmd(argv) {
  const args = parseArgs(argv, { booleans: ["force"] });
  const [file, outDir] = args._;
  if (!file || !outDir) { process.stderr.write(USAGE); return 2; }
  const bytes = await readBytes(file);
  const reader = await CapsuleReader.fromBytes(bytes);

  const target = resolve(outDir);

  // Refuse to overwrite a populated directory unless --force.
  let existingEntries = [];
  try {
    existingEntries = await readdir(target);
  } catch (e) {
    if (e.code !== "ENOENT") throw new CLIError(`cannot inspect ${target}: ${e.message}`, 2);
  }
  if (existingEntries.length > 0 && !args.force) {
    throw new CLIError(`${target} is not empty (${existingEntries.length} entries). Pass --force to overwrite.`, 2);
  }

  const files = reader.files_();
  await mkdir(target, { recursive: true });

  let totalBytes = 0;
  const written = [];
  for (const [path, data] of files.entries()) {
    // Defense in depth — assertSafePath in the SDK already rejected this,
    // but be belt-and-suspenders before writing to disk.
    if (path.includes("..") || path.startsWith("/")) {
      throw new CLIError(`refusing to write suspicious path: ${path}`, 2);
    }
    const dest = join(target, path);
    if (!resolve(dest).startsWith(target + (target.endsWith("/") ? "" : "/")) &&
        resolve(dest) !== target) {
      throw new CLIError(`refusing to write outside target: ${path}`, 2);
    }
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, data);
    written.push({ path, size: data.length });
    totalBytes += data.length;
  }

  written.sort((a, b) => (a.path < b.path ? -1 : 1));
  for (const w of written) out(`  wrote ${w.path.padEnd(48)} ${bytesText(w.size)}`);
  out(`extracted ${written.length} file${written.length === 1 ? "" : "s"} (${bytesText(totalBytes)}) to ${target}`);
  return 0;
}
