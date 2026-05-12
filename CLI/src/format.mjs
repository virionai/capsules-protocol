// Small formatting helpers shared by all commands. No external deps.

const TICK = "✓";
const CROSS = "✗";
const ARROW = "→";

export function truncHex(hex, head = 12) {
  if (typeof hex !== "string") return String(hex);
  if (hex.length <= head + 2) return hex;
  return `${hex.slice(0, head)}…`;
}

export function bytesText(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function check(ok) {
  return ok ? TICK : CROSS;
}

export function arrow() {
  return ARROW;
}

// Reads a file into Uint8Array; surfaces a clean error message on failure.
import { readFile } from "node:fs/promises";
export async function readBytes(path) {
  try {
    const buf = await readFile(path);
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  } catch (e) {
    throw new CLIError(`cannot read ${path}: ${e.message}`, 2);
  }
}

export class CLIError extends Error {
  constructor(message, exitCode = 2) {
    super(message);
    this.exitCode = exitCode;
  }
}

// Print to stdout / stderr without sprinkling process.stdout everywhere.
export function out(s) { process.stdout.write(s + "\n"); }
export function err(s) { process.stderr.write(s + "\n"); }
