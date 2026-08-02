// Tiny argv parser. No external deps. FAIL-CLOSED: any flag not declared
// in the spec is a usage error (exit 2), and commands cap how many
// positionals they accept. A typo'd --alowlist must never silently drop
// a trust policy, and `verify a.capsule b.capsule` must never verify
// only the first file and quietly ignore the second.
//
// Spec keys, all optional:
//   booleans:       ["json", ...]   present-or-absent flags
//   strings:        ["out", ...]    take a single value
//   arrays:         ["allowlist"]   may repeat; collected into an array
//   aliases:        { j: "json" }   short → long name
//   maxPositionals: N               reject positionals beyond N
//                                   (default: unlimited)
//
// `help` (alias `h`) is always recognized as a boolean, so every command
// answers --help without declaring it — and a fail-closed parser never
// turns a plea for help into an error.
//
// Behavior:
//   --key value     long with separate value
//   --key=value     long with inline value
//   --key           long boolean
//   -k value        short alias (looked up in aliases)
//   --              terminator; remainder collected as positionals verbatim
//
// Positionals collect into out._. All parse failures throw CLIError with
// exit code 2 so the dispatcher prints one clean line, not a stack trace.

import { CLIError } from "./format.mjs";

export function parseArgs(argv, spec = {}) {
  const booleans = new Set(spec.booleans || []);
  booleans.add("help");
  const strings = new Set(spec.strings || []);
  const arrays = new Set(spec.arrays || []);
  const aliases = { h: "help", ...(spec.aliases || {}) };
  const maxPositionals = spec.maxPositionals ?? Infinity;
  const out = { _: [] };
  for (const k of arrays) out[k] = [];

  const norm = (k) => k.replace(/-/g, "_");

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      out._.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const rawKey = eq >= 0 ? a.slice(2, eq) : a.slice(2);
      const key = norm(aliases[rawKey] || rawKey);
      const inlineVal = eq >= 0 ? a.slice(eq + 1) : null;
      if (booleans.has(key)) {
        out[key] = inlineVal === null ? true : inlineVal !== "false";
      } else if (strings.has(key)) {
        if (inlineVal !== null) out[key] = inlineVal;
        else if (i + 1 < argv.length) out[key] = argv[++i];
        else throw new CLIError(`flag --${rawKey} requires a value`, 2);
      } else if (arrays.has(key)) {
        if (inlineVal !== null) out[key].push(inlineVal);
        else if (i + 1 < argv.length) out[key].push(argv[++i]);
        else throw new CLIError(`flag --${rawKey} requires a value`, 2);
      } else {
        throw new CLIError(`unknown flag: --${rawKey}`, 2);
      }
      continue;
    }
    if (a.length > 1 && a.startsWith("-") && !/^-\d/.test(a)) {
      const short = a.slice(1);
      const key = norm(aliases[short] || short);
      if (booleans.has(key)) out[key] = true;
      else if (strings.has(key)) {
        if (i + 1 < argv.length) out[key] = argv[++i];
        else throw new CLIError(`flag -${short} requires a value`, 2);
      } else if (arrays.has(key)) {
        if (i + 1 < argv.length) out[key].push(argv[++i]);
        else throw new CLIError(`flag -${short} requires a value`, 2);
      } else {
        throw new CLIError(`unknown flag: -${short}`, 2);
      }
      continue;
    }
    out._.push(a);
  }

  if (out._.length > maxPositionals) {
    const extras = out._.slice(maxPositionals);
    throw new CLIError(
      `unexpected argument${extras.length === 1 ? "" : "s"}: ${extras.join(" ")}`,
      2,
    );
  }
  return out;
}
