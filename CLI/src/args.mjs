// Tiny argv parser. No external deps.
//
// Spec keys, all optional:
//   booleans: ["json", ...]   present-or-absent flags
//   strings:  ["out", ...]    take a single value
//   arrays:   ["allowlist"]   may repeat; collected into an array
//   aliases:  { j: "json" }   short → long name
//
// Behavior:
//   --key value     long with separate value
//   --key=value     long with inline value
//   --key           long boolean (or string defaulting to "")
//   -k value        short alias (looked up in aliases)
//   --              terminator; remainder collected as positionals verbatim
//
// Positionals collect into out._.

export function parseArgs(argv, spec = {}) {
  const booleans = new Set(spec.booleans || []);
  const strings = new Set(spec.strings || []);
  const arrays = new Set(spec.arrays || []);
  const aliases = spec.aliases || {};
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
        else throw new Error(`flag --${rawKey} requires a value`);
      } else if (arrays.has(key)) {
        if (inlineVal !== null) out[key].push(inlineVal);
        else if (i + 1 < argv.length) out[key].push(argv[++i]);
        else throw new Error(`flag --${rawKey} requires a value`);
      } else {
        // Unknown long flag — preserve, treat as boolean true unless inline
        out[key] = inlineVal === null ? true : inlineVal;
      }
      continue;
    }
    if (a.length > 1 && a.startsWith("-") && !/^-\d/.test(a)) {
      const short = a.slice(1);
      const key = norm(aliases[short] || short);
      if (booleans.has(key)) out[key] = true;
      else if (strings.has(key)) {
        if (i + 1 < argv.length) out[key] = argv[++i];
        else throw new Error(`flag -${short} requires a value`);
      } else if (arrays.has(key)) {
        if (i + 1 < argv.length) out[key].push(argv[++i]);
        else throw new Error(`flag -${short} requires a value`);
      } else {
        out[key] = true;
      }
      continue;
    }
    out._.push(a);
  }
  return out;
}
